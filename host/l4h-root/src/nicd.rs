//! Network devices and their drivers (DESIGN.md §9.8).  Each bound NIC is
//! driven by its own nicd, a component outside netd built from a driver
//! of the bundle (drivers.rs), joined to netd by an uplink channel
//! (l4h_host::uplink) whose frames are root's.  Root knows no device kind:
//! a driver's manifest says which devices it drives and what it needs, and
//! root checks the device against it.
//!
//! What a nicd gets: the BARs its manifest names (no more of each than its
//! window), a DMA region in the device's IOMMU domain only, one interrupt
//! vector remapped for the device, a snapshot of the configuration space
//! and the configuration writes root's filter lets through (`cfg_access`),
//! its channel, and a mailbox.  No PCI configuration capability, no
//! IRQControl, no Untyped, no endpoint to netd.
//!
//! A nicd is outside the TCB (`confined`) when its device has an IOMMU
//! domain, interrupt remapping, and an isolation group (`group`) of its
//! own or shared only with functions of the same driver.  Elsewhere its
//! driver is trusted code, which only the boot bundle's may be.
//!
//! Root never waits on a nicd.  A nicd that faults, refuses to start,
//! breaks its channel or stops taking frames is stopped (`kill`): its
//! thread suspended, bus mastering off and read back, the device reset
//! (FLR) where it can be, netd told to let go of the channel; once both
//! are done its memory is reclaimed, and a new instance started after a
//! backoff, at most `nic_max_restarts` an hour.  The channel stays, as
//! does the uplink's switch: the restart is invisible but for the lost
//! frames and the carrier going down and up on dom0's port.

use core::sync::atomic::Ordering;

use l4h_abi as abi;
use l4h_host::errno::Errno;
use l4h_host::fixed::ArrayVec;
use l4h_host::mailbox::RING;
use l4h_host::nicd::{self, Ids, Manifest, call::Request};
use l4h_host::{self as host, net, uplink, wire, wiring};
use sel4::{CapRights, ObjectBlueprint, VmAttributes, cap, cap_type};

use crate::blkd::{BarCache, bar_pages, carve_bars, is_legacy_virtio, is_modern_virtio, keep_bits, mappable, virtio_bar_mask, virtio_regions};
use crate::component::{self, Component, SpawnArgs, abs_of, root_cap};
use crate::drivers::Drivers;
use crate::iommu::Domain;
use crate::mailbox::{self, Mailbox};
use crate::mem::{Arena, Dest};
use crate::vspace::FRAME_BP;
use crate::{Host, ctl, pci};

const PAGE: usize = 4096;
pub const MAX_NICS: usize = net::MAX_UPLINKS;
/// How long an FLR takes before the function may be touched (PCIe 6.0
/// §6.6.2).
const FLR_MS: u64 = 100;
/// Configuration-space requests root answers for a nicd per tick
/// (TIMER_MS).
const CFG_PER_TICK: u32 = 32;
/// A nicd that has not answered a Ping for this long is hung: restarted.
const HANG_SECS: u64 = 5;
/// A nicd that has not come up this long after its start is restarted
/// (an X550's link alone takes 7 s; mlx5's firmware longer).
const START_SECS: u64 = 120;
/// Restart backoff: 1 s, doubling, at most this.
const BACKOFF_MAX_SECS: u64 = 60;
/// Root slot owners (mem::Slots::track) of the nicds' objects, after
/// vmmgr's guests and zombies (vmmgr.rs).
const fn slot_owner(n: usize) -> usize {
    2 * crate::MAX_GUESTS + 1 + n
}
const _: () = assert!(slot_owner(MAX_NICS) < crate::mem::GLOBAL as usize);

/// The driver bundle.
static mut DRIVERS: Drivers = Drivers::new();

pub fn drivers() -> &'static mut Drivers {
    // Root has one thread, and a function takes its reference again after
    // any call that takes one of its own.
    unsafe { &mut *(&raw mut DRIVERS) }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    /// No driver: left alone (as the firmware left it, decoding off).
    Unbound,
    /// Its nicd runs and has not published a good offer yet.
    Starting,
    Up,
    /// Being stopped: waiting for the FLR and for netd to let go.
    Stopping,
    /// Stopped; started again at `retry_at`.
    Backoff,
    /// Bound, but not driven until rebound or reboot: why is in `why`.
    Failed,
}

/// What follows a stop.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Then {
    Restart,
    /// Unbound: by dom0, or the driver refused the device.
    Unbind,
    Fail,
    /// Bound to another driver (dom0's bind).
    Rebind(usize),
}

/// A pending request to the nicd.
#[derive(Clone, Copy)]
enum Op {
    Start,
    Ping,
    /// A control message, for vmmgr op `token`.
    Ctl(usize),
}

/// A running nicd.
struct Inst {
    comp: Component,
    arena: Arena,
    mailbox: Mailbox<nicd::call::Proto>,
    ops: [Option<Op>; RING],
    /// Its notification, badged badges::nicd::TIMER, if it asked for one.
    timer: Option<cap::Notification>,
    /// The control page (root's frame, which the nicd maps).
    ctl_page: cap::Granule,
    /// The answer to its last control message: its length.
    ctl_len: usize,
    /// Its last configuration-space request's sequence number, and how
    /// many more root answers before its next tick.
    cfg_seq: u32,
    cfg_budget: u32,
}

/// The uplink channel: root's frames, kept from the first bind until
/// reboot, mapped into netd once and into each nicd.
/// A NIC's DMA region: root's, made at its first spawn and kept until
/// reboot, mapped in the device's IOMMU domain for good.  A device that a
/// restart could not reset may still use addresses its last driver gave
/// it: they are in this region, which nothing else ever gets.
#[derive(Clone, Copy)]
struct DmaRegion {
    frames: cap::CNode,
    bits: usize,
    paddr: usize,
    size: usize,
}

struct Chan {
    frames: cap::CNode,
    bits: usize,
    pages: usize,
    data_bits: u32,
}

pub struct Nic {
    pub pci: pci::Device,
    pub ids: Ids,
    pub driver: Option<usize>,
    pub state: State,
    pub why: &'static str,
    /// Outside the TCB (module doc).
    pub confined: bool,
    /// Its isolation group: functions that may reach each other without
    /// the IOMMU, by BDF.
    group: ArrayVec<u16, 64>,
    bars: BarCache,
    dom: Option<Domain>,
    /// Its vector, and the MSI address and data that send it, once bound.
    msi: Option<(u64, u64, u32)>,
    irq: Option<cap::IrqHandler>,
    io: Option<cap::Null>,
    chan: Option<Chan>,
    dma: Option<DmaRegion>,
    /// The driver whose instances last had the DMA region: another gets
    /// it cleared first.
    dma_driver: Option<usize>,
    inst: Option<Inst>,
    /// The MAC its first instance offered, which root checked: later
    /// instances must offer the same.
    pub mac: Option<u64>,
    /// netd's AddUplinks of the channel, as root posted them: the
    /// generation netd publishes with the channel's state.
    generation: u32,
    /// netd maps the channel and holds it (AddUplink posted, no
    /// RemoveUplink answered since).
    in_netd: bool,
    /// AddUplink waits for room in netd's mailbox (`tick` posts it).
    add_pending: bool,
    /// When this instance was started (Starting has a time limit).
    started_at: u64,
    /// dom0 asked for the restart: not counted, and no backoff.
    manual: bool,
    removing: bool,
    reset_until: u64,
    /// The header dwords an FLR clears (SAVED), as the firmware left them
    /// at boot: what root restores after a reset, whatever a driver did.
    saved: [u32; 8],
    /// And of the PCI Express capability: its offset, how many of
    /// PCIE_SAVED it has, and Device Control, Link Control, Device
    /// Control 2 and Link Control 2.
    pcie_saved: Option<(u8, usize, [u16; 4])>,
    then: Then,
    /// Restarts in the hour since `window_start`; the backoff.
    restarts: usize,
    window_start: u64,
    backoff_secs: u64,
    retry_at: u64,
    /// When the Ping not answered yet was posted (Op::Ping).
    ping_at: Option<u64>,
    /// Dom0's pin from the configuration: Some(None) to leave it unbound.
    pin: Option<Option<&'static str>>,
}

/// The network devices root found, in .bss.
static mut NICS: ArrayVec<Nic, MAX_NICS> = ArrayVec::new();

pub fn nics() -> &'static mut ArrayVec<Nic, MAX_NICS> {
    unsafe { &mut *(&raw mut NICS) }
}

pub fn bdf(d: &pci::Device) -> u32 {
    crate::netd::bdf(d)
}

/// A function root lists as a network device: one some driver of the
/// bundle matches, or that `nic_bind` names (a driver dom0 loads later may
/// take it).  Others stay the firmware's, and take no NIC number.
pub fn is_network(d: &pci::Device, ids: &Ids, pinned: bool) -> bool {
    let _ = d;
    pinned || drivers().matching(ids, |_| true).is_some()
}

pub fn ids_of(d: &pci::Device, pci: &pci::Pci) -> Ids {
    let sub = pci.read32(d.bus, d.dev, d.func, 0x2c);
    Ids {
        vendor: d.vendor,
        device: d.device,
        subvendor: sub as u16,
        subdevice: (sub >> 16) as u16,
        class: (d.class as u32) << 16 | (d.subclass as u32) << 8 | d.prog_if as u32,
        revision: d.revision,
    }
}

/// Boot: list `d`.  False if there are MAX_NICS already.
pub fn found(d: pci::Device, ids: Ids, pin: Option<Option<&'static str>>, pci: &pci::Pci) -> bool {
    let ns = nics();
    if ns.is_full() {
        log!("l4h-root: more than {} network devices, {:02x}:{:02x}.{} ignored", MAX_NICS, d.bus, d.dev, d.func);
        return false;
    }
    // Off until its driver starts, if one will: one no driver takes, or
    // that the configuration leaves to the firmware, stays as it is.
    if pin != Some(None) && drivers().matching(&ids, |_| true).is_some() {
        pci.disable(&d);
    }
    ns.must_push(Nic {
        pci: d,
        ids,
        driver: None,
        state: State::Unbound,
        why: "",
        confined: false,
        group: ArrayVec::new(),
        bars: [const { None }; 6],
        dom: None,
        msi: None,
        irq: None,
        io: None,
        chan: None,
        dma: None,
        dma_driver: None,
        inst: None,
        mac: None,
        generation: 0,
        in_netd: false,
        add_pending: false,
        started_at: 0,
        manual: false,
        removing: false,
        reset_until: 0,
        saved: core::array::from_fn(|k| pci.read32(d.bus, d.dev, d.func, SAVED[k])),
        pcie_saved: pcie_saved_of(pci, &d).map(|(c, k)| (c, k, core::array::from_fn(|i| if i < k { pci.read16(d.bus, d.dev, d.func, c + PCIE_SAVED[i]) } else { 0 }))),
        then: Then::Restart,
        restarts: 0,
        window_start: 0,
        backoff_secs: 1,
        retry_at: 0,
        ping_at: None,
        pin,
    });
    true
}

// ---------------------------------------------------------------------
// What a driver needs of a device.

/// The device as a driver with manifest `m` sees it: each BAR it maps cut
/// to the manifest's window (a BAR is a power of two, so its start is).
fn windowed(d: &pci::Device, m: &Manifest) -> pci::Device {
    let mut w = *d;
    for b in w.bars.iter_mut() {
        if !b.is_io {
            b.size = b.size.min(1 << m.bar_window_bits);
        }
    }
    w
}

/// The BARs root maps for driver `m` of `d`, bit b for BAR b; Err if the
/// device lacks what the driver needs.
fn bars_for(d: &pci::Device, m: &Manifest) -> Result<u8, &'static str> {
    let w = windowed(d, m);
    let mem = |b: usize| !w.bars[b].is_io && w.bars[b].size != 0;
    let msix = d.msix.ok_or("no MSI-X")?;
    if (msix.table_size as u16) < m.msix_min {
        return Err("too few MSI-X entries");
    }
    let mut bars = 0u8;
    for b in 0..6 {
        if m.bars & 1 << b != 0 {
            if !mem(b) {
                return Err("a BAR the driver needs is missing");
            }
            bars |= 1 << b;
        } else if m.bars_opt & 1 << b != 0 && mem(b) && d.bars[b].size <= 1 << m.bar_window_bits {
            bars |= 1 << b;
        }
    }
    if m.flags & nicd::F_VIRTIO != 0 {
        if is_modern_virtio(d) {
            bars |= virtio_bar_mask(d);
        } else if !(m.flags & nicd::F_LEGACY_IO != 0 && is_legacy_virtio(d)) {
            return Err("not a virtio device the driver takes");
        }
    }
    bars |= 1 << msix.table_bar;
    // The table, whole, inside what is mapped of its BAR.
    if msix.table_offset as u64 + msix.table_size as u64 * 16 > w.bars[msix.table_bar as usize].size {
        return Err("its MSI-X table is outside the mapped BAR");
    }
    if !mappable(&w, bars) {
        return Err("a BAR is not mappable");
    }
    Ok(bars)
}

// ---------------------------------------------------------------------
// Isolation groups (DESIGN.md §9.8, "Confinement").

/// Compute every NIC's isolation group, from the PCI topology root found
/// (`inventory`): the functions that share a path to the root complex
/// that does not isolate them (no ACS where it matters), and the other
/// functions of a multi-function device without ACS.
pub fn groups(h: &mut Host) {
    for i in 0..nics().len() {
        let g = group_of(h, nics()[i].pci);
        nics()[i].group = g;
    }
}

#[cfg(target_arch = "x86_64")]
fn group_of(h: &Host, d: pci::Device) -> ArrayVec<u16, 64> {
    let mut group = ArrayVec::new();
    let mut add = |b: u16| {
        if !group.contains(&b) && group.push(b).is_err() {
            // More than a group holds: one too large to check counts as
            // shared with something else.
            let _ = group.pop();
            let _ = group.push(u16::MAX);
        }
    };
    let me = bdf(&d) as u16;
    // Every function root found, however many: one left out could be a
    // bridge or peer the walk must see.
    let functions = || h.pci_inventory.iter().map(|p| p.bdf);
    crate::acs::group(&h.pci, functions, me, &mut add);
    // And every function whose DMA the IOMMU translates as the same
    // requester's: they share the NIC's domain, whatever ACS does.
    let requester = h.iommu.requester(me);
    for f in functions().filter(|&f| h.iommu.requester(f) == requester) {
        add(f);
    }
    group
}

#[cfg(target_arch = "aarch64")]
fn group_of(_h: &Host, d: pci::Device) -> ArrayVec<u16, 64> {
    // No IOMMU there: nothing is confined anyway.
    let mut g = ArrayVec::new();
    g.must_push(bdf(&d) as u16);
    g
}

/// A virtio device, whose DMA its driver may take past the IOMMU (by not
/// negotiating ACCESS_PLATFORM): a virtio PCI id (transitional 0x1000..,
/// modern 0x1040..0x107f), or virtio 1.x structures under any vendor's id
/// (hardware virtio, as vDPA NICs).
fn is_virtio(d: &pci::Device) -> bool {
    (d.vendor == 0x1af4 && (0x1000..=0x107f).contains(&d.device)) || is_modern_virtio(d)
}

/// Whether NIC `i` would be confined bound to `driver`: an IOMMU with
/// interrupt remapping, and every other function of its group unused by
/// the host or a NIC of the same driver.
fn confined(h: &Host, i: usize, driver: usize) -> bool {
    let [state, remap, ..] = h.iommu.info();
    if state != abi::IOMMU_ON || remap == 0 {
        return false;
    }
    // A partition sees only its own functions, not the bridges and other
    // partitions' functions its groups would need: none is confined.
    if crate::partition::get().is_some() {
        return false;
    }
    // A virtio device's DMA goes through the IOMMU only if its driver
    // negotiates ACCESS_PLATFORM (a legacy one's never does), and the
    // driver is what is not trusted: its own choice could bypass the
    // IOMMU, so a virtio NIC's driver is never confined.  The device
    // says what it is, not the driver's manifest: a driver dom0 loaded
    // could match a virtio device without F_VIRTIO.
    let n = &nics()[i];
    if is_virtio(&n.pci) || drivers().drivers[driver].manifest.flags & nicd::F_VIRTIO != 0 {
        return false;
    }
    // A device behind no IOMMU unit gets no domain: its DMA is
    // untranslated.
    if !matches!(n.dom, Some(d) if d != Domain::None) {
        return false;
    }
    n.group.iter().all(|&f| {
        if f == u16::MAX {
            return false;
        }
        if f == bdf(&n.pci) as u16 {
            return true;
        }
        if let Some(o) = nics().iter().find(|o| bdf(&o.pci) as u16 == f) {
            return o.driver.is_none() || o.driver == Some(driver);
        }
        h.pci_inventory.iter().find(|p| p.bdf == f).is_none_or(|p| matches!(p.owner, abi::PCI_OWNER_NONE | abi::PCI_OWNER_ROOT))
    })
}

// ---------------------------------------------------------------------
// Binding.

/// Boot: bind every NIC by the configuration (`nic_bind`, `nic_auto`).
pub fn boot(h: &mut Host) {
    groups(h);
    for i in 0..nics().len() {
        let n = &nics()[i];
        let choice = match n.pin {
            Some(None) => continue,
            Some(Some(name)) => match drivers().find(name) {
                Some(d) => Some(d),
                None => {
                    log!("l4h-root: nic {}: no driver {} in the bundle", i, name);
                    continue;
                }
            },
            None if h.cfg.nic_auto => None,
            None => continue,
        };
        if let Err(why) = bind(h, i, choice) {
            let p = &nics()[i].pci;
            info!("l4h-root: nic {} ({:02x}:{:02x}.{} {:04x}:{:04x}): not bound: {}", i, p.bus, p.dev, p.func, p.vendor, p.device, why);
        }
    }
}

/// Whether driver `d` may drive NIC `i` (not checking the device).
fn allowed(h: &Host, i: usize, d: usize) -> Result<(), &'static str> {
    let drv = &drivers().drivers[d];
    if confined(h, i, d) {
        return Ok(());
    }
    // Not confined, the driver is TCB code: only a measured one.  Wi-Fi
    // drivers parse what anyone in radio range sends: never in the TCB.
    if drv.manifest.class == nicd::CLASS_WIFI {
        return Err("a Wi-Fi driver runs only confined (IOMMU, interrupt remapping, isolation group)");
    }
    if !drv.boot {
        return Err("a driver dom0 loaded runs only confined (IOMMU, interrupt remapping, isolation group)");
    }
    Ok(())
}

/// Whether NIC `i` may run driver `d` without breaking another NIC's
/// confinement: one confined (or that may run again, Failed with its
/// driver kept) with this one in its group stays so only with the same
/// driver here.
fn group_free(i: usize, d: usize) -> Result<(), &'static str> {
    let me = bdf(&nics()[i].pci) as u16;
    let mine = &nics()[i].group;
    if nics().iter().enumerate().any(|(j, o)| j != i && o.confined && o.driver.is_some_and(|od| od != d)
        && o.state != State::Unbound && (o.group.contains(&me) || mine.contains(&(bdf(&o.pci) as u16)))) {
        return Err("another driver's NIC shares its isolation group, confined");
    }
    Ok(())
}

/// Bind NIC `i` to `driver`, or the first that matches, and start it.
pub fn bind(h: &mut Host, i: usize, driver: Option<usize>) -> Result<(), &'static str> {
    nics().get(i).ok_or("no such NIC")?;
    // Its IOMMU domain, which confinement needs (made once).
    if nics()[i].dom.is_none() {
        let dom = h.iommu.attach(&mut h.alloc, &nics()[i].pci);
        nics()[i].dom = Some(dom);
    }
    let n = &nics()[i];
    match (n.state, driver) {
        (State::Unbound | State::Failed, _) => {}
        // Another driver for a running NIC: stopped, then bound anew.
        (State::Starting | State::Up, Some(d)) if n.driver != Some(d) => {
            if drivers().drivers[d].manifest.matching(&n.ids).is_none() {
                return Err("the driver does not match the device");
            }
            allowed(h, i, d)?;
            group_free(i, d)?;
            // What the new driver needs of what stays the NIC's (BARs as
            // carved, the DMA region): checked before the running one goes.
            let m = drivers().drivers[d].manifest;
            let bars = bars_for(&n.pci, &m)?;
            let w = windowed(&n.pci, &m);
            if (0..6u8).filter(|b| bars & 1 << b != 0).any(|b| n.bars[b as usize].as_ref().is_some_and(|r| r.len() * PAGE < w.bars[b as usize].size as usize)) {
                return Err("its BARs were mapped for a driver with a smaller window: reboot to change");
            }
            if n.dma.is_some_and(|r| r.size != 1 << m.dma_bits) {
                return Err("its DMA region was made for a driver that wanted another size: reboot to change");
            }
            kill(h, i, Then::Rebind(d), "rebound by dom0");
            return Ok(());
        }
        _ => return Err("bound already"),
    }
    let ids = n.ids;
    let d = match driver {
        Some(d) => {
            if drivers().drivers[d].manifest.matching(&ids).is_none() {
                return Err("the driver does not match the device");
            }
            d
        }
        None => {
            let mut found = None;
            for d in 0..drivers().drivers.len() {
                if drivers().drivers[d].manifest.matching(&ids).is_some() && allowed(h, i, d).is_ok() {
                    found = Some(d);
                    break;
                }
            }
            found.ok_or("no driver matches")?
        }
    };
    allowed(h, i, d)?;
    group_free(i, d)?;
    let n = &nics()[i];
    let m = drivers().drivers[d].manifest;
    let bars = bars_for(&n.pci, &m)?;
    let w = windowed(&n.pci, &m);
    let n = &mut nics()[i];
    if !carve_bars(&mut h.alloc, &mut h.devmem, &w, &mut n.bars, bars) {
        return Err("its BARs are not free device memory");
    }
    // Carved for an earlier driver's smaller window: as much is all this
    // one can have.
    if (0..6u8).filter(|b| bars & 1 << b != 0).any(|b| (crate::blkd::bar_frames(&n.bars, b).len() * PAGE) < w.bars[b as usize].size as usize) {
        return Err("its BARs were mapped for a driver with a smaller window: reboot to change");
    }
    if n.msi.is_none() {
        let v = pci::vector_alloc().ok_or("no interrupt vector left")?;
        let dom = n.dom.unwrap();
        let n = &mut nics()[i];
        let (a, data) = h.iommu.msi(dom, v);
        n.msi = Some((v, a, data));
    }
    let n = &mut nics()[i];
    n.driver = Some(d);
    n.confined = confined(h, i, d);
    n.restarts = 0;
    n.backoff_secs = 1;
    n.why = "";
    if let Err(why) = spawn(h, i) {
        let n = &mut nics()[i];
        n.state = State::Failed;
        n.why = why;
        return Err(why);
    }
    let n = &nics()[i];
    let p = &n.pci;
    info!("l4h-root: nic {} ({:02x}:{:02x}.{} {:04x}:{:04x}): driver {}, {}", i, p.bus, p.dev, p.func, p.vendor, p.device,
        drivers().drivers[d].manifest.name(), if n.confined { "confined" } else { "trusted (not confined)" });
    Ok(())
}

/// Unbind NIC `i` (dom0's `nic unbind`): its nicd stopped, the device off.
pub fn unbind(h: &mut Host, i: usize) -> Result<(), Errno> {
    let n = nics().get_mut(i).ok_or(ctl::ENOENT)?;
    match n.state {
        State::Unbound => Ok(()),
        State::Failed | State::Backoff => {
            n.state = State::Unbound;
            n.driver = None;
            n.mac = None;
            Ok(())
        }
        State::Stopping => {
            n.then = Then::Unbind;
            Ok(())
        }
        State::Starting | State::Up => {
            kill(h, i, Then::Unbind, "unbound by dom0");
            Ok(())
        }
    }
}

/// Restart NIC `i`'s nicd (dom0's `nic restart`): a fresh instance now,
/// not counted against the restart limit.
pub fn restart(h: &mut Host, i: usize) -> Result<(), Errno> {
    let n = nics().get_mut(i).ok_or(ctl::ENOENT)?;
    match n.state {
        State::Starting | State::Up => {
            n.manual = true;
            kill(h, i, Then::Restart, "restarted by dom0");
        }
        State::Backoff | State::Failed if n.driver.is_some() => {
            n.retry_at = 0;
            n.state = State::Backoff;
            n.restarts = 0;
        }
        _ => return Err(ctl::EINVAL),
    }
    Ok(())
}

// ---------------------------------------------------------------------
// A nicd's life.

fn alloc_channel(h: &mut Host, i: usize, data_bits: u32) -> Result<(), &'static str> {
    let size = uplink::channel_size(data_bits);
    let pages = size / PAGE;
    let bits = keep_bits(pages);
    let chan = h.alloc.global(|alloc| -> Option<Chan> {
        let mut arena = alloc.arena(size + (64 << bits) + PAGE)?;
        let frames = arena.object_cap::<cap_type::CNode>(alloc, ObjectBlueprint::CNode { size_bits: bits });
        // In batches: each fits a region of the arena.
        let mut done = 0;
        while done < pages {
            let k = (pages - done).min(256);
            if arena.retype(alloc, &FRAME_BP, k, Dest { cnode: abs_of(frames), offset: done }).is_none() {
                alloc.release(arena);
                return None;
            }
            done += k;
        }
        // Root's until reboot: the arena is never released.
        core::mem::forget(arena);
        Some(Chan { frames, bits, pages, data_bits })
    }).ok_or("no memory for its channel")?;
    nics()[i].chan = Some(chan);
    // netd maps it once, for good.
    let c = nics()[i].chan.as_ref().unwrap();
    h.netd.map_uplink(i, c.frames, c.bits, c.pages, &mut h.alloc).map_err(|_| "netd cannot map its channel")
}

/// Make NIC `i`'s DMA region, 2^bits bytes, and map it in its device's
/// IOMMU domain, both for good (DmaRegion).
fn alloc_dma(h: &mut Host, i: usize, bits: usize) -> Result<(), &'static str> {
    let dom = nics()[i].dom.unwrap();
    let r = h.alloc.global(|alloc| -> Option<DmaRegion> {
        let slot = alloc.slots.alloc();
        let Some(mut region) = alloc.split(bits, slot) else {
            alloc.slots.free(slot);
            return None;
        };
        let pages = (1usize << bits) / PAGE;
        let cn_bits = keep_bits(pages);
        let cn_slot = alloc.object(ObjectBlueprint::CNode { size_bits: cn_bits });
        let frames = root_cap::<cap_type::CNode>(cn_slot);
        region.retype(&FRAME_BP, pages, Dest { cnode: abs_of(frames), offset: 0 })?;
        Some(DmaRegion { frames, bits: cn_bits, paddr: region.paddr, size: 1 << bits })
    }).ok_or("no memory for its DMA region")?;
    h.iommu.map(&mut h.alloc, dom, r.paddr, r.size, true);
    nics()[i].dma = Some(r);
    Ok(())
}

/// Zero the channel's header and rings: a fresh channel for netd and the
/// nicd (the data areas need not be: they hold only what both saw).
fn reset_channel(h: &mut Host, i: usize) {
    let c = nics()[i].chan.as_ref().unwrap();
    for p in 0..uplink::DATA_OFFSET / PAGE {
        let f = c.frames.absolute_cptr_from_bits_with_depth(p as u64, c.bits);
        h.wins.a.with_frame(&f, |page| unsafe { core::ptr::write_bytes(page, 0, PAGE) });
    }
}

/// The configuration space, as the nicd's snapshot shows it.
fn snapshot(pci: &pci::Pci, d: &pci::Device, page: *mut u8) {
    for off in (0..256).step_by(4) {
        let v = pci.read32(d.bus, d.dev, d.func, off as u8);
        unsafe { (page.add(off) as *mut u32).write(v) };
    }
    #[cfg(target_arch = "x86_64")]
    for off in (256..4096).step_by(4) {
        let v = pci.read_ext32(bdf(d) as u16, off as u16).unwrap_or(0);
        unsafe { (page.add(off) as *mut u32).write(v) };
    }
}

/// Start a new nicd for NIC `i`, bound already: its memory, its
/// capabilities, then Start.
fn spawn(h: &mut Host, i: usize) -> Result<(), &'static str> {
    let d = nics()[i].driver.unwrap();
    // What its group holds may have changed since the bind.
    allowed(h, i, d)?;
    group_free(i, d)?;
    nics()[i].confined = confined(h, i, d);
    let n = &nics()[i];
    let m = drivers().drivers[d].manifest;
    let elf = drivers().drivers[d].elf;
    if n.chan.is_none() {
        alloc_channel(h, i, m.channel_bits())?;
    }
    reset_channel(h, i);
    let dma_bits = m.dma_bits as usize;
    let dma = 1usize << dma_bits;
    let image = (1usize << m.image_max_bits) + m.firmware.iter().filter_map(|f| drivers().firmware(f)).map(|b| b.len()).sum::<usize>();
    // The image, its keep CNode (a slot a page of every mapping) and page
    // tables, a lot of each for the BAR windows.
    let maps = bars_for(&nics()[i].pci, &m).map_or(0, |b| bar_pages(&windowed(&nics()[i].pci, &m), b)) + dma / PAGE;
    if !h.can_afford(image + (4 << 20) + maps * 64 + maps / 512 * PAGE, 1, 1024) {
        return Err("no memory for it");
    }
    if nics()[i].dma.is_none() {
        alloc_dma(h, i, dma_bits)?;
    }
    let dma_region = nics()[i].dma.unwrap();
    if dma_region.size != dma {
        return Err("its DMA region was made for a driver that wanted another size: reboot to change");
    }
    // Another driver's buffers and descriptors are not this one's to see.
    if nics()[i].dma_driver.is_some_and(|o| o != d) {
        for p in 0..dma / PAGE {
            let f = dma_region.frames.absolute_cptr_from_bits_with_depth(p as u64, dma_region.bits);
            h.wins.a.with_frame(&f, |page| unsafe { core::ptr::write_bytes(page, 0, PAGE) });
        }
    }
    nics()[i].dma_driver = Some(d);
    let n = &nics()[i];
    let pdev = n.pci;
    let bars = bars_for(&pdev, &m)?;
    let w = windowed(&pdev, &m);
    let (vector, msi_address, msi_data) = n.msi.unwrap();
    let chan_bits = n.chan.as_ref().unwrap().data_bits;

    h.alloc.slots.track(slot_owner(i));
    let built = (|| -> Result<Inst, &'static str> {
        let mut arena = h.alloc.arena(image + (2 << 20)).ok_or("no memory for it")?;
        let DmaRegion { frames: dma_cn, bits: dma_cn_bits, paddr: dma_paddr, .. } = dma_region;
        let dma_pages = dma / PAGE;

        // Its configuration.
        let none = host::blk::PciRegion { va: 0, len: 0 };
        let bar_va = |b: u8| nicd::bar_va(b as usize);
        let mut cfg = nicd::Config {
            uplink: i as u32,
            pci_bdf: bdf(&pdev),
            vendor: pdev.vendor,
            device: pdev.device,
            subvendor: nics()[i].ids.subvendor,
            subdevice: nics()[i].ids.subdevice,
            class: nics()[i].ids.class,
            revision: pdev.revision as u32,
            flags: if nics()[i].confined { nicd::CONFINED } else { 0 },
            msi_address,
            msi_data,
            msix_entries: pdev.msix.map_or(0, |m| m.table_size as u32),
            msix_table: none,
            bars: core::array::from_fn(|b| if bars & 1 << b != 0 {
                host::blk::PciRegion { va: bar_va(b as u8) as u64, len: w.bars[b].size }
            } else { none }),
            legacy_io: 0,
            notify_off_multiplier: 0,
            common: none,
            notify: none,
            isr: none,
            device_cfg: none,
            dma_paddr: dma_paddr as u64,
            dma_size: dma as u64,
            channel_bits: chan_bits,
            reserved: 0,
            firmware: [none; nicd::MAX_FIRMWARE],
        };
        // Firmware blobs: copies in frames of its own, read-only to it.
        let mut blobs: [Option<&'static [u8]>; nicd::MAX_FIRMWARE] = [None; nicd::MAX_FIRMWARE];
        for (k, name) in m.firmware.iter().enumerate() {
            if name[0] == 0 {
                continue;
            }
            match drivers().firmware(name) {
                Some(b) if b.len() <= nicd::FIRMWARE_MAX => {
                    blobs[k] = Some(b);
                    cfg.firmware[k] = host::blk::PciRegion { va: nicd::firmware_va(k) as u64, len: b.len() as u64 };
                }
                _ => log!("l4h-root: nic {}: no firmware {} in the bundle", i, crate::drivers::name(name)),
            }
        }
        let msix = pdev.msix.unwrap();
        cfg.msix_table = host::blk::PciRegion {
            va: (bar_va(msix.table_bar) + msix.table_offset as usize) as u64,
            len: msix.table_size as u64 * 16,
        };
        if m.flags & nicd::F_VIRTIO != 0 && is_modern_virtio(&pdev) {
            let r = virtio_regions(&pdev, bar_va);
            (cfg.common, cfg.notify, cfg.notify_off_multiplier, cfg.isr, cfg.device_cfg) = (r.common, r.notify, r.notify_mult, r.isr, r.device);
        }
        let legacy = m.flags & nicd::F_LEGACY_IO != 0 && is_legacy_virtio(&pdev);
        if legacy {
            cfg.legacy_io = pdev.bars[0].addr as u32;
        }
        let cfg_bytes = unsafe {
            core::slice::from_raw_parts(&cfg as *const nicd::Config as *const u8, core::mem::size_of::<nicd::Config>())
        };
        let args = SpawnArgs {
            id: nicd::NICD_ID_BASE + i as u32,
            kind: host::KIND_NICD,
            elf,
            prio: host::PRIO_SERVICE,
            budget_us: h.info.timeslice_us,
            period_us: h.info.timeslice_us,
            config: cfg_bytes,
            ntfn: None,
            service_ep: None,
            cnode: None,
            cnode_bits: None,
        };
        // Spread across the cores, netd's core (0) last.
        let core = if h.info.cores > 1 { 1 + i % (h.info.cores - 1) } else { 0 };
        let comp = component::create(&args, &mut h.alloc, &mut arena, &mut h.wins.a,
            &mut |alloc, vspace| h.asids.assign(alloc, vspace), &h.info.spawn_context(core));

        let chan = nics()[i].chan.as_ref().unwrap();
        let fw_pages: usize = blobs.iter().flatten().map(|b| b.len().div_ceil(PAGE)).sum();
        let pages = bar_pages(&w, bars) + dma_pages + chan.pages + fw_pages + 2 + host::mailbox::MAILBOX_PAGES;
        let kb = keep_bits(pages);
        let keep = arena.object_cap::<cap_type::CNode>(&mut h.alloc, ObjectBlueprint::CNode { size_bits: kb });
        let mut next = 0u64;
        let mut keep_slot = || {
            next += 1;
            keep.absolute_cptr_from_bits_with_depth(next - 1, kb)
        };
        // A BAR's frames were carved at the first bind, for that driver's
        // window: this one maps no more of them than its own.
        let msix_bar = 1u8 << pdev.msix.unwrap().table_bar;
        for b in (0..6).filter(|b| bars & 1 << b != 0) {
            let frames = crate::blkd::bar_frames(&nics()[i].bars, b);
            let attrs = if (m.bars_wc & !msix_bar) & 1 << b != 0 { crate::blkd::wc_attrs() } else { crate::blkd::DEVICE_ATTRS };
            for (p, f) in frames.take((w.bars[b as usize].size as usize).div_ceil(PAGE)).map(crate::devmem::granule).enumerate() {
                comp.map_copy(&mut h.alloc, &mut arena, &abs_of(f), bar_va(b) + p * PAGE, CapRights::read_write(), attrs, keep_slot());
            }
        }
        for p in 0..dma_pages {
            let f = dma_cn.absolute_cptr_from_bits_with_depth(p as u64, dma_cn_bits);
            comp.map_copy(&mut h.alloc, &mut arena, &f, nicd::DMA_VA + p * PAGE, CapRights::read_write(), VmAttributes::DEFAULT, keep_slot());
        }
        for p in 0..chan.pages {
            let f = chan.frames.absolute_cptr_from_bits_with_depth(p as u64, chan.bits);
            comp.map_copy(&mut h.alloc, &mut arena, &f, nicd::CHANNEL_VA + p * PAGE, CapRights::read_write(), VmAttributes::DEFAULT, keep_slot());
        }
        for (k, b) in blobs.iter().enumerate() {
            let Some(b) = b else { continue };
            for (p, chunk) in b.chunks(PAGE).enumerate() {
                let f = arena.object_cap::<cap_type::Granule>(&mut h.alloc, FRAME_BP);
                h.wins.a.with_frame(&abs_of(f), |dst| unsafe { core::ptr::copy_nonoverlapping(chunk.as_ptr(), dst, chunk.len()) });
                comp.map_copy(&mut h.alloc, &mut arena, &abs_of(f), nicd::firmware_va(k) + p * PAGE, CapRights::read_only(),
                    VmAttributes::DEFAULT, keep_slot());
            }
        }
        // The control page and the configuration-space snapshot.
        let ctl_page = arena.object_cap::<cap_type::Granule>(&mut h.alloc, FRAME_BP);
        comp.map_copy(&mut h.alloc, &mut arena, &abs_of(ctl_page), nicd::CTL_VA, CapRights::read_write(), VmAttributes::DEFAULT, keep_slot());
        let cfg_page = arena.object_cap::<cap_type::Granule>(&mut h.alloc, FRAME_BP);
        let pci = &h.pci;
        h.wins.a.with_frame(&abs_of(cfg_page), |page| snapshot(pci, &pdev, page));
        comp.map_copy(&mut h.alloc, &mut arena, &abs_of(cfg_page), nicd::CFG_VA, CapRights::read_only(), VmAttributes::DEFAULT, keep_slot());
        let mailbox = Mailbox::new(&comp, mailbox::nicd_mailbox(i), &wiring::ROOT_NICD_CALL, &wiring::NICD_DONE, &mut h.alloc, &mut arena, &mut keep_slot);

        // The interrupt: one handler for the device, root's until reboot,
        // pointed at each instance's notification.
        let n = &mut nics()[i];
        if n.irq.is_none() {
            let s = h.alloc.slots.global(|s| s.alloc());
            pci::msi_irq(&pdev, vector, &abs_of(root_cap::<cap_type::Null>(s)));
            n.irq = Some(root_cap::<cap_type::IrqHandler>(s));
        }
        let irq = n.irq.unwrap();
        let irq_ntfn = root_cap::<cap_type::Notification>(h.alloc.slots.alloc());
        component::mint_edge(&abs_of(irq_ntfn), &wiring::IRQ_NICD, 0, &comp.obj()).expect("nicd IRQ notification");
        let _ = irq.irq_handler_clear();
        irq.irq_handler_set_notification(irq_ntfn).expect("nicd IRQ set notification");
        // One the last instance left unacknowledged.
        let _ = irq.irq_handler_ack();
        comp.give(nicd::NICD_SLOT_IRQ, irq, CapRights::all());
        if legacy {
            let n = &mut nics()[i];
            if n.io.is_none() {
                let (base, len) = (pdev.bars[0].addr as u16, pdev.bars[0].size as u16);
                n.io = h.alloc.global(|alloc| pci::io_ports(alloc, base, len));
            }
            match nics()[i].io {
                Some(io) => comp.give(nicd::NICD_SLOT_IOPORT, io, CapRights::all()),
                None => log!("l4h-root: nic {}: no I/O ports at {:#x}", i, pdev.bars[0].addr),
            }
        }
        // netd's notification, for the channel (netd gets the nicd's
        // below).
        h.netd.give_uplink_peer(&comp);
        let timer = (m.flags & nicd::F_TIMER != 0).then(|| {
            let t = root_cap::<cap_type::Notification>(h.alloc.slots.alloc());
            component::mint_edge(&abs_of(t), &wiring::ROOT_NICD_TIMER, 0, &comp.obj()).expect("nicd timer");
            t
        });
        Ok(Inst { comp, arena, mailbox, ops: [None; RING], timer, ctl_page, ctl_len: 0, cfg_seq: 0, cfg_budget: CFG_PER_TICK })
    })();
    h.alloc.slots.untrack();
    let mut inst = match built {
        Ok(inst) => inst,
        Err(why) => {
            h.alloc.slots.free_owned(slot_owner(i));
            return Err(why);
        }
    };
    if h.netd.signal_uplink(i, &inst.comp).is_err() {
        destroy(h, i, inst);
        return Err("netd refuses its channel");
    }
    // netd takes the fresh channel (it may already have been the uplink's).
    let n = &mut nics()[i];
    n.add_pending = h.netd.add_uplink(i, chan_bits).is_err();
    n.in_netd = !n.add_pending;
    if n.in_netd {
        n.generation = n.generation.wrapping_add(1);
    }
    // The device: decoding and bus mastering on, MSI-X on.
    if legacy_of(&pdev, &m) {
        h.pci.enable_io(&pdev);
    }
    h.pci.enable(&pdev);
    h.pci.enable_msix(&pdev);
    component::start(&inst.comp);
    let k = inst.mailbox.send(&Request::Start {}).expect("nicd mailbox room");
    inst.ops[k as usize % RING] = Some(Op::Start);
    let n = &mut nics()[i];
    n.inst = Some(inst);
    n.state = State::Starting;
    n.ping_at = None;
    n.started_at = crate::rdtsc();
    Ok(())
}

fn legacy_of(d: &pci::Device, m: &Manifest) -> bool {
    m.flags & nicd::F_LEGACY_IO != 0 && is_legacy_virtio(d)
}

/// Offsets in the PCI Express capability of what an FLR resets and root
/// restores: Device Control, Link Control, Device Control 2, Link
/// Control 2.
const PCIE_SAVED: [u8; 4] = [0x08, 0x10, 0x28, 0x30];

/// The PCI Express capability's offset and how many of PCIE_SAVED it has:
/// the controls 2 only from version 2 on (a version 1 capability, as
/// QEMU's 82574L has at 0xe0, ends at 0x14), and all of it within the
/// 256 bytes root reads.
fn pcie_saved_of(pci: &pci::Pci, d: &pci::Device) -> Option<(u8, usize)> {
    let c = pcie_cap_of(pci, d)?;
    let version = pci.read32(d.bus, d.dev, d.func, c) >> 16 & 0xf;
    let k = if version >= 2 { 4 } else { 2 };
    let k = (0..=k).rev().find(|&k| k == 0 || c as usize + PCIE_SAVED[k - 1] as usize + 2 <= 0x100)?;
    Some((c, k))
}

/// The PCI Express capability's offset, if the function has one.
fn pcie_cap(h: &Host, d: &pci::Device) -> Option<u8> {
    pcie_cap_of(&h.pci, d)
}

fn pcie_cap_of(pci: &pci::Pci, d: &pci::Device) -> Option<u8> {
    let mut off = (pci.read32(d.bus, d.dev, d.func, 0x34) & 0xfc) as u8;
    for _ in 0..48 {
        if off < 0x40 {
            return None;
        }
        let w = pci.read32(d.bus, d.dev, d.func, off);
        if w & 0xff == 0x10 {
            return Some(off);
        }
        off = ((w >> 8) & 0xfc) as u8;
    }
    None
}

/// The header dwords an FLR resets that root restores: the BARs, the ROM
/// BAR and the interrupt line (decoding stays off until a start).
const SAVED: [u8; 8] = [0x10, 0x14, 0x18, 0x1c, 0x20, 0x24, 0x30, 0x3c];

/// Start a Function Level Reset if the function has one: when root may
/// touch it again (now if none).
fn flr(h: &Host, d: &pci::Device) -> u64 {
    let Some(cap) = pcie_cap(h, d) else { return 0 };
    if h.pci.read32(d.bus, d.dev, d.func, cap + 4) & (1 << 28) == 0 {
        return 0;
    }
    let ctl = h.pci.read32(d.bus, d.dev, d.func, cap + 8);
    h.pci.write32(d.bus, d.dev, d.func, cap + 8, ctl | 1 << 15);
    crate::rdtsc() + h.info.tsc_hz / 1000 * FLR_MS
}

/// Stop NIC `i`'s nicd: suspended at once, its device unable to reach
/// memory, then reset; what happens next is `then`'s, once the reset is
/// over and netd has let go of the channel (`progress`).
fn kill(h: &mut Host, i: usize, then: Then, why: &'static str) {
    let n = &mut nics()[i];
    if n.state == State::Stopping {
        // Stopped already: only what follows can change.
        if n.then != Then::Fail {
            n.then = then;
        }
        return;
    }
    let Some(inst) = n.inst.as_mut() else { return };
    let _ = inst.comp.tcb.tcb_suspend();
    let p = n.pci;
    log!("l4h-root: nic {} ({:02x}:{:02x}.{}): nicd stopped: {}", i, p.bus, p.dev, p.func, why);
    h.pci.disable(&p);
    h.pci.bus_master(&p, false);
    if let Some(irq) = n.irq {
        let _ = irq.irq_handler_clear();
    }
    // Restored from root's boot record once it is over (`progress`).
    n.reset_until = flr(h, &p);
    n.then = then;
    n.why = why;
    n.state = State::Stopping;
    n.add_pending = false;
    if n.in_netd && !n.removing {
        n.removing = h.netd.remove_uplink(i);
        if !n.removing {
            // netd failed: it touches nothing any more.
            n.in_netd = false;
        }
    }
    progress(h, i);
}

/// netd let go of NIC `i`'s channel (RemoveUplink done, or netd failed).
pub fn netd_released(h: &mut Host, i: usize) {
    let Some(n) = nics().get_mut(i) else { return };
    n.removing = false;
    n.in_netd = false;
    progress(h, i);
}

/// Carry a stop on: once the reset is over and netd has let go, free the
/// instance and do what follows.
fn progress(h: &mut Host, i: usize) {
    let n = &mut nics()[i];
    if n.state != State::Stopping || n.removing || crate::rdtsc() < n.reset_until {
        return;
    }
    let p = n.pci;
    if n.reset_until != 0 {
        // What the reset cleared, as the firmware had it: the header, the
        // PCI Express controls (payload and request sizes, error
        // reporting, ASPM), and ACS, which root set at boot (acs.rs).
        for (k, &off) in SAVED.iter().enumerate() {
            h.pci.write32(p.bus, p.dev, p.func, off, n.saved[k]);
        }
        if let Some((c, count, v)) = n.pcie_saved {
            for (k, &o) in PCIE_SAVED[..count].iter().enumerate() {
                h.pci.write16(p.bus, p.dev, p.func, c + o, v[k]);
            }
        }
        n.reset_until = 0;
        #[cfg(target_arch = "x86_64")]
        if h.cfg.pcie_acs {
            let _ = crate::acs::enable(&h.pci, bdf(&p) as u16);
        }
        // Its ACS may isolate less than before: the group is taken anew,
        // and the next start checks confinement against it.
        nics()[i].group = group_of(h, p);
    }
    let n = &mut nics()[i];
    if let Some(inst) = n.inst.take() {
        destroy(h, i, inst);
    }
    let n = &mut nics()[i];
    let manual = core::mem::take(&mut n.manual);
    match n.then {
        Then::Restart if manual => {
            n.retry_at = 0;
            n.state = State::Backoff;
        }
        Then::Restart => {
            let now = crate::rdtsc();
            let hour = h.info.tsc_hz.saturating_mul(3600);
            if now.wrapping_sub(n.window_start) > hour {
                n.window_start = now;
                n.restarts = 0;
            }
            n.restarts += 1;
            if n.restarts > h.cfg.nic_max_restarts {
                n.state = State::Failed;
                log!("l4h-root: nic {}: restarted {} times within the hour: left stopped until rebound", i, h.cfg.nic_max_restarts);
                return;
            }
            n.retry_at = now + h.info.tsc_hz.saturating_mul(n.backoff_secs);
            n.backoff_secs = (n.backoff_secs * 2).clamp(1, BACKOFF_MAX_SECS);
            n.state = State::Backoff;
        }
        // A new driver offers the MAC anew: the last one's may have been
        // its own choice.
        Then::Unbind => {
            n.state = State::Unbound;
            n.driver = None;
            n.mac = None;
        }
        Then::Fail => n.state = State::Failed,
        Then::Rebind(d) => {
            n.state = State::Unbound;
            n.driver = None;
            n.mac = None;
            if let Err(why) = bind(h, i, Some(d)) {
                log!("l4h-root: nic {}: not bound: {}", i, why);
            }
        }
    }
}

/// Free instance `inst` of NIC `i`'s nicd, which is suspended (or never
/// started) and whose device cannot reach memory (bus mastering off and
/// read back, or never on).
fn destroy(h: &mut Host, i: usize, inst: Inst) {
    let _ = inst.comp.tcb.tcb_suspend();
    // The DMA region stays the NIC's, mapped (DmaRegion).
    for k in 0..RING {
        if let Some(Op::Ctl(t)) = inst.ops[k] {
            crate::vmmgr::op_done(h, t, Err(ctl::EIO));
        }
    }
    h.alloc.release(inst.arena);
    h.alloc.slots.free_owned(slot_owner(i));
    h.asids.in_use -= 1;
}

/// Component `id`'s fault, if it is a nicd's: stop it, and restart it.
pub fn fault(h: &mut Host, id: u32) -> bool {
    let Some(i) = id.checked_sub(nicd::NICD_ID_BASE).map(|i| i as usize).filter(|&i| i < nics().len()) else { return false };
    if nics()[i].inst.is_none() {
        return false;
    }
    kill(h, i, Then::Restart, "it faulted");
    true
}

/// What the nicds answered and asked (badges::root::MAILBOX), and what
/// netd says of their channels.
pub fn poll(h: &mut Host) {
    for i in 0..nics().len() {
        loop {
            let Some(inst) = nics()[i].inst.as_mut() else { break };
            if nics()[i].state == State::Stopping {
                break;
            }
            let Some((k, w)) = inst.mailbox.answer() else { break };
            match inst.ops[k as usize % RING].take() {
                None => {}
                Some(Op::Start) => {
                    if let Err(e) = wire::reply::<nicd::call::reply::Start>(&w) {
                        log!("l4h-root: nic {}: the driver refused the device ({:#x})", i, e);
                        kill(h, i, Then::Fail, "the driver refused the device");
                        break;
                    }
                }
                Some(Op::Ping) => nics()[i].ping_at = None,
                Some(Op::Ctl(t)) => {
                    let r = wire::reply::<nicd::call::reply::Ctl>(&w).map(|d| {
                        let len = (d.len as usize).min(nicd::CTL_MAX);
                        inst.ctl_len = len;
                        crate::vmmgr::OpResult::Vals([len as u64, 0, 0, 0, 0, 0].into_iter().collect())
                    });
                    crate::vmmgr::op_done(h, t, r);
                }
            }
        }
        cfg_access(h, i);
        check_uplink(h, i);
    }
}

/// netd's word on NIC `i`'s channel: its offer taken (the MAC checked
/// here), refused, or the channel broken.
fn check_uplink(h: &mut Host, i: usize) {
    let n = &nics()[i];
    if !matches!(n.state, State::Starting | State::Up) || !n.in_netd {
        return;
    }
    let Some((state, generation, mac)) = h.netd.uplink_state(i) else { return };
    if generation != n.generation & 0xff_ffff {
        return;
    }
    match state {
        net::UPLINK_UP if n.state == State::Starting => {
            let mac48 = mac & 0xffff_ffff_ffff;
            let boot = |k: usize| nics()[k].driver.is_some_and(|d| drivers().drivers[d].boot);
            let holder = (0..nics().len()).find(|&j| j != i && nics()[j].mac == Some(mac48));
            let why = if !is_unicast(mac48) {
                Some("its MAC is not a unicast address")
            } else if n.mac.is_some_and(|m| m != mac48) {
                Some("its MAC changed")
            } else if let Some(j) = holder {
                // A driver dom0 loaded that took a boot driver's NIC's MAC
                // first does not keep it from that NIC: the measured
                // driver's word wins.  Otherwise the newcomer goes.
                if boot(i) && !boot(j) {
                    log!("l4h-root: nic {}: its driver offered nic {}'s MAC", j, i);
                    nics()[j].mac = None;
                    kill(h, j, Then::Fail, "its MAC is another NIC's");
                    None
                } else {
                    Some("its MAC is another NIC's")
                }
            } else {
                None
            };
            if let Some(why) = why {
                kill(h, i, Then::Fail, why);
                return;
            }
            let n = &mut nics()[i];
            n.mac = Some(mac48);
            n.state = State::Up;
            n.backoff_secs = 1;
            info!("l4h-root: nic {}: up, mac {:012x}", i, mac48);
        }
        net::UPLINK_REFUSED => kill(h, i, Then::Fail, "netd refused its offer"),
        net::UPLINK_BROKEN => kill(h, i, Then::Restart, "it broke its channel"),
        _ => {}
    }
}

fn is_unicast(m: u64) -> bool {
    m != 0 && m >> 48 == 0 && (m >> 40) & 1 == 0
}

/// Root's tick: hung nicds, restarts due, resets done, timers.
pub fn tick(h: &mut Host) {
    let now = crate::rdtsc();
    for i in 0..nics().len() {
        if let Some(inst) = nics()[i].inst.as_mut() {
            inst.cfg_budget = CFG_PER_TICK;
        }
        // One left waiting for the budget.
        cfg_access(h, i);
        let n = &mut nics()[i];
        match n.state {
            State::Stopping => progress(h, i),
            State::Starting => {
                if n.add_pending {
                    let bits = n.chan.as_ref().unwrap().data_bits;
                    if h.netd.add_uplink(i, bits).is_ok() {
                        let n = &mut nics()[i];
                        n.add_pending = false;
                        n.in_netd = true;
                        n.generation = n.generation.wrapping_add(1);
                    }
                }
                let n = &nics()[i];
                if now.wrapping_sub(n.started_at) > h.info.tsc_hz.saturating_mul(START_SECS) {
                    kill(h, i, Then::Restart, "it did not come up in time");
                }
            }
            State::Backoff if now >= n.retry_at => {
                if let Err(why) = spawn(h, i) {
                    let n = &mut nics()[i];
                    log!("l4h-root: nic {}: restart failed: {}", i, why);
                    n.state = State::Backoff;
                    n.retry_at = now + h.info.tsc_hz.saturating_mul(n.backoff_secs);
                    n.backoff_secs = (n.backoff_secs * 2).clamp(1, BACKOFF_MAX_SECS);
                }
            }
            State::Up => {
                // A Ping a second; one unanswered for HANG_SECS: hung.
                match n.ping_at {
                    Some(at) if now.wrapping_sub(at) > h.info.tsc_hz.saturating_mul(HANG_SECS) => {
                        kill(h, i, Then::Restart, "it stopped answering");
                        continue;
                    }
                    Some(_) => {}
                    None => {
                        let inst = n.inst.as_mut().unwrap();
                        if let Some(k) = inst.mailbox.send(&Request::Ping {}) {
                            inst.ops[k as usize % RING] = Some(Op::Ping);
                            n.ping_at = Some(now);
                        }
                    }
                }
                if let Some(t) = nics()[i].inst.as_ref().and_then(|x| x.timer) {
                    t.signal();
                }
            }
            _ => {}
        }
    }
}

/// Whether every NIC bound at boot is up or has given up: boot waits
/// for their MACs (dom0's uplink port takes one).
pub fn ready() -> bool {
    nics().iter().all(|n| matches!(n.state, State::Unbound | State::Up | State::Failed))
}

/// Boot has waited long enough: NICs not up yet are failed.
pub fn fail_unready(h: &mut Host) {
    for i in 0..nics().len() {
        if matches!(nics()[i].state, State::Starting | State::Backoff | State::Stopping) {
            log!("l4h-root: nic {}: its driver did not come up in time", i);
            if nics()[i].state != State::Stopping && nics()[i].inst.is_some() {
                kill(h, i, Then::Fail, "it did not come up in time");
            }
            let n = &mut nics()[i];
            if n.state == State::Backoff {
                n.state = State::Failed;
            }
            // A pending unbind or rebind stands; a restart does not.
            if n.state == State::Stopping && n.then == Then::Restart {
                n.then = Then::Fail;
            }
        }
    }
}

/// NIC `i`'s MAC, once up: what root checked.
pub fn mac(i: usize) -> Option<u64> {
    // Later instances must offer the same (check_uplink): it stays the
    // NIC's while its driver restarts.
    nics().get(i).filter(|n| n.driver.is_some()).and_then(|n| n.mac)
}

// ---------------------------------------------------------------------
// Configuration-space requests (DESIGN.md §9.8, "Configuration space").

/// The bits of its dword a write of `size` bytes at `off` of NIC `i`'s
/// function may change, by root's filter: inside the manifest's windows,
/// past the header, and in no capability but a vendor-specific one (not
/// virtio's), AER's status registers, LTR, L1 PM substates, or PCI
/// Express's Device Control relaxed ordering and no-snoop bits and Link
/// Control's ASPM bits.  None if it may change
/// nothing.
fn write_allowed(h: &Host, n: &Nic, m: &Manifest, off: u16, size: u16) -> Option<u32> {
    let end = off + size;
    let inside = m.config_writes.iter().any(|w| w.len != 0 && off >= w.offset && end <= w.offset + w.len);
    if !inside || end > 4096 || off < 0x40 {
        return None;
    }
    let d = &n.pci;
    let dword = off & !3;
    // The bytes written, as bits of their dword.
    let shift = (off & 3) * 8;
    let mut bits = if size == 4 { u32::MAX } else { ((1u32 << (size * 8)) - 1) << shift };
    // Every capability, standard (below 0x100) and extended, by offset;
    // each taken to reach the next one up in its space, or the space's
    // end.  A write must lie inside one the driver may write: no byte
    // outside any capability, nor in another kind, is.
    let mut caps: ArrayVec<(u16, u16), 96> = ArrayVec::new();
    let mut c = (h.pci.read32(d.bus, d.dev, d.func, 0x34) & 0xfc) as u16;
    while c >= 0x40 && c < 0x100 && !caps.is_full() && !caps.iter().any(|&(o, _)| o == c) {
        let w = h.pci.read32(d.bus, d.dev, d.func, c as u8);
        caps.must_push((c, w as u8 as u16));
        c = ((w >> 8) & 0xfc) as u16;
    }
    #[cfg(target_arch = "x86_64")]
    {
        let mut c = 0x100u16;
        while c >= 0x100 && !caps.is_full() && !caps.iter().any(|&(o, _)| o == c) {
            let Some(w) = h.pci.read_ext32(bdf(d) as u16, c) else { break };
            if w == 0 || w == u32::MAX {
                break;
            }
            // Extended ids are marked apart from standard ones.
            caps.must_push((c, 0x8000 | (w & 0x7fff) as u16));
            c = (w >> 20) as u16 & 0xffc;
        }
    }
    let space_end = |c: u16| if c < 0x100 { 0x100 } else { 0x1000 };
    let Some(&(c, id)) = caps.iter().find(|&&(c, _)| {
        let next = caps.iter().map(|&(o, _)| o).filter(|&o| o > c && o < space_end(c)).min().unwrap_or(space_end(c));
        off >= c && end <= next
    }) else {
        return None;
    };
    match id {
        // Vendor-specific, but virtio's: one of those (PCI_CFG) reaches
        // the whole of a BAR, past the driver's window.
        0x09 if d.vendor != 0x1af4 => {}
        // PCI Express: Device Control's relaxed ordering (4) and no snoop
        // (11), Link Control's ASPM (0..1); nothing else.
        0x10 if dword == c + 8 => bits &= 1 << 4 | 1 << 11,
        0x10 if dword == c + 0x10 => bits &= 0b11,
        // AER: its status registers only (write 1 to clear), not the masks
        // or the severities.
        0x8001 if dword == c + 4 || dword == c + 0x10 => {}
        // Vendor-specific, LTR, L1 PM substates.
        0x800b | 0x8018 | 0x801e => {}
        _ => return None,
    }
    (bits != 0).then_some(bits)
}

/// Answer NIC `i`'s configuration-space request, if it made a new one.
fn cfg_access(h: &mut Host, i: usize) {
    let n = &nics()[i];
    let (Some(inst), Some(d)) = (n.inst.as_ref(), n.driver) else { return };
    if !matches!(n.state, State::Starting | State::Up) {
        return;
    }
    let p = inst.mailbox.published::<nicd::Published>();
    let req = p.cfg_req.load(Ordering::Acquire);
    let seq = (req >> 32) as u32;
    if seq == inst.cfg_seq || seq == 0 {
        return;
    }
    // A few a tick: a nicd asking without end must not keep root (and
    // netd, on its core) busy.  The rest wait for the next tick.
    if inst.cfg_budget == 0 {
        return;
    }
    let (kind, size, off) = (req & 0xf, (req >> 4 & 0xf) as u16, (req >> 16 & 0xfff) as u16);
    let value = p.cfg_value.load(Ordering::Relaxed);
    let m = drivers().drivers[d].manifest;
    let dev = n.pci;
    let aligned = matches!(size, 1 | 2 | 4) && off % size == 0;
    let r: Result<u32, Errno> = if !aligned {
        Err(ctl::EINVAL)
    } else {
        let dword = off & !3;
        let shift = (off & 3) * 8;
        let mask = if size == 4 { u32::MAX } else { ((1u32 << (size * 8)) - 1) << shift };
        let read = |h: &Host| -> Option<u32> {
            if dword < 256 {
                Some(h.pci.read32(dev.bus, dev.dev, dev.func, dword as u8))
            } else {
                #[cfg(target_arch = "x86_64")]
                { h.pci.read_ext32(bdf(&dev) as u16, dword) }
                #[cfg(not(target_arch = "x86_64"))]
                { None }
            }
        };
        match kind {
            nicd::CFG_READ => read(h).map(|v| (v & mask) >> shift).ok_or(ctl::EIO),
            nicd::CFG_WRITE => match write_allowed(h, n, &m, off, size).map(|b| b & mask) {
                None => Err(ctl::EPERM),
                Some(mask) => match read(h) {
                    Some(old) => {
                        let v = old & !mask | (value << shift) & mask;
                        if dword < 256 {
                            h.pci.write32(dev.bus, dev.dev, dev.func, dword as u8, v);
                            Ok(0)
                        } else {
                            #[cfg(target_arch = "x86_64")]
                            { if h.pci.write_ext32(bdf(&dev) as u16, dword, v) { Ok(0) } else { Err(ctl::EIO) } }
                            #[cfg(not(target_arch = "x86_64"))]
                            { Err(ctl::EIO) }
                        }
                    }
                    None => Err(ctl::EIO),
                },
            },
            _ => Err(ctl::EINVAL),
        }
    };
    let (ans, v) = match r {
        Ok(v) => (0, v),
        Err(e) => (e & 0xffff_ffff, 0),
    };
    p.cfg_ans_value.store(v, Ordering::Relaxed);
    p.cfg_ans.store((seq as u64) << 32 | ans, Ordering::Release);
    let inst = nics()[i].inst.as_mut().unwrap();
    inst.cfg_seq = seq;
    inst.cfg_budget -= 1;
    inst.mailbox.kick();
}

// ---------------------------------------------------------------------
// The control API (ctl.rs).

/// CTL_NIC_INFO for NIC `i`: vals, and the driver's name and the reason
/// it failed (NUL separated) in `data`.
pub fn info(h: &Host, i: usize, data: &mut [u8; abi::CTL_DATA_MAX]) -> Result<[u64; 6], Errno> {
    let n = nics().get(i).ok_or(ctl::ENOENT)?;
    let p = &n.pci;
    let state = match n.state {
        State::Unbound => abi::NIC_STATE_UNBOUND,
        State::Starting => abi::NIC_STATE_STARTING,
        State::Up => abi::NIC_STATE_UP,
        State::Stopping | State::Backoff => abi::NIC_STATE_RESTARTING,
        State::Failed => abi::NIC_STATE_FAILED,
    };
    let trust = if n.driver.is_none() { 0 } else if n.confined { abi::NIC_TRUST_CONFINED } else { abi::NIC_TRUST_TRUSTED };
    let mut at = 0;
    if let Some(d) = n.driver {
        let name = drivers().drivers[d].manifest.name().as_bytes();
        data[..name.len()].copy_from_slice(name);
        at = name.len();
    }
    data[at] = 0;
    let why = n.why.as_bytes();
    let w = why.len().min(abi::CTL_DATA_MAX - at - 2);
    data[at + 1..at + 1 + w].copy_from_slice(&why[..w]);
    let (rx, tx) = n.inst.as_ref().map_or((0, 0), |x| {
        let c = &x.mailbox.published::<nicd::Published>().counters;
        (c[nicd::RX_FRAMES].load(Ordering::Relaxed) & 0xffff_ffff, c[nicd::TX_FRAMES].load(Ordering::Relaxed) & 0xffff_ffff)
    });
    Ok([
        bdf(p) as u64,
        h.netd.uplink_switch(i).map_or(u64::MAX, |s| s as u64),
        mac(i).unwrap_or(0),
        state | trust << 8 | n.driver.map_or(0xff, |d| d as u64) << 16 | (n.restarts as u64 & 0xffff) << 32
            | (n.group.len() as u64) << 48,
        p.vendor as u64 | (p.device as u64) << 16,
        rx | tx << 32,
    ])
}

/// CTL_NIC_CTL: post dom0's control message of `len` bytes (at `off` of
/// its control data area, which root maps) to NIC `i`'s nicd: answered
/// later, with the answer's length.
pub fn ctl_post(h: &mut Host, i: usize, off: u64, len: u64) -> Result<usize, Errno> {
    let len = usize::try_from(len).ok().filter(|&l| l <= nicd::CTL_MAX).ok_or(ctl::EINVAL)?;
    let off = usize::try_from(off).ok().filter(|&o| o.checked_add(len).is_some_and(|e| e as u64 <= abi::CTL_LOAD_MAX)).ok_or(ctl::EINVAL)?;
    let n = nics().get(i).ok_or(ctl::ENOENT)?;
    if n.state != State::Up {
        return Err(ctl::EAGAIN);
    }
    let inst = n.inst.as_ref().unwrap();
    if inst.ops.iter().any(|o| matches!(o, Some(Op::Ctl(_)))) || !inst.mailbox.room() {
        return Err(ctl::EBUSY);
    }
    let page = inst.ctl_page;
    // dom0's bytes, copied: the nicd never sees dom0's memory.
    h.wins.a.with_frame(&abs_of(page), |p| unsafe {
        core::ptr::copy_nonoverlapping((crate::vmmgr::CTL_DATA_VA + off) as *const u8, p, len)
    });
    let t = crate::vmmgr::op_new(h, None, crate::pci::MAX_DISK_CTRLS + i)?;
    let inst = nics()[i].inst.as_mut().unwrap();
    let k = inst.mailbox.send(&Request::Ctl { len }).expect("nicd mailbox room");
    inst.ops[k as usize % RING] = Some(Op::Ctl(t));
    Ok(t)
}

/// CTL_NIC_CTL_READ: the answer to NIC `i`'s last control message.
pub fn ctl_read(h: &mut Host, i: usize, data: &mut [u8; abi::CTL_DATA_MAX]) -> Result<u64, Errno> {
    let inst = nics().get(i).and_then(|n| n.inst.as_ref()).ok_or(ctl::ENOENT)?;
    let len = inst.ctl_len.min(abi::CTL_DATA_MAX);
    h.wins.a.with_frame(&abs_of(inst.ctl_page), |p| unsafe { core::ptr::copy_nonoverlapping(p, data.as_mut_ptr(), len) });
    Ok(len as u64)
}

/// CTL_NIC_TEST (TEST_INJECT builds): make NIC `i`'s nicd panic (1) or
/// hang (2).
pub fn test(i: usize, what: u64) -> Result<(), Errno> {
    if !host::TEST_INJECT {
        return Err(ctl::ENOSYS);
    }
    let inst = nics().get_mut(i).and_then(|n| n.inst.as_mut()).ok_or(ctl::ENOENT)?;
    let req = match what {
        1 => Request::TestPanic {},
        2 => Request::TestHang {},
        _ => return Err(ctl::EINVAL),
    };
    inst.mailbox.send(&req).map(|_| ()).ok_or(ctl::EBUSY)
}

/// Driver images dom0 loaded, in DRIVER_IMAGES slots.
static mut LOADED: usize = 0;

/// CTL_DRIVER_LOAD: a driver image of `len` bytes at `off` of dom0's
/// control data area, copied into root's memory (dom0 could change its
/// own), checked as the bundle's are, and added: its index.  Refused
/// unless the host confines NIC drivers (an IOMMU with interrupt
/// remapping): it is not part of the measured boot image, and runs only
/// confined (`allowed`).  Each is logged with its SHA-256.
pub fn load_driver(h: &mut Host, off: u64, len: u64) -> Result<usize, Errno> {
    let [state, remap, ..] = h.iommu.info();
    if state != abi::IOMMU_ON || remap == 0 {
        return Err(ctl::EPERM);
    }
    let len = usize::try_from(len).ok().filter(|&l| l >= 64 && l as u64 <= abi::CTL_LOAD_MAX).ok_or(ctl::EINVAL)?;
    let off = usize::try_from(off).ok().filter(|&o| o.checked_add(len).is_some_and(|e| e as u64 <= abi::CTL_LOAD_MAX)).ok_or(ctl::EINVAL)?;
    let k = unsafe { LOADED };
    if k >= crate::drivers::MAX_DRIVERS || drivers().drivers.is_full() {
        return Err(ctl::ENOSPC);
    }
    let pages = len.div_ceil(PAGE);
    if !h.can_afford(pages * PAGE + (1 << 20), 0, pages + 8) {
        return Err(ctl::ENOMEM);
    }
    let base = crate::layout::DRIVER_IMAGES.base + k * abi::CTL_LOAD_MAX as usize;
    let mut arena = h.alloc.global(|alloc| alloc.arena(pages * PAGE + PAGE)).ok_or(ctl::ENOMEM)?;
    let wins = &mut h.wins;
    let ok = h.alloc.global(|alloc| {
        for p in 0..pages {
            let Some(s) = arena.try_object(alloc, FRAME_BP) else { return false };
            let f = root_cap::<cap_type::Granule>(s);
            crate::vspace::map_frame(&mut crate::mem::ObjCtx::global(alloc), sel4::init_thread::slot::VSPACE.cap(), f,
                base + p * PAGE, CapRights::read_only(), VmAttributes::DEFAULT);
            let n = (len - p * PAGE).min(PAGE);
            wins.a.with_frame(&abs_of(f), |dst| unsafe {
                core::ptr::copy_nonoverlapping((crate::vmmgr::CTL_DATA_VA + off + p * PAGE) as *const u8, dst, n)
            });
        }
        true
    });
    let image: &'static [u8] = unsafe { core::slice::from_raw_parts(base as *const u8, len) };
    match ok.then(|| drivers().add(image, false)) {
        Some(Ok(d)) => {
            core::mem::forget(arena);
            unsafe { LOADED = k + 1 };
            Ok(d)
        }
        r => {
            if let Some(Err(why)) = r {
                log!("l4h-root: driver image from dom0 refused: {}", why);
            }
            // Its frames go, and with them root's mapping of them.
            h.alloc.global(|alloc| alloc.release(arena));
            Err(if ok { ctl::EINVAL } else { ctl::ENOMEM })
        }
    }
}

/// The owner CTL_PCI_LIST reports for function `bdf`, if it is a NIC.
pub fn pci_owner(bdf: u16) -> Option<u16> {
    let n = nics().iter().find(|n| crate::netd::bdf(&n.pci) == bdf as u32)?;
    Some(match n.state {
        State::Unbound => abi::PCI_OWNER_NONE,
        State::Failed => abi::PCI_OWNER_ROOT,
        _ => abi::PCI_OWNER_NICD,
    })
}

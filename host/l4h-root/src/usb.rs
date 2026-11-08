//! Assigning a whole xHCI controller to a guest (DESIGN.md §9.7): an
//! l4h-usbd drives it, and the guest sends it host-controller operations
//! and URBs through a queue area of host frames.
//!
//! At boot root only lists the controllers and leaves them to the firmware
//! (legacy keyboard emulation, BMC virtual devices).  The first attach
//! claims one: root starts its usbd, which takes it from the firmware and
//! resets it.  From then on the controller and its usbd stay until reboot,
//! `idle` (halted, bus mastering off) whenever no guest has it.
//!
//! Every DMA address the controller sees is written by usbd, into its own
//! DMA region (which root allocates and the guest never maps) or the
//! owner's I/O pool, whose addresses root gives usbd from its own table.

use core::ptr::addr_of_mut;

use sel4::{CapRights, ObjectBlueprint, VmAttributes, cap, cap_type};

use l4h_abi::{self as abi, usb as uabi};
use l4h_host::{self as host, usb};
use l4h_host::fixed::ArrayVec;

use crate::blkd::{BarCache, DEVICE_ATTRS, bar_frames, keep_bits};
use crate::component::{self, Component, SpawnArgs, abs_of, root_cap};
use crate::iommu::Domain;
use crate::mem::{Arena, Dest, Slot};
use crate::vmmgr::RootGuest;
use crate::vspace::FRAME_BP;
use crate::{Host, ctl, pci};

static USBD_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/l4h-usbd.elf"));

const PAGE: usize = 4096;
/// Radix of the CNodes of a client's queue frames (vmmgr's copies, and
/// usbd's mapping capabilities).
pub const QUEUE_RADIX: usize = host::vmmgr::USB_QUEUE_RADIX;
const _: () = assert!(uabi::AREA_PAGES <= 1 << QUEUE_RADIX);

/// How long root waits for a controller after a reset (CNR) before it
/// reads its capabilities.
const CAP_WAIT_MS: u64 = 1000;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Not claimed: the firmware's.
    Firmware,
    /// Claimed, halted, bus mastering off.
    Idle,
    /// Guest `vm` has it.
    Vm(usize),
    /// Claim, reset or drain failed: quarantined until reboot.
    Failed,
    Unsupported(&'static str),
}

/// An xHCI controller root found at boot.
pub struct Ctrl {
    pub pci: pci::Device,
    pub state: State,
    /// USB 2 and USB 3 ports, max slots, HCIVERSION: known once claimed.
    pub usb2: u16,
    pub usb3: u16,
    bars: BarCache,
    driver: Option<Usbd>,
    dom: Domain,
    /// The owner's pool, while one is attached: (paddr, size).
    pool: Option<(usize, usize)>,
}

struct Usbd {
    comp: Component,
    #[allow(dead_code)]
    arena: Arena,
}

/// The controllers, in .bss with the disk controllers.
static mut CTRLS: ArrayVec<Ctrl, { usb::MAX_USB_CTRLS }> = ArrayVec::new();

pub fn ctrls() -> &'static mut ArrayVec<Ctrl, { usb::MAX_USB_CTRLS }> {
    // main takes the only reference once.
    unsafe { &mut *(&raw mut CTRLS) }
}

/// An xHCI controller: class 0c/03/30.
pub fn is_xhci(d: &pci::Device) -> bool {
    d.class == 0x0c && d.subclass == 0x03 && d.prog_if == 0x30
}

/// Why `d` cannot be driven, or None.
fn unsupported(d: &pci::Device, pci: &pci::Pci) -> Option<&'static str> {
    let bar = d.bars[0];
    if bar.is_io || bar.size < 0x1000 || bar.size as usize > crate::blkd::BAR_STRIDE {
        return Some("no usable BAR 0");
    }
    if d.msix.is_none() && d.msi.is_none() {
        return Some("no MSI or MSI-X");
    }
    // Renesas uPD720201/2 without a firmware ROM: their driver loads the
    // firmware through configuration space (Linux's renesas_xhci).
    if d.vendor == 0x1912 && matches!(d.device, 0x0014 | 0x0015) {
        let fw_loaded = pci.read32(d.bus, d.dev, d.func, 0xf4) & (1 << 4) != 0;
        let rom = pci.read32(d.bus, d.dev, d.func, 0xf4) >> 16 & (1 << 15) != 0;
        if !fw_loaded && !rom {
            return Some("Renesas uPD72020x without firmware ROM");
        }
    }
    if cfg!(target_arch = "aarch64") && d.msix.is_none() {
        return Some("no MSI-X");
    }
    None
}

/// Boot: list `d`, leaving it to the firmware.
pub fn found(d: pci::Device, pci: &pci::Pci) {
    let cs = ctrls();
    if cs.is_full() {
        log!("l4h-root: more than {} xHCI controllers, {:02x}:{:02x}.{} ignored", usb::MAX_USB_CTRLS, d.bus, d.dev, d.func);
        return;
    }
    let state = match unsupported(&d, pci) {
        Some(why) => State::Unsupported(why),
        None => State::Firmware,
    };
    info!("l4h-root: xHCI {:02x}:{:02x}.{} {:04x}:{:04x}: left to the firmware{}", d.bus, d.dev, d.func,
        d.vendor, d.device, if let State::Unsupported(w) = state { w } else { "" });
    cs.must_push(Ctrl { pci: d, state, usb2: 0, usb3: 0, bars: [const { None }; 6], driver: None, dom: Domain::NONE, pool: None });
}

/// A call to usbd.  One that has failed answers u64::MAX (its keeper).
fn call(ep: cap::Endpoint, label: u64, args: &[u64]) -> u64 {
    for (i, &v) in args.iter().enumerate() {
        crate::set_mr(i, v);
    }
    ep.call(sel4::MessageInfo::new(label, 0, 0, args.len()));
    crate::mr(0)
}

/// Stop the controller for good: usbd suspended, no DMA, no decoding, no
/// interrupts.
fn quarantine(c: &mut Ctrl, pci: &pci::Pci) {
    c.state = State::Failed;
    if let Some(d) = &c.driver {
        let _ = d.comp.tcb.tcb_suspend();
    }
    pci.disable(&c.pci);
    let p = &c.pci;
    log!("l4h-root: xHCI {:02x}:{:02x}.{}: quarantined until reboot", p.bus, p.dev, p.func);
}

/// The controller's capability registers, through a temporary mapping of
/// BAR 0's first page: (max slots, scratchpad buffers, page size).
fn caps(h: &mut Host, i: usize) -> Option<(u32, u32, u32)> {
    let c = &mut ctrls()[i];
    let frames = bar_frames(&mut h.alloc, &mut h.devmem, &c.pci, &mut c.bars, 0);
    h.pci.enable_memory(&c.pci);
    let frame = crate::devmem::granule(frames.start);
    let ticks_per_ms = h.info.tsc_hz / 1000;
    h.wins.a.with_frame_attrs(&abs_of(frame), DEVICE_ATTRS, |page| unsafe {
        let r32 = |o: usize| (page.add(o) as *const u32).read_volatile();
        let cap0 = r32(0);
        if cap0 == u32::MAX {
            return None;
        }
        let caplength = (cap0 & 0xff) as usize;
        if caplength < 0x20 || caplength + 0x40 > PAGE {
            return None;
        }
        // The firmware may be resetting it: wait for Controller Not Ready.
        let end = host::ticks::now() + CAP_WAIT_MS * ticks_per_ms;
        while r32(caplength + 0x04) & (1 << 11) != 0 {
            if host::ticks::now() > end {
                return None;
            }
            core::hint::spin_loop();
        }
        let (hcs1, hcs2) = (r32(4), r32(8));
        let slots = hcs1 & 0xff;
        let scratch = ((hcs2 >> 21) & 0x1f) << 5 | (hcs2 >> 27);
        let pagesize = (r32(caplength + 0x08) & 0xffff).trailing_zeros();
        if slots == 0 || pagesize > 4 {
            return None;
        }
        Some((slots, scratch, 4096 << pagesize))
    })
}

/// Intel PCH controllers that share ports with an EHCI: route them all to
/// the xHCI, as Linux's usb_enable_intel_xhci_ports does.
fn route_intel_ports(d: &pci::Device, pci: &pci::Pci) {
    const SWITCHABLE: [u16; 5] = [0x1e31, 0x8c31, 0x9c31, 0x9cb1, 0x8cb1];
    if d.vendor != 0x8086 || !SWITCHABLE.contains(&d.device) {
        return;
    }
    let (b, dv, f) = (d.bus, d.dev, d.func);
    // USB3_PSSEN from USB3PRM, XUSB2PR from XUSB2PRM.
    pci.write32(b, dv, f, 0xd8, pci.read32(b, dv, f, 0xdc));
    pci.write32(b, dv, f, 0xd0, pci.read32(b, dv, f, 0xd4));
}

/// Program the controller's interrupt (MSI-X entry 0, or MSI) for
/// `vector` in `dom`.
fn program_irq(h: &mut Host, i: usize, vector: u64, dom: Domain) {
    let (addr, data) = h.iommu.msi(dom, vector);
    let c = &mut ctrls()[i];
    match c.pci.msix {
        Some(m) => {
            let frames = bar_frames(&mut h.alloc, &mut h.devmem, &c.pci, &mut c.bars, m.table_bar);
            let off = m.table_offset as usize;
            let frame = crate::devmem::granule(frames.start + off / PAGE);
            h.wins.a.with_frame_attrs(&abs_of(frame), DEVICE_ATTRS, |page| unsafe {
                let e = page.add(off % PAGE) as *mut u32;
                e.write_volatile(addr as u32);
                e.add(1).write_volatile((addr >> 32) as u32);
                e.add(2).write_volatile(data);
                e.add(3).write_volatile(0);
            });
            h.pci.disable_msi(&c.pci);
            h.pci.enable_msix(&c.pci);
        }
        None => h.pci.enable_msi(&c.pci, addr, data),
    }
}

/// Claim controller `i` from the firmware: start its usbd, which does the
/// legacy handoff and resets it.  ENOMEM leaves it with the firmware;
/// EIO marks it failed (the handoff cannot be undone).
fn claim(h: &mut Host, i: usize) -> Result<(), i64> {
    let claimed = ctrls().iter().filter(|c| c.driver.is_some()).count();
    let Some(&vector) = pci::VECTORS_USB.get(claimed) else { return Err(ctl::ENOSPC) };
    let Some((slots, scratch, page)) = caps(h, i) else {
        let p = &ctrls()[i].pci;
        log!("l4h-root: xHCI {:02x}:{:02x}.{}: no capabilities", p.bus, p.dev, p.func);
        ctrls()[i].state = State::Failed;
        return Err(ctl::EIO);
    };
    let dma = usb::dma_bytes(slots, scratch, page);
    if !h.can_afford(dma + (8 << 20), 1, 4096) {
        return Err(ctl::ENOMEM);
    }
    // usbd's image, stacks and tables (about 1 MiB of statics).
    let mut arena = h.alloc.arena(4 << 20).ok_or(ctl::ENOMEM)?;
    let bits = dma.trailing_zeros() as usize;
    let dma_slot = h.alloc.slots.alloc();
    let Some(mut region) = h.alloc.split(bits, dma_slot) else {
        h.alloc.slots.free(dma_slot);
        h.alloc.reclaim(arena);
        return Err(ctl::ENOMEM);
    };
    let dma_paddr = region.paddr;
    arena.own(dma_slot, dma_paddr, bits);
    let n_dma = dma / PAGE;
    let dma_cn = arena.object_cap::<cap_type::CNode>(&mut h.alloc, ObjectBlueprint::CNode { size_bits: bits - 12 });
    region.retype(&FRAME_BP, n_dma, Dest { cnode: abs_of(dma_cn), offset: 0 }).expect("usbd DMA frames");

    let c = &mut ctrls()[i];
    let d = c.pci;
    // The device reaches this memory, and an attached client's pool.
    let dom = h.iommu.attach(&mut h.alloc, &d);
    h.iommu.map(&mut h.alloc, dom, dma_paddr, dma, true);
    let mut cfg = usb::UsbdConfig {
        bar0_va: host::MMIO_VA as u64,
        bar0_len: d.bars[0].size,
        pci_bdf: crate::netd::bdf(&d),
        force_handoff_timeout: (host::TEST_INJECT && h.cfg.test_usb_handoff_timeout) as u32,
        dma_va: host::DMA_VA as u64,
        dma_paddr: dma_paddr as u64,
        dma_size: dma as u64,
    };
    let cfg_bytes = unsafe {
        core::slice::from_raw_parts(addr_of_mut!(cfg) as *const u8, core::mem::size_of::<usb::UsbdConfig>())
    };
    let args = SpawnArgs {
        id: usb::USBD_ID_BASE + i as u32,
        kind: host::KIND_USBD,
        elf: USBD_ELF,
        prio: host::PRIO_SERVICE,
        budget_us: h.info.timeslice_us,
        period_us: h.info.timeslice_us,
        config: cfg_bytes,
        ntfn: None,
        service_ep: None,
        cnode: None,
        cnode_bits: None,
    };
    let comp = component::create(
        &args, &mut h.alloc, &mut arena, &mut h.wins.a, &mut |alloc, vspace| h.asids.assign(alloc, vspace),
        &h.info.spawn_context(0),
    );
    let bar_pages = (d.bars[0].size as usize).div_ceil(PAGE);
    let kb = keep_bits(n_dma + bar_pages);
    let keep = arena.object_cap::<cap_type::CNode>(&mut h.alloc, ObjectBlueprint::CNode { size_bits: kb });
    let mut next = 0u64;
    let mut keep_slot = || {
        next += 1;
        keep.absolute_cptr_from_bits_with_depth(next - 1, kb)
    };
    // BAR 0, uncached, and the DMA region.
    let bar = bar_frames(&mut h.alloc, &mut h.devmem, &d, &mut c.bars, 0);
    for (p, f) in bar.map(crate::devmem::granule).enumerate() {
        comp.map_copy(&mut h.alloc, &mut arena, &abs_of(f), host::MMIO_VA + p * PAGE, CapRights::read_write(), DEVICE_ATTRS, keep_slot());
    }
    for p in 0..n_dma {
        let f = dma_cn.absolute_cptr_from_bits_with_depth(p as u64, bits - 12);
        comp.map_copy(&mut h.alloc, &mut arena, &f, host::DMA_VA + p * PAGE, CapRights::read_write(), VmAttributes::DEFAULT, keep_slot());
    }
    // The interrupt.
    let irq_slot = h.alloc.slots.global(|s| s.alloc());
    pci::msi_irq(&d, vector, &abs_of(root_cap::<cap_type::Null>(irq_slot)));
    let irq = root_cap::<cap_type::IrqHandler>(irq_slot);
    let irq_ntfn = root_cap::<cap_type::Notification>(h.alloc.slots.alloc());
    abs_of(irq_ntfn).mint(&abs_of(comp.ntfn), CapRights::all(), usb::USBD_BADGE_IRQ).expect("usbd IRQ notification");
    irq.irq_handler_set_notification(irq_ntfn).expect("usbd IRQ set notification");
    comp.give(usb::USBD_SLOT_IRQ, irq, CapRights::all());
    c.dom = dom;
    program_irq(h, i, vector, dom);
    let c = &mut ctrls()[i];
    // The firmware may be using it (keyboard emulation): bus mastering
    // stays as it is until usbd has it halted.
    h.pci.enable_memory(&c.pci);
    component::start(&comp);
    let ep = comp.service_ep;
    c.driver = Some(Usbd { comp, arena });
    let r = call(ep, usb::USBD_CLAIM, &[]);
    if r != 0 {
        log!("l4h-root: xHCI {:02x}:{:02x}.{}: claim failed ({:#x})", d.bus, d.dev, d.func, r);
        quarantine(c, &h.pci);
        return Err(ctl::EIO);
    }
    let ports = crate::mr(1);
    (c.usb2, c.usb3) = (ports as u16, (ports >> 16) as u16);
    route_intel_ports(&d, &h.pci);
    h.pci.bus_master(&d, false);
    c.state = State::Idle;
    info!("l4h-root: xHCI {:02x}:{:02x}.{}: claimed, {} USB 2 and {} USB 3 ports, {} KiB of DMA memory",
        d.bus, d.dev, d.func, c.usb2, c.usb3, dma >> 10);
    Ok(())
}

/// What a guest's VMM and vmmgr get for an attached controller.
pub struct Attached {
    /// A CNode (radix QUEUE_RADIX) of the queue area's frames.
    pub frames: cap::CNode,
    /// usbd's kick notification, badged for the client.
    pub kick: cap::Notification,
}

/// Claim controller `i` if the firmware still has it: outside any
/// guest's slot tracking, since usbd outlives the guest.
pub fn ensure_claimed(h: &mut Host, i: usize) -> Result<(), i64> {
    match ctrls().get(i).ok_or(ctl::ENOENT)?.state {
        State::Firmware => claim(h, i),
        _ => Ok(()),
    }
}

/// VMMGR_USB_ATTACH: give guest `g` controller `i`, claimed already
/// (ensure_claimed).  The guest's USB device number is `g.usbs.len()`
/// (its VMM's badge).
pub fn attach(h: &mut Host, i: usize, g: &mut RootGuest) -> Result<Attached, i64> {
    let state = ctrls().get(i).ok_or(ctl::ENOENT)?.state;
    match state {
        State::Firmware => return Err(ctl::EIO),
        State::Idle => {}
        State::Vm(_) => return Err(ctl::EBUSY),
        State::Failed => return Err(ctl::EIO),
        State::Unsupported(_) => return Err(ctl::ENODEV),
    }
    if g.usbs.len() >= usb::MAX_GUEST_USB {
        return Err(ctl::ENOSPC);
    }
    if !h.can_afford((uabi::AREA_PAGES + 8) * PAGE, 0, 2 * (1 << QUEUE_RADIX)) {
        return Err(ctl::ENOMEM);
    }
    let n = g.usbs.len();
    let c = &mut ctrls()[i];
    let driver = c.driver.as_mut().expect("claimed usbd");
    // The queue area: host frames in the guest's arena, revoked at
    // GUEST_DEL after usbd let go of them.
    let frames = g.arena.object_cap::<cap_type::CNode>(&mut h.alloc, ObjectBlueprint::CNode { size_bits: QUEUE_RADIX });
    g.arena.retype(&mut h.alloc, &FRAME_BP, uabi::AREA_PAGES, Dest { cnode: abs_of(frames), offset: 0 }).ok_or(ctl::ENOMEM)?;
    let keep = g.arena.object_cap::<cap_type::CNode>(&mut h.alloc, ObjectBlueprint::CNode { size_bits: QUEUE_RADIX });
    for p in 0..uabi::AREA_PAGES {
        let f = frames.absolute_cptr_from_bits_with_depth(p as u64, QUEUE_RADIX);
        let k = keep.absolute_cptr_from_bits_with_depth(p as u64, QUEUE_RADIX);
        h.alloc.global(|alloc| driver.comp.map_copy(alloc, &mut driver.arena, &f, usb::queue_va(0) + p * PAGE,
            CapRights::read_write(), VmAttributes::DEFAULT, k));
    }
    // Completions go to the guest's VMM, which raises the device's event.
    let _ = driver.comp.slot(usb::USBD_SLOT_CLIENT_IRQ).delete();
    driver.comp.give_badged(usb::USBD_SLOT_CLIENT_IRQ, g.vmm_ntfn, CapRights::write_only(), host::vmm_badge_usb(n));
    let kick = root_cap::<cap_type::Notification>(h.alloc.slots.alloc());
    abs_of(kick).mint(&abs_of(driver.comp.ntfn), CapRights::write_only(), usb::USBD_BADGE_KICK).expect("usbd kick");
    let pool = (g.pool.paddr, g.pool.size);
    h.iommu.map(&mut h.alloc, c.dom, pool.0, pool.1, true);
    h.pci.bus_master(&c.pci, true);
    let ep = driver.comp.service_ep;
    c.pool = Some(pool);
    c.state = State::Vm(g.id);
    g.usbs.must_push(i);
    if call(ep, usb::USBD_ATTACH, &[0, g.pool.gpa as u64, pool.0 as u64, pool.1 as u64]) != 0 {
        // Detach at GUEST_DEL as for any other: the guest has it now.
        log!("l4h-root: xHCI {}: usbd refused the attachment", i);
        quarantine(c, &h.pci);
        return Err(ctl::EIO);
    }
    Ok(Attached { frames, kick })
}

/// GUEST_DEL: take controller `i` back from guest `vm` before its memory
/// is reused.  Whether the controller can no longer reach the guest's
/// pool: drained, or cut off by the IOMMU.
pub fn remove(h: &mut Host, i: usize) -> bool {
    let c = &mut ctrls()[i];
    let quiet = match (&c.state, &c.driver) {
        (State::Vm(_), Some(d)) => call(d.comp.service_ep, usb::USBD_REMOVE, &[0]) == 0,
        _ => false,
    };
    if !quiet {
        quarantine(c, &h.pci);
    } else {
        h.pci.bus_master(&c.pci, false);
        c.state = State::Idle;
    }
    if let Some(d) = &c.driver {
        let _ = d.comp.slot(usb::USBD_SLOT_CLIENT_IRQ).delete();
    }
    if let Some((pa, len)) = c.pool.take() {
        h.iommu.unmap(c.dom, pa, len);
    }
    quiet || c.dom != Domain::NONE
}

/// Claim the controllers named by `dom0_usb` (BDFs) before dom0 starts:
/// their indices, for vmmgr to attach to every dom0.
pub fn dom0_ctrls(h: &Host) -> ArrayVec<u64, { usb::MAX_GUEST_USB }> {
    let mut v = ArrayVec::new();
    for bdf in h.cfg.dom0_usb.iter().flatten() {
        match ctrls().iter().position(|c| crate::netd::bdf(&c.pci) == *bdf) {
            Some(i) => {
                if v.push(i as u64).is_err() {
                    log!("l4h-root: dom0_usb: more than {} controllers", usb::MAX_GUEST_USB);
                }
            }
            None => log!("l4h-root: dom0_usb: no xHCI controller at {:02x}:{:02x}.{}", bdf >> 8, (bdf >> 3) & 0x1f, bdf & 7),
        }
    }
    v
}

/// CTL_USB_INFO for controller `i`.
pub fn info(h: &Host, i: usize, data: &mut [u8; abi::CTL_DATA_MAX]) -> Result<[u64; 6], i64> {
    let c = ctrls().get(i).ok_or(ctl::ENOENT)?;
    let p = &c.pci;
    let (state, owner) = match c.state {
        State::Firmware => (abi::USB_STATE_FIRMWARE, u64::MAX),
        State::Idle => (abi::USB_STATE_IDLE, u64::MAX),
        State::Vm(vm) => (abi::USB_STATE_VM, vm as u64),
        State::Failed => (abi::USB_STATE_FAILED, u64::MAX),
        State::Unsupported(why) => {
            data[..why.len()].copy_from_slice(why.as_bytes());
            (abi::USB_STATE_UNSUPPORTED, u64::MAX)
        }
    };
    let refused = match (&c.driver, c.state) {
        (Some(d), State::Idle | State::Vm(_)) => match call(d.comp.service_ep, usb::USBD_INFO, &[]) {
            0 => crate::mr(1),
            _ => 0,
        },
        _ => 0,
    };
    let _ = h;
    Ok([
        crate::netd::bdf(p) as u64,
        p.vendor as u64 | (p.device as u64) << 16,
        c.usb2 as u64 | (c.usb3 as u64) << 16,
        state,
        owner,
        refused,
    ])
}

/// The slot root's allocator gave a capability it moved away.
pub fn free_slot(h: &mut Host, c: cap::Notification) {
    h.alloc.slots.free(c.bits() as Slot);
}

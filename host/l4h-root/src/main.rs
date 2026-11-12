//! l4h-root: the l4h root task.  Owns the devices and spawns the host
//! components, l4h-vmmgr last, which builds and runs the guests (vmmgr.rs).
//! Root makes what devices reach for guests when vmmgr asks: their I/O
//! pools, disk channels and netd ports.  Memory is l4h-memd's once it runs
//! (memd.rs).  See DESIGN.md §10.

#![no_std]
#![no_main]

/// Always retained and queued for logd in every build.
macro_rules! info {
    ($($arg:tt)*) => {
        l4h_task::print_log(format_args!($($arg)*))
    };
}

macro_rules! log {
    ($($arg:tt)*) => { l4h_task::print_log(format_args!($($arg)*)) };
}

#[cfg(target_arch = "x86_64")]
mod acpi;
mod amdvi;
mod blkd;
mod bootmod;
mod channel;
mod component;
mod config;
mod ctl;
mod dashboard;
mod devmem;
mod iommu;
mod layout;
mod logd;
mod mailbox;
mod memd;
mod monitor;
mod netd;
mod partition;
mod pci;
mod reset;
mod rtc;
mod trustd;
mod usb;
mod vmmgr;
#[cfg(target_arch = "x86_64")]
mod vtd;

use l4h_host::errno::Errno;
use l4h_host::fixed::StaticCell;

/// The root task's own capabilities.
pub use sel4::init_thread::slot;
use sel4::{ObjectBlueprint, cap, cap_type};
use sel4_root_task::{Never, root_task};

use l4h_host as host;
use l4h_host::badges::root as recv;
use l4h_host::root::call as root_call;
use l4h_host::fixed::ArrayVec;
use l4h_task::{mem, topology, vspace, window};
use l4h_task::reply::ReplySlot;

use crate::blkd::{Controller, Disk};
use crate::mem::{Alloc, Slots};
use crate::vmmgr::{Dom0Plan, RootGuest};
use crate::window::{Window, Windows};

pub use crate::vmmgr::MAX_GUEST_DEVICES;

pub const CNODE_SLOTS: usize = 1 << sel4::sel4_cfg_usize!(ROOT_CNODE_SIZE_BITS);
pub use l4h_task::mem::RETYPE_FAN_OUT;
static SLOT_STORAGE: StaticCell<mem::SlotStorage<{ CNODE_SLOTS / 64 }, CNODE_SLOTS>> =
    StaticCell::new(mem::SlotStorage::new());
static ALLOC_STORAGE: StaticCell<mem::AllocStorage> = StaticCell::new(mem::AllocStorage::new());
static LOG: host::log::Ring = host::log::Ring::new();
/// Partition 0's serial ring. A secondary only starts on it.
static SERIAL: host::serial::Ring = host::serial::Ring::new();
/// Partition 0's other writers' serial lanes (unused in a secondary).
static SERIAL_LANES: host::serial::Lanes = host::serial::Lanes::new();
pub const MAX_GUESTS: usize = 64;
/// What root made for vmmgr's guests, by id.
static GUESTS: StaticCell<[Option<RootGuest>; MAX_GUESTS]> = StaticCell::new([const { None }; MAX_GUESTS]);
static OPS: StaticCell<vmmgr::Ops> = StaticCell::new([const { None }; l4h_host::vmmgr::MAX_PENDING]);
static ZOMBIES: StaticCell<vmmgr::Zombies> = StaticCell::new([const { None }; MAX_GUESTS]);
/// Memory and root CNode slots kept back from guest requests.
const RESERVE_BYTES: usize = l4h_host::memd::HOST_RESERVE;
const RESERVE_SLOTS: usize = 32768;
/// Longest free slot range kept for disk DMA buffers.
const RESERVE_RANGE: usize = 4096;

/// Host disks, at most: the units of all controllers (a virtio-scsi
/// controller reports its own number).  Units beyond are reported and
/// ignored.
pub const MAX_DISKS: usize = 256;

/// Disk controllers and host disks, in .bss: too large for the root task's
/// stack, where `Host` is.  main takes each once.
static mut CTRLS: ArrayVec<Controller, { pci::MAX_DISK_CTRLS }> = ArrayVec::new();
static mut DISKS: ArrayVec<Disk, MAX_DISKS> = ArrayVec::new();

/// Facts about the host the guests run on.
pub struct HostInfo {
    pub cores: usize,
    pub topology: topology::Topology,
    pub tsc_hz: u64,
    log_frames: u64,
    serial_frames: u64,
    /// SERIAL_LANES' first frame, private to this partition.
    serial_lanes: u64,
    /// AArch64 feature ID registers for the guests' bootinfo (`cpu_id`).
    pub cpu_id: [u64; 5],
    pub hyp_ep: cap::Endpoint,
    sched_control_base: usize,
    pub timeslice_us: u64,
    /// Wall clock at boot (ns since the epoch, 0 if unknown) and the tick
    /// count when it was read.
    pub epoch_ns: u64,
    pub epoch_ticks: u64,
    /// The kernel makes VCPU objects: the CPU has VT-x or AMD-V and the
    /// kernel uses it (patches 0038 and 0040).
    pub vtx: bool,
}

impl HostInfo {
    pub fn spawn_context(&self, core: usize) -> component::SpawnContext {
        component::SpawnContext {
            authority: slot::TCB.cap(),
            sched_control: self.sched_control(core),
            parent_ep: self.hyp_ep,
            parent: l4h_host::wiring::Party::Root,
            tsc_hz: self.tsc_hz,
            log_frames: self.log_frames,
            serial_frames: self.serial_frames,
            serial_lanes: self.serial_lanes,
        }
    }

    pub fn serial_lanes(&self) -> u64 {
        self.serial_lanes
    }

    pub fn sched_control(&self, core: usize) -> cap::SchedControl {
        sel4::init_thread::Slot::<cap_type::SchedControl>::from_index(self.sched_control_base + core).cap()
    }
}

/// ASID pools; x86_64 seL4 has 8 pools of 512 ASIDs each in total.  Root
/// assigns ASIDs to its components until vmmgr runs, and then gives it
/// every pool (`make_all`).
pub struct AsidPools {
    pools: ArrayVec<(cap::AsidPool, usize), { 1 << sel4::sys::seL4_NumASIDPoolsBits }>,
    /// ASIDs assigned to live VSpaces (exact: guests return theirs).
    pub in_use: usize,
}

const ASID_CAPACITY: usize = (1 << sel4::sys::seL4_NumASIDPoolsBits) * ASIDS_PER_POOL;

const ASIDS_PER_POOL: usize = 1 << sel4::sys::seL4_ASIDPoolIndexBits;

impl AsidPools {
    pub fn available(&self) -> usize {
        ASID_CAPACITY.saturating_sub(self.in_use)
    }

    pub fn assign(&mut self, alloc: &mut Alloc, vspace: cap::VSpace) {
        assert!(self.in_use < ASID_CAPACITY, "out of ASIDs");
        self.in_use += 1;
        for (pool, used) in self.pools.iter_mut() {
            if *used < ASIDS_PER_POOL {
                if pool.asid_pool_assign(vspace).is_ok() {
                    *used += 1;
                    return;
                }
                *used = ASIDS_PER_POOL;
            }
        }
        // ASIDs of deleted VSpaces are freed by the kernel, so "full" pools
        // may have room again.
        for (pool, used) in self.pools.iter_mut() {
            if pool.asid_pool_assign(vspace).is_ok() {
                *used = ASIDS_PER_POOL / 2;
                return;
            }
        }
        let pool = self.make(alloc);
        pool.asid_pool_assign(vspace).expect("ASID assign");
        // At most seL4_NumASIDPoolsBits pools: in_use < ASID_CAPACITY.
        self.pools.must_push((pool, 1));
    }

    fn make(&mut self, alloc: &mut Alloc) -> cap::AsidPool {
        let (ut_slot, pool_slot) = alloc.slots.global(|slots| (slots.alloc(), slots.alloc()));
        let ut = alloc.split(sel4::sys::seL4_ASIDPoolBits as usize, ut_slot).expect("ASID pool memory");
        slot::ASID_CONTROL
            .cap()
            .asid_control_make_pool(ut.cap, &slot::CNODE.cap().absolute_cptr(sel4::init_thread::Slot::<cap_type::Null>::from_index(pool_slot).cap()))
            .expect("out of ASID pools");
        sel4::init_thread::Slot::<cap_type::AsidPool>::from_index(pool_slot).cap()
    }

    /// Make every pool vmmgr can take.
    pub fn make_all(&mut self, alloc: &mut Alloc) {
        assert!(self.pools.len() <= l4h_host::vmmgr::MAX_ASID_POOLS);
        while !self.pools.is_full() && self.pools.len() < l4h_host::vmmgr::MAX_ASID_POOLS {
            let pool = self.make(alloc);
            self.pools.must_push((pool, 0));
        }
    }

    /// The pools, and the ASIDs used in each.
    pub fn pools(&self) -> &[(cap::AsidPool, usize)] {
        &self.pools
    }
}

#[cfg(target_arch = "aarch64")]
fn tsc_hz(_bootinfo: &sel4::BootInfoPtr) -> u64 {
    host::ticks::hz()
}

#[cfg(target_arch = "x86_64")]
fn tsc_hz(bootinfo: &sel4::BootInfoPtr) -> u64 {
    for extra in bootinfo.extra() {
        if extra.id == sel4::BootInfoExtraId::X86TscFreq {
            let c = extra.content();
            let mhz = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
            return mhz as u64 * 1_000_000;
        }
    }
    panic!("no TSC frequency in bootinfo");
}

/// ID_AA64ISAR0/ISAR1/ISAR2/PFR0/PFR1_EL1 of the boot CPU, from the
/// bootinfo chunk added by kernel patch 0018; zero if it is missing.
#[cfg(target_arch = "aarch64")]
fn cpu_id(bootinfo: &sel4::BootInfoPtr) -> [u64; 5] {
    // SEL4_BOOTINFO_HEADER_AARCH64_ID_REGS
    const ID_REGS: u64 = 7;
    match bootmod::extra_chunk(bootinfo, ID_REGS) {
        Some(c) if c.len() >= 5 * 8 => core::array::from_fn(|i| u64::from_le_bytes(c[8 * i..8 * i + 8].try_into().unwrap())),
        _ => [0; 5],
    }
}

#[cfg(target_arch = "x86_64")]
fn cpu_id(_bootinfo: &sel4::BootInfoPtr) -> [u64; 5] {
    [0; 5]
}

/// All state of the root task.
pub struct Host {
    pub info: HostInfo,
    pub alloc: Alloc,
    pub wins: Windows,
    pub asids: AsidPools,
    pub pci: pci::Pci,
    pub pci_inventory: &'static mut pci::Inventory,
    pub iommu: iommu::Iommu,
    pub devmem: devmem::DevMem,
    /// Disk controllers, and their units as host disks.
    pub ctrls: &'static mut ArrayVec<Controller, { pci::MAX_DISK_CTRLS }>,
    pub disks: &'static mut ArrayVec<Disk, MAX_DISKS>,
    pub netd: netd::Netd,
    /// What root made for vmmgr's guests.
    pub guests: &'static mut [Option<RootGuest>; MAX_GUESTS],
    /// vmmgr's requests that wait for a driver.
    pub ops: &'static mut vmmgr::Ops,
    /// Deleted guests' memory that drivers may still use.
    pub zombies: &'static mut vmmgr::Zombies,
    pub total_bytes: usize,
    pub monitor: Option<monitor::Monitor>,
    pub dashboard: Option<dashboard::Dashboard>,
    pub cfg: config::Config,
    pub trustd: Option<trustd::Trustd>,
    /// Guest instances are root's to number: unique since boot, whatever
    /// vmmgr does.
    pub next_instance: u64,
    pub memd: memd::Memd,
    pub reset: reset::Reset,
    pub rtc: rtc::Rtc,
    pub vmmgr: Option<vmmgr::Vmmgr>,
    /// Partition 0's writer to the serial port.
    pub logd: Option<logd::Logd>,
    /// The notification bound to root's TCB, which its timer signals.
    pub ntfn: cap::Notification,
    /// One of several partitions: the channels to the others.
    pub channels: Option<channel::Channels>,
}

impl Host {
    /// Resources a guest operation may need, checked before starting it so
    /// that requests fail cleanly instead of exhausting the root task.
    pub fn can_afford(&self, bytes: usize, asids: usize, slots: usize) -> bool {
        bytes.checked_add(RESERVE_BYTES).is_some_and(|b| self.alloc.free_bytes() >= b)
            && self.asids.available() >= asids
            && self.alloc.slots.available() >= RESERVE_SLOTS + slots
            && self.alloc.slots.largest_range() >= RESERVE_RANGE
    }

    /// Learn the geometry of host disk `disk` if its controller could
    /// not tell at boot.
    pub fn ensure_disk(&mut self, disk: usize) -> Result<(), Errno> {
        let (c, unit) = self.disks.get(disk).map(|d| (d.ctrl, d.unit)).ok_or(ctl::ENOENT)?;
        if self.ctrls[c].failed { return Err(ctl::EIO); }
        if self.disks[disk].capacity == 0 {
            let d = self.ctrls[c].info(unit).0.ok_or(ctl::EIO)?;
            self.disks[disk] = Disk { ctrl: c, ..d };
        }
        Ok(())
    }

    /// Start every controller's blkd.  The host fails to boot if it cannot
    /// start them all (each needs 4 MiB of physically contiguous DMA
    /// memory), so no disk is ever missing its driver.
    fn start_disks(&mut self) {
        for c in 0..self.ctrls.len() {
            if !self.ctrls[c].failed {
                blkd::start(c, &mut self.ctrls[c], &self.pci, &mut self.iommu,
                    &mut self.alloc, &mut self.wins.a, &mut self.asids, &self.info);
            }
        }
    }

    /// Whether every driver has published what boot reads (its units, its
    /// NICs' MACs), or never will.
    fn drivers_ready(&self) -> bool {
        self.ctrls.iter().all(|c| c.ready()) && self.netd.ready()
    }

    /// The drivers have had DRIVERS_SLOW_SECS: say which boot still waits
    /// for.
    fn log_unready_drivers(&self) {
        for (c, ctrl) in self.ctrls.iter().enumerate() {
            if !ctrl.ready() {
                log!("l4h-root: disk controller {}: blkd has not reported its disks yet; boot waits {} s more at most",
                    c, DRIVERS_READY_SECS - DRIVERS_SLOW_SECS);
            }
        }
        if !self.netd.ready() {
            log!("l4h-root: netd has not reported its NICs yet; boot waits {} s more at most", DRIVERS_READY_SECS - DRIVERS_SLOW_SECS);
        }
    }

    /// The drivers have had DRIVERS_READY_SECS: one that has not published
    /// is failed as one that faulted, so that boot goes on without it.
    fn fail_unready_drivers(&mut self) {
        for c in 0..self.ctrls.len() {
            blkd::unpublished(self, c);
        }
        if !self.netd.ready() {
            log!("l4h-root: netd did not report its NICs");
            self.netd.fail(&self.pci);
            netd::Netd::poll(self);
        }
    }

    /// Number the host disks, once their blkds are ready: one per unit of
    /// each controller, in PCI order.  A controller that did not reset
    /// stays disabled: its disk (virtio-blk and NVMe have one) keeps its
    /// number and fails with EIO, and a virtio-scsi one has no units to
    /// report.
    fn number_disks(&mut self) {
        let add = |disks: &mut ArrayVec<Disk, MAX_DISKS>, d: Disk| {
            let (unit, ctrl) = (d.unit, d.ctrl);
            if disks.push(d).is_err() {
                log!("l4h-root: more than {} disks, unit {} of controller {} ignored", MAX_DISKS, unit, ctrl);
            }
        };
        for c in 0..self.ctrls.len() {
            if self.ctrls[c].kind != l4h_host::blk::BLKD_VIRTIO_SCSI {
                add(self.disks, Disk::new(c, 0));
                continue;
            }
            let units = self.ctrls[c].info(0).1;
            for u in 0..units {
                if let Some(d) = self.ctrls[c].info(u).0 {
                    add(self.disks, Disk { ctrl: c, ..d });
                }
            }
        }
    }

    /// Finish what the drivers have answered (mailbox.rs).
    fn poll_drivers(&mut self) {
        for c in 0..self.ctrls.len() {
            blkd::poll(self, c);
        }
        netd::Netd::poll(self);
        usb::poll(self);
        if let Some(v) = self.vmmgr.as_mut() {
            v.poll();
        }
    }
}

/// The root task's stack, its lowest page a guard (layout::guard_stack).
pub const ROOT_STACK: usize = 1024 * 1024;

#[root_task(stack_size = ROOT_STACK)]
fn main(bootinfo: &sel4::BootInfoPtr) -> sel4::Result<Never> {
    let tsc_hz = tsc_hz(bootinfo);
    LOG.set_clock(rdtsc(), tsc_hz);
    host::log::init(&LOG, 0);
    host::serial::init(&SERIAL, 0);
    sel4_root_task::panicking::set_hook(&|info| log!("l4h-root: {}", info));
    layout::guard_stack(bootinfo);
    layout::check_image(bootinfo);
    let cores = bootinfo.inner().numNodes as usize;
    let topology = topology::discover(
        cores, bootinfo.inner().nodeID as usize, slot::SC.cap(), slot::VSPACE.cap(),
        bootinfo.sched_control().range().start,
    );
    info!("l4h-root: CPU physical cores {:?}", topology.physical());
    let slots = Slots::new(slot::CNODE.cap(), SLOT_STORAGE.take(), bootinfo.empty().range());
    let mut alloc = Alloc::new(slots, ALLOC_STORAGE.take(), bootinfo);
    let total_bytes = alloc.free_bytes();
    info!("l4h-root: {} core(s), {} MiB free memory", cores, total_bytes >> 20);

    let hyp_ep = alloc.object_cap::<cap_type::Endpoint>(ObjectBlueprint::Endpoint);
    // The watchdog timer signals a notification bound to the root TCB, which
    // wakes the serve loop out of its receive on hyp_ep.
    let wd_ntfn = alloc.object_cap::<cap_type::Notification>(ObjectBlueprint::Notification);
    slot::TCB.cap().tcb_bind_notification(wd_ntfn).expect("bind watchdog notification");
    mailbox::init(wd_ntfn);
    component::minter(l4h_host::wiring::Party::Root);
    component::audit_in(alloc.slots.alloc());
    let reply_slot = alloc.slots.alloc();
    let reply = ReplySlot::new(&mut alloc, sel4::init_thread::Slot::<cap_type::Reply>::from_index(reply_slot).cap());
    let mut wins = Windows {
        a: Window::new(&mut alloc, slot::VSPACE.cap(), layout::WINDOWS.base),
        b: Window::new(&mut alloc, slot::VSPACE.cap(), layout::WINDOWS.base + 4096),
    };
    let mut devmem = devmem::DevMem::from_bootinfo(bootinfo);
    let modules = bootmod::load(bootinfo, &mut alloc, &mut devmem);
    let module = |name: &str| modules.iter().find(|m| m.name == name).map(|m| m.data);
    partition::init(module("l4h-partition"));
    let cfg = config::Config::new(module("l4h-config"));
    // The serial port is partition 0's.
    let uart = if partition::secondary() { None } else { logd::init_uart(&mut alloc, &mut devmem, cfg.serial_port) };
    let image_frame = |va: usize| bootinfo.user_image_frames().index((va - layout::image_base()) / 4096).cap().bits();
    let outgoing = partition::serial_ring(&mut alloc, &mut devmem);
    assert!(!partition::secondary() || outgoing.is_some(), "secondary serial relay ring");
    assert!(((&raw const SERIAL) as usize - layout::image_base()) / 4096 + host::serial::PAGES <= bootinfo.user_image_frames().len());
    let serial_frames = image_frame((&raw const SERIAL) as usize);
    // ACPI table frames are shared by RTC discovery, reset and trustd.
    #[cfg(target_arch = "x86_64")]
    let mut acpi_frames = acpi::Frames::new();
    // The RTC is partition 0's; the others start from the shim's reading.
    #[allow(unused_mut)]
    let mut rtc = if partition::secondary() { rtc::Rtc::none() } else { rtc::Rtc::new(&mut alloc, &mut devmem) };
    #[cfg(target_arch = "x86_64")]
    if !partition::secondary() {
        rtc.find_century(bootinfo, &mut acpi::Phys::new(&mut alloc, &mut devmem, &mut wins.a, &mut acpi_frames));
    }
    let info = HostInfo {
        cores,
        topology,
        tsc_hz,
        log_frames: {
            let first = (&raw const LOG) as usize;
            let i = (first - layout::image_base()) / 4096;
            assert!(i + host::log::PAGES <= bootinfo.user_image_frames().len());
            bootinfo.user_image_frames().index(i).cap().bits()
        },
        serial_frames,
        serial_lanes: {
            let first = (&raw const SERIAL_LANES) as usize;
            assert!((first - layout::image_base()) / 4096 + host::serial::LANES_PAGES <= bootinfo.user_image_frames().len());
            image_frame(first)
        },
        cpu_id: cpu_id(bootinfo),
        hyp_ep,
        sched_control_base: bootinfo.sched_control().range().start,
        timeslice_us: 5000,
        epoch_ns: if partition::secondary() { partition::epoch_ns(tsc_hz) } else { rtc.read_ns(&mut wins.a) },
        epoch_ticks: rdtsc(),
        // Asked by trying, and a debug kernel prints its refusal on the
        // serial port itself: asked here, before logd prints anything, the
        // message cannot land inside a line of host output (§10.4).
        #[cfg(target_arch = "x86_64")]
        vtx: alloc.can_retype(&sel4::ObjectBlueprintArch::VCpu.into()),
        #[cfg(not(target_arch = "x86_64"))]
        vtx: false,
    };
    let mut asids = AsidPools { pools: [(slot::ASID_POOL.cap(), 1)].into_iter().collect(), in_use: 1 };
    let dashboard = dashboard::Dashboard::new(bootinfo, &mut alloc, &mut devmem, cfg.fb_console);
    let logd = if uart.is_some() || outgoing.is_some() {
        let rings = partition::Rings::new(&mut alloc, &mut devmem);
        let fb = dashboard.as_ref().and_then(|d| d.console_area());
        logd::spawn(&mut alloc, &mut wins.a, &mut asids, &info, uart.as_ref(), &rings, fb, outgoing)
    } else { None };
    // From here on, memory comes from memd.
    let mut memd = memd::spawn(&mut alloc, &mut wins.a, &mut asids, &info);
    assert!(!host::TEST_INJECT || !cfg.test_early_panic, "injected early panic");

    // The region partitions share (IOMMU tables, locks): PCI configuration
    // without ECAM takes a lock in it.
    #[cfg(target_arch = "x86_64")]
    iommu::shared::map(&mut alloc, &mut devmem, info.tsc_hz / 1000);
    // PCI devices: disks can be passed through to guests.
    let pci = pci::Pci::new(&mut alloc, &mut devmem);
    // The IOMMU before any device is enabled: from here on, a device
    // reaches only memory root gives it (iommu.rs).
    #[cfg(target_arch = "x86_64")]
    let mut iommu = {
        let mut phys = acpi::Phys::new(&mut alloc, &mut devmem, &mut wins.a, &mut acpi_frames);
        iommu::Iommu::init(bootinfo, &mut phys, &pci, info.tsc_hz / 1000, cfg.iommu, cfg.iommu_intremap)
    };
    #[cfg(not(target_arch = "x86_64"))]
    let mut iommu = if cfg.iommu { iommu::Iommu::none() } else { iommu::Iommu::off() };
    // The statics' only references, taken once here; the root task is
    // single-threaded.
    let ctrls = unsafe { &mut *(&raw mut CTRLS) };
    let mut nics = ArrayVec::<pci::Device, { host::net::MAX_NICS }>::new();
    let mut nic_bars = ArrayVec::<blkd::BarCache, { host::net::MAX_NICS }>::new();
    let mut balloon = None;
    let pci_inventory = pci::INVENTORY.take();
    for d in pci.enumerate() {
        pci_inventory.must_push(pci.identity(&d));
        let record = pci_inventory.last_mut().unwrap();
        info!(
            "l4h-root: pci {:02x}:{:02x}.{} {:04x}:{:04x} class {:02x}{:02x}",
            d.bus, d.dev, d.func, d.vendor, d.device, d.class, d.subclass
        );
        if d.vendor == 0x1af4 || d.vendor == 0x1ae0 {
            let caps = pci::List(d.virtio_caps.iter().map(|c| c.cfg_type));
            let bars = pci::List(d.bars.iter().filter(|b| b.size != 0).map(|b| (b.addr, b.size, b.is_io)));
            info!(
                "l4h-root:   virtio caps {:?}, msix {:?}, bars {:x?}",
                caps, d.msix.map(|m| (m.table_bar, m.table_size)), bars
            );
        }
        if blkd::is_disk(&d) {
            if ctrls.len() == pci::MAX_DISK_CTRLS {
                log!("l4h-root: more than {} disk controllers, ignoring this one", pci::MAX_DISK_CTRLS);
                continue;
            }
            // Stop whatever the firmware left running: no DMA at all (the
            // memory it was given is not known), and a reset, since bus
            // mastering is enabled again on attach.
            pci.disable(&d);
            let v = pci::VECTOR_DISK_BASE + ctrls.len() as u64;
            let mut ctrl = Controller::new(d, v);
            blkd::reset(&mut ctrl, &pci, &mut alloc, &mut devmem, &mut wins.a, info.tsc_hz / 1000);
            pci.disable(&ctrl.pci);
            // Below MAX_DISK_CTRLS: checked above.
            let _ = ctrls.push(ctrl);
            record.owner = l4h_abi::PCI_OWNER_BLKD;
        } else if netd::is_uplink(&d) {
            pci.disable(&d);
            let mut bars = [const { None }; 6];
            if nics.is_full() {
                log!("l4h-root: more than {} NICs, ignoring {:02x}:{:02x}.{}", host::net::MAX_NICS, d.bus, d.dev, d.func);
            } else if netd::carve(&mut alloc, &mut devmem, &d, &mut bars) {
                nics.must_push(d);
                nic_bars.must_push(bars);
                record.owner = l4h_abi::PCI_OWNER_NETD;
            }
        } else if usb::is_xhci(&d) {
            // Left to the firmware, enabled as it is, until claimed.
            usb::found(d, &pci, &mut alloc, &mut devmem);
            record.owner = l4h_abi::PCI_OWNER_FIRMWARE;
        } else if memd::is_balloon(&d) && balloon.is_none() && !partition::secondary() {
            balloon = Some(d);
            record.owner = l4h_abi::PCI_OWNER_MEMD;
        }
    }
    pci_inventory.sort_unstable_by_key(|p| p.bdf);
    // The boot disk first: dom0 takes the first dom0_disks host disks.
    if let Some(bdf) = cfg.boot_disk {
        match ctrls.iter().position(|c: &Controller| netd::bdf(&c.pci) == bdf) {
            Some(i) => ctrls[..=i].rotate_right(1),
            None => log!("l4h-root: no boot disk at {:02x}:{:02x}.{}", bdf >> 8, (bdf >> 3) & 0x1f, bdf & 7),
        }
    }
    if let Some(d) = balloon {
        memd.attach_balloon(&d, &pci, &mut iommu, &mut alloc, &mut devmem);
    }
    // Only partition 0 resets the machine (DESIGN.md §11.4).
    #[cfg(target_arch = "x86_64")]
    let reset = if partition::secondary() {
        reset::Reset::default()
    } else {
        reset::Reset::find(bootinfo, &mut acpi::Phys::new(&mut alloc, &mut devmem, &mut wins.a, &mut acpi_frames))
    };
    #[cfg(not(target_arch = "x86_64"))]
    let reset = reset::Reset::default();
    let trustd = trustd::spawn(
        bootinfo, &mut alloc, &mut devmem, &mut wins.a, &mut asids, &info,
        #[cfg(target_arch = "x86_64")]
        acpi_frames,
    );
    let netd = netd::spawn(&nics, &nic_bars, &pci, &mut iommu, &mut alloc, &mut wins.a, &mut asids, &info);

    let mut h = Host {
        info,
        alloc,
        wins,
        asids,
        pci,
        pci_inventory,
        iommu,
        devmem,
        ctrls,
        disks: unsafe { &mut *(&raw mut DISKS) },
        netd,
        guests: GUESTS.take(),
        ops: OPS.take(),
        zombies: ZOMBIES.take(),
        total_bytes,
        monitor: None,
        dashboard,
        cfg,
        trustd,
        next_instance: 1,
        memd,
        reset,
        rtc,
        vmmgr: None,
        logd,
        ntfn: wd_ntfn,
        channels: None,
    };
    h.start_disks();
    // The serial port and its interrupt (an I/O APIC pin) are partition 0's.
    if !partition::secondary() {
        h.monitor = uart.as_ref().and_then(|u| monitor::Monitor::new(&mut h.alloc, wd_ntfn, u.monitor, h.cfg.serial_port, h.cfg.serial_irq, &mut h.iommu));
    }
    h.channels = channel::Channels::new(&mut h.alloc, &mut h.devmem, wd_ntfn, h.info.tsc_hz);
    // The rest of the boot needs the drivers' disks and MACs, which root
    // does not wait for: the serve loop finishes it (finish_boot).
    serve(&mut h, reply, &modules)
}

/// The drivers have published their disks and MACs: number the disks, and
/// start vmmgr with dom0's plan.
fn finish_boot(h: &mut Host, modules: &bootmod::Modules) {
    h.number_disks();
    if !modules.iter().any(|m| m.name == "guest-kernel") {
        log!("l4h-root: no guest kernel, nothing to do");
    } else {
        let plan = dom0_plan(h, h.ntfn);
        h.vmmgr = Some(vmmgr::spawn(h, modules, &plan));
    }
}

/// dom0's disks and vNICs, the same for every dom0 vmmgr starts: the
/// first dom0_disks host disks, and vNICs on switch 0 (with the uplink
/// NIC) and the other switches root makes now.  `ntfn` is root's own
/// notification, which netd signals to have link doorbells rung.
fn dom0_plan(h: &mut Host, ntfn: cap::Notification) -> Dom0Plan {
    let mut plan = Dom0Plan::default();
    let mut links = ArrayVec::<(l4h_partition::Channel, bool), { l4h_partition::MAX_PARTITIONS - 1 }>::new();
    for ch in h.channels.iter().flat_map(|c| c.links()) {
        links.must_push((*ch, ch.kind & l4h_partition::CHANNEL_LINK_UPLINK != 0));
    }
    // By default, room for full receive rings on all of dom0's vNICs (one
    // per uplink switch it is given, one per internal switch, one per link).
    // The counts are the config file's: more NICs than dom0 can have
    // stop the boot below.
    let nics = h.cfg.dom0_nics.saturating_add(h.cfg.uplink2_nic.is_some() as usize).saturating_add(h.cfg.dom0_internal_switches)
        .saturating_add(links.iter().filter(|&&(_, uplink)| !uplink).count()).min(host::vmmgr::DOM0_MAX_NICS);
    plan.io_pool = match h.cfg.dom0_io_pool_mb {
        0 => l4h_host::iopool::for_nics(nics, vmmgr::IO_POOL_DEFAULT).min(256 << 20),
        mb => mb.saturating_mul(1 << 20),
    };
    if h.cfg.dom0_disk0_windows.is_some() {
        assert!(h.cfg.dom0_disks > 0 && !h.disks.is_empty(), "dom0 disk windows need disk 0");
        assert!(h.cfg.dom0_disk0_mb == 0, "choose disk0_mb or disk0_windows");
    }
    for d in 0..h.disks.len().min(h.cfg.dom0_disks) {
        if let Err(e) = h.ensure_disk(d) {
            log!("l4h-root: dom0 disk {} geometry unavailable: error {}", d, e);
        }
        let capacity = match h.disks[d].capacity {
            0 => blkd::UNKNOWN_CAPACITY,
            n => n,
        };
        if d == 0 {
            if let Some(text) = h.cfg.dom0_disk0_windows {
                // A list that is no list of windows is the config file's
                // error; a disk too small for it is the disk's word.
                let (windows, len, fits) = blkd::dom0_windows::<{ host::vmmgr::DOM0_MAX_DISKS }>(text, h.disks[d].capacity)
                    .expect("invalid dom0_disk0_windows");
                if !fits {
                    log!("l4h-root: dom0_disk0_windows do not fit disk 0 ({} sectors): windows beyond it are placeholders", h.disks[d].capacity);
                }
                for w in &windows[..len] {
                    plan.disks.push(host::vmmgr::Dom0Disk { disk: 0, start: w.start, sectors: w.sectors })
                        .ok().expect("too many dom0 disk windows");
                }
                continue;
            }
        }
        // Of disk 0, only the first dom0_disk0_mb MiB if the disk is larger.
        let mut sectors = 0;
        if d == 0 && h.cfg.dom0_disk0_mb > 0 {
            let n = (h.cfg.dom0_disk0_mb as u64).saturating_mul(1 << 11);
            if n < capacity { sectors = n; }
        }
        plan.disks.push(l4h_host::vmmgr::Dom0Disk { disk: d as u64, start: 0, sectors })
            .ok().expect("too many dom0 disks");
    }
    // Switch 0, with the uplink NIC (if any; by default the first) as its
    // uplink.
    let sw = 0;
    h.netd.create_switch();
    let nic = match h.cfg.uplink_nic {
        None => (!h.netd.nics.is_empty()).then_some(0),
        Some(bdf) => {
            let n = h.netd.nics.iter().position(|n| netd::bdf(&n.pci) == bdf);
            if n.is_none() {
                log!("l4h-root: no uplink NIC at {:02x}:{:02x}.{}", bdf >> 8, (bdf >> 3) & 0x1f, bdf & 7);
            }
            n
        }
    };
    if let Some(nic) = nic {
        if let Err(e) = h.netd.attach_uplink(sw, nic) {
            log!("l4h-root: no uplink on switch {}: error {}", sw, e);
        }
    }
    let mut add_nic = |switch: u32, mac: u64| {
        plan.nics.push(l4h_host::vmmgr::Dom0Nic { switch: switch as u64, mac })
            .ok().expect("too many dom0 NICs");
    };
    // dom0's first vNIC takes the uplink NIC's MAC address: networks
    // like GCE's only deliver frames for the instance's own address, so
    // dom0 is then the host's router (DESIGN.md §9.3).
    let uplink = h.netd.nics.iter().position(|n| n.switch == Some(sw));
    for i in 0..h.cfg.dom0_nics {
        let mac = if i == 0 { uplink.and_then(|n| h.netd.nic_mac(n)).unwrap_or(0) } else { 0 };
        add_nic(sw, mac);
    }
    // The second uplink NIC, if any, on switch 1, then the internal
    // switches. dom0 finds its vNICs by MAC, not by their order.
    let uplink2 = h.cfg.uplink2_nic.and_then(|bdf| {
        let n = h.netd.nics.iter().position(|n| netd::bdf(&n.pci) == bdf);
        if n.is_none() {
            log!("l4h-root: no second uplink NIC at {:02x}:{:02x}.{}", bdf >> 8, (bdf >> 3) & 0x1f, bdf & 7);
        }
        n
    });
    if let Some(nic) = uplink2 {
        h.netd.create_switch();
        if let Err(e) = h.netd.attach_uplink(1, nic) {
            log!("l4h-root: no uplink on switch 1: error {}", e);
        }
        add_nic(1, h.netd.nic_mac(nic).unwrap_or(0));
    }
    let first = 1 + uplink2.is_some() as usize;
    let end = first.saturating_add(h.cfg.dom0_internal_switches);
    while (h.netd.switches as usize) < end {
        h.netd.create_switch();
    }
    for i in first..end {
        add_nic(i as u32, 0);
    }
    // Each link to another partition gets a switch of its own, with a
    // vNIC of dom0's: partitions meet where their dom0s connect them,
    // never on each other's uplink network.  An `uplink` link instead
    // joins switch 0 on both sides, where dom0's first vNIC (and the
    // uplink NIC, on the side that has one) are: partitions without a NIC
    // of their own share the network of one that has.
    let me = partition::get().map_or(0, |d| d.index);
    for (ch, uplink) in links.iter() {
        let (peer, uplink) = (ch.peer, *uplink);
        let sw = if uplink { 0 } else { h.netd.create_switch() };
        match h.netd.add_link(ch, me, sw, ntfn, &mut h.alloc, &mut h.devmem, &h.pci) {
            Ok(l) => info!("l4h-root: link to partition {} on switch {} (netd link {})", peer, sw, l),
            Err(e) => log!("l4h-root: no link to partition {}: error {}", peer, e),
        }
        if !uplink {
            add_nic(sw, 0);
        }
    }
    plan.usbs = usb::dom0_ctrls(h);
    // Reserve the whole plan before vmmgr can attach anything. Reservations
    // also cover placeholders and survive dom0 restarts, so no system range
    // becomes available to another guest or to provisioning on a failure.
    for d in &plan.disks {
        let index = d.disk as usize;
        let disk = &h.disks[index];
        let window = blkd::dom0_plan_reservation(d.start, d.sectors, disk.capacity).expect("invalid dom0 disk window");
        h.ctrls[disk.ctrl].reserve_dom0(index, disk.unit, window, disk.read_only);
    }
    plan
}

/// CPU time a scheduling context used since the last call, in timer ticks.
pub fn sched_consumed(sc: sel4::cap::SchedContext) -> u64 {
    let r = sel4::with_ipc_buffer_mut(|ipc| ipc.inner_mut().seL4_SchedContext_Consumed(sc.bits()));
    if r.error != 0 {
        log!("l4h-root: SchedContext_Consumed({:#x}) failed: {}", sc.bits(), r.error);
        return 0;
    }
    r.consumed
}

fn rdtsc() -> u64 {
    host::ticks::now()
}

/// The root task's timer period: dashboard, IOMMU faults and watchdog.
const TIMER_MS: u64 = 100;

/// How long boot waits for the drivers to publish their disks and MACs
/// (finish_boot), from when the serve loop starts, right after they were
/// started.  Root never waits on a driver without a bound: one that has
/// not published by then is failed (Host::fail_unready_drivers), and the
/// host boots without what it drove, until reboot.  That is the end of a
/// driver that hangs, not of one that is slow: a driver gives its own
/// device up long before (an NVMe controller that does not become ready,
/// a virtio device that does not reset, a NIC command that is not
/// answered), panics, and is failed at once as any that faults.  So the
/// bound is far beyond what a controller that works takes, on slow
/// emulation too, and root says after DRIVERS_SLOW_SECS which drivers it
/// still waits for.
const DRIVERS_READY_SECS: u64 = 180;
const DRIVERS_SLOW_SECS: u64 = 30;

pub fn arm_timer(info: &HostInfo) -> u64 {
    let deadline = rdtsc() + info.tsc_hz * TIMER_MS / 1000;
    set_timer(deadline);
    deadline
}

/// Signal root's notification at `deadline`, replacing what was armed.
pub fn set_timer(deadline: u64) {
    let tcb = slot::TCB.cap();
    sel4::with_ipc_buffer_mut(|ipc| ipc.inner_mut().seL4_TCB_SetTimer(tcb.bits(), deadline, recv::TIMER));
}

/// When the next watchdog dump is due: watchdog_secs is the config file's.
fn watchdog_after(h: &Host) -> u64 {
    rdtsc().saturating_add(h.info.tsc_hz.saturating_mul(h.cfg.watchdog_secs as u64))
}

/// Root's part of the watchdog dump (vmmgr dumps the guests' vCPUs).
fn watchdog_dump(h: &Host) {
    let ms = |ticks: u64| ticks * 1000 / h.info.tsc_hz.max(1);
    log!(
        "l4h-root: watchdog: netd used {} ms, vmmgr {} ms since the last dump",
        ms(h.netd.consumed()), ms(h.vmmgr.as_ref().map_or(0, |v| v.consumed()))
    );
}

/// Serve calls from host components and faults of guest kernels.
/// Root's thread: calls and faults of host components, the timer, the
/// serial monitor's and partitions' interrupts, and drivers' answers.
struct Root<'a> {
    h: &'a mut Host,
    modules: &'a bootmod::Modules,
    booting: bool,
    /// When boot stops waiting for the drivers (DRIVERS_READY_SECS), and
    /// when it says which it waits for (DRIVERS_SLOW_SECS; None once said).
    drivers_deadline: u64,
    drivers_slow: Option<u64>,
    next_watchdog: u64,
    deadline: u64,
}

fn serve(h: &mut Host, reply: ReplySlot, modules: &bootmod::Modules) -> ! {
    let deadline = arm_timer(&h.info);
    let next_watchdog = watchdog_after(h);
    let hyp_ep = h.info.hyp_ep;
    let after = |secs: u64| rdtsc().saturating_add(h.info.tsc_hz.saturating_mul(secs));
    let (drivers_deadline, drivers_slow) = (after(DRIVERS_READY_SECS), Some(after(DRIVERS_SLOW_SECS)));
    l4h_ipc::run(hyp_ep, reply, &mut Root { h, modules, booting: true, drivers_deadline, drivers_slow, next_watchdog, deadline })
}

impl l4h_ipc::Server for Root<'_> {
    const SIGNALS: u64 = recv::SIGNALS;
    const FAULT: u64 = recv::FAULT;
    type Sender = host::root::Sender;

    fn notification(&self) -> Option<l4h_ipc::Bound> {
        Some(l4h_ipc::Bound::new(slot::TCB.cap(), self.h.ntfn))
    }

    fn rebound(&mut self) {
        set_timer(self.deadline);
    }

    fn received(&mut self) {
        self.h.alloc.refill();
    }

    fn signal(&mut self, badge: u64) {
        let h = &mut *self.h;
        // Drivers' answers, and what a quarantine left (blkd::poll).  Not
        // on a call: it would overwrite the caller's message registers.
        h.poll_drivers();
        if self.booting && !h.drivers_ready() {
            let now = rdtsc();
            if now > self.drivers_deadline {
                h.fail_unready_drivers();
            } else if self.drivers_slow.is_some_and(|at| now > at) {
                self.drivers_slow = None;
                h.log_unready_drivers();
            }
        }
        if self.booting && h.drivers_ready() {
            self.booting = false;
            finish_boot(h, self.modules);
        }
        if badge & recv::MONITOR != 0 {
            monitor::Monitor::interrupt(h);
        }
        if badge & recv::CHANNEL != 0 {
            channel::poll(h);
        }
        if badge & recv::LINK.mask() != 0 {
            h.netd.link_ring(badge);
        }
        if badge & recv::TIMER != 0 {
            dashboard::Dashboard::tick(h);
            channel::tick(h);
            trustd::tick(h);
            h.iommu.poll();
            if h.cfg.watchdog_secs != 0 && rdtsc() >= self.next_watchdog {
                watchdog_dump(h);
                self.next_watchdog = watchdog_after(h);
            }
            self.deadline = arm_timer(&h.info);
        }
    }

    fn fault(&mut self, badge: u64, info: &sel4::MessageInfo) {
        let id = recv::ID.get(badge) as u32;
        let fault = sel4::with_ipc_buffer(|b| sel4::Fault::new(b, info));
        log!("l4h-root: component {:#x} fault: {:x?}", id, fault);
        // A driver (it has no keeper) is failed here; trustd's start-up
        // stops.
        let h = &mut *self.h;
        let _ = blkd::fault(h, id) || netd::Netd::fault(h, id) || crate::usb::fault(h, id);
        trustd::fault(h, id);
    }

    fn call(&mut self, from: host::root::Sender, _: u64, info: &sel4::MessageInfo) -> Option<sel4::MessageInfo> {
        l4h_ipc::serve::<root_call::Proto>(info, |label, args, out| root_call::serve(&mut vmmgr::Calls(self.h), label, args, from, out))
    }

    fn unknown(&mut self, badge: u64, info: &sel4::MessageInfo) {
        log!("l4h-root: unknown call {} badged {:#x}", info.label(), badge);
    }
}

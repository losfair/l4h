//! l4h-root: the l4h root task.  Owns the devices and spawns the host
//! components, l4h-vmmgr last, which builds and runs the guests (vmmgr.rs).
//! Root makes what devices reach for guests when vmmgr asks: their I/O
//! pools, disk channels and netd ports.  Memory is l4h-memd's once it runs
//! (memd.rs).  See DESIGN.md §9.

#![no_std]
#![no_main]

/// Always retained; printed to serial only in verbose builds.
macro_rules! info {
    ($($arg:tt)*) => {
        l4h_task::print_log(format_args!($($arg)*), l4h_host::VERBOSE)
    };
}

macro_rules! log {
    ($($arg:tt)*) => { l4h_task::print_log(format_args!($($arg)*), true) };
}

#[cfg(target_arch = "x86_64")]
mod acpi;
mod amdvi;
mod blkd;
mod bootmod;
mod component;
mod config;
mod ctl;
mod dashboard;
mod devmem;
mod font;
mod iommu;
mod layout;
mod memd;
mod monitor;
mod netd;
mod pci;
mod reset;
mod rtc;
mod trustd;
mod vmmgr;
#[cfg(target_arch = "x86_64")]
mod vtd;

use l4h_host::fixed::StaticCell;

/// The root task's own capabilities.
pub use sel4::init_thread::slot;
use sel4::{ObjectBlueprint, cap, cap_type};
use sel4_root_task::{Never, root_task};

use l4h_host as host;
use l4h_host::fixed::ArrayVec;
use l4h_task::{mem, topology, vspace, window};

use crate::blkd::{Controller, Disk};
use crate::component::ROOT_BADGE_COMPONENT;
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
pub const MAX_GUESTS: usize = 64;
/// Badge bit of a component's fault on the root endpoint.
pub const HYP_BADGE_FAULT: u64 = host::BADGE_FAULT;
/// What root made for vmmgr's guests, by id.
static GUESTS: StaticCell<[Option<RootGuest>; MAX_GUESTS]> = StaticCell::new([const { None }; MAX_GUESTS]);
/// Memory and root CNode slots kept back from guest requests.
const RESERVE_BYTES: usize = 32 << 20;
const RESERVE_SLOTS: usize = 32768;
/// Longest free slot range kept for disk DMA buffers.
const RESERVE_RANGE: usize = 4096;

const TIMER_BADGE: u64 = 1 << 40;

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
    /// AArch64 feature ID registers for the guests' bootinfo (`cpu_id`).
    pub cpu_id: [u64; 5],
    pub hyp_ep: cap::Endpoint,
    sched_control_base: usize,
    pub timeslice_us: u64,
    /// Wall clock at boot (ns since the epoch, 0 if unknown) and the tick
    /// count when it was read.
    pub epoch_ns: u64,
    pub epoch_ticks: u64,
}

impl HostInfo {
    pub fn spawn_context(&self, core: usize) -> component::SpawnContext {
        component::SpawnContext {
            authority: slot::TCB.cap(),
            sched_control: self.sched_control(core),
            parent_ep: self.hyp_ep,
            tsc_hz: self.tsc_hz,
            log_frames: self.log_frames,
        }
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
    pub iommu: iommu::Iommu,
    pub devmem: devmem::DevMem,
    /// Disk controllers, and their units as host disks.
    pub ctrls: &'static mut ArrayVec<Controller, { pci::MAX_DISK_CTRLS }>,
    pub disks: &'static mut ArrayVec<Disk, MAX_DISKS>,
    pub netd: netd::Netd,
    /// What root made for vmmgr's guests.
    pub guests: &'static mut [Option<RootGuest>; MAX_GUESTS],
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
    pub fn ensure_disk(&mut self, disk: usize) -> Result<(), i64> {
        let (c, unit) = self.disks.get(disk).map(|d| (d.ctrl, d.unit)).ok_or(ctl::ENOENT)?;
        if self.ctrls[c].failed { return Err(ctl::EIO); }
        if self.disks[disk].capacity == 0 {
            let d = self.ctrls[c].info(unit).0.ok_or(ctl::EIO)?;
            self.disks[disk] = Disk { ctrl: c, ..d };
        }
        Ok(())
    }

    /// Start every controller's blkd and number the host disks: one per
    /// unit of each controller, in PCI order.  The host fails to boot if
    /// it cannot start them all (each needs 4 MiB of physically
    /// contiguous DMA memory), so no disk is ever missing its driver.  A
    /// controller that did not reset stays disabled: its disk (virtio-blk
    /// and NVMe have one) keeps its number and fails with EIO, and a
    /// virtio-scsi one has no units to report.
    fn scan_disks(&mut self) {
        let add = |disks: &mut ArrayVec<Disk, MAX_DISKS>, d: Disk| {
            let (unit, ctrl) = (d.unit, d.ctrl);
            if disks.push(d).is_err() {
                log!("l4h-root: more than {} disks, unit {} of controller {} ignored", MAX_DISKS, unit, ctrl);
            }
        };
        for c in 0..self.ctrls.len() {
            let failed = self.ctrls[c].failed;
            if !failed {
                blkd::start(0x100 + c as u32, &mut self.ctrls[c], &self.pci, &mut self.iommu,
                    &mut self.devmem, &mut self.alloc, &mut self.wins.a, &mut self.asids, &self.info);
            }
            if self.ctrls[c].kind != l4h_host::blk::BLKD_VIRTIO_SCSI {
                add(self.disks, Disk::new(c, 0));
                continue;
            }
            if failed {
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
}

/// The root task's stack, its lowest page a guard (layout::guard_stack).
pub const ROOT_STACK: usize = 1024 * 1024;

#[root_task(stack_size = ROOT_STACK)]
fn main(bootinfo: &sel4::BootInfoPtr) -> sel4::Result<Never> {
    let tsc_hz = tsc_hz(bootinfo);
    LOG.set_clock(rdtsc(), tsc_hz);
    host::log::init(&LOG, 0);
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
    let reply = ReplySlot::new(&mut alloc);
    let mut wins = Windows {
        a: Window::new(&mut alloc, slot::VSPACE.cap(), layout::WINDOWS.base),
        b: Window::new(&mut alloc, slot::VSPACE.cap(), layout::WINDOWS.base + 4096),
    };
    let mut devmem = devmem::DevMem::from_bootinfo(bootinfo);
    let modules = bootmod::load(bootinfo, &mut alloc, &mut devmem);
    let module = |name: &str| modules.iter().find(|m| m.name == name).map(|m| m.data);
    let cfg = config::Config::new(module("l4h-config"));
    // ACPI table frames are shared by RTC discovery, reset and trustd.
    #[cfg(target_arch = "x86_64")]
    let mut acpi_frames = acpi::Frames::new();
    #[allow(unused_mut)]
    let mut rtc = rtc::Rtc::new(&mut alloc, &mut devmem);
    #[cfg(target_arch = "x86_64")]
    rtc.find_century(bootinfo, &mut acpi::Phys::new(&mut alloc, &mut devmem, &mut wins.a, &mut acpi_frames));
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
        cpu_id: cpu_id(bootinfo),
        hyp_ep,
        sched_control_base: bootinfo.sched_control().range().start,
        timeslice_us: 5000,
        epoch_ns: rtc.read_ns(&mut wins.a),
        epoch_ticks: rdtsc(),
    };
    let mut asids = AsidPools { pools: [(slot::ASID_POOL.cap(), 1)].into_iter().collect(), in_use: 1 };
    // From here on, memory comes from memd.
    let mut memd = memd::spawn(&mut alloc, &mut wins.a, &mut asids, &info);

    // PCI devices: disks can be passed through to guests.
    let pci = pci::Pci::new(&mut alloc, &mut devmem);
    // The IOMMU before any device is enabled: from here on, a device
    // reaches only memory root gives it (iommu.rs).
    #[cfg(target_arch = "x86_64")]
    let mut iommu = if cfg.iommu {
        let mut phys = acpi::Phys::new(&mut alloc, &mut devmem, &mut wins.a, &mut acpi_frames);
        iommu::Iommu::init(bootinfo, &mut phys, &pci, info.tsc_hz / 1000, cfg.iommu_intremap)
    } else {
        log!("l4h-root: iommu=0: DMA is not confined");
        iommu::Iommu::off()
    };
    #[cfg(not(target_arch = "x86_64"))]
    let mut iommu = if cfg.iommu { iommu::Iommu::none() } else { iommu::Iommu::off() };
    // The statics' only references, taken once here; the root task is
    // single-threaded.
    let ctrls = unsafe { &mut *(&raw mut CTRLS) };
    let mut nics = ArrayVec::<pci::Device, { host::net::MAX_NICS }>::new();
    let mut balloon = None;
    for d in pci.enumerate() {
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
        } else if netd::is_uplink(&d) {
            pci.disable(&d);
            if nics.push(d).is_err() {
                log!("l4h-root: more than {} NICs, ignoring {:02x}:{:02x}.{}", host::net::MAX_NICS, d.bus, d.dev, d.func);
            }
        } else if memd::is_balloon(&d) && balloon.is_none() {
            balloon = Some(d);
        }
    }
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
    #[cfg(target_arch = "x86_64")]
    let reset = reset::Reset::find(bootinfo, &mut acpi::Phys::new(&mut alloc, &mut devmem, &mut wins.a, &mut acpi_frames));
    #[cfg(not(target_arch = "x86_64"))]
    let reset = reset::Reset::default();
    let trustd = trustd::spawn(
        bootinfo, &mut alloc, &mut devmem, &mut wins.a, &mut asids, &info,
        #[cfg(target_arch = "x86_64")]
        acpi_frames,
    );
    let netd = netd::spawn(&nics, &pci, &mut iommu, &mut devmem, &mut alloc, &mut wins.a, &mut asids, &info);

    let mut h = Host {
        info,
        alloc,
        wins,
        asids,
        pci,
        iommu,
        devmem,
        ctrls,
        disks: unsafe { &mut *(&raw mut DISKS) },
        netd,
        guests: GUESTS.take(),
        total_bytes,
        monitor: None,
        dashboard: None,
        cfg,
        trustd,
        next_instance: 1,
        memd,
        reset,
        rtc,
        vmmgr: None,
    };
    h.scan_disks();
    h.monitor = monitor::Monitor::new(&mut h.alloc, &mut h.devmem, wd_ntfn, h.cfg.serial_port, h.cfg.serial_irq, &mut h.iommu);
    h.dashboard = dashboard::Dashboard::new(bootinfo, &mut h.alloc, &mut h.devmem, h.cfg.fb_console);

    if module("guest-kernel").is_none() {
        log!("l4h-root: no guest kernel, nothing to do");
    } else {
        let plan = dom0_plan(&mut h);
        h.vmmgr = Some(vmmgr::spawn(&mut h, &modules, &plan));
    }
    serve(&mut h, reply)
}

/// dom0's disks and vNICs, the same for every dom0 vmmgr starts: the
/// first dom0_disks host disks, and vNICs on switch 0 (with the uplink
/// NIC) and the other switches root makes now.
fn dom0_plan(h: &mut Host) -> Dom0Plan {
    let mut plan = Dom0Plan::default();
    // By default, room for full receive rings on all of dom0's vNICs (one
    // per uplink switch it is given, one per internal switch).
    let nics = h.cfg.dom0_nics + h.cfg.uplink2_nic.is_some() as usize + h.cfg.dom0_internal_switches;
    plan.io_pool = match h.cfg.dom0_io_pool_mb {
        0 => l4h_host::iopool::for_nics(nics, vmmgr::IO_POOL_DEFAULT).min(256 << 20),
        mb => mb << 20,
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
                let (windows, len) = host::blk::DiskWindow::parse_list::<{ host::vmmgr::DOM0_MAX_DISKS }>(text, capacity)
                    .expect("invalid dom0_disk0_windows");
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
            let n = (h.cfg.dom0_disk0_mb as u64) << 11;
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
    // dom0 is then the host's router (DESIGN.md §8.3).
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
    while (h.netd.switches as usize) < first + h.cfg.dom0_internal_switches {
        h.netd.create_switch();
    }
    for i in first..first + h.cfg.dom0_internal_switches {
        add_nic(i as u32, 0);
    }
    // Reserve the whole plan before vmmgr can attach anything. Reservations
    // also cover placeholders and survive dom0 restarts, so no system range
    // becomes available to another guest or to provisioning on a failure.
    for d in &plan.disks {
        let index = d.disk as usize;
        let disk = &h.disks[index];
        let window = blkd::dom0_reservation(d.start, d.sectors, disk.capacity).expect("invalid dom0 disk window");
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

fn arm_timer(info: &HostInfo) {
    let deadline = rdtsc() + info.tsc_hz * TIMER_MS / 1000;
    let tcb = slot::TCB.cap();
    sel4::with_ipc_buffer_mut(|ipc| ipc.inner_mut().seL4_TCB_SetTimer(tcb.bits(), deadline, TIMER_BADGE));
}

/// Root's part of the watchdog dump (vmmgr dumps the guests' vCPUs).
fn watchdog_dump(h: &Host) {
    let ms = |ticks: u64| ticks * 1000 / h.info.tsc_hz.max(1);
    log!(
        "l4h-root: watchdog: netd used {} ms, vmmgr {} ms since the last dump",
        ms(h.netd.consumed()), ms(h.vmmgr.as_ref().map_or(0, |v| v.consumed()))
    );
}

pub fn mr(i: usize) -> u64 {
    sel4::with_ipc_buffer(|b| b.msg_regs()[i])
}

pub fn set_mr(i: usize, v: u64) {
    sel4::with_ipc_buffer_mut(|b| b.msg_regs_mut()[i] = v)
}

/// Serve calls from host components and faults of guest kernels.
/// The serve loop's reply object, made from an Untyped of its own so that
/// one left unanswered can be replaced without using more memory.
struct ReplySlot {
    ut: cap::Untyped,
    reply: cap::Reply,
}

impl ReplySlot {
    fn new(alloc: &mut Alloc) -> Self {
        let (ut_slot, slot) = (alloc.slots.alloc(), alloc.slots.alloc());
        let ut = alloc.split(12, ut_slot).expect("reply object memory").cap;
        let r = ReplySlot { ut, reply: sel4::init_thread::Slot::<cap_type::Reply>::from_index(slot).cap() };
        r.make();
        r
    }

    fn make(&self) {
        self.ut
            .untyped_retype(&ObjectBlueprint::Reply, &mem::cnode_dest(slot::CNODE.cap()), self.reply.bits() as usize, 1)
            .expect("reply object");
    }

    /// Replace the reply object, which is bound to a caller left
    /// unanswered (a faulted or stopped thread): revoking the Untyped
    /// deletes it, which leaves that thread inactive for good.
    fn renew(&self) {
        slot::CNODE.cap().absolute_cptr(self.ut).revoke().expect("revoke reply object");
        self.make();
    }
}

/// Serve calls and faults of host components, and the timer and serial
/// interrupts.
fn serve(h: &mut Host, reply_slot: ReplySlot) -> ! {
    let reply = reply_slot.reply;
    let hyp_ep = h.info.hyp_ep;
    arm_timer(&h.info);
    let mut next_watchdog = rdtsc() + h.info.tsc_hz * h.cfg.watchdog_secs as u64;
    let (mut info, mut badge) = hyp_ep.recv(reply);
    loop {
        h.alloc.refill();
        let notified = badge & (TIMER_BADGE | monitor::MONITOR_BADGE) != 0;
        if badge & monitor::MONITOR_BADGE != 0 {
            monitor::Monitor::interrupt(h);
        }
        let resp = if notified {
            if badge & TIMER_BADGE != 0 {
                dashboard::Dashboard::tick(h);
                h.iommu.poll();
                if h.cfg.watchdog_secs != 0 && rdtsc() >= next_watchdog {
                    watchdog_dump(h);
                    next_watchdog = rdtsc() + h.info.tsc_hz * h.cfg.watchdog_secs as u64;
                }
                arm_timer(&h.info);
            }
            None
        } else if badge & ROOT_BADGE_COMPONENT != 0 {
            component_call(h, badge, &info)
        } else {
            log!("l4h-root: unexpected message, badge {:#x} label {}", badge, info.label());
            None
        };
        match resp {
            Some(len) => {
                (info, badge) = hyp_ep.reply_recv(sel4::MessageInfo::new(0, 0, 0, len), reply);
            }
            None => {
                // A reply object left unanswered (a faulted or stopped
                // thread) stays bound to its caller: make it afresh.
                if !notified {
                    reply_slot.renew();
                }
                (info, badge) = hyp_ep.recv(reply);
            }
        }
    }
}

/// A call or fault from a host component.  Sets the reply's message
/// registers and returns its length, or None to leave the caller blocked.
fn component_call(h: &mut Host, badge: u64, info: &sel4::MessageInfo) -> Option<usize> {
    let id = (badge & 0xffff) as u32;
    if badge & HYP_BADGE_FAULT != 0 {
        let fault = sel4::with_ipc_buffer(|b| sel4::Fault::new(b, info));
        log!("l4h-root: component {:#x} fault: {:x?}", id, fault);
        trustd::fault(h, id);
        return None;
    }
    let reply = |v: u64| {
        set_mr(0, v);
        Some(1)
    };
    match info.label() {
        host::ROOT_CALL_HW if id == trustd::TRUSTD_ID => reply(trustd::hw(h)),
        host::ROOT_CALL_ATTEST_DONE if id == trustd::TRUSTD_ID => {
            trustd::done(h, mr(0) as usize);
            reply(0)
        }
        label if id == l4h_host::vmmgr::VMMGR_ID => Some(vmmgr::call(h, label)),
        other => {
            log!("l4h-root: component {:#x}: unknown call {}", id, other);
            reply(u64::MAX)
        }
    }
}

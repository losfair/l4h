//! l4h-root: the l4h root task.  Owns the devices, creates and destroys
//! guests with their host components, and serves the control API for dom0.
//! Memory is l4h-memd's once it runs (memd.rs).  See DESIGN.md §9.

#![no_std]
#![no_main]

/// An informational message: printed only when `host::VERBOSE` (not in
/// release builds).  Use `sel4::debug_println!` for critical errors only.
macro_rules! info {
    ($($arg:tt)*) => {
        if l4h_host::VERBOSE {
            sel4::debug_println!($($arg)*);
        }
    };
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
mod elf;
mod font;
mod gpu;
mod guest;
mod iommu;
mod kimage;
mod layout;
mod mem;
mod memd;
mod monitor;
mod netd;
mod pci;
mod reset;
mod rtc;
mod sched;
mod trustd;
mod vmm;
#[cfg(target_arch = "x86_64")]
mod vtd;
mod vspace;
mod window;

use l4h_host::fixed::StaticCell;

use sel4::init_thread::slot;
use sel4::{ObjectBlueprint, cap, cap_type};
use sel4_root_task::{Never, root_task};

use l4h_host as host;
use l4h_host::fixed::ArrayVec;

use crate::blkd::{Controller, Disk};
use crate::component::ROOT_BADGE_COMPONENT;
use crate::guest::{Guest, GuestConfig, HYP_BADGE_FAULT, State, hyp_badge_guest, hyp_badge_vcpu};
use crate::mem::{Alloc, Slots};
use crate::window::{Window, Windows};

pub const RETYPE_FAN_OUT: usize = 16384;
pub const MAX_GUESTS: usize = 64;
/// The guests, by id: too large for a stack.
static GUESTS: StaticCell<[Option<Guest>; MAX_GUESTS]> = StaticCell::new([const { None }; MAX_GUESTS]);
/// Memory and root CNode slots kept back from guest requests.
const RESERVE_BYTES: usize = 32 << 20;
const RESERVE_SLOTS: usize = 32768;
/// Longest free slot range kept for vNIC ports and disk DMA buffers.
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
    pub topology: sched::topology::Topology,
    pub tsc_hz: u64,
    /// AArch64 feature ID registers for the guests' bootinfo (`cpu_id`).
    pub cpu_id: [u64; 5],
    pub hyp_ep: cap::Endpoint,
    sched_control_base: usize,
    pub timeslice_us: u64,
    /// Wall clock at boot (ns since the epoch, 0 if unknown) and the tick
    /// count when it was read.
    pub epoch_ns: u64,
    pub epoch_ticks: u64,
    /// Round-robin placement of new guests.
    placement: core::cell::Cell<usize>,
}

impl HostInfo {
    /// CPU for the next vCPU, visiting physical cores before SMT siblings.
    pub fn next_core(&self) -> usize {
        let c = self.placement.get();
        self.placement.set(c + 1);
        self.topology.placement(c)
    }

    pub fn sched_control(&self, core: usize) -> cap::SchedControl {
        sel4::init_thread::Slot::<cap_type::SchedControl>::from_index(self.sched_control_base + core).cap()
    }
}

/// ASID pools; x86_64 seL4 has 8 pools of 512 ASIDs each in total.
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
        let (ut_slot, pool_slot) = alloc.slots.global(|slots| (slots.alloc(), slots.alloc()));
        let ut = alloc.split(sel4::sys::seL4_ASIDPoolBits as usize, ut_slot).expect("ASID pool memory");
        slot::ASID_CONTROL
            .cap()
            .asid_control_make_pool(ut.cap, &slot::CNODE.cap().absolute_cptr(sel4::init_thread::Slot::<cap_type::Null>::from_index(pool_slot).cap()))
            .expect("out of ASID pools");
        let pool = sel4::init_thread::Slot::<cap_type::AsidPool>::from_index(pool_slot).cap();
        pool.asid_pool_assign(vspace).expect("ASID assign");
        // At most seL4_NumASIDPoolsBits pools: in_use < ASID_CAPACITY.
        self.pools.must_push((pool, 1));
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
    pub guests: &'static mut [Option<Guest>; MAX_GUESTS],
    pub total_bytes: usize,
    pub monitor: Option<monitor::Monitor>,
    pub dashboard: Option<dashboard::Dashboard>,
    pub cfg: config::Config,
    /// The kernel all guests run, and its module image (kimage.rs).
    pub kernel: Option<kimage::Kernel>,
    pub kmods: Option<kimage::Kmods>,
    /// dom0's initramfs, the module `dom0-initrd` (bootmod); kept for
    /// restarts.
    pub dom0_initrd: &'static [u8],
    pub trustd: Option<trustd::Trustd>,
    pub memd: memd::Memd,
    pub reset: reset::Reset,
    pub rtc: rtc::Rtc,
}

impl Host {
    /// Run `f` on guest `id` with root slot allocations tracked into it.
    pub fn with_guest<R>(&mut self, id: usize, f: impl FnOnce(&mut Host, &mut Guest) -> R) -> Option<R> {
        let mut g = self.guests.get_mut(id)?.take()?;
        self.alloc.slots.track(id);
        let asids = self.asids.in_use;
        let r = f(self, &mut g);
        g.asids += self.asids.in_use - asids;
        self.alloc.slots.untrack();
        self.guests[id] = Some(g);
        Some(r)
    }

    pub fn guest(&self, id: usize) -> Option<&Guest> {
        self.guests.get(id)?.as_ref()
    }

    /// Resources a guest operation may need, checked before starting it so
    /// that requests fail cleanly instead of exhausting the root task.
    pub fn can_afford(&self, bytes: usize, asids: usize, slots: usize) -> bool {
        bytes.checked_add(RESERVE_BYTES).is_some_and(|b| self.alloc.free_bytes() >= b)
            && self.asids.available() >= asids
            && self.alloc.slots.available() >= RESERVE_SLOTS + slots
            && self.alloc.slots.largest_range() >= RESERVE_RANGE
    }

    pub fn create_guest(&mut self, cfg: &GuestConfig) -> Option<usize> {
        let bytes = cfg.ram.checked_add(cfg.io_pool)?;
        if !self.can_afford(bytes, cfg.vspaces + 4, 0) {
            return None;
        }
        let id = (0..MAX_GUESTS).find(|&i| self.guest(i).is_none())?;
        self.alloc.slots.track(id);
        let asids = self.asids.in_use;
        let mut g = guest::create(id, cfg, &mut self.alloc, &mut self.asids, &self.info);
        if let (Ok(g), Some(t)) = (&mut g, &self.trustd) {
            t.give(g, &mut self.alloc, &mut self.wins.a);
        }
        if let (Ok(g), Some(k)) = (&mut g, &self.kmods) {
            k.map(g, &mut self.alloc);
        }
        self.alloc.slots.untrack();
        match g {
            Ok(mut g) => {
                g.asids = self.asids.in_use - asids;
                self.guests[id] = Some(g);
                Some(id)
            }
            Err(partial) => {
                // Give back whatever was built.
                self.asids.in_use = asids;
                match partial {
                    Some(g) => g.destroy(&mut self.alloc, false),
                    None => self.alloc.slots.free_owned(id),
                }
                info!("l4h-root: cannot create guest '{}': out of memory", cfg.name);
                None
            }
        }
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
                sel4::debug_println!("l4h-root: more than {} disks, unit {} of controller {} ignored", MAX_DISKS, unit, ctrl);
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

    /// Pass host disk `disk` (or sectors [lba_start, lba_start + lba_count)
    /// of it; 0 = to the end) through to guest `id` before it starts.
    /// The window must be aligned to blkd::WINDOW_ALIGN sectors.
    pub fn attach_disk(&mut self, id: usize, disk: usize, read_only: bool, lba_start: u64, lba_count: u64) -> Result<(), i64> {
        if lba_start % blkd::WINDOW_ALIGN != 0 || lba_count % blkd::WINDOW_ALIGN != 0 {
            return Err(ctl::EINVAL);
        }
        self.ensure_disk(disk)?;
        let (c, unit) = (self.disks[disk].ctrl, self.disks[disk].unit);
        let ctrl = &self.ctrls[c];
        let window = l4h_host::blk::DiskWindow::new(lba_start, lba_count, self.disks[disk].capacity).ok_or(ctl::EINVAL)?;
        let read_only = read_only || self.disks[disk].read_only;
        if ctrl.attachments(disk).any(|(_, a)| window.conflicts(read_only, a.window, a.read_only)) {
            return Err(ctl::EBUSY);
        }
        if ctrl.clients.iter().all(Option::is_some) { return Err(ctl::ENOSPC); }
        if !self.can_afford(1 << 20, 0, 0) { return Err(ctl::ENOMEM); }
        self.with_guest(id, |h, g| {
            if g.state != State::Created {
                return Err(ctl::EBUSY);
            }
            let d = g.add_device(&mut h.alloc, guest::DevKind::Virtio(2)).ok_or(ctl::ENOSPC)?;
            let (client, backend) = blkd::attach(&mut h.ctrls[c], disk, g, d, window, read_only, &mut h.alloc, &mut h.iommu);
            let active = blkd::activate(&mut h.ctrls[c], unit, client, g, &backend, &mut h.wins.a, &h.pci);
            // One each per device, of which add_device allows no more.
            g.backends.must_push((d, backend));
            g.disks.must_push((c, client));
            active
        })
        .ok_or(ctl::ENOENT)?
    }

    /// Spawn the guest's l4h-vmm; the guest starts when the VMM is ready.
    pub fn start_guest(&mut self, id: usize) -> Result<(), i64> {
        self.with_guest(id, |h, g| {
            if g.state != State::Created || g.vmm.is_some() {
                return Err(ctl::EBUSY);
            }
            let maps: usize = g.backends.iter().map(|(_, b)| b.map_bytes()).sum();
            if !g.reserve(&mut h.alloc, vmm::start_bytes(g.pool.size, g.vcpus.len(), g.devices.len()) + maps) {
                return Err(ctl::ENOMEM);
            }
            if let Some(t) = &mut h.trustd {
                t.register(g);
            }
            let v = vmm::spawn(g, &mut h.alloc, &mut h.wins.a, &mut h.asids, &h.info);
            component::start(&v);
            g.vmm = Some(v);
            Ok(())
        })
        .ok_or(ctl::ENOENT)?
    }

    /// Give guest `id` (before it starts) a virtio-net device on `switch`.
    /// Returns the MAC.
    pub fn create_nic(&mut self, id: usize, switch: u32, mac: u64, lock: bool, isolated: bool) -> Result<u64, i64> {
        if !self.can_afford(8 << 20, 0, 0) {
            return Err(ctl::ENOMEM);
        }
        self.with_guest(id, |h, g| {
            if g.state != State::Created || g.vmm.is_some() {
                return Err(ctl::EBUSY);
            }
            // Everything that can fail comes before the device is added:
            // it stays with the guest until it is destroyed.
            if g.devices.len() >= guest::MAX_GUEST_DEVICES {
                return Err(ctl::ENOSPC);
            }
            let p = h.netd.free_port(switch)?;
            let mac = if mac == 0 { 0x02_4c_34_00_00_00 | ((id as u64) << 8) | p as u64 } else { mac & 0xffff_ffff_ffff };
            if mac >> 40 & 1 != 0 {
                return Err(ctl::EINVAL);
            }
            let memory = netd::Netd::port_memory(&mut h.alloc)?;
            let d = g.add_device(&mut h.alloc, guest::DevKind::Virtio(1)).expect("guest device room checked");
            let backend = h.netd.add_port(g, d, p, switch, mac, lock, isolated, memory, &mut h.alloc);
            g.backends.must_push((d, backend));
            g.ports.must_push(p);
            Ok(mac)
        })
        .ok_or(ctl::ENOENT)?
    }

    /// Give guest `id` (before it starts) a virtio-gpu device with one
    /// scanout of `width` x `height` pixels.
    pub fn attach_gpu(&mut self, id: usize, width: u64, height: u64) -> Result<(), i64> {
        if !gpu::valid_size(width, height) {
            return Err(ctl::EINVAL);
        }
        let (width, height) = (width as u32, height as u32);
        let bytes = gpu::attach_bytes(width, height);
        let pages = host::gpu::display_pages(width, height);
        // The display area's mappings in the root task: a slot and page
        // tables, from the global allocator.
        if !self.can_afford(bytes + gpu::table_bytes(pages), 0, pages) {
            return Err(ctl::ENOMEM);
        }
        self.with_guest(id, |h, g| {
            if g.state != State::Created || g.vmm.is_some() || g.gpu.is_some() {
                return Err(ctl::EBUSY);
            }
            // The guest's buffers bounce through the pool.
            if g.pool.size < l4h_abi::GPU_POOL_IMAGES * host::gpu::image_bytes(width, height) {
                return Err(ctl::EINVAL);
            }
            if g.devices.len() >= guest::MAX_GUEST_DEVICES {
                return Err(ctl::ENOSPC);
            }
            if !g.reserve(&mut h.alloc, bytes) {
                return Err(ctl::ENOMEM);
            }
            let backend = gpu::attach(g, &mut h.alloc, width, height);
            let d = g.add_device(&mut h.alloc, guest::DevKind::Virtio(16)).expect("guest device room checked");
            g.backends.must_push((d, backend));
            Ok(())
        })
        .ok_or(ctl::ENOENT)?
    }

    pub fn destroy_guest(&mut self, id: usize) -> Result<(), i64> {
        let mut g = self.guests.get_mut(id).and_then(|g| g.take()).ok_or(ctl::ENOENT)?;
        g.stop();
        if let Some(t) = &mut self.trustd {
            t.unregister(id);
        }
        for &p in &g.ports {
            self.netd.remove_port(p);
        }
        // Disks are quiesced, or cut off by the IOMMU, before any memory
        // they were given is reused.
        let mut quiet = true;
        for &(ctrl, client) in &g.disks {
            quiet &= blkd::remove(&mut self.ctrls[ctrl], client, &self.pci, &mut self.iommu);
        }
        let name = g.name.clone();
        self.asids.in_use -= g.asids;
        g.destroy(&mut self.alloc, !quiet);
        info!(
            "l4h-root: guest {} '{}' destroyed, {} MiB free",
            id, name, self.alloc.free_bytes() >> 20
        );
        Ok(())
    }
}

#[root_task(stack_size = 1024 * 1024)]
fn main(bootinfo: &sel4::BootInfoPtr) -> sel4::Result<Never> {
    layout::check_image(bootinfo);
    let cores = bootinfo.inner().numNodes as usize;
    let topology = sched::topology::discover(bootinfo);
    info!("l4h-root: CPU physical cores {:?}", topology.physical());
    let mut alloc = Alloc::new(Slots::new(bootinfo.empty().range()), bootinfo);
    let total_bytes = alloc.free_bytes();
    info!("l4h-root: {} core(s), {} MiB free memory", cores, total_bytes >> 20);

    let hyp_ep = alloc.object_cap::<cap_type::Endpoint>(ObjectBlueprint::Endpoint);
    // The watchdog timer signals a notification bound to the root TCB, which
    // wakes the serve loop out of its receive on hyp_ep.
    let wd_ntfn = alloc.object_cap::<cap_type::Notification>(ObjectBlueprint::Notification);
    slot::TCB.cap().tcb_bind_notification(wd_ntfn).expect("bind watchdog notification");
    let reply = ReplySlot::new(&mut alloc);
    let mut wins = Windows { a: Window::new(&mut alloc, 0), b: Window::new(&mut alloc, 1) };
    let mut devmem = devmem::DevMem::from_bootinfo(bootinfo);
    let modules = bootmod::load(bootinfo, &mut alloc, &mut devmem);
    let module = |name: &str| modules.iter().find(|m| m.name == name).map(|m| m.data);
    let cfg = config::Config::new(module("l4h-config"));
    let kernel = module("guest-kernel").and_then(|k| {
        kimage::Kernel::parse(k)
            .inspect_err(|e| sel4::debug_println!("l4h-root: the guest kernel cannot be loaded: {}", e))
            .ok()
    });
    let kmods = module("guest-kmods").and_then(|m| kimage::Kmods::new(&mut alloc, m));
    let dom0_initrd = module("dom0-initrd").unwrap_or(&[]);
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
        tsc_hz: tsc_hz(bootinfo),
        cpu_id: cpu_id(bootinfo),
        hyp_ep,
        sched_control_base: bootinfo.sched_control().range().start,
        timeslice_us: 5000,
        epoch_ns: rtc.read_ns(&mut wins.a),
        epoch_ticks: rdtsc(),
        placement: core::cell::Cell::new(0),
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
        sel4::debug_println!("l4h-root: iommu=0: DMA is not confined");
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
                sel4::debug_println!("l4h-root: more than {} disk controllers, ignoring this one", pci::MAX_DISK_CTRLS);
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
                sel4::debug_println!("l4h-root: more than {} NICs, ignoring {:02x}:{:02x}.{}", host::net::MAX_NICS, d.bus, d.dev, d.func);
            }
        } else if memd::is_balloon(&d) && balloon.is_none() {
            balloon = Some(d);
        }
    }
    // The boot disk first: dom0 takes the first dom0_disks host disks.
    if let Some(bdf) = cfg.boot_disk {
        match ctrls.iter().position(|c: &Controller| netd::bdf(&c.pci) == bdf) {
            Some(i) => ctrls[..=i].rotate_right(1),
            None => sel4::debug_println!("l4h-root: no boot disk at {:02x}:{:02x}.{}", bdf >> 8, (bdf >> 3) & 0x1f, bdf & 7),
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
        kernel,
        kmods,
        dom0_initrd,
        trustd,
        memd,
        reset,
        rtc,
    };
    h.scan_disks();
    h.monitor = monitor::Monitor::new(&mut h.alloc, &mut h.devmem, wd_ntfn, h.cfg.serial_port, h.cfg.serial_irq, &mut h.iommu);
    h.dashboard = dashboard::Dashboard::new(bootinfo, &mut h.alloc, &mut h.devmem, h.cfg.fb_console);

    if h.kernel.is_none() {
        sel4::debug_println!("l4h-root: no guest kernel, nothing to do");
    } else {
        boot_dom0(&mut h);
    }
    serve(&mut h, reply)
}

pub fn boot_dom0(h: &mut Host) {
    let ram_base = h.kernel.as_ref().expect("guest kernel").ram_base;
    // By default, room for full receive rings on all of dom0's vNICs (one
    // per uplink switch it is given, one per internal switch).
    let nics = h.cfg.dom0_nics + h.cfg.uplink2_nic.is_some() as usize + h.cfg.dom0_internal_switches;
    let io_pool = match h.cfg.dom0_io_pool_mb {
        0 => l4h_host::iopool::for_nics(nics, guest::IO_POOL_DEFAULT).min(guest::IO_POOL_MAX),
        mb => mb << 20,
    };
    let cfg = GuestConfig {
        name: "dom0",
        ram: h.cfg.dom0_mem_mb << 20,
        vcpus: h.cfg.dom0_vcpus,
        io_pool,
        vspaces: 64,
        ram_base,
        dom0: true,
    };
    let id = h.create_guest(&cfg).expect("cannot create dom0");
    for d in 0..h.disks.len().min(h.cfg.dom0_disks) {
        // Of disk 0, only the first dom0_disk0_mb MiB if the disk is larger.
        let mut sectors = 0;
        if d == 0 && h.cfg.dom0_disk0_mb > 0 && h.ensure_disk(d).is_ok() {
            let n = (h.cfg.dom0_disk0_mb as u64) << 11;
            if n < h.disks[d].capacity { sectors = n; }
        }
        if let Err(e) = h.attach_disk(id, d, false, 0, sectors) {
            sel4::debug_println!("l4h-root: cannot give disk {} to dom0: error {}", d, e);
        }
    }
    // Switch 0, with the uplink NIC (if any; by default the first) as its
    // uplink (on first boot).
    let sw = 0;
    if h.netd.switches == 0 {
        h.netd.create_switch();
        let nic = match h.cfg.uplink_nic {
            None => (!h.netd.nics.is_empty()).then_some(0),
            Some(bdf) => {
                let n = h.netd.nics.iter().position(|n| netd::bdf(&n.pci) == bdf);
                if n.is_none() {
                    sel4::debug_println!("l4h-root: no uplink NIC at {:02x}:{:02x}.{}", bdf >> 8, (bdf >> 3) & 0x1f, bdf & 7);
                }
                n
            }
        };
        if let Some(nic) = nic {
            if let Err(e) = h.netd.attach_uplink(sw, nic) {
                sel4::debug_println!("l4h-root: no uplink on switch {}: error {}", sw, e);
            }
        }
    }
    // Like a disk, a vNIC dom0 cannot have (netd has failed: EIO) is left
    // out.
    let add_nic = |h: &mut Host, sw: u32, mac: u64| {
        if let Err(e) = h.create_nic(id, sw, mac, true, false) {
            sel4::debug_println!("l4h-root: cannot give dom0 a NIC on switch {}: error {}", sw, e);
        }
    };
    // dom0's first vNIC takes the uplink NIC's MAC address: networks
    // like GCE's only deliver frames for the instance's own address, so
    // dom0 is then the host's router (DESIGN.md §8.3).
    let uplink = h.netd.nics.iter().position(|n| n.switch == Some(sw));
    for i in 0..h.cfg.dom0_nics {
        let mac = if i == 0 { uplink.and_then(|n| h.netd.nic_mac(n)).unwrap_or(0) } else { 0 };
        add_nic(h, sw, mac);
    }
    // The second uplink NIC, if any, on switch 1, then the internal
    // switches. dom0 finds its vNICs by MAC, not by their order.
    let uplink2 = h.cfg.uplink2_nic.and_then(|bdf| {
        let n = h.netd.nics.iter().position(|n| netd::bdf(&n.pci) == bdf);
        if n.is_none() {
            sel4::debug_println!("l4h-root: no second uplink NIC at {:02x}:{:02x}.{}", bdf >> 8, (bdf >> 3) & 0x1f, bdf & 7);
        }
        n
    });
    if let Some(nic) = uplink2 {
        if h.netd.switches == 1 {
            h.netd.create_switch();
            if let Err(e) = h.netd.attach_uplink(1, nic) {
                sel4::debug_println!("l4h-root: no uplink on switch 1: error {}", e);
            }
        }
        let mac = h.netd.nic_mac(nic).unwrap_or(0);
        add_nic(h, 1, mac);
    }
    let first = 1 + uplink2.is_some() as usize;
    while (h.netd.switches as usize) < first + h.cfg.dom0_internal_switches {
        h.netd.create_switch();
    }
    for i in first..first + h.cfg.dom0_internal_switches {
        add_nic(h, i as u32, 0);
    }
    let cmdline = h.cfg.dom0_cmdline;
    h.with_guest(id, |h, g| {
        let kernel = h.kernel.as_ref().unwrap();
        assert!(
            guest::boot_with(g, &mut h.alloc, &mut h.wins.a, &h.info, kernel, h.dom0_initrd, cmdline),
            "dom0 image does not fit"
        );
    });
    h.start_guest(id).expect("start dom0");
}

/// dom0 rebooted or crashed: replace it.  Other guests keep running; the
/// new dom0 finds them with the control API.
pub fn restart_dom0(h: &mut Host, id: usize) {
    sel4::debug_println!("l4h-root: restarting dom0");
    let _ = h.destroy_guest(id);
    boot_dom0(h);
}

fn rdtsc() -> u64 {
    host::ticks::now()
}

/// The root task's periodic timer: balancer and watchdog.
fn arm_timer(info: &HostInfo) {
    let deadline = rdtsc() + info.tsc_hz * sched::BALANCE_MS / 1000;
    let tcb = slot::TCB.cap();
    sel4::with_ipc_buffer_mut(|ipc| ipc.inner_mut().seL4_TCB_SetTimer(tcb.bits(), deadline, TIMER_BADGE));
}

fn watchdog_dump(h: &Host) {
    sel4::debug_println!(
        "l4h-root: watchdog: netd used {} ms since the last dump",
        h.netd.consumed() * 1000 / h.info.tsc_hz.max(1)
    );
    for g in h.guests.iter().flatten() {
        if g.state != State::Running {
            continue;
        }
        for (v, vcpu) in g.vcpus.iter().enumerate() {
            match vcpu.ktcb.tcb_read_all_registers(false) {
                Ok(r) => sel4::debug_println!(
                    "l4h-root: watchdog: guest {} vCPU {} rip={:#x} rsp={:#x}",
                    g.id, v, *r.pc(), *r.sp()
                ),
                Err(e) => sel4::debug_println!("l4h-root: watchdog: guest {} vCPU {}: {:?}", g.id, v, e),
            }
        }
    }
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
            .untyped_retype(&ObjectBlueprint::Reply, &mem::root_cnode_dest(), self.reply.bits() as usize, 1)
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

fn serve(h: &mut Host, reply_slot: ReplySlot) -> ! {
    let reply = reply_slot.reply;
    let hyp_ep = h.info.hyp_ep;
    arm_timer(&h.info);
    let mut next_watchdog = rdtsc() + h.info.tsc_hz * h.cfg.watchdog_secs as u64;
    let mut last_balance = rdtsc();
    let (mut info, mut badge) = hyp_ep.recv(reply);
    loop {
        h.alloc.refill();
        let notified = badge & (TIMER_BADGE | monitor::MONITOR_BADGE) != 0;
        if badge & monitor::MONITOR_BADGE != 0 {
            monitor::Monitor::interrupt(h);
        }
        let resp = if badge & monitor::MONITOR_BADGE != 0 && badge & TIMER_BADGE == 0 {
            None
        } else if badge & TIMER_BADGE != 0 {
            let now = rdtsc();
            sched::balance(h, (now - last_balance) * 1_000_000 / h.info.tsc_hz);
            last_balance = now;
            dashboard::Dashboard::tick(h);
            h.iommu.poll();
            if h.cfg.watchdog_secs != 0 && rdtsc() >= next_watchdog {
                watchdog_dump(h);
                next_watchdog = rdtsc() + h.info.tsc_hz * h.cfg.watchdog_secs as u64;
            }
            arm_timer(&h.info);
            None
        } else if badge & ROOT_BADGE_COMPONENT != 0 {
            component_call(h, badge, &info)
        } else if badge & HYP_BADGE_FAULT != 0 {
            let gid = hyp_badge_guest(badge);
            let vcpu = hyp_badge_vcpu(badge);
            let fault = sel4::with_ipc_buffer(|b| sel4::Fault::new(b, &info));
            sel4::debug_println!("l4h-root: guest {} vCPU {} kernel fault: {:x?}", gid, vcpu, fault);
            if h.guest(gid).is_some_and(|g| g.dom0) {
                restart_dom0(h, gid);
            } else if let Some(Some(g)) = h.guests.get_mut(gid) {
                g.stop();
            }
            None
        } else {
            sel4::debug_println!("l4h-root: unexpected message, badge {:#x} label {}", badge, info.label());
            None
        };
        match resp {
            Some(v) => {
                set_mr(0, v);
                (info, badge) = hyp_ep.reply_recv(sel4::MessageInfo::new(0, 0, 0, 1), reply);
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

/// A call or fault from a host component.  Returns the reply value, or
/// None to leave the caller blocked.
fn component_call(h: &mut Host, badge: u64, info: &sel4::MessageInfo) -> Option<u64> {
    let id = (badge & 0xffff) as usize;
    if badge & HYP_BADGE_FAULT != 0 {
        let fault = sel4::with_ipc_buffer(|b| sel4::Fault::new(b, info));
        sel4::debug_println!("l4h-root: component {:#x} fault: {:x?}", id, fault);
        trustd::fault(h, id as u32);
        return None;
    }
    // Component ids below 0x100 are guest VMMs; the id is the guest's.
    let is_vmm = id < MAX_GUESTS;
    match info.label() {
        host::ROOT_CALL_VMM_READY if is_vmm => {
            h.guests.get_mut(id)?.as_mut()?.start();
            Some(0)
        }
        host::ROOT_CALL_GUEST_POWER if is_vmm => {
            let how = mr(1);
            info!("l4h-root: guest {} power request {}", id, how);
            if how != l4h_abi::POWER_OFF && h.guest(id).is_some_and(|g| g.dom0) {
                // The caller (dom0's VMM) is destroyed: no reply.
                restart_dom0(h, id);
                return None;
            }
            if let Some(Some(g)) = h.guests.get_mut(id) {
                for v in &g.vcpus {
                    let _ = v.ktcb.tcb_suspend();
                }
                g.state = State::Stopped;
            }
            if h.guests.iter().flatten().all(|g| g.state != State::Running) {
                info!("l4h-root: all guests stopped");
            }
            Some(0)
        }
        host::ROOT_CALL_HW if id == trustd::TRUSTD_ID as usize => Some(trustd::hw(h)),
        host::ROOT_CALL_ATTEST_DONE if id == trustd::TRUSTD_ID as usize => {
            trustd::done(h, mr(0) as usize);
            Some(0)
        }
        host::ROOT_CALL_CTL if is_vmm && h.guest(id).is_some_and(|g| g.dom0) => {
            ctl::handle(h, id);
            Some(0)
        }
        other => {
            sel4::debug_println!("l4h-root: component {:#x}: unknown call {}", id, other);
            Some(u64::MAX)
        }
    }
}

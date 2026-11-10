//! l4h-vmmgr: the guest manager (DESIGN.md §10.3).  Builds guests and their
//! l4h-vmm, runs their lifecycle and schedules their vCPUs, serves their
//! VMMs, their kernels' faults and dom0's control API.  l4h-root spawns it
//! and keeps the hardware: what guests get of disks, NICs, I/O pools and
//! attestation, vmmgr asks root for (root.rs, l4h_host::vmmgr).

#![no_std]
#![no_main]

/// Always retained; printed to serial only in verbose builds.
macro_rules! info {
    ($($arg:tt)*) => {
        l4h_rt::info!($($arg)*)
    };
}

mod component;
mod ctl;
mod ctl_failure;
mod gpu;
mod guest;
mod kimage;
mod layout;
mod memd;
mod root;
mod sched;
mod vmm;

use core::sync::atomic::Ordering;

use l4h_host::errno::{EINVAL, Errno};
use sel4::cap;

use l4h_abi as abi;
use l4h_host as host;
use l4h_host::fixed::{ArrayVec, StaticCell};
use l4h_host::vmmgr::{self as proto, VmmgrConfig};
use l4h_rt::Info;
use l4h_task::{elf, mem, topology, vspace, window};
use l4h_task::reply::ReplySlot;

use l4h_host::badges::vmmgr as recv;
use l4h_host::vmmgr::call;
use crate::guest::{Guest, GuestConfig, State};
use crate::mem::{Alloc, Slots};
use crate::root::Later;
use crate::window::{Window, Windows};

pub use crate::guest::MAX_GUEST_DEVICES;

/// vmmgr's own capabilities, at the standard component slots.
pub mod slot {
    use l4h_host as host;
    use sel4::cap_type;
    use sel4::init_thread::Slot;

    pub const CNODE: Slot<cap_type::CNode> = Slot::from_index(host::SLOT_CNODE as usize);
    pub const VSPACE: Slot<cap_type::VSpace> = Slot::from_index(host::SLOT_VSPACE as usize);
    pub const TCB: Slot<cap_type::Tcb> = Slot::from_index(host::SLOT_TCB as usize);
    pub const NTFN: Slot<cap_type::Notification> = Slot::from_index(host::SLOT_NTFN as usize);
}

pub const CNODE_SLOTS: usize = 1 << proto::CNODE_BITS;
static SLOT_STORAGE: StaticCell<mem::SlotStorage<{ CNODE_SLOTS / 64 }, CNODE_SLOTS>> =
    StaticCell::new(mem::SlotStorage::new());
static ALLOC_STORAGE: StaticCell<mem::AllocStorage> = StaticCell::new(mem::AllocStorage::new());
pub const MAX_GUESTS: usize = 64;
const _: () = assert!(MAX_GUESTS <= host::memd::MAX_GUESTS);
/// The guests, by id: too large for a stack.
static GUESTS: StaticCell<[Option<Guest>; MAX_GUESTS]> = StaticCell::new([const { None }; MAX_GUESTS]);
/// Memory and CNode slots kept back from guest requests.
const RESERVE_BYTES: usize = 32 << 20;
const RESERVE_SLOTS: usize = 16384;


/// Facts about the host the guests run on.
pub struct HostInfo {
    pub cores: usize,
    pub topology: topology::Topology,
    pub tsc_hz: u64,
    /// The kernel makes VCPU and EPT objects, on VT-x or AMD-V (VmmgrConfig::vtx).
    pub vtx: bool,
    /// AArch64 feature ID registers for the guests' bootinfo.
    pub cpu_id: [u64; 5],
    /// vmmgr's endpoint: VMMs call it, guest kernels fault to it.
    pub hyp_ep: cap::Endpoint,
    pub timeslice_us: u64,
    /// Wall clock at root's boot (ns since the epoch, 0 if unknown) and
    /// the tick count when it was read.
    pub epoch_ns: u64,
    pub epoch_ticks: u64,
    /// Round-robin placement of new guests.
    placement: core::cell::Cell<usize>,
}

impl HostInfo {
    pub fn spawn_context(&self, core: usize) -> component::SpawnContext {
        component::SpawnContext {
            authority: slot::TCB.cap(),
            sched_control: self.sched_control(core),
            parent_ep: self.hyp_ep,
            parent: l4h_host::wiring::Party::Vmmgr,
            tsc_hz: self.tsc_hz,
            log_frames: proto::SLOT_LOG_FRAMES,
            serial_frames: proto::SLOT_SERIAL_FRAMES,
        }
    }

    /// CPU for the next vCPU, visiting physical cores before SMT siblings.
    pub fn next_core(&self) -> usize {
        let c = self.placement.get();
        self.placement.set(c + 1);
        self.topology.placement(c)
    }

    pub fn sched_control(&self, core: usize) -> cap::SchedControl {
        assert!(core < self.cores);
        sel4::Cap::from_bits(proto::SLOT_SCHED_CONTROL + core as u64)
    }
}

const ASIDS_PER_POOL: usize = 1 << sel4::sys::seL4_ASIDPoolIndexBits;

/// The ASID pools root gave us: all there are, so none can be made.
pub struct AsidPools {
    pools: ArrayVec<(cap::AsidPool, usize), { proto::MAX_ASID_POOLS }>,
    /// ASIDs assigned to live VSpaces, root's components' included.
    pub in_use: usize,
}

impl AsidPools {
    fn capacity(&self) -> usize {
        self.pools.len() * ASIDS_PER_POOL
    }

    pub fn available(&self) -> usize {
        self.capacity().saturating_sub(self.in_use)
    }

    pub fn assign(&mut self, _alloc: &mut Alloc, vspace: cap::VSpace) {
        assert!(self.in_use < self.capacity(), "out of ASIDs");
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
        panic!("out of ASIDs");
    }
}

/// All state of vmmgr.
pub struct Vmmgr {
    pub info: HostInfo,
    pub alloc: Alloc,
    pub wins: Windows,
    pub asids: AsidPools,
    pub guests: &'static mut [Option<Guest>; MAX_GUESTS],
    pub cfg: &'static VmmgrConfig,
    /// The kernel all guests run, and its module image (kimage.rs).
    pub kernel: Option<kimage::Kernel>,
    pub kmods: Option<kimage::Kmods>,
    /// dom0's initramfs, kept for restarts.
    pub dom0_initrd: &'static [u8],
    /// trustd's flags, if it runs.
    pub flags: Option<root::Flags>,
    /// Requests root answers later (root::Later::Token), by token: what
    /// their answers are for.
    pub root_ops: [Option<RootOp>; proto::MAX_PENDING],
    /// The dom0 control request being executed: its dom0 and seq.
    pub ctl_now: Option<(usize, u32)>,
}

/// What a request root answers later is for.
pub enum RootOp {
    /// Disk device `d` of guest `id` (instance `instance`).
    Disk { id: usize, instance: u64, d: usize, then: Then },
    /// A host op of a control request (Then::Ctl).
    HostOp { then: Then },
}

/// What follows a request root answered later.
#[derive(Clone, Copy)]
pub enum Then {
    /// Answer dom0 `caller`'s control request `seq`.
    Ctl { caller: usize, instance: u64, seq: u32 },
    /// Go on booting dom0, after its boot disk `k`.
    Dom0Boot { k: usize },
}

impl Vmmgr {
    /// Run `f` on guest `id` with slot allocations tracked into it.
    pub fn with_guest<R>(&mut self, id: usize, f: impl FnOnce(&mut Vmmgr, &mut Guest) -> R) -> Option<R> {
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
    /// that requests fail cleanly instead of exhausting vmmgr.
    pub fn can_afford(&self, bytes: usize, asids: usize, slots: usize) -> bool {
        bytes.checked_add(RESERVE_BYTES).is_some_and(|b| self.alloc.free_bytes() >= b)
            && self.asids.available() >= asids
            && self.alloc.slots.available() >= RESERVE_SLOTS + slots
    }

    pub fn create_guest(&mut self, cfg: &GuestConfig) -> Option<usize> {
        let kernel = self.kernel.as_ref()?;
        let kmods = self.kmods.as_ref().map_or(0, |k| k.bytes());
        let bytes = cfg.ram.checked_add(cfg.io_pool)?.checked_add(kmods)?;
        if !self.can_afford(bytes, cfg.vspaces + 4 + if self.info.vtx { abi::MAX_EPT_ROOTS } else { 0 }, 0) {
            return None;
        }
        let id = (0..MAX_GUESTS).find(|&i| self.guest(i).is_none())?;
        self.alloc.slots.track(id);
        let asids = self.asids.in_use;
        let mut g = guest::create(id, cfg, &mut self.alloc, &mut self.asids, &self.info, kernel);
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
                    Some(g) => g.destroy(&mut self.alloc),
                    None => self.alloc.slots.free_owned(id),
                }
                info!("l4h-vmmgr: cannot create guest '{}': out of memory", cfg.name);
                None
            }
        }
    }

    /// Pass host disk `disk` (or sectors [lba_start, lba_start + lba_count)
    /// of it; 0 = to the end) through to guest `id` before it starts.
    /// `flags`: abi::BLK_*.  Attach a window of host disk `disk`, or the
    /// `extents.0` extents at offset `extents.1` of dom0's control data area.
    /// Root answers later, after blkd: then `then` follows (`root_done`).
    /// No device of the guest changes, nor does it start, meanwhile.
    pub fn attach_disk(&mut self, id: usize, disk: usize, flags: u64, lba_start: u64, lba_count: u64,
        extents: (u64, u64), then: Then) -> Result<Later<()>, Errno> {
        if !self.can_afford(1 << 20, 0, 0) { return Err(ctl::ENOMEM); }
        let instance = self.guest(id).ok_or(ctl::ENOENT)?.instance;
        self.with_guest(id, |h, g| {
            // Like every other attach path (attach_usb, create_nic, ...):
            // refuse once start_guest has spawned the VMM, which took the
            // devices there were then: a disk added before VmmReady would
            // be one it never serves.  (start_guest refuses while
            // root_pending, so no answer can come after the VMM is spawned.)
            if g.state != State::Created || g.vmm.is_some() || g.root_pending {
                return Err(ctl::EBUSY);
            }
            if g.devices.len() >= MAX_GUEST_DEVICES {
                return Err(ctl::ENOSPC);
            }
            // Root checks the window and the disk's other users, and makes
            // the channel; the device is added once it has.
            let d = g.devices.len();
            match root::disk_attach(&mut h.alloc, id, d, disk, flags, lba_start, lba_count, extents)? {
                Later::Now(backend) => {
                    add_disk(h, g, d, backend)?;
                    Ok(Later::Now(()))
                }
                Later::Token(t) => {
                    g.root_pending = true;
                    h.root_ops[t] = Some(RootOp::Disk { id, instance, d, then });
                    Ok(Later::Token(t))
                }
            }
        })
        .ok_or(ctl::ENOENT)?
    }

    /// Root answered the disk attachment of guest `id` (`attach_disk`).
    fn disk_attached(&mut self, id: usize, instance: u64, d: usize, token: usize) -> Result<(), Errno> {
        if self.guest(id).is_none_or(|g| g.instance != instance) {
            root::discard(token);
            return Err(ctl::ENOENT);
        }
        self.with_guest(id, |h, g| {
            g.root_pending = false;
            let backend = root::disk_attach_result(&mut h.alloc, token)?;
            add_disk(h, g, d, backend)
        })
        .ok_or(ctl::ENOENT)?
    }

    /// Root has the answers of the requests in `done` (tokens' bits).
    pub fn root_done(&mut self, done: [u64; proto::MAX_PENDING / 64]) {
        for t in (0..proto::MAX_PENDING).filter(|&t| done[t / 64] & (1 << (t % 64)) != 0) {
            match self.root_ops[t].take() {
                Some(RootOp::Disk { id, instance, d, then }) => {
                    let r = self.disk_attached(id, instance, d, t);
                    match then {
                        Then::Ctl { caller, instance, seq } => ctl::answer(self, caller, instance, seq, r.map(|()| [0; 6])),
                        Then::Dom0Boot { k } => dom0_disk_done(self, id, instance, k, r),
                    }
                }
                Some(RootOp::HostOp { then: Then::Ctl { caller, instance, seq } }) => {
                    let r = root::host_op_result(t);
                    ctl::answer(self, caller, instance, seq, r);
                }
                Some(RootOp::HostOp { then: Then::Dom0Boot { .. } }) | None => root::discard(t),
            }
        }
    }

    /// Give guest `id` (before it starts) the whole USB controller `ctrl`
    /// (DESIGN.md §9.7).  Root claims it on its first attachment.
    pub fn attach_usb(&mut self, id: usize, ctrl: usize) -> Result<(), Errno> {
        if !self.can_afford(1 << 20, 0, 0) { return Err(ctl::ENOMEM); }
        self.with_guest(id, |h, g| {
            if g.state != State::Created || g.vmm.is_some() || g.root_pending {
                return Err(ctl::EBUSY);
            }
            if g.devices.len() >= MAX_GUEST_DEVICES || g.usbs >= host::usb::MAX_GUEST_USB {
                return Err(ctl::ENOSPC);
            }
            let d = g.devices.len();
            let (frames, kick, n) = root::usb_attach(&mut h.alloc, id, d, ctrl)?;
            assert_eq!(n, g.usbs, "root and vmmgr number USB controllers alike");
            let added = g.add_usb(&mut h.alloc, n, frames, kick);
            assert_eq!(added, Some(d), "guest device room checked");
            g.backends.must_push((d, vmm::Backend::Usb { n }));
            Ok(())
        })
        .ok_or(ctl::ENOENT)?
    }

    /// Keep a failed boot disk's position without a channel or DMA access.
    pub fn attach_dummy_disk(&mut self, id: usize) -> Result<(), Errno> {
        self.with_guest(id, |h, g| {
            // As every attach path: not once the VMM, which was given the
            // devices there were, is spawned.
            if g.state != State::Created || g.vmm.is_some() || g.root_pending { return Err(ctl::EBUSY); }
            let d = g.add_device(&mut h.alloc, guest::DevKind::Virtio(2)).ok_or(ctl::ENOSPC)?;
            g.backends.must_push((d, vmm::Backend::UnavailableBlk));
            Ok(())
        }).ok_or(ctl::ENOENT)?
    }

    /// Spawn the guest's l4h-vmm; the guest starts when the VMM is ready.
    pub fn start_guest(&mut self, id: usize) -> Result<(), Errno> {
        self.with_guest(id, |h, g| {
            if g.state != State::Created || g.vmm.is_some() || g.root_pending {
                return Err(ctl::EBUSY);
            }
            let maps: usize = g.backends.iter().map(|(_, b)| b.map_bytes()).sum();
            if !g.reserve(&mut h.alloc, vmm::start_bytes(g.pool.size, g.vcpus.len(), g.devices.len()) + maps) {
                return Err(ctl::ENOMEM);
            }
            if g.attest {
                root::trust_register(g);
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
    pub fn create_nic(&mut self, id: usize, switch: u32, mac: u64, lock: bool, isolated: bool) -> Result<u64, Errno> {
        if !self.can_afford(1 << 20, 0, 0) {
            return Err(ctl::ENOMEM);
        }
        self.with_guest(id, |h, g| {
            if g.state != State::Created || g.vmm.is_some() || g.root_pending {
                return Err(ctl::EBUSY);
            }
            // Everything that can fail comes before the device is added:
            // it stays with the guest until it is destroyed.
            if g.devices.len() >= MAX_GUEST_DEVICES {
                return Err(ctl::ENOSPC);
            }
            let d = g.devices.len();
            let backend = root::nic_add(&mut h.alloc, &mut g.arena, id, d, switch, mac, lock, isolated)?;
            let mac = match &backend {
                vmm::Backend::Net { mac, .. } => mac.iter().fold(0, |m, &b| m << 8 | b as u64),
                _ => unreachable!(),
            };
            let added = g.add_device(&mut h.alloc, guest::DevKind::Virtio(1));
            assert_eq!(added, Some(d), "guest device room checked");
            g.backends.must_push((d, backend));
            Ok(mac)
        })
        .ok_or(ctl::ENOENT)?
    }

    /// Give guest `id` (before it starts) a virtio-gpu device with one
    /// scanout of `width` x `height` pixels.
    pub fn attach_gpu(&mut self, id: usize, width: u64, height: u64) -> Result<(), Errno> {
        if !gpu::valid_size(width, height) {
            return Err(ctl::EINVAL);
        }
        let (width, height) = (width as u32, height as u32);
        let bytes = gpu::attach_bytes(width, height);
        let pages = host::gpu::display_pages(width, height);
        // The display area's mappings in vmmgr: a slot and page tables,
        // from the global allocator.
        if !self.can_afford(bytes + gpu::table_bytes(pages), 0, pages) {
            return Err(ctl::ENOMEM);
        }
        self.with_guest(id, |h, g| {
            if g.state != State::Created || g.vmm.is_some() || g.gpu.is_some() || g.root_pending {
                return Err(ctl::EBUSY);
            }
            // The guest's buffers bounce through the pool.
            if g.pool.size < l4h_abi::GPU_POOL_IMAGES * host::gpu::image_bytes(width, height) {
                return Err(ctl::EINVAL);
            }
            if g.devices.len() >= MAX_GUEST_DEVICES {
                return Err(ctl::ENOSPC);
            }
            let backend = gpu::attach(g, &mut h.alloc, width, height)?;
            let d = g.add_device(&mut h.alloc, guest::DevKind::Virtio(16)).expect("guest device room checked");
            g.backends.must_push((d, backend));
            Ok(())
        })
        .ok_or(ctl::ENOENT)?
    }

    pub fn destroy_guest(&mut self, id: usize) -> Result<(), Errno> {
        let g = self.guests.get_mut(id).and_then(|g| g.take()).ok_or(ctl::ENOENT)?;
        let name = g.name.clone();
        self.asids.in_use -= g.asids;
        // Everything of ours first, then root drains the disks and takes
        // back the I/O pool (Guest::destroy).
        g.destroy(&mut self.alloc);
        info!("l4h-vmmgr: guest {} '{}' destroyed, {} MiB free", id, name, self.alloc.free_bytes() >> 20);
        Ok(())
    }

    /// Publish the guests in the status page, for root's dashboard and
    /// monitor.
    fn publish(&self) {
        let st = unsafe { &mut *(proto::STATUS_VA as *mut proto::Status) };
        for (id, e) in st.guests.iter_mut().enumerate() {
            let seq = e.seq.load(Ordering::Relaxed);
            e.seq.store(seq.wrapping_add(1), Ordering::Relaxed);
            core::sync::atomic::fence(Ordering::Release);
            let p = e as *mut proto::GuestStatus;
            unsafe {
                match self.guest(id) {
                    None => core::ptr::addr_of_mut!((*p).state).write_volatile(0),
                    Some(g) => {
                        let state = match g.state {
                            State::Created => abi::VM_CREATED,
                            State::Running => abi::VM_RUNNING,
                            State::Stopped => abi::VM_STOPPED,
                        };
                        let mut cores = [0; proto::STATUS_CORES];
                        for (c, v) in cores.iter_mut().zip(g.vcpus.iter()) {
                            *c = v.core as u8;
                        }
                        let mut name = [0; abi::CTL_NAME_MAX];
                        let nb = g.name.as_bytes();
                        name[..nb.len().min(abi::CTL_NAME_MAX - 1)].copy_from_slice(&nb[..nb.len().min(abi::CTL_NAME_MAX - 1)]);
                        core::ptr::addr_of_mut!((*p).state).write_volatile(state as u8 + 1);
                        core::ptr::addr_of_mut!((*p).dom0).write_volatile(g.dom0 as u8);
                        core::ptr::addr_of_mut!((*p).vcpus).write_volatile(g.vcpus.len() as u8);
                        core::ptr::addr_of_mut!((*p).cap_pct).write_volatile(g.cpu_cap_pct as u8);
                        core::ptr::addr_of_mut!((*p).ram_mb).write_volatile((g.owned_ram() >> 20) as u32);
                        core::ptr::addr_of_mut!((*p).cpu).write_volatile(g.vcpus.iter().map(|v| v.usage).sum());
                        core::ptr::addr_of_mut!((*p).cores).write_volatile(cores);
                        core::ptr::addr_of_mut!((*p).name).write_volatile(name);
                    }
                }
            }
            e.seq.store(seq.wrapping_add(2), Ordering::Release);
        }
    }
}

/// The modules root mapped for us, as slices of MODULES_VA.
fn module(r: &proto::ModuleRange) -> Option<&'static [u8]> {
    (r.len != 0).then(|| unsafe { core::slice::from_raw_parts((proto::MODULES_VA + r.offset as usize) as *const u8, r.len as usize) })
}

fn main(info: &'static Info) -> ! {
    l4h_rt::set_failure_handler(&ctl_failure::HANDLER);
    let cfg: &'static VmmgrConfig = unsafe { info.config() };
    let slots = Slots::new(slot::CNODE.cap(), SLOT_STORAGE.take(), proto::SLOT_DYN_BASE as usize..CNODE_SLOTS);
    let mut alloc = Alloc::empty(slots, ALLOC_STORAGE.take());
    alloc.memd = Some(memd::link());
    alloc.refill();
    l4h_task::edge::minter(l4h_host::wiring::Party::Vmmgr);
    component::audit_in(alloc.slots.alloc());
    // Root made SLOT_REPLY, which cannot be replaced: ours is there, where
    // the keeper finds it if vmmgr fails, so that the caller it holds gets
    // an answer (l4h_rt::abort_trap).
    let reply = sel4::Cap::from_bits(host::SLOT_REPLY);
    slot::CNODE.cap().absolute_cptr(reply).delete().expect("delete reply object");
    let reply = ReplySlot::new(&mut alloc, reply);
    let wins = Windows {
        a: Window::new(&mut alloc, slot::VSPACE.cap(), layout::WINDOWS.base),
        b: Window::new(&mut alloc, slot::VSPACE.cap(), layout::WINDOWS.base + 4096),
    };
    let mut pools = ArrayVec::new();
    for i in 0..cfg.asid_pools as usize {
        pools.must_push((sel4::Cap::from_bits(proto::SLOT_ASID_POOL + i as u64), cfg.asids_used[i] as usize));
    }
    let asids = AsidPools { in_use: pools.iter().map(|&(_, n)| n).sum(), pools };
    let info = HostInfo {
        cores: cfg.cores as usize,
        topology: topology::Topology::from_raw(cfg.topo_cpus as usize, cfg.topo_physical, cfg.topo_order),
        tsc_hz: cfg.tsc_hz,
        vtx: cfg.vtx != 0,
        cpu_id: cfg.cpu_id,
        hyp_ep: cap::Endpoint::from_bits(host::SLOT_SERVICE_EP),
        timeslice_us: cfg.timeslice_us,
        epoch_ns: cfg.epoch_ns,
        epoch_ticks: cfg.epoch_ticks,
        placement: core::cell::Cell::new(0),
    };
    let modules = kimage::Modules::new(cfg.modules_radix as usize, cfg.modules_pages as usize);
    let kernel = module(&cfg.kernel).and_then(|k| {
        kimage::Kernel::parse(k, &modules)
            .inspect_err(|e| l4h_rt::log!("l4h-vmmgr: the guest kernel cannot be loaded: {}", e))
            .ok()
    });
    let kmods = module(&cfg.kmods).and_then(|m| kimage::Kmods::new(&modules, m));
    let mut h = Vmmgr {
        info,
        alloc,
        wins,
        asids,
        guests: GUESTS.take(),
        cfg,
        kernel,
        kmods,
        dom0_initrd: module(&cfg.dom0_initrd).unwrap_or(&[]),
        flags: root::Flags::new(cfg),
        root_ops: [const { None }; proto::MAX_PENDING],
        ctl_now: None,
    };
    if h.kernel.is_none() {
        l4h_rt::log!("l4h-vmmgr: no guest kernel, nothing to do");
    } else {
        boot_dom0(&mut h);
    }
    h.publish();
    serve(&mut h, reply)
}

pub fn boot_dom0(h: &mut Vmmgr) {
    let ram_base = h.kernel.as_ref().expect("guest kernel").ram_base;
    let cfg = GuestConfig {
        name: "dom0",
        ram: h.cfg.dom0_mem as usize,
        vcpus: h.cfg.dom0_vcpus as usize,
        io_pool: h.cfg.dom0_io_pool as usize,
        vspaces: 64,
        ram_base,
        dom0: true,
    };
    let id = h.create_guest(&cfg).expect("cannot create dom0");
    // Count the actual console/control, memory and attestation devices
    // before attaching anything. A placeholder still needs a device slot.
    let used = h.guest(id).unwrap().devices.len();
    let total = used + h.cfg.dom0_disks as usize + h.cfg.dom0_nics as usize + h.cfg.dom0_usbs as usize;
    assert!(total <= MAX_GUEST_DEVICES,
        "dom0 device plan needs {} slots ({} built-in, {} disks, {} NICs); limit is {}",
        total, used, h.cfg.dom0_disks, h.cfg.dom0_nics, MAX_GUEST_DEVICES);
    dom0_disks(h, id, 0);
}

/// Attach dom0's boot disks from the `k`th on, which root answers later,
/// then go on (dom0_finish).  Root keeps every boot disk range reserved,
/// even if its driver cannot attach.  Preserve the disk's position so later
/// devices keep their names.
fn dom0_disks(h: &mut Vmmgr, id: usize, mut k: usize) {
    while k < h.cfg.dom0_disks as usize {
        let cfg = h.cfg;
        let d = &cfg.dom0_disk[k];
        match h.attach_disk(id, d.disk as usize, 0, d.start, d.sectors, (0, 0), Then::Dom0Boot { k }) {
            Ok(Later::Token(_)) => return,
            Ok(Later::Now(())) => {}
            Err(e) => dom0_no_disk(h, id, k, e),
        }
        k += 1;
    }
    dom0_finish(h, id);
}

/// Root answered dom0's boot disk `k` with `r`: the next, unless this dom0
/// (`instance`) is gone.
fn dom0_disk_done(h: &mut Vmmgr, id: usize, instance: u64, k: usize, r: Result<(), Errno>) {
    if h.guest(id).is_none_or(|g| g.instance != instance) {
        return;
    }
    if let Err(e) = r {
        dom0_no_disk(h, id, k, e);
    }
    dom0_disks(h, id, k + 1);
}

fn dom0_no_disk(h: &mut Vmmgr, id: usize, k: usize, e: Errno) {
    let d = &h.cfg.dom0_disk[k];
    l4h_rt::log!("l4h-vmmgr: disk {} window {}:{} unavailable to dom0: error {}; using zero-capacity device",
        d.disk, d.start, d.sectors, e);
    h.attach_dummy_disk(id).expect("cannot create dom0 disk placeholder");
}

/// dom0's NICs, its image, and it starts.
fn dom0_finish(h: &mut Vmmgr, id: usize) {
    for n in &h.cfg.dom0_nic[..h.cfg.dom0_nics as usize] {
        if let Err(e) = h.create_nic(id, n.switch as u32, n.mac, true, false) {
            l4h_rt::log!("l4h-vmmgr: cannot give dom0 a NIC on switch {}: error {}", n.switch, e);
        }
    }
    for &c in &h.cfg.dom0_usb[..h.cfg.dom0_usbs as usize] {
        if let Err(e) = h.attach_usb(id, c as usize) {
            l4h_rt::log!("l4h-vmmgr: cannot give dom0 USB controller {}: error {}", c, e);
        }
    }
    let cmdline = &h.cfg.dom0_cmdline;
    let cmdline = &cmdline[..cmdline.iter().position(|&c| c == 0).unwrap_or(cmdline.len())];
    h.with_guest(id, |h, g| {
        let kernel = h.kernel.as_ref().unwrap();
        assert!(
            guest::boot_with(g, &mut h.alloc, &mut h.wins.a, &h.info, kernel, h.dom0_initrd, cmdline),
            "dom0 image does not fit"
        );
    });
    h.start_guest(id).expect("start dom0");
}

/// Add the disk device of `backend` to `g` as device `d`, the index root
/// made the channel for.  attach_disk checked there was room and, while
/// root_pending, nothing else can add a device or spawn the VMM, so this
/// holds; should it not, the channel is given back rather than vmmgr
/// panicking or the channel landing on another device.
fn add_disk(h: &mut Vmmgr, g: &mut Guest, d: usize, backend: vmm::Backend) -> Result<(), Errno> {
    if g.state != State::Created || g.vmm.is_some() || g.devices.len() != d {
        root::disk_backend_drop(&mut h.alloc, backend);
        return Err(ctl::EBUSY);
    }
    let Some(added) = g.add_device(&mut h.alloc, guest::DevKind::Virtio(2)) else {
        root::disk_backend_drop(&mut h.alloc, backend);
        return Err(ctl::ENOSPC);
    };
    debug_assert_eq!(added, d);
    g.backends.must_push((d, backend));
    Ok(())
}

/// dom0 rebooted or crashed: replace it.  Other guests keep running; the
/// new dom0 finds them with the control API.
pub fn restart_dom0(h: &mut Vmmgr, id: usize) {
    l4h_rt::log!("l4h-vmmgr: restarting dom0");
    let _ = h.destroy_guest(id);
    boot_dom0(h);
}

fn rdtsc() -> u64 {
    host::ticks::now()
}

/// vmmgr's periodic timer: balancer and watchdog.
fn arm_timer(info: &HostInfo) {
    let deadline = rdtsc() + info.tsc_hz * sched::BALANCE_MS / 1000;
    let tcb = slot::TCB.cap();
    sel4::with_ipc_buffer_mut(|ipc| ipc.inner_mut().seL4_TCB_SetTimer(tcb.bits(), deadline, recv::TIMER));
}

fn watchdog_dump(h: &Vmmgr) {
    for g in h.guests.iter().flatten() {
        if g.state != State::Running {
            continue;
        }
        for (v, vcpu) in g.vcpus.iter().enumerate() {
            match vcpu.ktcb.tcb_read_all_registers(false) {
                Ok(r) => l4h_rt::log!(
                    "l4h-vmmgr: watchdog: guest {} vCPU {} rip={:#x} rsp={:#x}",
                    g.id, v, *r.pc(), *r.sp()
                ),
                Err(e) => l4h_rt::log!("l4h-vmmgr: watchdog: guest {} vCPU {}: {:?}", g.id, v, e),
            }
        }
    }
}


/// vmmgr's thread: calls from guests' VMMs, faults of guest kernels and
/// VMMs, root's notices and dom0's control requests, and the timer.
struct Serve<'a> {
    h: &'a mut Vmmgr,
    next_watchdog: u64,
    last_balance: u64,
}

fn serve(h: &mut Vmmgr, reply: ReplySlot) -> ! {
    arm_timer(&h.info);
    let next_watchdog = rdtsc() + h.info.tsc_hz * h.cfg.watchdog_secs;
    let hyp_ep = h.info.hyp_ep;
    l4h_ipc::run(hyp_ep, reply, &mut Serve { h, next_watchdog, last_balance: rdtsc() })
}

impl l4h_ipc::Server for Serve<'_> {
    const SIGNALS: u64 = recv::SIGNALS;
    const FAULT: u64 = recv::FAULT;
    type Sender = proto::Sender;

    fn received(&mut self) {
        self.h.alloc.refill();
    }

    fn signal(&mut self, badge: u64) {
        let h = &mut *self.h;
        if badge & recv::MAILBOX != 0 {
            root_notices(h);
        }
        if badge & recv::CTL_KICK != 0 {
            ctl::kicked(h);
        }
        if badge & recv::TIMER != 0 {
            let now = rdtsc();
            sched::balance(h, (now - self.last_balance) * 1_000_000 / h.info.tsc_hz);
            self.last_balance = now;
            if h.cfg.watchdog_secs != 0 && rdtsc() >= self.next_watchdog {
                watchdog_dump(h);
                self.next_watchdog = rdtsc() + h.info.tsc_hz * h.cfg.watchdog_secs;
            }
            arm_timer(&h.info);
        }
    }

    fn fault(&mut self, badge: u64, info: &sel4::MessageInfo) {
        let h = &mut *self.h;
        let id = recv::ID.get(badge) as usize;
        let fault = sel4::with_ipc_buffer(|b| sel4::Fault::new(b, info));
        if badge & recv::COMPONENT != 0 {
            l4h_rt::log!("l4h-vmmgr: guest {:#x}'s l4h-vmm fault: {:x?}", id, fault);
            return;
        }
        let vcpu = recv::VCPU.get(badge) as usize;
        l4h_rt::log!("l4h-vmmgr: guest {} vCPU {} kernel fault: {:x?}", id, vcpu, fault);
        if h.guest(id).is_some_and(|g| g.dom0) {
            restart_dom0(h, id);
        } else if let Some(Some(g)) = h.guests.get_mut(id) {
            g.stop();
        }
    }

    fn call(&mut self, from: proto::Sender, badge: u64, info: &sel4::MessageInfo) -> Option<sel4::MessageInfo> {
        match from {
            // The VMMs' component ids are their guests'.
            proto::Sender::Vmm(g) if g < MAX_GUESTS => {
                l4h_ipc::serve::<call::Proto>(info, |label, args, out| call::serve(&mut VmmCalls(self.h), label, args, from, out))
            }
            _ => {
                self.unknown(badge, info);
                Some(l4h_ipc::refuse())
            }
        }
    }

    fn unknown(&mut self, badge: u64, info: &sel4::MessageInfo) {
        l4h_rt::log!("l4h-vmmgr: unknown call {} badged {:#x}", info.label(), badge);
    }

    fn next(&mut self) -> l4h_ipc::Next {
        self.h.publish();
        l4h_ipc::Next::Wait
    }
}

/// Root's notices, in our mailbox (l4h_host::vmmgr::call, from Root).
fn root_notices(h: &mut Vmmgr) {
    let mut calls = VmmCalls(h);
    if l4h_rt::mailbox::serve(|label, args, out| call::serve(&mut calls, label, args, proto::Sender::Root, out)) {
        l4h_rt::mailbox::signal();
    }
}

/// The VMMs' calls, as l4h_host::vmmgr::call declares them.
struct VmmCalls<'a>(&'a mut Vmmgr);

impl call::Server for VmmCalls<'_> {
    fn vmm_ready(&mut self, from: proto::Sender) -> Result<(), Errno> {
        let proto::Sender::Vmm(id) = from else { return Err(EINVAL) };
        let g = self.0.guests.get_mut(id).and_then(|g| g.as_mut()).ok_or(l4h_host::wire::NO_REPLY)?;
        // Only a freshly built guest starts: a second VmmReady, or one from
        // the VMM of a running or stopped guest, must not reset vCPU 0.
        if g.state != State::Created {
            return Err(EINVAL);
        }
        g.start();
        Ok(())
    }

    fn guest_power(&mut self, from: proto::Sender, how: u64) -> Result<(), Errno> {
        let proto::Sender::Vmm(id) = from else { return Err(EINVAL) };
        let h = &mut *self.0;
        let reason = match how {
            abi::POWER_OFF => "power off",
            abi::POWER_REBOOT => "reboot",
            abi::POWER_CRASH => "kernel panic",
            _ => "unknown",
        };
        info!("l4h-vmmgr: guest {} power request {} ({})", id, how, reason);
        if how != abi::POWER_OFF && h.guest(id).is_some_and(|g| g.dom0) {
            // The caller (dom0's VMM) is destroyed: no reply.
            restart_dom0(h, id);
            return Err(l4h_host::wire::NO_REPLY);
        }
        if let Some(Some(g)) = h.guests.get_mut(id) {
            for v in &g.vcpus {
                let _ = v.ktcb.tcb_suspend();
            }
            g.state = State::Stopped;
        }
        if h.guests.iter().flatten().all(|g| g.state != State::Running) {
            info!("l4h-vmmgr: all guests stopped");
        }
        Ok(())
    }

    fn op_done(&mut self, _: proto::Sender, token: usize) -> Result<(), Errno> {
        if token >= proto::MAX_PENDING {
            return Err(EINVAL);
        }
        let mut done = [0; proto::MAX_PENDING / 64];
        done[token / 64] = 1 << (token % 64);
        self.0.root_done(done);
        Ok(())
    }

    fn attest_done(&mut self, _: proto::Sender, guest: usize) -> Result<(), Errno> {
        let h = &mut *self.0;
        let g = h.guests.get(guest).and_then(|g| g.as_ref()).ok_or(EINVAL)?;
        if let Some(d) = g.devices.iter().position(|d| d.kind == guest::DevKind::Attest) {
            g.raise_event(&mut h.alloc, guest::dev_event(d));
        }
        Ok(())
    }

    fn destroy(&mut self, _: proto::Sender, guest: usize) -> Result<(), Errno> {
        let h = &mut *self.0;
        if !h.guest(guest).is_some_and(|g| !g.dom0) {
            l4h_rt::log!("l4h-vmmgr: monitor: destroy {} refused", guest);
            return Err(EINVAL);
        }
        let _ = h.destroy_guest(guest);
        Ok(())
    }

    fn restart_dom0(&mut self, _: proto::Sender) -> Result<(), Errno> {
        let h = &mut *self.0;
        match h.guests.iter().flatten().find(|g| g.dom0).map(|g| g.id) {
            Some(id) => restart_dom0(h, id),
            None if h.kernel.is_some() => boot_dom0(h),
            None => {}
        }
        Ok(())
    }
}

l4h_rt::component!(main, no_heap);

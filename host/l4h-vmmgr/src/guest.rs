//! Construction of a guest: its CSpace, guest-kernel VSpace, RAM, vCPUs and
//! boot info, following `include/l4h/abi.h`.
//!
//! A guest is created empty (`create`), gets devices attached and its
//! image loaded (`write_ram`, `load_ram`), and is then booted
//! (`write_boot_info`, `start`).  All its objects come from its arena, so
//! `destroy` reclaims everything by revoking the arena.  What devices
//! reach (the I/O pool, disk channels, netd ports) is l4h-root's: root
//! makes it when vmmgr asks (root.rs), and takes it back after `destroy`.
//!
//! Guest RAM is a list of 2 MiB blocks, each its own Untyped from any free
//! 2 MiB of host memory (DESIGN.md §8.2).  l4h-memd keeps the original
//! Untyped of every block (memd.rs); the guest gets a copy of those it may
//! retype (all but the boot blocks, of which vmmgr gets a copy to fill
//! with frames for the image).  memd revokes the originals at destroy,
//! which deletes whatever the guest and vmmgr made of them.
//!
//! The blocks of the kernel image that every guest shares (kimage.rs) are
//! not among them: they hold read-only copies of the boot module's
//! frames, and are guest-physical space on top of the RAM the guest was
//! given.  Guest block b is memd's block b less the shared blocks below
//! it (`memd_block`).
//!
//! Above the I/O pool, every guest has a hotplug region (DESIGN.md §8.5):
//! guest-physical space up to abi::GPA_END in hotplug blocks of 128 MiB,
//! which its l4h-vmm plugs and unplugs with memd while it runs.  All the
//! host makes for it is the level-1 hotplug CNode (16 KiB).

use core::ptr;

use crate::slot;
use sel4::{CNodeCapData, CapRights, ObjectBlueprint, VmAttributes, cap, cap_type};

use l4h_abi as abi;
use l4h_host as host;
use l4h_host::fixed::{ArrayString, ArrayVec, Scratch};
use l4h_host::vmmgr as proto;

use crate::component::Component;
use crate::kimage::Kernel;
use crate::layout;
use crate::mem::{Alloc, Arena, Dest, ObjCtx, Slot, UtRegion};
use crate::{memd, root, vmm};
use crate::vspace::{FRAME_BP, PML4_BP, map_frame};
use crate::window::Window;
use crate::{AsidPools, HostInfo};

const PAGE: usize = 4096;
/// A block of guest RAM, and its frames.
pub const BLOCK: usize = abi::BLOCK_SIZE;
const BLOCK_FRAMES: usize = BLOCK / PAGE;
/// Blocks of host frames after the image: the guest kernel's memory until
/// it has mapped the rest of its RAM.
pub const BOOT_SLACK: usize = 1;
/// Host memory and slots filling a block with frames takes: its
/// level-2 RAM CNode and a page table of the direct map, and slots for
/// them and for its Untyped (block_frames).  The bytes count the
/// alignment: a 16 KiB CNode after a page table skips 12 KiB.
const BLOCK_FRAMES_BYTES: usize = 2 * (32 << abi::RAM_L2_BITS);
const BLOCK_FRAMES_SLOTS: usize = 3;
/// Devices a guest can have (console, control, virtio).
pub use l4h_host::MAX_GUEST_DEVICES;
/// VSpaces of a guest's processes (the guest's VSpace pool), at most.
pub const MAX_VSPACES: usize = 64;

/// Badge layout of vmmgr's fault endpoint for guest kernels.
pub const HYP_BADGE_FAULT: u64 = host::BADGE_FAULT;
pub fn hyp_badge(guest: usize, vcpu: usize) -> u64 {
    (guest as u64) | ((vcpu as u64) << 16)
}
pub fn hyp_badge_guest(b: u64) -> usize {
    (b & 0xffff) as usize
}
pub fn hyp_badge_vcpu(b: u64) -> usize {
    ((b >> 16) & 0xff) as usize
}

/// Where vmmgr maps a guest's pages for itself (layout::GUEST_PAGES):
/// its control page, its console page, then from these offsets its
/// console ring and the event page of each vCPU.
fn self_guest_va(id: usize) -> usize {
    assert!(id < crate::MAX_GUESTS);
    layout::GUEST_PAGES.base + id * layout::GUEST_STRIDE
}
const GUEST_RING_OFF: usize = 0x1_0000;
const GUEST_EVENTS_OFF: usize = 0x2_0000;
const _: () = assert!(2 * PAGE <= GUEST_RING_OFF);
const _: () = assert!(GUEST_RING_OFF + host::CONSOLE_RING_PAGES * PAGE <= GUEST_EVENTS_OFF);
const _: () = assert!(GUEST_EVENTS_OFF + abi::MAX_VCPUS * PAGE <= layout::GUEST_STRIDE);

/// Default size of a guest's I/O pool, and its bounds (a power of two).
pub const IO_POOL_DEFAULT: usize = 4 << 20;
pub const IO_POOL_MIN: usize = 1 << 20;
pub const IO_POOL_MAX: usize = 256 << 20;
/// The I/O pool starts at the first GPA above RAM with this alignment.
const IO_POOL_ALIGN: usize = 2 << 20;

pub struct GuestConfig<'a> {
    pub name: &'a str,
    /// Bytes of RAM, rounded up to whole blocks.  The shared blocks of the
    /// kernel image come on top.
    pub ram: usize,
    pub vcpus: usize,
    /// Bytes of I/O pool (a power of two, IO_POOL_MIN..=IO_POOL_MAX).
    pub io_pool: usize,
    pub vspaces: usize,
    /// Guest-virtual address of GPA 0 (from the kernel image).
    pub ram_base: usize,
    pub dom0: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DevKind {
    Console,
    Ctl,
    Virtio(u32),
    /// Served by trustd, which owns the page (trustd.rs).
    Attest,
    /// Memory hotplug (abi::MemPage), written by l4h-vmm.
    Mem,
}

pub struct GuestDev {
    pub kind: DevKind,
    pub page: cap::Granule,
}

/// Event line of boot info device `d`.
pub fn dev_event(d: usize) -> u32 {
    16 + d as u32
}
const _: () = assert!(16 + MAX_GUEST_DEVICES <= abi::NR_EVENTS);

/// Disjoint ranges of guest RAM, (gpa, len) in order: what was loaded
/// before boot.  When there are more islands than fit, the two closest
/// merge, which covers more than was loaded: checks against it can only
/// be stricter.
#[derive(Default)]
pub struct Ranges(ArrayVec<(usize, usize), 16>);

impl Ranges {
    pub fn add(&mut self, gpa: usize, len: usize) {
        let (mut lo, mut hi) = (gpa, gpa + len);
        // Absorb every range this touches.
        self.0.retain(|&(g, l)| {
            let touches = g <= hi && lo <= g + l;
            if touches {
                lo = lo.min(g);
                hi = hi.max(g + l);
            }
            !touches
        });
        let i = self.0.iter().position(|&(g, _)| g > lo).unwrap_or(self.0.len());
        if self.0.is_full() {
            // Merge the two ranges with the smallest gap between them.
            let j = (1..self.0.len()).min_by_key(|&j| self.0[j].0 - (self.0[j - 1].0 + self.0[j - 1].1)).unwrap();
            let (g, l) = self.0.remove(j);
            let prev = &mut self.0[j - 1];
            prev.1 = g + l - prev.0;
            return self.add(lo, hi - lo);
        }
        let _ = self.0.insert(i, (lo, hi - lo));
    }

    pub fn iter(&self) -> impl Iterator<Item = (usize, usize)> + '_ {
        self.0.iter().copied()
    }
}

/// Boot info under construction (16 KiB), before it is copied into the
/// guest's frames.
static BOOTINFO: Scratch<core::mem::MaybeUninit<abi::BootInfo>> = Scratch::new(core::mem::MaybeUninit::zeroed());

/// The guest's I/O pool: host-owned, physically contiguous memory above
/// guest RAM in guest-physical space.  All device I/O goes through it
/// (the guest bounces with swiotlb); devices and host components never
/// access guest RAM.  The guest gets mappings of it, not capabilities.
/// Root makes it (it maps it for disks) and holds its Untyped: vmmgr has
/// copies of its frames.
pub struct IoPool {
    pub gpa: usize,
    pub size: usize,
    /// The frames, slot i = page i (radix `radix`).
    frames: cap::CNode,
    radix: usize,
}

impl IoPool {
    pub fn frame(&self, i: usize) -> sel4::AbsoluteCPtr {
        self.frames.absolute_cptr_from_bits_with_depth(i as u64, self.radix)
    }

    pub fn pages(&self) -> usize {
        self.size >> self.frame_bits()
    }

    pub fn frame_bits(&self) -> usize { host::blk::pool_frame_bits(self.size) }
}

pub struct Vcpu {
    pub ktcb: cap::Tcb,
    pub ntfn: cap::Notification,
    pub event: cap::Granule,
    pub sc_k: cap::SchedContext,
    pub sc_u: cap::SchedContext,
    pub core: usize,
    /// Balancer periods before the vCPU may move again.
    pub cooldown: u32,
    /// CPU used in the last balancer period, in permille of a core.
    pub usage: u32,
    /// Under a CPU cap: SC_K's part of the vCPU's budget, in permille
    /// (sched::budgets).
    pub k_share: u32,
    /// Steal-time bookkeeping (counter ticks): time since the vCPU first
    /// ran, CPU it consumed; steal published so far (ns).
    pub wall_ticks: u64,
    pub run_ticks: u64,
    pub steal_ns: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Created,
    Running,
    Stopped,
}

pub struct Guest {
    pub id: usize,
    /// Unique since host boot, assigned before any console input.
    pub instance: u64,
    pub name: ArrayString<{ abi::CTL_NAME_MAX }>,
    pub arena: Arena,
    pub cnode: cap::CNode,
    pub vspace: cap::VSpace,
    pub ram_base: usize,
    /// Blocks of guest-physical RAM: memd's (it holds their Untypeds) and
    /// the shared ones.
    pub nr_blocks: usize,
    /// Shared blocks of the kernel image, one bit each (Kernel::shared).
    shared: u64,
    /// Blocks vmmgr filled with frames (boot blocks, shared blocks),
    /// one bit each; their level-2 RAM CNodes are in `ram_l1`.
    filled: [u64; abi::MAX_BLOCKS / 64],
    /// Level-1 RAM CNodes, one per GiB of guest-physical space.
    ram_l1: ArrayVec<cap::CNode, { abi::MAX_RAM_L1 }>,
    /// Blocks [0, boot_blocks) are host frames; set at boot.
    pub boot_blocks: usize,
    pub pool: IoPool,
    /// dom0: the control device's data area (VM_LOAD source), mapped in
    /// vmmgr at proto::CTL_DATA_VA.
    ctl_data: bool,
    pub vcpus: ArrayVec<Vcpu, { abi::MAX_VCPUS }>,
    pub state: State,
    pub dom0: bool,
    /// Its processes' VSpaces (the pool it recycles, abi::SLOT_VSPACE_POOL).
    vspaces: ArrayVec<cap::VSpace, MAX_VSPACES>,
    bootinfo: ArrayVec<cap::Granule, { abi::BOOTINFO_SIZE as usize / PAGE }>,
    entry: u64,
    /// Objects l4h-vmm serves the guest with: its endpoint (the guest's
    /// HYP_EP), its bound notification (device kicks) and the device pages.
    pub vmm_ep: cap::Endpoint,
    pub vmm_ntfn: cap::Notification,
    dev_cn: cap::CNode,
    pub devices: ArrayVec<GuestDev, MAX_GUEST_DEVICES>,
    /// Host side of each virtio device, by device index.
    pub backends: ArrayVec<(usize, vmm::Backend), MAX_GUEST_DEVICES>,
    pub console_ring: ArrayVec<cap::Granule, { host::CONSOLE_RING_PAGES }>,
    /// Large VMM objects reserved at creation, before VM_LOAD uses the arena.
    pub vmm_cnodes: Option<vmm::Cnodes>,
    pub vmm: Option<Component>,
    /// CPU cap per vCPU in percent of a core (0 = none).
    pub cpu_cap_pct: u32,
    /// ASIDs held by its VSpaces (its own, its processes', its components').
    pub asids: usize,
    /// It has an attestation device (trustd.rs).
    pub attest: bool,
    /// Guest RAM ranges loaded before boot: the image, which must lie in
    /// what the launch digest covers.
    loaded: Ranges,
    /// The launch digest, set at boot (DESIGN.md §10.2).
    pub launch: Option<[u8; 32]>,
    /// Bytes of the module image mapped at KMOD_VA (kimage.rs), 0 if none.
    pub kmod_size: usize,
    /// Its virtio-gpu's scanout size, if it has one; the display area is
    /// mapped at gpu::self_display_va(id).
    pub gpu: Option<(u32, u32)>,
    /// Its hotplug region: hp_count hotplug blocks from hp_gpa.
    pub hp_gpa: usize,
    pub hp_count: usize,
    /// Its memory device (DevKind::Mem).
    pub mem_dev: Option<usize>,
}

pub(crate) fn abs(c: impl sel4::HasCPtrWithDepth) -> sel4::AbsoluteCPtr {
    slot::CNODE.cap().absolute_cptr(c)
}

pub(crate) fn self_cap<T: sel4::CapType>(s: Slot) -> sel4::Cap<T> {
    sel4::init_thread::Slot::<T>::from_index(s).cap()
}


impl Guest {
    pub fn ctx<'a>(&'a mut self, alloc: &'a mut Alloc) -> ObjCtx<'a> {
        ObjCtx::arena(alloc, &mut self.arena)
    }

    /// Bytes of guest-physical RAM, shared blocks included.
    pub fn ram_size(&self) -> usize {
        self.nr_blocks * BLOCK
    }

    /// Bytes of RAM the guest was given: without the shared blocks.
    pub fn owned_ram(&self) -> usize {
        (self.nr_blocks - self.shared.count_ones() as usize) * BLOCK
    }

    fn is_filled(&self, b: usize) -> bool {
        self.filled[b / 64] & (1 << (b % 64)) != 0
    }

    fn is_shared(&self, b: usize) -> bool {
        b < 64 && self.shared & (1 << b) != 0
    }

    /// Shared blocks below block `b`.
    fn shared_below(&self, b: usize) -> usize {
        (self.shared & 1u64.checked_shl(b as u32).map_or(u64::MAX, |m| m - 1)).count_ones() as usize
    }

    /// memd's index of guest block `b`, which is not shared.
    fn memd_block(&self, b: usize) -> usize {
        b - self.shared_below(b)
    }

    /// Destination for a capability in the guest's root CNode.
    fn guest_slot(&self, idx: usize) -> sel4::AbsoluteCPtr {
        self.cnode.absolute_cptr_from_bits_with_depth(idx as u64, abi::ROOT_CNODE_BITS)
    }

    fn give(&self, idx: usize, src: impl sel4::HasCPtrWithDepth, rights: CapRights) {
        self.guest_slot(idx)
            .copy(&abs(src), rights)
            .unwrap_or_else(|e| panic!("guest slot {} copy failed: {:?}", idx, e));
    }

    pub(crate) fn give_badged(&self, idx: usize, src: impl sel4::HasCPtrWithDepth, rights: CapRights, badge: u64) {
        self.guest_slot(idx)
            .mint(&abs(src), rights, badge)
            .unwrap_or_else(|e| panic!("guest slot {} mint failed: {:?}", idx, e));
    }

    /// The frame capability backing guest-physical address `gpa`, which
    /// must be in a block vmmgr filled with frames.
    pub fn ram_frame(&self, gpa: usize) -> sel4::AbsoluteCPtr {
        let b = gpa / BLOCK;
        assert!(self.is_filled(b), "guest RAM block without host frames");
        // Through the level-1 RAM CNode, which holds the block's level-2
        // CNode at its index (both without guard).
        let l2 = b & ((1 << abi::RAM_L2_BITS) - 1);
        self.ram_l1[b >> abi::RAM_L2_BITS]
            .absolute_cptr_from_bits_with_depth(((l2 << abi::RAM_L2_BITS) | (gpa % BLOCK) / PAGE) as u64, 2 * abi::RAM_L2_BITS)
    }

    pub fn valid_gpa(&self, gpa: usize, len: usize) -> bool {
        gpa.checked_add(len).is_some_and(|end| end <= self.ram_size())
    }

    /// Fill block `b` with frames: a level-2 RAM CNode (which the guest
    /// finds in its level-1 CNode) holding 512 frames retyped from the
    /// block's Untyped, mapped in the direct map.  The block becomes a
    /// boot block: the guest gets no Untyped for it.
    fn block_frames(&mut self, alloc: &mut Alloc, b: usize) {
        if self.is_filled(b) {
            return;
        }
        let l2 = self.arena.object_cap::<cap_type::CNode>(alloc, ObjectBlueprint::CNode { size_bits: abi::RAM_L2_BITS });
        self.ram_l1[b >> abi::RAM_L2_BITS]
            .absolute_cptr_from_bits_with_depth((b & ((1 << abi::RAM_L2_BITS) - 1)) as u64, abi::RAM_L2_BITS)
            .copy(&abs(l2), CapRights::all())
            .expect("level-2 RAM CNode");
        // A copy of the block's Untyped, which memd revokes at destroy.
        let ut = alloc.slots.alloc();
        let paddr = memd::guest_copy(alloc, self.id, self.memd_block(b), ut);
        UtRegion::fresh(self_cap::<cap_type::Untyped>(ut), paddr, abi::BLOCK_SHIFT)
            .retype(&FRAME_BP, BLOCK_FRAMES, Dest { cnode: abs(l2), offset: 0 })
            .expect("RAM frames");
        self.filled[b / 64] |= 1 << (b % 64);
        // The direct map uses the original frame caps; the guest maps
        // copies elsewhere.
        let tmp = alloc.slots.alloc();
        for i in 0..BLOCK_FRAMES {
            let gpa = b * BLOCK + i * PAGE;
            abs(self_cap::<cap_type::Null>(tmp)).move_(&self.ram_frame(gpa)).expect("move frame");
            let frame = self_cap::<cap_type::Granule>(tmp);
            let (vspace, va) = (self.vspace, self.ram_base + gpa);
            map_frame(&mut self.ctx(alloc), vspace, frame, va, CapRights::read_write(), VmAttributes::DEFAULT);
            self.ram_frame(gpa).move_(&abs(frame)).expect("move frame back");
        }
        alloc.slots.free(tmp);
    }

    /// Fill shared block `b` with read-only copies of the kernel's frames
    /// for it, mapped in the direct map.  It has no Untyped: nothing of it
    /// is the guest's.
    fn share_block(&mut self, alloc: &mut Alloc, kernel: &Kernel, b: usize) {
        let l2 = self.arena.object_cap::<cap_type::CNode>(alloc, ObjectBlueprint::CNode { size_bits: abi::RAM_L2_BITS });
        self.ram_l1[b >> abi::RAM_L2_BITS]
            .absolute_cptr_from_bits_with_depth((b & ((1 << abi::RAM_L2_BITS) - 1)) as u64, abi::RAM_L2_BITS)
            .copy(&abs(l2), CapRights::all())
            .expect("level-2 RAM CNode");
        self.filled[b / 64] |= 1 << (b % 64);
        let tmp = alloc.slots.alloc();
        for i in 0..BLOCK_FRAMES {
            let gpa = b * BLOCK + i * PAGE;
            kernel.copy_frame(gpa, tmp);
            let frame = self_cap::<cap_type::Granule>(tmp);
            let (vspace, va) = (self.vspace, self.ram_base + gpa);
            map_frame(&mut self.ctx(alloc), vspace, frame, va, CapRights::read_only(), VmAttributes::DEFAULT);
            self.ram_frame(gpa).move_(&abs(frame)).expect("move shared frame");
        }
        alloc.slots.free(tmp);
    }

    /// Make guest RAM [gpa, gpa + len) host frames, to load an image into
    /// it before the guest runs.  Shared blocks are read-only: nothing is
    /// loaded into them.
    fn prepare_ram(&mut self, alloc: &mut Alloc, gpa: usize, len: usize) -> bool {
        if !self.valid_gpa(gpa, len) || self.state != State::Created || self.boot_blocks != 0 {
            return false;
        }
        if len != 0 {
            let blocks = gpa / BLOCK..=(gpa + len - 1) / BLOCK;
            if blocks.clone().any(|b| self.is_shared(b)) {
                return false;
            }
            for b in blocks {
                self.block_frames(alloc, b);
            }
        }
        true
    }

    /// Copy `data` into guest RAM at `gpa` (before boot).
    pub fn write_ram(&mut self, alloc: &mut Alloc, win: &mut Window, gpa: usize, data: &[u8]) -> bool {
        self.load_ram(alloc, win, gpa, data.as_ptr(), data.len())
    }

    /// Copy `len` bytes from `from` (memory of vmmgr) into guest
    /// RAM at `gpa` (before boot).
    pub fn load_ram(&mut self, alloc: &mut Alloc, win: &mut Window, gpa: usize, from: *const u8, len: usize) -> bool {
        if !self.prepare_ram(alloc, gpa, len) {
            return false;
        }
        if len != 0 {
            self.loaded.add(gpa, len);
        }
        let mut off = 0;
        while off < len {
            let d = gpa + off;
            let dp = d & !(PAGE - 1);
            let n = (PAGE - (d - dp)).min(len - off);
            win.with_frame(&self.ram_frame(dp), |to| unsafe {
                ptr::copy_nonoverlapping(from.add(off), to.add(d - dp), n);
            });
            off += n;
        }
        true
    }

    /// dom0's control data area (VM_LOAD source) as mapped in vmmgr.  It
    /// belongs to the host: vmmgr never reads a guest's RAM.
    pub fn ctl_data(&self) -> Option<*const u8> {
        self.ctl_data.then_some(proto::CTL_DATA_VA as *const u8)
    }

    /// Add a device: a shared page mapped in the guest at its device area
    /// and a kick capability (badged notification of l4h-vmm).
    pub fn add_device(&mut self, alloc: &mut Alloc, kind: DevKind) -> Option<usize> {
        let d = self.devices.len();
        if d >= MAX_GUEST_DEVICES || self.state != State::Created {
            return None;
        }
        let page = self.arena.object_cap::<cap_type::Granule>(alloc, FRAME_BP);
        let kick = match kind {
            // Control requests go to vmmgr itself, not through the VMM.
            DevKind::Ctl => (crate::slot::NTFN.cap(), crate::CTL_KICK_BADGE),
            DevKind::Mem => (self.vmm_ntfn, host::VMM_BADGE_MEM_REQ),
            _ => (self.vmm_ntfn, host::VMM_BADGE_KICK),
        };
        self.add_device_with(alloc, kind, page, kick)
    }

    /// Add a device with shared page `page`, whose kick notification is
    /// `kick` (a notification and a badge, or 0 if it is badged already).
    pub fn add_device_with(&mut self, alloc: &mut Alloc, kind: DevKind, page: cap::Granule, kick: (cap::Notification, u64)) -> Option<usize> {
        let d = self.devices.len();
        if d >= MAX_GUEST_DEVICES || self.state != State::Created {
            return None;
        }
        let vspace = self.vspace;
        let mut ctx = self.ctx(alloc);
        // The guest maps a copy; the original is kept for l4h-vmm.
        let copy = ctx.alloc.slots.alloc();
        abs(self_cap::<cap_type::Null>(copy)).copy(&abs(page), CapRights::all()).expect("device page copy");
        map_frame(&mut ctx, vspace, self_cap::<cap_type::Granule>(copy), abi::dev_area_va(d) as usize, CapRights::read_write(), VmAttributes::DEFAULT);
        let kick_slot = self.dev_cn.absolute_cptr_from_bits_with_depth(d as u64, abi::ROOT_CNODE_BITS);
        if kick.1 == 0 {
            kick_slot.copy(&abs(kick.0), CapRights::write_only())
        } else {
            kick_slot.mint(&abs(kick.0), CapRights::write_only(), kick.1)
        }
        .expect("device kick cap");
        // Console and control pages are also used by vmmgr itself.
        let self_va = match kind {
            DevKind::Ctl => Some(self_guest_va(self.id)),
            DevKind::Console => Some(self_guest_va(self.id) + PAGE),
            DevKind::Virtio(_) | DevKind::Attest | DevKind::Mem => None,
        };
        if let Some(va) = self_va {
            self.map_in_self(alloc, page, va);
        }
        if kind == DevKind::Ctl {
            // The data area for VM_LOAD: host frames that root made, mapped
            // in vmmgr and root and in every dom0.
            let frames = self_cap::<cap_type::CNode>(proto::SLOT_CTL_DATA as Slot);
            for i in 0..proto::CTL_DATA_PAGES {
                let copy = alloc.slots.alloc();
                abs(self_cap::<cap_type::Null>(copy))
                    .copy(&frames.absolute_cptr_from_bits_with_depth(i as u64, proto::CTL_DATA_RADIX), CapRights::all())
                    .expect("ctl data copy");
                let vspace = self.vspace;
                let va = abi::CTL_DATA_VA as usize + i * PAGE;
                map_frame(&mut self.ctx(alloc), vspace, self_cap::<cap_type::Granule>(copy), va, CapRights::read_write(), VmAttributes::DEFAULT);
            }
            self.ctl_data = true;
        }
        self.devices.must_push(GuestDev { kind, page });
        Some(d)
    }

    /// Map (a copy of) one of our frames into vmmgr.  The paging
    /// structures are global: the region is reused by later guests.
    fn map_in_self(&mut self, alloc: &mut Alloc, frame: cap::Granule, va: usize) {
        self.map_abs_in_self(alloc, &abs(frame), va);
    }

    /// map_in_self for a frame in any CNode.
    pub(crate) fn map_abs_in_self(&mut self, alloc: &mut Alloc, frame: &sel4::AbsoluteCPtr, va: usize) {
        let copy = alloc.slots.alloc();
        abs(self_cap::<cap_type::Null>(copy)).copy(frame, CapRights::all()).expect("vmmgr map copy");
        alloc.global(|alloc| {
            map_frame(&mut ObjCtx::global(alloc), slot::VSPACE.cap(), self_cap::<cap_type::Granule>(copy), va, CapRights::read_write(), VmAttributes::DEFAULT);
        });
    }

    pub fn ctl_page(&self) -> Option<*mut u8> {
        self.devices.iter().any(|d| d.kind == DevKind::Ctl).then(|| self_guest_va(self.id) as *mut u8)
    }

    pub fn console_page(&self) -> *mut abi::ConsolePage {
        (self_guest_va(self.id) + PAGE) as *mut abi::ConsolePage
    }

    /// Raise event line `ev` on vCPU 0, as l4h-vmm does for devices.
    pub fn raise_event(&self, alloc: &mut Alloc, ev: u32) {
        let page = self.event_page(0);
        unsafe {
            let w = core::ptr::addr_of_mut!((*page).pending[(ev / 64) as usize]) as *const core::sync::atomic::AtomicU64;
            (*w).fetch_or(1 << (ev % 64), core::sync::atomic::Ordering::SeqCst);
        }
        let s = alloc.slots.alloc();
        let badged = self_cap::<cap_type::Notification>(s);
        abs(badged).mint(&abs(self.vcpus[0].ntfn), CapRights::write_only(), abi::BADGE_EVENT).expect("event cap");
        badged.signal();
        abs(badged).delete().expect("delete event cap");
        alloc.slots.free(s);
    }

    /// Signal the guest's l4h-vmm with `badge` (host::VMM_BADGE_*).
    pub fn signal_vmm(&self, alloc: &mut Alloc, badge: u64) {
        let s = alloc.slots.alloc();
        let badged = self_cap::<cap_type::Notification>(s);
        abs(badged).mint(&abs(self.vmm_ntfn), CapRights::write_only(), badge).expect("VMM signal cap");
        badged.signal();
        abs(badged).delete().expect("delete VMM signal cap");
        alloc.slots.free(s);
    }

    /// Event page of vCPU `v`, as mapped in vmmgr.
    pub fn event_page(&self, v: usize) -> *mut abi::EventPage {
        (self_guest_va(self.id) + GUEST_EVENTS_OFF + v * PAGE) as *mut abi::EventPage
    }

    pub fn console_ring(&self) -> *const host::ConsoleRing {
        (self_guest_va(self.id) + GUEST_RING_OFF) as *const host::ConsoleRing
    }

    /// Host memory and slots filling these blocks with frames can
    /// need. Already filled blocks take nothing; page directories and a
    /// PDPT are counted conservatively even if they are already present.
    fn block_frames_cost(&self, blocks: core::ops::Range<usize>) -> (usize, usize) {
        let n = blocks.clone().filter(|&b| !self.is_filled(b)).count();
        if n == 0 {
            return (0, 0);
        }
        let dirs = blocks.end.div_ceil(512) - blocks.start / 512 + 1;
        (n * BLOCK_FRAMES_BYTES + dirs * PAGE, n * BLOCK_FRAMES_SLOTS + dirs)
    }

    /// What loading [gpa, gpa + len) costs before any block is filled.
    /// None for a range or state that load_ram refuses.
    pub fn load_cost(&self, gpa: usize, len: usize) -> Option<(usize, usize)> {
        if !self.valid_gpa(gpa, len) || self.state != State::Created || self.boot_blocks != 0 {
            return None;
        }
        if len == 0 {
            return Some((0, 0));
        }
        let blocks = gpa / BLOCK..(gpa + len).div_ceil(BLOCK);
        if blocks.clone().any(|b| self.is_shared(b)) {
            return None;
        }
        Some(self.block_frames_cost(blocks))
    }

    /// The boot blocks for an image ending at `kernel_end` and `initrd`: a
    /// prefix of RAM up to the image (and anything else loaded), plus
    /// slack.  None if the guest would have no block of its own left for
    /// seL4 objects.
    fn boot_prefix(&self, kernel_end: usize, initrd: (usize, usize)) -> Option<usize> {
        // An empty initrd has no end: its address must not grow the prefix.
        let image_end = if initrd.1 != 0 { kernel_end.max(initrd.0.checked_add(initrd.1)?) } else { kernel_end };
        let loaded = (0..self.nr_blocks).rev().find(|&b| self.is_filled(b)).map_or(0, |b| b + 1);
        let boot = image_end.div_ceil(BLOCK).max(loaded) + BOOT_SLACK;
        (boot < self.nr_blocks).then_some(boot)
    }

    /// What booting with `kernel_end` and `initrd` costs the host, in bytes
    /// and slots: filling the boot blocks that have no frames yet,
    /// and a page directory for every GiB of them.  dom0 chooses the
    /// prefix, which can be most of the guest's RAM, so it is checked
    /// before booting (and the bytes reserved, `reserve`) rather than
    /// covered by the guest's arena estimate.
    pub fn boot_cost(&self, kernel_end: usize, initrd: (usize, usize)) -> Option<(usize, usize)> {
        let boot = self.boot_prefix(kernel_end, initrd)?;
        Some(self.block_frames_cost(0..boot))
    }

    /// Grow the guest's arena to hold `bytes` more objects.
    pub fn reserve(&mut self, alloc: &mut Alloc, bytes: usize) -> bool {
        self.arena.reserve(alloc, bytes)
    }

    /// Write the boot info and give the guest its RAM: the boot blocks
    /// (image, initrd and BOOT_SLACK more) as host frames, the others as
    /// Untyped copies.  Validates the boot parameters.
    pub fn write_boot_info(
        &mut self,
        alloc: &mut Alloc,
        win: &mut Window,
        host_info: &HostInfo,
        entry: u64,
        kernel_end: usize,
        initrd: (usize, usize),
        cmdline: &[u8],
    ) -> bool {
        let ram = self.ram_size();
        let entry_gpa = (entry as usize).wrapping_sub(self.ram_base);
        if kernel_end > ram || kernel_end % PAGE != 0 || entry_gpa >= kernel_end || !self.valid_gpa(initrd.0, initrd.1) {
            return false;
        }
        if self.boot_blocks != 0 {
            return false;
        }
        // Everything loaded must be measured: the kernel image or the
        // initramfs.
        let within = |(gpa, len): (usize, usize), (lo, n): (usize, usize)| gpa >= lo && gpa + len <= lo + n;
        if !self.loaded.iter().all(|r| within(r, (0, kernel_end)) || within(r, initrd)) {
            return false;
        }
        let Some(boot) = self.boot_prefix(kernel_end, initrd) else {
            return false;
        };
        for b in 0..boot {
            self.block_frames(alloc, b);
        }
        // memd gives its blocks from the first after the boot blocks on, at
        // their guest index: past the shared blocks, which are all in the
        // image.
        let shared = self.shared_below(boot);
        if shared != self.shared.count_ones() as usize || !memd::guest_give(alloc, self.id, boot - shared, shared) {
            return false;
        }
        self.boot_blocks = boot;
        BOOTINFO.with(|bi| {
            *bi = core::mem::MaybeUninit::zeroed();
            self.fill_boot_info(unsafe { bi.assume_init_mut() }, win, host_info, entry, kernel_end, initrd, cmdline);
        });
        self.entry = entry;
        true
    }

    fn fill_boot_info(
        &mut self,
        bi: &mut abi::BootInfo,
        win: &mut Window,
        host_info: &HostInfo,
        entry: u64,
        kernel_end: usize,
        initrd: (usize, usize),
        cmdline: &[u8],
    ) {
        let ram = self.ram_size();
        bi.magic = abi::BOOTINFO_MAGIC;
        bi.abi_version = abi::ABI_VERSION;
        bi.guest_id = self.id as u64;
        bi.ram_base_va = self.ram_base as u64;
        bi.ram_size = ram as u64;
        bi.kernel_end_gpa = kernel_end as u64;
        if initrd.1 != 0 {
            bi.initrd_gpa = initrd.0 as u64;
            bi.initrd_size = initrd.1 as u64;
        }
        bi.nr_vcpus = self.vcpus.len() as u64;
        bi.tsc_hz = host_info.tsc_hz;
        bi.cpu_id = host_info.cpu_id;
        bi.nr_blocks = self.nr_blocks as u64;
        bi.boot_blocks = self.boot_blocks as u64;
        bi.nr_vspaces = self.vspaces.len() as u64;
        if self.kmod_size != 0 {
            bi.kmod_va = abi::KMOD_VA;
            bi.kmod_size = self.kmod_size as u64;
        }

        bi.flags = if self.dom0 { abi::BOOT_DOM0 } else { 0 };
        bi.io_pool_gpa = self.pool.gpa as u64;
        bi.io_pool_size = self.pool.size as u64;
        bi.hp_gpa = self.hp_gpa as u64;
        bi.hp_count = self.hp_count as u64;
        bi.nr_devices = self.devices.len() as u64;
        for (d, dev) in self.devices.iter().enumerate() {
            let (ty, virtio_id) = match dev.kind {
                DevKind::Console => (abi::DEV_CONSOLE, 0),
                DevKind::Ctl => (abi::DEV_CTL, 0),
                DevKind::Virtio(id) => (abi::DEV_VIRTIO, id),
                DevKind::Attest => (abi::DEV_ATTEST, 0),
                DevKind::Mem => (abi::DEV_MEM, 0),
            };
            let (data_va, data_size) = match dev.kind {
                DevKind::Ctl => (abi::CTL_DATA_VA, abi::CTL_LOAD_MAX),
                _ => (0, 0),
            };
            bi.devices[d] = abi::DevDesc {
                ty,
                virtio_id,
                page_va: abi::dev_area_va(d),
                page_size: PAGE as u64,
                event: dev_event(d),
                kick_slot: d as u32,
                data_va,
                data_size,
            };
        }
        let n = cmdline.iter().position(|&c| c == 0).unwrap_or(cmdline.len()).min(abi::CMDLINE_SIZE - 1);
        bi.cmdline[..n].copy_from_slice(&cmdline[..n]);
        if self.attest {
            self.launch = Some(self.measure(win, entry, kernel_end, initrd, &cmdline[..n]));
        }

        let bi_bytes = unsafe {
            core::slice::from_raw_parts(bi as *const abi::BootInfo as *const u8, core::mem::size_of::<abi::BootInfo>())
        };
        for (p, frame) in self.bootinfo.iter().enumerate() {
            let lo = (p * PAGE).min(bi_bytes.len());
            let hi = ((p + 1) * PAGE).min(bi_bytes.len());
            let chunk = &bi_bytes[lo..hi];
            win.with_frame(&abs(*frame), |dst| unsafe {
                ptr::write_bytes(dst, 0, PAGE);
                ptr::copy_nonoverlapping(chunk.as_ptr(), dst, chunk.len());
            });
        }
    }

    /// The launch digest (DESIGN.md §10.2): SHA-256 over the image as it is
    /// in guest RAM, the boot parameters that locate it, and the command
    /// line.
    fn measure(&self, win: &mut Window, entry: u64, kernel_end: usize, initrd: (usize, usize), cmdline: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"l4h-launch-v1");
        h.update((self.ram_base as u64).to_le_bytes());
        h.update(entry.to_le_bytes());
        h.update((kernel_end as u64).to_le_bytes());
        let mut range = |h: &mut Sha256, gpa: usize, len: usize| {
            let mut at = gpa;
            while at < gpa + len {
                let page = at & !(PAGE - 1);
                let n = (page + PAGE).min(gpa + len) - at;
                win.with_frame(&self.ram_frame(page), |p| h.update(unsafe { core::slice::from_raw_parts(p.add(at - page), n) }));
                at += n;
            }
        };
        range(&mut h, 0, kernel_end);
        h.update((initrd.1 as u64).to_le_bytes());
        range(&mut h, initrd.0, initrd.1);
        h.update((cmdline.len() as u64).to_le_bytes());
        h.update(cmdline);
        h.finalize().into()
    }

    /// Drop the cores none of its vCPUs is on from the TLB bitmaps of its
    /// VSpaces, the kernel's and its processes', after the balancer moved
    /// a vCPU (vspace::flush_tlb_bitmap).  A VSpace's threads run only on
    /// the cores of the guest's vCPUs, so its bitmap holds those cores and
    /// no others.  Processes moving between the guest's vCPUs are left to
    /// it: their VSpaces may still name the cores of other vCPUs.
    pub fn flush_tlb_bitmaps(&self) {
        crate::vspace::flush_tlb_bitmap(self.vspace);
        for &vs in &self.vspaces {
            crate::vspace::flush_tlb_bitmap(vs);
        }
    }

    /// Start vCPU 0 at the kernel entry point.
    pub fn start(&mut self) {
        let mut regs = sel4::UserContext::default();
        *regs.pc_mut() = self.entry;
        *regs.c_param_mut(0) = abi::BOOTINFO_VA;
        self.vcpus[0].ktcb.tcb_write_all_registers(true, &mut regs).expect("start vCPU 0");
        self.state = State::Running;
        info!("l4h-vmmgr: guest {} '{}' started", self.id, self.name);
    }

    /// Stop all threads of the guest and its VMM.
    pub fn stop(&mut self) {
        for v in &self.vcpus {
            let _ = v.ktcb.tcb_suspend();
        }
        if let Some(v) = &self.vmm {
            let _ = v.tcb.tcb_suspend();
        }
        self.state = State::Stopped;
    }

    /// Destroy the guest and return all its memory and slots, then have
    /// root drain its devices and take back what it made for it.  Guest
    /// RAM is never a DMA target, so it is reused at once; root keeps the
    /// I/O pool out of use for good if a disk could not be stopped.
    pub fn destroy(mut self, alloc: &mut Alloc) {
        self.stop();
        crate::ctl_failure::remove(self.id);
        // The arena first: it holds the VSpace roots, and once they are
        // gone, deleting the guest's frames (and the pool's, which root
        // revokes) unmaps nothing.  The other way round, every frame is
        // unmapped (and the TLBs of every core flushed) one by one, which
        // made destroy five times slower.
        alloc.reclaim(self.arena);
        // Then guest RAM: memd's revocation deletes all that was made of
        // it, the guest's objects and vmmgr's frames of boot blocks.
        memd::guest_destroy(alloc, self.id);
        // Capabilities that do not derive from the arena (badged endpoints,
        // copies of root's frames) are left in their slots.
        alloc.slots.free_owned(self.id);
        root::guest_del(self.id);
    }
}

/// Create a guest with no image.  Slots allocated here and in later
/// operations on the guest must be tracked into `Guest::slots` by the
/// caller (see `Alloc::slots`).  On failure, returns the partly built
/// guest, if there is one, for the caller to destroy.
pub fn create(
    id: usize,
    cfg: &GuestConfig,
    alloc: &mut Alloc,
    asids: &mut AsidPools,
    host_info: &HostInfo,
    kernel: &Kernel,
) -> Result<Guest, Option<Guest>> {
    // Every value comes from the control API: check before computing.
    if cfg.vcpus < 1 || cfg.vcpus > abi::MAX_VCPUS || cfg.ram < (8 << 20) || cfg.ram > abi::MAX_BLOCKS * BLOCK {
        return Err(None);
    }
    if cfg.vspaces > MAX_VSPACES {
        return Err(None);
    }
    // The pool's GPA is 2 MiB aligned; its direct-map VA must also
    // satisfy the frame size root uses for this pool.
    if cfg.ram_base % (1 << host::blk::pool_frame_bits(cfg.io_pool)) != 0 || cfg.ram_base != kernel.ram_base {
        return Err(None);
    }
    if !cfg.io_pool.is_power_of_two() || cfg.io_pool < IO_POOL_MIN || cfg.io_pool > IO_POOL_MAX {
        return Err(None);
    }
    let ram_base = cfg.ram_base;
    // The guest's own blocks, and the kernel's shared blocks on top, of
    // those that fall within them (all, unless RAM is too small for the
    // image to boot).
    let owned = cfg.ram.next_multiple_of(BLOCK) / BLOCK;
    let mut shared = kernel.shared;
    loop {
        let n = owned + shared.count_ones() as usize;
        let within = shared & 1u64.checked_shl(n as u32).map_or(u64::MAX, |m| m - 1);
        if within == shared {
            break;
        }
        shared = within;
    }
    let nr_blocks = owned + shared.count_ones() as usize;
    if nr_blocks > abi::MAX_BLOCKS {
        return Err(None);
    }
    let ram = nr_blocks * BLOCK;
    // The I/O pool follows RAM in guest-physical space and in the direct map.
    let pool_gpa = ram.next_multiple_of(IO_POOL_ALIGN);
    if ram_base == 0 || ram_base.checked_add(pool_gpa + cfg.io_pool).is_none_or(|end| end as u64 > abi::SPECIAL_BASE) {
        return Err(None);
    }
    // The hotplug region fills guest-physical space above the pool.
    let hp_gpa = (pool_gpa + cfg.io_pool).next_multiple_of(abi::HP_SIZE);
    let hp_count = (abi::GPA_END.saturating_sub(hp_gpa) / abi::HP_SIZE).min(abi::HP_MAX);
    if ram_base.checked_add(hp_gpa + hp_count * abi::HP_SIZE).is_none_or(|end| end as u64 > abi::SPECIAL_BASE) {
        return Err(None);
    }

    // Host-side objects for this guest (its arena grows if this is too
    // little): CNodes, the RAM CNodes of the boot blocks and the paging
    // structures mapping them, vCPU objects, the VSpace pool, the I/O
    // pool's mapping CNode, boot info, its l4h-vmm.  The pool itself is
    // root's.  Guest
    // RAM other than the boot blocks costs the host nothing but the
    // block's own memory and a slot: the guest makes its own RAM CNodes,
    // page tables and objects from it.
    let n_l1 = nr_blocks.div_ceil(1 << abi::RAM_L2_BITS);
    let block_radix = (nr_blocks.next_power_of_two().trailing_zeros() as usize).max(1);
    let pool_pages = cfg.io_pool / PAGE;
    let estimate = (32 << abi::ROOT_CNODE_BITS) * 4
        + n_l1 * (32 << abi::RAM_L2_BITS)
        + (32 << block_radix)
        + (32 << abi::HP_L1_BITS)
        + (16 + shared.count_ones() as usize) * ((32 << abi::RAM_L2_BITS) + PAGE)
        + 32 * pool_pages
        + (cfg.io_pool / 512 + 2 * PAGE)
        + cfg.vcpus * (16 << 10)
        + cfg.vspaces * PAGE
        + abi::BOOTINFO_SIZE as usize
        + if cfg.dom0 { abi::CTL_LOAD_MAX as usize } else { 0 }
        + vmm::arena_bytes(cfg.io_pool, cfg.vcpus, MAX_GUEST_DEVICES);
    if alloc.free_bytes() < estimate + owned * BLOCK {
        return Err(None);
    }
    let mut arena = alloc.arena(estimate).ok_or(None)?;

    // Guest root CNode.
    let cnode_slot = alloc.slots.alloc();
    arena
        .retype(alloc, &ObjectBlueprint::CNode { size_bits: abi::ROOT_CNODE_BITS }, 1, Dest::new(crate::slot::CNODE.cap(), cnode_slot))
        .expect("guest CNode");
    let vspace_slot = arena.object(alloc, PML4_BP);
    let vspace = self_cap::<cap_type::VSpace>(vspace_slot);
    asids.assign(alloc, vspace);

    let mut g = Guest {
        id,
        instance: 0,
        name: ArrayString::from_str_truncate(cfg.name),
        arena,
        cnode: self_cap::<cap_type::CNode>(cnode_slot),
        vspace,
        ram_base,
        nr_blocks: 0,
        shared,
        filled: [0; abi::MAX_BLOCKS / 64],
        ram_l1: ArrayVec::new(),
        boot_blocks: 0,
        pool: IoPool { gpa: pool_gpa, size: 0, frames: cap::CNode::from_bits(0), radix: 0 },
        ctl_data: false,
        vcpus: ArrayVec::new(),
        state: State::Created,
        dom0: cfg.dom0,
        vspaces: ArrayVec::new(),
        bootinfo: ArrayVec::new(),
        entry: 0,
        vmm_ep: cap::Endpoint::from_bits(0),
        vmm_ntfn: cap::Notification::from_bits(0),
        dev_cn: cap::CNode::from_bits(0),
        devices: ArrayVec::new(),
        backends: ArrayVec::new(),
        console_ring: ArrayVec::new(),
        vmm_cnodes: None,
        vmm: None,
        cpu_cap_pct: 0,
        asids: 0,
        attest: false,
        loaded: Ranges::default(),
        launch: None,
        kmod_size: 0,
        gpu: None,
        hp_gpa,
        hp_count,
        mem_dev: None,
    };

    let Some(cnodes) = vmm::Cnodes::new(&mut g.arena, alloc, cfg.io_pool) else {
        return Err(Some(g));
    };
    g.vmm_cnodes = Some(cnodes);

    let guard34 = CNodeCapData::new(0, abi::ROOT_GUARD_BITS).into_word();
    let guard6 = CNodeCapData::new(0, abi::L2_INDEX_BITS - abi::ROOT_CNODE_BITS).into_word();
    let meta = g.arena.object_cap::<cap_type::CNode>(alloc, ObjectBlueprint::CNode { size_bits: abi::ROOT_CNODE_BITS });
    meta.absolute_cptr_from_bits_with_depth(0, abi::ROOT_CNODE_BITS)
        .mint(&abs(g.cnode), CapRights::all(), guard34)
        .expect("meta CNode");
    g.give_badged(abi::SLOT_META, meta, CapRights::all(), guard6);
    g.give(abi::SLOT_VSPACE, g.vspace, CapRights::all());

    // ---- RAM: 2 MiB blocks, each an Untyped from any free 2 MiB of host
    // memory (physically contiguous within the block only).  Nothing is
    // retyped yet: the image is loaded into blocks that become host
    // frames (boot blocks), and the guest gets the others as Untypeds.
    // The shared blocks of the image are filled now.
    // Level-1 RAM CNodes (one per GiB, resolving 9 bits) for the guest's
    // level-2 RAM CNodes, and the block CNode for the Untyped copies.
    let guard0 = CNodeCapData::new(0, 0).into_word();
    for n in 0..n_l1 {
        let cn = g.arena.object_cap::<cap_type::CNode>(alloc, ObjectBlueprint::CNode { size_bits: abi::RAM_L2_BITS });
        g.give_badged(abi::SLOT_RAM_L1_BASE + n, cn, CapRights::all(), guard0);
        g.ram_l1.must_push(cn);
    }
    let block_cn = g.arena.object_cap::<cap_type::CNode>(alloc, ObjectBlueprint::CNode { size_bits: block_radix });
    let guard = CNodeCapData::new(0, abi::L2_INDEX_BITS - block_radix).into_word();
    g.give_badged(abi::SLOT_BLOCKS, block_cn, CapRights::all(), guard);
    // The hotplug CNode: the guest makes a level-2 CNode in slot m before
    // plugging hotplug block m, and memd copies its blocks into it.
    let hp_cn = g.arena.object_cap::<cap_type::CNode>(alloc, ObjectBlueprint::CNode { size_bits: abi::HP_L1_BITS });
    g.give_badged(abi::SLOT_HP, hp_cn, CapRights::all(), CNodeCapData::new(0, abi::HP_L1_GUARD).into_word());
    if !memd::guest_create(alloc, id, owned, block_cn, block_radix, hp_cn, hp_count) {
        return Err(Some(g));
    }
    g.nr_blocks = nr_blocks;
    for b in 0..nr_blocks.min(64) {
        if g.is_shared(b) {
            g.share_block(alloc, kernel, b);
        }
    }
    // ---- Hypercall endpoint (served by l4h-vmm).
    g.vmm_ep = g.arena.object_cap::<cap_type::Endpoint>(alloc, ObjectBlueprint::Endpoint);
    g.give_badged(
        abi::SLOT_HYP_EP,
        g.vmm_ep,
        sel4::CapRightsBuilder::none().write(true).grant_reply(true).build(),
        host::VMM_BADGE_HYPERCALL,
    );

    // ---- I/O pool: root's physically contiguous memory, whose frames we
    // map after RAM in the direct map.  The guest gets these mappings
    // only, never a capability to the pool.  And the VMM's notification,
    // which root's backends signal: root's too.
    let frame_bits = host::blk::pool_frame_bits(cfg.io_pool);
    let pool_radix = (cfg.io_pool.trailing_zeros() as usize - frame_bits).max(1);
    let new = match root::guest_new(alloc, id, cfg.io_pool, pool_gpa, cfg.dom0) {
        Ok(new) => new,
        Err(_) => return Err(Some(g)),
    };
    g.instance = new.instance;
    g.vmm_ntfn = new.vmm_ntfn;
    // The vCPUs' console output rings (in their event pages) are l4h-vmm's.
    g.give_badged(abi::SLOT_CONSOLE_KICK, g.vmm_ntfn, CapRights::write_only(), host::VMM_BADGE_CONSOLE);
    g.pool = IoPool { gpa: pool_gpa, size: cfg.io_pool, frames: new.pool_frames, radix: pool_radix };
    let tmp = alloc.slots.alloc();
    let keep = g.arena.object_cap::<cap_type::CNode>(alloc, ObjectBlueprint::CNode { size_bits: pool_radix });
    for i in 0..g.pool.pages() {
        abs(self_cap::<cap_type::Null>(tmp)).copy(&g.pool.frame(i), CapRights::all()).expect("pool frame copy");
        let frame = self_cap::<cap_type::Granule>(tmp);
        let vspace = g.vspace;
        let va = ram_base + pool_gpa + (i << frame_bits);
        if frame_bits == 21 {
            crate::vspace::map_large_page(&mut g.ctx(alloc), vspace, frame.cast(), va, CapRights::read_write());
        } else {
            map_frame(&mut g.ctx(alloc), vspace, frame, va, CapRights::read_write(), VmAttributes::DEFAULT);
        }
        keep.absolute_cptr_from_bits_with_depth(i as u64, pool_radix).move_(&abs(frame)).expect("keep pool mapping");
    }
    alloc.slots.free(tmp);


    // ---- VSpace pool for guest processes and device CNode.
    let pool_cn = g.arena.object_cap::<cap_type::CNode>(alloc, ObjectBlueprint::CNode { size_bits: abi::ROOT_CNODE_BITS });
    for i in 0..cfg.vspaces {
        let vs = g.arena.object_cap::<cap_type::VSpace>(alloc, PML4_BP);
        asids.assign(alloc, vs);
        g.vspaces.must_push(vs);
        pool_cn
            .absolute_cptr_from_bits_with_depth(i as u64, abi::ROOT_CNODE_BITS)
            .copy(&abs(vs), CapRights::all())
            .expect("vspace pool copy");
    }
    g.give_badged(abi::SLOT_VSPACE_POOL, pool_cn, CapRights::all(), guard6);
    g.dev_cn = g.arena.object_cap::<cap_type::CNode>(alloc, ObjectBlueprint::CNode { size_bits: abi::ROOT_CNODE_BITS });
    g.give_badged(abi::SLOT_DEV_CNODE, g.dev_cn, CapRights::all(), guard6);

    // ---- vCPUs.
    for v in 0..cfg.vcpus {
        let core = host_info.next_core();
        let mut ctx = ObjCtx::arena(alloc, &mut g.arena);
        let ktcb = ctx.cap::<cap_type::Tcb>(ObjectBlueprint::Tcb);
        let ep = ctx.cap::<cap_type::Endpoint>(ObjectBlueprint::Endpoint);
        let ntfn = ctx.cap::<cap_type::Notification>(ObjectBlueprint::Notification);
        let sc_bits = crate::sched::SC_BITS;
        let sc_k = ctx.cap::<cap_type::SchedContext>(ObjectBlueprint::SchedContext { size_bits: sc_bits });
        let sc_u = ctx.cap::<cap_type::SchedContext>(ObjectBlueprint::SchedContext { size_bits: sc_bits });
        let ipcbuf = ctx.cap::<cap_type::Granule>(FRAME_BP);
        let event = ctx.cap::<cap_type::Granule>(FRAME_BP);
        let vspace = g.vspace;
        map_frame(&mut ctx, vspace, ipcbuf, abi::vcpu_ipcbuf_va(v) as usize, CapRights::read_write(), VmAttributes::DEFAULT);
        map_frame(&mut ctx, vspace, event, abi::vcpu_event_va(v) as usize, CapRights::read_write(), VmAttributes::DEFAULT);

        let sched_control = host_info.sched_control(core);
        sched_control
            .sched_control_configure_flags(sc_k, host_info.timeslice_us, host_info.timeslice_us, 0, 0, 0)
            .expect("configure SC_K");
        sched_control
            .sched_control_configure_flags(sc_u, host_info.timeslice_us, host_info.timeslice_us, 0, 0, 0)
            .expect("configure SC_U");

        ktcb.tcb_configure(g.cnode, CNodeCapData::new(0, abi::ROOT_GUARD_BITS), g.vspace, abi::vcpu_ipcbuf_va(v), ipcbuf)
            .expect("kTCB configure");
        let fault_slot = alloc.slots.alloc();
        abs(self_cap::<cap_type::Null>(fault_slot))
            .mint(&abs(host_info.hyp_ep), CapRights::all(), hyp_badge(id, v) | HYP_BADGE_FAULT)
            .expect("fault ep");
        ktcb.tcb_set_sched_params(
            slot::TCB.cap(),
            abi::PRIO_KERNEL,
            abi::PRIO_KERNEL,
            sc_k,
            self_cap::<cap_type::Endpoint>(fault_slot),
        )
        .expect("kTCB sched params");
        ktcb.tcb_bind_notification(ntfn).expect("bind notification");

        let base = abi::slot_vcpu(v);
        g.give(base + abi::VCPU_KTCB, ktcb, CapRights::all());
        g.give(base + abi::VCPU_EP, ep, CapRights::all());
        g.give(base + abi::VCPU_NTFN, ntfn, CapRights::all());
        g.give(base + abi::VCPU_SC_U, sc_u, CapRights::all());
        g.give_badged(base + abi::VCPU_IPI, ntfn, CapRights::write_only(), abi::BADGE_IPI);
        g.give(base + abi::VCPU_IPCBUF, ipcbuf, CapRights::read_write());
        g.give(base + abi::VCPU_EVENT, event, CapRights::read_write());
        g.vcpus.must_push(Vcpu { ktcb, ntfn, event, sc_k, sc_u, core, cooldown: 0, usage: 0, k_share: crate::sched::K_SHARE_INIT, wall_ticks: 0, run_ticks: 0, steal_ns: 0 });
    }

    // ---- Event pages in vmmgr too (steal time).
    for v in 0..g.vcpus.len() {
        let ev = g.vcpus[v].event;
        g.map_in_self(alloc, ev, self_guest_va(id) + GUEST_EVENTS_OFF + v * PAGE);
    }

    // ---- Boot info frames (written at boot).
    for p in 0..(abi::BOOTINFO_SIZE as usize / PAGE) {
        let frame = g.arena.object_cap::<cap_type::Granule>(alloc, FRAME_BP);
        let vspace = g.vspace;
        map_frame(&mut g.ctx(alloc), vspace, frame, abi::BOOTINFO_VA as usize + p * PAGE, CapRights::read_only(), VmAttributes::DEFAULT);
        g.bootinfo.must_push(frame);
    }

    // ---- Console (input page, output ring) and, for dom0, control.
    g.add_device(alloc, DevKind::Console).unwrap();
    for i in 0..host::CONSOLE_RING_PAGES {
        let f = g.arena.object_cap::<cap_type::Granule>(alloc, FRAME_BP);
        let va = self_guest_va(id) + GUEST_RING_OFF + i * PAGE;
        g.map_in_self(alloc, f, va);
        g.console_ring.must_push(f);
    }
    if cfg.dom0 {
        let d = g.add_device(alloc, DevKind::Ctl).unwrap();
        // The failure service cannot allocate a notification after the
        // manager has failed. Keep this cap in the guest's tracked slots.
        let done = self_cap::<cap_type::Notification>(alloc.slots.alloc());
        abs(done).mint(&abs(g.vcpus[0].ntfn), CapRights::write_only(), abi::BADGE_EVENT).expect("control failure event");
        unsafe { crate::ctl_failure::register(g.id, g.ctl_page().unwrap(), g.event_page(0), dev_event(d), done.bits()) };
    }
    if hp_count != 0 {
        g.mem_dev = g.add_device(alloc, DevKind::Mem);
    }
    // ---- The attestation device, which trustd serves: root cleared its
    // page, and badged the kick for this guest.
    if let Some((page, kick)) = new.attest {
        g.attest = g.add_device_with(alloc, DevKind::Attest, page, (kick, 0)).is_some();
    }

    info!(
        "l4h-vmmgr: guest {} '{}' created: {} MiB RAM in {} blocks (and {} shared), {} vCPU(s), {} MiB I/O pool, {} KiB host objects",
        id, g.name, owned * BLOCK >> 20, owned, nr_blocks - owned, cfg.vcpus, g.pool.size >> 20, g.arena.bytes() >> 10
    );
    info!("l4h-vmmgr: guest {} '{}' initial CPUs {:?}", id, g.name, crate::sched::Cores(&g.vcpus));
    Ok(g)
}

/// Load the guest kernel into `g`, whose initrd (if any) is at `initrd`,
/// and write the boot info.  Only the initrd may have been loaded before:
/// the kernel is the host's.  Returns false if the parameters are bad or
/// the image does not fit.
pub fn boot(g: &mut Guest, alloc: &mut Alloc, win: &mut Window, host_info: &HostInfo, kernel: &Kernel, initrd: (usize, usize), cmdline: &[u8]) -> bool {
    let within = |(gpa, len): (usize, usize)| gpa >= initrd.0 && gpa + len <= initrd.0 + initrd.1;
    if g.ram_base != kernel.ram_base || (initrd.1 != 0 && initrd.0 < kernel.end) || !g.loaded.iter().all(within) {
        return false;
    }
    // Into every block but the shared ones, which already hold the image.
    for seg in kernel.elf.segments() {
        let gpa = seg.vaddr as usize - g.ram_base;
        let mut off = 0;
        while off < seg.data.len() {
            let n = (BLOCK - (gpa + off) % BLOCK).min(seg.data.len() - off);
            if !g.is_shared((gpa + off) / BLOCK) && !g.write_ram(alloc, win, gpa + off, &seg.data[off..off + n]) {
                return false;
            }
            off += n;
        }
    }
    g.write_boot_info(alloc, win, host_info, kernel.elf.entry, kernel.end, initrd, cmdline)
}

/// Boot the guest kernel with an initrd held by vmmgr (dom0's).
pub fn boot_with(g: &mut Guest, alloc: &mut Alloc, win: &mut Window, host_info: &HostInfo, kernel: &Kernel, initrd: &[u8], cmdline: &[u8]) -> bool {
    let initrd_gpa = kernel.initrd_gpa();
    if !initrd.is_empty() && !g.write_ram(alloc, win, initrd_gpa, initrd) {
        return false;
    }
    boot(g, alloc, win, host_info, kernel, (initrd_gpa, initrd.len()), cmdline)
}

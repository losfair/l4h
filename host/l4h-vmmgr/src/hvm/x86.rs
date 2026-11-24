//! HVM guests on an x86_64 kernel with VT-x support (hvm.rs).

use core::ptr;

use sel4::{CNodeCapData, CapRights, ObjectBlueprint, VmAttributes, cap, cap_type};

use l4h_abi as abi;
use l4h_host as host;
use l4h_host::errno::Errno;
use l4h_host::fixed::{ArrayVec, Scratch};
use l4h_host::hvm as hv;
use l4h_host::wiring::{self, o, p};
use l4h_task::edge::{Obj, mint as mint_edge};

use crate::component::{self, Component, SpawnArgs};
use crate::ctl;
use crate::guest::{self, DevKind, Guest, GuestConfig, GuestDev, State, Vcpu, abs, self_cap, try_cnode, BLOCK};
use crate::layout;
use crate::mem::{Alloc, Dest, ObjCtx, UtRegion};
use crate::vmm::Backend;
use crate::vspace::{FRAME_BP, ensure_large_page_tables, map_frame, map_large_page};
use crate::{AsidPools, HostInfo, memd, root, slot};

static HVM_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/l4h-hvm.elf"));

const PAGE: usize = 4096;
const GIB: usize = 1 << 30;

const LARGE_PAGE_BP: ObjectBlueprint = crate::vspace::LARGE_PAGE_BP;
const VCPU_BP: ObjectBlueprint = ObjectBlueprint::Arch(sel4::ObjectBlueprintX86::VCpu);
const EPT_PD_BP: ObjectBlueprint = ObjectBlueprint::Arch(sel4::ObjectBlueprintX86::EPTPageDirectory);
const EPT_PML4_BP: ObjectBlueprint = ObjectBlueprint::Arch(sel4::ObjectBlueprintX86::SeL4Arch(sel4::ObjectBlueprintX64::EPTPML4));
const EPT_PDPT_BP: ObjectBlueprint = ObjectBlueprint::Arch(sel4::ObjectBlueprintX86::SeL4Arch(sel4::ObjectBlueprintX64::EPTPDPT));

/// Whether HVM guests can be made here: VT-x or AMD-V, and an l4h-hvm.
pub fn available(host_info: &HostInfo) -> bool {
    host_info.vtx && !HVM_ELF.is_empty()
}

/// What an HVM guest has besides a guest's (guest.rs).
pub struct Hvm {
    /// RAM below the 32-bit hole and above 4 GiB, in bytes.
    pub low_ram: usize,
    pub high_ram: usize,
    /// Its EPT root (an EPT PML4, with an ASID).
    ept: cap::EPTPML4,
    /// memd's block CNode (radix `block_radix`): the Untyped of block b at
    /// b, from boot (Guest::boot_blocks) on; below it, those of the blocks
    /// vmmgr filled, which it parks there.
    block_cn: cap::CNode,
    block_radix: usize,
    /// The 2 MiB frames of the blocks, as mapped in the EPT and in l4h-hvm.
    keep_ept: cap::CNode,
    keep_hvm: cap::CNode,
    /// l4h-hvm's CNode, and the CNodes of its mapping capabilities: of the
    /// I/O pool's frames, and of the other shared pages.
    cspace: cap::CNode,
    keep_pool: cap::CNode,
    pool_radix: usize,
    keep_small: cap::CNode,
    /// The vCPUs' VCPU objects.
    vcpu_objs: ArrayVec<cap::VCpu, { hv::MAX_VCPUS }>,
    /// What CTL_VM_START gave, for l4h-hvm's configuration.
    boot: Option<Boot>,
}

struct Boot {
    kernel: (u64, u64),
    initrd: (u64, u64),
    flags: u64,
    cmdline: [u8; abi::CMDLINE_SIZE],
}

impl Hvm {
    /// The guest-physical address of RAM block `b`.
    fn block_gpa(&self, b: usize) -> usize {
        hv::ram_gpa(self.low_ram as u64, (b * BLOCK) as u64) as usize
    }

    /// The RAM block holding guest-physical address `gpa`, which is RAM.
    fn block_of(&self, gpa: usize) -> usize {
        let off = if gpa < self.low_ram { gpa } else { gpa - hv::HIGH_RAM_BASE as usize + self.low_ram };
        off / BLOCK
    }

    fn is_ram(&self, gpa: usize, len: usize) -> bool {
        hv::is_ram(self.low_ram as u64, self.high_ram as u64, gpa as u64, len as u64)
    }

    /// Each GiB of guest-physical space that holds RAM: an EPT page
    /// directory, and one of l4h-hvm's, cover it.
    fn ram_gibs(&self) -> impl Iterator<Item = usize> {
        let low = 0..self.low_ram.div_ceil(GIB);
        let high = hv::HIGH_RAM_BASE as usize / GIB..(hv::HIGH_RAM_BASE as usize + self.high_ram).div_ceil(GIB);
        low.chain(if self.high_ram == 0 { 0..0 } else { high })
    }

    fn keep(cnode: cap::CNode, radix: usize, i: usize) -> sel4::AbsoluteCPtr {
        cnode.absolute_cptr_from_bits_with_depth(i as u64, radix)
    }
}

/// What a guest of `cfg` takes, checked before anything is made: bytes of
/// its arena and vmmgr's slots, and its blocks.  None for a configuration
/// the control API cannot have.
pub struct Plan {
    pub blocks: usize,
    pub radix: usize,
    pub estimate: usize,
    pub slots: usize,
}

pub fn plan(cfg: &GuestConfig) -> Option<Plan> {
    let ram = cfg.ram as u64;
    if cfg.vcpus < 1 || cfg.vcpus > hv::MAX_VCPUS || !(hv::RAM_MIN..=hv::RAM_MAX).contains(&ram) || cfg.dom0 {
        return None;
    }
    if !cfg.io_pool.is_power_of_two() || !(guest::IO_POOL_MIN..=guest::IO_POOL_MAX).contains(&cfg.io_pool) {
        return None;
    }
    let blocks = cfg.ram.div_ceil(BLOCK);
    let radix = (blocks.next_power_of_two().trailing_zeros() as usize).max(1);
    let gibs = (blocks * BLOCK).div_ceil(GIB) + 1;
    let pool_pages = cfg.io_pool / PAGE;
    // Its CNodes (l4h-hvm's, its mapping CNodes, the two of the blocks'
    // frames), the EPT, the vCPUs' objects (TCB, SC, notification, VCPU,
    // event page: a VCPU is 32 KiB at most, on FL4), the console and its
    // ring, and l4h-hvm itself (start_bytes, reserved at start).
    let estimate = 2 * (32 << host::CNODE_BITS) + 32 * pool_pages.max(2) + 2 * (32 << radix)
        + (2 + gibs) * PAGE
        + cfg.vcpus * (64 << 10)
        + (2 + host::CONSOLE_RING_PAGES) * PAGE
        + vmm_like_bytes(cfg.io_pool);
    let slots = 64 + cfg.vcpus * 8 + gibs + 16;
    Some(Plan { blocks, radix, estimate, slots })
}

/// l4h-hvm's own host memory besides what plan counts, as a VMM's
/// (vmm::arena_bytes): reserved at start, counted at creation.
fn vmm_like_bytes(io_pool: usize) -> usize {
    crate::vmm::arena_bytes(io_pool, 1, hv::MAX_DEVICES)
}

/// Create an HVM guest with no image (guest::create's counterpart).  On
/// failure, the partly built guest, if there is one, for the caller to
/// destroy.  (A Guest, as guest::create returns it.)
#[allow(clippy::result_large_err)]
pub fn create(
    id: usize,
    cfg: &GuestConfig,
    alloc: &mut Alloc,
    asids: &mut AsidPools,
    host_info: &HostInfo,
    cores: &[(usize, usize)],
) -> Result<Guest, Option<Guest>> {
    let Some(Plan { blocks, radix, estimate, .. }) = plan(cfg) else { return Err(None) };
    if !available(host_info) || alloc.free_bytes() < estimate + (blocks + 1) * BLOCK {
        return Err(None);
    }
    let arena = alloc.arena(estimate).ok_or(None)?;
    let mut g = Guest::blank(id, cfg.name, arena, cap::CNode::from_bits(0), cap::VSpace::from_bits(0), 0, 0,
        hv::IO_POOL_GPA as usize, false, 0, 0);
    let ram = blocks * BLOCK;
    let low_ram = hv::low_ram(ram as u64) as usize;

    // ---- The EPT root, its PDPT and a directory for each GiB of RAM.
    let Some(ept_slot) = g.arena.try_object(alloc, EPT_PML4_BP) else { return Err(Some(g)) };
    asids.assign(alloc, self_cap::<cap_type::VSpace>(ept_slot));
    let ept = self_cap::<cap_type::EPTPML4>(ept_slot);

    // ---- CNodes: l4h-hvm's, its mapping CNodes, and the blocks' frames.
    let pool_radix = (cfg.io_pool / PAGE).trailing_zeros() as usize;
    let cnodes = [host::CNODE_BITS, pool_radix, host::CNODE_BITS, radix, radix]
        .map(|bits| try_cnode(&mut g.arena, alloc, bits));
    let [Some(cspace), Some(keep_pool), Some(keep_small), Some(keep_ept), Some(keep_hvm)] = cnodes else {
        return Err(Some(g));
    };
    let mut h = Hvm {
        low_ram, high_ram: ram - low_ram, ept, block_cn: cap::CNode::from_bits(0), block_radix: radix,
        keep_ept, keep_hvm, cspace, keep_pool, pool_radix, keep_small, vcpu_objs: ArrayVec::new(), boot: None,
    };
    let Some(pdpt) = g.arena.try_object(alloc, EPT_PDPT_BP) else { return Err(Some(g)) };
    self_cap::<cap_type::EPTPDPT>(pdpt).eptpdpt_map(ept, 0, VmAttributes::EPT_DEFAULT).expect("EPT PDPT");
    for gib in h.ram_gibs() {
        let Some(pd) = g.arena.try_object(alloc, EPT_PD_BP) else { return Err(Some(g)) };
        self_cap::<cap_type::EPTPageDirectory>(pd).ept_page_directory_map(ept, gib * GIB, VmAttributes::EPT_DEFAULT)
            .expect("EPT page directory");
    }

    // ---- RAM: memd's blocks.  Its block CNode, and a hotplug CNode, which
    // an HVM guest does not use.
    let slots = [alloc.slots.alloc(), alloc.slots.alloc()];
    if !memd::guest_create(alloc, id, blocks, radix, 0, slots) {
        for s in slots {
            let _ = abs(self_cap::<cap_type::Null>(s)).delete();
            alloc.slots.free(s);
        }
        g.hvm = Some(h);
        return Err(Some(g));
    }
    h.block_cn = self_cap::<cap_type::CNode>(slots[0]);
    g.nr_blocks = blocks;

    // ---- The I/O pool and the notification of the guest's VMM, which
    // root makes: l4h-hvm binds it.
    let new = match root::guest_new(alloc, id, cfg.io_pool, hv::IO_POOL_GPA as usize, false) {
        Ok(new) => new,
        Err(_) => {
            g.hvm = Some(h);
            return Err(Some(g));
        }
    };
    g.instance = new.instance;
    g.vmm_ntfn = new.vmm_ntfn;
    g.pool = guest::IoPool { gpa: hv::IO_POOL_GPA as usize, size: cfg.io_pool, frames: new.pool_frames, radix: pool_radix };
    // An HVM guest has no attestation device: root's page and kick, if it
    // made them, stay unused in our slots until destroy.

    // ---- vCPUs: a thread of l4h-hvm each, which spawn configures; its
    // VCPU, scheduling context, bound notification and event page.
    for &(core, vcore) in cores.iter().take(cfg.vcpus) {
        let mut ctx = ObjCtx::arena(alloc, &mut g.arena);
        let ktcb = ctx.cap::<cap_type::Tcb>(ObjectBlueprint::Tcb);
        let ntfn = ctx.cap::<cap_type::Notification>(ObjectBlueprint::Notification);
        let sc_k = ctx.cap::<cap_type::SchedContext>(ObjectBlueprint::SchedContext { size_bits: host::GUEST_SC_BITS });
        let vcpu = ctx.cap::<cap_type::VCpu>(VCPU_BP);
        let event = ctx.cap::<cap_type::Granule>(FRAME_BP);
        host_info.sched_control(core)
            .sched_control_configure_flags(sc_k, crate::sched::guest_timeslice(host_info), crate::sched::guest_timeslice(host_info), 0, 0, 0)
            .expect("configure SC_K");
        h.vcpu_objs.must_push(vcpu);
        g.vcpus.must_push(Vcpu { ktcb, ntfn, event, sc_k, sc_u: None, core, vcore, host_cap: 1024, cooldown: 0, usage: 0,
            k_share: crate::sched::K_SHARE_INIT, wall_ticks: 0, run_ticks: 0, steal_ns: 0 });
    }
    for v in 0..g.vcpus.len() {
        let ev = g.vcpus[v].event;
        g.map_in_self(alloc, ev, guest::self_guest_va(id) + guest::GUEST_EVENTS_OFF + v * PAGE);
        unsafe { ptr::addr_of_mut!((*g.event_page(v)).host_cap).write_volatile(1024) };
    }
    g.hvm = Some(h);

    // ---- The console: its page (input and power requests) and ring.
    if add_device(&mut g, alloc, DevKind::Console).is_none() {
        return Err(Some(g));
    }
    for i in 0..host::CONSOLE_RING_PAGES {
        let f = g.arena.object_cap::<cap_type::Granule>(alloc, FRAME_BP);
        g.map_in_self(alloc, f, guest::self_guest_va(id) + guest::GUEST_RING_OFF + i * PAGE);
        g.console_ring.must_push(f);
    }
    info!(
        "l4h-vmmgr: guest {} '{}' created (HVM): {} MiB RAM in {} blocks, {} vCPU(s), {} MiB I/O pool, {} KiB host objects",
        id, g.name, ram >> 20, blocks, cfg.vcpus, cfg.io_pool >> 20, g.arena.bytes() >> 10
    );
    info!("l4h-vmmgr: guest {} '{}' initial CPUs {:?}", id, g.name, crate::sched::Cores(&g.vcpus));
    Ok(g)
}

/// Add a device to an HVM guest (Guest::add_device): a page for the
/// console, whose input and power requests vmmgr writes there and
/// l4h-hvm reads; nothing for a PCI device, which l4h-hvm models itself.
/// The caller reserved guest::DEVICE_BYTES.
pub fn add_device(g: &mut Guest, alloc: &mut Alloc, kind: DevKind) -> Option<usize> {
    let d = g.devices.len();
    if d > hv::MAX_DEVICES || g.state != State::Created {
        return None;
    }
    let page = match kind {
        DevKind::Console => {
            let page = g.arena.object_cap::<cap_type::Granule>(alloc, FRAME_BP);
            g.map_in_self(alloc, page, guest::self_guest_va(g.id) + PAGE);
            page
        }
        DevKind::Virtio(1 | 2) => cap::Granule::from_bits(0),
        _ => return None,
    };
    g.devices.must_push(GuestDev { kind, page });
    Some(d)
}

/// The RAM block's frames, made and mapped in the EPT if they are not
/// yet: block `b` becomes a boot block, which l4h-hvm finds mapped.
/// False if memd has failed.
fn fill_block(g: &mut Guest, alloc: &mut Alloc, b: usize) -> bool {
    if g.is_filled(b) {
        return true;
    }
    let h = g.hvm.as_ref().expect("HVM guest");
    let ut = alloc.slots.alloc();
    let Some(paddr) = memd::guest_copy(alloc, g.id, b, ut) else {
        alloc.slots.free(ut);
        return false;
    };
    let f = alloc.slots.alloc();
    UtRegion::fresh(self_cap::<cap_type::Untyped>(ut), paddr, abi::BLOCK_SHIFT)
        .retype(&LARGE_PAGE_BP, 1, Dest::new(slot::CNODE.cap(), f))
        .expect("RAM block frame");
    let frame = self_cap::<cap_type::LargePage>(f);
    frame.ept_frame_map(h.ept, h.block_gpa(b), CapRights::read_write(), VmAttributes::EPT_DEFAULT).expect("EPT map");
    Hvm::keep(h.keep_hvm, h.block_radix, b).copy(&abs(frame), CapRights::read_write()).expect("block frame copy");
    Hvm::keep(h.keep_ept, h.block_radix, b).move_(&abs(frame)).expect("keep block frame");
    // memd gives the guest no block below the boot blocks: the slot of
    // this block's Untyped is free, and holds it, as memd revokes it.
    Hvm::keep(h.block_cn, h.block_radix, b).move_(&abs(self_cap::<cap_type::Null>(ut))).expect("park block Untyped");
    alloc.slots.free(f);
    alloc.slots.free(ut);
    g.filled[b / 64] |= 1 << (b % 64);
    true
}

/// What loading [gpa, gpa + len) costs, in bytes and slots: frames come
/// from the guest's own blocks, and the window's tables are vmmgr's.  None
/// for a range or state that load_ram refuses.
pub fn load_cost(g: &Guest, gpa: usize, len: usize) -> Option<(usize, usize)> {
    let h = g.hvm.as_ref()?;
    if g.state != State::Created || g.vmm.is_some() || g.boot_blocks != 0 || !h.is_ram(gpa, len) {
        return None;
    }
    Some((2 * PAGE, 4))
}

/// Copy `len` bytes from `from` (vmmgr's memory) into guest RAM at `gpa`
/// (VM_LOAD), filling the blocks it touches.
pub fn load_ram(g: &mut Guest, alloc: &mut Alloc, gpa: usize, from: *const u8, len: usize) -> bool {
    if load_cost(g, gpa, len).is_none() {
        return false;
    }
    let mut off = 0;
    while off < len {
        let at = gpa + off;
        let h = g.hvm.as_ref().unwrap();
        let b = h.block_of(at);
        let in_block = at - h.block_gpa(b);
        let n = (BLOCK - in_block).min(len - off);
        if !fill_block(g, alloc, b) {
            return false;
        }
        let h = g.hvm.as_ref().unwrap();
        with_block(alloc, &Hvm::keep(h.keep_ept, h.block_radix, b), |p| unsafe {
            ptr::copy_nonoverlapping(from.add(off), p.add(in_block), n);
        });
        off += n;
    }
    true
}

/// Map a copy of the 2 MiB frame `frame` at vmmgr's large window and run
/// `f` on its contents.
fn with_block<R>(alloc: &mut Alloc, frame: &sel4::AbsoluteCPtr, f: impl FnOnce(*mut u8) -> R) -> R {
    let s = alloc.slots.alloc();
    abs(self_cap::<cap_type::Null>(s)).copy(frame, CapRights::read_write()).expect("window copy");
    let page = self_cap::<cap_type::LargePage>(s);
    // The window's tables are vmmgr's, made once.
    alloc.global(|alloc| {
        map_large_page(&mut ObjCtx::global(alloc), slot::VSPACE.cap(), page, layout::LARGE_WINDOW.base, CapRights::read_write());
    });
    let r = f(layout::LARGE_WINDOW.base as *mut u8);
    page.frame_unmap().expect("window unmap");
    abs(page).delete().expect("window delete");
    alloc.slots.free(s);
    r
}

/// Boot an HVM guest (CTL_VM_START): its kernel at `kernel`, its initrd at
/// `initrd`, both (gpa, len) in its RAM, with `flags` (abi::HVM_BOOT_*)
/// and `cmdline`.  Fills block 0 and every block up to the last one
/// loaded, and memd gives l4h-hvm the others.  Nothing changes for a
/// start refused for its parameters.
pub fn boot(g: &mut Guest, alloc: &mut Alloc, kernel: (u64, u64), initrd: (u64, u64), flags: u64, cmdline: &[u8]) -> Result<(), Errno> {
    {
        let Some(h) = g.hvm.as_ref() else { return Err(ctl::EINVAL) };
        if g.state != State::Created || g.vmm.is_some() || g.boot_blocks != 0 || h.boot.is_some() {
            return Err(ctl::EBUSY);
        }
        let ram = |(gpa, len): (u64, u64)| usize::try_from(gpa).ok().zip(usize::try_from(len).ok())
            .is_some_and(|(gpa, len)| h.is_ram(gpa, len));
        if flags & !abi::HVM_BOOT_FLAGS != 0 || kernel.1 == 0 || !ram(kernel) || (initrd.1 != 0 && !ram(initrd)) {
            return Err(ctl::EINVAL);
        }
    }
    let boot = (0..g.nr_blocks).rev().find(|&b| g.is_filled(b)).map_or(1, |b| b + 1);
    for b in 0..boot {
        if !fill_block(g, alloc, b) {
            return Err(ctl::EIO);
        }
    }
    if !memd::guest_give(alloc, g.id, boot, 0) {
        return Err(ctl::EIO);
    }
    g.boot_blocks = boot;
    let n = cmdline.iter().position(|&c| c == 0).unwrap_or(cmdline.len()).min(abi::CMDLINE_SIZE - 1);
    let mut line = [0; abi::CMDLINE_SIZE];
    line[..n].copy_from_slice(&cmdline[..n]);
    g.hvm.as_mut().unwrap().boot = Some(Boot { kernel, initrd, flags, cmdline: line });
    Ok(())
}

/// Host memory spawning l4h-hvm takes (Guest::start_bytes): its image,
/// stacks and mappings, the vCPU threads' stacks, TLS and IPC buffers,
/// and the tables of its RAM's mapping.
pub fn start_bytes(g: &Guest) -> usize {
    let h = g.hvm.as_ref().expect("HVM guest");
    let image = l4h_task::elf::Elf::parse(HVM_ELF).map_or(4 << 20, |e| {
        e.segments().map(|s| (s.memsz as usize).next_multiple_of(PAGE) + PAGE).sum::<usize>()
    });
    let vcpu = (hv::VCPU_STACK_SIZE + hv::VCPU_TLS_SIZE + PAGE) + host::map_tables(1);
    image + host::map_tables(image / PAGE) + host::VMM_STACK_SIZE + (1 << 20)
        + g.vcpus.len() * vcpu
        + (h.ram_gibs().count() + 2) * PAGE
        + g.pool.size / 512 + 4 * PAGE
        + (g.vcpus.len() + g.devices.len() * 16 + host::CONSOLE_RING_PAGES + 1) * 2 * PAGE
}

/// vmmgr slots spawning l4h-hvm takes at most: one for each object it
/// makes in the guest's arena (frames of the image, the stacks, TLS and
/// IPC buffers; page tables), none smaller than a page but for the
/// component's own few (TCB, SC, CNode, notification, endpoint, info and
/// IPC pages), and the temporary ones (fault endpoint, scratch frame).
/// The copies it maps (I/O pool, shared pages, RAM blocks) go to the keep
/// CNodes made at creation, not to vmmgr's slots.
pub fn start_slots(g: &Guest) -> usize {
    start_bytes(g) / PAGE + 64
}

/// l4h-hvm's configuration under construction.
static CONFIG: Scratch<core::mem::MaybeUninit<hv::HvmConfig>> = Scratch::new(core::mem::MaybeUninit::zeroed());

/// Create the guest's l4h-hvm (not started), with its vCPU threads,
/// after boot.
pub fn spawn(
    g: &mut Guest,
    alloc: &mut Alloc,
    win: &mut crate::window::Window,
    asids: &mut AsidPools,
    host_info: &HostInfo,
    limits: crate::sched::budget::Plan,
) -> sel4::Result<Component> {
    let comp = CONFIG.with(|cfg| {
        *cfg = core::mem::MaybeUninit::zeroed();
        let cfg = unsafe { cfg.assume_init_mut() };
        configure(g, cfg, host_info);
        let bytes = unsafe {
            core::slice::from_raw_parts(cfg as *const hv::HvmConfig as *const u8, core::mem::size_of::<hv::HvmConfig>())
        };
        // sched::prepare_vmm's choice (hvm_monitor_core).
        let core = g.vmm_limits.map_or(g.vcpus[0].core, |(core, _)| core);
        let args = SpawnArgs {
            id: g.id as u32,
            kind: host::KIND_HVM,
            elf: HVM_ELF,
            prio: hv::PRIO_IO,
            budget_us: limits.vmm,
            period_us: limits.vmm_period,
            config: bytes,
            ntfn: Some(g.vmm_ntfn),
            service_ep: None,
            cnode: Some(g.hvm.as_ref().unwrap().cspace),
            cnode_bits: None,
        };
        component::try_create(&args, alloc, &mut g.arena, win, &mut |alloc, vspace| asids.assign(alloc, vspace),
            &host_info.spawn_context(core))
    })?;
    // Its threads raise no priority above a guest kernel's.
    comp.tcb.tcb_set_mc_priority(slot::TCB.cap(), hv::MCP)?;
    map(g, &comp, alloc);
    vcpus(g, &comp, alloc, host_info)?;
    // It cannot audit itself (its MCP is below the debug syscalls'): we do,
    // everything given, before it runs.
    comp.audit_cspace();
    Ok(comp)
}

/// Write l4h-hvm's configuration.
fn configure(g: &Guest, cfg: &mut hv::HvmConfig, host_info: &HostInfo) {
    let h = g.hvm.as_ref().expect("HVM guest");
    let boot = h.boot.as_ref().expect("HVM guest booted");
    cfg.guest_id = g.id as u32;
    cfg.nr_vcpus = g.vcpus.len() as u32;
    cfg.low_ram = h.low_ram as u64;
    cfg.high_ram = h.high_ram as u64;
    cfg.boot_blocks = g.boot_blocks as u32;
    cfg.block_radix = h.block_radix as u32;
    cfg.io_pool_gpa = g.pool.gpa as u64;
    cfg.io_pool_size = g.pool.size as u64;
    (cfg.kernel_gpa, cfg.kernel_size) = boot.kernel;
    (cfg.initrd_gpa, cfg.initrd_size) = boot.initrd;
    cfg.boot_flags = boot.flags;
    [cfg.epoch_ns, cfg.epoch_ticks] = host_info.clock_anchor;
    cfg.serial = 1;
    cfg.cmdline = boot.cmdline;
    let mut n = 0;
    for (d, b) in g.backends.iter() {
        let d = *d;
        let dev = &mut cfg.devices[n];
        dev.guest_index = d as u32;
        match b {
            Backend::UnavailableBlk => dev.kind = host::VDEV_BLK_UNAVAILABLE,
            Backend::Blk { chan, .. } => {
                dev.kind = host::VDEV_BLK;
                dev.chan_va = host::vmm_chan_va(d) as u64;
                dev.chan_size = (chan.len() * PAGE) as u64;
                dev.chan_kick_slot = wiring::HVM_BLKD_KICK.slot(d);
            }
            Backend::Net { mac, .. } => {
                dev.kind = host::VDEV_NET;
                dev.chan_va = host::vmm_chan_va(d) as u64;
                dev.chan_size = (host::net::PORT_PAGES * PAGE) as u64;
                dev.chan_kick_slot = wiring::HVM_NETD_KICK.slot(d);
                dev.mac[..6].copy_from_slice(mac);
            }
            // add_device refuses the others.
            _ => continue,
        }
        n += 1;
    }
    cfg.nr_devices = n as u32;
}

/// Map the pool, the console, event and channel pages, and the boot blocks,
/// into l4h-hvm, and give it its capabilities.
fn map(g: &mut Guest, comp: &Component, alloc: &mut Alloc) {
    let attrs = VmAttributes::DEFAULT;
    let rw = CapRights::read_write();
    let (keep_pool, pool_radix, keep_small) = {
        let h = g.hvm.as_ref().unwrap();
        (h.keep_pool, h.pool_radix, h.keep_small)
    };
    // ---- The I/O pool, where disk data bounces.
    for i in 0..g.pool.pages() {
        let frame = g.pool.frame(i);
        comp.map_copy(alloc, &mut g.arena, &frame, hv::IO_POOL_VA + i * PAGE, rw.clone(), attrs, Hvm::keep(keep_pool, pool_radix, i));
    }
    // ---- Event pages (idle time, for steal), the console page and ring.
    let mut small_next = 0;
    let mut keep_slot = || {
        let s = Hvm::keep(keep_small, host::CNODE_BITS, small_next);
        small_next += 1;
        s
    };
    for v in 0..g.vcpus.len() {
        let ev = abs(g.vcpus[v].event);
        comp.map_copy(alloc, &mut g.arena, &ev, host::vmm_event_page_va(v), rw.clone(), attrs, keep_slot());
    }
    let console = g.devices.iter().find(|d| d.kind == DevKind::Console).expect("console").page;
    comp.map_copy(alloc, &mut g.arena, &abs(console), hv::CONSOLE_PAGE_VA, rw.clone(), attrs, keep_slot());
    for (i, f) in g.console_ring.iter().enumerate() {
        let f = abs(*f);
        comp.map_copy(alloc, &mut g.arena, &f, host::VMM_CONSOLE_RING_VA + i * PAGE, rw.clone(), attrs, keep_slot());
    }
    // ---- Backends: disk channels and netd ports, and their kicks.
    let backends = core::mem::take(&mut g.backends);
    for &(d, ref b) in backends.iter() {
        match b {
            Backend::Blk { chan, kick } => {
                for (i, f) in chan.iter().enumerate() {
                    let fc = abs(*f);
                    comp.map_copy(alloc, &mut g.arena, &fc, host::vmm_chan_va(d) + i * PAGE, rw.clone(), attrs, keep_slot());
                }
                comp.pass_edge(&wiring::HVM_BLKD_KICK, d, *kick);
            }
            Backend::Net { chan, kick, keep, .. } => {
                for i in 0..host::net::PORT_PAGES {
                    let fc = chan.absolute_cptr_from_bits_with_depth(i as u64, l4h_host::vmmgr::PORT_RADIX);
                    let dst = keep.absolute_cptr_from_bits_with_depth(i as u64, l4h_host::vmmgr::PORT_RADIX);
                    comp.map_copy(alloc, &mut g.arena, &fc, host::vmm_chan_va(d) + i * PAGE, rw.clone(), attrs, dst);
                }
                comp.pass_edge(&wiring::HVM_NETD_KICK, d, *kick);
            }
            _ => {}
        }
    }
    g.backends = backends;

    // ---- Guest RAM: a directory for each GiB of it (l4h-hvm maps 2 MiB
    // frames into them itself), and the boot blocks.
    let h = g.hvm.as_ref().unwrap();
    let gibs: ArrayVec<usize, 80> = h.ram_gibs().collect();
    for &gib in gibs.iter() {
        ensure_large_page_tables(&mut ObjCtx::arena(alloc, &mut g.arena), comp.vspace, hv::RAM_VA + gib * GIB);
    }
    let tmp = alloc.slots.alloc();
    for b in 0..g.boot_blocks {
        let h = g.hvm.as_ref().unwrap();
        let keep = Hvm::keep(h.keep_hvm, h.block_radix, b);
        abs(self_cap::<cap_type::Null>(tmp)).move_(&keep).expect("boot block frame");
        let frame = self_cap::<cap_type::LargePage>(tmp);
        let va = hv::RAM_VA + h.block_gpa(b);
        map_large_page(&mut ObjCtx::arena(alloc, &mut g.arena), comp.vspace, frame, va, rw.clone());
        keep.move_(&abs(frame)).expect("boot block frame back");
    }
    alloc.slots.free(tmp);

    // ---- Its capabilities: the EPT root, the CNodes it maps blocks with,
    // and the signals and calls of its threads to its I/O thread.
    let h = g.hvm.as_ref().unwrap();
    comp.give(hv::SLOT_EPT, h.ept, CapRights::all());
    let none = CNodeCapData::new(0, 0);
    comp.give_cnode(hv::SLOT_BLOCKS, h.block_cn, none.clone());
    comp.give_cnode(hv::SLOT_KEEP_EPT, h.keep_ept, none.clone());
    comp.give_cnode(hv::SLOT_KEEP_HVM, h.keep_hvm, none);
    let own = Obj::claim(p::Hvm, o::Notification, abs(g.vmm_ntfn));
    comp.give_edge(&wiring::HVM_KICK, 0, 0, &own);
    comp.give_edge(&wiring::HVM_CONSOLE, 0, 0, &own);
    comp.give_edge(&wiring::HVM_CALL, 0, 0, &comp.obj::<p::Hvm, o::Endpoint>());
}

/// Set up l4h-hvm's vCPU threads (suspended: l4h-hvm starts them) and give
/// it their capabilities.
fn vcpus(g: &mut Guest, comp: &Component, alloc: &mut Alloc, host_info: &HostInfo) -> sel4::Result<()> {
    let ept = g.hvm.as_ref().unwrap().ept;
    let guard = CNodeCapData::new(0, 64 - host::CNODE_BITS);
    for v in 0..g.vcpus.len() {
        let (ktcb, ntfn, sc_k) = (g.vcpus[v].ktcb, g.vcpus[v].ntfn, g.vcpus[v].sc_k);
        let vcpu = g.hvm.as_ref().unwrap().vcpu_objs[v];
        // Stack (a guard page below it), TLS and IPC buffer: fresh frames.
        let mut ipcbuf = cap::Granule::from_bits(0);
        let stack = hv::vcpu_stack_top(v) - hv::VCPU_STACK_SIZE;
        for va in (stack..hv::vcpu_ipcbuf_va(v) + PAGE).step_by(PAGE) {
            let mut ctx = ObjCtx::arena(alloc, &mut g.arena);
            let f = ctx.cap::<cap_type::Granule>(FRAME_BP);
            map_frame(&mut ctx, comp.vspace, f, va, CapRights::read_write(), VmAttributes::DEFAULT);
            ipcbuf = f;
        }
        ktcb.tcb_configure(comp.cnode, guard.clone(), comp.vspace, hv::vcpu_ipcbuf_va(v) as u64, ipcbuf)?;
        // Its faults are its l4h-hvm's, which stop the guest.
        let fault = alloc.slots.alloc();
        mint_edge(&abs(self_cap::<cap_type::Null>(fault)), &wiring::HVM_FAULT, g.id,
            &Obj::claim(p::Vmmgr, o::Endpoint, abs(host_info.hyp_ep)))?;
        let r = ktcb.tcb_set_sched_params(slot::TCB.cap(), hv::MCP, abi::PRIO_KERNEL, sc_k, self_cap::<cap_type::Endpoint>(fault));
        let _ = abs(self_cap::<cap_type::Null>(fault)).delete();
        alloc.slots.free(fault);
        r?;
        ktcb.tcb_bind_notification(ntfn)?;
        vcpu.vcpu_set_tcb(ktcb)?;
        ktcb.tcb_set_ept_root(ept)?;
        comp.give(hv::SLOT_VCPU_TCB + v as u64, ktcb, CapRights::all());
        comp.give(hv::SLOT_VCPU_OBJ + v as u64, vcpu, CapRights::all());
        comp.give(hv::SLOT_VCPU_WAIT + v as u64, ntfn, CapRights::all());
        comp.give_edge(&wiring::HVM_VCPU, v, 0, &Obj::claim(p::Hvm, o::Vcpu, abs(ntfn)));
    }
    Ok(())
}

/// Tell the guest's l4h-hvm to look at its console page (wiring::VMMGR_HVM).
pub fn signal(g: &Guest, alloc: &mut Alloc) {
    if g.vmm.is_none() {
        return;
    }
    let s = alloc.slots.alloc();
    let badged = self_cap::<cap_type::Notification>(s);
    mint_edge(&abs(badged), &wiring::VMMGR_HVM, 0, &Obj::claim(p::Hvm, o::Notification, abs(g.vmm_ntfn))).expect("HVM signal cap");
    badged.signal();
    abs(badged).delete().expect("delete HVM signal cap");
    alloc.slots.free(s);
}

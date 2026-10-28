//! l4h-vmmgr, the guest manager (DESIGN.md §9.3): spawning it with what it
//! needs, and serving its calls (l4h_host::vmmgr).
//!
//! vmmgr builds and runs the guests.  Root keeps what devices reach: each
//! guest's I/O pool, disk channels and netd ports, made here when vmmgr
//! asks (`RootGuest`), and taken back when it is done with the guest.  The
//! addresses root gives the IOMMU, blkd and netd are all its own: vmmgr
//! passes guest ids, disk numbers, windows and sizes.

use core::sync::atomic::Ordering;

use sel4::{CapRights, ObjectBlueprint, VmAttributes, cap, cap_type};

use l4h_abi as abi;
use l4h_host as host;
use l4h_host::fixed::ArrayVec;
use l4h_host::vmmgr::{self as proto, VmmgrConfig};

use crate::bootmod::Modules;
use crate::component::{self, Component, SpawnArgs, abs_of, root_cap};
use crate::mem::{Arena, Dest, Slot};
use crate::vspace::{FRAME_BP, map_frame};
use crate::{Host, MAX_GUESTS, ctl, mr, set_mr};

static VMMGR_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/l4h-vmmgr.elf"));

const PAGE: usize = 4096;
/// Devices a guest can have (console, control, virtio).
pub use l4h_host::MAX_GUEST_DEVICES;
/// Bounds of a guest's I/O pool (a power of two).
const IO_POOL_MIN: usize = 1 << 20;
const IO_POOL_MAX: usize = 256 << 20;
/// Default size of dom0's I/O pool, when its vNICs need less.
pub const IO_POOL_DEFAULT: usize = 4 << 20;

/// Where root maps the pages it shares with vmmgr.
const EVENTS_VA: usize = crate::layout::VMMGR_PAGES.base;
const STATUS_VA: usize = EVENTS_VA + PAGE;
const RESULT_VA: usize = EVENTS_VA + 2 * PAGE;
/// dom0's control data area (the source of CTL_BLK_WRITE).
pub const CTL_DATA_VA: usize = crate::layout::CTL_DATA.base;

/// The I/O pool of a guest: physically contiguous memory at `paddr`,
/// which the guest sees at `gpa`.
#[derive(Clone, Copy)]
pub struct Pool {
    pub gpa: usize,
    pub paddr: usize,
    pub size: usize,
}

/// What root made for a guest of vmmgr's.
pub struct RootGuest {
    pub id: usize,
    pub instance: u64,
    pub dom0: bool,
    /// The pool, disk channels and port memory: revoked at GUEST_DEL.
    pub arena: Arena,
    pub pool: Pool,
    /// Its l4h-vmm's notification: backends signal it (badged).
    pub vmm_ntfn: cap::Notification,
    /// Disk windows attached to the guest: (controller, blkd client).
    pub disks: ArrayVec<(usize, usize), MAX_GUEST_DEVICES>,
    /// netd ports of its virtio-net devices.
    pub ports: ArrayVec<usize, MAX_GUEST_DEVICES>,
    /// It has an attestation device (trustd.rs).
    pub attest: bool,
}

/// vmmgr, as root keeps it.
pub struct Vmmgr {
    comp: Component,
    #[allow(dead_code)]
    arena: Arena,
    /// Its bound notification, badged BADGE_ROOT_EVENT.
    signal: cap::Notification,
}

impl Vmmgr {
    fn events(&self) -> &proto::Events {
        unsafe { &*(EVENTS_VA as *const proto::Events) }
    }

    /// trustd answered guest `id`: vmmgr raises its device's event.
    pub fn attest_done(&self, id: usize) {
        self.events().attest_done.fetch_or(1 << id, Ordering::AcqRel);
        self.signal.signal();
    }

    /// Have vmmgr run a monitor command (MONITOR_*); false if it has not
    /// taken the last one yet.
    pub fn monitor(&self, cmd: u64, arg: u32) -> bool {
        let ok = self.events().monitor.compare_exchange(0, cmd << 32 | arg as u64, Ordering::AcqRel, Ordering::Acquire).is_ok();
        if ok {
            self.signal.signal();
        }
        ok
    }

    /// Guest `id` as vmmgr last reported it.
    pub fn guest(&self, id: usize) -> Option<proto::GuestStatus> {
        let st = unsafe { &*(STATUS_VA as *const proto::Status) };
        let e = st.guests.get(id)?;
        // A few tries: vmmgr rewrites the page after every request.
        (0..16).find_map(|_| e.read()).filter(|g| g.state != 0)
    }

    /// CPU time vmmgr used since the last call, in timer ticks.
    pub fn consumed(&self) -> u64 {
        crate::sched_consumed(self.comp.sc)
    }
}

/// dom0's disks and vNICs, which root chooses at boot (it makes the
/// switches): the same for every dom0 vmmgr starts.
#[derive(Default)]
pub struct Dom0Plan {
    pub io_pool: usize,
    pub disks: ArrayVec<proto::Dom0Disk, { proto::DOM0_MAX_DISKS }>,
    pub nics: ArrayVec<proto::Dom0Nic, { proto::DOM0_MAX_NICS }>,
}

/// The vmmgr configuration under construction.
static CONFIG: l4h_host::fixed::Scratch<core::mem::MaybeUninit<VmmgrConfig>> =
    l4h_host::fixed::Scratch::new(core::mem::MaybeUninit::zeroed());

/// Spawn vmmgr, the last component: give it the modules guests boot from,
/// the CPUs' scheduling controls and the ASID pools, and endpoints to memd
/// and trustd's flags.
pub fn spawn(h: &mut Host, modules: &Modules, plan: &Dom0Plan) -> Vmmgr {
    // The modules, page after page at MODULES_VA, and their frames.
    let mods = ["guest-kernel", "guest-kmods", "dom0-initrd"].map(|name| modules.iter().find(|m| m.name == name).map(|m| m.data));
    let frames = modules.frames();
    let page_range = |d: &[u8]| {
        let p = d.as_ptr() as usize;
        (p & !(PAGE - 1))..(p + d.len()).next_multiple_of(PAGE)
    };
    // A module some page of which has no known frame stays root's.
    let mut mods = mods.map(|m| m.filter(|d| !d.is_empty() && page_range(d).step_by(PAGE).all(|va| frames.get(va).is_some())));
    if let Some(d) = mods[1] {
        if !kmods_shareable(modules, &mut h.wins.a, d) {
            mods[1] = None;
        }
    }
    let pages: usize = mods.iter().flatten().map(|d| page_range(d).len() / PAGE).sum();
    let radix = pages.max(1).next_power_of_two().trailing_zeros() as usize;
    assert!(pages * PAGE <= proto::MODULES_SIZE, "l4h-root: boot modules too large for vmmgr");

    let bits = proto::CNODE_BITS;
    let mut arena = h.alloc
        .arena((32 << bits) + 2 * (32 << radix) + (pages / 512 + 64) * PAGE + (4 << 20))
        .expect("memory for vmmgr");
    let mut ranges = [proto::ModuleRange::default(); 3];
    let comp = CONFIG.with(|cfg| {
        *cfg = core::mem::MaybeUninit::zeroed();
        let cfg = unsafe { cfg.assume_init_mut() };
        cfg.cores = h.info.cores as u64;
        cfg.tsc_hz = h.info.tsc_hz;
        cfg.timeslice_us = h.info.timeslice_us;
        cfg.epoch_ns = h.info.epoch_ns;
        cfg.epoch_ticks = h.info.epoch_ticks;
        cfg.cpu_id = h.info.cpu_id;
        let (cpus, physical, order) = h.info.topology.raw();
        (cfg.topo_cpus, cfg.topo_physical, cfg.topo_order) = (cpus as u64, physical, order);
        cfg.watchdog_secs = h.cfg.watchdog_secs as u64;
        cfg.trust = h.trustd.is_some() as u64;
        cfg.modules_radix = radix as u64;
        cfg.modules_pages = pages as u64;
        let mut at = 0;
        for (r, m) in ranges.iter_mut().zip(mods.iter()) {
            let Some(d) = m else { continue };
            let range = page_range(d);
            *r = proto::ModuleRange { offset: (at + d.as_ptr() as usize % PAGE) as u64, len: d.len() as u64 };
            at += range.len();
        }
        (cfg.kernel, cfg.kmods, cfg.dom0_initrd) = (ranges[0], ranges[1], ranges[2]);
        cfg.dom0_mem = (h.cfg.dom0_mem_mb << 20) as u64;
        cfg.dom0_vcpus = h.cfg.dom0_vcpus as u64;
        cfg.dom0_io_pool = plan.io_pool as u64;
        cfg.dom0_disks = plan.disks.len() as u64;
        cfg.dom0_disk[..plan.disks.len()].copy_from_slice(&plan.disks);
        cfg.dom0_nics = plan.nics.len() as u64;
        cfg.dom0_nic[..plan.nics.len()].copy_from_slice(&plan.nics);
        let cmdline = h.cfg.dom0_cmdline.as_bytes();
        let n = cmdline.len().min(abi::CMDLINE_SIZE - 1);
        cfg.dom0_cmdline[..n].copy_from_slice(&cmdline[..n]);
        // The ASID pools: all there can be, made now (none can be made
        // without ASIDControl, which stays here).
        h.asids.make_all(&mut h.alloc);
        let pools = h.asids.pools();
        cfg.asid_pools = pools.len() as u64;
        for (i, &(_, used)) in pools.iter().enumerate() {
            cfg.asids_used[i] = used as u64;
        }
        let cfg_bytes = unsafe {
            core::slice::from_raw_parts(cfg as *const VmmgrConfig as *const u8, core::mem::size_of::<VmmgrConfig>())
        };
        let args = SpawnArgs {
            id: proto::VMMGR_ID,
            kind: host::KIND_VMMGR,
            elf: VMMGR_ELF,
            // Above the guests and their VMMs, which it configures.
            prio: abi::PRIO_KERNEL + 2,
            budget_us: h.info.timeslice_us,
            period_us: h.info.timeslice_us,
            config: cfg_bytes,
            ntfn: None,
            service_ep: None,
            cnode: None,
            cnode_bits: Some(bits),
        };
        component::create(
            &args, &mut h.alloc, &mut arena, &mut h.wins.a,
            &mut |alloc, vspace| h.asids.assign(alloc, vspace), &h.info.spawn_context(0),
        )
    });

    for i in 0..host::log::PAGES {
        comp.give(proto::SLOT_LOG_FRAMES + i as u64,
            cap::Granule::from_bits(h.info.log_frames + i as u64), CapRights::read_write());
    }
    for core in 0..h.info.cores {
        comp.give(proto::SLOT_SCHED_CONTROL + core as u64, h.info.sched_control(core), CapRights::all());
    }
    for (i, &(pool, _)) in h.asids.pools().iter().enumerate() {
        comp.give(proto::SLOT_ASID_POOL + i as u64, pool, CapRights::all());
    }
    crate::memd::give_vmmgr(&mut h.alloc, &mut arena, &comp);

    // Mapping capabilities: the modules', and the shared pages'.
    let keep_mods = arena.object_cap::<cap_type::CNode>(&mut h.alloc, ObjectBlueprint::CNode { size_bits: radix });
    let mods_cn = arena.object_cap::<cap_type::CNode>(&mut h.alloc, ObjectBlueprint::CNode { size_bits: radix });
    comp.give(proto::SLOT_MODULES, mods_cn, CapRights::all());
    let mut i = 0;
    for d in mods.iter().flatten() {
        for va in page_range(d).step_by(PAGE) {
            let f = abs_of(root_cap::<cap_type::Granule>(frames.get(va).unwrap()));
            mods_cn.absolute_cptr_from_bits_with_depth(i as u64, radix).copy(&f, CapRights::read_only()).expect("vmmgr module frame");
            let keep = keep_mods.absolute_cptr_from_bits_with_depth(i as u64, radix);
            comp.map_copy(&mut h.alloc, &mut arena, &f, proto::MODULES_VA + i * PAGE, CapRights::read_only(), VmAttributes::DEFAULT, keep);
            i += 1;
        }
    }
    const KEEP_BITS: usize = 10;
    let keep = arena.object_cap::<cap_type::CNode>(&mut h.alloc, ObjectBlueprint::CNode { size_bits: KEEP_BITS });
    let mut keep_next = 0;
    let mut keep_slot = || {
        keep_next += 1;
        keep.absolute_cptr_from_bits_with_depth(keep_next - 1, KEEP_BITS)
    };
    if let Some(t) = &h.trustd {
        t.give_vmmgr(&comp, &mut h.alloc, &mut arena, &mut keep_slot);
    }
    h.memd.map_status(&comp, &mut h.alloc, &mut arena, keep_slot());
    // The events page (both write), the status page (vmmgr writes), the
    // result page (root writes), all host memory of root's.
    for (root_va, va, rights) in [
        (EVENTS_VA, proto::EVENTS_VA, CapRights::read_write()),
        (STATUS_VA, proto::STATUS_VA, CapRights::read_write()),
        (RESULT_VA, proto::RESULT_VA, CapRights::read_only()),
    ] {
        let f = h.alloc.object_cap::<cap_type::Granule>(FRAME_BP);
        let root_rights = if va == proto::STATUS_VA { CapRights::read_only() } else { CapRights::read_write() };
        map_in_root(h, f, root_va, root_rights);
        comp.map_copy(&mut h.alloc, &mut arena, &abs_of(f), va, rights, VmAttributes::DEFAULT, keep_slot());
    }
    // dom0's control data area: vmmgr maps it into every dom0.
    let ctl_cn = arena.object_cap::<cap_type::CNode>(&mut h.alloc, ObjectBlueprint::CNode { size_bits: proto::CTL_DATA_RADIX });
    arena
        .retype(&mut h.alloc, &FRAME_BP, proto::CTL_DATA_PAGES, Dest { cnode: abs_of(ctl_cn), offset: 0 })
        .expect("dom0 control data area");
    comp.give(proto::SLOT_CTL_DATA, ctl_cn, CapRights::all());
    for p in 0..proto::CTL_DATA_PAGES {
        let f = ctl_cn.absolute_cptr_from_bits_with_depth(p as u64, proto::CTL_DATA_RADIX);
        let copy = h.alloc.slots.alloc();
        abs_of(root_cap::<cap_type::Null>(copy)).copy(&f, CapRights::all()).expect("control data copy");
        map_in_root(h, root_cap(copy), CTL_DATA_VA + p * PAGE, CapRights::read_only());
        comp.map_copy(&mut h.alloc, &mut arena, &f, proto::CTL_DATA_VA + p * PAGE, CapRights::read_write(), VmAttributes::DEFAULT, keep_slot());
    }

    let s = h.alloc.slots.alloc();
    let signal = root_cap::<cap_type::Notification>(s);
    abs_of(signal).mint(&abs_of(comp.ntfn), CapRights::write_only(), proto::BADGE_ROOT_EVENT).expect("vmmgr signal");
    component::start(&comp);
    info!("l4h-root: vmmgr started with {} MiB of boot modules", pages * PAGE >> 20);
    Vmmgr { comp, arena, signal }
}

/// Whether guests may map the module image `data` in whole pages: it must
/// start a page, and its last page holds nothing else.  Root clears what
/// follows the image in that page (a boot loader leaves whatever was in
/// memory there) before any guest exists.
fn kmods_shareable(modules: &Modules, win: &mut crate::window::Window, data: &'static [u8]) -> bool {
    if data.len() as u64 > abi::KMOD_MAX {
        log!("l4h-root: module image of {} bytes ignored", data.len());
        return false;
    }
    let frames = modules.frames();
    let (start, end) = (data.as_ptr() as usize, data.as_ptr() as usize + data.len());
    if start % PAGE != 0 {
        log!("l4h-root: module image at {:#x}: not in whole pages of its boot module, ignored", start);
        return false;
    }
    let rest = end.next_multiple_of(PAGE) - end;
    // Mapped in the root task with the rest of the module's last page.
    let tail = unsafe { core::slice::from_raw_parts(end as *const u8, rest) };
    if tail.iter().any(|&b| b != 0) {
        // Another module there would be lost, or leak to every guest.
        let there = modules.iter().any(|m| {
            let p = m.data.as_ptr() as usize;
            p < end + rest && end < p + m.data.len()
        });
        if there {
            log!("l4h-root: module image at {:#x} shares its last page, ignored", start);
            return false;
        }
        let last = frames.get(end & !(PAGE - 1)).expect("module image frame");
        win.with_frame(&abs_of(root_cap::<cap_type::Granule>(last)), |p| unsafe {
            core::ptr::write_bytes(p.add(PAGE - rest), 0, rest)
        });
    }
    true
}

/// Map frame `f` (a root slot) at `va` in the root task, for good.
fn map_in_root(h: &mut Host, f: cap::Granule, va: usize, rights: CapRights) {
    h.alloc.global(|alloc| {
        map_frame(&mut crate::mem::ObjCtx::global(alloc), crate::slot::VSPACE.cap(), f, va, rights, VmAttributes::DEFAULT);
    });
}

/// Exchange slot `i` of vmmgr's, emptied for root to put a capability in:
/// whatever vmmgr left there must not make root fail.
fn xchg(h: &Host, i: usize) -> sel4::AbsoluteCPtr {
    let s = h.vmmgr.as_ref().expect("vmmgr").comp.slot(proto::SLOT_XCHG + i as u64);
    let _ = s.delete();
    s
}

/// A call from vmmgr (label `label`): its reply's length.
pub fn call(h: &mut Host, label: u64) -> usize {
    let a: [u64; 8] = core::array::from_fn(mr);
    let mut len = 1;
    let r = match label {
        proto::VMMGR_GUEST_NEW => guest_new(h, a),
        proto::VMMGR_GUEST_DEL => guest_del(h, a[0] as usize),
        proto::VMMGR_DISK_ATTACH => disk_attach(h, a),
        proto::VMMGR_NIC_ADD => nic_add(h, a),
        proto::VMMGR_TRUST_REGISTER => trust_register(h, a),
        proto::VMMGR_HOST_OP => {
            let data = unsafe { &mut *(RESULT_VA as *mut [u8; abi::CTL_DATA_MAX]) };
            data.fill(0);
            let args = a[1..7].try_into().unwrap();
            ctl::host_op(h, a[0] as u32, &args, data).map(|vals| vals.into_iter().collect())
        }
        _ => Err(ctl::ENOSYS),
    };
    match r {
        Ok(vals) => {
            set_mr(0, 0);
            for (i, &v) in vals.iter().enumerate() {
                set_mr(1 + i, v);
            }
            len += vals.len();
        }
        Err(e) => set_mr(0, e as u64),
    }
    len
}

/// Up to six reply values.
type Vals = ArrayVec<u64, 6>;

fn guest_arg(id: u64) -> Result<usize, i64> {
    let id = id as usize;
    if id < MAX_GUESTS { Ok(id) } else { Err(ctl::ENOENT) }
}

/// Run `f` on guest `id` with root slot allocations tracked into it.
fn with_guest<R>(h: &mut Host, id: usize, f: impl FnOnce(&mut Host, &mut RootGuest) -> Result<R, i64>) -> Result<R, i64> {
    let mut g = h.guests.get_mut(id).and_then(|g| g.take()).ok_or(ctl::ENOENT)?;
    h.alloc.slots.track(id);
    let r = f(h, &mut g);
    h.alloc.slots.untrack();
    h.guests[id] = Some(g);
    r
}

/// VMMGR_GUEST_NEW: the pool, and the attestation device.
fn guest_new(h: &mut Host, a: [u64; 8]) -> Result<Vals, i64> {
    let id = guest_arg(a[0])?;
    let (size, gpa, dom0) = (a[1] as usize, a[2] as usize, a[3] != 0);
    if h.guests[id].is_some() || !size.is_power_of_two() || !(IO_POOL_MIN..=IO_POOL_MAX).contains(&size) || gpa % PAGE != 0 {
        return Err(ctl::EINVAL);
    }
    let bits = size.trailing_zeros() as usize;
    let radix = bits - 12;
    if !h.can_afford(size + (32 << radix) + PAGE, 0, 4) {
        return Err(ctl::ENOMEM);
    }
    h.alloc.slots.track(id);
    let r = (|| {
        let mut arena = h.alloc.arena(32 << radix).ok_or(ctl::ENOMEM)?;
        // Its VMM's notification, which backends signal: root's, so that
        // it is a notification whatever vmmgr does.
        let vmm_ntfn = arena.object_cap::<cap_type::Notification>(&mut h.alloc, ObjectBlueprint::Notification);
        // One physically contiguous Untyped retyped into frames, kept in
        // a CNode.
        let pool_slot = h.alloc.slots.alloc();
        let Some(mut region) = h.alloc.split(bits, pool_slot) else {
            h.alloc.reclaim(arena);
            return Err(ctl::ENOMEM);
        };
        let paddr = region.paddr;
        arena.own(pool_slot, paddr, bits);
        let frames = arena.object_cap::<cap_type::CNode>(&mut h.alloc, ObjectBlueprint::CNode { size_bits: radix });
        region.retype(&FRAME_BP, size / PAGE, Dest { cnode: abs_of(frames), offset: 0 }).expect("I/O pool frames");
        xchg(h, 0).copy(&abs_of(frames), CapRights::all()).expect("vmmgr pool frames");
        xchg(h, 3).copy(&abs_of(vmm_ntfn), CapRights::all()).expect("vmmgr VMM notification");
        let (page, kick) = (xchg(h, 1), xchg(h, 2));
        let attest = match &h.trustd {
            Some(t) => t.give(id, &mut h.wins.a, &page, &kick),
            None => false,
        };
        let instance = h.next_instance;
        h.next_instance = instance.checked_add(1).expect("guest instance exhausted");
        h.guests[id] = Some(RootGuest {
            id,
            instance,
            dom0,
            arena,
            pool: Pool { gpa, paddr, size },
            vmm_ntfn,
            disks: ArrayVec::new(),
            ports: ArrayVec::new(),
            attest,
        });
        Ok([instance, attest as u64].into_iter().collect())
    })();
    h.alloc.slots.untrack();
    if r.is_err() {
        h.alloc.slots.free_owned(id);
    }
    r
}

/// VMMGR_GUEST_DEL: vmmgr has stopped and torn down guest `id`.  Disks are
/// quiesced, or cut off by the IOMMU, before any memory they were given is
/// reused.
fn guest_del(h: &mut Host, id: usize) -> Result<Vals, i64> {
    let g = h.guests.get_mut(id).and_then(|g| g.take()).ok_or(ctl::ENOENT)?;
    if let Some(t) = &mut h.trustd {
        t.unregister(id);
    }
    for &p in &g.ports {
        h.netd.remove_port(p);
    }
    let mut quiet = true;
    for &(ctrl, client) in &g.disks {
        quiet &= crate::blkd::remove(&mut h.ctrls[ctrl], client, &h.pci, &mut h.iommu);
    }
    // A disk that could not be stopped may still write to the pool, the
    // only memory of the guest's a device is given: it is kept out of use
    // for good.
    let pool = g.pool.paddr;
    let pinned = h.alloc.reclaim_pinning(g.arena, |p| !quiet && p == pool);
    h.alloc.slots.free_owned(id);
    Ok([pinned as u64].into_iter().collect())
}

/// VMMGR_DISK_ATTACH: pass host disk `disk` (or sectors [lba_start,
/// lba_start + lba_count) of it; 0 = to the end) through to the guest.
/// The window must be aligned to blkd::WINDOW_ALIGN sectors.
fn disk_attach(h: &mut Host, a: [u64; 8]) -> Result<Vals, i64> {
    let id = guest_arg(a[0])?;
    let (dev, disk, read_only, lba_start, lba_count) = (a[1] as usize, a[2] as usize, a[3] != 0, a[4], a[5]);
    if dev >= MAX_GUEST_DEVICES || lba_start % crate::blkd::WINDOW_ALIGN != 0 || lba_count % crate::blkd::WINDOW_ALIGN != 0 {
        return Err(ctl::EINVAL);
    }
    h.ensure_disk(disk)?;
    let (c, unit) = (h.disks[disk].ctrl, h.disks[disk].unit);
    let ctrl = &h.ctrls[c];
    let window = l4h_host::blk::DiskWindow::new(lba_start, lba_count, h.disks[disk].capacity).ok_or(ctl::EINVAL)?;
    let read_only = read_only || h.disks[disk].read_only;
    if ctrl.attachments(disk).any(|(_, a)| window.conflicts(read_only, a.window, a.read_only)) {
        return Err(ctl::EBUSY);
    }
    if ctrl.clients.iter().all(Option::is_some) { return Err(ctl::ENOSPC); }
    if !h.can_afford(1 << 20, 0, 0) { return Err(ctl::ENOMEM); }
    with_guest(h, id, |h, g| {
        if g.disks.is_full() {
            return Err(ctl::ENOSPC);
        }
        let (client, chan, kick) = crate::blkd::attach(&mut h.ctrls[c], disk, g, window, read_only, &mut h.alloc, &mut h.iommu);
        g.disks.must_push((c, client));
        crate::blkd::activate(&mut h.ctrls[c], unit, client, g, &chan, &mut h.wins.a, &h.pci)?;
        for (i, f) in chan.iter().enumerate() {
            xchg(h, i).copy(&abs_of(*f), CapRights::all()).expect("vmmgr channel frame");
        }
        xchg(h, chan.len()).move_(&abs_of(kick)).expect("vmmgr blkd kick");
        h.alloc.slots.free(kick.bits() as Slot);
        Ok(Vals::new())
    })
}

/// VMMGR_NIC_ADD: a port of `switch` for the guest.  Returns the MAC.
fn nic_add(h: &mut Host, a: [u64; 8]) -> Result<Vals, i64> {
    let id = guest_arg(a[0])?;
    let (dev, switch, mac, lock, isolated) = (a[1] as usize, a[2] as u32, a[3], a[4] != 0, a[5] != 0);
    if dev >= MAX_GUEST_DEVICES {
        return Err(ctl::EINVAL);
    }
    if !h.can_afford(8 << 20, 0, 0) {
        return Err(ctl::ENOMEM);
    }
    with_guest(h, id, |h, g| {
        if g.ports.is_full() {
            return Err(ctl::ENOSPC);
        }
        let p = h.netd.free_port(switch)?;
        let mac = if mac == 0 { 0x02_4c_34_00_00_00 | ((id as u64) << 8) | p as u64 } else { mac & 0xffff_ffff_ffff };
        if mac >> 40 & 1 != 0 {
            return Err(ctl::EINVAL);
        }
        let memory = crate::netd::Netd::port_memory(&mut h.alloc)?;
        let (chan, kick) = h.netd.add_port(g, p, switch, mac, lock, isolated, memory, &mut h.alloc);
        g.ports.must_push(p);
        xchg(h, 0).copy(&abs_of(chan), CapRights::all()).expect("vmmgr port frames");
        xchg(h, 1).move_(&abs_of(kick)).expect("vmmgr port kick");
        h.alloc.slots.free(kick.bits() as Slot);
        Ok([mac].into_iter().collect())
    })
}

/// VMMGR_TRUST_REGISTER: the guest starts.
fn trust_register(h: &mut Host, a: [u64; 8]) -> Result<Vals, i64> {
    let id = guest_arg(a[0])?;
    let g = h.guests[id].as_ref().ok_or(ctl::ENOENT)?;
    if !g.attest {
        return Err(ctl::EINVAL);
    }
    let mut launch = [0; 32];
    for (i, w) in a[4..8].iter().enumerate() {
        launch[8 * i..8 * i + 8].copy_from_slice(&w.to_le_bytes());
    }
    let record = host::trust::GuestRecord {
        instance: 0,
        ram: a[1],
        vcpus: a[2] as u32,
        // dom0 is root's to say.
        flags: if g.dom0 { host::trust::RECORD_DOM0 } else { 0 },
        launch,
        reserved: 0,
    };
    let instance = g.instance;
    if let Some(t) = &mut h.trustd {
        t.register(id, instance, record);
    }
    Ok(Vals::new())
}

//! The attestation service, l4h-trustd (DESIGN.md §9.2): finding the TPM,
//! starting trustd with it, making guests' attestation devices (vmmgr adds
//! them to guests), the registry page through which trustd learns about
//! guests, and what trustd asks root for: raising a device's event when it
//! has answered (vmmgr raises it), and the hardware accesses of its AML
//! interpreter.
//!
//! Only x86 finds a TPM (in ACPI) so far; other hosts run flags only.
#![cfg_attr(not(target_arch = "x86_64"), allow(dead_code, unused_imports))]


use sel4::{CNodeCapData, CapRights, ObjectBlueprint, VmAttributes, cap, cap_type};

use l4h_abi as abi;
use l4h_host as host;
use l4h_host::fixed::ArrayVec;
use l4h_host::trust::{self, GuestRecord, TrustdConfig};

use crate::component::{self, Component, SpawnArgs, abs_of, component_badge, root_cap};
use crate::devmem::DevMem;
use crate::mem::{Alloc, Arena, ObjCtx};
use crate::vspace::{FRAME_BP, map_frame};
use crate::window::Window;
use crate::{AsidPools, Host, HostInfo, mr};

pub use l4h_host::trust::AML_MAX;

static TRUSTD_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/l4h-trustd.elf"));

const PAGE: usize = 4096;
pub const TRUSTD_ID: u32 = 0x300;
pub const FLAGS_ID: u32 = 0x301;
/// The registry page in the root task.
const REGISTRY_VA: usize = crate::layout::TRUSTD_REGISTRY.base;
/// Mapping capabilities trustd's ranges and AML pages can need.
const KEEP_BITS: usize = 12;

pub struct Trustd {
    comp: Component,
    #[allow(dead_code)]
    arena: Arena,
    registry: *mut GuestRecord,
    kexec_state: *mut trust::KexecState,
    measure_kick: cap::Notification,
    measure_reply: crate::ReplySlot,
    flags_ep: cap::Endpoint,
    no_reports: bool,
    /// The firmware describes a TPM, so a kexec must be measured even
    /// when trustd cannot use it.
    tpm_found: bool,
    failed: bool,
    /// The request page of each guest id, mapped in trustd.
    pages: [cap::Granule; trust::MAX_RECORDS],
    /// Guests signal it, badged with trust::kick_badge(id).
    kick: cap::Notification,
    /// The flags table, which root and vmmgr map read-only.
    flags: [cap::Granule; trust::FLAGS_SIZE / PAGE],
    /// Device memory carved for trustd's ranges and its AML's accesses.
    #[cfg(target_arch = "x86_64")]
    frames: crate::acpi::Frames,
}

/// Where the TPM is: its interface and the ranges trustd maps, with the
/// registers and buffers in them as (range, offset in it).
#[derive(Default)]
struct Layout {
    iface: u32,
    start: u32,
    ranges: ArrayVec<(usize, usize), { trust::MAX_RANGES }>,
    loc: Option<(usize, usize)>,
    ctrl: Option<(usize, usize)>,
    cmd: Option<(usize, usize, usize)>,
    rsp: Option<(usize, usize, usize)>,
    start_bell: Option<(usize, usize)>,
    reply_bell: Option<(usize, usize)>,
}

impl Layout {
    /// A new range covering [paddr, paddr + len): (range, offset).
    fn range(&mut self, paddr: usize, len: usize) -> Option<(usize, usize)> {
        let base = paddr & !(PAGE - 1);
        let size = (paddr + len).next_multiple_of(PAGE) - base;
        if size > trust::RANGE_STRIDE {
            return None;
        }
        self.ranges.push((base, size)).ok()?;
        Some((self.ranges.len() - 1, paddr - base))
    }

    fn va((r, off): (usize, usize)) -> u64 {
        (trust::TPM_VA + r * trust::RANGE_STRIDE + off) as u64
    }

    fn config(&self, aml_size: usize) -> TrustdConfig {
        let mut ranges = [trust::Range::default(); trust::MAX_RANGES];
        for (r, &(paddr, size)) in self.ranges.iter().enumerate() {
            ranges[r] = trust::Range { paddr: paddr as u64, size: size as u64 };
        }
        let va = |x: Option<(usize, usize)>| x.map_or(0, Self::va);
        let buf = |x: Option<(usize, usize, usize)>| x.map_or((0, 0), |(r, off, n)| (Self::va((r, off)), n as u64));
        let (cmd_va, cmd_size) = buf(self.cmd);
        let (rsp_va, rsp_size) = buf(self.rsp);
        TrustdConfig {
            iface: self.iface,
            start: self.start,
            ranges,
            loc_va: va(self.loc),
            ctrl_va: va(self.ctrl),
            cmd_va,
            cmd_size,
            rsp_va,
            rsp_size,
            start_va: va(self.start_bell),
            reply_va: va(self.reply_bell),
            aml_size: aml_size as u64,
            kexec_log_va: 0,
            kexec_log_size: 0,
        }
    }
}

/// The TPM, from its ACPI table (DESIGN.md §9.2).
#[cfg(target_arch = "x86_64")]
fn find_tpm(bootinfo: &sel4::BootInfoPtr, phys: &mut crate::acpi::Phys) -> Option<Layout> {
    use crate::blkd::DEVICE_ATTRS;
    /// TPM 2.0 at its standard address (PC Client PTP), where the ACPI
    /// table gives none (FIFO interface).
    const TPM_DEFAULT_BASE: usize = 0xfed4_0000;
    // The TPM2 table, up to the Pluton doorbells (revision 4 is 76 bytes).
    let mut buf = [0; 76];
    let Some(t) = crate::acpi::find(bootinfo, phys, b"TPM2", &mut buf).filter(|t| t.len() >= 52) else {
        info!("l4h-root: no TPM, no attestation");
        return None;
    };
    let u64_at = |i: usize| u64::from_le_bytes(t[i..i + 8].try_into().unwrap()) as usize;
    let control = u64_at(40);
    let method = u32::from_le_bytes(t[48..52].try_into().unwrap());
    let mut l = Layout::default();
    let unusable = |why: &str| -> Option<Layout> {
        log!("l4h-root: TPM (start method {}) unusable, no attestation: {}", method, why);
        None
    };
    if method == 6 {
        // FIFO ("TIS"): locality 0's registers.
        l.iface = trust::TPM_TIS;
        l.loc = l.range(if control != 0 { control & !(PAGE - 1) } else { TPM_DEFAULT_BASE }, PAGE);
        return Some(l);
    }
    l.iface = trust::TPM_CRB;
    l.start = match method {
        7 => trust::START_CRB,
        2 | 8 => trust::START_ACPI,
        13 => trust::START_PLUTON,
        _ => return unusable("unsupported start method"),
    };
    if control == 0 {
        return unusable("no control area");
    }
    // Only plain CRB has locality registers, the page the control area is
    // at 0x40 of (as Linux tpm_crb).
    if method == 7 {
        if control % PAGE != 0x40 {
            return unusable("control area not in the locality page");
        }
        l.loc = l.range(control & !(PAGE - 1), PAGE);
    }
    // The control area and the buffers it names.
    let mut regs = [0; 0x30];
    phys.read_into_attrs(control, &mut regs, DEVICE_ATTRS)?;
    let w32 = |i: usize| u32::from_le_bytes(regs[i..i + 4].try_into().unwrap()) as usize;
    let (cmd, cmd_size) = (w32(0x1c) | w32(0x20) << 32, w32(0x18));
    let (rsp, rsp_size) = (w32(0x28) | w32(0x2c) << 32, w32(0x24));
    if cmd == 0 || rsp == 0 || cmd_size < 10 || rsp_size < 10 {
        return unusable("no command or response buffer");
    }
    l.ctrl = l.range(control, 0x30);
    l.cmd = l.range(cmd, cmd_size).map(|(r, off)| (r, off, cmd_size));
    l.rsp = l.range(rsp, rsp_size).map(|(r, off)| (r, off, rsp_size));
    if method == 13 {
        // Pluton: the doorbells' addresses (struct tpm2_crb_pluton in
        // Linux) right after the table's fixed part, in place of the
        // start method parameters.
        if t.len() < 52 + 16 {
            return unusable("no Pluton doorbells");
        }
        l.start_bell = l.range(u64_at(52), 4);
        l.reply_bell = l.range(u64_at(60), 4);
    }
    if l.ctrl.is_none() || l.cmd.is_none() || l.rsp.is_none() || (method == 13 && l.reply_bell.is_none()) {
        return unusable("registers or buffers too large");
    }
    Some(l)
}

/// Start trustd whenever built in. Without a usable TPM it serves flags.
pub fn spawn(
    bootinfo: &sel4::BootInfoPtr,
    alloc: &mut Alloc,
    devmem: &mut DevMem,
    win: &mut Window,
    asids: &mut AsidPools,
    info: &HostInfo,
    #[cfg(target_arch = "x86_64")]
    frames: crate::acpi::Frames,
    kexec_log: Option<&[u8]>,
) -> Option<Trustd> {
    if TRUSTD_ELF.is_empty() {
        return None;
    }
    #[cfg(target_arch = "x86_64")]
    {
        let mut frames = frames;
        let mut phys = crate::acpi::Phys::new(alloc, devmem, win, &mut frames);
        let tpm_found = crate::acpi::find(bootinfo, &mut phys, b"TPM2", &mut [0; 76]).is_some();
        let Some(l) = find_tpm(bootinfo, &mut phys) else {
            return flags_only(alloc, win, asids, info, tpm_found, frames);
        };
        // The pages of each range, which stay in `frames`.
        for &(base, size) in &l.ranges {
            if (0..size / PAGE).any(|p| phys.frame(base + p * PAGE).is_none()) {
                log!("l4h-root: TPM at {:#x} is not device memory, no attestation", base);
                return flags_only(alloc, win, asids, info, true, frames);
            }
        }
        // The AML's size.  Its pages are carved now, so that copying it
        // once trustd exists cannot fail for want of them.
        let aml_size = match l.start {
            trust::START_ACPI => {
                let touch = |phys: &mut crate::acpi::Phys, pa: usize, len: usize| {
                    (pa & !(PAGE - 1)..pa + len).step_by(PAGE).try_for_each(|p| phys.frame(p).map(drop))
                };
                match crate::acpi::aml_tables(bootinfo, &mut phys, touch) {
                    Some(n) => n,
                    None => {
                        log!("l4h-root: cannot read the ACPI tables for the TPM, no attestation");
                        return flags_only(alloc, win, asids, info, true, frames);
                    }
                }
            }
            _ => 0,
        };
        info!(
            "l4h-root: TPM 2.0 ({}) at {:#x}",
            match (l.iface, l.start) {
                (trust::TPM_TIS, _) => "FIFO",
                (_, trust::START_ACPI) => "CRB, ACPI start",
                (_, trust::START_PLUTON) => "CRB, Pluton",
                _ => "CRB",
            },
            l.ranges[0].0
        );
        let mut cfg = l.config(aml_size);
        cfg.kexec_log_va = kexec_log.filter(|log| log.len() <= trust::KEXEC_LOG_MAX).map_or(0, |_| trust::KEXEC_LOG_VA as u64);
        cfg.kexec_log_size = kexec_log.map_or(0, |log| {
            if log.len() > trust::KEXEC_LOG_MAX { trust::KEXEC_LOG_INVALID } else { log.len() as u64 }
        });
        let (comp, arena, keep) = create(&cfg, alloc, win, asids, info, aml_size)?;
        let mut keep_next = 0;
        let mut keep_slot = || {
            keep_next += 1;
            keep.absolute_cptr_from_bits_with_depth(keep_next - 1, KEEP_BITS)
        };
        let mut arena = arena;
        for (r, &(base, size)) in l.ranges.iter().enumerate() {
            for p in 0..size / PAGE {
                let f = frames.get(base + p * PAGE).expect("TPM page carved above");
                let va = trust::TPM_VA + r * trust::RANGE_STRIDE + p * PAGE;
                comp.map_copy(alloc, &mut arena, &abs_of(f), va, CapRights::read_write(), crate::blkd::DEVICE_ATTRS, keep_slot());
            }
        }
        // The ACPI tables, copied into fresh frames a piece at a time, as
        // trustd sees them: back to back from AML_VA.
        if aml_size != 0 {
            let mut at = 0;
            let mut frame = None;
            let copy = |phys: &mut crate::acpi::Phys, pa: usize, len: usize| {
                let mut buf = [0; 512];
                let mut done = 0;
                while done < len {
                    if at % PAGE == 0 {
                        let f = arena.object_cap::<cap_type::Granule>(phys.alloc, FRAME_BP);
                        comp.map_copy(phys.alloc, &mut arena, &abs_of(f), trust::AML_VA + at, CapRights::read_only(), VmAttributes::DEFAULT, keep_slot());
                        frame = Some(f);
                    }
                    let n = (len - done).min(PAGE - at % PAGE).min(buf.len());
                    phys.read_into(pa + done, &mut buf[..n])?;
                    let off = at % PAGE;
                    phys.win.with_frame(&abs_of(frame?), |dst| unsafe { core::ptr::copy_nonoverlapping(buf.as_ptr(), dst.add(off), n) });
                    (done, at) = (done + n, at + n);
                }
                Some(())
            };
            let mut phys = crate::acpi::Phys::new(alloc, devmem, win, &mut frames);
            if crate::acpi::aml_tables(bootinfo, &mut phys, copy) != Some(aml_size) {
                log!("l4h-root: cannot copy the ACPI tables for the TPM, no attestation");
                alloc.reclaim(arena);
                return flags_only(alloc, win, asids, info, true, frames);
            }
        }
        finish(comp, arena, alloc, win, &mut keep_slot, info, false, frames, kexec_log)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (bootinfo, devmem);
        flags_only(alloc, win, asids, info, false)
    }
}

/// The same flags service on machines with no usable TPM.
fn flags_only(
    alloc: &mut Alloc, win: &mut Window, asids: &mut AsidPools, info: &HostInfo, tpm_found: bool,
    #[cfg(target_arch = "x86_64")] frames: crate::acpi::Frames,
) -> Option<Trustd> {
    let (comp, arena, keep) = create(&Layout::default().config(0), alloc, win, asids, info, 0)?;
    let mut next = 0;
    let mut t = finish(comp, arena, alloc, win, &mut || {
        let slot = keep.absolute_cptr_from_bits_with_depth(next, KEEP_BITS);
        next += 1;
        slot
    }, info, true, #[cfg(target_arch = "x86_64")] frames, None)?;
    t.tpm_found = tpm_found;
    Some(t)
}

/// Create trustd with configuration `cfg`, and the CNode that keeps its
/// mapping capabilities.
fn create(
    cfg: &TrustdConfig,
    alloc: &mut Alloc,
    win: &mut Window,
    asids: &mut AsidPools,
    info: &HostInfo,
    aml_size: usize,
) -> Option<(Component, Arena, cap::CNode)> {
    let mut arena = alloc.arena((8 << 20) + 2 * aml_size).expect("memory for trustd and flags service");
    let cfg_bytes = unsafe {
        core::slice::from_raw_parts(cfg as *const TrustdConfig as *const u8, core::mem::size_of::<TrustdConfig>())
    };
    let args = SpawnArgs {
        id: TRUSTD_ID,
        kind: host::KIND_TRUSTD,
        elf: TRUSTD_ELF,
        prio: abi::PRIO_KERNEL + 1,
        // At most a quarter of a core, whatever the TPM or its firmware's
        // AML does (trustd sleeps between polls of the TPM).
        budget_us: info.timeslice_us,
        period_us: 4 * info.timeslice_us,
        config: cfg_bytes,
        ntfn: None,
        service_ep: None,
        cnode: None,
        cnode_bits: None,
    };
    let comp = component::create(
        &args, alloc, &mut arena, win, &mut |alloc, vspace| asids.assign(alloc, vspace),
        &info.spawn_context(info.cores - 1),
    );
    let keep = arena.object_cap::<cap_type::CNode>(alloc, ObjectBlueprint::CNode { size_bits: KEEP_BITS });
    Some((comp, arena, keep))
}

/// Map the registry and request pages, give trustd its kick notification,
/// and start it.
fn finish(
    comp: Component,
    mut arena: Arena,
    alloc: &mut Alloc,
    win: &mut Window,
    keep: &mut impl FnMut() -> sel4::AbsoluteCPtr,
    info: &HostInfo,
    no_reports: bool,
    #[cfg(target_arch = "x86_64")]
    frames: crate::acpi::Frames,
    kexec_log: Option<&[u8]>,
) -> Option<Trustd> {
    let registry = alloc.object_cap::<cap_type::Granule>(FRAME_BP);
    alloc.global(|alloc| {
        let copy = alloc.slots.alloc();
        abs_of(sel4::init_thread::Slot::<cap_type::Null>::from_index(copy).cap())
            .copy(&abs_of(registry), CapRights::all())
            .expect("registry copy");
        let f = sel4::init_thread::Slot::<cap_type::Granule>::from_index(copy).cap();
        map_frame(&mut ObjCtx::global(alloc), sel4::init_thread::slot::VSPACE.cap(), f, REGISTRY_VA, CapRights::read_write(), VmAttributes::DEFAULT);
    });
    comp.map_copy(alloc, &mut arena, &abs_of(registry), trust::REGISTRY_VA, CapRights::read_only(), VmAttributes::DEFAULT, keep());
    let kexec = alloc.object_cap::<cap_type::Granule>(FRAME_BP);
    map_frame(&mut ObjCtx::global(alloc), sel4::init_thread::slot::VSPACE.cap(), kexec,
        crate::layout::TRUSTD_KEXEC.base, CapRights::read_write(), VmAttributes::DEFAULT);
    comp.map_copy(alloc, &mut arena, &abs_of(kexec), trust::KEXEC_STATE_VA, CapRights::read_write(), VmAttributes::DEFAULT, keep());
    let pages = core::array::from_fn(|g| {
        let f = arena.object_cap::<cap_type::Granule>(alloc, FRAME_BP);
        comp.map_copy(alloc, &mut arena, &abs_of(f), trust::page_va(g), CapRights::read_write(), VmAttributes::DEFAULT, keep());
        f
    });
    let kick = arena.object_cap::<cap_type::Notification>(alloc, ObjectBlueprint::Notification);
    comp.give(trust::SLOT_KICK, kick, CapRights::all());
    let slot = alloc.slots.alloc();
    let measure_kick = sel4::init_thread::Slot::<cap_type::Notification>::from_index(slot).cap();
    abs_of(measure_kick).mint(&abs_of(kick), CapRights::write_only(), trust::kick_badge(0)).expect("kexec measurement notification");
    comp.give_badged(trust::SLOT_MEASURE_DONE, info.events, CapRights::write_only(), trust::MEASURE_DONE_BADGE);
    let flags = core::array::from_fn(|p| {
        let f = arena.object_cap::<cap_type::Granule>(alloc, FRAME_BP);
        comp.map_copy(alloc, &mut arena, &abs_of(f), trust::FLAGS_VA + p * PAGE, CapRights::read_only(), VmAttributes::DEFAULT, keep());
        comp.map_copy(alloc, &mut arena, &abs_of(f), trust::FLAGS_WRITE_VA + p * PAGE, CapRights::read_write(), VmAttributes::DEFAULT, keep());
        map_frame(&mut ObjCtx::global(alloc), sel4::init_thread::slot::VSPACE.cap(), f,
            crate::layout::TRUSTD_FLAGS.base + p * PAGE, CapRights::read_only(), VmAttributes::DEFAULT);
        f
    });
    let ep = arena.object_cap::<cap_type::Endpoint>(alloc, ObjectBlueprint::Endpoint);
    comp.give(trust::SLOT_FLAGS_EP, ep, CapRights::all());
    let call_rights = sel4::CapRightsBuilder::none().write(true).grant_reply(true).build();
    comp.give_badged(trust::SLOT_FLAGS_CALL, ep, call_rights.clone(), trust::FLAGS_TRUSTD);
    let slot = alloc.slots.alloc();
    let flags_ep = sel4::init_thread::Slot::<cap_type::Endpoint>::from_index(slot).cap();
    abs_of(flags_ep).mint(&abs_of(ep), call_rights, trust::FLAGS_ROOT).expect("root flags endpoint");
    for (page, chunk) in kexec_log
        .filter(|log| log.len() <= trust::KEXEC_LOG_MAX)
        .unwrap_or(&[])
        .chunks(PAGE)
        .enumerate()
    {
        let f = arena.object_cap::<cap_type::Granule>(alloc, FRAME_BP);
        win.with_frame(&abs_of(f), |p| unsafe {
            core::ptr::copy_nonoverlapping(chunk.as_ptr(), p, chunk.len());
        });
        comp.map_copy(alloc, &mut arena, &abs_of(f), trust::KEXEC_LOG_VA + page * PAGE, CapRights::read_only(), VmAttributes::DEFAULT, keep());
    }
    let bootstrap = flags_thread(&comp, alloc, &mut arena, info);
    component::start(&comp);
    // reply_recv puts the worker back on the endpoint before returning
    // this reply. Unbind only now: subsequent calls donate their SC.
    sel4::with_ipc_buffer_mut(|b| b.msg_regs_mut()[..8].fill(0));
    flags_ep.call(sel4::MessageInfo::new(0, 0, 0, 8));
    bootstrap.unbind().expect("passive flags server");
    Some(Trustd { comp, arena, registry: REGISTRY_VA as *mut GuestRecord,
        kexec_state: crate::layout::TRUSTD_KEXEC.base as *mut trust::KexecState,
        measure_kick, measure_reply: crate::ReplySlot::new(alloc), flags_ep, no_reports, tpm_found: !no_reports, failed: false, pages, kick, flags,
        #[cfg(target_arch = "x86_64")] frames })
}

/// Extend PCR 14 with a new image's event, then stop trustd. Root services
/// its normal endpoint while waiting, including trustd's own AML accesses.
pub fn measure(h: &mut Host, digest: [u8; 32]) -> Result<(), i64> {
    if h.trustd.as_ref().ok_or(crate::ctl::ENODEV)?.kexec_key()?.is_none() {
        return Ok(());
    }
    let t = h.trustd.as_ref().unwrap();
    let (p, reply_slot) = (t.kexec_state, t.measure_reply);
    let mailbox = unsafe { core::ptr::addr_of_mut!((*p).measure) };
    let seq = unsafe { host::handoff::Mailbox::post(mailbox, digest) };
    t.measure_kick.signal();
    let end = l4h_host::ticks::now() + 10 * h.info.tsc_hz;
    let result = crate::handoff_wait(h, Some(&reply_slot), end, |badge| {
        if badge & trust::MEASURE_DONE_BADGE != 0 {
            if let Some(status) = unsafe { host::handoff::Mailbox::answer(mailbox, seq) } {
                return Some(if status == 0 { Ok(()) } else { Err(status as i64) });
            }
        }
        let status = unsafe { core::ptr::addr_of!((*p).status).read_volatile() };
        (status == trust::KEXEC_UNAVAILABLE).then_some(Err(crate::ctl::ENODEV))
    })
    .unwrap_or_else(|| {
        log!("l4h-root: trustd kexec measurement timed out");
        Err(crate::ctl::EIO)
    });
    let _ = h.trustd.as_ref().unwrap().comp.tcb.tcb_suspend();
    result
}

impl Trustd {
    /// Give vmmgr the flags: read-only at FLAGS_VA, and the capability to
    /// act on them for the console (root's, FLAGS_ROOT).
    pub fn give_vmmgr(&self, vmmgr: &Component, alloc: &mut Alloc, arena: &mut Arena, keep: &mut impl FnMut() -> sel4::AbsoluteCPtr) {
        vmmgr.give(l4h_host::vmmgr::SLOT_FLAGS_EP, self.flags_ep, CapRights::all());
        for (p, &f) in self.flags.iter().enumerate() {
            vmmgr.map_copy(alloc, arena, &abs_of(f), l4h_host::vmmgr::FLAGS_VA + p * PAGE, CapRights::read_only(), VmAttributes::DEFAULT, keep());
        }
    }

    /// Let trustd publish guest completions directly to vmmgr. This keeps its
    /// main thread independent of root while root waits for a measurement.
    /// It gets only vmmgr's attestation page, not root's events page.
    pub fn connect_completions(&mut self, vmmgr: &Component, attest: &sel4::AbsoluteCPtr, alloc: &mut Alloc) {
        let keep = self.comp.slot(trust::SLOT_ATTEST_EVENTS);
        self.comp.map_copy(alloc, &mut self.arena, attest, trust::ATTEST_EVENTS_VA, CapRights::read_write(), VmAttributes::DEFAULT, keep);
        self.comp.give_badged(trust::SLOT_VMMGR_NTFN, vmmgr.ntfn, CapRights::write_only(), l4h_host::vmmgr::BADGE_ROOT_EVENT);
    }

    /// The public PCR 15 extension value trustd published at init, or None
    /// when the firmware describes no TPM. EAGAIN while trustd is starting.
    /// ENODEV when a TPM exists but trustd cannot measure with it:
    /// bypassing it would let a kexec masquerade as the original cold boot.
    pub fn kexec_key(&self) -> Result<Option<[u8; 32]>, i64> {
        if self.no_reports || self.failed {
            return if self.tpm_found { Err(crate::ctl::ENODEV) } else { Ok(None) };
        }
        match unsafe { core::ptr::addr_of!((*self.kexec_state).status).read_volatile() } {
            trust::KEXEC_STARTING => Err(crate::ctl::EAGAIN),
            trust::KEXEC_READY => {
                core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
                Ok(Some(unsafe { core::ptr::addr_of!((*self.kexec_state).key_extension).read_volatile() }))
            }
            _ => Err(crate::ctl::ENODEV),
        }
    }

    /// Make guest `id`'s attestation device: its request page, cleared,
    /// copied into `page`, and a kick capability badged with its id, into
    /// `kick`.  False if trustd has failed.
    pub fn give(&self, id: usize, win: &mut Window, page: &sel4::AbsoluteCPtr, kick: &sel4::AbsoluteCPtr) -> bool {
        if self.failed { return false; }
        let p = self.pages[id];
        win.with_frame(&abs_of(p), |p| unsafe {
            // Do not carry any guest-writable state across instances.
            // If TPM initialization failed, trustd also sets NO_REPORTS
            // on the new guest's probe request before answering it.
            core::ptr::write_bytes(p, 0, PAGE);
            core::ptr::addr_of_mut!((*(p as *mut abi::AttestPage)).state)
                .write_volatile(if self.no_reports { abi::ATTEST_NO_REPORTS } else { 0 });
        });
        page.copy(&abs_of(p), CapRights::all()).expect("attestation page");
        kick.mint(&abs_of(self.kick), CapRights::write_only(), trust::kick_badge(id)).expect("attestation kick");
        true
    }

    /// Guest `id`, instance `instance`, starts: its reports describe it
    /// from now on.
    pub fn register(&mut self, id: usize, instance: u64, record: GuestRecord) {
        if self.failed { return; }
        let p = self.registry.wrapping_add(id);
        unsafe {
            p.write_volatile(record);
            core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
            core::ptr::addr_of_mut!((*p).instance).write_volatile(instance);
        }
    }

    /// Guest `id` is destroyed.
    pub fn unregister(&mut self, id: usize) {
        unsafe { core::ptr::addr_of_mut!((*self.registry.wrapping_add(id)).instance).write_volatile(0) };
    }

    /// The main thread faulted (the firmware's AML can make it panic): stop it,
    /// mark every guest's page failed and answer what it asked with -EIO,
    /// so that no guest waits for good.  New guests get no attestation.
    fn fail(&mut self, h: &mut Host) {
        self.failed = true;
        unsafe {
            core::ptr::addr_of_mut!((*self.kexec_state).status).write_volatile(trust::KEXEC_UNAVAILABLE);
        }
        let _ = self.comp.tcb.tcb_suspend();
        let kick = abs_of(self.kick);
        let _ = kick.revoke();
        for id in 0..h.guests.len() {
            if h.guests[id].as_ref().is_none_or(|g| !g.attest) {
                continue;
            }
            h.wins.a.with_frame(&abs_of(self.pages[id]), |p| unsafe {
                let p = p as *mut abi::AttestPage;
                core::ptr::addr_of_mut!((*p).state).write_volatile(abi::ATTEST_FAILED);
                let seq = core::ptr::addr_of!((*p).seq).read_volatile();
                core::ptr::addr_of_mut!((*p).status).write_volatile(-(crate::ctl::EIO as i32));
                core::ptr::addr_of_mut!((*p).total).write_volatile(0);
                core::ptr::addr_of_mut!((*p).out_len).write_volatile(0);
                core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
                core::ptr::addr_of_mut!((*p).done).write_volatile(seq);
            });
            done(h, id);
        }
        log!("l4h-root: trustd failed, no attestation");
    }
}

/// Stop a failed main thread, retaining the independent flags server.
pub fn fault(h: &mut Host, id: u32) {
    assert!(id != FLAGS_ID, "l4h-root: flags thread faulted");
    if id == TRUSTD_ID {
        if let Some(mut t) = h.trustd.take() {
            t.fail(h);
            h.trustd = Some(t);
        }
    }
}

/// Raise a failed guest request's event through vmmgr. Normal trustd
/// completions use the shared attestation page directly and do not call root.
pub fn done(h: &mut Host, id: usize) {
    if h.guests.get(id).and_then(|g| g.as_ref()).is_some_and(|g| g.attest) {
        if let Some(v) = &h.vmmgr {
            v.attest_done(id);
        }
    }
}

/// ROOT_CALL_HW from trustd: one access the firmware's AML makes
/// (trust::HW_*).  Returns what it read (all ones when refused).
#[cfg(target_arch = "x86_64")]
pub fn hw(h: &mut Host) -> u64 {
    let (op, addr, off, width, value) = (mr(0), mr(1) as usize, mr(2) as usize, mr(3) as usize, mr(4));
    let write = op & 1 != 0;
    let r = match op {
        trust::HW_MEM_READ | trust::HW_MEM_WRITE => {
            let Some(t) = h.trustd.as_mut() else { return u64::MAX };
            crate::acpi::Phys::new(&mut h.alloc, &mut h.devmem, &mut h.wins.a, &mut t.frames).access(addr, width, write, value)
        }
        trust::HW_IO_READ | trust::HW_IO_WRITE => io(&mut h.alloc, addr, width, write, value),
        trust::HW_PCI_READ | trust::HW_PCI_WRITE => {
            let (bus, dev, func) = ((addr >> 8) as u8, (addr >> 3 & 0x1f) as u8, (addr & 7) as u8);
            let driven = h.ctrls.iter().map(|c| &c.pci).chain(h.netd.nics.iter().map(|n| &n.pci))
                .any(|d| (d.bus, d.dev, d.func) == (bus, dev, func));
            if addr >> 16 != 0 || off + width > 256 || off % width != 0 || !matches!(width, 1 | 2 | 4) || (write && driven) {
                None
            } else {
                let (word, shift) = (off as u8 & !3, (off % 4) * 8);
                let old = h.pci.read32(bus, dev, func, word);
                let mask = if width == 4 { u32::MAX } else { ((1u32 << (8 * width)) - 1) << shift };
                if write {
                    h.pci.write32(bus, dev, func, word, (old & !mask) | ((value as u32) << shift & mask));
                }
                Some(((old & mask) >> shift) as u64)
            }
        }
        _ => None,
    };
    r.unwrap_or_else(|| {
        info!("l4h-root: trustd: refused hardware access {} at {:#x}+{:#x}", op, addr, off);
        u64::MAX
    })
}

#[cfg(not(target_arch = "x86_64"))]
pub fn hw(_h: &mut Host) -> u64 {
    u64::MAX
}

/// An I/O port access, through a capability for just those ports: seL4
/// refuses ports already given out (the serial port, PCI configuration,
/// legacy NICs).
#[cfg(target_arch = "x86_64")]
fn io(alloc: &mut Alloc, port: usize, width: usize, write: bool, value: u64) -> Option<u64> {
    if !matches!(width, 1 | 2 | 4) || port + width > 0x1_0000 {
        return None;
    }
    let cap = crate::pci::io_ports(alloc, port as u16, width as u16)?;
    let (c, p) = (cap.bits(), port as u16);
    let r = sel4::with_ipc_buffer_mut(|ipc| {
        let ipc = ipc.inner_mut();
        match (width, write) {
            (1, false) => ipc.seL4_X86_IOPort_In8(c, p).result as u64,
            (2, false) => ipc.seL4_X86_IOPort_In16(c, p).result as u64,
            (_, false) => ipc.seL4_X86_IOPort_In32(c, p).result as u64,
            (1, true) => {
                ipc.seL4_X86_IOPort_Out8(c, p as u64, value);
                0
            }
            (2, true) => {
                ipc.seL4_X86_IOPort_Out16(c, p as u64, value);
                0
            }
            (_, true) => {
                ipc.seL4_X86_IOPort_Out32(c, p as u64, value);
                0
            }
        }
    });
    let _ = abs_of(cap).delete();
    alloc.slots.free(cap.bits() as usize);
    Some(r)
}

/// trustd's passive flags server. Its temporary SC is unbound after the
/// initial reply_recv handshake; thereafter only callers supply budget.
fn flags_thread(c: &Component, alloc: &mut Alloc, arena: &mut Arena, info: &HostInfo) -> cap::SchedContext {
    use host::trust;
    let mut ctx = ObjCtx::arena(alloc, arena);
    let tcb = ctx.cap::<cap_type::Tcb>(ObjectBlueprint::Tcb);
    let sc = ctx.cap::<cap_type::SchedContext>(ObjectBlueprint::SchedContext {
        size_bits: sel4::sys::seL4_MinSchedContextBits as usize,
    });
    let ipc = ctx.cap::<cap_type::Granule>(FRAME_BP);
    let reply = ctx.cap::<cap_type::Reply>(ObjectBlueprint::Reply);
    map_frame(&mut ctx, c.vspace, ipc, trust::FLAGS_IPCBUF_VA, CapRights::read_write(), VmAttributes::DEFAULT);
    for va in (trust::FLAGS_STACK_TOP - trust::FLAGS_STACK_SIZE..trust::FLAGS_STACK_TOP).step_by(PAGE) {
        let f = ctx.cap::<cap_type::Granule>(FRAME_BP);
        map_frame(&mut ctx, c.vspace, f, va, CapRights::read_write(), VmAttributes::DEFAULT);
    }
    let fault_slot = ctx.alloc.slots.alloc();
    abs_of(root_cap::<cap_type::Null>(fault_slot))
        .mint(&abs_of(info.hyp_ep), CapRights::all(), component_badge(FLAGS_ID) | crate::HYP_BADGE_FAULT)
        .expect("flags fault ep");
    tcb.tcb_configure(c.cnode, CNodeCapData::new(0, 64 - c.cnode_bits), c.vspace, trust::FLAGS_IPCBUF_VA as u64, ipc)
        .expect("flags TCB configure");
    info.sched_control(info.cores - 1).sched_control_configure_flags(sc, info.timeslice_us, info.timeslice_us, 0, 0, 0)
        .expect("flags bootstrap SC");
    // Root is the initial task, at the maximum priority.
    let prio = 255;
    tcb.tcb_set_sched_params(crate::slot::TCB.cap(), prio, prio, sc, root_cap::<cap_type::Endpoint>(fault_slot))
        .expect("flags sched params");
    c.give(trust::SLOT_FLAGS_TCB, tcb, CapRights::all());
    c.give(trust::SLOT_FLAGS_REPLY, reply, CapRights::all());
    sc
}

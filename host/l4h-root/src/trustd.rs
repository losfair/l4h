//! The attestation service, l4h-trustd (DESIGN.md §10.2): finding the TPM,
//! starting trustd with it and its flags server, making guests'
//! attestation devices (vmmgr adds them to guests), the registry page
//! through which trustd learns about guests, and what trustd asks root
//! for: raising a device's event when it has answered (vmmgr raises it),
//! and the hardware accesses of its AML interpreter.
//!
//! Only x86 finds a TPM (in ACPI) so far; other hosts run flags only.  In
//! a multikernel secondary, which has no TPM, trustd has the primary's
//! trustd quote its key and run its ActivateCredential, through the relay
//! pages and the control channel (trust::RELAY_*).
#![cfg_attr(not(target_arch = "x86_64"), allow(dead_code, unused_imports))]


use core::cell::Cell;
use core::sync::atomic::{Ordering, fence};

use sel4::{CapRights, ObjectBlueprint, VmAttributes, cap, cap_type};

use l4h_abi as abi;
use l4h_host as host;
use l4h_host::fixed::ArrayVec;
use l4h_host::wiring;
use l4h_host::trust::{self, GuestRecord, TrustdConfig};

use crate::component::{self, Component, Obj, SpawnArgs, abs_of, o, p};
use crate::devmem::DevMem;
use crate::mem::{Alloc, Arena, ObjCtx};
use crate::vspace::{FRAME_BP, map_frame};
use crate::window::Window;
use crate::{AsidPools, Host, HostInfo};

pub use l4h_host::trust::AML_MAX;

static TRUSTD_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/l4h-trustd.elf"));

const PAGE: usize = 4096;
pub use l4h_host::root::{FLAGS_ID, TRUSTD_ID};
/// The registry page in the root task.
const REGISTRY_VA: usize = crate::layout::TRUSTD_REGISTRY.base;
/// Mapping capabilities trustd's ranges and AML pages, and the flags
/// server's pages, can need.
const KEEP_BITS: usize = 12;

pub struct Trustd {
    comp: Component,
    /// The flags server (host::KIND_FLAGS), on a scheduling context of
    /// its own (trust::FLAGS_BUDGET_US).
    flags_server: Component,
    #[allow(dead_code)]
    arena: Arena,
    registry: *mut GuestRecord,
    no_reports: bool,
    failed: bool,
    /// Multikernel: the kick, badged trust::RELAY_BADGE, to tell trustd about a
    /// message in its relay inbox.
    relay: Option<cap::Notification>,
    /// The two request pages of each guest id, mapped in trustd
    /// (trust::page_of), and which of them the id's guest has (the second:
    /// true).
    pages: [[cap::Granule; 2]; trust::MAX_RECORDS],
    second: [Cell<bool>; trust::MAX_RECORDS],
    /// trustd's status page (trust::Status), which root reads through its
    /// window.
    status: cap::Granule,
    /// Guests signal it, badged with badges::trustd_kick::GUEST bit id.
    kick: cap::Notification,
    /// The flags table: the flags server maps it writable, trustd, root and
    /// vmmgr read-only.
    flags: [cap::Granule; trust::FLAGS_SIZE / PAGE],
    /// What the ACPI start method's AML may reach (`hw`); None for every
    /// other TPM interface, whose trustd gets no hardware access.
    #[cfg(target_arch = "x86_64")]
    hw: Option<Hw>,
    /// Refused accesses (`hw`) that root logs: trustd asks as often as it
    /// likes, and must not fill root's log with them.
    hw_refusals: host::log::RateLimit<1>,
}

/// What `hw` serves trustd's AML from, and refuses it.
#[cfg(target_arch = "x86_64")]
struct Hw {
    /// The device pages it touched, a table of its own (acpi::Frames::hw).
    frames: crate::acpi::Frames,
    /// The MCFG's ECAM windows, of every segment, and whether these are
    /// all of them.  If the firmware lists more than root keeps, no memory
    /// write is served: any could be a configuration write.
    ecam: ArrayVec<trust::Ecam, { trust::MAX_ECAM }>,
    ecam_complete: bool,
    /// I/O ports that reset the machine, put it to sleep or enter SMM:
    /// (first, count).
    ports: ArrayVec<(usize, usize), 16>,
}

#[cfg(target_arch = "x86_64")]
impl Hw {
    /// From the firmware's tables, read with `phys`.
    fn find(bootinfo: &sel4::BootInfoPtr, phys: &mut crate::acpi::Phys) -> Hw {
        let mut hw = Hw { frames: crate::acpi::Frames::hw(), ecam: ArrayVec::new(), ecam_complete: true, ports: ArrayVec::new() };
        // The keyboard controller's and port A's reset, APM's SMI command
        // and data, the reset control register.
        for r in [(0x60, 1), (0x64, 1), (0x92, 1), (0xb2, 2), (0xcf9, 1)] {
            let _ = hw.ports.push(r);
        }
        let mut buf = [0; crate::acpi::FADT_LEN];
        if let Some(f) = crate::acpi::find(bootinfo, phys, b"FACP", &mut buf) {
            let u8_at = |i: usize| f.get(i).map_or(0, |&b| b as usize);
            let u32_at = |i: usize| f.get(i..i + 4).map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap()) as usize);
            // SMI_CMD, PM1a/b_CNT_BLK (sleep), PM2_CNT_BLK.
            for (at, len) in [(48, 1), (64, u8_at(89)), (68, u8_at(89)), (72, u8_at(90))] {
                let port = u32_at(at);
                if port != 0 && port < 0x1_0000 {
                    let _ = hw.ports.push((port, len.max(1)));
                }
            }
            // X_PM1a/b_CNT_BLK and X_PM2_CNT_BLK in I/O space (space 1).
            for at in [172, 184, 196] {
                let addr = f.get(at + 4..at + 12).map_or(0, |b| u64::from_le_bytes(b.try_into().unwrap()));
                if u8_at(at) == 1 && addr != 0 && addr < 0x1_0000 {
                    let _ = hw.ports.push((addr as usize, (u8_at(at + 1) / 8).max(1)));
                }
            }
        }
        // Every ECAM window, or the AML writes no memory: a write into
        // one root does not know of would go unchecked.
        let mut buf = [0; trust::MCFG_MAX];
        match crate::acpi::find_len(bootinfo, phys, b"MCFG", &mut buf) {
            Ok(None) => {}
            Ok(Some((t, len))) => (hw.ecam, hw.ecam_complete) = trust::mcfg_windows(t, len),
            Err(crate::acpi::Unreadable) => hw.ecam_complete = false,
        }
        if !hw.ecam_complete {
            log!("l4h-root: the MCFG cannot be read, or lists more than {} ECAM windows: the TPM's AML gets no memory writes", trust::MAX_ECAM);
        }
        hw
    }

    /// Whether ports [port, port + width) are any of `ports`.
    fn refused_port(&self, port: usize, width: usize) -> bool {
        self.ports.iter().any(|&(p, n)| port < p + n && p < port + width)
    }

    /// The PCI function whose ECAM page `paddr` is in, if it is one, and
    /// the offset in its configuration space: (segment, bus, device,
    /// function, offset).
    fn ecam_function(&self, paddr: usize) -> Option<(u16, u8, u8, u8, usize)> {
        self.ecam.iter().find_map(|w| w.function(paddr).map(|(bus, dev, func, off)| (w.segment, bus, dev, func, off)))
    }
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
        // The firmware's or the TPM's: the end must not wrap.
        let base = paddr & !(PAGE - 1);
        let size = paddr.checked_add(len)?.checked_next_multiple_of(PAGE)? - base;
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
            partition: crate::partition::get().map_or(0, |d| d.index),
            partitions: crate::partition::get().map_or(1, |d| d.count),
        }
    }
}

/// The TPM, from its ACPI table (DESIGN.md §10.2).
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
) -> Option<Trustd> {
    if TRUSTD_ELF.is_empty() {
        return None;
    }
    #[cfg(target_arch = "x86_64")]
    {
        // A secondary's TPM is the primary's, over the control channel.
        let to_primary = crate::partition::get()
            .is_some_and(|d| d.channels().iter().any(|c| c.peer == 0 && c.kind & l4h_partition::CHANNEL_CONTROL != 0));
        if crate::partition::secondary() {
            let iface = if to_primary { trust::TPM_REMOTE } else { trust::TPM_NONE };
            return without_tpm(alloc, win, asids, info, iface);
        }
        let mut frames = frames;
        let mut phys = crate::acpi::Phys::new(alloc, devmem, win, &mut frames);
        let Some(l) = find_tpm(bootinfo, &mut phys) else {
            return flags_only(alloc, win, asids, info);
        };
        // The pages of each range, which stay in `frames`.
        for &(base, size) in &l.ranges {
            if (0..size / PAGE).any(|p| phys.frame(base + p * PAGE).is_none()) {
                log!("l4h-root: TPM at {:#x} is not device memory, no attestation", base);
                return flags_only(alloc, win, asids, info);
            }
        }
        // The AML's size.  Its pages are carved now, so that copying it
        // once trustd exists cannot fail for want of them.
        let aml_size = match l.start {
            trust::START_ACPI => {
                let touch = |phys: &mut crate::acpi::Phys, pa: usize, len: usize| {
                    (pa & !(PAGE - 1)..pa.checked_add(len)?).step_by(PAGE).try_for_each(|p| phys.frame(p).map(drop))
                };
                match crate::acpi::aml_tables(bootinfo, &mut phys, touch) {
                    Some(n) => n,
                    None => {
                        log!("l4h-root: cannot read the ACPI tables for the TPM, no attestation");
                        return flags_only(alloc, win, asids, info);
                    }
                }
            }
            _ => 0,
        };
        // Only the ACPI start method runs AML, which needs root's hardware.
        let hw = (l.start == trust::START_ACPI).then(|| Hw::find(bootinfo, &mut phys));
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
        let cfg = l.config(aml_size);
        let (comp, flags_server, arena, keep) = create(&cfg, alloc, win, asids, info, aml_size)?;
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
                    phys.read_into(pa.checked_add(done)?, &mut buf[..n])?;
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
                return flags_only(alloc, win, asids, info);
            }
        }
        finish(comp, flags_server, arena, alloc, &mut keep_slot, false, hw)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (bootinfo, devmem);
        flags_only(alloc, win, asids, info)
    }
}

/// The same flags service on machines with no usable TPM.
fn flags_only(alloc: &mut Alloc, win: &mut Window, asids: &mut AsidPools, info: &HostInfo) -> Option<Trustd> {
    without_tpm(alloc, win, asids, info, trust::TPM_NONE)
}

/// trustd with no TPM of its own: flags only, or (TPM_REMOTE) the
/// primary's TPM through the relay.
fn without_tpm(alloc: &mut Alloc, win: &mut Window, asids: &mut AsidPools, info: &HostInfo, iface: u32) -> Option<Trustd> {
    let cfg = TrustdConfig { iface, ..Layout::default().config(0) };
    let (comp, flags_server, arena, keep) = create(&cfg, alloc, win, asids, info, 0)?;
    let mut next = 0;
    finish(comp, flags_server, arena, alloc, &mut || {
        let slot = keep.absolute_cptr_from_bits_with_depth(next, KEEP_BITS);
        next += 1;
        slot
    }, iface == trust::TPM_NONE, #[cfg(target_arch = "x86_64")] None)
}

/// Create trustd with configuration `cfg`, its flags server, and the CNode
/// that keeps their mapping capabilities.
fn create(
    cfg: &TrustdConfig,
    alloc: &mut Alloc,
    win: &mut Window,
    asids: &mut AsidPools,
    info: &HostInfo,
    aml_size: usize,
) -> Option<(Component, Component, Arena, cap::CNode)> {
    // trustd and the flags server are an image each (with the AML
    // interpreter's heap), and trustd has the AML's copy.
    let mut arena = alloc.arena((12 << 20) + 2 * aml_size).expect("memory for trustd and flags service");
    let cfg_bytes = unsafe {
        core::slice::from_raw_parts(cfg as *const TrustdConfig as *const u8, core::mem::size_of::<TrustdConfig>())
    };
    let args = SpawnArgs {
        id: TRUSTD_ID,
        kind: host::KIND_TRUSTD,
        elf: TRUSTD_ELF,
        prio: host::PRIO_VMM,
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
    // The flags server: the same image, with spaces of its own, so that
    // nothing trustd's main thread does (it parses guests' pages and runs
    // the firmware's AML) reaches the flags but its calls.  It runs at
    // root's priority, the maximum, so that no caller waits behind
    // another thread, on a scheduling context of its own, as its keeper
    // does: a tenth of a core each at most (trust::FLAGS_BUDGET_US), which
    // a caller's flood can use up and nothing more.  It never runs on a
    // caller's: a server without a scheduling context would stop for good
    // on a message sent without a call, which donates none, and its
    // callers with it.
    let args = SpawnArgs {
        id: FLAGS_ID,
        kind: host::KIND_FLAGS,
        elf: TRUSTD_ELF,
        prio: 255,
        budget_us: trust::FLAGS_BUDGET_US,
        period_us: trust::FLAGS_PERIOD_US,
        config: &[],
        ntfn: None,
        service_ep: None,
        cnode: None,
        cnode_bits: None,
    };
    let flags_server = component::create(
        &args, alloc, &mut arena, win, &mut |alloc, vspace| asids.assign(alloc, vspace),
        &info.spawn_context(info.cores - 1),
    );
    let keep = arena.object_cap::<cap_type::CNode>(alloc, ObjectBlueprint::CNode { size_bits: KEEP_BITS });
    Some((comp, flags_server, arena, keep))
}

/// Map the registry, request, status and flags pages, give trustd its
/// kick notification and its capability to the flags server, start the
/// flags server, then trustd.
fn finish(
    comp: Component,
    flags_server: Component,
    mut arena: Arena,
    alloc: &mut Alloc,
    keep: &mut impl FnMut() -> sel4::AbsoluteCPtr,
    no_reports: bool,
    #[cfg(target_arch = "x86_64")]
    hw: Option<Hw>,
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
    for c in [&comp, &flags_server] {
        c.map_copy(alloc, &mut arena, &abs_of(registry), trust::REGISTRY_VA, CapRights::read_only(), VmAttributes::DEFAULT, keep());
    }
    let pages = core::array::from_fn(|g| {
        [false, true].map(|b| {
            let f = arena.object_cap::<cap_type::Granule>(alloc, FRAME_BP);
            comp.map_copy(alloc, &mut arena, &abs_of(f), trust::page_va(trust::page_of(g, b)), CapRights::read_write(), VmAttributes::DEFAULT, keep());
            f
        })
    });
    let status = arena.object_cap::<cap_type::Granule>(alloc, FRAME_BP);
    comp.map_copy(alloc, &mut arena, &abs_of(status), trust::STATUS_VA, CapRights::read_write(), VmAttributes::DEFAULT, keep());
    let kick = arena.object_cap::<cap_type::Notification>(alloc, ObjectBlueprint::Notification);
    comp.give(trust::SLOT_KICK, kick, CapRights::all());
    // The relay pages, shared with root, when there are other partitions.
    let relay = crate::partition::get().filter(|d| d.count > 1).map(|_| {
        for p in 0..trust::RELAY_PAGES {
            let f = arena.object_cap::<cap_type::Granule>(alloc, FRAME_BP);
            comp.map_copy(alloc, &mut arena, &abs_of(f), trust::RELAY_VA + p * PAGE, CapRights::read_write(), VmAttributes::DEFAULT, keep());
            map_frame(&mut ObjCtx::global(alloc), sel4::init_thread::slot::VSPACE.cap(), f,
                crate::layout::TRUSTD_RELAY.base + p * PAGE, CapRights::read_write(), VmAttributes::DEFAULT);
        }
        let slot = alloc.slots.alloc();
        let badged = sel4::init_thread::Slot::<cap_type::Notification>::from_index(slot).cap();
        component::mint_edge(&abs_of(badged), &wiring::ROOT_TRUSTD_RELAY, 0, &Obj::claim(p::Trustd, o::Kick, abs_of(kick))).expect("relay kick");
        badged
    });
    // The flags: writable only in the flags server.
    let flags = core::array::from_fn(|p| {
        let f = arena.object_cap::<cap_type::Granule>(alloc, FRAME_BP);
        flags_server.map_copy(alloc, &mut arena, &abs_of(f), trust::FLAGS_VA + p * PAGE, CapRights::read_write(), VmAttributes::DEFAULT, keep());
        comp.map_copy(alloc, &mut arena, &abs_of(f), trust::FLAGS_VA + p * PAGE, CapRights::read_only(), VmAttributes::DEFAULT, keep());
        map_frame(&mut ObjCtx::global(alloc), sel4::init_thread::slot::VSPACE.cap(), f,
            crate::layout::TRUSTD_FLAGS.base + p * PAGE, CapRights::read_only(), VmAttributes::DEFAULT);
        f
    });
    let flags_obj = flags_server.obj::<p::Flags, o::Endpoint>();
    comp.give_edge(&wiring::TRUSTD_FLAGS, 0, 0, &flags_obj);
    let slot = alloc.slots.alloc();
    let flags_ep = sel4::init_thread::Slot::<cap_type::Endpoint>::from_index(slot).cap();
    component::mint_edge(&abs_of(flags_ep), &wiring::ROOT_FLAGS, 0, &flags_obj).expect("root flags endpoint");
    component::start(&flags_server);
    // Root's one call to it, before any guest exists: the server answers
    // once it serves its endpoint.  One that failed meanwhile answers
    // FAILED (its keeper), as it does every later call: their actions are
    // refused.  It keeps its scheduling context (`create`).
    {
        use l4h_host::trust::call::Client;
        if l4h_ipc::Endpoint::chosen(&wiring::ROOT_FLAGS, wiring::p::Root, flags_ep).ready().is_err() {
            log!("l4h-root: the flags server failed: no guest action can be recorded");
        }
    }
    let _ = abs_of(flags_ep).delete();
    alloc.slots.free(slot);
    component::start(&comp);
    Some(Trustd { comp, flags_server, arena, registry: REGISTRY_VA as *mut GuestRecord,
        no_reports, failed: false, relay, pages, second: core::array::from_fn(|_| Cell::new(false)), status, kick, flags,
        #[cfg(target_arch = "x86_64")] hw, hw_refusals: host::log::RateLimit::new() })
}

impl Trustd {
    /// trustd's kick notification, which root made.
    fn kick_obj(&self) -> Obj<p::Trustd, o::Kick> {
        Obj::claim(p::Trustd, o::Kick, abs_of(self.kick))
    }

    /// Give vmmgr the flags: read-only at FLAGS_VA, and the capability to
    /// act on them for the console (its own, badged Sender::Vmmgr:
    /// wiring::VMMGR_FLAGS).
    pub fn give_vmmgr(&self, vmmgr: &Component, alloc: &mut Alloc, arena: &mut Arena, keep: &mut impl FnMut() -> sel4::AbsoluteCPtr) {
        vmmgr.give_edge(&wiring::VMMGR_FLAGS, 0, 0, &self.flags_server.obj::<p::Flags, o::Endpoint>());
        for (p, &f) in self.flags.iter().enumerate() {
            vmmgr.map_copy(alloc, arena, &abs_of(f), l4h_host::vmmgr::FLAGS_VA + p * PAGE, CapRights::read_only(), VmAttributes::DEFAULT, keep());
        }
    }

    /// Make guest `id`'s attestation device: its request page, cleared,
    /// copied into `page`, and a kick capability badged with its id, into
    /// `kick`.  False if trustd has failed.
    pub fn give(&self, id: usize, win: &mut Window, page: &sel4::AbsoluteCPtr, kick: &sel4::AbsoluteCPtr) -> bool {
        if self.failed { return false; }
        // The id's last guest is unregistered.  If trustd may still be
        // writing an answer for it into its page, this guest gets the
        // other one (trust::Status).
        fence(Ordering::SeqCst);
        let answering = win.with_frame(&abs_of(self.status), |p| unsafe {
            (*(p as *const trust::Status)).answering.load(Ordering::SeqCst)
        });
        let second = &self.second[id];
        if answering == trust::page_of(id, second.get()) as u64 + 1 {
            second.set(!second.get());
        }
        let p = self.pages[id][second.get() as usize];
        win.with_frame(&abs_of(p), |p| unsafe {
            // Do not carry any guest-writable state across instances.
            // If TPM initialization failed, trustd also sets NO_REPORTS
            // on the new guest's probe request before answering it.
            core::ptr::write_bytes(p, 0, PAGE);
            core::ptr::addr_of_mut!((*(p as *mut abi::AttestPage)).state)
                .write_volatile(if self.no_reports { abi::ATTEST_NO_REPORTS } else { 0 });
        });
        page.copy(&abs_of(p), CapRights::all()).expect("attestation page");
        component::mint_edge(kick, &wiring::GUEST_TRUSTD, id, &self.kick_obj()).expect("attestation kick");
        true
    }

    /// Guest `id`, instance `instance`, starts: its reports describe it
    /// from now on.  False, and nothing changes, if it is registered
    /// already: a running guest's record stays as it is, and its instance
    /// never reads as 0, which would let trustd drop an answer and the
    /// flags server take another instance for it.
    pub fn register(&mut self, id: usize, instance: u64, record: GuestRecord) -> bool {
        if self.failed { return true; }
        let p = self.registry.wrapping_add(id);
        let page = if self.second[id].get() { trust::RECORD_PAGE_B } else { 0 };
        unsafe {
            if core::ptr::addr_of!((*p).instance).read_volatile() != 0 {
                return false;
            }
            // Every other field, then the instance.
            core::ptr::addr_of_mut!((*p).ram).write_volatile(record.ram);
            core::ptr::addr_of_mut!((*p).vcpus).write_volatile(record.vcpus);
            core::ptr::addr_of_mut!((*p).flags).write_volatile(record.flags & !trust::RECORD_PAGE_B | page);
            core::ptr::addr_of_mut!((*p).launch).write_volatile(record.launch);
            core::ptr::addr_of_mut!((*p).reserved).write_volatile(0);
            core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
            core::ptr::addr_of_mut!((*p).instance).write_volatile(instance);
        }
        true
    }

    /// Guest `id` is destroyed.  Before its id is given again (`give`):
    /// trustd either sees it gone or has said which page it answers in.
    pub fn unregister(&mut self, id: usize) {
        unsafe { core::ptr::addr_of_mut!((*self.registry.wrapping_add(id)).instance).write_volatile(0) };
        fence(Ordering::SeqCst);
    }

    /// The main thread faulted (the firmware's AML can make it panic): stop it,
    /// mark every guest's page failed and answer what it asked with -EIO,
    /// so that no guest waits for good.  New guests get no attestation.
    fn fail(&mut self, h: &mut Host) {
        self.failed = true;
        let _ = self.comp.tcb.tcb_suspend();
        let kick = abs_of(self.kick);
        let _ = kick.revoke();
        for id in 0..h.guests.len() {
            if h.guests[id].as_ref().is_none_or(|g| !g.attest) {
                continue;
            }
            h.wins.a.with_frame(&abs_of(self.pages[id][self.second[id].get() as usize]), |p| unsafe {
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

/// A fault of trustd's main thread: stop it (`fail`).  The flags server
/// is a component of its own, which the main thread cannot reach but by
/// its calls: its faults go to its keeper, which answers every call FAILED
/// from then on (the actions they were for are refused, so seals stay
/// enforced); only the keeper's own faults come here.
pub fn fault(h: &mut Host, id: u32) {
    match id {
        TRUSTD_ID => {
            if let Some(mut t) = h.trustd.take() {
                t.fail(h);
                h.trustd = Some(t);
            }
        }
        FLAGS_ID => log!("l4h-root: the flags server's keeper faulted"),
        _ => {}
    }
}

/// `attest_done`: trustd answered guest `id`; vmmgr raises the
/// event of its attestation device.
pub fn done(h: &mut Host, id: usize) {
    if h.guests.get(id).and_then(|g| g.as_ref()).is_some_and(|g| g.attest) {
        if let Some(v) = h.vmmgr.as_mut() {
            v.attest_done(id);
        }
    }
}

/// `hw` from trustd: one access the firmware's AML makes (trust::HW_*),
/// served only for the ACPI start method.  Returns what it read (all ones
/// when refused).  trustd's main thread runs that AML and parses guests'
/// pages, so root takes its requests for an attacker's and serves only
/// what cannot reach beyond the hardware root has no use for:
///
/// - memory that is free device memory: not RAM, and not what root carved
///   for itself or a driver, which its frame table cannot have again.  On
///   a machine split into partitions, only where it is known to be no
///   partition's memory (`partition_allows`);
/// - I/O ports seL4 has not issued, other than those that reset the
///   machine, put it to sleep or enter SMM;
/// - of the BARs of the functions root drives, nothing;
/// - PCI configuration, by the configuration mechanism or through ECAM:
///   reads; writes only to functions root does not manage (`managed`),
///   and in no function to the command register, the BARs or the
///   expansion ROM's (trust::hw_config_write_protected), so that the AML
///   neither moves a device onto another's addresses nor lets one master
///   the bus.
///
/// Refusals are logged a few a second at most.
#[cfg(target_arch = "x86_64")]
pub fn hw(h: &mut Host, op: u64, addr: usize, off: usize, width: usize, value: u64) -> u64 {
    match hw_access(h, op, addr, off, width, value) {
        Ok(read) => read,
        Err(why) => {
            let (now, hz) = (host::ticks::now(), h.info.tsc_hz);
            if let Some(more) = h.trustd.as_mut().and_then(|t| t.hw_refusals.allow(0, now, hz)) {
                info!("l4h-root: trustd: refused hardware access {} at {:#x}+{:#x}: {}{}", op, addr, off, why, more);
            }
            u64::MAX
        }
    }
}

/// `hw`: what was read (0 for a write), or why the access is refused.
#[cfg(target_arch = "x86_64")]
fn hw_access(h: &mut Host, op: u64, addr: usize, off: usize, width: usize, value: u64) -> Result<u64, &'static str> {
    let write = op & 1 != 0;
    let Some(hw) = h.trustd.as_ref().and_then(|t| t.hw.as_ref()) else { return Err("no ACPI start method") };
    let r = match op {
        trust::HW_MEM_READ | trust::HW_MEM_WRITE => {
            // `addr` and `width` are trustd's: the access must not wrap,
            // and, aligned, lies in one page.
            if !matches!(width, 1 | 2 | 4 | 8) || addr % width != 0 || addr.checked_add(width).is_none() {
                return Err("bad width or address");
            }
            if !partition_allows(addr, width) {
                return Err("not known to be outside the partitions' memory");
            }
            if write {
                if !hw.ecam_complete {
                    return Err("a memory write, with more ECAM windows than root knows");
                }
                if let Some((segment, b, d, f, o)) = hw.ecam_function(addr) {
                    if trust::hw_config_write_protected(o, width) {
                        return Err("a function's command register, BARs or ROM");
                    }
                    // Root reads only segment 0, and cannot tell what a
                    // function of another is.
                    if segment != 0 || managed(h, b, d, f) {
                        return Err("configuration of a function root manages");
                    }
                }
            }
            if in_bars(h, addr, width, false) {
                return Err("a BAR of a function root manages");
            }
            let Some(hw) = h.trustd.as_mut().and_then(|t| t.hw.as_mut()) else { return Err("no ACPI start method") };
            crate::acpi::Phys::new(&mut h.alloc, &mut h.devmem, &mut h.wins.a, &mut hw.frames).access(addr, width, write, value)
        }
        trust::HW_IO_READ | trust::HW_IO_WRITE => {
            if !matches!(width, 1 | 2 | 4) || addr.checked_add(width).is_none_or(|e| e > 0x1_0000) {
                return Err("bad width or port");
            }
            if hw.refused_port(addr, width) || in_bars(h, addr, width, true) {
                return Err("a port the AML has no business with");
            }
            io(&mut h.alloc, addr, width, write, value)
        }
        trust::HW_PCI_READ | trust::HW_PCI_WRITE => {
            let (bus, dev, func) = ((addr >> 8) as u8, (addr >> 3 & 0x1f) as u8, (addr & 7) as u8);
            // Width first: the `off % width` and `off + width` below are
            // undefined or overflow for a width (or offset) trustd chose
            // badly, and a panic here is the whole host.
            if !matches!(width, 1 | 2 | 4) || addr >> 16 != 0 || off.checked_add(width).is_none_or(|e| e > 256)
                || off % width != 0 {
                return Err("bad width or offset");
            }
            if write && trust::hw_config_write_protected(off, width) {
                return Err("a function's command register, BARs or ROM");
            }
            if write && managed(h, bus, dev, func) {
                return Err("configuration of a function root manages");
            }
            let (word, shift) = (off as u8 & !3, (off % 4) * 8);
            let old = h.pci.read32(bus, dev, func, word);
            let mask = if width == 4 { u32::MAX } else { ((1u32 << (8 * width)) - 1) << shift };
            if write {
                h.pci.write32(bus, dev, func, word, (old & !mask) | ((value as u32) << shift & mask));
            }
            Some(((old & mask) >> shift) as u64)
        }
        _ => return Err("no such access"),
    };
    r.ok_or("in use, or not device memory")
}

/// Whether memory [addr, addr + width) may be the AML's on this machine,
/// as far as partitions go.  With the machine to itself root knows its RAM
/// from the device memory seL4 gave it.  One of several partitions does
/// not: the others' RAM, their kernels and the memory the shim shares
/// between them are all device memory to this kernel, and the partition
/// descriptor does not list them.  So there the AML gets memory only where
/// it cannot be any of that: the chipset's addresses below 4 GiB
/// (trust::HW_CHIPSET), the ECAM window, and the memory BARs of this
/// partition's own PCI functions.
#[cfg(target_arch = "x86_64")]
fn partition_allows(addr: usize, width: usize) -> bool {
    let Some(d) = crate::partition::get().filter(|d| d.count > 1) else { return true };
    let within = |base: u64, size: u64| trust::hw_within(addr, width, base, size);
    let buses = (d.ecam_bus_end as u64 + 1).saturating_sub(d.ecam_bus_start as u64);
    within(trust::HW_CHIPSET.0, trust::HW_CHIPSET.1)
        || d.ecam_base != 0 && within(d.ecam_base.saturating_add((d.ecam_bus_start as u64) << 20), buses << 20)
        || d.funcs().iter().flat_map(|f| f.bars.iter())
            .any(|b| b.size != 0 && b.flags & l4h_partition::BAR_IO == 0 && within(b.addr, b.size))
}

/// Whether root manages PCI function bus:dev.func, whose configuration
/// the AML may then read but not write: the disk controllers and uplink
/// NICs it drives, every xHCI controller (each is root's or the
/// firmware's until claimed), the balloon device, IOMMUs, every bridge
/// (the host bridge's and the PCI bridges' bus numbers and windows route
/// the others; an ISA or LPC bridge's registers place the chipset's
/// power and reset blocks), and the function that holds the FADT's reset
/// register.  So is a function root cannot read.
#[cfg(target_arch = "x86_64")]
fn managed(h: &Host, bus: u8, dev: u8, func: u8) -> bool {
    let is = |d: &crate::pci::Device| (d.bus, d.dev, d.func) == (bus, dev, func);
    if h.ctrls.iter().any(|c| is(&c.pci)) || h.netd.nics.iter().any(|n| is(&n.pci)) || crate::usb::ctrls().iter().any(|c| is(&c.pci)) {
        return true;
    }
    let id = h.pci.read32(bus, dev, func, 0);
    // Class, subclass and programming interface.
    let class = h.pci.read32(bus, dev, func, 8) >> 8;
    let header = h.pci.read32(bus, dev, func, 0xc) >> 16 & 0x7f;
    id & 0xffff == 0xffff
        || header != 0
        // Base class 6: every bridge.
        || class >> 16 == 0x06
        || class >> 8 == 0x0806
        || class == 0x0c0330
        // virtio's balloon, modern and transitional (memd::is_balloon).
        || id & 0xffff == 0x1af4 && matches!(id >> 16, 0x1045 | 0x1002)
        || h.reset.pci_function() == Some((bus, dev, func))
}

/// Whether [start, start + len), memory or (`io`) ports, meets a BAR of a
/// function root drives: what its drivers reach is not the AML's.
#[cfg(target_arch = "x86_64")]
fn in_bars(h: &Host, start: usize, len: usize, io: bool) -> bool {
    let end = start.saturating_add(len);
    h.ctrls.iter().map(|c| &c.pci).chain(h.netd.nics.iter().map(|n| &n.pci)).chain(crate::usb::ctrls().iter().map(|c| &c.pci))
        .flat_map(|d| d.bars.iter())
        .any(|b| b.size != 0 && b.is_io == io && (b.addr as usize) < end && start < (b.addr as usize).saturating_add(b.size as usize))
}

#[cfg(not(target_arch = "x86_64"))]
pub fn hw(_h: &mut Host, _op: u64, _addr: usize, _off: usize, _width: usize, _value: u64) -> u64 {
    u64::MAX
}

/// An I/O port access, through a capability for just those ports: seL4
/// refuses ports already given out (the serial port, PCI configuration,
/// legacy NICs).
#[cfg(target_arch = "x86_64")]
fn io(alloc: &mut Alloc, port: usize, width: usize, write: bool, value: u64) -> Option<u64> {
    if !matches!(width, 1 | 2 | 4) || port.checked_add(width).is_none_or(|e| e > 0x1_0000) {
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

// A relayed message fits a control channel's ring.
const _: () = assert!(8 + trust::RELAY_MSG_MAX as u64
    <= l4h_partition::MsgRing::max_room(l4h_partition::CHANNEL_SIZE / 2 - l4h_partition::MSG_RING_HEADER as u64));

/// The relay page at `off` in root.
fn relay_va(off: usize) -> usize {
    crate::layout::TRUSTD_RELAY.base + off
}

/// A trustd message from partition `peer` (channel.rs): requests reach
/// the primary, replies the secondaries.  Into the peer's inbox slot,
/// replacing what trustd has not read (a request is repeated until
/// answered).
pub fn channel_message(h: &mut Host, peer: u32, ty: u32, msg: &[u8]) {
    let want = if crate::partition::secondary() { l4h_partition::MSG_TPM_REPLY } else { l4h_partition::MSG_TPM_REQUEST };
    let Some(relay) = h.trustd.as_ref().filter(|t| !t.failed).and_then(|t| t.relay) else { return };
    if ty != want || peer as usize >= trust::MAX_PARTITIONS || msg.len() > trust::RELAY_MSG_MAX {
        return;
    }
    let va = relay_va(trust::relay_slot_va(peer as usize) - trust::RELAY_VA);
    let slot = unsafe { &*(va as *const trust::RelaySlot) };
    use core::sync::atomic::Ordering;
    let seq = slot.seq.load(Ordering::Relaxed);
    slot.seq.store(seq | 1, Ordering::Relaxed);
    core::sync::atomic::fence(Ordering::Release);
    unsafe {
        core::ptr::copy_nonoverlapping(msg.as_ptr(), (va + trust::RELAY_SLOT_HEADER) as *mut u8, msg.len());
    }
    slot.len.store(msg.len() as u32, Ordering::Relaxed);
    // `seq` comes from a page the peer's trustd maps writable: never let its
    // value overflow root's own increment.
    slot.seq.store((seq | 1).wrapping_add(1), Ordering::Release);
    relay.signal();
}

/// `relay` from trustd: its outbox (`len` bytes) to partition `peer`.
/// 0, or u64::MAX if root cannot.
pub fn relay(h: &mut Host, peer: u32, len: usize) -> u64 {
    let secondary = crate::partition::secondary();
    let ty = if secondary { l4h_partition::MSG_TPM_REQUEST } else { l4h_partition::MSG_TPM_REPLY };
    // Secondaries ask only the primary, which answers only them.
    let (Some(cs), true) = (h.channels.as_ref(), h.trustd.as_ref().is_some_and(|t| t.relay.is_some())) else { return u64::MAX };
    if len > trust::RELAY_MSG_MAX || (secondary && peer != 0) || (!secondary && peer == 0) {
        return u64::MAX;
    }
    let msg = unsafe { core::slice::from_raw_parts(relay_va(trust::RELAY_SLOT_HEADER) as *const u8, len) };
    if cs.send(peer, ty, &[msg]) { 0 } else { u64::MAX }
}

/// Root's timer: guests' allowance of attestation notices is new
/// (trust::AttestNotices); and kick trustd while it waits for an answer
/// from another partition, so that it can ask again or give up.
pub fn tick(h: &mut Host) {
    if let Some(v) = h.vmmgr.as_mut() {
        v.attest_tick();
    }
    let Some(relay) = h.trustd.as_ref().filter(|t| !t.failed).and_then(|t| t.relay) else { return };
    let out = unsafe { &*(relay_va(0) as *const trust::RelaySlot) };
    if out.wake.load(core::sync::atomic::Ordering::Relaxed) != 0 {
        relay.signal();
    }
}

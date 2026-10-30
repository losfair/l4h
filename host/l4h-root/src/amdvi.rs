//! The AMD IOMMU (AMD-Vi), driven by the root task itself rather than by
//! seL4 (DESIGN.md §9.5).  Only root gives devices memory, so it builds
//! the IOMMU's tables itself: a device table that blocks every device,
//! and for each requester group root enables an I/O page table that maps
//! the memory its devices were given, at its physical address. Drivers see no
//! difference; a device that strays faults instead of reaching memory.
//!
//! Interrupts are remapped too: a device root drives has a table of the
//! interrupts it may send, and its MSI data is an index into it; any
//! other device's MSIs are dropped.
//!
//! No AMD IOMMU (no IVRS table, aarch64, `iommu=0`) leaves
//! every operation a no-op: devices then reach all memory, as before.

use core::sync::atomic::{Ordering, compiler_fence};

use l4h_host::fixed::ArrayVec;

use l4h_abi as abi;

use crate::mem::Alloc;
use crate::pci;
use crate::iommu::{Access, mappings::Mappings, MAX_MAPPINGS};

const PAGE: usize = 4096;
/// IOMMUs driven, at most (an EPYC has one per root complex, up to 8).
const MAX_UNITS: usize = 16;
/// Device IDs: PCI segment 0's bus/device/function numbers.
const DEVICES: usize = 1 << 16;
const MAX_ATTACHED: usize = pci::MAX_DISK_CTRLS + l4h_host::net::MAX_NICS + 1;
/// I/O page table levels: 48-bit I/O addresses, which every IOMMU
/// supports (EFR.HATS) and which cover all physical memory.
const LEVELS: u64 = 4;
/// Table memory (the device table, I/O page tables, command buffers and
/// event logs) is carved from 2 MiB chunks, kept until reboot.
const CHUNK_BITS: usize = 21;
const CHUNK_PAGES: usize = 1 << (CHUNK_BITS - 12);
const MAX_CHUNKS: usize = crate::layout::IOMMU_TABLES.size >> CHUNK_BITS;
/// Unity-mapped ranges the firmware asks for (IVMD), at most.
const MAX_UNITY: usize = 32;
/// Events printed per poll; the rest are counted.
const EVENTS_PER_POLL: usize = 8;

// MMIO registers.
const DEV_TABLE_BASE: usize = 0x0000;
const CMD_BUF_BASE: usize = 0x0008;
const EVT_LOG_BASE: usize = 0x0010;
const CONTROL: usize = 0x0018;
const EXT_FEATURES: usize = 0x0030;
const CMD_HEAD: usize = 0x2000;
const CMD_TAIL: usize = 0x2008;
const EVT_HEAD: usize = 0x2010;
const EVT_TAIL: usize = 0x2018;
const STATUS: usize = 0x2020;
/// The registers above: all an IOMMU is required to have.
const MMIO_BYTES: usize = 0x4000;

// Control register.
const CTRL_EN: u64 = 1 << 0;
const CTRL_HT_TUN: u64 = 1 << 1;
const CTRL_EVT_LOG: u64 = 1 << 2;
const CTRL_INV_TIMEOUT_1S: u64 = 4 << 5;
const CTRL_PASSPW: u64 = 1 << 8;
const CTRL_RESPASSPW: u64 = 1 << 9;
const CTRL_COHERENT: u64 = 1 << 10;
const CTRL_ISOC: u64 = 1 << 11;
const CTRL_CMD_BUF: u64 = 1 << 12;
/// Status register: the event log overflowed and stopped.
const STATUS_EVT_OVERFLOW: u64 = 1 << 0;
/// Extended features: INVALIDATE_IOMMU_ALL.
const EFR_IA_SUP: u64 = 1 << 6;
/// Capability header (PCI config space): the EFR register exists.
const CAP_EFR_SUP: u32 = 1 << 27;

/// Command buffer and event log: a page each, 256 entries of 16 bytes
/// (length field 8: log2 of the entries).
const RING_BYTES: usize = PAGE;
const RING_LEN: u64 = 8 << 56;
const RING_MASK: u64 = 0x7fff0;

// Commands: the opcode is in bits 31:28 of the second dword.
const CMD_COMPLETION_WAIT: u32 = 0x1 << 28;
const CMD_INV_DEVTAB_ENTRY: u32 = 0x2 << 28;
const CMD_INV_IOMMU_PAGES: u32 = 0x3 << 28;
const CMD_INV_INT_TABLE: u32 = 0x5 << 28;
const CMD_INV_IOMMU_ALL: u32 = 0x8 << 28;

// Device table entries, first quadword: valid, translation valid, paging
// mode (levels) in bits 11:9, the page table, read and write allowed.
// V and TV with mode 0 and no IR/IW: every access is blocked.
const DTE_V: u64 = 1 << 0;
const DTE_TV: u64 = 1 << 1;
const DTE_IR: u64 = 1 << 61;
const DTE_IW: u64 = 1 << 62;
const DTE_BLOCKED: u64 = DTE_V | DTE_TV;
// Device table entries, third quadword: the interrupt table is valid,
// its length (log2 of the entries) in bits 4:1, its address, and fixed
// and arbitrated interrupts remapped (IntCtl 10b; 00b: dropped).
const DTE_IV: u64 = 1 << 0;
const DTE_INTCTL_REMAP: u64 = 2 << 60;
/// A requester group may contain many controllers. Allow every CPU
/// vector in its shared table (still less than one allocated page).
const IRT_LEN: u64 = 8;
const IRT_ENTRIES: usize = 1 << IRT_LEN;
// Interrupt table entries (32-bit format): remapping enabled, fixed
// delivery (IntType 0), physical destination APIC ID in bits 15:8, the
// vector in bits 23:16.
const IRTE_REMAP_EN: u32 = 1 << 0;

// I/O page table entries: present, next level in bits 11:9 (0: a page),
// force coherent, read, write.
const PTE_PR: u64 = 1 << 0;
const PTE_FC: u64 = 1 << 60;
const PTE_IR: u64 = 1 << 61;
const PTE_IW: u64 = 1 << 62;
const PTE_ADDR: u64 = 0x000f_ffff_ffff_f000;

/// An I/O address space: a domain ID and its page table, shared by the
/// device IDs of one requester group. `Domain::NONE` is no domain: without an
/// IOMMU, every call taking one does nothing.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Domain {
    id: u16,
    root: usize,
    /// The group's interrupt table (else 0), and this attachment's
    /// device ID and firmware alias.
    irt: usize,
    dev: [u16; 2],
}

impl Domain {
    pub const NONE: Domain = Domain { id: 0, root: 0, irt: 0, dev: [0; 2] };
}

/// A memory range the firmware needs devices first..=last to keep
/// reaching (IVMD).
#[derive(Clone, Copy)]
struct Unity {
    first: u16,
    last: u16,
    start: usize,
    end: usize,
    access: Access,
}

impl Unity {
    fn all(&self) -> bool {
        self.first == 0 && self.last == u16::MAX
    }

    fn covers(&self, id: u16) -> bool {
        (self.first..=self.last).contains(&id)
    }

    fn covers_group(&self, alias: u16, dev: &DevInfo) -> bool {
        self.covers(alias) || (self.first..=self.last).any(|id| dev.alias[id as usize] == alias)
    }
}

struct Unit {
    mmio: usize,
    cmd: usize,
    evt: usize,
    /// The command buffer's tail and the event log's head, in bytes.
    tail: usize,
    head: usize,
    /// Completion-wait store, and the value of the last wait.
    sem: usize,
    sem_pa: usize,
    seq: u64,
    inv_all: bool,
}

/// What the IVHDs say of each device ID: its DTE setting byte (interrupt
/// pass-through and SysMgt), whether an IOMMU translates it, and the ID
/// its requests carry (an alias, behind a PCI bridge); and the chunks of
/// table memory: (virtual, physical) address.  In .bss: too large for
/// the root task's stack, where `Host` is.
struct DevInfo {
    flags: [u8; DEVICES],
    covered: [u64; DEVICES / 64],
    /// I/O APICs and HPETs: their interrupts pass unremapped, since seL4
    /// programs them in the compatibility format.
    special: [u64; DEVICES / 64],
    alias: [u16; DEVICES],
    /// Driven devices only, separate from the firmware's boot domains.
    /// Aliases share a page table and an interrupt table, even when
    /// interrupt remapping is disabled.
    attached: ArrayVec<Domain, MAX_ATTACHED>,
    mappings: Mappings<MAX_MAPPINGS>,
    chunks: ArrayVec<(usize, usize), MAX_CHUNKS>,
}

static mut DEV_INFO: DevInfo =
    DevInfo {
    flags: [0; DEVICES],
    covered: [0; DEVICES / 64],
    special: [0; DEVICES / 64],
    alias: [0; DEVICES],
    attached: ArrayVec::new(),
    mappings: Mappings::new(),
    chunks: ArrayVec::new(),
};
static DEV_INFO_TAKEN: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

impl DevInfo {
    fn covered(&self, id: u16) -> bool {
        self.covered[id as usize / 64] & 1 << (id % 64) != 0
    }

    fn set(&mut self, id: u16, flags: u8, alias: u16) {
        self.flags[id as usize] = flags;
        self.alias[id as usize] = alias;
        self.covered[id as usize / 64] |= 1 << (id % 64);
    }
}

pub struct AmdVi {
    units: ArrayVec<Unit, MAX_UNITS>,
    /// Pages of the last chunk handed out.
    used: usize,
    devtab: usize,
    unity: ArrayVec<Unity, MAX_UNITY>,
    /// The domain of devices with only "all devices" unity ranges.
    shared: Option<Domain>,
    next_domain: u16,
    ticks_per_ms: u64,
    /// Remap interrupts (`iommu_intremap`).
    intremap: bool,
    /// Events not printed (beyond EVENTS_PER_POLL).
    dropped: u64,
    dev: Option<&'static mut DevInfo>,
    /// For CTL_IOMMU_INFO: abi::IOMMU_*, the devices given a domain and
    /// those behind no IOMMU, and the events logged since boot.
    state: u64,
    confined: u64,
    unconfined: u64,
    events: u64,
}

pub fn device_id(d: &pci::Device) -> u16 {
    ((d.bus as u16) << 8) | ((d.dev as u16) << 3) | d.func as u16
}

fn u16_at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

/// One IOMMU as an IVHD describes it.
#[derive(Clone, Copy)]
struct Ivhd {
    kind: u8,
    flags: u8,
    id: u16,
    cap: u16,
    base: usize,
}

impl AmdVi {
    /// No IOMMU: every device reaches all memory.
    pub fn none() -> Self {
        AmdVi {
            units: ArrayVec::new(),
            used: 0,
            devtab: 0,
            unity: ArrayVec::new(),
            shared: None,
            next_domain: 1,
            ticks_per_ms: 0,
            intremap: false,
            dropped: 0,
            dev: None,
            state: abi::IOMMU_NONE,
            confined: 0,
            unconfined: 0,
            events: 0,
        }
    }

    /// Turned off (`iommu=0`): as `none`, but reported so.
    pub fn off() -> Self {
        AmdVi { state: abi::IOMMU_OFF, ..AmdVi::none() }
    }

    /// CTL_IOMMU_INFO's values: state, interrupts remapped, IOMMUs,
    /// devices confined, devices behind no IOMMU, events logged.
    pub fn info(&self) -> [u64; 6] {
        let remapped = self.active() && self.intremap;
        [self.state, remapped as u64, self.units.len() as u64, self.confined, self.unconfined, self.events]
    }

    /// Whether devices are confined.
    pub fn active(&self) -> bool {
        !self.units.is_empty()
    }

    /// Find the IOMMUs (IVRS), block every device and enable them.  None
    /// found, or one that cannot be used, leaves devices unconfined.
    #[cfg(target_arch = "x86_64")]
    pub fn init(bootinfo: &sel4::BootInfoPtr, phys: &mut crate::acpi::Phys, pci: &pci::Pci, ticks_per_ms: u64,
        intremap: bool) -> Self {
        let mut me = AmdVi::none();
        me.ticks_per_ms = ticks_per_ms;
        me.intremap = intremap;
        let mut buf = [0u8; 32 << 10];
        let Some(ivrs) = crate::acpi::find(bootinfo, phys, b"IVRS", &mut buf) else {
            info!("l4h-root: no IOMMU (DMAR/IVRS): DMA is not confined");
            return me;
        };
        if ivrs.len() < 48 || (u32_at(ivrs, 4) as usize) > ivrs.len() {
            log!("l4h-root: iommu: IVRS unreadable or over {} bytes: DMA is not confined", buf.len());
            me.state = abi::IOMMU_FAILED;
            return me;
        }
        assert!(!DEV_INFO_TAKEN.swap(true, Ordering::Relaxed), "IOMMU device table info taken twice");
        // The flag gives out the only reference; the root task is
        // single-threaded.
        let dev = unsafe { &mut *(&raw mut DEV_INFO) };
        for (i, a) in dev.alias.iter_mut().enumerate() {
            *a = i as u16;
        }
        let ivrs = &ivrs[..u32_at(ivrs, 4) as usize];
        let Some(units) = me.parse(ivrs, dev) else {
            log!("l4h-root: iommu: IVRS malformed: DMA is not confined");
            me.state = abi::IOMMU_FAILED;
            return me;
        };
        if units.is_empty() {
            info!("l4h-root: IVRS lists no IOMMU on PCI segment 0: DMA is not confined");
            return me;
        }
        me.dev = Some(dev);
        me.enable(&units, phys, pci);
        me
    }

    /// Read the IVRS's blocks: the IOMMUs (for each, the IVHD of the
    /// highest type known; they describe the same devices), their devices
    /// into `dev`, and the unity ranges.
    #[cfg(target_arch = "x86_64")]
    fn parse(&mut self, ivrs: &[u8], dev: &mut DevInfo) -> Option<ArrayVec<Ivhd, MAX_UNITS>> {
        let blocks = || {
            let mut at = 48;
            core::iter::from_fn(move || {
                let b = ivrs.get(at..at + 4)?;
                let len = u16_at(b, 2) as usize;
                let block = ivrs.get(at..at + len).filter(|_| len >= 4)?;
                at += len;
                Some(block)
            })
        };
        let mut units = ArrayVec::<Ivhd, MAX_UNITS>::new();
        for b in blocks() {
            if !matches!(b[0], 0x10 | 0x11 | 0x40) || b.len() < 24 || u16_at(b, 16) != 0 {
                continue;
            }
            let h = Ivhd { kind: b[0], flags: b[1], id: u16_at(b, 4), cap: u16_at(b, 6), base: u64_at(b, 8) as usize };
            match units.iter_mut().find(|u| u.id == h.id) {
                Some(u) if u.kind < h.kind => *u = h,
                Some(_) => {}
                None => {
                    if units.push(h).is_err() {
                        log!("l4h-root: iommu: more than {} IOMMUs", MAX_UNITS);
                        return None;
                    }
                }
            }
        }
        for b in blocks() {
            match b[0] {
                0x10 | 0x11 | 0x40 if units.iter().any(|u| u.id == u16_at(b, 4) && u.kind == b[0]) && u16_at(b, 16) == 0 => {
                    let header = if b[0] == 0x10 { 24 } else { 40 };
                    Self::devices(b.get(header..)?, dev)?;
                }
                0x20..=0x22 if b.len() >= 32 => {
                    let (flags, id) = (b[1], u16_at(b, 4));
                    let (unity, read, write, exclusion) = (flags & 1 != 0, flags & 2 != 0, flags & 4 != 0, flags & 8 != 0);
                    if !unity && !exclusion || !read && !write && !exclusion {
                        continue;
                    }
                    let (first, last) = match b[0] {
                        0x20 => (0, u16::MAX),
                        0x21 => (id, id),
                        _ => (id, u16_at(b, 6)),
                    };
                    let (start, len) = (u64_at(b, 16) as usize, u64_at(b, 24) as usize);
                    let end = start.checked_add(len)?.next_multiple_of(PAGE);
                    let u = Unity { first, last, start: start & !(PAGE - 1), end,
                        access: if write || exclusion { Access::ReadWrite } else { Access::Read } };
                    info!("l4h-root: iommu: unity range {:#x}..{:#x} for devices {:#06x}..={:#06x}", u.start, u.end, first, last);
                    if self.unity.push(u).is_err() {
                        log!("l4h-root: iommu: more than {} unity ranges", MAX_UNITY);
                        return None;
                    }
                }
                _ => {}
            }
        }
        Some(units)
    }

    /// An IVHD's device entries.
    #[cfg(target_arch = "x86_64")]
    fn devices(mut e: &[u8], dev: &mut DevInfo) -> Option<()> {
        // A range being described: (first ID, setting, alias).
        let mut range: Option<(u16, u8, Option<u16>)> = None;
        while let Some(&kind) = e.first() {
            let len = match kind {
                0..=0x7f => 4 << (kind >> 6),
                0xf0 => *e.get(21)? as usize + 22,
                _ => {
                    info!("l4h-root: iommu: IVHD entry type {:#x} not known, rest of the IVHD skipped", kind);
                    return Some(());
                }
            };
            let ent = e.get(..len)?;
            e = &e[len..];
            let (id, flags) = (u16_at(ent, 1), ent[3]);
            match kind {
                // Every device.
                0x01 => (0..=u16::MAX).for_each(|i| dev.set(i, flags, i)),
                0x02 | 0x46 | 0xf0 => dev.set(id, flags, id),
                0x03 | 0x47 => range = Some((id, flags, None)),
                0x04 => {
                    let (first, flags, alias) = range.take()?;
                    for i in first..=id {
                        dev.set(i, flags, alias.unwrap_or(i));
                    }
                    if let Some(a) = alias {
                        dev.set(a, flags, a);
                    }
                }
                0x42 => {
                    let alias = u16_at(ent, 5);
                    dev.set(id, flags, alias);
                    dev.set(alias, flags, alias);
                }
                0x43 => range = Some((id, flags, Some(u16_at(ent, 5)))),
                // A special device (I/O APIC, HPET): its ID is at byte 5.
                0x48 => {
                    let id = u16_at(ent, 5);
                    dev.set(id, flags, id);
                    dev.special[id as usize / 64] |= 1 << (id % 64);
                    let what = match ent[7] { 1 => "I/O APIC", 2 => "HPET", _ => "special device" };
                    info!("l4h-root: iommu: {} {} at {:02x}:{:02x}.{}", what, ent[4], id >> 8, (id >> 3) & 0x1f, id & 7);
                }
                _ => {}
            }
        }
        Some(())
    }

    /// Map the IOMMUs' registers, build the tables, enable translation.
    #[cfg(target_arch = "x86_64")]
    fn enable(&mut self, units: &[Ivhd], phys: &mut crate::acpi::Phys, pci: &pci::Pci) {
        use sel4::init_thread::slot;
        // Every IOMMU's registers first, so that none is enabled unless all can be.
        let mut mmio = ArrayVec::<usize, MAX_UNITS>::new();
        for (n, u) in units.iter().enumerate() {
            let Some(frames) = phys.alloc.slots.global(|s| phys.devmem.frames(s, u.base, MMIO_BYTES)) else {
                log!("l4h-root: iommu at {:#x}: registers not in device memory: DMA is not confined", u.base);
                self.state = abi::IOMMU_FAILED;
                return;
            };
            let va = crate::layout::IOMMU_MMIO.base + n * MMIO_BYTES;
            for (i, f) in frames.map(crate::devmem::granule).enumerate() {
                crate::vspace::map_frame(&mut crate::mem::ObjCtx::global(phys.alloc), slot::VSPACE.cap(), f,
                    va + i * PAGE, sel4::CapRights::read_write(), crate::blkd::DEVICE_ATTRS);
            }
            let _ = mmio.push(va);
        }
        // The device table: a whole chunk, 65536 entries of 32 bytes.
        let (devtab, devtab_pa) = self.chunk(phys.alloc);
        self.used = CHUNK_PAGES;
        self.devtab = devtab;
        for id in 0..=u16::MAX {
            let irq = self.irq_dte(id, Domain::NONE);
            self.write_dte(id, DTE_BLOCKED, 0, irq);
        }
        let (sems, sems_pa) = self.page(phys.alloc);
        for (n, u) in units.iter().enumerate() {
            let ((cmd, cmd_pa), (evt, evt_pa)) = (self.page(phys.alloc), self.page(phys.alloc));
            let header = pci.read32((u.id >> 8) as u8, ((u.id >> 3) & 0x1f) as u8, (u.id & 7) as u8, u.cap as u8);
            let base = mmio[n];
            let r = |off: usize| unsafe { ((base + off) as *const u64).read_volatile() };
            let w = |off: usize, v: u64| unsafe { ((base + off) as *mut u64).write_volatile(v) };
            let unit = Unit {
                mmio: base, cmd, evt, tail: 0, head: 0,
                sem: sems + n * 8, sem_pa: sems_pa + n * 8, seq: 0,
                inv_all: header & CAP_EFR_SUP != 0 && r(EXT_FEATURES) & EFR_IA_SUP != 0,
            };
            // Off, as firmware may have left it, while it is set up.
            w(CONTROL, 0);
            w(DEV_TABLE_BASE, devtab_pa as u64 | (CHUNK_PAGES as u64 - 1));
            w(CMD_BUF_BASE, cmd_pa as u64 | RING_LEN);
            w(CMD_HEAD, 0);
            w(CMD_TAIL, 0);
            w(EVT_LOG_BASE, evt_pa as u64 | RING_LEN);
            w(EVT_HEAD, 0);
            w(EVT_TAIL, 0);
            w(STATUS, r(STATUS));
            let mut ctrl = CTRL_COHERENT | CTRL_INV_TIMEOUT_1S | CTRL_CMD_BUF | CTRL_EVT_LOG;
            for (bit, c) in [(0, CTRL_HT_TUN), (1, CTRL_PASSPW), (2, CTRL_RESPASSPW), (3, CTRL_ISOC)] {
                if u.flags & 1 << bit != 0 {
                    ctrl |= c;
                }
            }
            w(CONTROL, ctrl);
            compiler_fence(Ordering::SeqCst);
            w(CONTROL, ctrl | CTRL_EN);
            info!("l4h-root: iommu {:02x}:{:02x}.{} at {:#x}: enabled", u.id >> 8, (u.id >> 3) & 0x1f, u.id & 7, u.base);
            let _ = self.units.push(unit);
        }
        self.state = abi::IOMMU_ON;
        // Whatever the firmware left cached.
        if self.units.iter().all(|u| u.inv_all) {
            self.command([0, CMD_INV_IOMMU_ALL, 0, 0]);
        } else {
            for id in 0..=u16::MAX {
                self.command([id as u32, CMD_INV_DEVTAB_ENTRY, 0, 0]);
            }
        }
        self.sync();
        // The firmware's unity ranges.  "All devices" ranges go in one
        // shared domain; the devices a range names share a domain with
        // it and the "all devices" ranges (a device named by two ranges
        // takes both into the first one's domain).
        for all in [true, false] {
            for i in 0..self.unity.len() {
                let u = self.unity[i];
                if u.all() != all {
                    continue;
                }
                let mut own = None;
                // Domains given this range: mapping it again is harmless
                // but slow, once per device ID of an "all devices" range.
                let mut given = ArrayVec::<u16, 64>::new();
                for id in u.first..=u.last {
                    if !self.covered(id) {
                        continue;
                    }
                    let alias = self.dev.as_ref().unwrap().alias[id as usize];
                    let d = match (self.domain_of(alias), own) {
                        (Some(d), _) if all || Some(d) != self.shared => d,
                        (_, Some(d)) => d,
                        _ => *own.insert(self.unity_domain(phys.alloc, id, |u| u.all())),
                    };
                    if all {
                        self.shared = Some(d);
                    }
                    if !given.contains(&d.id) {
                        self.map_range(phys.alloc, d, u.start, u.end - u.start, u.access);
                        let _ = given.push(d.id);
                    }
                    self.set_dte(id, d);
                    if alias != id {
                        self.set_dte(alias, d);
                    }
                }
            }
        }
        self.sync();
    }

    /// A new domain for device ID `id` with the unity ranges `which`
    /// picks.
    fn unity_domain(&mut self, alloc: &mut Alloc, id: u16, which: impl Fn(&Unity) -> bool) -> Domain {
        let d = self.new_domain(alloc, id);
        for i in 0..self.unity.len() {
            let u = self.unity[i];
            if which(&u) {
                self.map_range(alloc, d, u.start, u.end - u.start, u.access);
            }
        }
        d
    }

    /// A driven group gets all its members' firmware ranges, including
    /// devices without a driver. Boot-only domains may also contain
    /// unrelated requesters, so never reuse those for driver DMA.
    fn group_domain(&mut self, alloc: &mut Alloc, alias: u16) -> Domain {
        let mut d = self.new_domain(alloc, alias);
        for i in 0..self.unity.len() {
            let u = self.unity[i];
            if u.covers_group(alias, self.dev.as_ref().unwrap()) {
                self.map_range(alloc, d, u.start, u.end - u.start, u.access);
            }
        }
        if self.intremap {
            d.irt = self.page(alloc).1;
        }
        d
    }

    fn covered(&self, id: u16) -> bool {
        self.dev.as_ref().is_some_and(|d| d.covered(id))
    }

    fn r64(&self, u: usize, off: usize) -> u64 {
        unsafe { ((self.units[u].mmio + off) as *const u64).read_volatile() }
    }

    fn w64(&self, u: usize, off: usize, v: u64) {
        unsafe { ((self.units[u].mmio + off) as *mut u64).write_volatile(v) }
    }

    /// Table memory: 2 MiB chunks, (virtual, physical) address.
    fn chunks(&self) -> &ArrayVec<(usize, usize), MAX_CHUNKS> {
        &self.dev.as_ref().expect("iommu tables without an IOMMU").chunks
    }

    /// A zeroed page of table memory: (virtual, physical) address.
    fn page(&mut self, alloc: &mut Alloc) -> (usize, usize) {
        if self.chunks().is_empty() || self.used == CHUNK_PAGES {
            self.chunk(alloc);
            self.used = 0;
        }
        let &(va, pa) = self.chunks().last().unwrap();
        let off = self.used * PAGE;
        self.used += 1;
        (va + off, pa + off)
    }

    /// A new chunk, zeroed, mapped in root's address space.
    fn chunk(&mut self, alloc: &mut Alloc) -> (usize, usize) {
        use crate::vspace::{LARGE_PAGE_BP, map_large_page};
        use sel4::init_thread::slot;
        assert!(!self.chunks().is_full(), "l4h-root: iommu: out of table space");
        let (ut, page) = alloc.slots.global(|s| (s.alloc(), s.alloc()));
        let mut region = alloc.split(CHUNK_BITS, ut).expect("l4h-root: iommu: no memory for tables");
        let pa = region.retype(&LARGE_PAGE_BP, 1, crate::mem::Dest::new(crate::slot::CNODE.cap(), page)).expect("iommu table chunk");
        let va = crate::layout::IOMMU_TABLES.base + (self.chunks().len() << CHUNK_BITS);
        let cap = sel4::init_thread::Slot::<sel4::cap_type::LargePage>::from_index(page).cap();
        map_large_page(&mut crate::mem::ObjCtx::global(alloc), slot::VSPACE.cap(), cap, va, sel4::CapRights::read_write());
        let _ = self.dev.as_mut().unwrap().chunks.push((va, pa));
        (va, pa)
    }

    /// Table memory at `pa`.
    fn table(&self, pa: u64) -> *mut u64 {
        let pa = (pa & PTE_ADDR) as usize;
        let &(va, base) = self
            .chunks()
            .iter()
            .find(|&&(_, base)| (base..base + (1 << CHUNK_BITS)).contains(&pa))
            .expect("iommu: table outside its chunks");
        (va + (pa - base)) as *mut u64
    }

    fn dte(&self, id: u16) -> *mut u64 {
        (self.devtab + id as usize * 32) as *mut u64
    }

    /// Write device ID `id`'s entry: `q0`, and `domain` with the IVHD's
    /// settings.  The first quadword, which enables translation, last.
    fn write_dte(&mut self, id: u16, q0: u64, domain: u16, irq: u64) {
        let flags = self.dev.as_ref().map_or(0, |d| d.flags[id as usize]) as u64;
        // SysMgt (bits 5:4) to bits 41:40; INITPass, EIntPass, NMIPass
        // (bits 2:0) to 58:56; Lint0Pass, Lint1Pass (7:6) to 63:62.
        let q1 = domain as u64 | (flags >> 4 & 3) << 40;
        let q2 = irq | (flags & 7) << 56 | (flags >> 6 & 3) << 62;
        let e = self.dte(id);
        unsafe {
            e.add(3).write_volatile(0);
            e.add(2).write_volatile(q2);
            e.add(1).write_volatile(q1);
            compiler_fence(Ordering::SeqCst);
            e.write_volatile(q0);
        }
    }

    /// Point device ID `id` at domain `d`; takes effect at the next sync.
    fn set_dte(&mut self, id: u16, d: Domain) {
        let irq = self.irq_dte(id, d);
        self.write_dte(id, DTE_V | DTE_TV | LEVELS << 9 | d.root as u64 | DTE_IR | DTE_IW, d.id, irq);
        self.command([id as u32, CMD_INV_DEVTAB_ENTRY, 0, 0]);
        self.command([id as u32, CMD_INV_INT_TABLE, 0, 0]);
    }

    /// Device ID `id`'s interrupt settings in domain `d`: its table if
    /// root drives it, else none, so that its MSIs are dropped.  I/O
    /// APICs and HPETs, and every device without `intremap`, pass theirs
    /// unremapped (IV 0).
    fn irq_dte(&self, id: u16, d: Domain) -> u64 {
        let special = self.dev.as_ref().is_some_and(|dev| dev.special[id as usize / 64] & 1 << (id % 64) != 0);
        if !self.intremap || special {
            0
        } else if d.irt != 0 {
            d.irt as u64 | IRT_LEN << 1 | DTE_IV | DTE_INTCTL_REMAP
        } else {
            DTE_IV
        }
    }

    /// The MSI data that makes device `d` raise CPU vector `vector` (as
    /// `pci::msi_data` numbers them), at the address `pci::msi_address`
    /// (APIC ID 0).  Remapped: the index of an entry of the device's
    /// interrupt table; else the vector itself.
    pub fn msi_data(&mut self, d: Domain, vector: u64) -> u32 {
        let data = pci::msi_data(vector);
        if d.irt == 0 {
            return data;
        }
        let table = self.table(d.irt as u64) as *mut u32;
        let entry = (data & 0xff) << 16 | IRTE_REMAP_EN;
        let free = (0..IRT_ENTRIES).find(|&i| {
            let e = unsafe { table.add(i).read_volatile() };
            e == entry || e & IRTE_REMAP_EN == 0
        });
        let i = free.expect("l4h-root: iommu: requester interrupt table full");
        unsafe { table.add(i).write_volatile(entry) };
        // Every attached BDF and the bridge alias can cache this table.
        // Handles returned before a sibling attached must invalidate it too.
        self.command([d.dev[1] as u32, CMD_INV_INT_TABLE, 0, 0]);
        for n in 0..self.dev.as_ref().unwrap().attached.len() {
            let member = self.dev.as_ref().unwrap().attached[n];
            if member.id == d.id && member.dev[0] != d.dev[1] {
                self.command([member.dev[0] as u32, CMD_INV_INT_TABLE, 0, 0]);
            }
        }
        self.sync();
        i as u32
    }

    /// The domain device ID `id` is in, if any.
    fn domain_of(&self, id: u16) -> Option<Domain> {
        let e = self.dte(id);
        let (q0, q1) = unsafe { (e.read_volatile(), e.add(1).read_volatile()) };
        (q0 & DTE_TV != 0 && q0 >> 9 & 7 != 0).then(|| Domain { id: q1 as u16, root: (q0 & PTE_ADDR) as usize, ..Domain::NONE })
    }

    /// A new, empty domain, for device ID `id` (named if one runs out).
    fn new_domain(&mut self, alloc: &mut Alloc, id: u16) -> Domain {
        assert!(self.next_domain != 0, "l4h-root: iommu: out of domain IDs at device {:#06x}", id);
        let d = Domain { id: self.next_domain, root: self.page(alloc).1, ..Domain::NONE };
        self.next_domain = self.next_domain.wrapping_add(1);
        // Translations the firmware may have cached under this ID.
        self.flush(d);
        d
    }

    /// Join device `d` to its requester's domain, with the unity ranges
    /// of every member, and nothing else until root maps its memory.
    /// Without an IOMMU, Domain::NONE.
    pub fn attach(&mut self, alloc: &mut Alloc, d: &pci::Device) -> Domain {
        if !self.active() {
            return Domain::NONE;
        }
        let id = device_id(d);
        if !self.covered(id) {
            log!(
                "l4h-root: iommu: {:02x}:{:02x}.{} is behind no IOMMU: its DMA is not confined",
                d.bus, d.dev, d.func
            );
            self.unconfined += 1;
            return Domain::NONE;
        }
        let alias = self.dev.as_ref().unwrap().alias[id as usize];
        let existing = self.dev.as_ref().unwrap().attached.iter().find(|d| d.dev[1] == alias).copied();
        let mut dom = existing.unwrap_or_else(|| self.group_domain(alloc, alias));
        dom.dev = [id, alias];
        self.set_dte(id, dom);
        if alias != id && existing.is_none() {
            self.set_dte(alias, dom);
        }
        assert!(self.dev.as_mut().unwrap().attached.push(dom).is_ok(), "iommu: too many attached devices");
        self.sync();
        self.confined += 1;
        dom
    }

    /// Let domain `d` reach [pa, pa + len) with device-side `access`.
    pub fn map(&mut self, alloc: &mut Alloc, d: Domain, pa: usize, len: usize, access: Access) {
        if d == Domain::NONE {
            return;
        }
        assert!(pa % PAGE == 0 && len % PAGE == 0);
        let end = pa.checked_add(len).expect("iommu: invalid DMA range");
        // Permanent firmware mappings cannot also be recyclable DMA pools.
        assert!(!self.unity.iter().any(|u| u.covers_group(d.dev[1], self.dev.as_ref().unwrap())
            && pa < u.end && u.start < end), "iommu: allocated DMA memory overlaps an IVMD range");
        if !self.dev.as_mut().unwrap().mappings.acquire(d.id as u32, pa, len, access) { return; }
        self.map_range(alloc, d, pa, len, access);
        // An IOMMU may cache missing entries (NpCache).
        self.flush(d);
        self.sync();
    }

    fn map_range(&mut self, alloc: &mut Alloc, d: Domain, pa: usize, len: usize, access: Access) {
        assert!(pa % PAGE == 0 && len % PAGE == 0);
        let leaf = PTE_PR | PTE_FC | if access.read() { PTE_IR } else { 0 } | if access.write() { PTE_IW } else { 0 };
        for at in (pa..pa + len).step_by(PAGE) {
            let pte = self.walk(Some(alloc), d, at).unwrap();
            // Overlapping firmware ranges retain the union of permissions.
            unsafe { pte.write_volatile(pte.read_volatile() | at as u64 | leaf) };
        }
    }

    /// Release one owner's mapping. Only the final owner removes the
    /// translation, after which the requester can no longer reach it.
    pub fn unmap(&mut self, d: Domain, pa: usize, len: usize) {
        if d == Domain::NONE {
            return;
        }
        if !self.dev.as_mut().unwrap().mappings.release(d.id as u32, pa, len) { return; }
        for at in (pa..pa + len).step_by(PAGE) {
            if let Some(pte) = self.walk(None, d, at) {
                unsafe { pte.write_volatile(0) };
            }
        }
        self.flush(d);
        self.sync();
    }

    /// The last-level entry for `iova` in domain `d`, making the tables
    /// down to it with `alloc` (else None if one is missing).
    fn walk(&mut self, mut alloc: Option<&mut Alloc>, d: Domain, iova: usize) -> Option<*mut u64> {
        let mut table = self.table(d.root as u64);
        for level in (2..=LEVELS).rev() {
            let e = unsafe { table.add(iova >> (12 + 9 * (level - 1)) & 511) };
            let mut v = unsafe { e.read_volatile() };
            if v & PTE_PR == 0 {
                let (_, pa) = self.page(alloc.as_deref_mut()?);
                v = pa as u64 | (level - 1) << 9 | PTE_PR | PTE_IR | PTE_IW;
                unsafe { e.write_volatile(v) };
            }
            table = self.table(v);
        }
        Some(unsafe { table.add(iova >> 12 & 511) })
    }

    /// Drop domain `d`'s cached translations; takes effect at the next
    /// sync.
    fn flush(&mut self, d: Domain) {
        // All pages: address 0x7fff_ffff_ffff_f000 with S, and PDE.
        self.command([0, d.id as u32 | CMD_INV_IOMMU_PAGES, 0xffff_f000 | 3, 0x7fff_ffff]);
    }

    /// Append a command to every IOMMU's buffer.
    fn command(&mut self, cmd: [u32; 4]) {
        for u in 0..self.units.len() {
            self.command_to(u, cmd);
        }
    }

    fn command_to(&mut self, u: usize, cmd: [u32; 4]) {
        let next = (self.units[u].tail + 16) % RING_BYTES;
        let end = l4h_host::ticks::now() + 1000 * self.ticks_per_ms;
        while self.r64(u, CMD_HEAD) & RING_MASK == next as u64 {
            // Commands are not carried out: DMA can no longer be confined.
            assert!(l4h_host::ticks::now() < end, "l4h-root: iommu {}: command buffer stuck", u);
            core::hint::spin_loop();
        }
        let at = (self.units[u].cmd + self.units[u].tail) as *mut u32;
        for (i, w) in cmd.iter().enumerate() {
            unsafe { at.add(i).write_volatile(*w) };
        }
        compiler_fence(Ordering::SeqCst);
        self.units[u].tail = next;
        self.w64(u, CMD_TAIL, next as u64);
    }

    /// Wait until every IOMMU has carried out the commands before.
    fn sync(&mut self) {
        for u in 0..self.units.len() {
            self.units[u].seq += 1;
            let (pa, seq) = (self.units[u].sem_pa as u64, self.units[u].seq);
            // Store `seq` at the unit's own semaphore.
            self.command_to(u, [pa as u32 | 1, (pa >> 32) as u32 | CMD_COMPLETION_WAIT, seq as u32, (seq >> 32) as u32]);
        }
        for u in 0..self.units.len() {
            let sem = self.units[u].sem as *const u64;
            let end = l4h_host::ticks::now() + 1000 * self.ticks_per_ms;
            while unsafe { sem.read_volatile() } != self.units[u].seq {
                assert!(l4h_host::ticks::now() < end, "l4h-root: iommu {}: commands not completed", u);
                core::hint::spin_loop();
            }
        }
    }

    /// Print what the IOMMUs logged: faults of devices that reached for
    /// memory they were not given, and errors.
    pub fn poll(&mut self) {
        let mut printed = 0;
        for u in 0..self.units.len() {
            if self.r64(u, STATUS) & STATUS_EVT_OVERFLOW != 0 {
                log!("l4h-root: iommu {}: event log overflowed, restarted", u);
                let ctrl = self.r64(u, CONTROL);
                self.w64(u, CONTROL, ctrl & !CTRL_EVT_LOG);
                self.w64(u, EVT_HEAD, 0);
                self.w64(u, EVT_TAIL, 0);
                self.units[u].head = 0;
                self.w64(u, STATUS, STATUS_EVT_OVERFLOW);
                self.w64(u, CONTROL, ctrl | CTRL_EVT_LOG);
                continue;
            }
            let tail = (self.r64(u, EVT_TAIL) & RING_MASK) as usize;
            while self.units[u].head != tail {
                let at = (self.units[u].evt + self.units[u].head) as *const u32;
                let e: [u32; 4] = core::array::from_fn(|i| unsafe { at.add(i).read_volatile() });
                self.events += 1;
                if printed < EVENTS_PER_POLL {
                    printed += 1;
                    let id = e[0] & 0xffff;
                    let what = match e[1] >> 28 {
                        1 => "illegal device table entry",
                        2 => "page fault",
                        3 => "device table error",
                        4 => "page table error",
                        5 => "illegal command",
                        6 => "command error",
                        7 => "IOTLB invalidation timeout",
                        8 => "invalid device request",
                        _ => "event",
                    };
                    log!(
                        "l4h-root: iommu: {:02x}:{:02x}.{}: {} at {:#x} (domain {}, flags {:#x})",
                        id >> 8, (id >> 3) & 0x1f, id & 7, what, (e[3] as u64) << 32 | e[2] as u64,
                        e[1] & 0xffff, (e[1] >> 16) & 0xfff
                    );
                } else {
                    self.dropped += 1;
                }
                self.units[u].head = (self.units[u].head + 16) % RING_BYTES;
            }
            self.w64(u, EVT_HEAD, tail as u64);
        }
        if printed == EVENTS_PER_POLL && self.dropped != 0 {
            log!("l4h-root: iommu: {} more events not shown", self.dropped);
            self.dropped = 0;
        }
    }
}

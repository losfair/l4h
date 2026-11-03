//! Intel VT-d, owned by root with seL4's KernelIOMMU disabled.
//!
//! Legacy root/context tables select a private second-level page table
//! per requester. Untranslated requests are translated, ATS/translated
//! requests are blocked. Interrupt entries validate the complete PCI
//! requester ID; compatibility-format interrupts are disabled globally.
//! With several partitions (iommu/shared.rs) the root, context and
//! interrupt remapping tables and the invalidation queues are in the
//! shared region: partition 0 sets them up, every partition fills in its
//! own functions' context entries and its share of IRTEs, and takes the
//! unit's lock around each batch of invalidations.
//! See Intel VT-d Architecture Specification, rev. 5.0, §§6,8,9,11:
//! https://cdrdv2-public.intel.com/831418/vt-directed-io-spec.pdf

mod dmar;
mod format;
mod requester;

use core::sync::atomic::{Ordering, compiler_fence};
use l4h_host::fixed::{ArrayVec, StaticCell};
use l4h_abi as abi;
use crate::{mem::Alloc, pci};
use crate::iommu::{mappings, shared::Shared, MAX_MAPPINGS};
use dmar::{Dmar, MAX_IOAPICS, MAX_UNITS};
use format::{ADDR, PRESENT, READ, WRITE};

const PAGE: usize = 4096;
const CHUNK_BITS: usize = 21;
const CHUNK_PAGES: usize = 1 << (CHUNK_BITS - 12);
const MAX_CHUNKS: usize = crate::layout::IOMMU_TABLES.size >> CHUNK_BITS;
const MMIO_STRIDE: usize = 1 << 16;
const EVENTS_PER_POLL: usize = 8;

const VER: usize = 0x00;
const CAP: usize = 0x08;
const ECAP: usize = 0x10;
const GCMD: usize = 0x18;
const GSTS: usize = 0x1c;
const RTADDR: usize = 0x20;
const CCMD: usize = 0x28;
const FSTS: usize = 0x34;
const FECTL: usize = 0x38;
const PMEN: usize = 0x64;
const IQH: usize = 0x80;
const IQT: usize = 0x88;
const IQA: usize = 0x90;
const IECTL: usize = 0xa0;
const IRTA: usize = 0xb8;
const TE: u32 = 1 << 31;
const SRTP: u32 = 1 << 30;
const WBF: u32 = 1 << 27;
const QIE: u32 = 1 << 26;
const IRE: u32 = 1 << 25;
const SIRTP: u32 = 1 << 24;
const CFI: u32 = 1 << 23;
const EAFL: u32 = 1 << 28;
const QI_ERRORS: u32 = (1 << 4) | (1 << 5) | (1 << 6);
// A unit's pages in the shared region.
const SHARED_ROOT: usize = 0;
const SHARED_QUEUE: usize = 1;
const SHARED_IRT: usize = 8;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Domain {
    unit: usize,
    id: u16,
    sid: u16,
    root: usize,
}

impl Domain {
    fn key(self) -> u32 { (self.unit as u32) << 16 | self.id as u32 }
}

struct Unit {
    mmio: usize,
    cap: u64,
    ecap: u64,
    levels: u8,
    width: u8,
    root: usize,
    /// Domain IDs not yet given out: this partition's share.
    domains: core::ops::Range<u32>,
    control: u32,
    queue: usize,
    tail: usize,
    sem: usize,
    sem_pa: usize,
    seq: u32,
    irt: usize,
}

impl Unit {
    fn r32(&self, off: usize) -> u32 { unsafe { ((self.mmio + off) as *const u32).read_volatile() } }
    fn r64(&self, off: usize) -> u64 { unsafe { ((self.mmio + off) as *const u64).read_volatile() } }
    fn w32(&self, off: usize, v: u32) { unsafe { ((self.mmio + off) as *mut u32).write_volatile(v) } }
    fn w64(&self, off: usize, v: u64) { unsafe { ((self.mmio + off) as *mut u64).write_volatile(v) } }
    fn qi(&self) -> bool { self.ecap & 2 != 0 }
    fn fault_offset(&self) -> usize { ((self.cap >> 24 & 0x3ff) * 16) as usize }
    fn fault_count(&self) -> usize { (self.cap >> 40 & 255) as usize + 1 }
    fn iotlb(&self) -> usize { ((self.ecap >> 8 & 0x3ff) * 16) as usize + 8 }
    fn drain(&self) -> u64 {
        // DRD/DWD are implicit for v2+, but 1-setting the descriptor
        // bits is only needed (and supported) on hardware reporting them.
        ((self.cap >> 55 & 1) << 7) | ((self.cap >> 54 & 1) << 6)
    }
}

// Too large for root's stack; the only active IOMMU backend owns it.
static CHUNKS: StaticCell<ArrayVec<(usize, usize), MAX_CHUNKS>> = StaticCell::new(ArrayVec::new());
static DMAR: StaticCell<Dmar> = StaticCell::new(Dmar::empty());
static MAPPINGS: StaticCell<mappings::Mappings<MAX_MAPPINGS>> = StaticCell::new(mappings::Mappings::new());

pub struct Vtd {
    dmar: &'static mut Dmar,
    requesters: requester::Requesters,
    mappings: &'static mut mappings::Mappings<MAX_MAPPINGS>,
    ioapic_ids: ArrayVec<u8, MAX_IOAPICS>,
    units: ArrayVec<Unit, MAX_UNITS>,
    chunks: Option<&'static mut ArrayVec<(usize, usize), MAX_CHUNKS>>,
    used: usize,
    coherent: bool,
    cache_line: usize,
    ticks_per_ms: u64,
    intremap: bool,
    state: u64,
    confined: u64,
    unconfined: u64,
    events: u64,
    shared: Option<Shared>,
    /// The primary: the next context table in the shared region.
    next_context: usize,
    /// The interrupt remapping entries this partition may use.
    irtes: core::ops::Range<usize>,
}

impl Vtd {
    /// None means no DMAR, so discovery may try AMD-Vi. A DMAR that
    /// cannot be used is reported as failed, never mistaken for absence.
    pub fn init(bootinfo: &sel4::BootInfoPtr, phys: &mut crate::acpi::Phys, pci: &pci::Pci,
        ticks_per_ms: u64, intremap: bool, shared: Option<Shared>) -> Option<Self> {
        let mut buf = [0u8; 32 << 10];
        let table = crate::acpi::find(bootinfo, phys, b"DMAR", &mut buf)?;
        let mut me = Self {
            dmar: DMAR.take(), requesters: requester::Requesters::empty(), ioapic_ids: ArrayVec::new(),
            mappings: MAPPINGS.take(),
            units: ArrayVec::new(), chunks: None, used: CHUNK_PAGES,
            coherent: true, cache_line: 64, ticks_per_ms, intremap: false, state: abi::IOMMU_FAILED,
            confined: 0, unconfined: 0, events: 0,
            shared, next_context: shared.map_or(0, |s| s.tables().start), irtes: 0..format::IR_ENTRIES,
        };
        let Some(dmar) = Dmar::parse(table, |b, d, f, off| pci.read32(b, d, f, off)) else {
            log!("l4h-root: VT-d: malformed or unsupported DMAR: DMA is not confined");
            return Some(me);
        };
        *me.dmar = dmar;
        let Some(requesters) = requester::Requesters::discover(|b, d, f, o| pci.read32(b, d, f, o)) else {
            log!("l4h-root: VT-d: malformed PCI bridge topology: DMA is not confined");
            return Some(me);
        };
        me.requesters = requesters;
        if let Some(ids) = crate::acpi::find(bootinfo, phys, b"APIC", &mut buf).and_then(dmar::madt_ioapics) {
            me.ioapic_ids = ids;
        }
        if me.dmar.units.is_empty() {
            log!("l4h-root: VT-d: no unit on PCI segment 0: DMA is not confined");
            return Some(me);
        }
        if let Err(reason) = me.prepare(phys, intremap) {
            log!("l4h-root: VT-d: {}: DMA is not confined", reason);
            return Some(me);
        }
        me.chunks = Some(CHUNKS.take());
        match shared {
            Some(s) if !s.primary => me.join(phys.alloc, pci),
            _ => me.enable(phys.alloc, pci),
        }
        Some(me)
    }

    pub fn info(&self) -> [u64; 6] {
        [self.state, (self.state == abi::IOMMU_ON && self.intremap) as u64,
            self.units.len() as u64, self.confined, self.unconfined, self.events]
    }

    /// Validate every unit before changing any register. Older units can
    /// use register invalidation for DMA; interrupt remapping needs QI.
    fn prepare(&mut self, phys: &mut crate::acpi::Phys, intremap: bool) -> Result<(), &'static str> {
        use sel4::init_thread::slot;
        for (n, desc) in self.dmar.units.iter().enumerate() {
            let mmio = crate::layout::IOMMU_MMIO.base + n * MMIO_STRIDE;
            let mut map_page = |off| -> Result<(), &'static str> {
                let f = phys.frame(desc.base + off).ok_or("registers unavailable in device memory")?;
                crate::vspace::map_frame(&mut crate::mem::ObjCtx::global(phys.alloc), slot::VSPACE.cap(),
                    f, mmio + off, sel4::CapRights::read_write(), crate::blkd::DEVICE_ATTRS);
                Ok(())
            };
            map_page(0)?;
            let mut u = Unit {
                mmio, cap: 0, ecap: 0, levels: 0, width: 0, root: 0, domains: 1..1,
                control: 0, queue: 0, tail: 0, sem: 0, sem_pa: 0, seq: 0, irt: 0,
            };
            u.cap = u.r64(CAP);
            u.ecap = u.r64(ECAP);
            if u.cap == u64::MAX || u.ecap == u64::MAX || u.cap & 7 == 7 {
                return Err("invalid capabilities");
            }
            u.levels = format::levels(u.cap).ok_or("no 39/48-bit legacy page tables")?;
            u.width = (12 + 9 * u.levels).min((u.cap >> 16 & 63) as u8 + 1).min(self.dmar.haw);
            if u.width < 32 { return Err("unsupported DMA address width"); }
            if u.r32(VER) >> 4 & 15 < 2 && u.cap & (3 << 54) != 3 << 54 {
                return Err("DMA read/write draining unavailable");
            }
            // l4h's MSI destinations use xAPIC ID 0. Do not advertise
            // remapping on hardware that requires extended mode.
            if u.ecap & (1 << 61) != 0 { return Err("extended interrupt mode required"); }
            let bytes = (u.fault_offset() + u.fault_count() * 16).max(u.iotlb() + 8).max(PAGE);
            if bytes > MMIO_STRIDE { return Err("register aperture too large"); }
            let ids = 1u32 << (4 + 2 * (u.cap & 7));
            u.domains = match self.shared {
                // Domain 0 is reserved with caching mode (CAP.CM).
                Some(s) => { let p = s.part(ids); p.start.max(1)..p.end }
                None => 1..ids,
            };
            if self.shared.is_some() {
                if n >= l4h_partition::IOMMU_MAX_UNITS { return Err("more units than the shared region has room for"); }
                if !u.qi() { return Err("a shared unit needs queued invalidation"); }
            }
            for off in (PAGE..bytes.next_multiple_of(PAGE)).step_by(PAGE) { map_page(off)?; }
            self.coherent &= u.ecap & 1 != 0;
            self.units.push(u).ok().unwrap();
        }
        if !self.coherent {
            let cpu = core::arch::x86_64::__cpuid(1);
            self.cache_line = ((cpu.ebx as usize >> 8) & 255) * 8;
            if cpu.edx & (1 << 19) == 0 || !self.cache_line.is_power_of_two() || self.cache_line > PAGE {
                return Err("noncoherent tables require CLFLUSH");
            }
        }
        self.intremap = intremap && self.dmar.interrupt_remapping && self.units.iter().all(|u| u.ecap & 8 != 0 && u.qi());
        if intremap && !self.intremap {
            log!("l4h-root: VT-d: interrupt remapping unavailable; confining DMA only");
        }
        if !self.intremap && self.units.iter().any(|u| u.ecap & (1 << 62) != 0) {
            return Err("hardware requires interrupt remapping");
        }
        if let Some(s) = self.shared {
            if !s.primary && s.control().units.load(Ordering::Relaxed) as usize != self.units.len() {
                return Err("partition 0 enabled a different number of units");
            }
            let p = s.part(format::IR_SHARED_ENTRIES as u32);
            self.irtes = p.start as usize..p.end as usize;
        }
        Ok(())
    }

    fn deadline(&self) -> u64 { l4h_host::ticks::now().saturating_add(self.ticks_per_ms.max(1) * 1000) }

    fn wait_for(&self, u: usize, what: &str, mut done: impl FnMut(&Unit) -> bool) {
        let end = self.deadline();
        while !done(&self.units[u]) {
            assert!(l4h_host::ticks::now() < end, "l4h-root: VT-d {}: {} timed out", u, what);
            core::hint::spin_loop();
        }
    }

    fn set_control(&mut self, u: usize, bit: u32, enabled: bool) {
        let unit = &mut self.units[u];
        if enabled { unit.control |= bit; } else { unit.control &= !bit; }
        unit.w32(GCMD, unit.control);
        self.wait_for(u, "global command", |u| (u.r32(GSTS) & bit != 0) == enabled);
    }

    fn command(&self, u: usize, bit: u32, status_set: bool) {
        let unit = &self.units[u];
        unit.w32(GCMD, unit.control | bit);
        self.wait_for(u, "global command", |u| (u.r32(GSTS) & bit != 0) == status_set);
    }

    fn enable(&mut self, alloc: &mut Alloc, pci: &pci::Pci) {
        for n in 0..self.units.len() {
            self.units[n].control = self.units[n].r32(GSTS) & (TE | QIE | IRE | CFI | EAFL);
            self.units[n].w32(FECTL, 1 << 31); // faults are polled
            if self.units[n].control & IRE != 0 { self.set_control(n, IRE, false); }
            self.set_control(n, TE, false);
            if self.units[n].control & QIE != 0 {
                self.wait_for(n, "firmware invalidation queue", |u| u.r64(IQH) == u.r64(IQT));
                self.set_control(n, QIE, false);
            }
            if self.units[n].control & EAFL != 0 { self.set_control(n, EAFL, false); }
            if self.units[n].control & CFI != 0 { self.set_control(n, CFI, false); }
            self.units[n].root = match self.shared {
                Some(s) => s.unit_page(n, SHARED_ROOT).1,
                None => self.page(alloc).1,
            };
        }
        // Every bus with a function, whichever partition has it, gets its
        // context table now: no other partition ever adds one.
        if let Some(d) = crate::partition::get().filter(|_| self.shared.is_some()) {
            for o in d.owners() {
                // The unit by the function, as attach() and domain()
                // choose it; the table by the requester it reaches it as.
                if let Some(unit) = self.dmar.owner(o.bdf) {
                    self.context_table(alloc, unit, self.requesters.requester(o.bdf));
                }
            }
        }
        // Firmware's reserved memory must be reachable when TE goes on,
        // including for devices that no l4h driver will ever attach.
        for r in 0..self.dmar.reserved.len() {
            let reserved = self.dmar.reserved[r];
            for sid in reserved.scope.first..=reserved.scope.last {
                // Partition 0 reads every partition's functions; each
                // maps its own reserved memory (`join`).
                if pci.read32((sid >> 8) as u8, (sid >> 3 & 31) as u8, (sid & 7) as u8, 0) & 0xffff == 0xffff
                    || !pci::ours(sid) {
                    continue;
                }
                let unit = self.dmar.owner(sid).expect("VT-d: RMRR device has no remapping unit");
                let d = self.domain(alloc, unit, sid);
                self.map_range(alloc, d, reserved.start, reserved.end - reserved.start, true);
            }
        }
        for n in 0..self.units.len() {
            let root = self.units[n].root;
            self.units[n].w64(RTADDR, root as u64); // legacy mode, TTM=00
            self.command(n, SRTP, true);
            if self.units[n].qi() {
                let (queue, queue_pa) = match self.shared {
                    Some(s) => s.unit_page(n, SHARED_QUEUE),
                    None => self.page(alloc),
                };
                let (sem, sem_pa) = match self.shared {
                    Some(s) => s.done(n),
                    None => self.page(alloc),
                };
                let u = &mut self.units[n];
                u.queue = queue;
                u.sem = sem;
                u.sem_pa = sem_pa;
                u.w32(IECTL, 1 << 31);
                u.w64(IQT, 0);
                u.w64(IQA, queue_pa as u64); // 4 KiB, 128-bit descriptors
                self.set_control(n, QIE, true);
            }
            self.invalidate(n, true, None);
            if self.intremap {
                let (irt, pa, size) = match self.shared {
                    Some(s) => { let (va, pa) = s.unit_page(n, SHARED_IRT); (va, pa, format::IR_SHARED_SIZE) }
                    None => { let (va, pa) = self.page(alloc); (va, pa, format::IR_SIZE) }
                };
                self.units[n].irt = irt;
                self.units[n].w64(IRTA, pa as u64 | size);
                self.command(n, SIRTP, true);
                self.queue(n, &[format::invalidate_interrupts()]);
                self.set_control(n, IRE, true);
                // Never allow compatibility MSIs to bypass the IRTEs.
                assert_eq!(self.units[n].r32(GSTS) & CFI, 0);
            }
            self.set_control(n, TE, true);
            if self.units[n].cap & (3 << 5) != 0 {
                self.units[n].w32(PMEN, 0);
                self.wait_for(n, "protected memory disable", |u| u.r32(PMEN) & 1 == 0);
            }
            info!("l4h-root: VT-d at {:#x}: enabled, {}-bit DMA, interrupts {}",
                self.dmar.units[n].base, self.units[n].width, if self.intremap { "remapped" } else { "not remapped" });
        }
        self.state = abi::IOMMU_ON;
    }

    /// A secondary partition: partition 0 set the units up and keeps
    /// them; take its tables and map our own firmware-reserved memory.
    fn join(&mut self, alloc: &mut Alloc, pci: &pci::Pci) {
        let s = self.shared.unwrap();
        for n in 0..self.units.len() {
            let (sem, sem_pa) = s.done(n);
            let u = &mut self.units[n];
            u.control = u.r32(GSTS);
            assert!(u.control & TE != 0 && u.control & QIE != 0, "VT-d {}: partition 0 did not enable it", n);
            u.root = s.unit_page(n, SHARED_ROOT).1;
            u.queue = s.unit_page(n, SHARED_QUEUE).0;
            (u.sem, u.sem_pa) = (sem, sem_pa);
            u.irt = s.unit_page(n, SHARED_IRT).0;
            info!("l4h-root: VT-d at {:#x}: shared, {}-bit DMA, interrupts {}",
                self.dmar.units[n].base, u.width, if self.intremap { "remapped" } else { "not remapped" });
        }
        self.state = abi::IOMMU_ON;
        // Our functions only: others' read as absent, or, the bridges
        // above ours, as present but partition 0's to map.
        for r in 0..self.dmar.reserved.len() {
            let reserved = self.dmar.reserved[r];
            for sid in reserved.scope.first..=reserved.scope.last {
                if pci.read32((sid >> 8) as u8, (sid >> 3 & 31) as u8, (sid & 7) as u8, 0) & 0xffff == 0xffff
                    || !pci::ours(sid) {
                    continue;
                }
                let unit = self.dmar.owner(sid).expect("VT-d: RMRR device has no remapping unit");
                let d = self.domain(alloc, unit, sid);
                self.map_range(alloc, d, reserved.start, reserved.end - reserved.start, true);
                self.invalidate(unit, false, Some(d.id));
            }
        }
    }

    fn flush_cpu(&self, ptr: usize, len: usize) {
        if !self.coherent {
            let line = self.cache_line;
            for at in (ptr & !(line - 1)..ptr + len).step_by(line) {
                unsafe { core::arch::x86_64::_mm_clflush(at as *const u8) };
            }
        }
        // Orders cached table stores/CLFLUSH before present bits and MMIO.
        core::sync::atomic::fence(Ordering::SeqCst);
    }

    fn store(&self, ptr: *mut u64, value: u64) {
        unsafe { ptr.write_volatile(value) };
        self.flush_cpu(ptr as usize, 8);
    }

    fn page(&mut self, alloc: &mut Alloc) -> (usize, usize) {
        if self.used == CHUNK_PAGES {
            use crate::vspace::{LARGE_PAGE_BP, map_large_page};
            use sel4::init_thread::slot;
            let chunks = self.chunks.as_mut().unwrap();
            assert!(!chunks.is_full(), "VT-d: out of table space");
            let (ut, page) = alloc.slots.global(|s| (s.alloc(), s.alloc()));
            let mut region = alloc.split(CHUNK_BITS, ut).expect("VT-d: no memory for tables");
            let pa = region.retype(&LARGE_PAGE_BP, 1, crate::mem::Dest::new(crate::slot::CNODE.cap(), page)).expect("VT-d table chunk");
            let va = crate::layout::IOMMU_TABLES.base + (chunks.len() << CHUNK_BITS);
            let cap = sel4::init_thread::Slot::<sel4::cap_type::LargePage>::from_index(page).cap();
            map_large_page(&mut crate::mem::ObjCtx::global(alloc), slot::VSPACE.cap(), cap, va, sel4::CapRights::read_write());
            chunks.push((va, pa)).ok().unwrap();
            self.used = 0;
        }
        let &(va, pa) = self.chunks.as_ref().unwrap().last().unwrap();
        let off = self.used * PAGE;
        self.used += 1;
        assert!(pa.checked_add(off + PAGE).is_some_and(|end| end as u64 <= 1u64 << self.dmar.haw),
            "VT-d: table memory exceeds host address width");
        // seL4 zeroed this memory; publish those zeros to noncoherent walkers.
        self.flush_cpu(va + off, PAGE);
        (va + off, pa + off)
    }

    fn table(&self, pa: u64) -> *mut u64 {
        let pa = (pa & ADDR) as usize;
        if let Some(va) = self.shared.and_then(|s| s.va_of(pa)) {
            return va as *mut u64;
        }
        let &(va, base) = self.chunks.as_ref().unwrap().iter()
            .find(|&&(_, base)| (base..base + (1 << CHUNK_BITS)).contains(&pa))
            .expect("VT-d: table outside chunks");
        (va + pa - base) as *mut u64
    }

    fn domain(&mut self, alloc: &mut Alloc, unit: usize, sid: u16) -> Domain {
        // Devices behind a conventional PCI bridge share its requester
        // and therefore one domain. Never replace a sibling's mappings.
        let sid = self.requesters.requester(sid);
        let ctx = unsafe { self.context_table(alloc, unit, sid).add((sid & 255) as usize * 2) };
        let (lo, hi) = unsafe { (ctx.read_volatile(), ctx.add(1).read_volatile()) };
        if lo & PRESENT != 0 {
            return Domain { unit, sid, id: (hi >> 8) as u16, root: (lo & ADDR) as usize };
        }
        let next = self.units[unit].domains.start;
        assert!(next < self.units[unit].domains.end, "VT-d: out of domain IDs");
        self.units[unit].domains.start += 1;
        let d = Domain { unit, sid, id: next as u16, root: self.page(alloc).1 };
        let [lo, hi] = format::context(d.root, d.id, self.units[unit].levels);
        self.store(unsafe { ctx.add(1) }, hi);
        self.store(ctx, lo); // present last
        if self.shared.is_some() && self.state == abi::IOMMU_ON && self.units[unit].cap & (1 << 7) != 0 {
            // Caching mode: the unit may hold this requester's entry as
            // not present, tagged with domain 0. Drop just that.
            self.queue(unit, &[format::invalidate_context_device(sid, 0), format::invalidate_iotlb(Some(0), 0)]);
        }
        d
    }

    /// The context table of requester `sid`'s bus, made if missing. In a
    /// shared IOMMU only the primary makes them, at init.
    fn context_table(&mut self, alloc: &mut Alloc, unit: usize, sid: u16) -> *mut u64 {
        let root = unsafe { self.table(self.units[unit].root as u64).add((sid >> 8) as usize * 2) };
        let mut entry = unsafe { root.read_volatile() };
        if entry & PRESENT == 0 {
            let pa = match self.shared {
                None => self.page(alloc).1,
                Some(s) => {
                    assert!(s.primary && self.state != abi::IOMMU_ON,
                        "VT-d: bus {:#x} has no context table from partition 0", sid >> 8);
                    assert!(self.next_context + PAGE <= s.tables().end, "VT-d: out of shared context tables");
                    let (va, pa) = s.at(self.next_context);
                    self.next_context += PAGE;
                    // The shim zeroed the region.
                    self.flush_cpu(va, PAGE);
                    pa
                }
            };
            entry = pa as u64 | PRESENT;
            self.store(root, entry);
        }
        self.table(entry)
    }

    pub fn attach(&mut self, alloc: &mut Alloc, device: &pci::Device) -> Option<Domain> {
        if self.state != abi::IOMMU_ON { return None; }
        let sid = crate::amdvi::device_id(device);
        let Some(unit) = self.dmar.owner(sid) else {
            log!("l4h-root: VT-d: {:02x}:{:02x}.{} is behind no IOMMU: DMA is not confined",
                device.bus, device.dev, device.func);
            self.unconfined += 1;
            return None;
        };
        let d = self.domain(alloc, unit, sid);
        if sid != d.sid {
            info!("l4h-root: VT-d: {:02x}:{:02x}.{} uses shared requester {:02x}:{:02x}.{}",
                device.bus, device.dev, device.func, d.sid >> 8, d.sid >> 3 & 31, d.sid & 7);
        }
        // Global context + IOTLB invalidation also evicts cached misses
        // tagged with domain zero (CAP.CM), not just the new domain ID.
        // A shared unit: domain() invalidated just this requester's.
        if self.shared.is_none() {
            self.invalidate(unit, true, None);
        }
        self.confined += 1;
        Some(d)
    }

    fn walk(&mut self, mut alloc: Option<&mut Alloc>, d: Domain, iova: usize) -> Option<*mut u64> {
        let mut table = self.table(d.root as u64);
        for level in (2..=self.units[d.unit].levels).rev() {
            let pte = unsafe { table.add(iova >> (12 + 9 * (level - 1)) & 511) };
            let mut entry = unsafe { pte.read_volatile() };
            if entry & (READ | WRITE) == 0 {
                entry = self.page(alloc.as_deref_mut()?).1 as u64 | READ | WRITE;
                self.store(pte, entry);
            }
            table = self.table(entry);
        }
        Some(unsafe { table.add(iova >> 12 & 511) })
    }

    fn map_range(&mut self, alloc: &mut Alloc, d: Domain, pa: usize, len: usize, write: bool) {
        let range = format::range(pa, len, self.units[d.unit].width).expect("VT-d: invalid DMA range");
        let flags = READ | if write { WRITE } else { 0 }
            | if self.units[d.unit].ecap & (1 << 7) != 0 { format::SNOOP } else { 0 };
        for at in range.step_by(PAGE) {
            let pte = self.walk(Some(alloc), d, at).unwrap();
            self.store(pte, at as u64 | flags);
        }
    }

    pub fn map(&mut self, alloc: &mut Alloc, d: Domain, pa: usize, len: usize, write: bool) {
        let range = format::range(pa, len, self.units[d.unit].width).expect("VT-d: invalid DMA range");
        // Firmware-reserved memory must never become a recyclable pool:
        // its permanent mapping would defeat unmap's isolation guarantee.
        assert!(!self.dmar.reserved.iter().any(|r| self.requesters.scope_contains(r.scope, d.sid)
            && range.start < r.end && r.start < range.end), "VT-d: allocated DMA memory overlaps an RMRR");
        if !self.mappings.acquire(d.key(), pa, len, write) { return; }
        self.map_range(alloc, d, pa, len, write);
        self.invalidate(d.unit, false, Some(d.id));
    }

    /// The final unmap drains DMA before the caller reuses RAM.
    /// RMRRs remain mapped for the lifetime of their firmware requester.
    pub fn unmap(&mut self, d: Domain, pa: usize, len: usize) {
        let range = format::range(pa, len, self.units[d.unit].width).expect("VT-d: invalid DMA range");
        if !self.mappings.release(d.key(), pa, len) { return; }
        let reserved: ArrayVec<_, { dmar::MAX_RESERVED }> = self.dmar.reserved.iter()
            .filter(|r| self.requesters.scope_contains(r.scope, d.sid)).map(|r| (r.start, r.end)).collect();
        for at in range.step_by(PAGE) {
            if reserved.iter().any(|&(start, end)| (start..end).contains(&at)) { continue; }
            if let Some(pte) = self.walk(None, d, at) { self.store(pte, 0); }
        }
        self.invalidate(d.unit, false, Some(d.id));
    }

    pub fn msi(&mut self, d: Domain, vector: u64) -> (u64, u32) {
        let data = pci::msi_data(vector);
        if !self.intremap { return (pci::msi_address(), data); }
        format::msi(self.interrupt(d.unit, d.sid, data))
    }

    /// None selects a legacy I/O APIC entry. With remapping enabled,
    /// missing firmware routing is an error, never a compatibility bypass.
    pub fn ioapic_irq(&mut self, index: usize, vector: u64) -> Result<Option<u16>, &'static str> {
        if self.state != abi::IOMMU_ON || !self.intremap { return Ok(None); }
        let id = *self.ioapic_ids.get(index).ok_or("I/O APIC missing from MADT")?;
        let a = *self.dmar.ioapics.iter().find(|a| a.id == id).ok_or("I/O APIC missing from DMAR")?;
        Ok(Some(self.interrupt(a.unit, a.sid, pci::msi_data(vector))))
    }

    fn interrupt(&mut self, unit: usize, sid: u16, data: u32) -> u16 {
        assert!(data <= 255);
        let table = self.units[unit].irt as *mut u64;
        let entry = format::irte(sid, data as u8, crate::partition::msi_dest());
        for index in self.irtes.clone() {
            let ptr = unsafe { table.add(index * 2) };
            let old = unsafe { [ptr.read_volatile(), ptr.add(1).read_volatile()] };
            if old == entry { return index as u16; }
            if old[0] & PRESENT == 0 {
                self.store(unsafe { ptr.add(1) }, entry[1]);
                self.store(ptr, entry[0]);
                let inv = if self.shared.is_some() {
                    format::invalidate_interrupt(index as u16)
                } else {
                    format::invalidate_interrupts()
                };
                self.queue(unit, &[inv]);
                return index as u16;
            }
        }
        panic!("VT-d: interrupt table full");
    }

    fn invalidate(&mut self, n: usize, context: bool, domain: Option<u16>) {
        if self.units[n].qi() {
            let iotlb = format::invalidate_iotlb(domain, self.units[n].drain());
            if context {
                self.queue(n, &[format::invalidate_context(), iotlb]);
            } else {
                self.queue(n, &[iotlb]);
            }
        } else {
            if self.units[n].cap & (1 << 4) != 0 { self.command(n, WBF, false); }
            if context {
                self.units[n].w64(CCMD, (1 << 63) | (1 << 61));
                self.wait_for(n, "context invalidation", |u| u.r64(CCMD) & (1 << 63) == 0);
                assert_ne!(self.units[n].r64(CCMD) >> 59 & 3, 0, "VT-d: context invalidation failed");
            }
            let u = &self.units[n];
            let command = (1 << 63) | domain.map_or(1 << 60, |d| (2 << 60) | (d as u64) << 32)
                | ((u.drain() >> 6) << 48);
            u.w64(u.iotlb(), command);
            self.wait_for(n, "IOTLB invalidation", |u| u.r64(u.iotlb()) & (1 << 63) == 0);
            assert_ne!(self.units[n].r64(self.units[n].iotlb()) >> 57 & 3, 0, "VT-d: IOTLB invalidation failed");
        }
    }

    /// Submit `descs` and wait for them. A shared unit's queue is the
    /// lock holder's: the tail and the last wait value are read anew.
    fn queue(&mut self, n: usize, descs: &[[u64; 2]]) {
        if let Some(s) = self.shared {
            s.lock(n);
            let u = &mut self.units[n];
            u.tail = u.r64(IQT) as usize;
            u.seq = unsafe { (u.sem as *const u32).read_volatile() };
        }
        for &d in descs { self.submit(n, d); }
        self.sync(n);
        if let Some(s) = self.shared { s.unlock(n); }
    }

    fn submit(&mut self, n: usize, desc: [u64; 2]) {
        let next = (self.units[n].tail + 16) & (PAGE - 1);
        self.wait_for(n, "invalidation queue full", |u| u.r64(IQH) as usize != next);
        let u = &mut self.units[n];
        assert_eq!(u.r32(FSTS) & QI_ERRORS, 0, "VT-d: invalidation queue fault");
        let ptr = (u.queue + u.tail) as *mut u64;
        unsafe { ptr.write_volatile(desc[0]); ptr.add(1).write_volatile(desc[1]); }
        core::sync::atomic::fence(Ordering::SeqCst); // QI accesses are always coherent
        u.tail = next;
        u.w64(IQT, next as u64);
    }

    fn sync(&mut self, n: usize) {
        self.units[n].seq = self.units[n].seq.wrapping_add(1);
        let u = &self.units[n];
        let desc = format::wait(u.sem_pa, u.seq);
        self.submit(n, desc);
        self.wait_for(n, "invalidation completion", |u| {
            assert_eq!(u.r32(FSTS) & QI_ERRORS, 0, "VT-d: invalidation queue fault");
            unsafe { (u.sem as *const u32).read_volatile() == u.seq }
        });
        compiler_fence(Ordering::SeqCst);
    }

    /// Faults: with several partitions, partition 0 handles everyone's.
    pub fn poll(&mut self) {
        if self.state != abi::IOMMU_ON || self.shared.is_some_and(|s| !s.primary) { return; }
        let mut shown = 0;
        let mut dropped = 0;
        for (n, u) in self.units.iter().enumerate() {
            let status = u.r32(FSTS);
            assert_eq!(status & QI_ERRORS, 0, "VT-d: invalidation queue fault");
            for i in 0..u.fault_count() {
                let off = u.fault_offset() + i * 16;
                let hi = u.r64(off + 8);
                if hi & (1 << 63) == 0 { continue; }
                let addr = u.r64(off);
                self.events = self.events.saturating_add(1);
                if shown < EVENTS_PER_POLL {
                    log!("l4h-root: VT-d {}: {:02x}:{:02x}.{}: fault {:#x}, info {:#x}{}",
                        n, hi >> 8 & 255, hi >> 3 & 31, hi & 7, hi >> 32 & 255, addr,
                        crate::iommu::shared::OwnerNote(hi as u16));

                    shown += 1;
                } else { dropped += 1; }
                u.w64(off + 8, 1 << 63); // F is W1C
            }
            if status & 1 != 0 {
                log!("l4h-root: VT-d {}: fault records overflowed", n);
                self.events = self.events.saturating_add(1);
                u.w32(FSTS, 1); // PFO is W1C; PPF follows the fault records
            }
        }
        if dropped != 0 { log!("l4h-root: VT-d: {} more faults not shown", dropped); }
    }
}

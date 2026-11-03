//! One IOMMU shared by several partitions (DESIGN.md §4.6).
//!
//! The shim reserves one region for the whole machine. Partition 0 resets
//! the units, builds the tables every partition shares in it (VT-d root
//! and context tables, interrupt remapping tables, AMD's device table),
//! enables translation and then sets the ready flag. Every partition's
//! root then writes only its own functions' entries, with page tables in
//! its own RAM and its own share of domain IDs and interrupt entries. Only
//! the command queues are written by all: a ticket lock per unit in the
//! control page serializes "write commands, move the tail, wait for
//! completion", the one step the drivers already take for it.

use core::ops::Range;
use core::sync::atomic::Ordering;

use l4h_partition::{
    IOMMU_MAX_UNITS, IOMMU_READY_ABSENT, IOMMU_READY_OFF, IOMMU_READY_ON, IOMMU_TABLES_BASE, IOMMU_UNIT_BASE,
    IOMMU_UNIT_SIZE, IommuControl, IommuLock,
};

use crate::devmem::DevMem;
use crate::mem::Alloc;

#[derive(Clone, Copy)]
pub struct Shared {
    pub va: usize,
    pub pa: usize,
    pub size: usize,
    pub primary: bool,
    part: l4h_partition::Iommu,
    index: u32,
    ticks_per_ms: u64,
}

impl Shared {
    /// The shared region, mapped, when this is one of several partitions.
    pub fn new(alloc: &mut Alloc, devmem: &mut DevMem, ticks_per_ms: u64) -> Option<Shared> {
        let d = crate::partition::get().filter(|d| d.count > 1)?;
        let (pa, size) = (d.iommu.paddr as usize, d.iommu.size as usize);
        let region = &crate::layout::IOMMU_SHARED;
        assert!(pa != 0 && size <= region.size && size >= IOMMU_TABLES_BASE as usize + (2 << 20),
            "l4h-root: shared IOMMU region {:#x}+{:#x} unusable", pa, size);
        crate::partition::map(alloc, devmem, pa, size, region.base)
            .expect("l4h-root: cannot map the shared IOMMU region");
        Some(Shared { va: region.base, pa, size, primary: d.is_primary(), part: d.iommu, index: d.index, ticks_per_ms })
    }

    pub fn control(&self) -> &'static IommuControl {
        // The control page lives as long as root, at a fixed address.
        unsafe { &*(self.va as *const IommuControl) }
    }

    /// This partition's part of `0..n` (domain IDs, interrupt entries).
    pub fn part(&self, n: u32) -> Range<u32> {
        self.part.part(n)
    }

    /// (virtual, physical) address of `off` in the region.
    pub fn at(&self, off: usize) -> (usize, usize) {
        assert!(off < self.size);
        (self.va + off, self.pa + off)
    }

    /// Unit `n`'s own pages: `page` of IOMMU_UNIT_SIZE / 4096.
    pub fn unit_page(&self, n: usize, page: usize) -> (usize, usize) {
        assert!(n < IOMMU_MAX_UNITS && (page + 1) * 4096 <= IOMMU_UNIT_SIZE as usize);
        self.at(IOMMU_UNIT_BASE as usize + n * IOMMU_UNIT_SIZE as usize + page * 4096)
    }

    /// The table area (AMD device table, VT-d context tables).
    pub fn tables(&self) -> Range<usize> {
        IOMMU_TABLES_BASE as usize..self.size
    }

    /// Whether physical address `pa` is in the region: its virtual one.
    pub fn va_of(&self, pa: usize) -> Option<usize> {
        (self.pa..self.pa + self.size).contains(&pa).then(|| self.va + pa - self.pa)
    }

    /// Unit `n`'s completion word: (virtual, physical) address.
    pub fn done(&self, n: usize) -> (usize, usize) {
        let l = &self.control().locks[n].done as *const _ as usize;
        (l, self.pa + l - self.va)
    }

    /// Take unit `n`'s command queue lock.
    pub fn lock(&self, n: usize) {
        let l: &IommuLock = &self.control().locks[n];
        let ticket = l.next.fetch_add(1, Ordering::Relaxed);
        let second = self.ticks_per_ms.max(1) * 1000;
        let mut end = l4h_host::ticks::now() + second;
        while l.serving.load(Ordering::Acquire) != ticket {
            if l4h_host::ticks::now() > end {
                // A partition that died holding it blocks every partition's
                // IOMMU updates until the machine restarts (§4.6).
                log!("l4h-root: iommu {}: command queue lock held by partition {} for over a second",
                    n, l.holder.load(Ordering::Relaxed));
                end = l4h_host::ticks::now() + second;
            }
            core::hint::spin_loop();
        }
        l.holder.store(self.index, Ordering::Relaxed);
    }

    pub fn unlock(&self, n: usize) {
        let l = &self.control().locks[n];
        l.serving.fetch_add(1, Ordering::Release);
    }

    /// The primary: the IOMMUs are set up (`state`, abi::IOMMU_*), with
    /// `units` units and interrupts remapped or not.
    pub fn set_ready(&self, state: u64, units: usize, intremap: bool) {
        let c = self.control();
        c.units.store(units as u32, Ordering::Relaxed);
        c.intremap.store(intremap as u32, Ordering::Relaxed);
        let ready = match state {
            l4h_abi::IOMMU_ON => IOMMU_READY_ON,
            l4h_abi::IOMMU_NONE => IOMMU_READY_ABSENT,
            _ => IOMMU_READY_OFF,
        };
        c.ready.store(ready, Ordering::Release);
    }

    /// A secondary: wait until the primary set the IOMMUs up, before any
    /// device of ours may DMA. IOMMU_READY_*, the units and whether
    /// interrupts are remapped.
    pub fn wait_ready(&self) -> (u32, usize, bool) {
        let c = self.control();
        let second = self.ticks_per_ms.max(1) * 1000;
        let mut end = l4h_host::ticks::now() + second;
        loop {
            let ready = c.ready.load(Ordering::Acquire);
            if ready != 0 {
                return (ready, c.units.load(Ordering::Relaxed) as usize, c.intremap.load(Ordering::Relaxed) != 0);
            }
            if l4h_host::ticks::now() > end {
                log!("l4h-root: waiting for partition 0 to set up the IOMMU");
                end = l4h_host::ticks::now() + 10 * second;
            }
            core::hint::spin_loop();
        }
    }
}

/// After a requester in a fault message: the partition it belongs to,
/// when there are several.
pub struct OwnerNote(pub u16);

impl core::fmt::Display for OwnerNote {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        if crate::partition::get().is_none_or(|d| d.count < 2) {
            return Ok(());
        }
        match crate::partition::owner(self.0) {
            Some(p) => write!(f, " (partition {})", p),
            None => write!(f, " (no partition's)"),
        }
    }
}

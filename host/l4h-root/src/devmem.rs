//! Device memory: frames for physical address ranges (PCI BARs), carved out
//! of the device Untypeds by repeated halving.

use core::ops::Range;
use core::sync::atomic::{AtomicBool, Ordering};

use sel4::{ObjectBlueprint, cap, cap_type};

use l4h_host::fixed::ArrayVec;

use crate::mem::{Alloc, Dest, Slot, Slots};
use crate::vspace::FRAME_BP;

/// Free device regions, at most: the boot device Untypeds
/// (KernelMaxNumBootinfoUntypedCaps, 230) and the halves split off them.
/// Carving a range leaves at most one free half per halving, and the
/// ranges carved (BARs, boot modules, ACPI pages) are few and mostly
/// contiguous, so this leaves ample room.  A carve that would overflow it
/// fails before it starts.
const DEVMEM_REGIONS: usize = 1024;

struct Region {
    cap: cap::Untyped,
    paddr: usize,
    size_bits: usize,
}

type Regions = ArrayVec<Region, DEVMEM_REGIONS>;

/// In .bss: too large for the root task's stack, where `Host` is.
static mut FREE: Regions = ArrayVec::new();
static FREE_TAKEN: AtomicBool = AtomicBool::new(false);

pub struct DevMem {
    /// Untouched device Untypeds (boot ones and halves split off them).
    free: &'static mut Regions,
}

/// The frame capability in root slot `s` (of a range from `DevMem::frames`).
pub fn granule(s: Slot) -> cap::Granule {
    sel4::init_thread::Slot::<cap_type::Granule>::from_index(s).cap()
}

impl DevMem {
    pub fn from_bootinfo(bootinfo: &sel4::BootInfo) -> Self {
        assert!(!FREE_TAKEN.swap(true, Ordering::Relaxed), "device memory taken twice");
        // The flag gives out the only reference; the root task is
        // single-threaded.
        let free = unsafe { &mut *(&raw mut FREE) };
        for (i, desc) in bootinfo.untyped_list().iter().enumerate() {
            if desc.is_device() {
                let r = Region { cap: bootinfo.untyped().index(i).cap(), paddr: desc.paddr(), size_bits: desc.size_bits() };
                if free.push(r).is_err() {
                    sel4::debug_println!("l4h-root: more than {} device untypeds, ignoring the rest", DEVMEM_REGIONS);
                    break;
                }
            }
        }
        DevMem { free }
    }

    /// 4 KiB frames covering [paddr, paddr + size), which must be aligned to
    /// its power-of-two size (as PCI BARs are), in consecutive root slots.
    pub fn frames(&mut self, slots: &mut Slots, paddr: usize, size: usize) -> Option<Range<Slot>> {
        let size = size.max(4096).next_power_of_two();
        let bits = size.trailing_zeros() as usize;
        assert!(paddr % size == 0, "device range {:#x}+{:#x} not aligned", paddr, size);
        let i = self
            .free
            .iter()
            .position(|r| r.paddr <= paddr && paddr + size <= r.paddr + (1 << r.size_bits))?;
        // Each halving leaves one free half.
        if self.free.len() - 1 + (self.free[i].size_bits - bits) > DEVMEM_REGIONS {
            sel4::debug_println!("l4h-root: device memory table full, cannot carve {:#x}+{:#x}", paddr, size);
            return None;
        }
        let mut r = self.free.swap_remove(i);
        while r.size_bits > bits {
            let half = r.size_bits - 1;
            let s = slots.alloc_range(2);
            r.cap
                .untyped_retype(&ObjectBlueprint::Untyped { size_bits: half }, &Dest::new(crate::slot::CNODE.cap(), s.start).cnode, s.start, 2)
                .expect("split device untyped");
            let lo = Region { cap: slot_cap(s.start), paddr: r.paddr, size_bits: half };
            let hi = Region { cap: slot_cap(s.start + 1), paddr: r.paddr + (1 << half), size_bits: half };
            let (keep, spare) = if paddr < hi.paddr { (lo, hi) } else { (hi, lo) };
            // Room was checked above.
            let _ = self.free.push(spare);
            r = keep;
        }
        let n = size / 4096;
        let s = slots.alloc_range(n);
        // The kernel caps fan-out per call (a framebuffer can be larger).
        for at in (0..n).step_by(crate::RETYPE_FAN_OUT) {
            let k = (n - at).min(crate::RETYPE_FAN_OUT);
            r.cap.untyped_retype(&FRAME_BP, &Dest::new(crate::slot::CNODE.cap(), s.start).cnode, s.start + at, k).expect("device frames");
        }
        Some(s)
    }

    /// Whether the free device Untypeds cover [paddr, paddr + size).
    fn covers(&self, paddr: usize, size: usize) -> bool {
        let (mut at, end) = (paddr, paddr + size);
        while at < end {
            match self.free.iter().find(|r| r.paddr <= at && at < r.paddr + (1 << r.size_bits)) {
                Some(r) => at = r.paddr + (1 << r.size_bits),
                None => return false,
            }
        }
        true
    }

    /// 4 KiB frames covering the page-aligned range [paddr, paddr + size),
    /// which may span several device Untypeds and need not be aligned to
    /// its size.  The frames come in chunks of consecutive root slots, in
    /// order, each passed to `f` as it is carved: a range can be far too
    /// large to list (a boot module of many GiB).  None if the range is
    /// not all free device memory (then nothing is carved), or if carving
    /// fails part way.
    pub fn frames_range(
        &mut self,
        alloc: &mut Alloc,
        paddr: usize,
        size: usize,
        mut f: impl FnMut(&mut Alloc, Range<Slot>),
    ) -> Option<()> {
        assert!(paddr % 4096 == 0 && size % 4096 == 0);
        if !self.covers(paddr, size) {
            return None;
        }
        let (mut at, end) = (paddr, paddr + size);
        while at < end {
            let r = self.free.iter().find(|r| r.paddr <= at && at < r.paddr + (1 << r.size_bits))?;
            // The largest aligned block at `at` inside both r and the
            // range, of at most RETYPE_FAN_OUT frames.
            let bits = (at.trailing_zeros() as usize)
                .min(usize::BITS as usize - 1 - (end - at).leading_zeros() as usize)
                .min(r.size_bits)
                .min(12 + crate::RETYPE_FAN_OUT.trailing_zeros() as usize);
            let frames = alloc.slots.global(|slots| self.frames(slots, at, 1 << bits))?;
            f(alloc, frames);
            at += 1 << bits;
        }
        Some(())
    }
}

fn slot_cap(i: usize) -> cap::Untyped {
    sel4::init_thread::Slot::<cap_type::Untyped>::from_index(i).cap()
}

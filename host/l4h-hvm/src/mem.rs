//! An HVM guest's RAM as l4h-hvm sees it: GPA g at RAM_VA + g.  On x86-64,
//! low RAM and the RAM above 4 GiB (the hole between is never mapped); on
//! AArch64 one contiguous range from `ram_base`.  A 2 MiB block
//! is mapped the first time anything here touches it (`map`): the RAM the
//! guest has not touched yet need not be backed (DESIGN.md §5.11).  The
//! virtqueue code of l4h-vmm (virtq.rs), which this crate shares, takes it
//! as its `GuestMem`: every guest address it uses is checked with `valid`
//! first, which maps it too.  Free of seL4: the mapping is a function.

use core::sync::atomic::{AtomicU64, Ordering};

pub const BLOCK_SHIFT: u32 = 21;
pub const HIGH_RAM_BASE: u64 = 4 << 30;

#[derive(Clone, Copy)]
pub struct GuestMem {
    /// Where GPA 0 is mapped.
    pub base: usize,
    /// The GPA of the RAM's first byte: 0 on x86-64, hvm::arm::RAM_BASE on
    /// AArch64 (which has all of its RAM in `low`).
    pub ram_base: u64,
    /// Bytes of RAM below the hole, and from 4 GiB on.
    pub low: u64,
    pub high: u64,
    /// Blocks mapped, a bit each (atomic: any thread may map one).
    pub mapped: &'static [AtomicU64],
    /// Map block b (RAM offset b * BLOCK): false if it cannot be.
    pub map: fn(usize) -> bool,
}

impl GuestMem {
    /// The block holding RAM GPA `gpa`.
    pub fn block_of(&self, gpa: u64) -> usize {
        let g = gpa - self.ram_base;
        let off = if g < self.low { g } else { g - HIGH_RAM_BASE + self.low };
        (off >> BLOCK_SHIFT) as usize
    }

    /// The GPA of block `b`.
    pub fn block_gpa(&self, b: usize) -> u64 {
        let off = (b as u64) << BLOCK_SHIFT;
        self.ram_base + if off < self.low { off } else { off - self.low + HIGH_RAM_BASE }
    }

    pub fn blocks(&self) -> usize {
        ((self.low + self.high) >> BLOCK_SHIFT) as usize
    }

    pub fn is_mapped(&self, b: usize) -> bool {
        self.mapped.get(b / 64).is_some_and(|w| w.load(Ordering::Acquire) & (1 << (b % 64)) != 0)
    }

    /// Record that block `b` is mapped.
    pub fn set_mapped(&self, b: usize) {
        self.mapped[b / 64].fetch_or(1 << (b % 64), Ordering::Release);
    }

    /// Whether [gpa, gpa + len) is RAM, all on one side of the hole.
    pub fn is_ram(&self, gpa: u64, len: u64) -> bool {
        let Some(end) = gpa.checked_add(len) else { return false };
        let Some(g) = gpa.checked_sub(self.ram_base) else { return false };
        let end = end - self.ram_base;
        end <= self.low || (self.high != 0 && g >= HIGH_RAM_BASE && end - HIGH_RAM_BASE <= self.high)
    }

    /// Whether [gpa, gpa + len) is RAM, mapping its blocks.
    pub fn valid(&self, gpa: u64, len: u64) -> bool {
        if !self.is_ram(gpa, len) {
            return false;
        }
        if len == 0 {
            return true;
        }
        let (first, last) = (self.block_of(gpa), self.block_of(gpa + len - 1));
        (first..=last).all(|b| self.is_mapped(b) || (self.map)(b))
    }

    fn ptr<T>(&self, gpa: u64) -> *mut T {
        assert!(self.valid(gpa, core::mem::size_of::<T>() as u64), "guest access outside RAM: {:#x}", gpa);
        (self.base + gpa as usize) as *mut T
    }

    /// Read a value the guest may change concurrently (plain integer
    /// types only).  Callers check guest addresses with `valid`; this
    /// panics on a bad one only as a last line of defence.  The guest
    /// chooses the alignment: unaligned values are read byte by byte.
    pub fn read<T: Copy>(&self, gpa: u64) -> T {
        let p = self.ptr::<T>(gpa);
        if p.is_aligned() {
            return unsafe { p.read_volatile() };
        }
        let mut v = core::mem::MaybeUninit::<T>::uninit();
        let (src, dst) = (p as *const u8, v.as_mut_ptr() as *mut u8);
        for i in 0..core::mem::size_of::<T>() {
            unsafe { dst.add(i).write(src.add(i).read_volatile()) };
        }
        unsafe { v.assume_init() }
    }

    pub fn write<T: Copy>(&self, gpa: u64, v: T) {
        let p = self.ptr::<T>(gpa);
        if p.is_aligned() {
            return unsafe { p.write_volatile(v) };
        }
        let (src, dst) = (&v as *const T as *const u8, p as *mut u8);
        for i in 0..core::mem::size_of::<T>() {
            unsafe { dst.add(i).write_volatile(src.add(i).read()) };
        }
    }

    /// `len` bytes of RAM at `gpa`, which must be valid.
    pub fn bytes(&self, gpa: u64, len: usize) -> *mut u8 {
        assert!(self.valid(gpa, len as u64), "guest access outside RAM: {:#x}+{:#x}", gpa, len);
        (self.base + gpa as usize) as *mut u8
    }

    /// Copy `src` into RAM at `gpa` (false if it is not RAM).
    pub fn write_bytes(&self, gpa: u64, src: &[u8]) -> bool {
        if !self.valid(gpa, src.len() as u64) {
            return false;
        }
        let dst = (self.base + gpa as usize) as *mut u8;
        for (i, &b) in src.iter().enumerate() {
            unsafe { dst.add(i).write_volatile(b) };
        }
        true
    }

    /// Copy RAM at `gpa` into `dst` (false if it is not RAM).
    pub fn read_bytes(&self, gpa: u64, dst: &mut [u8]) -> bool {
        if !self.valid(gpa, dst.len() as u64) {
            return false;
        }
        let src = (self.base + gpa as usize) as *const u8;
        for (i, b) in dst.iter_mut().enumerate() {
            *b = unsafe { src.add(i).read_volatile() };
        }
        true
    }
}

#[cfg(test)]
pub mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// A GuestMem over a buffer the test owns, every block mapped.
    pub fn fake(low: u64, high: u64) -> (GuestMem, Vec<u8>) {
        let buf = std::vec![0u8; (low + high.min(1 << 20)) as usize];
        let words = (((low + high) >> BLOCK_SHIFT) as usize).div_ceil(64).max(1);
        let mapped: &'static [AtomicU64] = Vec::leak((0..words).map(|_| AtomicU64::new(u64::MAX)).collect());
        // High RAM is only exercised in bounds checks: base is the buffer.
        (GuestMem { base: buf.as_ptr() as usize, ram_base: 0, low, high, mapped, map: |_| false }, buf)
    }

    #[test]
    fn bounds_and_blocks() {
        let mapped: &'static [AtomicU64] = Vec::leak(std::vec![AtomicU64::new(0)]);
        let m = GuestMem { base: 0, ram_base: 0, low: 3 << 30, high: 1 << 30, mapped, map: |b| b != 5 };
        assert!(m.is_ram(0, 3 << 30));
        assert!(!m.is_ram((3 << 30) - 1, 2), "into the hole");
        assert!(m.is_ram(4 << 30, 1 << 30));
        assert!(!m.is_ram(4 << 30, (1 << 30) + 1));
        assert!(!m.is_ram(u64::MAX, 2));
        assert_eq!(m.block_of(0x20_0000), 1);
        assert_eq!(m.block_of(4 << 30), 1536);
        assert_eq!(m.block_gpa(1536), 4 << 30);
        assert_eq!(m.blocks(), 2048);
        // valid() maps; a block that cannot be mapped is not valid.
        assert!(m.valid(0x40_0000, 0x20_0000));
        assert!(!m.valid(0xa0_0000, 1), "block 5");
        assert!(m.valid(0, 0));
    }

    /// AArch64's RAM: one range from `ram_base`, block 0 at its first byte.
    #[test]
    fn ram_from_a_base() {
        let mapped: &'static [AtomicU64] = Vec::leak(std::vec![AtomicU64::new(u64::MAX)]);
        let base = 0x4000_0000;
        let m = GuestMem { base: 0, ram_base: base, low: 1 << 30, high: 0, mapped, map: |_| false };
        assert!(m.is_ram(base, 1 << 30));
        assert!(!m.is_ram(base - 1, 1), "below the RAM");
        assert!(!m.is_ram(base - 1, 2), "across its start");
        assert!(!m.is_ram(base + (1 << 30), 1), "past its end");
        assert!(!m.is_ram(base + (4 << 30), 0), "no high RAM");
        assert!(!m.is_ram(u64::MAX, 2));
        assert_eq!(m.block_of(base), 0);
        assert_eq!(m.block_of(base + 0x20_0000), 1);
        assert_eq!(m.block_gpa(1), base + 0x20_0000);
        assert_eq!(m.blocks(), 512);
    }
}

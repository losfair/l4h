//! The arithmetic of carving device memory, which needs no seL4: tested by
//! tests/devmem.rs (tests/run-alloctest.sh).

use core::ops::Range;

/// The whole pages [addr, addr + len) is in: None if its end wraps.
pub fn pages(addr: usize, len: usize) -> Option<Range<usize>> {
    let end = addr.checked_add(len)?.checked_next_multiple_of(4096)?;
    Some(addr & !4095..end)
}

/// The size, as a power of two, of the block `DevMem::frames_range`
/// carves at `at` of [at, end): the largest aligned at `at` inside both
/// the range and the free Untyped of 2^`region_bits` bytes that holds
/// `at`, of at most 2^`max_bits` bytes.  An aligned block that holds `at`
/// and is no larger than that Untyped (itself aligned) is inside it.
pub fn block_bits(at: usize, end: usize, region_bits: usize, max_bits: usize) -> usize {
    (at.trailing_zeros() as usize)
        .min(usize::BITS as usize - 1 - (end - at).leading_zeros() as usize)
        .min(region_bits)
        .min(max_bits)
}

//! The order guest ports take turns in each pass of netd's loop: the
//! ports first in a pass go first at what they all share (uplink and
//! peer rings, the frame pool).

/// The `k`th port of a pass over `n` that starts at `cursor`.
pub fn nth(cursor: usize, k: usize, n: usize) -> usize {
    (cursor + k) % n
}

/// Where the next pass starts: after the first port this pass served
/// (`served`, bit i: port i), so that the ports with work take turns
/// going first, as many as there are, whatever their numbers; where it
/// was if none was served.  Bits from `n` on are ignored.
pub fn next(cursor: usize, served: u64, n: usize) -> usize {
    (0..n).map(|k| nth(cursor, k, n)).find(|&i| served & (1 << i) != 0).map_or(cursor, |i| (i + 1) % n)
}


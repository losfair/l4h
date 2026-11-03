//! Sets of physical address ranges.

use crate::io::{Vec, align_down, align_up};

#[derive(Clone, Copy, Debug)]
pub struct Range {
    pub start: u64,
    pub end: u64,
}

impl Range {
    pub const fn new(start: u64, end: u64) -> Range {
        Range { start, end }
    }

    pub fn len(&self) -> u64 {
        self.end - self.start
    }
}

/// Disjoint ranges, sorted, adjacent ones merged.
#[derive(Clone, Copy)]
pub struct Ranges {
    pub list: Vec<Range, 512>,
}

impl Ranges {
    pub const fn new() -> Ranges {
        Ranges { list: Vec::new() }
    }

    pub fn total(&self) -> u64 {
        self.list.iter().map(|r| r.len()).sum()
    }

    pub fn add(&mut self, r: Range) {
        if r.start >= r.end {
            return;
        }
        let mut r = r;
        let mut i = 0;
        while i < self.list.len() {
            let o = self.list[i];
            if o.end < r.start {
                i += 1;
                continue;
            }
            if o.start > r.end {
                break;
            }
            r = Range::new(r.start.min(o.start), r.end.max(o.end));
            self.list.remove(i);
        }
        self.list.insert(i, r);
    }

    pub fn remove(&mut self, r: Range) {
        if r.start >= r.end {
            return;
        }
        let mut i = 0;
        while i < self.list.len() {
            let o = self.list[i];
            if o.end <= r.start || o.start >= r.end {
                i += 1;
                continue;
            }
            self.list.remove(i);
            if o.start < r.start {
                self.list.insert(i, Range::new(o.start, r.start));
                i += 1;
            }
            if o.end > r.end {
                self.list.insert(i, Range::new(r.end, o.end));
                i += 1;
            }
        }
    }

    pub fn contains(&self, r: Range) -> bool {
        self.list.iter().any(|o| o.start <= r.start && r.end <= o.end)
    }

    pub fn overlaps(&self, r: Range) -> bool {
        self.list.iter().any(|o| o.start < r.end && r.start < o.end)
    }

    /// Take `size` bytes, aligned to `align`, wholly within [lo, hi):
    /// the lowest fit, or the highest with `top`.
    pub fn take(&mut self, size: u64, align: u64, lo: u64, hi: u64, top: bool) -> Option<u64> {
        let mut best: Option<u64> = None;
        for r in self.list.iter() {
            let (s, e) = (r.start.max(lo), r.end.min(hi));
            if s >= e {
                continue;
            }
            let at = if top {
                if e < size {
                    continue;
                }
                let a = align_down(e - size, align);
                if a < s {
                    continue;
                }
                a
            } else {
                let a = align_up(s, align);
                if a + size > e {
                    continue;
                }
                a
            };
            best = match best {
                Some(b) if (top && b > at) || (!top && b < at) => Some(b),
                _ => Some(at),
            };
        }
        let at = best?;
        self.remove(Range::new(at, at + size));
        Some(at)
    }

    /// Take up to `size` bytes in pieces of `align`-aligned memory within
    /// [lo, hi) for which `want` holds, largest pieces first; adds them to
    /// `out` and returns how much it took.
    pub fn take_pieces(&mut self, size: u64, align: u64, lo: u64, hi: u64, out: &mut Ranges, want: impl Fn(Range) -> bool) -> u64 {
        let mut got = 0;
        while got < size {
            let mut best: Option<Range> = None;
            for r in self.list.iter() {
                let (s, e) = (align_up(r.start.max(lo), align), align_down(r.end.min(hi), align));
                if s >= e || !want(Range::new(s, e)) {
                    continue;
                }
                if best.is_none_or(|b| e - s > b.len()) {
                    best = Some(Range::new(s, e));
                }
            }
            let Some(b) = best else { break };
            let n = b.len().min(align_up(size - got, align));
            let piece = Range::new(b.start, b.start + n);
            self.remove(piece);
            out.add(piece);
            got += n;
        }
        got
    }
}

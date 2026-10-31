//! First-fit contiguous runs in the controller's fixed 4 MiB write area.
//! A run stays owned until the hardware completes the request.
const PAGE: usize = 4096;
pub const SIZE: usize = crate::blk::BOUNCE_SIZE;
const _: () = assert!(crate::blk::MAX_REQUEST_BYTES <= SIZE as u64);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Run { first: u16, pages: u16 }
impl Run { pub fn offset(self) -> usize { self.first as usize * PAGE } }
pub struct Bounce { used: [u64; SIZE / PAGE / 64] }
impl Bounce {
    pub const fn new() -> Self { Self { used: [0; SIZE / PAGE / 64] } }
    pub fn alloc(&mut self, bytes: usize) -> Option<Run> {
        if bytes == 0 || bytes > SIZE { return None; }
        let pages = bytes.div_ceil(PAGE);
        let mut free = 0;
        for word in 0..self.used.len() {
            let mut bit = 0;
            while bit < 64 {
                let tail = self.used[word] >> bit;
                if tail & 1 != 0 {
                    free = 0;
                    bit += (tail.trailing_ones() as usize).min(64 - bit);
                } else {
                    let n = (tail.trailing_zeros() as usize).min(64 - bit);
                    free += n;
                    bit += n;
                    if free >= pages {
                        let run = Run { first: (word * 64 + bit - free) as u16, pages: pages as u16 };
                        self.mark(run, true);
                        return Some(run);
                    }
                }
            }
        }
        None
    }
    pub fn free(&mut self, run: Run) {
        self.mark(run, false);
    }
    fn mark(&mut self, run: Run, used: bool) {
        let first = run.first as usize;
        let end = first + run.pages as usize;
        for word in first / 64..end.div_ceil(64) {
            let lo = first.saturating_sub(word * 64);
            let hi = (end - word * 64).min(64);
            let mask = (u64::MAX << lo) & (u64::MAX >> (64 - hi));
            debug_assert_eq!(self.used[word] & mask, if used { 0 } else { mask });
            if used { self.used[word] |= mask; }
            else { self.used[word] &= !mask; }
        }
    }
}

//! First-fit contiguous runs in the controller's fixed 4 MiB write area.
//! A run stays owned until the hardware completes the request.
const PAGE: usize = 4096;
pub const SIZE: usize = 4 << 20;
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
        for i in 0..SIZE / PAGE {
            if self.used[i / 64] & (1 << (i % 64)) != 0 { free = 0; continue; }
            free += 1;
            if free == pages {
                let first = i + 1 - pages;
                for p in first..=i { self.used[p / 64] |= 1 << (p % 64); }
                return Some(Run { first: first as u16, pages: pages as u16 });
            }
        }
        None
    }
    pub fn free(&mut self, run: Run) {
        for p in run.first as usize..(run.first + run.pages) as usize {
            debug_assert_ne!(self.used[p / 64] & (1 << (p % 64)), 0);
            self.used[p / 64] &= !(1 << (p % 64));
        }
    }
}

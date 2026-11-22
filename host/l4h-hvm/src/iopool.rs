//! The bounce buffers of an HVM guest's disks (DESIGN.md §5.11): devices
//! reach only the guest's I/O pool, which root makes, not its RAM, so
//! l4h-hvm copies a request's data through the pool.  Each request takes
//! contiguous 4 KiB pages of it, first fit; when none fit, the request
//! waits for earlier ones to complete (blk.rs's backpressure).  Free of
//! seL4.

pub const PAGE: u64 = 4096;
/// Pages of the largest pool (guest::IO_POOL_MAX in vmmgr: 256 MiB).
pub const MAX_PAGES: usize = (256 << 20) / PAGE as usize;

pub struct Pool {
    pages: usize,
    used: [u64; MAX_PAGES / 64],
    /// Where the next search starts (the end of the last allocation).
    hint: usize,
}

impl Pool {
    pub const fn new(bytes: u64) -> Self {
        let pages = (bytes / PAGE) as usize;
        Pool { pages: if pages > MAX_PAGES { MAX_PAGES } else { pages }, used: [0; MAX_PAGES / 64], hint: 0 }
    }

    fn is_used(&self, p: usize) -> bool {
        self.used[p / 64] & (1 << (p % 64)) != 0
    }

    fn set(&mut self, first: usize, n: usize, used: bool) {
        for p in first..first + n {
            if used {
                self.used[p / 64] |= 1 << (p % 64);
            } else {
                self.used[p / 64] &= !(1 << (p % 64));
            }
        }
    }

    /// The first run of `n` free pages from `lo` on.
    fn find(&self, lo: usize, n: usize) -> Option<usize> {
        let mut p = lo;
        while p + n <= self.pages {
            match (p..p + n).find(|&q| self.is_used(q)) {
                Some(q) => p = q + 1,
                None => return Some(p),
            }
        }
        None
    }

    /// `n` contiguous free pages: the first one, or None if none are.
    pub fn alloc(&mut self, n: usize) -> Option<usize> {
        if n == 0 || n > self.pages {
            return None;
        }
        let p = self.find(self.hint, n).or_else(|| self.find(0, n))?;
        self.set(p, n, true);
        self.hint = (p + n) % self.pages;
        Some(p)
    }

    pub fn free(&mut self, first: usize, n: usize) {
        assert!(first + n <= self.pages && (first..first + n).all(|p| self.is_used(p)), "bounce pages freed twice");
        self.set(first, n, false);
    }

    /// Bytes of the pool.
    pub fn bytes(&self) -> u64 {
        self.pages as u64 * PAGE
    }

    #[cfg(test)]
    pub fn free_pages(&self) -> usize {
        (0..self.pages).filter(|&p| !self.is_used(p)).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_fit_and_backpressure() {
        let mut p = Pool::new(64 * PAGE);
        let a = p.alloc(16).unwrap();
        let b = p.alloc(32).unwrap();
        let c = p.alloc(16).unwrap();
        assert_eq!((a, b, c), (0, 16, 48));
        // Full: the next request waits.
        assert_eq!(p.alloc(1), None);
        p.free(b, 32);
        assert_eq!(p.alloc(33), None, "not contiguous enough");
        let d = p.alloc(20).unwrap();
        assert_eq!(d, 16);
        p.free(a, 16);
        p.free(c, 16);
        p.free(d, 20);
        assert_eq!(p.free_pages(), 64);
        assert_eq!(p.alloc(64), Some(0));
        assert_eq!(p.alloc(0), None);
        assert_eq!(Pool::new(8 * PAGE).alloc(9), None);
    }

    #[test]
    #[should_panic]
    fn double_free() {
        let mut p = Pool::new(8 * PAGE);
        let a = p.alloc(2).unwrap();
        p.free(a, 2);
        p.free(a, 2);
    }
}

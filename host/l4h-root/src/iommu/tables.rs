//! Page-table memory of an IOMMU (VT-d's or AMD-Vi's): 2 MiB chunks,
//! handed out a 4 KiB page at a time, and never freed.  A chunk is a block
//! of host memory, which may not be there: what a device operation needs
//! is reserved before it changes anything (`Pages::reserve`), so that it
//! fails as an error rather than panic root half way.

pub const CHUNK_BITS: usize = 21;
pub const CHUNK_PAGES: usize = 1 << (CHUNK_BITS - 12);
const PAGE_BITS: usize = 12;

/// The pages of the chunks made so far: the first `used` are taken; of
/// the rest, `held` are kept for a mapping made later (usb.rs's ATTACH,
/// once usbd has answered what came before it).
pub struct Pages {
    used: usize,
    held: usize,
}

impl Pages {
    pub const fn new() -> Self {
        Pages { used: 0, held: 0 }
    }

    /// Pages of `chunks` chunks not taken yet, held ones included.
    pub fn spare(&self, chunks: usize) -> usize {
        (chunks * CHUNK_PAGES).saturating_sub(self.used)
    }

    /// Chunks to add to `chunks` so that `pages` more can be taken
    /// besides those held.
    pub fn short(&self, chunks: usize, pages: usize) -> usize {
        self.held.saturating_add(pages).saturating_sub(self.spare(chunks)).div_ceil(CHUNK_PAGES)
    }

    /// The next page: its chunk and its offset in it, in bytes.  None if
    /// a chunk must be added first.
    pub fn take(&mut self, chunks: usize) -> Option<(usize, usize)> {
        if self.spare(chunks) == 0 {
            return None;
        }
        let page = self.used;
        self.used += 1;
        Some((page / CHUNK_PAGES, (page % CHUNK_PAGES) << PAGE_BITS))
    }

    /// The pages of the last of `chunks` chunks are taken whole (AMD-Vi's
    /// device table).
    pub fn take_chunk(&mut self, chunks: usize) {
        self.used = chunks * CHUNK_PAGES;
    }

    /// Keep `pages` reserved pages (`short` counted them) for a mapping
    /// made later, until `unhold`.
    pub fn hold(&mut self, pages: usize) {
        self.held = self.held.saturating_add(pages);
    }

    pub fn unhold(&mut self, pages: usize) {
        self.held = self.held.saturating_sub(pages);
    }
}

/// Bytes a table at `level` (1: the last, of 4 KiB pages) translates.
fn reach_bits(level: usize) -> u32 {
    (PAGE_BITS + 9 * level) as u32
}

/// Tables below the root that translating [pa, pa + len) takes, at most,
/// with `levels` levels of tables (those that exist already are not
/// made again).
pub fn map_pages(pa: usize, len: usize, levels: usize) -> usize {
    if len == 0 {
        return 0;
    }
    let last = pa.saturating_add(len - 1);
    (1..levels).map(|l| {
        let b = reach_bits(l);
        (last.checked_shr(b).unwrap_or(0)) - (pa.checked_shr(b).unwrap_or(0)) + 1
    }).sum()
}

/// `map_pages` of a range of `len` bytes wherever it starts: one that
/// does not start at a table's boundary takes one more at each level.
pub fn map_pages_any(len: usize, levels: usize) -> usize {
    if len == 0 {
        return 0;
    }
    (1..levels).map(|l| (len - 1).checked_shr(reach_bits(l)).unwrap_or(0) + 2).sum()
}

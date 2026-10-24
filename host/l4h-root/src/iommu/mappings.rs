//! Count ownership of DMA allocations within a requester domain. Several
//! disks can use the same guest I/O pool, including through bridge aliases.

use l4h_host::fixed::ArrayVec;

struct Mapping {
    domain: u32,
    pa: usize,
    len: usize,
    users: u16,
    write: bool,
}

pub struct Mappings<const N: usize> {
    ranges: ArrayVec<Mapping, N>,
}

impl<const N: usize> Mappings<N> {
    pub const fn new() -> Self { Self { ranges: ArrayVec::new() } }

    /// True for the first owner, which must install the page-table entries.
    /// Callers give whole, nonoverlapping allocations with fixed permissions.
    pub fn acquire(&mut self, domain: u32, pa: usize, len: usize, write: bool) -> bool {
        if len == 0 { return false; }
        for r in self.ranges.iter_mut().filter(|r| r.domain == domain) {
            if r.pa == pa && r.len == len {
                assert_eq!(r.write, write, "IOMMU: shared DMA permissions changed");
                r.users = r.users.checked_add(1).expect("IOMMU: DMA reference overflow");
                return false;
            }
            assert!(pa >= r.pa + r.len || r.pa >= pa + len, "IOMMU: DMA allocations partially overlap");
        }
        assert!(self.ranges.push(Mapping { domain, pa, len, users: 1, write }).is_ok(), "IOMMU: DMA mapping table full");
        true
    }

    /// Only the final owner removes the translation and drains DMA.
    pub fn release(&mut self, domain: u32, pa: usize, len: usize) -> bool {
        if len == 0 { return false; }
        let i = self.ranges.iter().position(|r| r.domain == domain && r.pa == pa && r.len == len)
            .expect("IOMMU: unmap of unknown DMA allocation");
        self.ranges[i].users -= 1;
        if self.ranges[i].users != 0 { return false; }
        self.ranges.swap_remove(i);
        true
    }
}

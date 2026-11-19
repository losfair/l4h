// Run with tests/run-alloctest.sh; no seL4 runtime is needed.
// The framebuffer's carve (host/l4h-root/src/dashboard.rs) through
// DevMem::frames_range, against a model of the device Untypeds that
// splits them as DevMem::carve does.
#[path = "../host/l4h-root/src/devmem/span.rs"]
mod span;

/// RETYPE_FAN_OUT (16384 frames in kernel/configs), as a block size.
const MAX_BITS: usize = 12 + 14;

/// Free device Untypeds: (paddr, size_bits).
struct Free(Vec<(usize, usize)>);

impl Free {
    fn holding(&self, at: usize) -> Option<(usize, usize)> {
        self.0.iter().copied().find(|&(p, b)| p <= at && at - p < 1 << b)
    }
    /// DevMem::carve of the aligned block [paddr, paddr + 2^bits): the
    /// free halves split off stay free.
    fn carve(&mut self, paddr: usize, bits: usize) -> bool {
        let Some(i) = self.0.iter().position(|&(p, b)| p <= paddr && paddr + (1 << bits) <= p + (1 << b)) else { return false };
        let (mut p, mut b) = self.0.swap_remove(i);
        while b > bits {
            b -= 1;
            let (lo, hi) = (p, p + (1 << b));
            let (keep, spare) = if paddr < hi { (lo, hi) } else { (hi, lo) };
            self.0.push((spare, b));
            p = keep;
        }
        assert_eq!(p, paddr);
        true
    }
    /// DevMem::frames_range: the blocks carved, or None if the range is
    /// not all free.
    fn frames_range(&mut self, start: usize, len: usize) -> Option<Vec<(usize, usize)>> {
        let (mut at, end) = (start, start + len);
        while at < end {
            at = self.holding(at).map(|(p, b)| p + (1 << b))?;
        }
        let (mut at, mut out) = (start, Vec::new());
        while at < end {
            let (_, region) = self.holding(at)?;
            let bits = span::block_bits(at, end, region, MAX_BITS);
            assert!(self.carve(at, bits), "block {at:#x}+{bits} outside its Untyped");
            out.push((at, bits));
            at += 1 << bits;
        }
        Some(out)
    }
}

/// What Dashboard::new carved before: the smallest aligned power-of-two
/// block around the framebuffer.
fn inflated(addr: usize, len: usize) -> (usize, usize) {
    let mut size = len.next_power_of_two();
    while addr + len - (addr & !(size - 1)) > size {
        size *= 2;
    }
    (addr & !(size - 1), size)
}

#[test]
fn a_framebuffer_across_a_large_boundary_takes_its_pages_only() {
    // 16 MiB at 0xdfc0_0000, across 0xe000_0000: the block around it is
    // 1 GiB, 2^18 frames of root's 2^19 slots and every BAR below 4 GiB.
    let (addr, len) = (0xdfc0_0000, 16 << 20);
    assert_eq!(inflated(addr, len), (0xc000_0000, 1 << 30));
    assert_eq!(span::pages(addr, len), Some(0xdfc0_0000..0xe0c0_0000));
    // Two device Untypeds meet at the boundary (a BAR below, another
    // above): the framebuffer's pages come from both, and nothing else.
    let mut free = Free(vec![(0xc000_0000, 29), (0xe000_0000, 28)]);
    let blocks = free.frames_range(0xdfc0_0000, 16 << 20).unwrap();
    let pages: usize = blocks.iter().map(|&(_, b)| 1 << (b - 12)).sum();
    assert_eq!(pages, 4096);
    assert!(blocks.iter().all(|&(at, b)| at >= 0xdfc0_0000 && at + (1 << b) <= 0xe0c0_0000 && b <= MAX_BITS));
    // Everything around it is still free: a BAR at 0xdfbf_f000 or
    // 0xe0c0_0000 can be carved.
    assert!(free.carve(0xdfbf_f000, 12) && free.carve(0xe0c0_0000, 12));
    assert_eq!(free.frames_range(0xdfc0_0000, 4096), None);
}

#[test]
fn framebuffer_pages_round_out_and_never_wrap() {
    assert_eq!(span::pages(0x8000_0400, 0x1000), Some(0x8000_0000..0x8000_2000));
    assert_eq!(span::pages(0x8000_0000, 0x1000), Some(0x8000_0000..0x8000_1000));
    assert_eq!(span::pages(usize::MAX - 0x1000, 0x800), None);
    assert_eq!(span::pages(usize::MAX - 0x1000, 0x2000), None);
    // Across 512 GiB, above RAM: the block around it would be 1 TiB,
    // 2^28 frames, more than root's CNode has slots.
    let (addr, len) = (0x7f_ffc0_0000, 8 << 20);
    assert_eq!(inflated(addr, len), (0, 1 << 40));
    assert_eq!(span::pages(addr, len).map(|r| r.len()), Some(8 << 20));
    let mut free = Free(vec![(0x40_0000_0000, 38), (0x80_0000_0000, 39)]);
    let blocks = free.frames_range(addr, len).unwrap();
    assert_eq!(blocks.iter().map(|&(_, b)| 1usize << b).sum::<usize>(), len);
}

#[test]
fn dashboard_carves_the_pages_into_consecutive_slots() {
    // Dashboard::new takes its span's pages through frames_range, each
    // chunk's frames moved into one run of slots that logd's FbArea
    // indexes, not a power-of-two block through DevMem::frames.
    let src = include_str!("../host/l4h-root/src/dashboard.rs");
    let new = &src[src.find("pub fn new(bootinfo").unwrap()..];
    let new = &new[..new.find("\n    }\n").unwrap()];
    assert!(new.contains("crate::devmem::span::pages(addr, len)?"));
    assert!(new.contains("devmem.frames_range(alloc, span.start, span.len()"));
    assert!(!new.contains("devmem.frames(") && !new.contains("next_power_of_two"));
}

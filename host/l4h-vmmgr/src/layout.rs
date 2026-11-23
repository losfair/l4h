//! vmmgr's own address space: every region that vmmgr maps at a fixed
//! address, besides the component layout of `l4h_host` (image, info page,
//! stacks below 0x1100_0000) and what root maps for it (`l4h_host::vmmgr`).
//! The regions are checked at compile time to be disjoint.

use l4h_host::vmmgr as proto;

/// A region of vmmgr's address space: [base, base + size).
pub struct Region {
    pub base: usize,
    pub size: usize,
}

impl Region {
    pub const fn end(&self) -> usize {
        self.base + self.size
    }
}

const PAGE: usize = 4096;
const MIB: usize = 1 << 20;

/// The two windows on frames of guests and VMMs (window.rs).
pub const WINDOWS: Region = Region { base: 0x7000_0000_0000, size: 2 * PAGE };
/// A 2 MiB window on the RAM blocks of HVM guests (hvm.rs), 2 MiB aligned.
pub const LARGE_WINDOW: Region = Region { base: 0x7000_0020_0000, size: 2 * MIB };
/// Each guest's console, control and event pages, GUEST_STRIDE apart
/// (guest.rs).
pub const GUEST_PAGES: Region = Region { base: 0x7100_0000_0000, size: crate::MAX_GUESTS * GUEST_STRIDE };
/// Each guest's virtio-gpu display area, DISPLAY_STRIDE apart (gpu.rs).
pub const DISPLAY: Region = Region { base: 0x7a00_0000_0000, size: crate::MAX_GUESTS * DISPLAY_STRIDE };
/// What root maps: the boot modules, then its shared pages.
const FROM_ROOT: Region = Region { base: proto::MODULES_VA, size: proto::CTL_DATA_VA + l4h_abi::CTL_LOAD_MAX as usize - proto::MODULES_VA };

/// Distance between two guests' pages in GUEST_PAGES.
pub const GUEST_STRIDE: usize = MIB;
/// Distance between two guests' display areas in DISPLAY.
pub const DISPLAY_STRIDE: usize = 16 * MIB;

const fn disjoint(a: &Region, b: &Region) -> bool {
    a.end() <= b.base || b.end() <= a.base
}

const _: () = assert!(LARGE_WINDOW.base.is_multiple_of(2 * MIB) && disjoint(&LARGE_WINDOW, &WINDOWS)
    && disjoint(&LARGE_WINDOW, &GUEST_PAGES) && disjoint(&LARGE_WINDOW, &DISPLAY) && disjoint(&LARGE_WINDOW, &FROM_ROOT));
const _: () = assert!(
    disjoint(&WINDOWS, &GUEST_PAGES) && disjoint(&WINDOWS, &DISPLAY) && disjoint(&GUEST_PAGES, &DISPLAY)
        && disjoint(&FROM_ROOT, &WINDOWS) && disjoint(&FROM_ROOT, &GUEST_PAGES) && disjoint(&FROM_ROOT, &DISPLAY)
);
const _: () = assert!(proto::MODULES_VA + proto::MODULES_SIZE <= proto::FLAGS_VA && FROM_ROOT.base >= l4h_host::STACK_TOP);
const _: () = assert!(DISPLAY.end() <= 0x0000_7fff_ffff_f000);

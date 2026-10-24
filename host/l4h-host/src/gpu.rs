//! A guest's virtio-gpu display (l4h-vmm's gpu.rs): the image of its one
//! scanout, which l4h-vmm writes on every flush and l4h-root copies out
//! for dom0 (CTL_GPU_READ).  The guest's buffers themselves stay in its
//! I/O pool; this is the only image the host keeps.

use core::sync::atomic::AtomicU64;

/// The first page of the display area; the image follows at
/// IMAGE_OFFSET, `width * 4` bytes a row.
#[repr(C)]
pub struct DisplayHeader {
    /// Odd while l4h-vmm writes the image; it changes with every update.
    pub frame: AtomicU64,
    /// The scanout's size, set at attach.
    pub width: u32,
    pub height: u32,
    /// The VIRTIO_GPU_FORMAT_* of what is shown, 0 if nothing is.
    pub format: u32,
    pub reserved: [u32; 11],
}

pub const IMAGE_OFFSET: usize = 4096;

pub const fn image_bytes(width: u32, height: u32) -> usize {
    width as usize * height as usize * 4
}

/// Bytes of a resource of `width` x `height` pixels of 4 bytes, None if
/// that does not fit in a u64 (the guest chooses both).
pub const fn resource_bytes(width: u32, height: u32) -> Option<u64> {
    match (width as u64).checked_mul(height as u64) {
        Some(p) => p.checked_mul(4),
        None => None,
    }
}

/// Copy `n` bytes with volatile accesses, whole words while both
/// pointers are aligned, then byte by byte: the other side may be writing
/// meanwhile (a seqlock tells).
///
/// # Safety
/// `src` and `dst` must be valid for `n` bytes.
pub unsafe fn copy_volatile(src: *const u8, dst: *mut u8, n: usize) {
    let mut i = 0;
    if src as usize % 8 == 0 && dst as usize % 8 == 0 {
        while i + 8 <= n {
            unsafe { (dst.add(i) as *mut u64).write_volatile((src.add(i) as *const u64).read_volatile()) };
            i += 8;
        }
    }
    while i < n {
        unsafe { dst.add(i).write_volatile(src.add(i).read_volatile()) };
        i += 1;
    }
}

/// Pages of the display area: the header and the image.
pub const fn display_pages(width: u32, height: u32) -> usize {
    1 + image_bytes(width, height).div_ceil(4096)
}

/// Pages of l4h-vmm's own tables of resources and their backing, mapped
/// at VMM_GPU_STATE_VA in it alone.
pub const STATE_PAGES: usize = 320;

/// crate::SHARED_VA, which lib.rs checks: this file builds alone for its
/// tests (tests/run-alloctest.sh).
pub(crate) const SHARED_VA: usize = 0x2000_0000_0000;

/// Where l4h-vmm maps the display area (at most DISPLAY_MAX_PAGES) and
/// its tables.
pub const VMM_DISPLAY_VA: usize = SHARED_VA + 0x2000_0000;
pub const DISPLAY_MAX_PAGES: usize = 0x1000_0000 / 4096;
pub const VMM_GPU_STATE_VA: usize = VMM_DISPLAY_VA + DISPLAY_MAX_PAGES * 4096;

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn resource_bytes_does_not_overflow() {
        assert_eq!(resource_bytes(1920, 1200), Some(1920 * 1200 * 4));
        // (2^31)^2 * 4 = 2^64, and u32::MAX^2 * 4 > 2^64.
        assert_eq!(resource_bytes(1 << 31, 1 << 31), None);
        assert_eq!(resource_bytes(u32::MAX, u32::MAX), None);
        assert_eq!(resource_bytes(1 << 16, 1 << 16), Some(1 << 34));
    }

    #[test]
    fn copy_volatile_copies_every_byte() {
        // 65 x 65 pixels: 16900 bytes, not a whole number of words.
        let src: std::vec::Vec<u64> = (0..2113u64).map(|i| i.wrapping_mul(0x9e37_79b9_7f4a_7c15)).collect();
        for n in [0, 1, 7, 8, 9, 16900, 2113 * 8] {
            let mut dst = std::vec![u64::MAX; 2113];
            unsafe { copy_volatile(src.as_ptr() as *const u8, dst.as_mut_ptr() as *mut u8, n) };
            let (s, d) = unsafe {
                (core::slice::from_raw_parts(src.as_ptr() as *const u8, 2113 * 8), core::slice::from_raw_parts(dst.as_ptr() as *const u8, 2113 * 8))
            };
            assert_eq!(&d[..n], &s[..n], "{n}");
            assert!(d[n..].iter().all(|&b| b == 0xff), "{n}");
        }
        // Unaligned: byte by byte.
        let mut dst = [0u8; 17];
        let s = [7u8; 20];
        unsafe { copy_volatile(s.as_ptr().wrapping_add(1), dst.as_mut_ptr().wrapping_add(1), 15) };
        assert_eq!(dst[0], 0);
        assert!(dst[1..16].iter().all(|&b| b == 7));
        assert_eq!(dst[16], 0);
    }
}

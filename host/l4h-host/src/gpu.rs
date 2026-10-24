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

/// Pages of the display area: the header and the image.
pub const fn display_pages(width: u32, height: u32) -> usize {
    1 + image_bytes(width, height).div_ceil(4096)
}

/// Pages of l4h-vmm's own tables of resources and their backing, mapped
/// at VMM_GPU_STATE_VA in it alone.
pub const STATE_PAGES: usize = 320;

/// Where l4h-vmm maps the display area (at most DISPLAY_MAX_PAGES) and
/// its tables.
pub const VMM_DISPLAY_VA: usize = crate::SHARED_VA + 0x2000_0000;
pub const DISPLAY_MAX_PAGES: usize = 0x1000_0000 / 4096;
pub const VMM_GPU_STATE_VA: usize = VMM_DISPLAY_VA + DISPLAY_MAX_PAGES * 4096;

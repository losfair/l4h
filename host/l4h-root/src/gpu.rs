//! A guest's virtio-gpu (DESIGN.md §8.6).  l4h-vmm serves the device; here
//! is the host memory it needs: the display area, which l4h-vmm writes and
//! l4h-root maps too, to copy the image out for dom0 (CTL_GPU_READ), and
//! l4h-vmm's tables of the guest's resources.  The guest's buffers stay in
//! its I/O pool.

use core::sync::atomic::{Ordering, fence};

use sel4::{ObjectBlueprint, cap_type};

use l4h_abi as abi;
use l4h_host as host;
use l4h_host::gpu::{DisplayHeader, IMAGE_OFFSET, STATE_PAGES, display_pages, image_bytes};

use crate::ctl::{EAGAIN, EINVAL, ENOMEM};
use crate::guest::{Guest, abs};
use crate::layout;
use crate::mem::{ARENA_TAIL, Alloc, Dest};
use crate::vmm::Backend;
use crate::vspace::FRAME_BP;

const PAGE: usize = 4096;

const _: () = assert!(display_pages(abi::GPU_MAX_WIDTH, abi::GPU_MAX_HEIGHT) * PAGE <= layout::DISPLAY_STRIDE);
const _: () = assert!(display_pages(abi::GPU_MAX_WIDTH, abi::GPU_MAX_HEIGHT) <= host::gpu::DISPLAY_MAX_PAGES);

/// Where l4h-root maps guest `id`'s display area (layout::DISPLAY).
pub fn root_display_va(id: usize) -> usize {
    assert!(id < crate::MAX_GUESTS);
    layout::DISPLAY.base + id * layout::DISPLAY_STRIDE
}

/// Whether a scanout of `width` x `height` is one CTL_GPU_ATTACH accepts.
pub fn valid_size(width: u64, height: u64) -> bool {
    (abi::GPU_MIN as u64..=abi::GPU_MAX_WIDTH as u64).contains(&width)
        && (abi::GPU_MIN as u64..=abi::GPU_MAX_HEIGHT as u64).contains(&height)
}

/// Frames of a GPU of this size (display area and tables), and the radix of
/// the CNodes keeping them.
fn frames(width: u32, height: u32) -> (usize, usize) {
    let n = display_pages(width, height) + STATE_PAGES;
    (n, n.next_power_of_two().trailing_zeros() as usize)
}

/// Host memory attach() takes from the guest's arena: the frames and the
/// two CNodes.  The VMM's page tables for them are Backend::map_bytes.
pub fn attach_bytes(width: u32, height: u32) -> usize {
    let (n, radix) = frames(width, height);
    n * PAGE + 2 * (32 << radix)
}

/// Frames retyped at once: what Arena::reserve guarantees will fit
/// however fragmented the arena is.
const FRAME_BATCH: usize = ARENA_TAIL / PAGE;

/// Page tables for mapping `pages` consecutive pages, at any alignment.
pub fn table_bytes(pages: usize) -> usize {
    (pages / 512 + 2) * PAGE
}

/// The frames of a GPU with one scanout of `width` x `height`, its display
/// area mapped in l4h-root.  ENOMEM if the host has too little memory;
/// what was allocated by then stays in the guest's arena until destroy.
pub fn attach(g: &mut Guest, alloc: &mut Alloc, width: u32, height: u32) -> Result<Backend, i64> {
    let (n, radix) = frames(width, height);
    // The CNodes are larger than reserve guarantees: they may not fit.
    let mut cnode = || {
        let s = g.arena.try_object(alloc, ObjectBlueprint::CNode { size_bits: radix }).ok_or(ENOMEM)?;
        Ok::<_, i64>(sel4::init_thread::Slot::<cap_type::CNode>::from_index(s).cap())
    };
    let frames = cnode()?;
    let keep = cnode()?;
    if !g.reserve(alloc, n * PAGE) {
        return Err(ENOMEM);
    }
    let mut i = 0;
    while i < n {
        let k = (n - i).min(FRAME_BATCH);
        g.arena.retype(alloc, &FRAME_BP, k, Dest { cnode: abs(frames), offset: i }).ok_or(ENOMEM)?;
        i += k;
    }
    let pages = display_pages(width, height);
    let va = root_display_va(g.id);
    for p in 0..pages {
        g.map_abs_in_root(alloc, &frames.absolute_cptr_from_bits_with_depth(p as u64, radix), va + p * PAGE);
    }
    let hdr = va as *mut DisplayHeader;
    unsafe {
        core::ptr::addr_of_mut!((*hdr).width).write_volatile(width);
        core::ptr::addr_of_mut!((*hdr).height).write_volatile(height);
    }
    g.gpu = Some((width, height));
    Ok(Backend::Gpu { frames, keep, radix, display_pages: pages, width, height })
}

/// CTL_GPU_READ: copy the image of guest `g` from byte `offset` into `to`
/// (dom0's control data area, CTL_LOAD_MAX bytes).  The size is l4h-root's
/// own, not what l4h-vmm may have written in the header.
pub fn read(g: &Guest, offset: u64, to: *mut u8) -> Result<[u64; 6], i64> {
    let (width, height) = g.gpu.ok_or(EINVAL)?;
    let base = root_display_va(g.id);
    let hdr = unsafe { &*(base as *const DisplayHeader) };
    let frame = hdr.frame.load(Ordering::Acquire);
    if frame & 1 != 0 {
        return Err(EAGAIN);
    }
    let format = unsafe { core::ptr::addr_of!(hdr.format).read_volatile() };
    let total = image_bytes(width, height) as u64;
    let off = offset.min(total);
    let n = (total - off).min(abi::CTL_LOAD_MAX) as usize;
    // l4h-vmm may be writing meanwhile: the frame counter tells.
    unsafe { host::gpu::copy_volatile((base + IMAGE_OFFSET + off as usize) as *const u8, to, n) };
    fence(Ordering::Acquire);
    if hdr.frame.load(Ordering::Relaxed) != frame {
        return Err(EAGAIN);
    }
    Ok([n as u64, width as u64, height as u64, width as u64 * 4, format as u64, frame])
}

//! Capability allocation, address spaces and component loading shared by
//! seL4 tasks. Callers supply their capabilities, storage and mappings;
//! this crate does not assume the caller's slots or virtual address layout.
//!
//! Root and vmmgr use these mechanisms to construct tasks and manage their
//! objects. Other components should reuse them when they need object
//! allocation, mapping, or loading. Component startup and runtime support
//! belong in `l4h-rt`; shared protocols and layouts belong in `l4h-host`.
//! This crate is independent of `l4h-rt`. Executables retain boot setup,
//! authorization, ASID assignment policy, and placement decisions. Memd's
//! memory-service accounting remains in memd, separate from the grant client
//! here. See DESIGN.md §10 for the shared crate boundaries.

#![no_std]

#[cfg(test)]
extern crate std;

macro_rules! log {
    ($($arg:tt)*) => { crate::print_log(format_args!($($arg)*)) };
}

/// Retain a host diagnostic and queue it for logd in every build.
pub fn print_log(args: core::fmt::Arguments<'_>) {
    l4h_host::log::record(args);
    l4h_host::serial::record(args);
}

pub mod bootinfo;
pub mod component;
pub mod edge;
pub mod elf;
pub mod mem;
pub mod memd;
pub mod reply;
pub mod topology;
pub mod vspace;
pub mod window;

/// A capability addressed by its slot in the caller's CSpace.
pub fn cap_at<T: sel4::CapType>(slot: usize) -> sel4::Cap<T> {
    sel4::Cap::from_bits(slot as u64)
}

/// Retype `count` frames of 2^`size_bits` bytes (4 KiB or 2 MiB) from
/// `untyped` into `dst`, from slot `dst_offset` on, shared with the
/// hypervisor so that devices can reach them by DMA on a confidential VM
/// (FL4's seL4_Untyped_RetypeShared: at most 256 4 KiB frames, or one
/// 2 MiB frame, per call).  Callers go through `mem::UtRegion::retype_dma`,
/// which keeps the watermark.
#[cfg(l4h_kernel_shared_dma)]
pub fn retype_shared(
    untyped: sel4::cap::Untyped,
    size_bits: usize,
    dst: &sel4::AbsoluteCPtr,
    dst_offset: usize,
    count: usize,
) -> sel4::Result<()> {
    let err = sel4::with_ipc_buffer_mut(|ipc| {
        ipc.inner_mut().seL4_Untyped_RetypeShared(
            untyped.bits(),
            size_bits as u64,
            dst.root().bits(),
            dst.path().bits(),
            dst.path().depth() as u64,
            dst_offset as u64,
            count as u64,
        )
    });
    sel4::Error::from_sys(err).map_or(Ok(()), Err)
}

/// A kernel without shared frames refuses them, as FL4 does off a
/// confidential VM (seL4_IllegalOperation).
#[cfg(not(l4h_kernel_shared_dma))]
pub fn retype_shared(
    _untyped: sel4::cap::Untyped,
    _size_bits: usize,
    _dst: &sel4::AbsoluteCPtr,
    _dst_offset: usize,
    _count: usize,
) -> sel4::Result<()> {
    Err(sel4::Error::IllegalOperation)
}

/// seL4_Untyped_Retype of `count` fixed-size objects of seL4 type
/// `obj_type`, which rust-sel4's ObjectBlueprint cannot name.  Callers
/// go through `mem::UtRegion::retype_raw`, which keeps the watermark.
pub fn retype_raw(
    untyped: sel4::cap::Untyped,
    obj_type: u64,
    dst: &sel4::AbsoluteCPtr,
    dst_offset: usize,
    count: usize,
) -> sel4::Result<()> {
    let err = sel4::with_ipc_buffer_mut(|ipc| {
        ipc.inner_mut().seL4_Untyped_Retype(
            untyped.bits(),
            obj_type,
            0,
            dst.root().bits(),
            dst.path().bits(),
            dst.path().depth() as u64,
            dst_offset as u64,
            count as u64,
        )
    });
    sel4::Error::from_sys(err).map_or(Ok(()), Err)
}

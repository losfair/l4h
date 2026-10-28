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
//! here. See DESIGN.md §9 for the shared crate boundaries.

#![no_std]

#[cfg(test)]
extern crate std;

macro_rules! log {
    ($($arg:tt)*) => { crate::print_log(format_args!($($arg)*), true) };
}

/// Retain a host diagnostic, with optional synchronous serial output.
pub fn print_log(args: core::fmt::Arguments<'_>, serial: bool) {
    l4h_host::log::record(args);
    if serial { sel4::debug_println!("{}", args); }
}

pub mod component;
pub mod elf;
pub mod mem;
pub mod memd;
pub mod topology;
pub mod vspace;
pub mod window;

/// A capability addressed by its slot in the caller's CSpace.
pub fn cap_at<T: sel4::CapType>(slot: usize) -> sel4::Cap<T> {
    sel4::Cap::from_bits(slot as u64)
}

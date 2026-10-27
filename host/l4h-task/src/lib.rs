//! Capability allocation, address spaces and component loading shared by
//! seL4 tasks. Callers supply their capabilities, storage and mappings;
//! this crate does not assume the caller's slots or virtual address layout.

#![no_std]

#[cfg(test)]
extern crate std;

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

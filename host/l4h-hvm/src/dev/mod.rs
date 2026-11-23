//! The virtual platform's devices (DESIGN.md §5.11), free of seL4: what
//! threads share them and how is in hvm.rs and io.rs.

pub mod apic;
pub mod blk;
pub mod ioapic;
pub mod lapic;
pub mod net;
pub mod pci;
pub mod pit;
pub mod pm;
pub mod rtc;
pub mod uart;
pub mod virtio_pci;

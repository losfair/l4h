//! The virtual platform's devices (DESIGN.md §5.11), free of seL4: what
//! threads share them and how is in hvm.rs and io.rs.  PCI, virtio and the
//! attestation port are every architecture's; the rest here is the PC's (AArch64's are in arm/).

#[cfg(target_arch = "x86_64")]
pub mod apic;
pub mod attest;
pub mod blk;
#[cfg(target_arch = "x86_64")]
pub mod ioapic;
#[cfg(target_arch = "x86_64")]
pub mod lapic;
pub mod net;
pub mod pci;
#[cfg(target_arch = "x86_64")]
pub mod pit;
#[cfg(target_arch = "x86_64")]
pub mod pm;
#[cfg(target_arch = "x86_64")]
pub mod rtc;
#[cfg(target_arch = "x86_64")]
pub mod uart;
pub mod virtio_pci;

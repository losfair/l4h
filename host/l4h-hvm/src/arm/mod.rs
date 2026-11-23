//! The AArch64 machine l4h-hvm gives an unmodified arm64 Linux (DESIGN.md
//! §5.11): QEMU `virt`'s board, as a device tree describes it: a GIC, PSCI,
//! the architected timer, a PL011, PL031 and PL061, and PCI (dev/) over
//! ECAM.  What is free of seL4 is tested on the build host
//! (tests/hvm-arm64.rs).

pub mod boot;
pub mod fdt;
pub mod hw;
pub mod pl011;
pub mod pl031;
pub mod pl061;
pub mod psci;
pub mod regs;
#[cfg(target_arch = "aarch64")]
pub mod stage2;
pub mod sysreg;
pub mod vcpu;
pub mod vgic;
pub mod vm;

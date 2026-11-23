//! What l4h-hvm knows of x86 itself, free of seL4: decoding the
//! instructions it emulates, walking the guest's page tables, CPUID, MSRs
//! and kvmclock.

pub mod cpuid;
pub mod decode;
pub mod msr;
pub mod pvclock;
pub mod walk;

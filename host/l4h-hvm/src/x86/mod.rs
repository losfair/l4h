//! What l4h-hvm knows of x86 itself, free of seL4: decoding the
//! instructions it emulates and walking the guest's page tables.

pub mod cpuid;
pub mod decode;
pub mod msr;
pub mod walk;

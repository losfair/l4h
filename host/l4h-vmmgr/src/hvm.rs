//! HVM guests (DESIGN.md §5.11): unmodified kernels in hardware guest mode
//! (x86-64 on VT-x or AMD-V, AArch64 at EL1 under FL4 at EL2), with an
//! l4h-hvm (l4h_host::hvm) in place of their l4h-vmm.
//!
//! vmmgr builds such a guest's objects (its second-stage tables, vCPU
//! threads and their VCPUs, the CNodes its l4h-hvm maps its RAM with) and
//! its RAM, of which it fills only what dom0 loads (VM_LOAD), and block 0,
//! with 2 MiB frames mapped in the second stage; the guest's l4h-hvm maps
//! the other blocks itself, from their Untypeds, as the guest first touches
//! them.  vmmgr does not read the images: l4h-hvm boots them.  The guest
//! itself holds no capability.
//!
//! What only an x86_64 kernel with VT-x support has is in hvm/x86.rs, what
//! only FL4 on AArch64 has in hvm/aarch64.rs; elsewhere (hvm/none.rs) no
//! guest is HVM.

sel4::sel4_cfg_if! {
    if #[sel4_cfg(all(ARCH_X86_64, VTX))] {
        #[path = "hvm/x86.rs"]
        mod imp;
    } else {
        #[cfg(all(target_arch = "aarch64", l4h_arm_virt))]
        #[path = "hvm/aarch64.rs"]
        mod imp;
        #[cfg(not(all(target_arch = "aarch64", l4h_arm_virt)))]
        #[path = "hvm/none.rs"]
        mod imp;
    }
}

pub use imp::*;

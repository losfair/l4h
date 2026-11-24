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

/// An HVM guest's launch digest (DESIGN.md §10.2): SHA-256 over what
/// CTL_VM_START names, with the SHA-256 of each image as guest RAM has
/// it: `"l4h-launch-hvm-v1" ‖ arch ‖ flags ‖ kernel gpa ‖ kernel size ‖
/// SHA-256(kernel) ‖ initrd gpa ‖ initrd size ‖ SHA-256(initrd) ‖ cmdline
/// length ‖ cmdline`, integers u64 little-endian, the initrd's gpa 0
/// without one.  What l4h-hvm makes of them (the kernel where it runs,
/// its boot parameters and the platform's tables) is a function of these,
/// the guest's RAM and vCPUs (in its reports) and l4h-hvm itself, which
/// the host's measurement covers.
#[allow(dead_code)] // hvm/none.rs has no guests.
pub fn launch_digest(flags: u64, kernel: ((u64, u64), [u8; 32]), initrd: ((u64, u64), [u8; 32]), cmdline: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let arch = if cfg!(target_arch = "aarch64") { l4h_host::hvm::LAUNCH_ARCH_AARCH64 } else { l4h_host::hvm::LAUNCH_ARCH_X86_64 };
    let ((kernel_gpa, kernel_size), kernel_hash) = kernel;
    let ((initrd_gpa, initrd_size), initrd_hash) = initrd;
    let mut h = Sha256::new();
    h.update(l4h_host::hvm::LAUNCH_DOMAIN);
    for v in [arch, flags, kernel_gpa, kernel_size] {
        h.update(v.to_le_bytes());
    }
    h.update(kernel_hash);
    for v in [if initrd_size != 0 { initrd_gpa } else { 0 }, initrd_size] {
        h.update(v.to_le_bytes());
    }
    h.update(initrd_hash);
    h.update((cmdline.len() as u64).to_le_bytes());
    h.update(cmdline);
    h.finalize().into()
}

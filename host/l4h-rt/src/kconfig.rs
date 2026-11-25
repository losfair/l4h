//! What the kernel found and chose at boot: FL4's seL4_KernelConfig
//! (DESIGN.md §10.1), one word per key (libsel4's seL4_KernelConfig_*,
//! FL4's fl4_abi::consts::kernel_config).  It needs no capability and no
//! IPC buffer, and the answers never change after boot.  seL4 has no such
//! call: built against its libsel4 (build.rs), every key is -ENOSYS.

/// The keys l4h reads itself (sel4/constants.h, seL4_KernelConfig_*).
pub mod keys {
    pub const ARCH: u64 = 0x0001;
    pub const SPEC_CTRL_MSR: u64 = 0x0305;
    pub const SPEC_TSX_CTRL_MSR: u64 = 0x0306;
    pub const SPEC_MCU_OPT_CTRL_MSR: u64 = 0x0307;
    pub const SPEC_AMD_DE_CFG_MSR: u64 = 0x0309;
    pub const SPEC_AMD_BP_CFG_MSR: u64 = 0x030a;
    pub const SPEC_MSR_VALID: u64 = 0x030b;
    pub const X86_ARCH_CAPABILITIES: u64 = 0x0409;
}

/// seL4_KernelConfig_SpecMsrValid: the boot core's MSRs the kernel read or
/// wrote at boot, whose keys are their values.
pub mod spec_msr_valid {
    pub const ARCH_CAPABILITIES: u64 = 1 << 0;
    pub const SPEC_CTRL: u64 = 1 << 1;
    pub const TSX_CTRL: u64 = 1 << 2;
    pub const MCU_OPT_CTRL: u64 = 1 << 3;
    pub const EFER: u64 = 1 << 4;
    pub const AMD_DE_CFG: u64 = 1 << 5;
    pub const AMD_BP_CFG: u64 = 1 << 6;
}

pub const ENOENT: i32 = -2;
pub const ENOSYS: i32 = -38;

/// seL4_SysKernelConfig.
#[cfg(l4h_kernel_config)]
const SYS_KERNEL_CONFIG: i64 = -24;
/// seL4_NoError.
#[cfg(l4h_kernel_config)]
const NO_ERROR: u64 = 0;

/// The kernel's value of `key`: Err(ENOENT) for a key it does not know
/// (or one of the other architecture: seL4_InvalidArgument), Err(ENOSYS)
/// on a kernel without the call.
pub fn get(key: u64) -> Result<u64, i32> {
    #[cfg(l4h_kernel_config)]
    {
        let (error, value) = call(key);
        if error == NO_ERROR { Ok(value) } else { Err(ENOENT) }
    }
    #[cfg(not(l4h_kernel_config))]
    {
        let _ = key;
        Err(ENOSYS)
    }
}

/// The call (libsel4's seL4_KernelConfig): in, the syscall number and the
/// key as the destination; out, the error where the badge comes back and
/// the value in the first message register.  The other registers of a
/// send-receive are the kernel's to clobber.
#[cfg(all(l4h_kernel_config, target_arch = "x86_64"))]
fn call(key: u64) -> (u64, u64) {
    let (error, value): (u64, u64);
    unsafe {
        core::arch::asm!(
            "mov r14, rsp",
            "syscall",
            "mov rsp, r14",
            in("rdx") SYS_KERNEL_CONFIG,
            inout("rdi") key => error,
            inout("rsi") 0u64 => _,
            inout("r10") 0u64 => value,
            inout("r8") 0u64 => _,
            inout("r9") 0u64 => _,
            inout("r15") 0u64 => _,
            in("r12") 0u64,
            lateout("rcx") _,
            lateout("r11") _,
            lateout("r14") _,
        );
    }
    (error, value)
}

#[cfg(all(l4h_kernel_config, target_arch = "aarch64"))]
fn call(key: u64) -> (u64, u64) {
    let (error, value): (u64, u64);
    unsafe {
        core::arch::asm!(
            "svc 0",
            in("x7") SYS_KERNEL_CONFIG,
            inout("x0") key => error,
            inout("x1") 0u64 => _,
            inout("x2") 0u64 => value,
            inout("x3") 0u64 => _,
            inout("x4") 0u64 => _,
            inout("x5") 0u64 => _,
            in("x6") 0u64,
        );
    }
    (error, value)
}

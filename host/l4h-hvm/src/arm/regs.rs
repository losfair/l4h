//! The state area seL4_ARM_VCPU_Run reads and writes in a vCPU thread's IPC
//! buffer frame (FL4's seL4_ARM_VCPUState), and what its fields hold.  Free
//! of seL4.

use l4h_rt::host::hvm::arm::VCPU_STATE_SIZE;

/// seL4_VCPUReg: indices of `State::regs`.
pub mod reg {
    pub const SCTLR: usize = 0;
    pub const ESR: usize = 10;
    pub const FAR: usize = 11;
    pub const VBAR: usize = 13;
    pub const VMPIDR: usize = 15;
    pub const ELR_EL1: usize = 17;
    pub const SPSR_EL1: usize = 18;
    pub const CNTV_CTL: usize = 21;
    pub const CNTV_CVAL: usize = 22;
    pub const CNTVOFF: usize = 23;
    pub const CNTKCTL: usize = 24;
    pub const VPIDR: usize = 25;
    pub const HCR: usize = 26;
    pub const VGIC_HCR: usize = 35;
    pub const VGIC_LR0: usize = 48;
}

/// Indices of `State::gprs`, the guest's TCB registers: x0-x30 at their
/// numbers, then these.
pub const GPR_PC: usize = 32;
pub const GPR_PSTATE: usize = 33;

/// seL4_ARM_VCPUState_*: the groups of registers a transfer moves.
pub const S_EL1: u64 = 1 << 0;
pub const S_TIMER: u64 = 1 << 2;
pub const S_VGIC: u64 = 1 << 3;
pub const S_GPRS: u64 = 1 << 4;
pub const S_VGIC_LR: u64 = 1 << 5;
pub const S_ALL: u64 = 0x3f;

/// HCR_EL2 traps the monitor asks for: WFI (to wait), and the ID registers
/// (to show only what FL4 switches).  FL4 forces the rest.
pub const HCR_TWI: u64 = 1 << 13;
pub const HCR_TID3: u64 = 1 << 18;
pub const HCR_GUEST: u64 = HCR_TWI | HCR_TID3;

/// SCTLR_EL1's reset value: RES1 bits, MMU and caches off.
pub const SCTLR_RESET: u64 = 0x30d0_0800;
/// PSTATE at reset: EL1h, DAIF masked.
pub const PSTATE_EL1H_MASKED: u64 = 0x3c5;

const PSTATE_NZCV: u64 = 0xf << 28;
const PSTATE_DIT: u64 = 1 << 24;
const PSTATE_PAN: u64 = 1 << 22;
const PSTATE_SSBS: u64 = 1 << 12;
const SCTLR_SPAN: u64 = 1 << 23;
const SCTLR_DSSBS: u64 = 1 << 44;

/// PSTATE on taking an exception to EL1 from `old`, as the architecture
/// has it (AArch64.TakeException) for what the guest is shown it has: the
/// flags and DIT stay, EL1h with DAIF masked; PAN is set unless
/// SCTLR_EL1.SPAN says to leave it; SSBS is SCTLR_EL1.DSSBS.  SS, IL, UAO
/// and BTYPE clear.
pub fn exception_pstate(old: u64, sctlr: u64, has_pan: bool, has_ssbs: bool) -> u64 {
    let mut p = (old & (PSTATE_NZCV | PSTATE_DIT)) | PSTATE_EL1H_MASKED;
    if has_pan {
        p |= if sctlr & SCTLR_SPAN == 0 { PSTATE_PAN } else { old & PSTATE_PAN };
    }
    if has_ssbs && sctlr & SCTLR_DSSBS != 0 {
        p |= PSTATE_SSBS;
    }
    p
}

/// CNTV_CTL_EL0.
pub const CNTV_ENABLE: u64 = 1 << 0;
pub const CNTV_IMASK: u64 = 1 << 1;

#[repr(C, align(64))]
#[derive(Clone)]
pub struct State {
    pub regs: [u64; 64],
    pub gprs: [u64; 37],
    /// Bit 0: the virtual timer's PPI is masked at the host's GIC.
    pub vppi_masked: u64,
    _rest: [u64; 26],
}
const _: () = assert!(core::mem::size_of::<State>() == VCPU_STATE_SIZE);
const _: () = assert!(core::mem::offset_of!(State, vppi_masked) == (64 + 37) * 8);

impl State {
    pub const fn zeroed() -> Self {
        State { regs: [0; 64], gprs: [0; 37], vppi_masked: 0, _rest: [0; 26] }
    }

    /// General register `r` as an instruction names it (31 is XZR).
    pub fn x(&self, r: usize) -> u64 {
        if r < 31 { self.gprs[r] } else { 0 }
    }

    pub fn set_x(&mut self, r: usize, v: u64) {
        if r < 31 {
            self.gprs[r] = v;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_exception_keeps_the_flags_and_masks() {
        for from in [0u64, 0b0100, 0b0101] {
            let p = exception_pstate(from | 0xa000_0000, 0, false, false);
            assert_eq!(p, 0xa000_0000 | 0x3c5, "from mode {from:#b}");
        }
        assert_eq!(exception_pstate(PSTATE_DIT, 0, false, false) & PSTATE_DIT, PSTATE_DIT);
    }

    #[test]
    fn an_exception_clears_what_it_does_not_keep() {
        // SS, IL, UAO, BTYPE; and PAN and SSBS where the guest has neither.
        let old = 1 << 21 | 1 << 20 | 1 << 23 | 3 << 10 | PSTATE_PAN | PSTATE_SSBS | 0b0101;
        assert_eq!(exception_pstate(old, u64::MAX, false, false), 0x3c5);
    }

    #[test]
    fn pan_follows_span() {
        for from in [0u64, 0b0100, 0b0101] {
            assert_ne!(exception_pstate(from, 0, true, false) & PSTATE_PAN, 0, "SPAN=0 sets it");
            assert_eq!(exception_pstate(from, SCTLR_SPAN, true, false) & PSTATE_PAN, 0, "SPAN=1 leaves it clear");
            assert_ne!(exception_pstate(from | PSTATE_PAN, SCTLR_SPAN, true, false) & PSTATE_PAN, 0, "SPAN=1 leaves it set");
        }
    }

    #[test]
    fn ssbs_is_dssbs() {
        assert_eq!(exception_pstate(PSTATE_SSBS, 0, false, true) & PSTATE_SSBS, 0);
        assert_ne!(exception_pstate(0, SCTLR_DSSBS, false, true) & PSTATE_SSBS, 0);
    }
}

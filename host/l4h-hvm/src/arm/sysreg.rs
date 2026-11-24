//! System register traps (DESIGN.md §5.11): what a guest's MRS and MSR
//! raise with HCR_EL2.TID3, and of the registers FL4 traps anyway.  The ID
//! registers show the CPU without what FL4 does not switch for a guest (as
//! guest/linux/arch/l4h/kvm/arm64/init.c, l4h_kvm_id_reg()).  Free of seL4.

use l4h_abi::ArmVirtInfo;

/// A system register by its encoding: Op0, Op1, CRn, CRm, Op2.
pub const fn enc(op0: u32, op1: u32, crn: u32, crm: u32, op2: u32) -> u32 {
    op0 << 16 | op1 << 12 | crn << 8 | crm << 4 | op2
}

pub const ID_AA64PFR0: u32 = enc(3, 0, 0, 4, 0);
pub const ID_AA64PFR1: u32 = enc(3, 0, 0, 4, 1);
pub const ID_AA64DFR0: u32 = enc(3, 0, 0, 5, 0);
pub const ID_AA64ISAR0: u32 = enc(3, 0, 0, 6, 0);
pub const ID_AA64ISAR1: u32 = enc(3, 0, 0, 6, 1);
pub const ID_AA64ISAR2: u32 = enc(3, 0, 0, 6, 2);
pub const ID_AA64MMFR0: u32 = enc(3, 0, 0, 7, 0);
pub const ID_AA64MMFR1: u32 = enc(3, 0, 0, 7, 1);
pub const ID_AA64MMFR2: u32 = enc(3, 0, 0, 7, 2);
pub const ACTLR_EL1: u32 = enc(3, 0, 1, 0, 1);
pub const ICC_SGI1R: u32 = enc(3, 0, 12, 11, 5);
pub const ICC_ASGI1R: u32 = enc(3, 0, 12, 11, 6);
pub const ICC_SGI0R: u32 = enc(3, 0, 12, 11, 7);
pub const CNTPCT_EL0: u32 = enc(3, 3, 14, 0, 1);
pub const CNTP_TVAL_EL0: u32 = enc(3, 3, 14, 2, 0);
pub const CNTP_CTL_EL0: u32 = enc(3, 3, 14, 2, 1);
pub const CNTP_CVAL_EL0: u32 = enc(3, 3, 14, 2, 2);

/// A trapped MRS or MSR, from its syndrome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Access {
    pub reg: u32,
    pub rt: usize,
    pub read: bool,
}

/// The ISS of an MSR/MRS trap (EC 0x18).
pub fn decode(esr: u64) -> Access {
    let f = |shift: u32, bits: u32| ((esr >> shift) as u32) & ((1 << bits) - 1);
    Access {
        reg: enc(f(20, 2), f(14, 3), f(10, 4), f(1, 4), f(17, 3)),
        rt: f(5, 5) as usize,
        read: esr & 1 != 0,
    }
}

const fn field(shift: u32) -> u64 {
    0xf << shift
}

const PFR0_HIDDEN: u64 = field(0) | field(4) | field(8) | field(12) // EL0-EL3, set again below
    | field(24) | field(28) | field(32) | field(40) | field(44) | field(36) | field(52); // GIC, RAS, SVE, MPAM, AMU, SEL2, RME
const PFR1_HIDDEN: u64 = field(8) | field(12) | field(16) | field(24) | field(36) | field(40) | field(44) | field(48)
    | field(52) | field(56) | field(60); // MTE, RAS_frac, MPAM_frac, SME, NMI, MTE_frac, GCS, THE, MTEX, DF2, PFAR
const ISAR1_HIDDEN: u64 = field(4) | field(8) | field(24) | field(28) | field(60); // APA, API, GPA, GPI, LS64
/// APA3, GPA3, SYSREG_128; MOPS (HCRX_EL2.MSCEn is not set); WFxT, whose
/// timeout the trap of WFI would lose.
const ISAR2_HIDDEN: u64 = field(0) | field(8) | field(12) | field(16) | field(32);
const MMFR0_HIDDEN: u64 = field(56) | field(60); // FGT, ECV
const MMFR1_HIDDEN: u64 = field(8) | field(32); // VH, TWED
const MMFR2_HIDDEN: u64 = field(24) | field(40) | field(56); // NV, FWB, EVT
/// PMUVer, TraceVer, PMSVer, DoubleLock, TraceFilt, TraceBuffer, MTPMU, BRBE.
const DFR0_HIDDEN: u64 = field(8) | field(4) | field(32) | field(36) | field(40) | field(44) | field(48) | field(52);

/// ID_AA64MMFR0's PARange for the IPA sizes FL4's Stage-2 roots have.
const fn parange(ipa_bits: u64) -> u64 {
    if ipa_bits >= 48 {
        5
    } else if ipa_bits >= 44 {
        4
    } else {
        2
    }
}

/// What the guest reads of ID register `reg`: None if it is no ID register.
pub fn id_reg(reg: u32, cpu_id: &[u64; 5], av: &ArmVirtInfo, gicv3: bool) -> Option<u64> {
    // Op0 3, Op1 0, CRn 0, CRm 1-7: the ID group TID3 traps.
    if reg >> 8 != 3 << 8 || (reg >> 4) & 0xf == 0 {
        return None;
    }
    Some(match reg {
        ID_AA64PFR0 => (cpu_id[3] & !PFR0_HIDDEN) | 1 | 1 << 4 | (gicv3 as u64) << 24,
        ID_AA64PFR1 => cpu_id[4] & !PFR1_HIDDEN,
        ID_AA64ISAR0 => cpu_id[0],
        ID_AA64ISAR1 => cpu_id[1] & !ISAR1_HIDDEN,
        ID_AA64ISAR2 => cpu_id[2] & !ISAR2_HIDDEN,
        ID_AA64MMFR0 => {
            let v = av.id_aa64mmfr0 & !MMFR0_HIDDEN;
            (v & !0xf) | (v & 0xf).min(parange(av.ipa_bits))
        }
        ID_AA64MMFR1 => av.id_aa64mmfr1 & !MMFR1_HIDDEN,
        ID_AA64MMFR2 => av.id_aa64mmfr2 & !MMFR2_HIDDEN,
        // DoubleLock's 0xf is "not implemented".
        ID_AA64DFR0 => (av.id_aa64dfr0 & !DFR0_HIDDEN) | field(36),
        // AArch32's, and those of features it does not have.
        _ => 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn av() -> ArmVirtInfo {
        ArmVirtInfo {
            ipa_bits: 40,
            id_aa64mmfr0: u64::MAX,
            id_aa64mmfr1: u64::MAX,
            id_aa64mmfr2: u64::MAX,
            id_aa64dfr0: u64::MAX,
            ..ArmVirtInfo::default()
        }
    }

    #[test]
    fn decodes_the_syndrome() {
        // MRS x3, ID_AA64PFR0_EL1: Op0 3, Op2 0, Op1 0, CRn 0, CRm 4.
        let esr = 0x18 << 26 | 3 << 20 | 0 << 17 | 0 << 14 | 0 << 10 | 3 << 5 | 4 << 1 | 1;
        assert_eq!(decode(esr), Access { reg: ID_AA64PFR0, rt: 3, read: true });
        // MSR ICC_SGI1R_EL1, x9.
        let esr = 0x18 << 26 | 3 << 20 | 5 << 17 | 0 << 14 | 12 << 10 | 9 << 5 | 11 << 1;
        assert_eq!(decode(esr), Access { reg: ICC_SGI1R, rt: 9, read: false });
    }

    #[test]
    fn hides_what_fl4_does_not_switch() {
        let ids = [u64::MAX; 5];
        let a = av();
        let pfr0 = id_reg(ID_AA64PFR0, &ids, &a, true).unwrap();
        assert_eq!(pfr0 & 0xffff, 0x0011, "EL0 and EL1 only");
        assert_eq!((pfr0 >> 24) & 0xf, 1, "GICv3 system registers");
        assert_eq!((pfr0 >> 32) & 0xf, 0, "no SVE");
        assert_eq!((pfr0 >> 28) & 0xf, 0, "no RAS");
        assert_eq!((id_reg(ID_AA64PFR0, &ids, &a, false).unwrap() >> 24) & 0xf, 0, "GICv2");
        let pfr1 = id_reg(ID_AA64PFR1, &ids, &a, true).unwrap();
        assert_eq!((pfr1 >> 8) & 0xf, 0, "no MTE");
        assert_eq!((pfr1 >> 24) & 0xf, 0, "no SME");
        let isar1 = id_reg(ID_AA64ISAR1, &ids, &a, true).unwrap();
        assert_eq!(isar1 & (field(4) | field(8) | field(24) | field(28)), 0, "no PAC");
        let isar2 = id_reg(ID_AA64ISAR2, &ids, &a, true).unwrap();
        assert_eq!(isar2 & (field(16) | field(0)), 0, "no MOPS, no WFxT");
        let mmfr0 = id_reg(ID_AA64MMFR0, &ids, &a, true).unwrap();
        assert_eq!(mmfr0 & 0xf, 2, "a 40-bit IPA");
        assert_eq!(mmfr0 >> 56, 0, "no FGT, no ECV");
        assert_eq!(id_reg(ID_AA64MMFR1, &ids, &a, true).unwrap() & field(8), 0, "no VHE");
        assert_eq!(id_reg(ID_AA64MMFR2, &ids, &a, true).unwrap() & field(40), 0, "no FWB");
        let dfr0 = id_reg(ID_AA64DFR0, &ids, &a, true).unwrap();
        assert_eq!(dfr0 & field(8), 0, "no PMU");
        assert_eq!((dfr0 >> 36) & 0xf, 0xf, "no DoubleLock");
        let host_without = ArmVirtInfo { id_aa64dfr0: 0, ..av() };
        assert_eq!(id_reg(ID_AA64DFR0, &ids, &host_without, true).unwrap(), field(36), "whatever the host's says");
        assert_eq!(id_reg(enc(3, 0, 0, 1, 0), &ids, &a, true), Some(0), "AArch32's");
        assert_eq!(id_reg(enc(3, 0, 0, 0, 0), &ids, &a, true), None, "MIDR is not trapped");
        assert_eq!(id_reg(ACTLR_EL1, &ids, &a, true), None);
    }

    #[test]
    fn parange_follows_the_stage2_root() {
        let mut a = av();
        a.id_aa64mmfr0 = 5;
        let ids = [0; 5];
        for (bits, r) in [(40, 2), (42, 2), (44, 4), (48, 5)] {
            a.ipa_bits = bits;
            assert_eq!(id_reg(ID_AA64MMFR0, &ids, &a, true).unwrap() & 0xf, r);
        }
        // Never more than the CPU has.
        a.ipa_bits = 48;
        a.id_aa64mmfr0 = 2;
        assert_eq!(id_reg(ID_AA64MMFR0, &ids, &a, true).unwrap() & 0xf, 2);
    }
}

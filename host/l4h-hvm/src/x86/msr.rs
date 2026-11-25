//! The model-specific registers an HVM guest's vCPU has besides what the
//! VCPU object holds (EFER, PAT, the syscall MSRs and the segment bases,
//! hw.rs) and the local APIC (APIC_BASE, TSC_DEADLINE, x2APIC): MTRRs
//! (kept, with write-back the default; the EPT decides memory types),
//! MISC_ENABLE, FEATURE_CONTROL, DEBUGCTL, microcode and machine-check
//! registers that read as nothing, and AMD's HWCR, DE_CFG and VM_CR; vcpu.rs
//! has kvmclock's two (x86/pvclock.rs).  Of the speculation controls, the
//! host's as the kernel says them (vm::SpecMsrs): IA32_ARCH_CAPABILITIES
//! (its hardware properties alone, IBRS_ALL only where the host runs with
//! IBRS set), and SPEC_CTRL, TSX_CTRL, MCU_OPT_CTRL and AMD's BP_CFG and
//! DE_CFG read only, as the host has them, since none is switched for the
//! guest (a write of the value they hold is taken, as Linux makes one, and
//! SPEC_CTRL's IBRS alone where the host has it, which Linux writes for
//! enhanced IBRS); PRED_CMD stays hidden.  Any other MSR is #GP(0), as on
//! a CPU without it (DESIGN.md §5.11).  Free of seL4.

use crate::vm::SpecMsrs;

pub const TSC: u32 = 0x10;
pub const PLATFORM_ID: u32 = 0x17;
pub const FEATURE_CONTROL: u32 = 0x3a;
pub const BIOS_SIGN_ID: u32 = 0x8b;
pub const MTRR_CAP: u32 = 0xfe;
pub const SYSENTER_CS: u32 = 0x174;
pub const SYSENTER_ESP: u32 = 0x175;
pub const SYSENTER_EIP: u32 = 0x176;
pub const MCG_CAP: u32 = 0x179;
pub const MCG_STATUS: u32 = 0x17a;
pub const MISC_ENABLE: u32 = 0x1a0;
pub const DEBUGCTL: u32 = 0x1d9;
pub const MTRR_DEF_TYPE: u32 = 0x2ff;
pub const PAT: u32 = 0x277;
pub const EFER: u32 = 0xc000_0080;
pub const STAR: u32 = 0xc000_0081;
pub const LSTAR: u32 = 0xc000_0082;
pub const CSTAR: u32 = 0xc000_0083;
pub const FMASK: u32 = 0xc000_0084;
pub const FS_BASE: u32 = 0xc000_0100;
pub const GS_BASE: u32 = 0xc000_0101;
pub const KERNEL_GS_BASE: u32 = 0xc000_0102;
const AMD_HWCR: u32 = 0xc001_0015;
const AMD_NB_CFG: u32 = 0xc001_001f;
const AMD_VM_CR: u32 = 0xc001_0114;
const AMD_HSAVE_PA: u32 = 0xc001_0117;
const AMD_DE_CFG: u32 = 0xc001_1029;
const AMD_BP_CFG: u32 = 0xc001_102e;
pub const SPEC_CTRL: u32 = 0x48;
/// SPEC_CTRL's IBRS.
const SPEC_CTRL_IBRS: u64 = 1 << 0;
pub const ARCH_CAPABILITIES: u32 = 0x10a;
pub const TSX_CTRL: u32 = 0x122;
pub const MCU_OPT_CTRL: u32 = 0x123;
/// DE_CFG's LFENCE-serializing bit, which Linux sets.
const DE_CFG_LFENCE_SERIAL: u64 = 1 << 1;

/// IA32_ARCH_CAPABILITIES's bits the guest sees, of the host's: what the
/// hardware is immune to or does (RDCL_NO, RSBA,
/// SKIP_L1DFL_VMENTRY, SSB_NO, MDS_NO, IF_PSCHANGE_MC_NO, TAA_NO,
/// SBDR_SSDP_NO, FBSDP_NO, PSDP_NO, FB_CLEAR, RRSBA, BHI_NO, PBRSB_NO,
/// GDS_NO, RFDS_NO, RFDS_CLEAR, ITS_NO), never that it has a control MSR
/// the guest has not (MISC_PACKAGE_CTRLS, ENERGY_FILTERING_CTL, DOITM,
/// XAPIC_DISABLE_STATUS, OVERCLOCKING_STATUS, the UMONITOR ones) or a bit
/// we do not know.
pub const ARCH_CAP_KEPT: u64 = (1 << 0) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 8)
    | (1 << 13) | (1 << 14) | (1 << 15) | (1 << 17) | (1 << 19) | (1 << 20) | (1 << 24) | (1 << 26) | (1 << 27)
    | (1 << 28) | (1 << 62);
/// Enhanced IBRS, kept where the host runs with IBRS set in SPEC_CTRL
/// (which the guest runs with: Linux then takes enhanced IBRS, and writes
/// IBRS, which is taken, where it would otherwise use retpolines).
pub const ARCH_CAP_IBRS_ALL: u64 = 1 << 1;
/// TSX_CTRL's enumeration, kept with that MSR; FB_CLEAR_CTRL and GDS_CTRL
/// (MCU_OPT_CTRL's bits), with that one.
pub const ARCH_CAP_TSX_CTRL: u64 = 1 << 7;
pub const ARCH_CAP_MCU_OPT_CTRL: u64 = (1 << 18) | (1 << 25);

/// The guest's IA32_ARCH_CAPABILITIES, of the host's `raw`, with the
/// TSX_CTRL and MCU_OPT_CTRL MSRs where the guest reads them, and the
/// host's SPEC_CTRL with IBRS set (`host_ibrs`) or not.
pub fn guest_arch_capabilities(raw: u64, has_tsx_ctrl: bool, has_mcu_opt_ctrl: bool, host_ibrs: bool) -> u64 {
    let kept = ARCH_CAP_KEPT
        | if host_ibrs { ARCH_CAP_IBRS_ALL } else { 0 }
        | if has_tsx_ctrl { ARCH_CAP_TSX_CTRL } else { 0 }
        | if has_mcu_opt_ctrl { ARCH_CAP_MCU_OPT_CTRL } else { 0 };
    raw & kept
}

/// PAT at reset.
pub const PAT_DEFAULT: u64 = 0x0007_0406_0007_0406;

/// Whether `pat` holds only valid memory types (UC, WC, WT, WP, WB, UC-).
pub fn pat_valid(pat: u64) -> bool {
    (0..8).all(|i| matches!((pat >> (8 * i)) as u8, 0 | 1 | 4 | 5 | 6 | 7))
}

pub struct Msrs {
    amd: bool,
    mtrr_def: u64,
    mtrr_fixed: [u64; 11],
    mtrr_var: [u64; 16],
    misc_enable: u64,
    hwcr: u64,
    de_cfg: u64,
    /// The host's DE_CFG (0 if unknown): its bits stay set.
    host_de_cfg: u64,
    spec: SpecMsrs,
}

/// MTRRcap: 8 variable ranges, fixed ranges, write-combining.
const MTRR_CAP_VALUE: u64 = 0x508;

impl Msrs {
    pub fn new(amd: bool, spec: SpecMsrs) -> Self {
        let host_de_cfg = spec.amd_de_cfg.unwrap_or(0);
        Msrs {
            amd,
            // MTRRs on, fixed ranges on, write-back by default.
            mtrr_def: 0xc06,
            mtrr_fixed: [0x0606_0606_0606_0606; 11],
            mtrr_var: [0; 16],
            // Fast strings; no BTS and no PEBS.
            misc_enable: 1 | (1 << 11) | (1 << 12),
            hwcr: 0,
            de_cfg: host_de_cfg,
            host_de_cfg,
            spec,
        }
    }

    fn fixed_index(msr: u32) -> Option<usize> {
        match msr {
            0x250 => Some(0),
            0x258 | 0x259 => Some(1 + (msr - 0x258) as usize),
            0x268..=0x26f => Some(3 + (msr - 0x268) as usize),
            _ => None,
        }
    }

    /// The host runs with IBRS set in SPEC_CTRL (enhanced IBRS, where
    /// IA32_ARCH_CAPABILITIES has IBRS_ALL).
    fn host_ibrs(&self) -> bool {
        self.spec.spec_ctrl.is_some_and(|v| v & SPEC_CTRL_IBRS != 0)
    }

    /// RDMSR: None for #GP.
    pub fn read(&self, msr: u32) -> Option<u64> {
        if let Some(i) = Self::fixed_index(msr) {
            return Some(self.mtrr_fixed[i]);
        }
        Some(match msr {
            0x200..=0x20f => self.mtrr_var[(msr - 0x200) as usize],
            MTRR_CAP => MTRR_CAP_VALUE,
            MTRR_DEF_TYPE => self.mtrr_def,
            BIOS_SIGN_ID | MCG_CAP | MCG_STATUS | DEBUGCTL => 0,
            PLATFORM_ID | MISC_ENABLE | FEATURE_CONTROL if self.amd => return None,
            PLATFORM_ID => 0,
            MISC_ENABLE => self.misc_enable,
            // Locked, VMX off.
            FEATURE_CONTROL => 1,
            AMD_HWCR if self.amd => self.hwcr,
            AMD_DE_CFG if self.amd => self.de_cfg,
            AMD_NB_CFG | AMD_VM_CR | AMD_HSAVE_PA if self.amd => 0,
            ARCH_CAPABILITIES if !self.amd => {
                let s = &self.spec;
                guest_arch_capabilities(s.arch_capabilities?, s.tsx_ctrl.is_some(), s.mcu_opt_ctrl.is_some(), self.host_ibrs())
            }
            SPEC_CTRL => self.spec.spec_ctrl?,
            TSX_CTRL if !self.amd => self.spec.tsx_ctrl?,
            MCU_OPT_CTRL if !self.amd => self.spec.mcu_opt_ctrl?,
            AMD_BP_CFG if self.amd => self.spec.amd_bp_cfg?,
            _ => return None,
        })
    }

    /// WRMSR: None for #GP.
    pub fn write(&mut self, msr: u32, v: u64) -> Option<()> {
        // Memory types: UC, WC, WT, WP, WB.
        let ty = |t: u64| matches!(t, 0 | 1 | 4 | 5 | 6);
        if let Some(i) = Self::fixed_index(msr) {
            if !(0..8).all(|b| ty((v >> (8 * b)) & 0xff)) {
                return None;
            }
            self.mtrr_fixed[i] = v;
            return Some(());
        }
        match msr {
            0x200..=0x20f => {
                let i = (msr - 0x200) as usize;
                // A base's type; a mask's valid bit and reserved bits.
                if i.is_multiple_of(2) && !ty(v & 0xff) || v & (0xfff0_0000_0000_0000 | if i.is_multiple_of(2) { 0xf00 } else { 0x7ff }) != 0 {
                    return None;
                }
                self.mtrr_var[i] = v;
            }
            MTRR_DEF_TYPE => {
                if !ty(v & 0xff) || v & !0xcff != 0 {
                    return None;
                }
                self.mtrr_def = v;
            }
            BIOS_SIGN_ID | MCG_STATUS => {}
            DEBUGCTL if v == 0 => {}
            MISC_ENABLE if !self.amd => {
                // What the guest may turn off or on, as KVM lets it; the
                // unavailable bits stay.
                self.misc_enable = (v & !0x1800) | 0x1800;
            }
            AMD_HWCR if self.amd => self.hwcr = v & !(1 << 18),
            AMD_DE_CFG if self.amd => {
                // The host's bits (Zenbleed's, LFENCE serializing) stay,
                // and LFENCE serializing is all the guest may add.
                let host = self.host_de_cfg;
                if v & host != host || v & !(host | DE_CFG_LFENCE_SERIAL) != 0 {
                    return None;
                }
                self.de_cfg = v;
            }
            // The host's, read only: Linux writes back what it read, and
            // IBRS alone where it takes enhanced IBRS (the host's has it).
            SPEC_CTRL if self.spec.spec_ctrl == Some(v) || (v == SPEC_CTRL_IBRS && self.host_ibrs()) => {}
            TSX_CTRL if !self.amd && self.spec.tsx_ctrl == Some(v) => {}
            MCU_OPT_CTRL if !self.amd && self.spec.mcu_opt_ctrl == Some(v) => {}
            AMD_BP_CFG if self.amd && self.spec.amd_bp_cfg == Some(v) => {}
            AMD_VM_CR | AMD_HSAVE_PA if self.amd && v == 0 => {}
            AMD_NB_CFG if self.amd => {}
            _ => return None,
        }
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mtrrs_and_vendor_registers() {
        let mut m = Msrs::new(false, SpecMsrs::default());
        assert_eq!(m.read(MTRR_CAP), Some(0x508));
        assert_eq!(m.read(MTRR_DEF_TYPE), Some(0xc06));
        assert_eq!(m.write(0x200, 0x8000_0006), Some(()));
        assert_eq!(m.read(0x200), Some(0x8000_0006));
        assert_eq!(m.write(0x200, 0x8000_0002), None, "type 2 is reserved");
        assert_eq!(m.write(0x201, 0x8_0000_0800 | 0x1), None, "reserved mask bits");
        assert_eq!(m.write(0x268, 0x0505_0505_0505_0505), Some(()));
        assert_eq!(m.read(0x268), Some(0x0505_0505_0505_0505));
        assert_eq!(m.write(0x250, 0x0303), None);
        assert_eq!(m.read(FEATURE_CONTROL), Some(1));
        assert_eq!(m.write(DEBUGCTL, 1), None);
        assert_eq!(m.write(MISC_ENABLE, 0), Some(()));
        assert_eq!(m.read(MISC_ENABLE), Some(0x1800));
        assert_eq!(m.read(AMD_DE_CFG), None, "Intel");
        assert_eq!((m.read(SPEC_CTRL), m.write(SPEC_CTRL, 1)), (None, None), "no SPEC_CTRL the kernel did not say");
        let mut a = Msrs::new(true, SpecMsrs::default());
        assert_eq!(a.read(FEATURE_CONTROL), None);
        assert_eq!(a.write(AMD_DE_CFG, 2), Some(()));
        assert_eq!(a.read(AMD_DE_CFG), Some(2));
        assert_eq!(a.write(AMD_DE_CFG, 4), None);
        assert_eq!(a.write(AMD_VM_CR, 1), None);
        assert!(pat_valid(PAT_DEFAULT) && !pat_valid(0x02));
        // A kernel that says none of the speculation controls (seL4): no
        // such MSRs.
        for m in [ARCH_CAPABILITIES, SPEC_CTRL, TSX_CTRL, MCU_OPT_CTRL] {
            assert_eq!(Msrs::new(false, SpecMsrs::default()).read(m), None, "{m:#x}");
        }
        assert_eq!(a.read(AMD_BP_CFG), None);
    }

    /// An Intel host's, as FL4 says them: everything read, enhanced IBRS
    /// (IBRS) and BHI_DIS_S set.
    const INTEL: SpecMsrs = SpecMsrs {
        arch_capabilities: Some(u64::MAX),
        spec_ctrl: Some(0x401),
        tsx_ctrl: Some(0x3),
        mcu_opt_ctrl: Some(0x1),
        amd_de_cfg: None,
        amd_bp_cfg: None,
    };

    #[test]
    fn arch_capabilities_are_the_hardwares_properties() {
        // Every bit set: the immunities and properties, and the controls'
        // enumeration with their MSRs.
        let all = guest_arch_capabilities(u64::MAX, true, true, true);
        assert_eq!(all, ARCH_CAP_KEPT | ARCH_CAP_IBRS_ALL | ARCH_CAP_TSX_CTRL | ARCH_CAP_MCU_OPT_CTRL);
        for b in [0, 1, 2, 3, 4, 5, 6, 7, 8, 13, 14, 15, 17, 18, 19, 20, 24, 25, 26, 27, 28, 62] {
            assert!(all & (1 << b) != 0, "bit {b} kept");
        }
        // Never control MSRs the guest has not, nor unknown bits.
        for b in [9, 10, 11, 12, 16, 21, 22, 23, 29, 30, 31, 32, 61, 63] {
            assert_eq!(all & (1 << b), 0, "bit {b} masked");
        }
        // TSX_CTRL's and MCU_OPT_CTRL's bits go with their MSRs, IBRS_ALL
        // with the host's IBRS.
        assert_eq!(guest_arch_capabilities(u64::MAX, false, true, true) & ARCH_CAP_TSX_CTRL, 0);
        assert_eq!(guest_arch_capabilities(u64::MAX, true, false, true) & ARCH_CAP_MCU_OPT_CTRL, 0);
        assert_eq!(guest_arch_capabilities(u64::MAX, true, true, false) & ARCH_CAP_IBRS_ALL, 0);
        assert_eq!(guest_arch_capabilities(1 << 18, true, true, true), 1 << 18, "FB_CLEAR_CTRL");
        assert_eq!(guest_arch_capabilities(1 << 1, true, true, true), 1 << 1, "IBRS_ALL");
        // A recent Xeon's: the immunities kept, with TSX_CTRL's and
        // MCU_OPT_CTRL's bits, but MISC_PACKAGE_CTRLS,
        // ENERGY_FILTERING_CTL, DOITM and XAPIC_DISABLE_STATUS.
        let raw = 0x0f3e_fdeb;
        assert_eq!(guest_arch_capabilities(raw, true, true, true), raw & !((1 << 10) | (1 << 11) | (1 << 12) | (1 << 21)));
        assert_eq!(guest_arch_capabilities(raw, true, true, false), raw & !((1 << 1) | (1 << 10) | (1 << 11) | (1 << 12) | (1 << 21)));
    }

    #[test]
    fn intel_speculation_controls_read_only() {
        let mut m = Msrs::new(false, INTEL);
        assert_eq!(m.read(ARCH_CAPABILITIES), Some(guest_arch_capabilities(u64::MAX, true, true, true)));
        assert_eq!(m.write(ARCH_CAPABILITIES, 0), None);
        assert_eq!(m.write(ARCH_CAPABILITIES, m.read(ARCH_CAPABILITIES).unwrap()), None, "never written");
        // TSX_CTRL and MCU_OPT_CTRL: the host's, which only it may write.
        assert_eq!((m.read(TSX_CTRL), m.read(MCU_OPT_CTRL)), (Some(0x3), Some(0x1)));
        assert_eq!((m.write(TSX_CTRL, 0x3), m.write(MCU_OPT_CTRL, 0x1)), (Some(()), Some(())));
        assert_eq!((m.write(TSX_CTRL, 0), m.write(MCU_OPT_CTRL, 0x11)), (None, None));
        assert_eq!((m.read(TSX_CTRL), m.read(MCU_OPT_CTRL)), (Some(0x3), Some(0x1)));
        // SPEC_CTRL: the host's, written back, or IBRS alone (Linux's
        // enhanced IBRS, on the boot vCPU and every other); nothing that
        // clears the host's IBRS or sets a bit it has not.
        assert_eq!(m.read(SPEC_CTRL), Some(0x401));
        assert_eq!((m.write(SPEC_CTRL, 0x401), m.write(SPEC_CTRL, 1)), (Some(()), Some(())));
        for v in [0, 0x400, 0x403, 0x2, 0x5] {
            assert_eq!(m.write(SPEC_CTRL, v), None, "{v:#x}");
        }
        assert_eq!(m.read(SPEC_CTRL), Some(0x401), "never changed");
        // Without the host's IBRS: no IBRS_ALL, and IBRS is no write of
        // its value; with SPEC_CTRL not said, no MSR.
        let m = Msrs::new(false, SpecMsrs { spec_ctrl: Some(0x400), ..INTEL });
        assert_eq!(m.read(ARCH_CAPABILITIES).unwrap() & ARCH_CAP_IBRS_ALL, 0);
        let mut m = Msrs::new(false, SpecMsrs { spec_ctrl: Some(0), ..INTEL });
        assert_eq!((m.read(SPEC_CTRL), m.write(SPEC_CTRL, 0), m.write(SPEC_CTRL, 1)), (Some(0), Some(()), None));
        let mut m = Msrs::new(false, SpecMsrs { spec_ctrl: None, ..INTEL });
        assert_eq!((m.read(SPEC_CTRL), m.write(SPEC_CTRL, 1)), (None, None));
        assert_eq!(m.read(ARCH_CAPABILITIES).unwrap() & ARCH_CAP_IBRS_ALL, 0);
        // PRED_CMD stays hidden; AMD's are none of Intel's.
        let mut m = Msrs::new(false, INTEL);
        assert_eq!((m.read(0x49), m.write(0x49, 1)), (None, None));
        assert_eq!(Msrs::new(false, SpecMsrs { amd_bp_cfg: Some(1), ..INTEL }).read(AMD_BP_CFG), None);
        // Without an MSR the kernel read, none of it, and the
        // capabilities do not say it is there.
        let some = SpecMsrs { tsx_ctrl: None, mcu_opt_ctrl: None, ..INTEL };
        let m = Msrs::new(false, some);
        assert_eq!((m.read(TSX_CTRL), m.read(MCU_OPT_CTRL)), (None, None));
        assert_eq!(m.read(ARCH_CAPABILITIES).unwrap() & (ARCH_CAP_TSX_CTRL | ARCH_CAP_MCU_OPT_CTRL), 0);
        let m = Msrs::new(false, SpecMsrs { arch_capabilities: None, ..INTEL });
        assert_eq!((m.read(ARCH_CAPABILITIES), m.read(TSX_CTRL)), (None, Some(0x3)));
        // An AMD guest has no Intel ones, whatever the kernel says, but
        // SPEC_CTRL as the host has it.
        let mut a = Msrs::new(true, INTEL);
        assert_eq!((a.read(ARCH_CAPABILITIES), a.read(TSX_CTRL), a.read(MCU_OPT_CTRL)), (None, None, None));
        assert_eq!((a.read(SPEC_CTRL), a.write(SPEC_CTRL, 0x401), a.write(SPEC_CTRL, 0)), (Some(0x401), Some(()), None));
    }

    #[test]
    fn spec_msrs_of_the_kernels_configuration() {
        use l4h_rt::kconfig::{ENOENT, ENOSYS, keys, spec_msr_valid as v};
        // seL4: none.
        assert_eq!(SpecMsrs::of_kernel(|_| Err(ENOSYS)), SpecMsrs::default());
        // FL4 on Intel: the MSRs it read alone (EFER is never the
        // guest's), each the kernel's value of its key.
        let intel = |k: u64| match k {
            keys::SPEC_MSR_VALID => Ok(v::ARCH_CAPABILITIES | v::TSX_CTRL | v::SPEC_CTRL | v::EFER),
            keys::X86_ARCH_CAPABILITIES => Ok(0x0f3e_fdeb),
            keys::SPEC_CTRL_MSR => Ok(0x401),
            keys::SPEC_TSX_CTRL_MSR => Ok(3),
            // Valid or not, a key not read is not asked for.
            keys::SPEC_MCU_OPT_CTRL_MSR => Ok(0x11),
            _ => Err(ENOENT),
        };
        assert_eq!(
            SpecMsrs::of_kernel(intel),
            SpecMsrs { arch_capabilities: Some(0x0f3e_fdeb), spec_ctrl: Some(0x401), tsx_ctrl: Some(3), ..SpecMsrs::default() }
        );
        // FL4 on AMD (Zen 4): DE_CFG and BP_CFG.
        let amd = |k: u64| match k {
            keys::SPEC_MSR_VALID => Ok(v::AMD_DE_CFG | v::AMD_BP_CFG | v::EFER),
            keys::SPEC_AMD_DE_CFG_MSR => Ok(0x202),
            keys::SPEC_AMD_BP_CFG_MSR => Ok(0x20),
            _ => Err(ENOENT),
        };
        assert_eq!(SpecMsrs::of_kernel(amd), SpecMsrs { amd_de_cfg: Some(0x202), amd_bp_cfg: Some(0x20), ..SpecMsrs::default() });
        // A key that fails although valid says nothing of its MSR.
        let odd = |k: u64| if k == keys::SPEC_MSR_VALID { Ok(v::TSX_CTRL) } else { Err(ENOENT) };
        assert_eq!(SpecMsrs::of_kernel(odd), SpecMsrs::default());
    }

    #[test]
    fn amd_speculation_controls() {
        // Zenbleed's chicken bit (9) and LFENCE serializing (1) set by
        // the host, BP_CFG's shared-BTB fix (5).
        let spec = SpecMsrs { amd_de_cfg: Some(0x202), amd_bp_cfg: Some(0x20), ..SpecMsrs::default() };
        let mut a = Msrs::new(true, spec);
        assert_eq!((a.read(AMD_DE_CFG), a.read(AMD_BP_CFG)), (Some(0x202), Some(0x20)));
        // Linux's read-modify-write of LFENCE serializing is taken; the
        // host's bits cannot be cleared, nor others set.
        assert_eq!(a.write(AMD_DE_CFG, 0x202 | 2), Some(()));
        assert_eq!(a.write(AMD_DE_CFG, 2), None, "Zenbleed's bit stays");
        assert_eq!(a.write(AMD_DE_CFG, 0x200), None, "LFENCE serializing stays");
        assert_eq!(a.write(AMD_DE_CFG, 0x202 | 4), None);
        assert_eq!(a.read(AMD_DE_CFG), Some(0x202));
        assert_eq!((a.write(AMD_BP_CFG, 0x20), a.write(AMD_BP_CFG, 0)), (Some(()), None));
        // A host that set only Zenbleed's: the guest may add LFENCE
        // serializing, and take it away again.
        let mut a = Msrs::new(true, SpecMsrs { amd_de_cfg: Some(0x200), ..SpecMsrs::default() });
        assert_eq!((a.write(AMD_DE_CFG, 0x202), a.read(AMD_DE_CFG)), (Some(()), Some(0x202)));
        assert_eq!((a.write(AMD_DE_CFG, 0x200), a.read(AMD_DE_CFG)), (Some(()), Some(0x200)));
        assert_eq!(a.read(AMD_BP_CFG), None, "BP_CFG the kernel did not read");
        // Intel has neither.
        let m = Msrs::new(false, spec);
        assert_eq!((m.read(AMD_DE_CFG), m.read(AMD_BP_CFG)), (None, None));
    }
}

//! The model-specific registers an HVM guest's vCPU has besides what the
//! VCPU object holds (EFER, PAT, the syscall MSRs and the segment bases,
//! hw.rs) and the local APIC (APIC_BASE, TSC_DEADLINE, x2APIC): MTRRs
//! (kept, with write-back the default; the EPT decides memory types),
//! MISC_ENABLE, FEATURE_CONTROL, DEBUGCTL, microcode and machine-check
//! registers that read as nothing, and AMD's HWCR, DE_CFG and VM_CR; vcpu.rs
//! has kvmclock's two (x86/pvclock.rs).  Any
//! other MSR is #GP(0), as on a CPU without it (DESIGN.md §5.11).  Free of
//! seL4.

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
}

/// MTRRcap: 8 variable ranges, fixed ranges, write-combining.
const MTRR_CAP_VALUE: u64 = 0x508;

impl Msrs {
    pub fn new(amd: bool) -> Self {
        Msrs {
            amd,
            // MTRRs on, fixed ranges on, write-back by default.
            mtrr_def: 0xc06,
            mtrr_fixed: [0x0606_0606_0606_0606; 11],
            mtrr_var: [0; 16],
            // Fast strings; no BTS and no PEBS.
            misc_enable: 1 | (1 << 11) | (1 << 12),
            hwcr: 0,
            de_cfg: 0,
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
                // LFENCE serializing is all there is.
                if v & !2 != 0 {
                    return None;
                }
                self.de_cfg = v;
            }
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
        let mut m = Msrs::new(false);
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
        assert_eq!(m.read(0x48), None, "SPEC_CTRL is hidden");
        let mut a = Msrs::new(true);
        assert_eq!(a.read(FEATURE_CONTROL), None);
        assert_eq!(a.write(AMD_DE_CFG, 2), Some(()));
        assert_eq!(a.read(AMD_DE_CFG), Some(2));
        assert_eq!(a.write(AMD_DE_CFG, 4), None);
        assert_eq!(a.write(AMD_VM_CR, 1), None);
        assert!(pat_valid(PAT_DEFAULT) && !pat_valid(0x02));
    }
}

//! CPUID as an HVM guest sees it (DESIGN.md §5.11): the host's, without
//! what seL4's VCPUs do not switch or let a guest have, as the guest
//! kernel's KVM hides it (l4h_kvm_set_cpu_caps() in arch/l4h/kvm/common.c,
//! and what neither VT-x nor AMD-V offers a guest of ours: VMX, SVM,
//! MONITOR, the PMU, PKU, XSAVES, AVX-512, AMX, CET, LA57, RDTSCP and RDPID,
//! the speculation-control MSRs, TSX's controls, SGX), with what our
//! platform has: an x2APIC with the TSC-deadline timer and ARAT, an
//! invariant TSC whose rate leaves 0x15 and 0x16 give, and a topology of
//! one thread per core (leaves 0xb and 0x1f).  Free of seL4: the host's
//! CPUID is a function.

/// What a vCPU's CPUID depends on besides the host.
#[derive(Clone, Copy, Debug)]
pub struct Ctx {
    pub vcpu: u32,
    pub vcpus: u32,
    pub tsc_hz: u64,
    /// The guest's CR4.OSXSAVE, and XCR0.
    pub osxsave: bool,
    pub xcr0: u64,
    /// INVPCID can be enabled for guests (VT-x's control stuck).
    pub invpcid: bool,
}

const fn bit(n: u32) -> u32 {
    1 << n
}

/// The XSAVE features a guest may enable: x87, SSE and AVX, as seL4
/// (KernelXSaveFeatureSet 7) has them.
pub const XCR0_ALLOWED: u64 = 0x7;

/// The XCR0 features the guest may enable on this host.
pub fn xcr0_supported(host: &impl Fn(u32, u32) -> [u32; 4]) -> u64 {
    if host(0, 0)[0] < 0xd || host(1, 0)[2] & bit(26) == 0 {
        return 0;
    }
    host(0xd, 0)[0] as u64 & XCR0_ALLOWED
}

/// Whether XSETBV of `value` to XCR0 is valid: x87 always, AVX with SSE,
/// nothing outside what is supported.
pub fn xcr0_valid(value: u64, supported: u64) -> bool {
    value & 1 != 0 && value & !supported == 0 && (value & 4 == 0 || value & 2 != 0)
}

/// Bytes of an XSAVE area holding the features in `xcr0`.
fn xsave_size(xcr0: u64, host: &impl Fn(u32, u32) -> [u32; 4]) -> u32 {
    let mut size = 576;
    for f in 2..3u32 {
        if xcr0 & (1 << f) != 0 {
            let [sz, off, _, _] = host(0xd, f);
            size = size.max(off + sz);
        }
    }
    size
}

/// The guest's CPUID leaf `leaf`, subleaf `sub`, from the host's.
pub fn cpuid(leaf: u32, sub: u32, ctx: &Ctx, host: &impl Fn(u32, u32) -> [u32; 4]) -> [u32; 4] {
    let max_std = host(0, 0)[0];
    let max_ext = host(0x8000_0000, 0)[0];
    let amd = host(0, 0)[1] == u32::from_le_bytes(*b"Auth");
    let ours = |l: u32| matches!(l, 0x15 | 0x16 | 0xb | 0x1f | 0x4000_0000..=0x4000_00ff);
    // Leaves beyond the host's, other than the ones we make, are zero.
    if leaf < 0x8000_0000 && leaf > max_std && !ours(leaf) {
        return [0; 4];
    }
    if leaf >= 0x8000_0000 && leaf > max_ext.min(0x8000_0008) {
        return [0; 4];
    }
    let log2 = 32 - (ctx.vcpus.max(1) - 1).leading_zeros();
    match leaf {
        0 => {
            let [_, b, c, d] = host(0, 0);
            [max_std.max(0x1f), b, c, d]
        }
        1 => {
            let [a, b, c, d] = host(1, 0);
            // EBX: CLFLUSH size and brand kept; logical processors and the
            // initial APIC ID ours.
            let b = (b & 0xffff) | (ctx.vcpus.min(255) << 16) | (ctx.vcpu << 24);
            // ECX: hide DTES64, MONITOR, DS-CPL, VMX, SMX, EST, TM2, CNXT-ID,
            // SDBG, xTPR, PDCM, DCA, and say: x2APIC, TSC-deadline, a
            // hypervisor; OSXSAVE follows the guest's CR4.
            let hide_c = bit(2) | bit(3) | bit(4) | bit(5) | bit(6) | bit(7) | bit(8) | bit(10) | bit(11) | bit(14) | bit(15)
                | bit(18) | bit(27);
            let mut c = (c & !hide_c) | bit(21) | bit(24) | bit(31);
            if ctx.osxsave && c & bit(26) != 0 {
                c |= bit(27);
            }
            // EDX: hide MCE and MCA (no banks), PN, DS, ACPI, TM, PBE; HTT
            // with more than one vCPU.
            let hide_d = bit(7) | bit(14) | bit(18) | bit(21) | bit(22) | bit(29) | bit(31);
            let htt = if ctx.vcpus > 1 { bit(28) } else { 0 };
            let d = (d & !hide_d & !bit(28)) | htt | bit(9);
            [a, b, c, d]
        }
        // Cache parameters: no cores shared (topology is 0xb's).
        4 => {
            let [a, b, c, d] = host(4, sub);
            [a & 0x3ff, b, c, d]
        }
        // No MONITOR/MWAIT, no PMU.
        5 | 0xa => [0; 4],
        // Power management: ARAT only.
        6 => [bit(2), 0, 0, 0],
        7 => match sub {
            0 => {
                let [a, b, c, d] = host(7, 0);
                // EBX: hide TSC_ADJUST, SGX, PQM, MPX, PQE, AVX-512*, Intel
                // PT; INVPCID only where the VCPU can have it.
                let hide_b = bit(1) | bit(2) | bit(12) | bit(14) | bit(15) | bit(16) | bit(17) | bit(21) | bit(25) | bit(26)
                    | bit(27) | bit(28) | bit(30) | bit(31) | if ctx.invpcid { 0 } else { bit(10) };
                // ECX: hide AVX512_VBMI, PKU, OSPKE, WAITPKG, AVX512_VBMI2,
                // CET_SS, AVX512_VNNI, AVX512_BITALG, AVX512_VPOPCNTDQ, LA57,
                // RDPID, KL, SGX_LC, PKS.
                let hide_c = bit(1) | bit(3) | bit(4) | bit(5) | bit(6) | bit(7) | bit(11) | bit(12) | bit(14) | bit(16)
                    | bit(22) | bit(23) | bit(30) | bit(31);
                // EDX: keep FSRM, MD_CLEAR, SERIALIZE: hide the rest (AVX-512,
                // TSX controls, hybrid, PCONFIG, CET_IBT, AMX, speculation
                // control and the capability MSRs).
                let keep_d = bit(4) | bit(10) | bit(14);
                [a.min(1), b & !hide_b, c & !hide_c, d & keep_d]
            }
            // AVX-VNNI only.
            1 => [host(7, 1)[0] & bit(4), 0, 0, 0],
            _ => [0; 4],
        },
        // Topology: one thread per core, every vCPU a core of one package.
        0xb | 0x1f => {
            let x2apic = ctx.vcpu;
            match sub {
                0 => [0, 1, 1 << 8, x2apic],
                1 => [log2, ctx.vcpus, (2 << 8) | 1, x2apic],
                _ => [0, 0, sub, x2apic],
            }
        }
        0xd => {
            let supported = xcr0_supported(host);
            if supported == 0 {
                return [0; 4];
            }
            let cur = if ctx.osxsave { ctx.xcr0 } else { 1 };
            match sub {
                0 => [supported as u32, xsave_size(cur, host), xsave_size(supported, host), 0],
                // XSAVEOPT, XSAVEC and XGETBV with ECX=1, not XSAVES.
                1 => [host(0xd, 1)[0] & (bit(0) | bit(1) | bit(2)), xsave_size(cur, host), 0, 0],
                2 if supported & 4 != 0 => {
                    let [a, b, _, _] = host(0xd, 2);
                    [a, b, 0, 0]
                }
                _ => [0; 4],
            }
        }
        // TSC and crystal: the crystal (the APIC timer's clock) at 1 GHz,
        // the TSC at tsc_hz, to the kHz.
        0x15 => {
            let khz = (ctx.tsc_hz / 1000).min(u32::MAX as u64) as u32;
            [1_000_000, khz, 1_000_000_000, 0]
        }
        0x16 => {
            let mhz = (ctx.tsc_hz / 1_000_000).min(0xffff) as u32;
            [mhz, mhz, 100, 0]
        }
        // Not KVM, nor any hypervisor Linux knows: our own signature.
        0x4000_0000 => [0x4000_0001, u32::from_le_bytes(*b"L4HL"), u32::from_le_bytes(*b"4HL4"), u32::from_le_bytes(*b"HL4H")],
        0x4000_0001..=0x4000_00ff => [0; 4],
        0x8000_0000 => {
            let [_, b, c, d] = host(0x8000_0000, 0);
            [max_ext.min(0x8000_0008), b, c, d]
        }
        0x8000_0001 => {
            let [a, b, c, d] = host(0x8000_0001, 0);
            // ECX: hide CMP_LEGACY, SVM, EXTAPIC, CR8_LEGACY, OSVW, IBS,
            // SKINIT, WDT, LWP, NODEID, TOPOEXT, the performance counter
            // extensions, DBX, PERFTSC, PCX_L2I, MWAITX.
            let hide_c = bit(1) | bit(2) | bit(3) | bit(4) | bit(9) | bit(10) | bit(12) | bit(13) | bit(15) | bit(19)
                | bit(22) | bit(23) | bit(24) | bit(26) | bit(27) | bit(28) | bit(29);
            // EDX: hide RDTSCP.
            [a, b, c & !hide_c, d & !bit(27)]
        }
        0x8000_0002..=0x8000_0006 => host(leaf, 0),
        // Invariant TSC, and nothing else of power management.
        0x8000_0007 => [0, 0, 0, bit(8)],
        0x8000_0008 => {
            let [a, b, _, _] = host(0x8000_0008, 0);
            // Address sizes; of EBX's features CLZERO and XSAVEERPTR (no
            // speculation controls); a core per vCPU.
            let ecx = if amd { (ctx.vcpus.max(1) - 1) & 0xff | (log2 << 12) } else { 0 };
            [a & 0xffff, b & (bit(0) | bit(2)), ecx, 0]
        }
        _ => host(leaf, sub),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A host with everything set, as an Intel CPU with leaves up to 0x20.
    fn host(leaf: u32, sub: u32) -> [u32; 4] {
        match (leaf, sub) {
            (0, _) => [0x20, u32::from_le_bytes(*b"Genu"), u32::from_le_bytes(*b"ntel"), u32::from_le_bytes(*b"ineI")],
            (0xd, 0) => [0xe7, 0xa88, 0xa88, 0],
            (0xd, 2) => [256, 576, 0, 0],
            (0x8000_0000, _) => [0x8000_0021, 0, 0, 0],
            (0x8000_0008, _) => [0x3030, u32::MAX, u32::MAX, u32::MAX],
            _ => [u32::MAX; 4],
        }
    }

    const CTX: Ctx = Ctx { vcpu: 2, vcpus: 4, tsc_hz: 2_100_000_000, osxsave: false, xcr0: 1, invpcid: false };

    #[test]
    fn filtering() {
        let [_, b, c, d] = cpuid(1, 0, &CTX, &host);
        assert_eq!(b >> 24, 2);
        assert_eq!((b >> 16) & 0xff, 4);
        assert_eq!(c & (bit(5) | bit(3) | bit(27)), 0, "no VMX, MONITOR, OSXSAVE yet");
        assert_eq!(c & (bit(21) | bit(24) | bit(31)), bit(21) | bit(24) | bit(31));
        assert_eq!(d & (bit(7) | bit(14)), 0, "no MCE/MCA");
        let [_, _, c, _] = cpuid(1, 0, &Ctx { osxsave: true, ..CTX }, &host);
        assert!(c & bit(27) != 0);
        assert_eq!(cpuid(6, 0, &CTX, &host), [4, 0, 0, 0]);
        let [a, b, c, d] = cpuid(7, 0, &CTX, &host);
        assert_eq!(a, 1);
        assert_eq!(b & (bit(16) | bit(10) | bit(1)), 0, "AVX-512F, INVPCID, TSC_ADJUST");
        assert!(b & bit(5) != 0, "AVX2 stays");
        assert_eq!(c & (bit(3) | bit(16) | bit(22)), 0, "PKU, LA57, RDPID");
        assert_eq!(d, bit(4) | bit(10) | bit(14));
        assert!(cpuid(7, 0, &Ctx { invpcid: true, ..CTX }, &host)[1] & bit(10) != 0);
        assert_eq!(cpuid(0x8000_0001, 0, &CTX, &host)[3] & bit(27), 0, "RDTSCP");
        assert_eq!(cpuid(0x8000_0001, 0, &CTX, &host)[2] & bit(2), 0, "SVM");
        assert_eq!(cpuid(0x8000_0007, 0, &CTX, &host), [0, 0, 0, bit(8)]);
        assert_eq!(cpuid(0x8000_0000, 0, &CTX, &host)[0], 0x8000_0008);
        assert_eq!(cpuid(0x8000_0010, 0, &CTX, &host), [0; 4]);
        assert_eq!(cpuid(0xa, 0, &CTX, &host), [0; 4]);
    }

    #[test]
    fn tsc_topology_xsave() {
        let [a, b, c, _] = cpuid(0x15, 0, &CTX, &host);
        assert_eq!(c as u64 * b as u64 / a as u64, 2_100_000_000);
        assert_eq!(cpuid(0x16, 0, &CTX, &host)[0], 2100);
        assert_eq!(cpuid(0xb, 0, &CTX, &host), [0, 1, 0x100, 2]);
        assert_eq!(cpuid(0xb, 1, &CTX, &host), [2, 4, 0x201, 2]);
        assert_eq!(cpuid(0x1f, 2, &CTX, &host), [0, 0, 2, 2]);
        // XSAVE: x87, SSE, AVX only; the size follows XCR0.
        assert_eq!(cpuid(0xd, 0, &CTX, &host), [7, 576, 832, 0]);
        assert_eq!(cpuid(0xd, 0, &Ctx { osxsave: true, xcr0: 7, ..CTX }, &host)[1], 832);
        assert_eq!(cpuid(0xd, 1, &CTX, &host)[0], 7, "not XSAVES");
        assert!(xcr0_valid(7, 7) && xcr0_valid(3, 7) && xcr0_valid(1, 7));
        assert!(!xcr0_valid(0, 7) && !xcr0_valid(5, 7) && !xcr0_valid(0xf, 7) && !xcr0_valid(7, 3));
        let sig = cpuid(0x4000_0000, 0, &CTX, &host);
        assert_eq!(&[sig[1].to_le_bytes(), sig[2].to_le_bytes(), sig[3].to_le_bytes()].concat(), b"L4HL4HL4HL4H");
    }
}

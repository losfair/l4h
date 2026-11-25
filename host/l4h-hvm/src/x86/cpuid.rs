//! CPUID as an HVM guest sees it (DESIGN.md §5.11): the host's, without
//! what seL4's VCPUs do not switch or let a guest have, as the guest
//! kernel's KVM hides it (l4h_kvm_set_cpu_caps() in arch/l4h/kvm/common.c,
//! and what neither VT-x nor AMD-V offers a guest of ours: VMX, SVM,
//! MONITOR, the PMU, PKU, XSAVES, AVX-512, AMX, CET, LA57, RDTSCP and RDPID,
//! the speculation-control MSRs, TSX's controls, SGX; IA32_ARCH_CAPABILITIES
//! where the host's kernel says it, x86/msr.rs), with what our
//! platform has: an x2APIC with the TSC-deadline timer and ARAT, an
//! invariant TSC whose rate leaves 0x15 and 0x16 give (and kvmclock, under
//! KVM's signature, on AMD too), and vmmgr's vCores as SMT cores of one
//! package (Topology: leaves 1, 4, 0xb and 0x1f, and AMD's 0x8000_0008,
//! 0x8000_001d and 0x8000_001e).  Free of seL4: the host's CPUID is a
//! function.

/// The guest's topology: its vCPUs, one package, whose cores are
/// vmmgr's vCores (HvmConfig::vcpu_core), each vCPU an SMT thread of its
/// vCore's core.  vmmgr keeps a vCore on one physical core for the
/// guest's life (DESIGN.md §7.3), so siblings here are siblings there.
/// A vCPU's APIC ID is its vCore's number above `smt_shift` bits and its
/// place among its vCore's vCPUs below; the MADT and the local APICs
/// have the same.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Topology {
    pub vcpus: u32,
    pub apic_id: [u32; MAX_VCPUS],
    /// APIC ID bits of the thread within its core, and of the core and
    /// thread (the package's).
    pub smt_shift: u32,
    pub core_shift: u32,
    /// The most vCPUs one core has.
    pub threads: u32,
}

/// vCPUs we lay out (HvmConfig::vcpu_core's).
pub const MAX_VCPUS: usize = l4h_rt::host::hvm::MAX_VCPUS;

/// Bits that hold the numbers 0..n.
fn bits(n: u32) -> u32 {
    32 - (n.max(1) - 1).leading_zeros()
}

impl Topology {
    /// Every vCPU a core of its own, its APIC ID its number.
    pub fn flat(vcpus: usize) -> Topology {
        let vcpus = vcpus.clamp(1, MAX_VCPUS) as u32;
        let apic_id = core::array::from_fn(|v| if v < vcpus as usize { v as u32 } else { 0 });
        Topology { vcpus, apic_id, smt_shift: 0, core_shift: bits(vcpus), threads: 1 }
    }

    /// vCPU v in vCore `vcore[v]` (numbered 0.., below the vCPUs); flat if
    /// they are not that, or if an APIC ID would not fit the MADT's and
    /// xAPIC's 8 bits (0xff is the broadcast).
    pub fn of(vcore: &[u8]) -> Topology {
        let n = vcore.len().clamp(1, MAX_VCPUS);
        if vcore.len() > MAX_VCPUS || vcore.iter().any(|&c| c as usize >= n) {
            return Topology::flat(n);
        }
        let mut threads = [0u32; MAX_VCPUS];
        let mut apic_id = [0u32; MAX_VCPUS];
        for (v, &c) in vcore.iter().enumerate() {
            apic_id[v] = threads[c as usize];
            threads[c as usize] += 1;
        }
        let most = threads.iter().copied().max().unwrap_or(1).max(1);
        let cores = vcore.iter().copied().max().unwrap_or(0) as u32 + 1;
        let smt_shift = bits(most);
        let core_shift = smt_shift + bits(cores);
        if ((cores - 1) << smt_shift) + most - 1 >= 0xff {
            return Topology::flat(n);
        }
        for (v, &c) in vcore.iter().enumerate() {
            apic_id[v] |= (c as u32) << smt_shift;
        }
        Topology { vcpus: n as u32, apic_id, smt_shift, core_shift, threads: most }
    }

    /// vCPU `v`'s place in it.
    pub fn place(&self, v: usize) -> Place {
        Place { apic_id: self.apic_id[v], vcpus: self.vcpus, smt_shift: self.smt_shift, core_shift: self.core_shift,
            threads: self.threads }
    }
}

/// A vCPU's place in the Topology, as its CPUID shows it.
#[derive(Clone, Copy, Debug)]
pub struct Place {
    pub apic_id: u32,
    pub vcpus: u32,
    pub smt_shift: u32,
    pub core_shift: u32,
    pub threads: u32,
}

impl Place {
    /// The vCPUs that share a cache of `level` (1.., in Intel's and AMD's
    /// cache leaves), less one, as those leaves hold it: the L1 and L2 a
    /// core's threads, the L3 the package's.  That L3 is what one-socket
    /// hosts with one L3 have; on hosts with several (AMD's CCXs) the
    /// vCPUs' physical cores may be under different ones, which vCore
    /// swaps change at any time: the package's is what KVM's guests are
    /// usually told too, and lets the guest's scheduler find an idle vCPU
    /// on a wakeup (its LLC domain).
    fn sharing(&self, level: u32) -> u32 {
        let shift = if level <= 2 { self.smt_shift } else { self.core_shift };
        ((1u32 << shift) - 1).min(0xfff)
    }
}

/// What a vCPU's CPUID depends on besides the host.
#[derive(Clone, Copy, Debug)]
pub struct Ctx {
    pub topo: Place,
    pub tsc_hz: u64,
    /// The guest's CR4.OSXSAVE, and XCR0.
    pub osxsave: bool,
    pub xcr0: u64,
    /// The XCR0 features the VM's guests may enable (vm::Vm::xcr0).
    pub xcr0_max: u64,
    /// The guest's CR4.PKE (CPUID's OSPKE).
    pub pke: bool,
    /// INVPCID can be enabled for guests (VT-x's control stuck).
    pub invpcid: bool,
    /// The guest reads IA32_ARCH_CAPABILITIES (vm::SpecMsrs).
    pub arch_capabilities: bool,
}

const fn bit(n: u32) -> u32 {
    1 << n
}

/// The XSAVE features a guest may enable: x87, SSE, AVX, AVX-512's
/// opmask, ZMM_Hi256 and Hi16_ZMM, and PKRU, where the VCPU takes them (the VM's
/// `Ctx::xcr0_max`, which main.rs probes: FL4 does, seL4 with
/// KernelXSaveFeatureSet 7 not).  On Zen 4 a guest that runs with
/// AVX-512 left out of XCR0 gets no use of the op cache: every
/// instruction goes through the decoders (tests/run-hvmbench.sh, 25-50%
/// on throughput-bound code).
pub const XCR0_ALLOWED: u64 = 0x2e7;
/// XCR0's AVX-512 state components, and PKRU.
pub const XCR0_AVX512: u64 = 0xe0;
pub const XCR0_PKRU: u64 = 1 << 9;

/// The XCR0 features the guest may enable on this host.
pub fn xcr0_supported(host: &impl Fn(u32, u32) -> [u32; 4]) -> u64 {
    if host(0, 0)[0] < 0xd || host(1, 0)[2] & bit(26) == 0 {
        return 0;
    }
    let mut x = host(0xd, 0)[0] as u64 & XCR0_ALLOWED;
    let leaf7 = if host(0, 0)[0] >= 7 { host(7, 0) } else { [0; 4] };
    // AVX-512's three components together, with AVX512F; PKRU with PKU.
    if x & XCR0_AVX512 != XCR0_AVX512 || leaf7[1] & bit(16) == 0 {
        x &= !XCR0_AVX512;
    }
    if leaf7[2] & bit(3) == 0 {
        x &= !XCR0_PKRU;
    }
    x
}

/// Whether XSETBV of `value` to XCR0 is valid: x87 always, AVX with SSE,
/// AVX-512's three components all or none and with AVX, nothing outside
/// what is supported.
pub fn xcr0_valid(value: u64, supported: u64) -> bool {
    let avx512 = value & XCR0_AVX512;
    value & 1 != 0
        && value & !supported == 0
        && (value & 4 == 0 || value & 2 != 0)
        && (avx512 == 0 || (avx512 == XCR0_AVX512 && value & 6 == 6))
}

/// Bytes of an XSAVE area holding the features in `xcr0`.
fn xsave_size(xcr0: u64, host: &impl Fn(u32, u32) -> [u32; 4]) -> u32 {
    let mut size = 576;
    for f in 2..10u32 {
        if xcr0 & (1 << f) != 0 {
            let [sz, off, _, _] = host(0xd, f);
            size = size.max(off + sz);
        }
    }
    size
}

/// Bytes of a compacted (XSAVEC) XSAVE area holding the features in
/// `xcr0`: the components in order after the header, each 64-byte
/// aligned where the host's subleaf says so (ECX bit 1).  Intel's
/// standard format leaves MPX's room before AVX-512's state, so the two
/// differ there; AMD's has no gap.
fn xsave_compacted_size(xcr0: u64, host: &impl Fn(u32, u32) -> [u32; 4]) -> u32 {
    let mut size: u32 = 576;
    for f in 2..10u32 {
        if xcr0 & (1 << f) != 0 {
            let [sz, _, c, _] = host(0xd, f);
            if c & bit(1) != 0 {
                size = size.next_multiple_of(64);
            }
            size += sz;
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
    if leaf >= 0x8000_0000 && leaf > max_ext.min(max_ext_ours(amd)) {
        return [0; 4];
    }
    let t = &ctx.topo;
    match leaf {
        0 => {
            let [_, b, c, d] = host(0, 0);
            [max_std.max(0x1f), b, c, d]
        }
        1 => {
            let [a, b, c, d] = host(1, 0);
            // EBX: CLFLUSH size and brand kept; the package's addressable
            // APIC IDs and the initial APIC ID ours.
            let b = (b & 0xffff) | ((1u32 << t.core_shift).min(255) << 16) | (t.apic_id << 24);
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
            let htt = if t.vcpus > 1 { bit(28) } else { 0 };
            let d = (d & !hide_d & !bit(28)) | htt | bit(9);
            [a, b, c, d]
        }
        // Cache parameters: the host's, shared as Place::sharing says, in
        // a package of our cores (topology is 0xb's).
        4 => {
            let [a, b, c, d] = host(4, sub);
            let cores = ((1u32 << (t.core_shift - t.smt_shift)) - 1).min(63);
            [if a & 0x1f == 0 { 0 } else { cache_sharing(a, t) | cores << 26 }, b, c, d]
        }
        // No MONITOR/MWAIT, no PMU.
        5 | 0xa => [0; 4],
        // Power management: ARAT only.
        6 => [bit(2), 0, 0, 0],
        7 => match sub {
            0 => {
                let [a, b, c, d] = host(7, 0);
                // AVX-512 where its state is the guest's (XCR0_ALLOWED):
                // F, DQ, IFMA, CD, BW, VL; VBMI, VBMI2, VNNI, BITALG,
                // VPOPCNTDQ.  Never Xeon Phi's PF and ER.
                let avx512 = ctx.xcr0_max & XCR0_AVX512 == XCR0_AVX512;
                let avx512_b = bit(16) | bit(17) | bit(21) | bit(28) | bit(30) | bit(31);
                let avx512_c = bit(1) | bit(6) | bit(11) | bit(12) | bit(14);
                // EBX: hide TSC_ADJUST, SGX, PQM, MPX, PQE, AVX-512 without
                // its state, Intel PT; INVPCID only where the VCPU can have it.
                let hide_b = bit(1) | bit(2) | bit(12) | bit(14) | bit(15) | bit(25) | bit(26) | bit(27)
                    | if avx512 { 0 } else { avx512_b } | if ctx.invpcid { 0 } else { bit(10) };
                // ECX: hide WAITPKG, CET_SS, LA57, RDPID, KL, SGX_LC, PKS;
                // AVX-512's without its state; PKU without PKRU's (the
                // guest's protection keys in its XSAVE state, as KVM gives
                // them), OSPKE as the guest's CR4.PKE has it.
                let pku = ctx.xcr0_max & XCR0_PKRU != 0;
                let hide_c = bit(4) | bit(5) | bit(7) | bit(16) | bit(22) | bit(23) | bit(30) | bit(31)
                    | if avx512 { 0 } else { avx512_c } | if pku { 0 } else { bit(3) };
                let c = (c & !hide_c) | if pku && ctx.pke { bit(4) } else { 0 };
                // EDX: keep FSRM, MD_CLEAR, SERIALIZE, and ARCH_CAPABILITIES
                // where the guest reads it: hide the rest (AVX-512, TSX
                // controls, hybrid, PCONFIG, CET_IBT, AMX, speculation
                // control and the core capabilities MSR).
                let keep_d = bit(4) | bit(10) | bit(14) | if ctx.arch_capabilities { bit(29) } else { 0 };
                [a.min(1), b & !hide_b, c, d & keep_d]
            }
            // AVX-VNNI, and AVX512_BF16 with AVX-512's state.
            1 => {
                let bf16 = if ctx.xcr0_max & XCR0_AVX512 == XCR0_AVX512 { bit(5) } else { 0 };
                [host(7, 1)[0] & (bit(4) | bf16), 0, 0, 0]
            }
            _ => [0; 4],
        },
        // Topology: SMT threads of cores of one package (Topology).
        0xb | 0x1f => {
            let x2apic = t.apic_id;
            match sub {
                0 => [t.smt_shift, t.threads, 1 << 8, x2apic],
                1 => [t.core_shift, t.vcpus, (2 << 8) | 1, x2apic],
                _ => [0, 0, sub, x2apic],
            }
        }
        0xd => {
            let supported = ctx.xcr0_max;
            if supported == 0 {
                return [0; 4];
            }
            let cur = if ctx.osxsave { ctx.xcr0 } else { 1 };
            match sub {
                0 => [supported as u32, xsave_size(cur, host), xsave_size(supported, host), 0],
                // XSAVEOPT, XSAVEC and XGETBV with ECX=1, not XSAVES; EBX
                // the size of XCR0's state (IA32_XSS is 0) as XSAVEC lays
                // it out, which Linux checks it against.
                1 => [host(0xd, 1)[0] & (bit(0) | bit(1) | bit(2)), xsave_compacted_size(cur, host), 0, 0],
                // User state components: their size, standard offset and
                // XSAVEC alignment (ECX bit 1).
                2 | 5..=7 | 9 if supported & (1 << sub) != 0 => {
                    let [a, b, c, _] = host(0xd, sub);
                    [a, b, c & bit(1), 0]
                }
                _ => [0; 4],
            }
        }
        // TSC and crystal: the crystal (the APIC timer's clock) at
        // CRYSTAL_HZ, the TSC at tsc_hz as a ratio Linux computes in 32
        // bits (tsc_ratio).
        0x15 => {
            let (den, num) = tsc_ratio(ctx.tsc_hz / 1000, CRYSTAL_HZ / 1000);
            [den, num, CRYSTAL_HZ as u32, 0]
        }
        0x16 => {
            let mhz = (ctx.tsc_hz / 1_000_000).min(0xffff) as u32;
            [mhz, mhz, 100, 0]
        }
        // KVM's signature, for kvmclock alone (pvclock.rs): Linux on AMD
        // has no other way to the TSC's rate than calibrating it, and its
        // other KVM features stay off without their bits.
        0x4000_0000 => [0x4000_0001, u32::from_le_bytes(*b"KVMK"), u32::from_le_bytes(*b"VMKV"), u32::from_le_bytes(*b"M\0\0\0")],
        0x4000_0001 => [super::pvclock::FEATURES, 0, 0, 0],
        0x4000_0002..=0x4000_00ff => [0; 4],
        0x8000_0000 => {
            let [_, b, c, d] = host(0x8000_0000, 0);
            [max_ext.min(max_ext_ours(amd)), b, c, d]
        }
        0x8000_0001 => {
            let [a, b, c, d] = host(0x8000_0001, 0);
            // ECX: hide CMP_LEGACY, SVM, EXTAPIC, CR8_LEGACY, OSVW, IBS,
            // SKINIT, WDT, LWP, NODEID, the performance counter
            // extensions, DBX, PERFTSC, PCX_L2I, MWAITX.  TOPOEXT (AMD's
            // only way to SMT siblings in Linux) with its leaves, ours.
            let hide_c = bit(1) | bit(2) | bit(3) | bit(4) | bit(9) | bit(10) | bit(12) | bit(13) | bit(15) | bit(19)
                | bit(23) | bit(24) | bit(26) | bit(27) | bit(28) | bit(29) | if topoext(amd, host) { 0 } else { bit(22) };
            // EDX: hide RDTSCP.
            [a, b, c & !hide_c, d & !bit(27)]
        }
        0x8000_0002..=0x8000_0006 => host(leaf, 0),
        // AMD's cache properties, as leaf 4 (with TOPOEXT): the host's,
        // shared as ours.
        0x8000_001d if topoext(amd, host) => {
            let [a, b, c, d] = host(0x8000_001d, sub);
            [cache_sharing(a, t), b, c, d]
        }
        // AMD's topology (with TOPOEXT): the extended APIC ID; the core's
        // threads and number; one node.
        0x8000_001e if topoext(amd, host) => [t.apic_id, ((t.threads - 1) << 8) | (t.apic_id >> t.smt_shift) & 0xff, 0, 0],
        // Invariant TSC, and nothing else of power management.
        0x8000_0007 => [0, 0, 0, bit(8)],
        0x8000_0008 => {
            let [a, b, _, _] = host(0x8000_0008, 0);
            // Address sizes: virtual 48 bits at most (no LA57), physical
            // below 2^47 (seL4's EPT); of EBX's features CLZERO and
            // XSAVEERPTR, and on AMD the hardware's BTC_NO (no
            // speculation controls); the package's threads and APIC ID
            // bits.
            let (phys, virt) = ((a & 0xff).min(MAX_PHYS_BITS), ((a >> 8) & 0xff).min(48));
            let ecx = if amd { (t.vcpus.max(1) - 1) & 0xff | (t.core_shift << 12) } else { 0 };
            let keep_b = bit(0) | bit(2) | if amd { BTC_NO } else { 0 };
            [phys | virt << 8, b & keep_b, ecx, 0]
        }
        // AMD's extended features 2: LFENCE always serializing, and
        // Automatic IBRS, whose EFER.AIBRSE the VMCB holds for the guest
        // (hw/svm.rs), so that Linux need not fall back to retpolines; and
        // what the hardware is or is immune to (no nested data
        // breakpoints, null selectors clearing the base, SRSO_NO and
        // SRSO_USER_KERNEL_NO).  Nothing of TSA or the speculation
        // controls' MSRs, which seL4's VCPUs do not switch.
        0x8000_0021 if amd => [host(0x8000_0021, 0)[0] & EXT21_KEPT, 0, 0, 0],
        // The legacy cache descriptors; any other leaf (SGX, PT, RDT, AMX,
        // key locker, hybrid, LBR, ...) is none.
        2 => host(2, 0),
        _ => [0; 4],
    }
}

/// A cache leaf's EAX (Intel's 4, AMD's 0x8000_001d): its type, level and
/// associativity the host's, the vCPUs sharing it ours.
fn cache_sharing(a: u32, t: &Place) -> u32 {
    if a & 0x1f == 0 {
        return 0;
    }
    (a & 0x3ff) | t.sharing((a >> 5) & 7) << 14
}

/// AMD's topology extensions (TOPOEXT, 0x8000_0001 ECX bit 22) on the
/// host: its 0x8000_001d cache leaves, which ours are made from.
fn topoext(amd: bool, host: &impl Fn(u32, u32) -> [u32; 4]) -> bool {
    amd && host(0x8000_0000, 0)[0] >= 0x8000_001e && host(0x8000_0001, 0)[2] & bit(22) != 0
}

/// CPUID 0x8000_0021 EAX: LFENCE always serializing, Automatic IBRS, and
/// what the guest is told of the hardware with them.
pub const LFENCE_SERIAL: u32 = 1 << 2;
pub const AUTO_IBRS: u32 = 1 << 8;
pub const NO_NESTED_DATA_BP: u32 = 1 << 0;
pub const NULL_SEL_CLR_BASE: u32 = 1 << 6;
pub const SRSO_NO: u32 = 1 << 29;
pub const SRSO_USER_KERNEL_NO: u32 = 1 << 30;
const EXT21_KEPT: u32 = NO_NESTED_DATA_BP | LFENCE_SERIAL | NULL_SEL_CLR_BASE | AUTO_IBRS | SRSO_NO | SRSO_USER_KERNEL_NO;
/// CPUID 0x8000_0008 EBX: AMD's branch type confusion immunity.
pub const BTC_NO: u32 = 1 << 29;

/// The last extended leaf we give: AMD's 0x8000_0021 (the leaves between
/// it and 0x8000_0008 are zero), Intel's 0x8000_0008.
const fn max_ext_ours(amd: bool) -> u32 {
    if amd { 0x8000_0021 } else { 0x8000_0008 }
}

/// The crystal clock CPUID 0x15 gives, which the local APIC timer runs at
/// (dev/lapic.rs): 25 MHz, as many Intel parts have.
pub const CRYSTAL_HZ: u64 = 25_000_000;
/// Guest-physical addresses are below 2^47 (seL4's 4-level EPT).
pub const MAX_PHYS_BITS: u32 = 47;

const fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

/// CPUID 0x15's (denominator, numerator) for a TSC of `tsc_khz` and a
/// crystal of `crystal_khz`: Linux takes the TSC as `crystal_khz *
/// numerator / denominator` in 32-bit arithmetic (tsc.c,
/// native_calibrate_tsc()), which must not overflow; as exact as fits.
pub fn tsc_ratio(tsc_khz: u64, crystal_khz: u64) -> (u32, u32) {
    if tsc_khz == 0 || crystal_khz == 0 {
        return (0, 0);
    }
    let g = gcd(tsc_khz, crystal_khz);
    let (num, den) = (tsc_khz / g, crystal_khz / g);
    let max_num = u32::MAX as u64 / crystal_khz;
    if num <= max_num && den <= u32::MAX as u64 {
        return (den as u32, num as u32);
    }
    let den = ((max_num * crystal_khz) / tsc_khz).max(1);
    let num = ((tsc_khz * den + crystal_khz / 2) / crystal_khz).min(max_num);
    (den as u32, num as u32)
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

    const FLAT4: Place = Place { apic_id: 2, vcpus: 4, smt_shift: 0, core_shift: 2, threads: 1 };
    const CTX: Ctx = Ctx {
        topo: FLAT4, tsc_hz: 2_100_000_000, osxsave: false, xcr0: 1, xcr0_max: 7, pke: false, invpcid: false, arch_capabilities: false,
    };

    /// An AMD host with everything set and extended leaves to 0x8000_0021.
    fn amd_host(leaf: u32, sub: u32) -> [u32; 4] {
        match leaf {
            0 => [0x10, u32::from_le_bytes(*b"Auth"), u32::from_le_bytes(*b"cAMD"), u32::from_le_bytes(*b"enti")],
            0x8000_0000 => [0x8000_0028, 0, 0, 0],
            _ => host(leaf, sub),
        }
    }

    #[test]
    fn avx512_with_its_state_alone() {
        // A host with AVX-512's state, its XSAVE components at their usual
        // offsets.
        let h = |leaf: u32, sub: u32| match (leaf, sub) {
            (0xd, 0) => [0x2e7, 0x988, 0x988, 0],
            (0xd, 2) => [256, 576, 0, 0],
            (0xd, 5) => [64, 832, 0, 0],
            (0xd, 6) => [512, 896, 0, 0],
            (0xd, 7) => [1024, 1408, 0, 0],
            _ => host(leaf, sub),
        };
        let on = Ctx { xcr0_max: 0xe7, ..CTX };
        let [_, b, c, _] = cpuid(7, 0, &on, &h);
        assert_eq!(b & (bit(16) | bit(30) | bit(31)), bit(16) | bit(30) | bit(31), "AVX-512 F, BW, VL");
        assert_eq!(b & (bit(26) | bit(27)), 0, "never PF, ER");
        assert_eq!(c & (bit(1) | bit(14)), bit(1) | bit(14), "VBMI, VPOPCNTDQ");
        assert_eq!(c & bit(4), 0, "OSPKE off");
        assert_eq!(cpuid(7, 1, &on, &h)[0] & bit(5), bit(5), "AVX512_BF16");
        assert_eq!(cpuid(0xd, 0, &Ctx { osxsave: true, xcr0: 0xe7, ..on }, &h), [0xe7, 2432, 2432, 0]);
        assert_eq!(cpuid(0xd, 6, &on, &h), [512, 896, 0, 0]);
        assert_eq!(cpuid(0xd, 1, &Ctx { osxsave: true, xcr0: 0xe7, ..on }, &h)[1], 2432);
        // Without the state (seL4's VCPUs): none of it.
        let [_, b, c, _] = cpuid(7, 0, &CTX, &h);
        assert_eq!(b & (bit(16) | bit(17) | bit(21) | bit(28) | bit(30) | bit(31)), 0);
        assert_eq!(c & (bit(1) | bit(6) | bit(11) | bit(12) | bit(14)), 0);
        assert_eq!(cpuid(7, 1, &CTX, &h)[0] & bit(5), 0);
        assert_eq!(cpuid(0xd, 0, &CTX, &h)[0], 7);
        assert_eq!(cpuid(0xd, 5, &CTX, &h), [0; 4]);
        assert_eq!(xcr0_supported(&h), 0x2e7, "x87, SSE, AVX, AVX-512, PKRU");
        // PKRU's state without PKU, AVX-512's without AVX512F: not offered.
        let no = |leaf: u32, reg: usize, b: u32| move |l: u32, s: u32| {
            let mut r = h(l, s);
            if l == leaf && s == 0 {
                r[reg] &= !b;
            }
            r
        };
        assert_eq!(xcr0_supported(&no(7, 2, bit(3))), 0xe7);
        assert_eq!(xcr0_supported(&no(7, 1, bit(16))), 0x207);
        // PKU with PKRU's state, OSPKE as the guest's CR4.PKE.
        let with = Ctx { xcr0_max: 0x2e7, ..CTX };
        assert_eq!(cpuid(7, 0, &with, &h)[2] & (bit(3) | bit(4)), bit(3));
        assert_eq!(cpuid(7, 0, &Ctx { pke: true, ..with }, &h)[2] & (bit(3) | bit(4)), bit(3) | bit(4));
        assert_eq!(cpuid(7, 0, &Ctx { pke: true, ..CTX }, &h)[2] & (bit(3) | bit(4)), 0, "no PKU without PKRU");
        let h9 = |l: u32, s: u32| if (l, s) == (0xd, 9) { [8, 2440, 0, 0] } else { h(l, s) };
        assert_eq!(cpuid(0xd, 9, &with, &h9), [8, 2440, 0, 0]);
        assert_eq!(cpuid(0xd, 0, &Ctx { osxsave: true, xcr0: 0x2e7, ..with }, &h9)[1], 2448);
    }

    #[test]
    fn xsavec_size_on_intel_layout() {
        // Intel (Emerald Rapids, GCE C4): MPX's room (960..1088) before
        // AVX-512's state in the standard format, none in the compacted.
        let h = |leaf: u32, sub: u32| match (leaf, sub) {
            (0xd, 0) => [0x2e7, 0xa88, 0xa88, 0],
            (0xd, 1) => [0xf, 0xa88, 0, 0],
            (0xd, 2) => [256, 576, 0, 0],
            (0xd, 5) => [64, 1088, 0, 0],
            (0xd, 6) => [512, 1152, 0, 0],
            (0xd, 7) => [1024, 1664, 0, 0],
            (0xd, 9) => [8, 2688, 0, 0],
            _ => host(leaf, sub),
        };
        let on = Ctx { osxsave: true, xcr0: 0xe7, xcr0_max: 0x2e7, ..CTX };
        assert_eq!(cpuid(0xd, 0, &on, &h), [0x2e7, 2688, 2696, 0], "standard sizes");
        assert_eq!(cpuid(0xd, 1, &on, &h), [7, 2432, 0, 0], "XSAVEC's size, no XSAVES");
        assert_eq!(cpuid(0xd, 1, &Ctx { xcr0: 0x2e7, ..on }, &h)[1], 2440);
        assert_eq!(cpuid(0xd, 1, &Ctx { xcr0: 7, ..on }, &h)[1], 832);
        // A component 64-byte aligned in the compacted format (a made-up
        // layout: 8 bytes of component 5, so 6 starts at 896, not 840).
        let ha = |l: u32, s: u32| match (l, s) {
            (0xd, 5) => [8, 1088, 0, 0],
            (0xd, 6) => [512, 1152, 2, 0],
            _ => h(l, s),
        };
        assert_eq!(cpuid(0xd, 6, &on, &ha), [512, 1152, 2, 0]);
        assert_eq!(cpuid(0xd, 1, &on, &ha)[1], 896 + 512 + 1024);
    }

    #[test]
    fn amd_extended_leaves_give_auto_ibrs_alone() {
        assert_eq!(cpuid(0x8000_0000, 0, &CTX, &amd_host)[0], 0x8000_0021);
        assert_eq!(cpuid(0x8000_0021, 0, &CTX, &amd_host), [EXT21_KEPT, 0, 0, 0]);
        assert_eq!(EXT21_KEPT, (1 << 0) | (1 << 2) | (1 << 6) | (1 << 8) | (1 << 29) | (1 << 30));
        // TSA's and the speculation controls' bits stay hidden (all set on
        // the host): exactly those six.
        assert_eq!(cpuid(0x8000_0021, 0, &CTX, &amd_host)[0].count_ones(), 6);
        // BTC_NO with CLZERO and XSAVEERPTR on AMD; Intel has none.
        assert_eq!(cpuid(0x8000_0008, 0, &CTX, &amd_host)[1], bit(0) | bit(2) | BTC_NO);
        assert_eq!(cpuid(0x8000_0008, 0, &CTX, &host)[1], bit(0) | bit(2));
        // SVM, SEV, the TLB leaves: none.
        for leaf in [0x8000_000a, 0x8000_0019, 0x8000_001f, 0x8000_0020, 0x8000_0022] {
            assert_eq!(cpuid(leaf, 0, &CTX, &amd_host), [0; 4], "{leaf:#x}");
        }
        // Without it on the host, the bit is off; Intel stops at 0x8000_0008.
        let no = |l: u32, s: u32| if l == 0x8000_0021 { [0; 4] } else { amd_host(l, s) };
        assert_eq!(cpuid(0x8000_0021, 0, &CTX, &no)[0] & AUTO_IBRS, 0);
        assert_eq!(cpuid(0x8000_0021, 0, &CTX, &host), [0; 4]);
        let h = crate::vm::Host::of(&amd_host);
        assert!(h.auto_ibrs);
        assert!(!crate::vm::Host::of(&no).auto_ibrs);
    }

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
        // IA32_ARCH_CAPABILITIES where the guest reads it (x86/msr.rs).
        assert_eq!(cpuid(7, 0, &Ctx { arch_capabilities: true, ..CTX }, &host)[3], bit(4) | bit(10) | bit(14) | bit(29));
        assert!(cpuid(7, 0, &Ctx { invpcid: true, ..CTX }, &host)[1] & bit(10) != 0);
        assert_eq!(cpuid(0x8000_0001, 0, &CTX, &host)[3] & bit(27), 0, "RDTSCP");
        assert_eq!(cpuid(0x8000_0001, 0, &CTX, &host)[2] & bit(2), 0, "SVM");
        assert_eq!(cpuid(0x8000_0007, 0, &CTX, &host), [0, 0, 0, bit(8)]);
        assert_eq!(cpuid(0x8000_0000, 0, &CTX, &host)[0], 0x8000_0008);
        assert_eq!(cpuid(0x8000_0010, 0, &CTX, &host), [0; 4]);
        assert_eq!(cpuid(0xa, 0, &CTX, &host), [0; 4]);
    }

    /// Linux's TSC from leaf 0x15, as it computes it (u32), for TSCs
    /// whole and not, to over 10 GHz: no overflow, within 0.01%.
    #[test]
    fn tsc_ratio_fits_linux_arithmetic() {
        for hz in [2_100_000_000u64, 3_600_000_000, 5_000_000_000, 2_100_345_678, 5_333_333_333, 1_000_000, 11_111_111_111,
            25_000_000, 1_799_999_999, 4_294_967_295_000]
        {
            let [den, num, crystal, _] = cpuid(0x15, 0, &Ctx { tsc_hz: hz, ..CTX }, &host);
            let crystal_khz = crystal / 1000;
            let linux = crystal_khz.checked_mul(num).expect("no overflow") / den;
            let khz = hz / 1000;
            let err = (linux as i64 - khz as i64).unsigned_abs();
            assert!(err * 10_000 <= khz, "{hz} Hz: Linux sees {linux} kHz, err {err}");
        }
        assert_eq!(tsc_ratio(2_100_000, 25_000), (1, 84));
        assert_eq!(tsc_ratio(0, 25_000), (0, 0));
    }

    #[test]
    fn address_sizes_and_unknown_leaves() {
        // A host with LA57 and 52-bit physical addresses.
        let big = |leaf: u32, sub: u32| if leaf == 0x8000_0008 { [52 | 57 << 8, 0, 0, 0] } else { host(leaf, sub) };
        let a = cpuid(0x8000_0008, 0, &CTX, &big)[0];
        assert_eq!((a & 0xff, (a >> 8) & 0xff), (47, 48));
        let small = |leaf: u32, sub: u32| if leaf == 0x8000_0008 { [39 | 48 << 8, 0, 0, 0] } else { host(leaf, sub) };
        let a = cpuid(0x8000_0008, 0, &CTX, &small)[0];
        assert_eq!((a & 0xff, (a >> 8) & 0xff), (39, 48), "smaller ones kept");
        for leaf in [3, 8, 9, 0xc, 0xe, 0xf, 0x10, 0x12, 0x14, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x20] {
            assert_eq!(cpuid(leaf, 0, &CTX, &host), [0; 4], "leaf {leaf:#x}");
        }
        assert_eq!(cpuid(2, 0, &CTX, &host), host(2, 0));
    }

    /// vmmgr's vCores: 0 and 2 on one, 1 and 4 on another, 3 alone.
    #[test]
    fn topology_from_vcores() {
        let t = Topology::of(&[0, 1, 0, 2, 1]);
        assert_eq!(&t.apic_id[..5], &[0, 2, 1, 4, 3]);
        assert_eq!((t.vcpus, t.smt_shift, t.core_shift, t.threads), (5, 1, 3, 2));
        // One vCPU a vCore (a guest no larger than the host's cores): flat.
        let one = Topology::of(&[0, 1, 2, 3]);
        assert_eq!(one, Topology::flat(4));
        assert_eq!((one.smt_shift, one.core_shift, one.threads), (0, 2, 1));
        assert_eq!(Topology::of(&[0]), Topology::flat(1));
        assert_eq!(Topology::flat(1).core_shift, 0);
        // Three on one core: two bits of thread.
        let three = Topology::of(&[0, 0, 0, 1]);
        assert_eq!(&three.apic_id[..4], &[0, 1, 2, 4]);
        assert_eq!((three.smt_shift, three.core_shift, three.threads), (2, 3, 3));
        // vCores that are not 0.. below the vCPUs, or APIC IDs past 0xfe:
        // flat.
        assert_eq!(Topology::of(&[0, 4, 0]), Topology::flat(3));
        let mut big = [0u8; MAX_VCPUS];
        for (v, c) in big.iter_mut().enumerate() {
            *c = if v < 32 { 0 } else { (v - 31) as u8 };
        }
        assert_eq!(Topology::of(&big), Topology::flat(MAX_VCPUS));
        let pairs: [u8; MAX_VCPUS] = core::array::from_fn(|v| (v / 2) as u8);
        let p = Topology::of(&pairs);
        assert_eq!((p.smt_shift, p.core_shift, p.apic_id[MAX_VCPUS - 1]), (1, 6, MAX_VCPUS as u32 - 1));
    }

    #[test]
    fn smt_and_caches_in_cpuid() {
        let t = Topology::of(&[0, 1, 0, 2, 1]);
        let ctx = |v: usize| Ctx { topo: t.place(v), ..CTX };
        // vCPU 4: thread 1 of core 1.
        assert_eq!(cpuid(0xb, 0, &ctx(4), &host), [1, 2, 0x100, 3]);
        assert_eq!(cpuid(0xb, 1, &ctx(4), &host), [3, 5, 0x201, 3]);
        assert_eq!(cpuid(0x1f, 0, &ctx(3), &host), [1, 2, 0x100, 4]);
        let [_, b, _, d] = cpuid(1, 0, &ctx(4), &host);
        assert_eq!((b >> 24, (b >> 16) & 0xff, d & bit(28) != 0), (3, 8, true));
        // Leaf 4: L1 and L2 the core's two threads, L3 the package's 8 IDs;
        // 4 cores' IDs.
        let cache = |level: u32| {
            move |l: u32, s: u32| match (l, s) {
                (4, 0) => [1 | level << 5 | 0x3ff << 14 | 0x3f << 26, 7, 8, 9],
                (4, _) => [0; 4],
                _ => host(l, s),
            }
        };
        for (level, share) in [(1, 1), (2, 1), (3, 7)] {
            let [a, b, c, d] = cpuid(4, 0, &ctx(0), &cache(level));
            assert_eq!((a & 0x3ff, (a >> 14) & 0xfff, a >> 26, b, c, d), (1 | level << 5, share, 3, 7, 8, 9), "L{level}");
        }
        let none = |l: u32, s: u32| if l == 4 { [0, 0, 0, 0] } else { host(l, s) };
        assert_eq!(cpuid(4, 1, &ctx(0), &none), [0; 4], "no more caches");
        // Flat: nothing shared below L3.
        let [a, ..] = cpuid(4, 0, &CTX, &cache(2));
        assert_eq!(((a >> 14) & 0xfff, a >> 26), (0, 3));
        let [a, ..] = cpuid(4, 0, &CTX, &cache(3));
        assert_eq!((a >> 14) & 0xfff, 3);
        // Intel: no TOPOEXT, no AMD leaves.
        assert_eq!(cpuid(0x8000_0001, 0, &ctx(0), &host)[2] & bit(22), 0);
        assert_eq!(cpuid(0x8000_001e, 0, &ctx(0), &host), [0; 4]);
    }

    #[test]
    fn amd_topoext() {
        let t = Topology::of(&[0, 1, 0, 2, 1]);
        let ctx = |v: usize| Ctx { topo: t.place(v), ..CTX };
        let l3 = |l: u32, s: u32| match (l, s) {
            (0x8000_001d, 0) => [1 | 3 << 5 | 0xfff << 14, 7, 8, 9],
            (0x8000_001d, _) => [0; 4],
            _ => amd_host(l, s),
        };
        assert!(cpuid(0x8000_0001, 0, &ctx(4), &l3)[2] & bit(22) != 0, "TOPOEXT");
        assert_eq!(cpuid(0x8000_001d, 0, &ctx(4), &l3), [1 | 3 << 5 | 7 << 14, 7, 8, 9]);
        assert_eq!(cpuid(0x8000_001d, 1, &ctx(4), &l3), [0, 0, 0, 0]);
        // vCPU 4: APIC ID 3, two threads a core, core 1, one node.
        assert_eq!(cpuid(0x8000_001e, 0, &ctx(4), &l3), [3, (1 << 8) | 1, 0, 0]);
        assert_eq!(cpuid(0x8000_001e, 0, &CTX, &l3), [2, 2, 0, 0], "flat: a thread a core");
        let [_, _, c, _] = cpuid(0x8000_0008, 0, &ctx(4), &l3);
        assert_eq!((c & 0xff, (c >> 12) & 0xf), (4, 3));
        // A host without it: neither the bit nor its leaves.
        let no = |l: u32, s: u32| {
            let [a, b, c, d] = amd_host(l, s);
            if l == 0x8000_0001 { [a, b, c & !bit(22), d] } else { [a, b, c, d] }
        };
        assert_eq!(cpuid(0x8000_0001, 0, &ctx(0), &no)[2] & bit(22), 0);
        assert_eq!(cpuid(0x8000_001d, 0, &ctx(0), &no), [0; 4]);
        assert_eq!(cpuid(0x8000_001e, 0, &ctx(0), &no), [0; 4]);
    }

    #[test]
    fn tsc_topology_xsave() {
        let [a, b, c, _] = cpuid(0x15, 0, &CTX, &host);
        assert_eq!(c as u64, CRYSTAL_HZ);
        assert_eq!((c / 1000).checked_mul(b).map(|x| x / a), Some(2_100_000), "Linux's 32-bit arithmetic");
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
        // AVX-512: its three components together, and with SSE and AVX.
        assert!(xcr0_valid(0xe7, 0x2e7) && xcr0_valid(0x2e7, 0x2e7) && xcr0_valid(0x207, 0x2e7));
        for x in [0x21, 0xe1, 0xe3, 0x67, 0xa7] {
            assert!(!xcr0_valid(x, 0x2e7), "{x:#x}");
        }
        let sig = cpuid(0x4000_0000, 0, &CTX, &host);
        assert_eq!(&[sig[1].to_le_bytes(), sig[2].to_le_bytes(), sig[3].to_le_bytes()].concat(), b"KVMKVMKVM\0\0\0");
        assert_eq!(sig[0], 0x4000_0001);
        // kvmclock (CLOCKSOURCE2) with the stable bit, steal time, PV
        // EOI, and no other feature.
        assert_eq!(cpuid(0x4000_0001, 0, &CTX, &host), [(1 << 3) | (1 << 5) | (1 << 6) | (1 << 24), 0, 0, 0]);
        assert_eq!(cpuid(0x4000_0002, 0, &CTX, &host), [0; 4]);
    }
}

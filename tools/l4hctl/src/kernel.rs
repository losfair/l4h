// SPDX-License-Identifier: BSD-2-Clause

//! What the host's microkernel found and chose at boot (FL4's
//! seL4_KernelConfig, DESIGN.md §10.1), one word per key: in any guest.
//! An l4h guest asks through its kernel's /dev/l4h-kconfig, an HVM guest
//! through its kernel configuration port (abi.h, L4H_KCONFIG_PORT_*).
//! The keys and the meaning of their values are libsel4's
//! (`sel4/constants.h`, seL4_KernelConfig_*).

use super::*;
use std::io::{Read, Write};
use std::path::Path;

/// Which architecture's kernel has a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arch {
    Both,
    X86,
    Arm,
}

/// How a key's value reads.
#[derive(Clone, Copy, Debug)]
pub enum Kind {
    /// A number.
    Num,
    /// A number best read in hex.
    Hex,
    /// One of these.
    Enum(&'static [(u64, &'static str)]),
    /// Bits of these.
    Flags(&'static [(u64, &'static str)]),
    /// An MSR of the boot core, valid with this SpecMsrValid bit, whose
    /// bits are these.
    Msr(u64, &'static [(u64, &'static str)]),
}

pub struct Key {
    pub id: u64,
    /// libsel4's name, after seL4_KernelConfig_.
    pub name: &'static str,
    pub group: &'static str,
    pub arch: Arch,
    pub kind: Kind,
}

const fn bits<const N: usize>(names: [(u32, &'static str); N]) -> [(u64, &'static str); N] {
    let mut out = [(0u64, ""); N];
    let mut i = 0;
    while i < N {
        out[i] = (1u64 << names[i].0, names[i].1);
        i += 1;
    }
    out
}

const ARCHS: &[(u64, &str)] = &[(1, "x86_64"), (2, "aarch64")];
const BUILD_FLAGS: &[(u64, &str)] =
    &bits([(0, "debug"), (1, "printing"), (2, "smp"), (3, "hw-debug-api"), (4, "export-pmc-user"), (5, "dangerous-msr")]);
const VIRT_BACKENDS: &[(u64, &str)] = &[(0, "none"), (1, "vt-x"), (2, "amd-v"), (3, "el2-vhe"), (4, "el2-nvhe")];
const VIRT_REJECTS: &[(u64, &str)] = &[
    (0, "none"),
    (1, "no hardware"),
    (2, "disabled by firmware"),
    (3, "missing features"),
    (4, "rejected by the mitigation policy"),
    (5, "skim active"),
    (6, "confidential VM"),
    (7, "vmxon failed"),
    (8, "novirt on the command line"),
    (9, "no vgic"),
    (10, "el1 only"),
];
const VIRT_FEATURES_X86: &[(u64, &str)] =
    &bits([(0, "vpid-single"), (1, "vpid-all"), (2, "invept-single"), (3, "svm-vmcb-clean"), (4, "vmx-perf-global-ctrl")]);
const VIRT_FEATURES_ARM: &[(u64, &str)] = &bits([(0, "virt-ready"), (1, "vmid16"), (2, "gicv2-vgic"), (3, "gicv3-vgic")]);
const CVM_TYPES: &[(u64, &str)] = &[(0, "none"), (1, "sev"), (2, "sev-snp"), (3, "tdx")];
const CVM_FLAGS: &[(u64, &str)] = &bits([(0, "hardened"), (1, "shared-dma")]);
const SPEC_STATUS: &[(u64, &str)] = &[(0, "incomplete"), (1, "complete")];
const SPEC_REJECTS: &[(u64, &str)] = &[
    (0, "none"),
    (1, "vendor"),
    (2, "meltdown"),
    (3, "no smep"),
    (4, "before zen 2"),
    (5, "no ibpb"),
    (6, "srso microcode"),
    (7, "buffer-clearing microcode"),
    (8, "its microcode"),
    (9, "lfence not serializing"),
];
const SPEC_FLAGS: &[(u64, &str)] = &bits([
    (0, "skim"),
    (1, "safe-ret"),
    (2, "retpoline"),
    (3, "eibrs"),
    (4, "auto-ibrs"),
    (5, "legacy-ibrs"),
    (6, "stibp"),
    (7, "bhi-dis-s"),
    (8, "verw-buffers"),
    (9, "no-smt"),
    (10, "disable-tsx"),
    (11, "vmexit-ibpb-deferred"),
    (12, "eager-fpu"),
]);
const SPEC_ACTIONS: &[(u64, &str)] = &bits([(0, "ibpb"), (1, "rsb"), (2, "pbrsb"), (3, "legacy-ibrs"), (4, "bhb"), (5, "ibhf")]);
const SPEC_MSR_VALID: &[(u64, &str)] = &bits([
    (0, "arch-capabilities"),
    (1, "spec-ctrl"),
    (2, "tsx-ctrl"),
    (3, "mcu-opt-ctrl"),
    (4, "efer"),
    (5, "amd-de-cfg"),
    (6, "amd-bp-cfg"),
]);
const ARM_MITIGATIONS: &[(u64, &str)] = &bits([(0, "pan"), (1, "pauth"), (2, "clrbhb")]);
const X86_VENDORS: &[(u64, &str)] = &[(0, "other"), (1, "intel"), (2, "amd"), (3, "hygon")];
const X86_FEATURES: &[(u64, &str)] = &bits([
    (0, "nx"),
    (1, "smep"),
    (2, "smap"),
    (3, "fsgsbase"),
    (4, "1g-pages"),
    (5, "pcid"),
    (6, "invpcid"),
    (7, "x2apic"),
    (8, "tsc-deadline"),
    (9, "idle-poll"),
    (10, "hypervisor"),
]);
const XCR0: &[(u64, &str)] = &bits([
    (0, "x87"),
    (1, "sse"),
    (2, "avx"),
    (3, "bndregs"),
    (4, "bndcsr"),
    (5, "opmask"),
    (6, "zmm-hi256"),
    (7, "hi16-zmm"),
    (9, "pkru"),
    (17, "tilecfg"),
    (18, "tiledata"),
]);
const FPU_INSNS: &[(u64, &str)] = &[(0, "fxsave"), (1, "xsave"), (2, "xsaveopt"), (3, "xsavec"), (4, "xsaves")];
const TSC_SOURCES: &[(u64, &str)] = &[(1, "cpuid"), (2, "hypervisor"), (3, "pit"), (4, "kvm")];
const ARM_PLATFORM_FLAGS: &[(u64, &str)] =
    &bits([(0, "asid16"), (1, "hw-af"), (2, "gicv3-sre"), (3, "its"), (4, "timer-local-ack"), (5, "el2-vhe"), (6, "el2-nvhe")]);
const ARM_PSCI: &[(u64, &str)] = &[(0, "absent"), (1, "smc"), (2, "hvc")];

// The MSRs' bits, as Linux names them.
const ARCH_CAPABILITIES: &[(u64, &str)] = &bits([
    (0, "RDCL_NO"),
    (1, "IBRS_ALL"),
    (2, "RSBA"),
    (3, "SKIP_L1DFL_VMENTRY"),
    (4, "SSB_NO"),
    (5, "MDS_NO"),
    (6, "PSCHANGE_MC_NO"),
    (7, "TSX_CTRL"),
    (8, "TAA_NO"),
    (10, "MISC_PACKAGE_CTRLS"),
    (11, "ENERGY_FILTERING_CTL"),
    (12, "DOITM"),
    (13, "SBDR_SSDP_NO"),
    (14, "FBSDP_NO"),
    (15, "PSDP_NO"),
    (17, "FB_CLEAR"),
    (18, "FB_CLEAR_CTRL"),
    (19, "RRSBA"),
    (20, "BHI_NO"),
    (21, "XAPIC_DISABLE"),
    (23, "OVERCLOCKING_STATUS"),
    (24, "PBRSB_NO"),
    (25, "GDS_CTRL"),
    (26, "GDS_NO"),
    (27, "RFDS_NO"),
    (28, "RFDS_CLEAR"),
    (29, "IGN_UMONITOR"),
    (30, "MON_UMON_MITG"),
    (62, "ITS_NO"),
]);
const SPEC_CTRL: &[(u64, &str)] = &bits([
    (0, "IBRS"),
    (1, "STIBP"),
    (2, "SSBD"),
    (3, "IPRED_DIS_U"),
    (4, "IPRED_DIS_S"),
    (5, "RRSBA_DIS_U"),
    (6, "RRSBA_DIS_S"),
    (7, "PSFD"),
    (8, "DDPD_U"),
    (10, "BHI_DIS_S"),
]);
const TSX_CTRL: &[(u64, &str)] = &bits([(0, "RTM_DISABLE"), (1, "TSX_CPUID_CLEAR")]);
const MCU_OPT_CTRL: &[(u64, &str)] =
    &bits([(0, "RNGDS_MITG_DIS"), (1, "RTM_ALLOW"), (2, "RTM_LOCKED"), (3, "FB_CLEAR_DIS"), (4, "GDS_MITG_DIS"), (5, "GDS_MITG_LOCKED")]);
const EFER: &[(u64, &str)] = &bits([
    (0, "SCE"),
    (8, "LME"),
    (10, "LMA"),
    (11, "NXE"),
    (12, "SVME"),
    (13, "LMSLE"),
    (14, "FFXSR"),
    (15, "TCE"),
    (21, "AUTOIBRS"),
]);
const AMD_DE_CFG: &[(u64, &str)] = &bits([(1, "LFENCE_SERIALIZE"), (9, "ZEN2_FP_BACKUP_FIX")]);
const AMD_BP_CFG: &[(u64, &str)] = &bits([(5, "SHARED_BTB_FIX")]);

const fn key(id: u64, name: &'static str, group: &'static str, arch: Arch, kind: Kind) -> Key {
    Key { id, name, group, arch, kind }
}

use Arch::{Arm, Both, X86};
use Kind::{Enum, Flags, Hex, Msr, Num};

/// Every key, in libsel4's order (by number).
pub const KEYS: &[Key] = &[
    key(0x0001, "Arch", "kernel", Both, Enum(ARCHS)),
    key(0x0002, "BuildFlags", "kernel", Both, Flags(BUILD_FLAGS)),
    key(0x0003, "OnlineCpus", "kernel", Both, Num),
    key(0x0004, "MaxCpus", "kernel", Both, Num),
    key(0x0100, "VirtBackend", "virtualization", Both, Enum(VIRT_BACKENDS)),
    key(0x0101, "VirtReject", "virtualization", Both, Enum(VIRT_REJECTS)),
    // The same bits mean other features on AArch64 (`virt_features`).
    key(0x0102, "VirtFeatures", "virtualization", Both, Flags(VIRT_FEATURES_X86)),
    key(0x0103, "VirtS2IpaBits", "virtualization", Arm, Num),
    key(0x0104, "VirtVgicLrs", "virtualization", Arm, Num),
    key(0x0200, "CvmType", "confidential vm", Both, Enum(CVM_TYPES)),
    key(0x0201, "CvmFlags", "confidential vm", Both, Flags(CVM_FLAGS)),
    key(0x0300, "SpecStatus", "mitigations", X86, Enum(SPEC_STATUS)),
    key(0x0301, "SpecReject", "mitigations", X86, Enum(SPEC_REJECTS)),
    key(0x0302, "SpecFlags", "mitigations", X86, Flags(SPEC_FLAGS)),
    key(0x0303, "SpecEntryActions", "mitigations", X86, Flags(SPEC_ACTIONS)),
    key(0x0304, "SpecVmexitActions", "mitigations", X86, Flags(SPEC_ACTIONS)),
    key(0x0305, "SpecCtrlMsr", "msrs", X86, Msr(1 << 1, SPEC_CTRL)),
    key(0x0306, "SpecTsxCtrlMsr", "msrs", X86, Msr(1 << 2, TSX_CTRL)),
    key(0x0307, "SpecMcuOptCtrlMsr", "msrs", X86, Msr(1 << 3, MCU_OPT_CTRL)),
    key(0x0308, "SpecEferMsr", "msrs", X86, Msr(1 << 4, EFER)),
    key(0x0309, "SpecAmdDeCfgMsr", "msrs", X86, Msr(1 << 5, AMD_DE_CFG)),
    key(0x030a, "SpecAmdBpCfgMsr", "msrs", X86, Msr(1 << 6, AMD_BP_CFG)),
    key(0x030b, "SpecMsrValid", "msrs", X86, Flags(SPEC_MSR_VALID)),
    key(0x0380, "ArmMitigations", "mitigations", Arm, Flags(ARM_MITIGATIONS)),
    key(0x0400, "X86CpuVendor", "cpu", X86, Enum(X86_VENDORS)),
    key(0x0401, "X86CpuFeatures", "cpu", X86, Flags(X86_FEATURES)),
    key(0x0402, "X86FpuXcr0", "cpu", X86, Flags(XCR0)),
    key(0x0403, "X86FpuSaveInsn", "cpu", X86, Enum(FPU_INSNS)),
    key(0x0404, "X86TscMhz", "cpu", X86, Num),
    key(0x0405, "X86TscSource", "cpu", X86, Enum(TSC_SOURCES)),
    key(0x0406, "X86MicrocodeRev", "cpu", X86, Hex),
    key(0x0407, "X86MaxPaddrBits", "cpu", X86, Num),
    key(0x0408, "X86IoapicCount", "cpu", X86, Num),
    key(0x0409, "X86ArchCapabilities", "msrs", X86, Msr(1 << 0, ARCH_CAPABILITIES)),
    key(0x0480, "ArmPlatformFlags", "cpu", Arm, Flags(ARM_PLATFORM_FLAGS)),
    key(0x0481, "ArmPaBits", "cpu", Arm, Num),
    key(0x0482, "ArmGicVersion", "cpu", Arm, Num),
    key(0x0483, "ArmMaxSpi", "cpu", Arm, Num),
    key(0x0484, "ArmPsciMethod", "cpu", Arm, Enum(ARM_PSCI)),
    key(0x0485, "ArmTimerFreqHz", "cpu", Arm, Num),
];

/// Groups, in the order they are shown.
const GROUPS: &[&str] = &["kernel", "virtualization", "confidential vm", "mitigations", "cpu", "msrs"];

/// The key named `s`: its libsel4 name (any case, with or without
/// seL4_KernelConfig_), or a number (hex with 0x, or decimal), which need
/// not be one we know.
pub fn parse_key(s: &str) -> Result<u64> {
    let bare = s.strip_prefix("seL4_KernelConfig_").unwrap_or(s);
    if let Some(k) = KEYS.iter().find(|k| k.name.eq_ignore_ascii_case(bare)) {
        return Ok(k.id);
    }
    let n = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) => u64::from_str_radix(h, 16),
        None => s.parse(),
    };
    n.map_err(|_| Error(format!("unknown kernel configuration key: {s}")))
}

pub fn find(id: u64) -> Option<&'static Key> {
    KEYS.iter().find(|k| k.id == id)
}

/// `table`'s names of the bits of `v`, with bitN for the rest.
fn flag_names(table: &[(u64, &str)], v: u64) -> Vec<String> {
    let mut out: Vec<String> = table.iter().filter(|&&(b, _)| v & b != 0).map(|&(_, n)| n.to_string()).collect();
    let known = table.iter().fold(0, |a, &(b, _)| a | b);
    out.extend((0..64).filter(|i| v & !known & (1 << i) != 0).map(|i| format!("bit{i}")));
    out
}

fn enum_name(table: &[(u64, &str)], v: u64) -> String {
    table.iter().find(|&&(n, _)| n == v).map_or_else(|| format!("unknown ({v})"), |&(_, n)| n.to_string())
}

/// The kernel's answers: (key, value) for each it has.
pub type Answers = Vec<(u64, u64)>;

/// What a key's value says, for people: `answers` for what decides it
/// (the architecture, which MSRs are valid).
pub fn describe(k: &Key, v: u64, answers: &Answers) -> String {
    let get = |id: u64| answers.iter().find(|a| a.0 == id).map(|a| a.1);
    let flags = |table: &[(u64, &str)], v: u64| {
        let names = flag_names(table, v);
        if names.is_empty() { format!("{v:#x}") } else { format!("{v:#x} ({})", names.join(", ")) }
    };
    match k.kind {
        Num => v.to_string(),
        Hex => format!("{v:#x}"),
        Enum(t) => enum_name(t, v),
        Flags(_) if k.id == 0x0102 && get(0x0001) == Some(2) => flags(VIRT_FEATURES_ARM, v),
        Flags(t) => flags(t, v),
        Msr(bit, _) if get(0x030b).is_some_and(|valid| valid & bit == 0) => "not read".into(),
        Msr(_, t) => flags(t, v),
    }
}

/// A JSON string (the names and descriptions are ours: no control
/// characters).
fn js(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// One key's JSON object.
pub fn json_key(id: u64, v: u64, answers: &Answers) -> String {
    let Some(k) = find(id) else {
        return format!("{{\"key\":\"{id:#06x}\",\"value\":{v},\"hex\":\"{v:#x}\"}}");
    };
    let get = |id: u64| answers.iter().find(|a| a.0 == id).map(|a| a.1);
    let mut o = format!("{{\"key\":\"{id:#06x}\",\"name\":{},\"group\":{},\"value\":{v},\"hex\":\"{v:#x}\"", js(k.name), js(k.group));
    let list = |names: Vec<String>| format!("[{}]", names.iter().map(|n| js(n)).collect::<Vec<_>>().join(","));
    match k.kind {
        Num | Hex => {}
        Enum(t) => o += &format!(",\"decoded\":{}", js(&enum_name(t, v))),
        Flags(_) if k.id == 0x0102 && get(0x0001) == Some(2) => o += &format!(",\"flags\":{}", list(flag_names(VIRT_FEATURES_ARM, v))),
        Flags(t) => o += &format!(",\"flags\":{}", list(flag_names(t, v))),
        Msr(bit, t) => {
            let read = get(0x030b).is_none_or(|valid| valid & bit != 0);
            o += &format!(",\"read\":{read},\"flags\":{}", list(if read { flag_names(t, v) } else { Vec::new() }));
        }
    }
    o + "}"
}

/// Every answer as people read it, by group.
pub fn render(answers: &Answers) -> String {
    let mut out = String::new();
    for g in GROUPS {
        let rows: Vec<_> = KEYS.iter().filter(|k| k.group == *g).filter_map(|k| answers.iter().find(|a| a.0 == k.id).map(|a| (k, a.1))).collect();
        if rows.is_empty() {
            continue;
        }
        out += &format!("{g}:\n");
        for (k, v) in rows {
            out += &format!("  {:<20} {}\n", k.name, describe(k, v, answers));
        }
    }
    out
}

/// Every answer as JSON.
pub fn render_json(answers: &Answers) -> String {
    let rows: Vec<String> = answers.iter().map(|&(id, v)| json_key(id, v, answers)).collect();
    format!("[{}]", rows.join(","))
}

/// The two lines `l4hctl info` adds: the virtualization backend (or why
/// there is none) and the mitigations, from what the kernel says.
pub fn summary(answers: &Answers) -> Vec<String> {
    let get = |id: u64| answers.iter().find(|a| a.0 == id).map(|a| a.1);
    let mut out = Vec::new();
    if let Some(b) = get(0x0100) {
        let mut s = enum_name(VIRT_BACKENDS, b);
        if let (0, Some(r)) = (b, get(0x0101)) {
            s += &format!(" ({})", enum_name(VIRT_REJECTS, r));
        }
        out.push(format!("virt:   {s}"));
    }
    if let Some(st) = get(0x0300) {
        let mut s = enum_name(SPEC_STATUS, st);
        if let (0, Some(r)) = (st, get(0x0301)) {
            s += &format!(" ({})", enum_name(SPEC_REJECTS, r));
        }
        if let Some(f) = get(0x0302) {
            let names = flag_names(SPEC_FLAGS, f);
            if !names.is_empty() {
                s += &format!(", {}", names.join(","));
            }
        }
        out.push(format!("spec:   {s}"));
    } else if let Some(m) = get(0x0380) {
        let names = flag_names(ARM_MITIGATIONS, m);
        out.push(format!("spec:   {}", if names.is_empty() { "none".into() } else { names.join(",") }));
    }
    out
}

const DRIVER: &str = "/dev/l4h-kconfig";
const PORT_NAME: &str = "l4h.kconfig";
const PORT_MAGIC: u32 = 0x4b48_344c;
const ENOENT: i32 = 2;
const ENOSYS: i32 = 38;

#[repr(C)]
struct Ioc {
    key: u64,
    value: u64,
}

// _IOWR('L', 3, struct l4h_kconfig_ioc)
const IOC: u64 = (3 << 30) | ((std::mem::size_of::<Ioc>() as u64) << 16) | ((b'L' as u64) << 8) | 3;

/// One request on the port `f`: the value, or the errno it is answered.
fn port_get(f: &mut (impl Read + Write), key: u64) -> io::Result<u64> {
    let mut req = [0u8; 16];
    req[0..4].copy_from_slice(&PORT_MAGIC.to_le_bytes());
    req[8..16].copy_from_slice(&key.to_le_bytes());
    // One write: a request is not interleaved with another's.
    f.write_all(&req)?;
    let mut resp = [0u8; 24];
    f.read_exact(&mut resp)?;
    if u32::from_le_bytes(resp[0..4].try_into().unwrap()) != PORT_MAGIC {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "kernel configuration port: not an answer"));
    }
    match i32::from_le_bytes(resp[4..8].try_into().unwrap()) {
        0 => Ok(u64::from_le_bytes(resp[8..16].try_into().unwrap())),
        s if (-4095..0).contains(&s) => Err(io::Error::from_raw_os_error(-s)),
        _ => Err(io::Error::from_raw_os_error(5)),
    }
}

/// How the guest asks: its kernel's driver, or an HVM guest's port.
pub enum Dev {
    Driver(File),
    Port(File),
}

impl Dev {
    /// The driver where the guest's kernel has it, else the port (whose
    /// one opener at a time another l4hctl may be: it is waited for).
    pub fn open() -> Result<Dev> {
        match File::open(DRIVER) {
            Ok(f) => return Ok(Dev::Driver(f)),
            Err(e) if e.kind() != io::ErrorKind::NotFound => return err(format!("{DRIVER}: {e}")),
            Err(_) => {}
        }
        let Some(path) = attest::find_port(Path::new("/sys/class/virtio-ports"), Path::new("/dev"), PORT_NAME) else {
            return err(format!("{DRIVER}: not found, and no kernel configuration port (not an l4h guest?)"));
        };
        let start = std::time::Instant::now();
        loop {
            match File::options().read(true).write(true).open(&path) {
                Ok(f) => return Ok(Dev::Port(f)),
                // EBUSY: open elsewhere, for a moment.
                Err(e) if e.raw_os_error() == Some(16) && start.elapsed() < PORT_WAIT => std::thread::sleep(std::time::Duration::from_millis(20)),
                Err(e) => return err(format!("kernel configuration port ({}): {e}", path.display())),
            }
        }
    }

    /// The kernel's value of `key`: None for a key it does not know.
    pub fn get(&mut self, key: u64) -> Result<Option<u64>> {
        let r = match self {
            Dev::Port(f) => port_get(f, key),
            Dev::Driver(f) => {
                let mut c = Ioc { key, value: 0 };
                if unsafe { ioctl(f.as_raw_fd(), IOC, &mut c as *mut Ioc) } < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(c.value)
                }
            }
        };
        match r {
            Ok(v) => Ok(Some(v)),
            Err(e) => match e.raw_os_error() {
                Some(ENOENT) => Ok(None),
                Some(ENOSYS) => err("the host's kernel does not say its configuration (seL4: FL4 alone has seL4_KernelConfig)"),
                _ => err(format!("kernel configuration key {key:#06x}: {e}")),
            },
        }
    }

    /// Every key the kernel has.
    pub fn all(&mut self) -> Result<Answers> {
        let mut out = Vec::new();
        for k in KEYS {
            if let Some(v) = self.get(k.id)? {
                out.push((k.id, v));
            }
        }
        Ok(out)
    }
}

/// How long another's use of the port is waited for: its answers are
/// immediate.
const PORT_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

#[cfg(test)]
mod tests {
    use super::*;

    /// The host's end of a kernel configuration port: answers each
    /// request from `keys`.
    struct Host {
        keys: Vec<(u64, u64)>,
        status: Option<i32>,
        asked: Vec<u64>,
        answer: Vec<u8>,
    }

    impl Write for Host {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            assert_eq!(b.len(), 16, "one whole request a write");
            assert_eq!((u32::from_le_bytes(b[0..4].try_into().unwrap()), &b[4..8]), (PORT_MAGIC, &[0u8; 4][..]));
            let key = u64::from_le_bytes(b[8..16].try_into().unwrap());
            self.asked.push(key);
            let (status, value) = match (self.status, self.keys.iter().find(|k| k.0 == key)) {
                (Some(s), _) => (s, 0),
                (None, Some(&(_, v))) => (0, v),
                (None, None) => (-2, 0),
            };
            self.answer.extend_from_slice(&PORT_MAGIC.to_le_bytes());
            self.answer.extend_from_slice(&status.to_le_bytes());
            self.answer.extend_from_slice(&value.to_le_bytes());
            self.answer.extend_from_slice(&[0; 8]);
            Ok(16)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Read for Host {
        // A few bytes at a time, as a port may give them.
        fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
            let n = b.len().min(self.answer.len()).min(5);
            b[..n].copy_from_slice(&self.answer[..n]);
            self.answer.drain(..n);
            Ok(n)
        }
    }

    fn host(keys: &[(u64, u64)]) -> Host {
        Host { keys: keys.to_vec(), status: None, asked: Vec::new(), answer: Vec::new() }
    }

    #[test]
    fn keys_are_libsel4s() {
        assert_eq!(KEYS.len(), 40);
        // In order, each once, every group shown.
        assert!(KEYS.windows(2).all(|w| w[0].id < w[1].id));
        assert!(KEYS.iter().all(|k| GROUPS.contains(&k.group)));
        assert_eq!(parse_key("X86ArchCapabilities").unwrap(), 0x0409);
        assert_eq!(parse_key("seL4_KernelConfig_VirtBackend").unwrap(), 0x0100);
        assert_eq!(parse_key("virtbackend").unwrap(), 0x0100);
        assert_eq!(parse_key("0x030b").unwrap(), 0x030b);
        assert_eq!(parse_key("0X10").unwrap(), 0x10);
        assert_eq!(parse_key("3").unwrap(), 3);
        assert!(parse_key("Nonesuch").is_err());
        assert!(parse_key("0xzz").is_err());
        // The MSRs' valid bits are SpecMsrValid's.
        let valid = |name| match find(parse_key(name).unwrap()).unwrap().kind {
            Msr(bit, _) => bit,
            _ => 0,
        };
        assert_eq!(
            ["X86ArchCapabilities", "SpecCtrlMsr", "SpecTsxCtrlMsr", "SpecMcuOptCtrlMsr", "SpecEferMsr", "SpecAmdDeCfgMsr", "SpecAmdBpCfgMsr"].map(valid),
            [1, 2, 4, 8, 16, 32, 64]
        );
    }

    #[test]
    fn values_as_people_read_them() {
        let answers: Answers = vec![(0x0001, 1), (0x030b, 0b1_0011), (0x0100, 0), (0x0101, 3)];
        let d = |id: u64, v: u64| describe(find(id).unwrap(), v, &answers);
        assert_eq!(d(0x0001, 1), "x86_64");
        assert_eq!(d(0x0001, 9), "unknown (9)");
        assert_eq!(d(0x0002, 6), "0x6 (printing, smp)");
        assert_eq!(d(0x0002, 0), "0x0");
        assert_eq!(d(0x0003, 8), "8");
        assert_eq!(d(0x0406, 0xb000_0040), "0xb0000040");
        assert_eq!(d(0x0302, (1 << 3) | (1 << 40)), "0x10000000008 (eibrs, bit40)");
        assert_eq!(d(0x0409, 0x0f3e_fdeb).split_once(' ').unwrap().0, "0xf3efdeb");
        assert!(d(0x0409, 0x0f3e_fdeb).contains("RDCL_NO, IBRS_ALL, SKIP_L1DFL_VMENTRY"));
        assert!(d(0x0409, 1 << 62).contains("ITS_NO"));
        // An MSR the kernel did not read.
        assert_eq!(d(0x0306, 0), "not read");
        assert_eq!(d(0x0308, 0xd01), "0xd01 (SCE, LME, LMA, NXE)");
        // VirtFeatures by the architecture.
        assert_eq!(d(0x0102, 3), "0x3 (vpid-single, vpid-all)");
        let arm: Answers = vec![(0x0001, 2)];
        assert_eq!(describe(find(0x0102).unwrap(), 3, &arm), "0x3 (virt-ready, vmid16)");
    }

    #[test]
    fn grouped_and_json() {
        let answers: Answers = vec![(0x0001, 1), (0x0100, 1), (0x0101, 0), (0x0300, 1), (0x0302, 0x8), (0x030b, 0b1_0001), (0x0306, 0), (0x0409, 3)];
        let text = render(&answers);
        assert_eq!(text.lines().next(), Some("kernel:"));
        assert!(text.contains("virtualization:\n  VirtBackend          vt-x\n"));
        assert!(text.contains("  SpecTsxCtrlMsr       not read\n"));
        assert!(text.contains("  X86ArchCapabilities  0x3 (RDCL_NO, IBRS_ALL)\n"));
        assert!(!text.contains("confidential vm"), "no group without answers");
        let json = render_json(&answers);
        assert!(json.starts_with("[{\"key\":\"0x0001\",\"name\":\"Arch\",\"group\":\"kernel\",\"value\":1,\"hex\":\"0x1\",\"decoded\":\"x86_64\"}"));
        assert!(json.contains("{\"key\":\"0x0306\",\"name\":\"SpecTsxCtrlMsr\",\"group\":\"msrs\",\"value\":0,\"hex\":\"0x0\",\"read\":false,\"flags\":[]}"));
        assert!(json.contains("\"name\":\"X86ArchCapabilities\",\"group\":\"msrs\",\"value\":3,\"hex\":\"0x3\",\"read\":true,\"flags\":[\"RDCL_NO\",\"IBRS_ALL\"]}"));
        assert!(json.contains("\"name\":\"SpecFlags\",\"group\":\"mitigations\",\"value\":8,\"hex\":\"0x8\",\"flags\":[\"eibrs\"]}"));
        assert!(json.ends_with("}]"));
        // A key we do not know (a newer kernel's), asked by number.
        assert_eq!(json_key(0x0500, 7, &answers), "{\"key\":\"0x0500\",\"value\":7,\"hex\":\"0x7\"}");
        // MSR values past 2^53 are in hex too.
        assert!(json_key(0x0409, u64::MAX, &answers).contains("\"hex\":\"0xffffffffffffffff\""));
    }

    #[test]
    fn the_info_summary() {
        let x86: Answers = vec![(0x0100, 0), (0x0101, 4), (0x0300, 0), (0x0301, 6), (0x0302, (1 << 1) | (1 << 2))];
        assert_eq!(summary(&x86), ["virt:   none (rejected by the mitigation policy)", "spec:   incomplete (srso microcode), safe-ret,retpoline"]);
        let ok: Answers = vec![(0x0100, 2), (0x0101, 0), (0x0300, 1), (0x0302, 0)];
        assert_eq!(summary(&ok), ["virt:   amd-v", "spec:   complete"]);
        let arm: Answers = vec![(0x0100, 3), (0x0380, 3)];
        assert_eq!(summary(&arm), ["virt:   el2-vhe", "spec:   pan,pauth"]);
        assert!(summary(&Vec::new()).is_empty());
    }

    #[test]
    fn the_port() {
        let mut h = host(&[(0x0001, 2), (0x0409, u64::MAX)]);
        assert_eq!(port_get(&mut h, 0x0001).unwrap(), 2);
        assert_eq!(port_get(&mut h, 0x0409).unwrap(), u64::MAX);
        assert_eq!(port_get(&mut h, 0x0300).unwrap_err().raw_os_error(), Some(ENOENT));
        assert_eq!(h.asked, [0x0001, 0x0409, 0x0300]);
        // The host's errno, as the driver gives one; no errno is EIO.
        let mut h = host(&[]);
        h.status = Some(-38);
        assert_eq!(port_get(&mut h, 1).unwrap_err().raw_os_error(), Some(ENOSYS));
        h.status = Some(7);
        assert_eq!(port_get(&mut h, 1).unwrap_err().raw_os_error(), Some(5));
        // What is not an answer.
        let mut h = host(&[]);
        h.answer = vec![0; 24];
        h.status = Some(0);
        assert!(port_get(&mut h, 1).is_err());
    }
}

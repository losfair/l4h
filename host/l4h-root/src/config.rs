//! Host and dom0 settings.  The defaults are fixed when root is built
//! ($L4H_* variables); the `l4h-config` boot module, a file of `key=value`
//! lines on the EFI system partition, overrides them at boot (DESIGN.md
//! §10).  GRUB sources the same file, so it is also valid GRUB script: no
//! spaces around `=`, and values with spaces in double quotes.


/// A decimal number, or hexadecimal after "0x".
const fn try_parse_usize(s: &str) -> Option<usize> {
    let b = s.as_bytes();
    let (mut i, radix) = if b.len() > 2 && b[0] == b'0' && b[1] == b'x' { (2, 16) } else { (0, 10) };
    if i == b.len() {
        return None;
    }
    let mut v: usize = 0;
    while i < b.len() {
        let d = match b[i] {
            b'0'..=b'9' => b[i] - b'0',
            b'a'..=b'f' => b[i] - b'a' + 10,
            b'A'..=b'F' => b[i] - b'A' + 10,
            _ => return None,
        };
        if d as usize >= radix {
            return None;
        }
        v = match v.checked_mul(radix) {
            Some(v) => v,
            None => return None,
        };
        v = match v.checked_add(d as usize) {
            Some(v) => v,
            None => return None,
        };
        i += 1;
    }
    Some(v)
}

/// A PCI address "bus:device.function" (hexadecimal) as bus << 8 |
/// device << 3 | function.
const fn try_parse_bdf(s: &str) -> Option<u32> {
    let b = s.as_bytes();
    let mut v = [0u32; 3];
    let mut digits = [0usize; 3];
    let (mut i, mut f) = (0, 0);
    while i < b.len() {
        match b[i] {
            b':' if f == 0 => f = 1,
            b'.' if f == 1 => f = 2,
            c => {
                let d = match c {
                    b'0'..=b'9' => c - b'0',
                    b'a'..=b'f' => c - b'a' + 10,
                    b'A'..=b'F' => c - b'A' + 10,
                    _ => return None,
                };
                if digits[f] == 2 {
                    return None;
                }
                v[f] = v[f] * 16 + d as u32;
                digits[f] += 1;
            }
        }
        i += 1;
    }
    if f != 2 || digits[0] == 0 || digits[1] == 0 || digits[2] != 1 {
        return None;
    }
    if v[1] > 31 || v[2] > 7 {
        return None;
    }
    Some(v[0] << 8 | v[1] << 3 | v[2])
}

const fn parse_usize(s: Option<&str>, default: usize) -> usize {
    match s {
        None => default,
        Some(s) => match try_parse_usize(s) {
            Some(v) => v,
            None => panic!("not a number"),
        },
    }
}

const fn parse_bdf(s: Option<&str>) -> Option<u32> {
    match s {
        None => None,
        Some(s) => match try_parse_bdf(s) {
            Some(v) => Some(v),
            None => panic!("not a PCI address"),
        },
    }
}

pub struct Config {
    pub dom0_mem_mb: usize,
    pub dom0_vcpus: usize,
    /// dom0's I/O pool (a power of two, 1-256 MiB); 0, the default: room
    /// for full receive rings on its vNICs (host::iopool::for_nics), at
    /// least 4 MiB.
    pub dom0_io_pool_mb: usize,
    /// Disks passed to dom0 at boot (the first n); the rest are free for
    /// the control API.
    pub dom0_disks: usize,
    /// Of host disk 0 (the boot disk), dom0 gets only the first n MiB; the
    /// rest is free for the control API, as windows (§8.2).  0, or more than
    /// the disk: all of it.
    pub dom0_disk0_mb: usize,
    /// vNICs of dom0 on switch 0, which has the first NIC as its uplink.
    pub dom0_nics: usize,
    /// Internal switches, after switch 0 and the second uplink's (1..=n, or
    /// 2..=n+1), created at first boot, each with one more vNIC of dom0 (a
    /// normal port, for routing between it and isolated guests).
    pub dom0_internal_switches: usize,
    /// dom0's kernel command line.
    pub dom0_cmdline: &'static str,
    /// The PCI address (bus:dev.fn) of the uplink NIC, when it is not the
    /// first NIC: e.g. the public port of a two-port card.
    pub uplink_nic: Option<u32>,
    /// The PCI address of a second uplink NIC: the uplink of switch 1,
    /// where dom0 has one more vNIC, with the NIC's MAC address; the
    /// internal switches follow. E.g. a provider's storage network on the
    /// other port.
    pub uplink2_nic: Option<u32>,
    /// The PCI address of the boot disk's controller, when it is not the
    /// first disk controller: it becomes host disk 0.
    pub boot_disk: Option<u32>,
    /// The serial monitor's port and IRQ (x86).
    pub serial_port: u16,
    pub serial_irq: u64,
    /// The kernel copies its console to the lower half of the screen.
    pub fb_console: bool,
    /// Seconds between watchdog dumps of guest vCPU state; 0 disables.
    pub watchdog_secs: usize,
    /// Confine devices with the platform IOMMU, if there is one (§8.5).
    pub iommu: bool,
    /// With it, remap their interrupts too.
    pub iommu_intremap: bool,
}

impl Config {
    /// The settings built in, overridden by `text` (the `l4h-config`
    /// module).  Bad lines are reported and ignored.
    pub fn new(text: Option<&'static [u8]>) -> Self {
        let mut c = Config {
            dom0_mem_mb: parse_usize(option_env!("L4H_DOM0_MEM_MB"), 256),
            dom0_vcpus: parse_usize(option_env!("L4H_DOM0_VCPUS"), 1),
            dom0_io_pool_mb: parse_usize(option_env!("L4H_DOM0_IO_POOL_MB"), 0),
            dom0_disks: parse_usize(option_env!("L4H_DOM0_DISKS"), 64),
            dom0_disk0_mb: parse_usize(option_env!("L4H_DOM0_DISK0_MB"), 0),
            dom0_nics: parse_usize(option_env!("L4H_DOM0_NICS"), 1),
            dom0_internal_switches: parse_usize(option_env!("L4H_DOM0_INTERNAL_SWITCHES"), 0),
            dom0_cmdline: option_env!("L4H_DOM0_CMDLINE").unwrap_or("console=hvc0"),
            uplink_nic: parse_bdf(option_env!("L4H_UPLINK_NIC")),
            uplink2_nic: parse_bdf(option_env!("L4H_UPLINK2_NIC")),
            boot_disk: parse_bdf(option_env!("L4H_BOOT_DISK")),
            serial_port: parse_usize(option_env!("L4H_SERIAL_PORT"), 0x3f8) as u16,
            serial_irq: parse_usize(option_env!("L4H_SERIAL_IRQ"), 4) as u64,
            fb_console: parse_usize(option_env!("L4H_FB_CONSOLE"), 0) != 0,
            watchdog_secs: parse_usize(option_env!("L4H_WATCHDOG_SECS"), 0),
            iommu: parse_usize(option_env!("L4H_IOMMU"), 1) != 0,
            iommu_intremap: parse_usize(option_env!("L4H_IOMMU_INTREMAP"), 1) != 0,
        };
        let Some(text) = text else { return c };
        let Ok(text) = core::str::from_utf8(text) else {
            log!("l4h-root: config: not UTF-8, ignored");
            return c;
        };
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let ok = match line.split_once('=') {
                Some((key, value)) => c.set(key.trim(), unquote(value.trim())),
                None => false,
            };
            if !ok {
                log!("l4h-root: config line {}: '{}' ignored", n + 1, line);
            }
        }
        c
    }

    fn set(&mut self, key: &str, value: &'static str) -> bool {
        let num = |v: &mut usize| try_parse_usize(value).map(|n| *v = n).is_some();
        let bdf = |v: &mut Option<u32>| try_parse_bdf(value).map(|n| *v = Some(n)).is_some();
        let flag = |v: &mut bool| match value {
            "0" | "1" => {
                *v = value == "1";
                true
            }
            _ => false,
        };
        match key {
            "dom0_mem_mb" => num(&mut self.dom0_mem_mb),
            "dom0_vcpus" => num(&mut self.dom0_vcpus),
            "dom0_io_pool_mb" => num(&mut self.dom0_io_pool_mb),
            "dom0_disks" => num(&mut self.dom0_disks),
            "dom0_disk0_mb" => num(&mut self.dom0_disk0_mb),
            "dom0_nics" => num(&mut self.dom0_nics),
            "dom0_internal_switches" => num(&mut self.dom0_internal_switches),
            "dom0_cmdline" => {
                self.dom0_cmdline = value;
                true
            }
            "uplink_nic" => bdf(&mut self.uplink_nic),
            "uplink2_nic" => bdf(&mut self.uplink2_nic),
            "boot_disk" => bdf(&mut self.boot_disk),
            "serial_port" => match try_parse_usize(value) {
                Some(p) if p <= 0xfff8 => {
                    self.serial_port = p as u16;
                    true
                }
                _ => false,
            },
            "serial_irq" => match try_parse_usize(value) {
                Some(irq) if irq < 24 => {
                    self.serial_irq = irq as u64;
                    true
                }
                _ => false,
            },
            "fb_console" => flag(&mut self.fb_console),
            "iommu" => flag(&mut self.iommu),
            "iommu_intremap" => flag(&mut self.iommu_intremap),
            "watchdog_secs" => num(&mut self.watchdog_secs),
            _ => false,
        }
    }
}

/// Values GRUB itself uses from l4h.conf. Kexec accepts any literal
/// key=value assignment except a GRUB control variable, which could change
/// the boot root is reproducing.
pub struct KexecOverrides<'a> {
    pub serial_port: Option<&'a str>,
    pub fb_console: Option<&'a str>,
}

pub fn kexec_overrides(text: Option<&[u8]>) -> Result<KexecOverrides<'_>, &'static str> {
    let mut out = KexecOverrides { serial_port: None, fb_console: None };
    let Some(text) = text else { return Ok(out) };
    let text = core::str::from_utf8(text).map_err(|_| "l4h.conf is not UTF-8")?;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line.split_once('=').ok_or("l4h.conf is not limited to key=value lines")?;
        if key != key.trim() || value != value.trim() {
            return Err("l4h.conf has a setting kexec cannot reproduce");
        }
        if value.bytes().any(|b| matches!(b, 0 | b'$' | b'`' | b'\\' | b';' | b'&' | b'|' | b'<' | b'>')) {
            return Err("l4h.conf has shell syntax kexec cannot reproduce");
        }
        let value = kexec_value(value)?;
        if !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') || !key.bytes().next().is_some_and(|b| b.is_ascii_alphabetic() || b == b'_') {
            return Err("l4h.conf has a setting kexec cannot reproduce");
        }
        if matches!(key, "esp" | "fbcon" | "root" | "prefix" | "cmdpath" | "timeout" | "default" | "fallback" | "next_entry" | "check_signatures" | "debug" | "pager") {
            return Err("l4h.conf assigns a GRUB control variable");
        }
        match key {
            "serial_port" => out.serial_port = Some(value),
            "fb_console" => out.fb_console = Some(value),
            _ => {}
        }
    }
    Ok(out)
}

/// A kexec value is one literal word or one quoted string. Unquoted
/// whitespace and unmatched or embedded quotes are not literal config.
fn kexec_value(v: &str) -> Result<&str, &'static str> {
    if !v.is_empty() && (v.starts_with('"') || v.starts_with('\'')) {
        let q = v.as_bytes()[0];
        if v.len() < 2 || v.as_bytes()[v.len() - 1] != q || v.as_bytes()[1..v.len() - 1].contains(&q) {
            return Err("l4h.conf has shell syntax kexec cannot reproduce");
        }
        Ok(&v[1..v.len() - 1])
    } else {
        if v.bytes().any(|b| b.is_ascii_whitespace() || b == b'"' || b == b'\'') {
            return Err("l4h.conf has shell syntax kexec cannot reproduce");
        }
        Ok(v)
    }
}

/// The value without one pair of surrounding quotes.
fn unquote(v: &str) -> &str {
    for q in ['"', '\''] {
        if let Some(inner) = v.strip_prefix(q).and_then(|v| v.strip_suffix(q)) {
            return inner;
        }
    }
    v
}

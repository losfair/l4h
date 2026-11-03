//! `l4hctl mk-check [l4h-mk.conf]`: check a multikernel split against this
//! machine before rebooting into it (DESIGN.md §11.4), from native Linux:
//! the same rules as l4h-mkshim's (boot/l4h-mkshim/src/main.rs), over the
//! ACPI tables and PCI functions Linux shows.  The shim checks again at
//! boot, with the firmware's memory map.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use l4hctl::{Error, Result};

const MAX_PARTITIONS: usize = 8;

#[derive(Clone, Default)]
struct Part {
    cpus: Option<String>,
    mem: Option<u64>,
    pci: Vec<u16>,
}

struct Cpu {
    apic: u32,
    node: u32,
}

struct Func {
    bdf: u16,
    vendor: u16,
    device: u16,
    class: u32,
    bridge: bool,
}

impl Func {
    fn is_disk(&self) -> bool {
        // Match the shim: GCE's legacy virtio-scsi reports class 0.
        self.class >> 16 == 0x01 || (self.vendor == 0x1af4 && matches!(self.device, 0x1001 | 0x1004 | 0x1042 | 0x1048))
    }
}

fn fail<T>(msg: String) -> Result<T> {
    Err(Error(msg))
}

fn bdf(s: &str) -> Option<u16> {
    let s = s.trim();
    let s = if s.matches(':').count() == 2 { s.split_once(':')?.1 } else { s };
    let (bus, rest) = s.split_once(':')?;
    let (dev, func) = rest.split_once('.')?;
    let (bus, dev, func) = (u16::from_str_radix(bus, 16).ok()?, u16::from_str_radix(dev, 16).ok()?, u16::from_str_radix(func, 16).ok()?);
    (bus < 256 && dev < 32 && func < 8).then_some(bus << 8 | dev << 3 | func)
}

fn fmt_bdf(b: u16) -> String {
    format!("0000:{:02x}:{:02x}.{}", b >> 8, (b >> 3) & 0x1f, b & 7)
}

fn size(v: &str) -> Option<u64> {
    let v = v.trim();
    let (num, shift) = match v.chars().last()? {
        'G' | 'g' => (&v[..v.len() - 1], 30),
        'M' | 'm' => (&v[..v.len() - 1], 20),
        'T' | 't' => (&v[..v.len() - 1], 40),
        _ => (v, 0),
    };
    num.trim().parse::<u64>().ok().map(|n| n << shift)
}

fn parse(text: &str) -> Result<(usize, Vec<Part>, Vec<(usize, usize, bool)>)> {
    let mut n = 1;
    let mut parts = vec![Part::default(); MAX_PARTITIONS];
    let mut links = Vec::new();
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let bad = || Error(format!("l4h-mk.conf: cannot use '{line}'"));
        let (key, value) = line.split_once('=').ok_or_else(bad)?;
        let (key, value) = (key.trim(), value.trim());
        let index = |p: &str| p.strip_prefix('p').and_then(|n| n.parse::<usize>().ok()).filter(|&n| n < MAX_PARTITIONS);
        if key == "partitions" {
            n = value.parse().ok().filter(|n| (1..=MAX_PARTITIONS).contains(n)).ok_or_else(bad)?;
        } else if let Some(l) = key.strip_prefix("link.") {
            let (a, b) = l.split_once('-').ok_or_else(bad)?;
            let (a, b) = (index(a).ok_or_else(bad)?, index(b).ok_or_else(bad)?);
            if a == b {
                return Err(bad());
            }
            match value {
                "1" => links.push((a.min(b), a.max(b), false)),
                "uplink" => links.push((a.min(b), a.max(b), true)),
                "0" => {}
                _ => return Err(bad()),
            }
        } else {
            let (p, field) = key.split_once('.').ok_or_else(bad)?;
            let part = &mut parts[index(p).ok_or_else(bad)?];
            match field {
                "cpus" => part.cpus = Some(value.to_string()),
                "mem" => part.mem = Some(size(value).ok_or_else(bad)?),
                "pci" => {
                    for b in value.split(',').filter(|s| !s.trim().is_empty()) {
                        part.pci.push(bdf(b).ok_or_else(bad)?);
                    }
                }
                _ => return Err(bad()),
            }
        }
    }
    parts.truncate(n);
    Ok((n, parts, links))
}

/// The enabled CPUs in MADT order (the first is the boot CPU), with their
/// SRAT nodes.
fn cpus(root: &Path) -> Result<Vec<Cpu>> {
    let madt = fs::read(root.join("sys/firmware/acpi/tables/APIC")).map_err(|e| Error(format!("ACPI MADT: {e}")))?;
    let u32_at = |b: &[u8], i: usize| u32::from_le_bytes(b[i..i + 4].try_into().unwrap());
    let mut out = Vec::new();
    let mut off = 44;
    while off + 2 <= madt.len() {
        let (ty, len) = (madt[off], madt[off + 1] as usize);
        if len < 2 || off + len > madt.len() {
            break;
        }
        let e = &madt[off..off + len];
        match ty {
            0 if len >= 8 && u32_at(e, 4) & 1 != 0 => out.push(Cpu { apic: e[3] as u32, node: 0 }),
            9 if len >= 16 && u32_at(e, 8) & 1 != 0 => out.push(Cpu { apic: u32_at(e, 4), node: 0 }),
            _ => {}
        }
        off += len;
    }
    if let Ok(srat) = fs::read(root.join("sys/firmware/acpi/tables/SRAT")) {
        let mut off = 48;
        while off + 2 <= srat.len() {
            let (ty, len) = (srat[off], srat[off + 1] as usize);
            if len < 2 || off + len > srat.len() {
                break;
            }
            let e = &srat[off..off + len];
            let entry = match ty {
                0 if len >= 16 && u32_at(e, 4) & 1 != 0 => Some((e[3] as u32, e[2] as u32 | (e[9] as u32) << 8 | (e[10] as u32) << 16 | (e[11] as u32) << 24)),
                2 if len >= 24 && u32_at(e, 12) & 1 != 0 => Some((u32_at(e, 8), u32_at(e, 4))),
                _ => None,
            };
            if let Some((apic, node)) = entry {
                out.iter_mut().filter(|c| c.apic == apic).for_each(|c| c.node = node);
            }
            off += len;
        }
    }
    Ok(out)
}

fn funcs(root: &Path) -> Result<Vec<Func>> {
    let mut out = Vec::new();
    for e in fs::read_dir(root.join("sys/bus/pci/devices")).map_err(|e| Error(format!("PCI devices: {e}")))? {
        let e = e.map_err(|e| Error(e.to_string()))?;
        let name = e.file_name().to_string_lossy().into_owned();
        let Some(rest) = name.strip_prefix("0000:") else { continue };
        let Some(b) = bdf(rest) else { continue };
        let hex = |name: &str| fs::read_to_string(e.path().join(name)).ok()
            .and_then(|c| u32::from_str_radix(c.trim().trim_start_matches("0x"), 16).ok()).unwrap_or(0);
        let class = hex("class");
        out.push(Func { bdf: b, vendor: hex("vendor") as u16, device: hex("device") as u16, class, bridge: class >> 8 == 0x0604 });
    }
    out.sort_by_key(|f| f.bdf);
    Ok(out)
}

fn ram_bytes(root: &Path) -> u64 {
    fs::read_to_string(root.join("proc/meminfo")).ok()
        .and_then(|m| m.lines().find_map(|l| l.strip_prefix("MemTotal:").map(|v| v.trim().trim_end_matches(" kB").parse::<u64>().ok())))
        .flatten().map_or(0, |kb| kb << 10)
}

pub fn run(args: &[String]) -> Result<i32> {
    let path = args.first().map_or("/boot/efi/l4h/l4h-mk.conf", |s| s.as_str());
    check(Path::new("/"), path)
}

fn check(root: &Path, path: &str) -> Result<i32> {
    let text = fs::read_to_string(path).map_err(|e| Error(format!("{path}: {e}")))?;
    let (n, parts, links) = parse(&text)?;
    if fs::metadata(root.join("sys/kernel/l4h")).is_ok() {
        return fail("mk-check reads the machine's ACPI tables and PCI functions: run it from native Linux, not dom0".into());
    }
    let cpus_v = cpus(root)?;
    let cpus = &cpus_v;
    let funcs = funcs(root)?;
    // Without MCFG the shim and roots use shared PCI configuration ports;
    // Linux exposes the functions through sysfs either way.
    // CPUs: explicit ones first, then counts and even shares in APIC ID
    // order, the boot CPU (the MADT's first) first.
    let mut owner: Vec<Option<usize>> = vec![None; cpus.len()];
    let mut counts = vec![None; n];
    for (k, p) in parts.iter().enumerate() {
        let Some(spec) = &p.cpus else { continue };
        let want: Box<dyn Fn(usize) -> bool + '_> = if let Some(node) = spec.strip_prefix("node:") {
            let node: u32 = node.trim().parse().map_err(|_| Error(format!("p{k}.cpus: {spec}")))?;
            Box::new(move |i| cpus[i].node == node)
        } else if let Some(list) = spec.strip_prefix("apic:") {
            let list: Vec<u32> = list.split(',').map(|a| a.trim().parse().map_err(|_| Error(format!("p{k}.cpus: {spec}")))).collect::<Result<_>>()?;
            Box::new(move |i| list.contains(&cpus[i].apic))
        } else if let Some((a, b)) = spec.split_once('-') {
            let (a, b): (usize, usize) = (a.trim().parse().map_err(|_| Error(format!("p{k}.cpus: {spec}")))?,
                b.trim().parse().map_err(|_| Error(format!("p{k}.cpus: {spec}")))?);
            Box::new(move |i| (a..=b).contains(&i))
        } else {
            counts[k] = Some(spec.parse::<usize>().map_err(|_| Error(format!("p{k}.cpus: {spec}")))?);
            continue;
        };
        for i in 0..cpus.len() {
            if want(i) {
                if let Some(o) = owner[i] {
                    return fail(format!("CPU {i} (APIC ID {}) is in p{o} and p{k}", cpus[i].apic));
                }
                owner[i] = Some(k);
            }
        }
    }
    let mut left: Vec<usize> = (0..cpus.len()).filter(|&i| owner[i].is_none()).collect();
    left.sort_by_key(|&i| (i != 0, cpus[i].apic));
    let counted: usize = counts.iter().flatten().sum();
    let defaults = (0..n).filter(|&k| parts[k].cpus.is_none()).count();
    if counted > left.len() {
        return fail(format!("{counted} CPUs asked for, {} left", left.len()));
    }
    let share = if defaults > 0 { (left.len() - counted) / defaults } else { 0 };
    let mut next = 0;
    for k in 0..n {
        let c = match (counts[k], &parts[k].cpus) {
            (Some(c), _) => c,
            (None, None) if k == 0 => share + (left.len() - counted) % defaults.max(1),
            (None, None) => share,
            _ => 0,
        };
        for _ in 0..c {
            owner[left[next]] = Some(k);
            next += 1;
        }
    }
    let part_cpus = |k: usize| (0..cpus.len()).filter(|&i| owner[i] == Some(k)).collect::<Vec<_>>();
    if owner.first().copied().flatten() != Some(0) {
        return fail("partition 0 does not have the boot CPU (the MADT's first)".into());
    }
    // PCI functions.
    let mut fowner: BTreeMap<u16, usize> = funcs.iter().map(|f| (f.bdf, 0)).collect();
    for (k, p) in parts.iter().enumerate() {
        for &b in &p.pci {
            let Some(f) = funcs.iter().find(|f| f.bdf == b) else { return fail(format!("p{k}.pci: no PCI function {}", fmt_bdf(b))) };
            if f.bridge {
                return fail(format!("PCI function {} is a bridge", fmt_bdf(b)));
            }
            if k != 0 {
                if fowner[&b] != 0 {
                    return fail(format!("PCI function {} is in p{} and p{k}", fmt_bdf(b), fowner[&b]));
                }
                fowner.insert(b, k);
            }
        }
    }
    let ram = ram_bytes(root);
    let mut asked = 0;
    let mut ok = true;
    for k in 0..n {
        let c = part_cpus(k);
        let fs: Vec<&Func> = funcs.iter().filter(|f| fowner[&f.bdf] == k).collect();
        if c.is_empty() {
            println!("p{k}: no CPU");
            ok = false;
        }
        if !fs.iter().any(|f| f.is_disk()) {
            println!("p{k}: no disk controller");
            ok = false;
        }
        asked += parts[k].mem.unwrap_or(0);
        let apics: Vec<String> = c.iter().map(|&i| cpus[i].apic.to_string()).collect();
        let nodes: std::collections::BTreeSet<u32> = c.iter().map(|&i| cpus[i].node).collect();
        println!("p{k}: {} CPU(s) (APIC IDs {}; node(s) {:?}), memory {}", c.len(), apics.join(" "), nodes,
            parts[k].mem.map_or(if k == 0 { "the rest".to_string() } else { "an even share".to_string() }, |m| format!("{} MiB", m >> 20)));
        for f in fs.iter().filter(|f| k != 0 || f.is_disk() || f.class >> 16 == 0x02) {
            println!("p{k}:   {} class {:06x}", fmt_bdf(f.bdf), f.class);
        }
    }
    for (a, b, uplink) in &links {
        if *b >= n {
            println!("link p{a}-p{b}: no partition {b}");
            ok = false;
        } else {
            println!("link p{a}-p{b}{}", if *uplink { " (on their uplink switches)" } else { "" });
        }
    }
    if ram != 0 && asked > ram {
        println!("{} MiB asked for, the machine has {} MiB", asked >> 20, ram >> 20);
        ok = false;
    }
    println!("{}", if ok { "mk-check: ok (the shim checks memory placement again at boot)" } else { "mk-check: not bootable" });
    Ok(if ok { 0 } else { 1 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Machine(PathBuf);

    impl Machine {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let root = std::env::temp_dir().join(format!("l4h-mkcheck-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
            fs::create_dir(&root).unwrap();
            let m = Self(root);
            let mut madt = vec![0u8; 44];
            madt[..4].copy_from_slice(b"APIC");
            madt[8] = 1;
            madt[36..40].copy_from_slice(&0xfee0_0000u32.to_le_bytes());
            madt[40] = 1;
            for id in 0..4 {
                madt.extend_from_slice(&[0, 8, id, id, 1, 0, 0, 0]);
            }
            let len = madt.len() as u32;
            madt[4..8].copy_from_slice(&len.to_le_bytes());
            madt[9] = 0u8.wrapping_sub(madt.iter().fold(0u8, |sum, &b| sum.wrapping_add(b)));
            m.write("sys/firmware/acpi/tables/APIC", &madt);
            m.write("proc/meminfo", b"MemTotal:       8388608 kB\n");
            m.write("l4h-mk.conf", b"partitions = 2\np1.cpus = 2\np1.pci = 00:06.0\n");
            m.pci("00:04.0", 0x010000, 0x1af4, 0x1042);
            m.pci("00:06.0", 0x010802, 0x1b36, 0x0010);
            m
        }

        fn write(&self, path: &str, data: &[u8]) {
            let path = self.0.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, data).unwrap();
        }

        fn pci(&self, bdf: &str, class: u32, vendor: u16, device: u16) {
            for (name, value) in [("class", class), ("vendor", vendor as u32), ("device", device as u32)] {
                self.write(&format!("sys/bus/pci/devices/0000:{bdf}/{name}"), format!("0x{value:06x}\n").as_bytes());
            }
        }

        fn check(&self) -> Result<i32> {
            super::check(&self.0, self.0.join("l4h-mk.conf").to_str().unwrap())
        }
    }

    impl Drop for Machine {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn accepts_partitions_without_mcfg() {
        let m = Machine::new();
        assert_eq!(m.check().unwrap(), 0);
    }

    #[test]
    fn accepts_partitions_with_mcfg() {
        let m = Machine::new();
        m.write("sys/firmware/acpi/tables/MCFG", &[]);
        assert_eq!(m.check().unwrap(), 0);
    }

    #[test]
    fn accepts_unclassified_virtio_disks_without_mcfg() {
        let m = Machine::new();
        // GCE's boot disk controller is 1af4:1004 with class 0; the shim
        // also recognizes the other legacy/modern virtio disk IDs.
        for device in [0x1004, 0x1001, 0x1042, 0x1048] {
            m.pci("00:04.0", 0, 0x1af4, device);
            assert_eq!(m.check().unwrap(), 0);
        }
    }

    #[test]
    fn rejects_missing_disk_without_mcfg() {
        let m = Machine::new();
        // Neither an unrelated vendor nor a virtio NIC is a disk.
        for (vendor, device) in [(0x1234, 0x1004), (0x1af4, 0x1000)] {
            m.pci("00:06.0", 0, vendor, device);
            assert_eq!(m.check().unwrap(), 1);
        }
    }

    #[test]
    fn rejects_missing_cpu_without_mcfg() {
        let m = Machine::new();
        m.write("l4h-mk.conf", b"partitions = 2\np1.cpus = 0\np1.pci = 00:06.0\n");
        assert_eq!(m.check().unwrap(), 1);
    }

    #[test]
    fn rejects_dom0_without_mcfg() {
        let m = Machine::new();
        m.write("sys/kernel/l4h/present", &[]);
        assert!(m.check().unwrap_err().0.contains("run it from native Linux, not dom0"));
    }
}

//! The firmware's ACPI tables: the ones the shim reads (MADT, SRAT, MCFG,
//! FADT, DMAR, IVRS) and the list every partition's copy starts from.

use crate::io::{Vec, phys, rd16, rd32, rd64};

pub struct Acpi {
    pub rsdp: [u8; 36],
    /// The tables the XSDT (or RSDT) lists.
    pub tables: Vec<u64, 128>,
}

#[derive(Clone, Copy)]
pub struct Cpu {
    pub apic_id: u32,
    /// The MADT entry (type 0 or 9), as is.
    pub entry: [u8; 16],
    pub entry_len: u8,
    /// SRAT proximity domain, 0 without an SRAT.
    pub node: u32,
}

#[derive(Clone, Copy)]
pub struct MemAffinity {
    pub base: u64,
    pub len: u64,
    pub node: u32,
}

pub fn header(pa: u64) -> &'static [u8] {
    unsafe { phys(pa, 36) }
}

pub fn table(pa: u64) -> &'static [u8] {
    let len = rd32(header(pa), 4) as usize;
    unsafe { phys(pa, len) }
}

pub fn checksum(b: &[u8]) -> u8 {
    0u8.wrapping_sub(b.iter().fold(0u8, |a, &x| a.wrapping_add(x)))
}

impl Acpi {
    pub fn new(rsdp: [u8; 36]) -> Acpi {
        let mut a = Acpi { rsdp, tables: Vec::new() };
        let xsdt = if rsdp[15] >= 2 { rd64(&rsdp, 24) } else { 0 };
        if xsdt != 0 {
            let t = table(xsdt);
            for i in 0..(t.len() - 36) / 8 {
                a.tables.must_push(rd64(t, 36 + 8 * i));
            }
        } else {
            let t = table(rd32(&rsdp, 16) as u64);
            for i in 0..(t.len() - 36) / 4 {
                a.tables.must_push(rd32(t, 36 + 4 * i) as u64);
            }
        }
        a
    }

    pub fn find(&self, sig: &[u8; 4]) -> Option<u64> {
        self.tables.iter().copied().find(|&pa| pa != 0 && &header(pa)[..4] == sig)
    }

    /// The enabled CPUs, in MADT order, and whether the MADT lists an I/O
    /// APIC.
    pub fn cpus(&self) -> Vec<Cpu, 1024> {
        let mut cpus = Vec::new();
        let Some(madt) = self.find(b"APIC") else { crate::fail(format_args!("no MADT")) };
        let t = table(madt);
        let mut off = 44;
        while off + 2 <= t.len() {
            let (ty, len) = (t[off], t[off + 1] as usize);
            if len < 2 || off + len > t.len() {
                break;
            }
            let e = &t[off..off + len];
            let cpu = match ty {
                0 if len >= 8 && rd32(e, 4) & 1 != 0 => Some(e[3] as u32),
                9 if len >= 16 && rd32(e, 8) & 1 != 0 => Some(rd32(e, 4)),
                _ => None,
            };
            if let Some(apic_id) = cpu {
                let mut entry = [0; 16];
                entry[..len.min(16)].copy_from_slice(&e[..len.min(16)]);
                cpus.must_push(Cpu { apic_id, entry, entry_len: len.min(16) as u8, node: 0 });
            }
            off += len;
        }
        if let Some(srat) = self.find(b"SRAT") {
            let t = table(srat);
            let mut off = 48;
            while off + 2 <= t.len() {
                let (ty, len) = (t[off], t[off + 1] as usize);
                if len < 2 || off + len > t.len() {
                    break;
                }
                let e = &t[off..off + len];
                let (apic, node, enabled) = match ty {
                    0 if len >= 16 => (e[3] as u32, e[2] as u32 | (e[9] as u32) << 8 | (e[10] as u32) << 16 | (e[11] as u32) << 24, rd32(e, 4) & 1 != 0),
                    2 if len >= 24 => (rd32(e, 8), rd32(e, 4), rd32(e, 12) & 1 != 0),
                    _ => (u32::MAX, 0, false),
                };
                if enabled {
                    for c in cpus.iter_mut() {
                        if c.apic_id == apic {
                            c.node = node;
                        }
                    }
                }
                off += len;
            }
        }
        cpus
    }

    /// SRAT memory affinity: which node each RAM range is on.
    pub fn mem_affinity(&self) -> Vec<MemAffinity, 64> {
        let mut out = Vec::new();
        let Some(srat) = self.find(b"SRAT") else { return out };
        let t = table(srat);
        let mut off = 48;
        while off + 2 <= t.len() {
            let (ty, len) = (t[off], t[off + 1] as usize);
            if len < 2 || off + len > t.len() {
                break;
            }
            let e = &t[off..off + len];
            if ty == 1 && len >= 40 && rd32(e, 28) & 1 != 0 {
                out.push(MemAffinity { base: rd64(e, 8), len: rd64(e, 16), node: rd32(e, 2) });
            }
            off += len;
        }
        out
    }

    /// The ECAM of segment 0: base, first and last bus.
    pub fn ecam(&self) -> Option<(u64, u8, u8)> {
        let t = table(self.find(b"MCFG")?);
        let mut off = 44;
        while off + 16 <= t.len() {
            let e = &t[off..off + 16];
            if rd16(e, 8) == 0 {
                return Some((rd64(e, 0), e[10], e[11]));
            }
            off += 16;
        }
        None
    }

    /// The CMOS register of the century, from the FADT (0: none).
    pub fn century(&self) -> u8 {
        match self.find(b"FACP") {
            Some(f) => {
                let t = table(f);
                if t.len() > 108 { t[108] } else { 0 }
            }
            None => 0,
        }
    }

    pub fn has_iommu(&self) -> bool {
        self.find(b"DMAR").is_some() || self.find(b"IVRS").is_some()
    }
}

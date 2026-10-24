//! DMAR parsing and PCI scope resolution, independent of MMIO and seL4.

use l4h_host::fixed::ArrayVec;

pub const MAX_UNITS: usize = 16;
const MAX_SCOPES: usize = 256;
pub const MAX_RESERVED: usize = 128;
pub const MAX_IOAPICS: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scope {
    pub first: u16,
    pub last: u16,
}

impl Scope {
    pub fn contains(self, id: u16) -> bool { (self.first..=self.last).contains(&id) }
}

pub struct Drhd {
    pub base: usize,
    pub all: bool,
}

#[derive(Clone, Copy)]
pub struct Reserved {
    pub scope: Scope,
    pub start: usize,
    pub end: usize,
}

#[derive(Clone, Copy)]
pub struct IoApic {
    pub id: u8,
    pub sid: u16,
    pub unit: usize,
}

pub struct Dmar {
    pub haw: u8,
    pub interrupt_remapping: bool,
    pub units: ArrayVec<Drhd, MAX_UNITS>,
    scopes: ArrayVec<(Scope, usize), MAX_SCOPES>,
    pub reserved: ArrayVec<Reserved, MAX_RESERVED>,
    pub ioapics: ArrayVec<IoApic, MAX_IOAPICS>,
}

pub fn u16_at(b: &[u8], at: usize) -> u16 { u16::from_le_bytes(b[at..at + 2].try_into().unwrap()) }
pub fn u32_at(b: &[u8], at: usize) -> u32 { u32::from_le_bytes(b[at..at + 4].try_into().unwrap()) }
fn u64_at(b: &[u8], at: usize) -> u64 { u64::from_le_bytes(b[at..at + 8].try_into().unwrap()) }

impl Dmar {
    pub const fn empty() -> Self {
        Self { haw: 0, interrupt_remapping: false, units: ArrayVec::new(),
            scopes: ArrayVec::new(), reserved: ArrayVec::new(), ioapics: ArrayVec::new() }
    }

    /// Explicit scopes take precedence over INCLUDE_PCI_ALL, regardless
    /// of the order firmware used. Only segment 0 is driven by l4h's PCI.
    pub fn owner(&self, id: u16) -> Option<usize> {
        self.scopes.iter().find(|(s, _)| s.contains(id)).map(|(_, u)| *u)
            .or_else(|| self.units.iter().position(|u| u.all))
    }

    pub fn parse(table: &[u8], mut read: impl FnMut(u8, u8, u8, u8) -> u32) -> Option<Self> {
        if table.len() < 48 || table.get(..4)? != b"DMAR" { return None; }
        let len = u32_at(table, 4) as usize;
        let table = table.get(..len).filter(|t| t.len() >= 48)?;
        if table.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)) != 0 { return None; }
        let haw = table[36].checked_add(1)?;
        if !(32..=52).contains(&haw) { return None; }
        let mut me = Self { haw, interrupt_remapping: table[37] & 1 != 0, ..Self::empty() };
        let mut at = 48;
        while at < table.len() {
            let header = table.get(at..at + 4)?;
            let len = u16_at(header, 2) as usize;
            let block = table.get(at..at + len).filter(|b| b.len() >= 4)?;
            at += len;
            match u16_at(block, 0) {
                0 => {
                    if len < 16 { return None; }
                    if u16_at(block, 6) != 0 { continue; }
                    let base = usize::try_from(u64_at(block, 8)).ok()?;
                    if base == 0 || base & 4095 != 0 || base.checked_add(65536)? as u64 > 1u64 << haw {
                        return None;
                    }
                    let all = block[4] & 1 != 0;
                    if me.units.iter().any(|u| u.base == base || (all && u.all)) { return None; }
                    let unit = me.units.len();
                    me.units.push(Drhd { base, all }).ok()?;
                    scopes(&block[16..], &mut read, |scope| {
                        if me.scopes.iter().any(|(s, _)| s.first <= scope.last && scope.first <= s.last) {
                            return None;
                        }
                        me.scopes.push((scope, unit)).ok()
                    }, |id, sid| {
                        if me.ioapics.iter().any(|a| a.id == id) { return None; }
                        me.ioapics.push(IoApic { id, sid, unit }).ok()
                    })?;
                }
                1 => {
                    if len < 24 { return None; }
                    if u16_at(block, 6) != 0 { continue; }
                    let start = usize::try_from(u64_at(block, 8)).ok()?;
                    let end = usize::try_from(u64_at(block, 16)).ok()?.checked_add(1)?;
                    if start >= end || start & 4095 != 0 || end & 4095 != 0 || end as u64 > 1u64 << haw {
                        return None;
                    }
                    scopes(&block[24..], &mut read, |scope| {
                        me.reserved.push(Reserved { scope, start, end }).ok()
                    }, |_, _| None)?;
                }
                // ATS is never enabled. Unknown structures are length-delimited.
                _ => {},
            }
        }
        Some(me)
    }
}

fn scopes(mut bytes: &[u8], read: &mut impl FnMut(u8, u8, u8, u8) -> u32,
    mut add: impl FnMut(Scope) -> Option<()>, mut ioapic: impl FnMut(u8, u16) -> Option<()>) -> Option<()> {
    while !bytes.is_empty() {
        let len = *bytes.get(1)? as usize;
        let scope = bytes.get(..len).filter(|s| s.len() >= 8 && s.len() % 2 == 0)?;
        bytes = &bytes[len..];
        if scope[6..].chunks_exact(2).any(|p| p[0] > 31 || p[1] > 7) { return None; }
        match scope[0] {
            // HPET interrupts stay blocked. I/O APIC scopes describe
            // interrupt sources and must never grant DMA access.
            4 => continue,
            1 | 2 | 3 => {},
            // Do not guess coverage of namespace devices or unknown scopes.
            _ => return None,
        }
        let mut bus = scope[5];
        let mut path = scope[6..].chunks_exact(2).peekable();
        while let Some(p) = path.next() {
            if scope[0] == 3 && path.peek().is_none() {
                // The final requester need not expose PCI configuration
                // space (e.g. QEMU's I/O APIC). Only bridges are probed.
                let sid = (bus as u16) << 8 | (p[0] as u16) << 3 | p[1] as u16;
                ioapic(scope[4], sid)?;
                break;
            }
            if read(bus, p[0], p[1], 0) & 0xffff == 0xffff {
                break;
            }
            if path.peek().is_some() || scope[0] == 2 {
                // Every intermediate hop and a sub-hierarchy's final hop
                // must be a PCI bridge with a configured bus range.
                if read(bus, p[0], p[1], 8) >> 16 != 0x0604 { return None; }
                let buses = read(bus, p[0], p[1], 0x18);
                let (secondary, subordinate) = ((buses >> 8) as u8, (buses >> 16) as u8);
                if secondary <= bus || subordinate < secondary { return None; }
                if path.peek().is_none() {
                    add(Scope { first: (secondary as u16) << 8, last: (subordinate as u16) << 8 | 255 })?;
                }
                bus = secondary;
            } else {
                let id = (bus as u16) << 8 | (p[0] as u16) << 3 | p[1] as u16;
                add(Scope { first: id, last: id })?;
            }
        }
        // Firmware may describe disabled/absent devices. No existing
        // requester can be covered by a path through an absent bridge.
    }
    Some(())
}

/// seL4 numbers I/O APICs by their order in MADT, while DMAR names them
/// by their firmware ID. Preserve that distinction even for nonzero IDs.
pub fn madt_ioapics(table: &[u8]) -> Option<ArrayVec<u8, MAX_IOAPICS>> {
    if table.len() < 44 || table.get(..4)? != b"APIC" { return None; }
    let table = table.get(..u32_at(table, 4) as usize).filter(|t| t.len() >= 44)?;
    if table.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)) != 0 { return None; }
    let mut ids = ArrayVec::new();
    let mut at = 44;
    while at < table.len() {
        let header = table.get(at..at + 2)?;
        let entry = table.get(at..at + header[1] as usize).filter(|e| e.len() >= 2)?;
        at += entry.len();
        if entry[0] == 1 {
            if entry.len() < 12 || ids.iter().any(|&id| id == entry[2]) { return None; }
            ids.push(entry[2]).ok()?;
        }
    }
    Some(ids)
}

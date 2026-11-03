//! PCI functions: the shim finds and sizes them all before any kernel
//! runs, so that no partition's root ever sizes a BAR (which stops a
//! device decoding while it runs).

use l4h_partition::{BAR_64, BAR_IO, BAR_PREFETCH, Bar};

use crate::io::{Vec, inl, outl};

/// Device memory is reached through the uncached alias of the identity
/// map (main.rs).
pub const UC_ALIAS: u64 = 1 << 39;

pub struct Pci {
    ecam: Option<(u64, u8, u8)>,
}

#[derive(Clone, Copy)]
pub struct Func {
    pub bdf: u16,
    pub vendor: u16,
    pub device: u16,
    pub class: u32,
    pub header: u8,
    pub bars: [Bar; 6],
    /// Buses below a bridge: [secondary, subordinate].
    pub secondary: u8,
    pub subordinate: u8,
    /// A bridge whose functions below share one requester ID: a
    /// conventional PCI bridge, or a PCIe-to-PCI bridge.
    pub aliasing: bool,
}

impl Func {
    pub fn is_disk(&self) -> bool {
        self.class >> 16 == 0x01
    }

    pub fn is_nic(&self) -> bool {
        self.class >> 16 == 0x02
    }
}

impl Pci {
    pub fn new(ecam: Option<(u64, u8, u8)>) -> Pci {
        Pci { ecam }
    }

    pub fn read32(&self, bdf: u16, off: u16) -> u32 {
        match self.ecam {
            Some((base, start, end)) => {
                let bus = (bdf >> 8) as u8;
                if bus < start || bus > end {
                    return u32::MAX;
                }
                let p = UC_ALIAS + base + (((bdf as u64) << 12) | (off as u64 & 0xffc));
                unsafe { (p as *const u32).read_volatile() }
            }
            None => {
                outl(0xcf8, 0x8000_0000 | (bdf as u32) << 8 | (off as u32 & 0xfc));
                inl(0xcfc)
            }
        }
    }

    pub fn write32(&self, bdf: u16, off: u16, v: u32) {
        match self.ecam {
            Some((base, _, _)) => {
                let p = UC_ALIAS + base + (((bdf as u64) << 12) | (off as u64 & 0xffc));
                unsafe { (p as *mut u32).write_volatile(v) }
            }
            None => {
                outl(0xcf8, 0x8000_0000 | (bdf as u32) << 8 | (off as u32 & 0xfc));
                outl(0xcfc, v);
            }
        }
    }

    fn read8(&self, bdf: u16, off: u16) -> u8 {
        (self.read32(bdf, off & !3) >> ((off & 3) * 8)) as u8
    }

    fn read16(&self, bdf: u16, off: u16) -> u16 {
        (self.read32(bdf, off & !3) >> ((off & 2) * 8)) as u16
    }

    fn write16(&self, bdf: u16, off: u16, v: u16) {
        let old = self.read32(bdf, off & !3);
        let shift = (off & 2) * 8;
        self.write32(bdf, off & !3, (old & !(0xffff << shift)) | (v as u32) << shift);
    }

    /// Every function on segment 0.
    pub fn scan(&self) -> Vec<Func, 1024> {
        let mut out = Vec::new();
        let last = self.ecam.map_or(255, |(_, _, e)| e as u32);
        let first = self.ecam.map_or(0, |(_, s, _)| s as u32);
        for bus in first..=last {
            for dev in 0..32u16 {
                let bdf0 = (bus as u16) << 8 | dev << 3;
                if self.read32(bdf0, 0) & 0xffff == 0xffff {
                    continue;
                }
                let multi = self.read8(bdf0, 0xe) & 0x80 != 0;
                for func in 0..if multi { 8 } else { 1 } {
                    let bdf = bdf0 | func;
                    let id = self.read32(bdf, 0);
                    if id & 0xffff == 0xffff {
                        continue;
                    }
                    out.must_push(self.probe(bdf, id));
                }
            }
        }
        out
    }

    fn probe(&self, bdf: u16, id: u32) -> Func {
        let header = self.read8(bdf, 0xe) & 0x7f;
        let class = self.read32(bdf, 8) >> 8;
        let mut f = Func {
            bdf,
            vendor: id as u16,
            device: (id >> 16) as u16,
            class,
            header,
            bars: [Bar::default(); 6],
            secondary: 0,
            subordinate: 0,
            aliasing: false,
        };
        match header {
            0 => f.bars = self.size_bars(bdf, 6),
            1 => {
                let buses = self.read32(bdf, 0x18);
                f.secondary = (buses >> 8) as u8;
                f.subordinate = (buses >> 16) as u8;
                // PCIe capability: a PCIe-to-PCI bridge aliases what is
                // below it; a bridge without one is conventional PCI.
                f.aliasing = match self.pcie_type(bdf) {
                    Some(t) => t == 0x7,
                    None => true,
                };
            }
            _ => {}
        }
        f
    }

    fn pcie_type(&self, bdf: u16) -> Option<u8> {
        if self.read16(bdf, 6) & 0x10 == 0 {
            return None;
        }
        let mut ptr = self.read8(bdf, 0x34) & !3;
        let mut guard = 0;
        while ptr != 0 && guard < 48 {
            if self.read8(bdf, ptr as u16) == 0x10 {
                return Some((self.read16(bdf, ptr as u16 + 2) >> 4) as u8 & 0xf);
            }
            ptr = self.read8(bdf, ptr as u16 + 1) & !3;
            guard += 1;
        }
        None
    }

    fn size_bars(&self, bdf: u16, n: usize) -> [Bar; 6] {
        let mut bars = [Bar::default(); 6];
        let cmd = self.read16(bdf, 4);
        self.write16(bdf, 4, cmd & !3);
        let mut i = 0;
        while i < n {
            let off = 0x10 + 4 * i as u16;
            let orig = self.read32(bdf, off);
            self.write32(bdf, off, 0xffff_ffff);
            let lo = self.read32(bdf, off);
            self.write32(bdf, off, orig);
            if orig & 1 != 0 {
                let sz = lo & !3;
                if sz != 0 {
                    bars[i] = Bar { addr: (orig & !3) as u64, size: ((!sz).wrapping_add(1) & 0xffff) as u64, flags: BAR_IO, _pad: 0 };
                }
                i += 1;
                continue;
            }
            let is64 = (orig >> 1) & 3 == 2;
            let mut addr = (orig & !0xf) as u64;
            let mut mask = (lo & !0xf) as u64 | 0xffff_ffff_0000_0000;
            if is64 && i + 1 < n {
                let orig_hi = self.read32(bdf, off + 4);
                self.write32(bdf, off + 4, 0xffff_ffff);
                let hi = self.read32(bdf, off + 4);
                self.write32(bdf, off + 4, orig_hi);
                addr |= (orig_hi as u64) << 32;
                mask = (hi as u64) << 32 | (lo & !0xf) as u64;
            }
            if lo & !0xf != 0 {
                let mut flags = 0;
                if is64 {
                    flags |= BAR_64;
                }
                if orig & 8 != 0 {
                    flags |= BAR_PREFETCH;
                }
                bars[i] = Bar { addr, size: (!mask).wrapping_add(1), flags, _pad: 0 };
            }
            i += if is64 { 2 } else { 1 };
        }
        self.write16(bdf, 4, cmd);
        bars
    }
}

pub fn fmt_bdf(bdf: u16) -> impl core::fmt::Display {
    struct B(u16);
    impl core::fmt::Display for B {
        fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
            write!(f, "{:02x}:{:02x}.{}", self.0 >> 8, (self.0 >> 3) & 0x1f, self.0 & 7)
        }
    }
    B(bdf)
}

/// "0000:80:04.0" or "80:04.0" as bus << 8 | dev << 3 | func.
pub fn parse_bdf(s: &str) -> Option<u16> {
    let s = s.trim();
    let s = match s.matches(':').count() {
        2 => {
            let (seg, rest) = s.split_once(':')?;
            if u16::from_str_radix(seg, 16).ok()? != 0 {
                return None;
            }
            rest
        }
        1 => s,
        _ => return None,
    };
    let (bus, rest) = s.split_once(':')?;
    let (dev, func) = rest.split_once('.')?;
    let (bus, dev, func) = (u8::from_str_radix(bus, 16).ok()?, u8::from_str_radix(dev, 16).ok()?, u8::from_str_radix(func, 16).ok()?);
    (dev < 32 && func < 8).then_some((bus as u16) << 8 | (dev as u16) << 3 | func as u16)
}

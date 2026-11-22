//! The ACPI tables of an HVM guest (DESIGN.md §5.11), in the BIOS area at
//! 0xe0000, which the E820 map reserves (boot.rs): RSDP (2.0), XSDT, FADT
//! (6.1; fixed hardware in dev/pm.rs: PM1a event and control blocks, the
//! PM timer, SCI on IRQ 9, the reset register at 0xcf9), FACS, MADT (a
//! local APIC per vCPU, the I/O APIC, the SCI's override, no 8259:
//! PCAT_COMPAT clear), MCFG (ECAM of bus 0) and a DSDT with \_S5, the PCI
//! host bridge \_SB.PCI0 (its windows and INTx routing, _PRT).  The power
//! button is the fixed-hardware one (FADT's PWR_BUTTON clear, PM1's
//! PWRBTN), which l4hctl shutdown presses: no control-method one beside
//! it.  Free of seL4.

use crate::dev::{ioapic, pci, pm};

pub const RSDP: u64 = 0xe_0000;
const XSDT: u64 = 0xe_0040;
const FACS: u64 = 0xe_00c0;
const FADT: u64 = 0xe_0100;
const MADT: u64 = 0xe_0300;
const MCFG: u64 = 0xe_0b00;
const DSDT: u64 = 0xe_0c00;
pub const END: u64 = 0x10_0000;

const OEM_ID: &[u8; 6] = b"L4H   ";
const OEM_TABLE: &[u8; 8] = b"L4HHVM  ";

/// A table being written: bytes, little-endian.
pub struct Table<const N: usize> {
    pub b: [u8; N],
    pub len: usize,
}

impl<const N: usize> Table<N> {
    pub const fn new() -> Self {
        Table { b: [0; N], len: 0 }
    }

    pub fn bytes(&mut self, s: &[u8]) -> &mut Self {
        self.b[self.len..self.len + s.len()].copy_from_slice(s);
        self.len += s.len();
        self
    }

    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.bytes(&[v])
    }

    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.bytes(&v.to_le_bytes())
    }

    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.bytes(&v.to_le_bytes())
    }

    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.bytes(&v.to_le_bytes())
    }

    /// A standard header for `sig`, revision `rev`; length and checksum are
    /// filled in by `finish`.
    fn header(&mut self, sig: &[u8; 4], rev: u8) -> &mut Self {
        self.bytes(sig).u32(0).u8(rev).u8(0).bytes(OEM_ID).bytes(OEM_TABLE).u32(1).bytes(b"L4H ").u32(1)
    }

    /// Fill in the header's length and checksum.
    fn finish(&mut self) {
        let len = self.len as u32;
        self.b[4..8].copy_from_slice(&len.to_le_bytes());
        self.b[9] = 0;
        self.b[9] = checksum(&self.b[..self.len]);
    }

    /// A Generic Address Structure: system I/O at `port`, `bits` wide.
    fn gas_io(&mut self, port: u16, bits: u8) -> &mut Self {
        let access = match bits {
            8 => 1,
            16 => 2,
            32 => 3,
            _ => 0,
        };
        let (space, bits) = if bits == 0 { (0, 0) } else { (1, bits) };
        self.u8(space).u8(bits).u8(0).u8(access).u64(port as u64)
    }
}

impl<const N: usize> Default for Table<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// The byte that makes `b` sum to zero.
pub fn checksum(b: &[u8]) -> u8 {
    0u8.wrapping_sub(b.iter().fold(0u8, |s, &x| s.wrapping_add(x)))
}

/// AML, written into a fixed buffer: package lengths are known only once
/// their contents are, so a package's body is written into a buffer of its
/// own first (`pkg`).
pub struct Aml<'a> {
    b: &'a mut [u8],
    len: usize,
}

impl<'a> Aml<'a> {
    pub fn new(b: &'a mut [u8]) -> Self {
        Aml { b, len: 0 }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn raw(&mut self, s: &[u8]) -> &mut Self {
        self.b[self.len..self.len + s.len()].copy_from_slice(s);
        self.len += s.len();
        self
    }

    /// PkgLength of a body of `n` bytes: the length counts itself.
    fn pkg_length(&mut self, n: usize) -> &mut Self {
        if n + 1 < 0x40 {
            return self.raw(&[(n + 1) as u8]);
        }
        let (extra, total) = if n + 2 < 0x1000 { (1, n + 2) } else if n + 3 < 0x10_0000 { (2, n + 3) } else { (3, n + 4) };
        self.raw(&[((extra as u8) << 6) | (total & 0xf) as u8]);
        for i in 0..extra {
            self.raw(&[(total >> (4 + 8 * i)) as u8]);
        }
        self
    }

    /// `op`, then a package of what `f` writes.
    pub fn pkg(&mut self, op: &[u8], f: impl FnOnce(&mut Aml)) -> &mut Self {
        let mut body = [0u8; 4096];
        let mut a = Aml::new(&mut body);
        f(&mut a);
        let n = a.len;
        self.raw(op).pkg_length(n).raw(&body[..n])
    }

    /// An integer, in its shortest encoding.
    pub fn int(&mut self, v: u64) -> &mut Self {
        match v {
            0 => self.raw(&[0x00]),
            1 => self.raw(&[0x01]),
            2..=0xff => self.raw(&[0x0a, v as u8]),
            0x100..=0xffff => self.raw(&[0x0b]).raw(&(v as u16).to_le_bytes()),
            0x1_0000..=0xffff_ffff => self.raw(&[0x0c]).raw(&(v as u32).to_le_bytes()),
            _ => self.raw(&[0x0e]).raw(&v.to_le_bytes()),
        }
    }

    /// Name(`name`, ...) with what `f` writes as its value.
    pub fn name(&mut self, name: &[u8], f: impl FnOnce(&mut Aml)) -> &mut Self {
        self.raw(&[0x08]).raw(name);
        f(self);
        self
    }

    /// Package(n) { what `f` writes }.
    pub fn package(&mut self, n: u8, f: impl FnOnce(&mut Aml)) -> &mut Self {
        self.pkg(&[0x12], |a| {
            a.raw(&[n]);
            f(a);
        })
    }

    /// Buffer() { `data` }.
    pub fn buffer(&mut self, data: &[u8]) -> &mut Self {
        self.pkg(&[0x11], |a| {
            a.int(data.len() as u64).raw(data);
        })
    }

    pub fn device(&mut self, name: &[u8], f: impl FnOnce(&mut Aml)) -> &mut Self {
        self.pkg(&[0x5b, 0x82], |a| {
            a.raw(name);
            f(a);
        })
    }
}

/// EisaId("PNP" + hex): as the 32-bit integer ASL makes of it.
pub const fn eisa_pnp(product: u16) -> u64 {
    // "PNP" compressed: 0x41d0, big-endian; the product big-endian too.
    (0xd041 | ((product as u32 & 0xff) << 24) | ((product as u32 >> 8) << 16)) as u64
}

/// The host bridge's resources: bus 0, the configuration ports, all other
/// I/O ports, and the 32-bit MMIO window.
fn pci_crs() -> ([u8; 128], usize) {
    let mut t = Table::<128>::new();
    // WordBusNumber: producer, min and max fixed, 0-0.
    t.u8(0x88).u16(13).u8(2).u8(0x0c).u8(0).u16(0).u16(0).u16(0).u16(0).u16(1);
    // IO(Decode16, 0xcf8, 0xcf8, 1, 8)
    t.u8(0x47).u8(1).u16(0xcf8).u16(0xcf8).u8(1).u8(8);
    // WordIO 0-0xcf7 and 0xd00-0xffff (ISA and non-ISA ranges).
    t.u8(0x88).u16(13).u8(1).u8(0x0c).u8(3).u16(0).u16(0).u16(0xcf7).u16(0).u16(0xcf8);
    t.u8(0x88).u16(13).u8(1).u8(0x0c).u8(3).u16(0).u16(0xd00).u16(0xffff).u16(0).u16(0xf300);
    // DWordMemory: read-write, non-cacheable, the window.
    let (base, size) = (pci::MMIO_BASE as u32, pci::MMIO_SIZE as u32);
    t.u8(0x87).u16(23).u8(0).u8(0x0c).u8(1).u32(0).u32(base).u32(base + (size - 1)).u32(0).u32(size);
    // End tag (no checksum).
    t.u8(0x79).u8(0);
    (t.b, t.len)
}

/// Write the DSDT's AML (after its header) into `a`.
fn dsdt_body(a: &mut Aml) {
    // \_S5: SLP_TYP for PM1a and PM1b.
    a.name(b"_S5_", |a| {
        a.package(4, |a| {
            a.int(pm::SLP_TYP_S5 as u64).int(pm::SLP_TYP_S5 as u64).int(0).int(0);
        });
    });
    // Scope (\_SB)
    a.pkg(&[0x10], |a| {
        a.raw(b"\\_SB_");
        a.device(b"PCI0", |a| {
            a.name(b"_HID", |a| {
                a.int(eisa_pnp(0x0a08));
            });
            a.name(b"_CID", |a| {
                a.int(eisa_pnp(0x0a03));
            });
            a.name(b"_SEG", |a| {
                a.int(0);
            });
            a.name(b"_BBN", |a| {
                a.int(0);
            });
            a.name(b"_UID", |a| {
                a.int(0);
            });
            let (crs, n) = pci_crs();
            a.name(b"_CRS", |a| {
                a.buffer(&crs[..n]);
            });
            // INTx of each slot's pins, straight to I/O APIC pins.
            a.name(b"_PRT", |a| {
                a.package(((pci::SLOTS - 1) * 4) as u8, |a| {
                    for slot in 1..pci::SLOTS {
                        for pin in 0..4u8 {
                            a.package(4, |a| {
                                a.int(((slot as u64) << 16) | 0xffff).int(pin as u64).int(0)
                                    .int(pci::intx_gsi(slot, pin + 1) as u64);
                            });
                        }
                    }
                });
            });
        });
    });
}

/// Write every table into `out` (the bytes from RSDP to END, at RSDP),
/// for `vcpus` vCPUs.
pub fn build(vcpus: usize, out: &mut [u8; (END - RSDP) as usize]) {
    out.fill(0);
    let mut put = |at: u64, b: &[u8]| {
        let o = (at - RSDP) as usize;
        out[o..o + b.len()].copy_from_slice(b);
    };

    // DSDT.
    let mut dsdt = Table::<8192>::new();
    dsdt.header(b"DSDT", 2);
    let mut body = [0u8; 8000];
    let mut aml = Aml::new(&mut body);
    dsdt_body(&mut aml);
    let n = aml.len();
    dsdt.bytes(&body[..n]);
    dsdt.finish();
    assert!(DSDT + dsdt.len as u64 <= END);
    put(DSDT, &dsdt.b[..dsdt.len]);

    // FACS: no checksum.
    let mut facs = Table::<64>::new();
    facs.bytes(b"FACS").u32(64).u32(0).u32(0).u32(0).u32(0).u64(0).u8(2);
    put(FACS, &facs.b[..64]);

    // FADT 6.1.
    let mut f = Table::<276>::new();
    f.header(b"FACP", 6);
    f.u32(FACS as u32).u32(DSDT as u32);
    f.u8(0).u8(0).u16(pm::SCI_IRQ as u16).u32(0);
    f.u8(0).u8(0).u8(0).u8(0);
    f.u32(pm::PM1_EVT as u32).u32(0).u32(pm::PM1_CNT as u32).u32(0).u32(0).u32(pm::PM_TMR as u32);
    f.u32(0).u32(0);
    f.u8(4).u8(2).u8(0).u8(4).u8(0).u8(0).u8(0).u8(0);
    // C2 and C3 unsupported (latencies over 100 and 1000 us).
    f.u16(101).u16(1001).u16(0).u16(0);
    f.u8(0).u8(0).u8(0).u8(0).u8(0x32);
    // IAPC_BOOT_ARCH: no VGA; no 8042.
    f.u16(1 << 2).u8(0);
    // Flags: WBINVD, C1, no sleep button, 32-bit PM timer, reset register.
    f.u32((1 << 0) | (1 << 2) | (1 << 5) | (1 << 8) | (1 << 10));
    f.gas_io(pm::RESET, 8).u8(6);
    f.u16(0).u8(1);
    f.u64(FACS).u64(DSDT);
    f.gas_io(pm::PM1_EVT, 32).gas_io(0, 0).gas_io(pm::PM1_CNT, 16).gas_io(0, 0).gas_io(0, 0);
    f.gas_io(pm::PM_TMR, 32).gas_io(0, 0).gas_io(0, 0).gas_io(0, 0).gas_io(0, 0);
    f.bytes(b"L4H\0\0\0\0\0");
    assert_eq!(f.len, 276);
    f.finish();
    put(FADT, &f.b[..f.len]);

    // MADT: no 8259 (PCAT_COMPAT clear).
    let mut m = Table::<1024>::new();
    m.header(b"APIC", 5);
    m.u32(crate::dev::lapic::BASE_ADDR as u32).u32(0);
    for v in 0..vcpus {
        m.u8(0).u8(8).u8(v as u8).u8(v as u8).u32(1);
    }
    m.u8(1).u8(12).u8(0).u8(0).u32(ioapic::BASE as u32).u32(0);
    // The SCI: ISA IRQ 9 is GSI 9, level-triggered, active high.
    m.u8(2).u8(10).u8(0).u8(pm::SCI_IRQ as u8).u32(pm::SCI_IRQ as u32).u16(0x000d);
    // LINT1 of every processor is NMI.
    m.u8(4).u8(6).u8(0xff).u16(0).u8(1);
    m.finish();
    assert!(MADT + m.len as u64 <= MCFG);
    put(MADT, &m.b[..m.len]);

    // MCFG: bus 0's ECAM.
    let mut c = Table::<64>::new();
    c.header(b"MCFG", 1).u64(0);
    c.u64(pci::ECAM_BASE).u16(0).u8(0).u8(0).u32(0);
    c.finish();
    put(MCFG, &c.b[..c.len]);

    // XSDT.
    let mut x = Table::<64>::new();
    x.header(b"XSDT", 1).u64(FADT).u64(MADT).u64(MCFG);
    x.finish();
    put(XSDT, &x.b[..x.len]);

    // RSDP 2.0: a checksum over the first 20 bytes, and over all 36.
    let mut r = Table::<36>::new();
    r.bytes(b"RSD PTR ").u8(0).bytes(OEM_ID).u8(2).u32(0).u32(36).u64(XSDT).u8(0).bytes(&[0; 3]);
    r.b[8] = checksum(&r.b[..20]);
    r.b[32] = checksum(&r.b[..36]);
    put(RSDP, &r.b[..36]);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    fn table(all: &[u8], at: u64) -> &[u8] {
        let o = (at - RSDP) as usize;
        let len = u32::from_le_bytes(all[o + 4..o + 8].try_into().unwrap()) as usize;
        &all[o..o + len]
    }

    #[test]
    fn tables_and_checksums() {
        let mut out = std::boxed::Box::new([0u8; (END - RSDP) as usize]);
        build(4, &mut out);
        // RSDP: both checksums, the XSDT.
        assert_eq!(&out[..8], b"RSD PTR ");
        assert_eq!(out[..20].iter().fold(0u8, |s, &b| s.wrapping_add(b)), 0);
        assert_eq!(out[..36].iter().fold(0u8, |s, &b| s.wrapping_add(b)), 0);
        assert_eq!(u64::from_le_bytes(out[24..32].try_into().unwrap()), XSDT);
        let sum = |t: &[u8]| t.iter().fold(0u8, |s, &b| s.wrapping_add(b));
        let xsdt = table(&out[..], XSDT);
        assert_eq!((&xsdt[..4], sum(xsdt)), (&b"XSDT"[..], 0));
        let entries: std::vec::Vec<u64> = xsdt[36..].chunks(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect();
        assert_eq!(entries, [FADT, MADT, MCFG]);
        for (at, sig) in [(FADT, b"FACP"), (MADT, b"APIC"), (MCFG, b"MCFG"), (DSDT, b"DSDT")] {
            let t = table(&out[..], at);
            assert_eq!(&t[..4], sig);
            assert_eq!(sum(t), 0, "{}", std::str::from_utf8(sig).unwrap());
        }
        // FADT: its blocks, SCI, the DSDT and FACS, no 8259 flag in MADT.
        let f = table(&out[..], FADT);
        assert_eq!(f.len(), 276);
        assert_eq!(u16::from_le_bytes([f[46], f[47]]), 9);
        assert_eq!(u32::from_le_bytes(f[56..60].try_into().unwrap()), 0x600);
        assert_eq!(u32::from_le_bytes(f[64..68].try_into().unwrap()), 0x604);
        assert_eq!(u32::from_le_bytes(f[76..80].try_into().unwrap()), 0x608);
        assert_eq!(u64::from_le_bytes(f[140..148].try_into().unwrap()), DSDT);
        assert_eq!(u64::from_le_bytes(f[120..128].try_into().unwrap()), 0xcf9);
        assert_eq!(f[128], 6);
        assert_eq!(&out[(FACS - RSDP) as usize..][..4], b"FACS");
        let m = table(&out[..], MADT);
        assert_eq!(u32::from_le_bytes(m[40..44].try_into().unwrap()), 0, "PCAT_COMPAT clear");
        assert_eq!((m[44], m[45], m[46], m[47]), (0, 8, 0, 0));
        // DSDT: \_S5_, PCI0's ids; the power button only the fixed one.
        let d = table(&out[..], DSDT);
        let has = |s: &[u8]| d.windows(s.len()).any(|w| w == s);
        assert!(has(b"_S5_") && has(b"PCI0") && has(b"_PRT") && has(b"_CRS"));
        assert!(has(&[0x0c, 0x41, 0xd0, 0x0a, 0x08]), "EisaId(PNP0A08)");
        assert!(!has(b"PWRB") && !has(&[0x0c, 0x41, 0xd0, 0x0c, 0x0c]), "no PNP0C0C");
        let flags = u32::from_le_bytes(f[112..116].try_into().unwrap());
        assert_eq!(flags & (1 << 4), 0, "PWR_BUTTON clear: the fixed power button");
    }

    #[test]
    fn aml_encodings() {
        let mut b = [0u8; 8192];
        let mut a = Aml::new(&mut b);
        a.int(0).int(1).int(5).int(0x1234).int(0x12345678).int(1 << 40);
        assert_eq!(&b[..1 + 1 + 2 + 3 + 5 + 9], &[0, 1, 0x0a, 5, 0x0b, 0x34, 0x12, 0x0c, 0x78, 0x56, 0x34, 0x12,
            0x0e, 0, 0, 0, 0, 0, 1, 0, 0][..21]);
        // Package lengths: one byte below 63, two below 4095.
        let mut b = [0u8; 8192];
        let mut a = Aml::new(&mut b);
        a.buffer(&[7; 10]);
        assert_eq!(&b[..4], &[0x11, 13, 0x0a, 10]);
        let mut b = [0u8; 8192];
        let mut a = Aml::new(&mut b);
        a.buffer(&[7; 100]);
        // Body: 0x0a 100 and 100 bytes = 102, plus 2 length bytes = 104.
        assert_eq!(&b[..3], &[0x11, 0x40 | (104 & 0xf), 104 >> 4]);
        assert_eq!(eisa_pnp(0x0a03), 0x030a_d041);
    }
}

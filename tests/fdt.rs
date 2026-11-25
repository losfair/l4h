// Run with tests/run-acstest.sh; no seL4 runtime is needed.  With
// L4H_TEST_QEMU_DTB_V2 / L4H_TEST_QEMU_DTB_V3 (QEMU virt's own device
// trees, gic-version=2 and 3) it also checks those.
#[path = "../host/l4h-root/src/fdt.rs"]
mod fdt;

use fdt::has_qemu_gicv2m;

/// A device tree, built as dtc would lay it out.
struct Builder {
    strct: Vec<u8>,
    strings: Vec<u8>,
}

impl Builder {
    fn new() -> Builder {
        Builder { strct: Vec::new(), strings: Vec::new() }
    }
    fn word(&mut self, w: u32) {
        self.strct.extend_from_slice(&w.to_be_bytes());
    }
    fn pad(&mut self) {
        while self.strct.len() % 4 != 0 {
            self.strct.push(0);
        }
    }
    fn begin(&mut self, name: &str) -> &mut Self {
        self.word(1);
        self.strct.extend_from_slice(name.as_bytes());
        self.strct.push(0);
        self.pad();
        self
    }
    fn end(&mut self) -> &mut Self {
        self.word(2);
        self
    }
    fn prop(&mut self, name: &str, value: &[u8]) -> &mut Self {
        let off = self.strings.len() as u32;
        self.strings.extend_from_slice(name.as_bytes());
        self.strings.push(0);
        self.word(3);
        self.word(value.len() as u32);
        self.word(off);
        self.strct.extend_from_slice(value);
        self.pad();
        self
    }
    fn cells(&mut self, name: &str, cells: &[u32]) -> &mut Self {
        let v: Vec<u8> = cells.iter().flat_map(|c| c.to_be_bytes()).collect();
        self.prop(name, &v)
    }
    fn finish(&mut self) -> Vec<u8> {
        self.word(9);
        let (off_rsv, off_struct) = (40u32, 56u32);
        let off_strings = off_struct + self.strct.len() as u32;
        let total = off_strings + self.strings.len() as u32;
        let mut b = Vec::new();
        for w in [0xd00d_feed, total, off_struct, off_strings, off_rsv, 17, 16, 0, self.strings.len() as u32, self.strct.len() as u32] {
            b.extend_from_slice(&w.to_be_bytes());
        }
        b.extend_from_slice(&[0; 16]); // an empty memory reservation map
        b.extend_from_slice(&self.strct);
        b.extend_from_slice(&self.strings);
        b
    }
}

/// QEMU virt's GIC with its GICv2m (gic-version=2), `v2m` adding to or
/// replacing the frame's properties, and `chosen` the /chosen node's.
fn qemu_virt(v2m: &dyn Fn(&mut Builder), intc_ranges: &[u8], chosen: &dyn Fn(&mut Builder)) -> Vec<u8> {
    let mut b = Builder::new();
    b.begin("").cells("#address-cells", &[2]).cells("#size-cells", &[2]).prop("compatible", b"linux,dummy-virt\0");
    b.begin("chosen");
    chosen(&mut b);
    b.end();
    b.begin("intc@8000000").cells("#address-cells", &[2]).cells("#size-cells", &[2]).prop("ranges", intc_ranges)
        .prop("compatible", b"arm,cortex-a15-gic\0").cells("reg", &[0, 0x0800_0000, 0, 0x10000, 0, 0x0801_0000, 0, 0x10000]);
    b.begin("v2m@8020000");
    v2m(&mut b);
    b.end();
    b.end();
    b.end();
    b.finish()
}

fn stock_v2m(b: &mut Builder) {
    b.cells("phandle", &[0x8003]).cells("reg", &[0, 0x0802_0000, 0, 0x1000]).prop("msi-controller", b"")
        .prop("compatible", b"arm,gic-v2m-frame\0");
}

fn nothing(_: &mut Builder) {}

#[test]
fn stock_qemu_virt_gicv2m() {
    assert!(has_qemu_gicv2m(&qemu_virt(&stock_v2m, b"", &nothing)));
}

#[test]
fn enabled_statuses_and_spis() {
    for status in [&b"okay\0"[..], b"ok\0"] {
        assert!(has_qemu_gicv2m(&qemu_virt(&|b| { stock_v2m(b); b.prop("status", status); }, b"", &nothing)));
    }
    assert!(has_qemu_gicv2m(&qemu_virt(&|b| {
        stock_v2m(b);
        b.cells("arm,msi-base-spi", &[80]).cells("arm,msi-num-spis", &[64]);
    }, b"", &nothing)));
}

#[test]
fn disabled_frame() {
    assert!(!has_qemu_gicv2m(&qemu_virt(&|b| { stock_v2m(b); b.prop("status", b"disabled\0"); }, b"", &nothing)));
    assert!(!has_qemu_gicv2m(&qemu_virt(&|b| { stock_v2m(b); b.prop("status", b"fail\0"); }, b"", &nothing)));
}

#[test]
fn string_elsewhere() {
    // In /chosen, not a node's compatible; and no frame.
    let dtb = qemu_virt(&|b| { b.cells("reg", &[0, 0x0802_0000, 0, 0x1000]); },
        b"", &|b| { b.prop("bootargs", b"arm,gic-v2m-frame\0"); });
    assert!(!has_qemu_gicv2m(&dtb));
    // A /chosen with the compatible and a reg of its own.
    let dtb = qemu_virt(&nothing, b"", &|b| {
        b.prop("compatible", b"arm,gic-v2m-frame\0").prop("msi-controller", b"").cells("reg", &[0, 0x0802_0000, 0, 0x1000]);
    });
    assert!(has_qemu_gicv2m(&dtb), "a real node anywhere counts");
    // A substring of another compatible.
    assert!(!has_qemu_gicv2m(&qemu_virt(&|b| {
        b.cells("reg", &[0, 0x0802_0000, 0, 0x1000]).prop("msi-controller", b"").prop("compatible", b"vendor,arm,gic-v2m-frame-x\0");
    }, b"", &nothing)));
}

#[test]
fn compatible_list() {
    assert!(has_qemu_gicv2m(&qemu_virt(&|b| {
        b.cells("reg", &[0, 0x0802_0000, 0, 0x1000]).prop("msi-controller", b"").prop("compatible", b"vendor,frame\0arm,gic-v2m-frame\0");
    }, b"", &nothing)));
}

#[test]
fn wrong_frame() {
    // Elsewhere, too small, not an MSI controller, other SPIs.
    for v2m in [
        &(|b: &mut Builder| { b.cells("reg", &[0, 0x0803_0000, 0, 0x1000]).prop("msi-controller", b"").prop("compatible", b"arm,gic-v2m-frame\0"); }) as &dyn Fn(&mut Builder),
        &|b: &mut Builder| { b.cells("reg", &[0, 0x0802_0000, 0, 0x800]).prop("msi-controller", b"").prop("compatible", b"arm,gic-v2m-frame\0"); },
        &|b: &mut Builder| { b.cells("reg", &[0, 0x0802_0000, 0, 0x1000]).prop("compatible", b"arm,gic-v2m-frame\0"); },
        &|b: &mut Builder| { stock_v2m(b); b.cells("arm,msi-base-spi", &[96]); },
        &|b: &mut Builder| { stock_v2m(b); b.cells("arm,msi-num-spis", &[32]); },
        &|b: &mut Builder| { b.cells("reg", &[0, 0x0802_0000]).prop("msi-controller", b"").prop("compatible", b"arm,gic-v2m-frame\0"); },
        &|b: &mut Builder| { b.prop("msi-controller", b"").prop("compatible", b"arm,gic-v2m-frame\0"); },
    ] {
        assert!(!has_qemu_gicv2m(&qemu_virt(v2m, b"", &nothing)));
    }
}

#[test]
fn translated_parent() {
    // A non-empty ranges: the frame's reg is not a CPU address.
    let ranges: Vec<u8> = [0u32, 0, 0, 0x1000_0000, 0, 0x100_0000].iter().flat_map(|c| c.to_be_bytes()).collect();
    assert!(!has_qemu_gicv2m(&qemu_virt(&stock_v2m, &ranges, &nothing)));
}

#[test]
fn corrupt_trees() {
    let good = qemu_virt(&stock_v2m, b"", &nothing);
    assert!(!has_qemu_gicv2m(&[]));
    for len in [3, 39, 40, 60, good.len() / 2, good.len() - 1] {
        assert!(!has_qemu_gicv2m(&good[..len]), "truncated to {}", len);
    }
    let mut bad = good.clone();
    bad[0] = 0;
    assert!(!has_qemu_gicv2m(&bad), "magic");
    let mut bad = good.clone();
    bad[4..8].copy_from_slice(&(good.len() as u32 + 1).to_be_bytes());
    assert!(!has_qemu_gicv2m(&bad), "totalsize past the buffer");
    let mut bad = good.clone();
    bad[36..40].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(!has_qemu_gicv2m(&bad), "size_dt_struct");
    let mut bad = good.clone();
    bad[12..16].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(!has_qemu_gicv2m(&bad), "off_dt_strings");
    // Every single-byte corruption ends, whatever it says.
    for i in 0..good.len() {
        let mut bad = good.clone();
        bad[i] ^= 0xff;
        let _ = has_qemu_gicv2m(&bad);
    }
    // Nodes nested past the walker's depth.
    let mut b = Builder::new();
    for _ in 0..40 {
        b.begin("n");
    }
    assert!(!has_qemu_gicv2m(&b.finish()));
}

#[test]
fn qemu_device_trees() {
    if let Ok(p) = std::env::var("L4H_TEST_QEMU_DTB_V2") {
        assert!(has_qemu_gicv2m(&std::fs::read(p).unwrap()), "QEMU virt, gic-version=2");
    }
    if let Ok(p) = std::env::var("L4H_TEST_QEMU_DTB_V3") {
        assert!(!has_qemu_gicv2m(&std::fs::read(p).unwrap()), "QEMU virt, gic-version=3 (an ITS, no GICv2m)");
    }
}

#[test]
fn parent_without_ranges() {
    // QEMU's tree as it is, but the GIC without its empty ranges: its
    // children's addresses are then no CPU addresses.
    let mut b = Builder::new();
    b.begin("").cells("#address-cells", &[2]).cells("#size-cells", &[2]);
    b.begin("intc@8000000").cells("#address-cells", &[2]).cells("#size-cells", &[2]);
    b.begin("v2m@8020000");
    stock_v2m(&mut b);
    b.end().end().end();
    assert!(!has_qemu_gicv2m(&b.finish()));
}

#[test]
fn disabled_parent() {
    let mut b = Builder::new();
    b.begin("").cells("#address-cells", &[2]).cells("#size-cells", &[2]);
    b.begin("intc@8000000").cells("#address-cells", &[2]).cells("#size-cells", &[2]).prop("ranges", b"")
        .prop("status", b"disabled\0");
    b.begin("v2m@8020000");
    stock_v2m(&mut b);
    b.end().end().end();
    assert!(!has_qemu_gicv2m(&b.finish()));
}

#[test]
fn unfinished_tree() {
    // A good frame, then no FDT_END, or nodes left open.
    let header = |strct: &[u8], strings: &[u8]| {
        let (off_struct, off_strings) = (56u32, 56 + strct.len() as u32);
        let total = off_strings + strings.len() as u32;
        let mut d = Vec::new();
        for w in [0xd00d_feed, total, off_struct, off_strings, 40, 17, 16, 0, strings.len() as u32, strct.len() as u32] {
            d.extend_from_slice(&w.to_be_bytes());
        }
        d.extend_from_slice(&[0; 16]);
        d.extend_from_slice(strct);
        d.extend_from_slice(strings);
        d
    };
    let mut b = Builder::new();
    b.begin("").cells("#address-cells", &[2]).cells("#size-cells", &[2]);
    b.begin("intc@8000000").cells("#address-cells", &[2]).cells("#size-cells", &[2]).prop("ranges", b"");
    b.begin("v2m@8020000");
    stock_v2m(&mut b);
    b.end();
    // Two nodes still open, then FDT_END.
    let mut open = Builder { strct: b.strct.clone(), strings: b.strings.clone() };
    assert!(!has_qemu_gicv2m(&open.finish()), "unclosed nodes");
    // Closed, without FDT_END.
    b.end().end();
    assert!(!has_qemu_gicv2m(&header(&b.strct, &b.strings)), "no FDT_END");
    // With it: the same tree is good.
    assert!(has_qemu_gicv2m(&b.finish()));
}

/// An ACPI table: `sig`, its header's length field, then `body` at 36.
fn acpi_table(sig: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let mut t = vec![0; 36];
    t[..4].copy_from_slice(sig);
    t.extend_from_slice(body);
    let len = t.len() as u32;
    t[4..8].copy_from_slice(&len.to_le_bytes());
    t
}

/// An SPCR of interface type `ty` with its console at `addr` (space 0).
fn spcr(ty: u8, addr: u64) -> Vec<u8> {
    // At 36 the type; at 40 the address structure: space 0, 32 bits wide,
    // dword accesses, the address at 44.
    let mut b = vec![0; 44];
    b[0] = ty;
    b[4..8].copy_from_slice(&[0, 32, 0, 3]);
    b[8..16].copy_from_slice(&addr.to_le_bytes());
    acpi_table(b"SPCR", &b)
}

/// An MCFG of (base, segment, start bus, end bus) entries.
fn mcfg(entries: &[(u64, u16, u8, u8)]) -> Vec<u8> {
    let mut b = vec![0; 8];
    for &(base, seg, start, end) in entries {
        b.extend_from_slice(&base.to_le_bytes());
        b.extend_from_slice(&seg.to_le_bytes());
        b.extend_from_slice(&[start, end, 0, 0, 0, 0]);
    }
    acpi_table(b"MCFG", &b)
}

#[test]
fn acpi_on_a_virt_like_vm_keeps_its_defaults() {
    // GCE's C4A: virt's PL011, no MCFG read.
    let hw = fdt::from_acpi(Some(&spcr(0x03, 0x0900_0000)), None);
    assert_eq!(hw, fdt::ArmHw::qemu_virt_default());
    // No SPCR at all: the defaults, as before.
    assert_eq!(fdt::from_acpi(None, None), fdt::ArmHw::qemu_virt_default());
}

#[test]
fn acpi_on_bare_metal_takes_its_console_and_ecam() {
    let m = mcfg(&[(0x4000_0000_0000, 1, 0, 255), (0x3000_0000_0000, 0, 0, 255)]);
    let hw = fdt::from_acpi(Some(&spcr(0x0e, 0x2_0000_0000)), Some(&m));
    assert_eq!(hw.pl011_base, Some(0x2_0000_0000));
    // Segment 0's, at most the 16 buses root maps.
    assert_eq!(hw.pci_ecam, (0x3000_0000_0000, 16 << 20));
    // Nothing of virt's that could be another device there.
    assert_eq!((hw.pl031_base, hw.pci_mmio32, hw.gicv2m), (None, (0, 0), None));
    // Without an MCFG, no ECAM; with a 16550 console, none.
    let hw = fdt::from_acpi(Some(&spcr(0x00, 0x2_0000_0000)), None);
    assert_eq!((hw.pl011_base, hw.pci_ecam), (None, (0, 0)));
    // A window that starts past bus 0 is not one root can map.
    let hw = fdt::from_acpi(Some(&spcr(0x03, 0x2_0000_0000)), Some(&mcfg(&[(0x3000_0000_0000, 0, 1, 255)])));
    assert_eq!(hw.pci_ecam, (0, 0));
}

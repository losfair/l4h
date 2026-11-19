//! AMD-Vi IVHD device entries (host/l4h-root/src/amdvi.rs `devices`),
//! extracted unchanged by tests/run-devicetest.sh.
#![allow(dead_code)]

macro_rules! info { ($($arg:tt)*) => { println!($($arg)*) }; }
macro_rules! log { ($($arg:tt)*) => { println!($($arg)*) }; }

const DEVICES: usize = 1 << 16;

struct DevInfo {
    flags: Vec<u8>,
    covered: Vec<u64>,
    special: Vec<u64>,
    alias: Vec<u16>,
}

struct AmdVi;

include!(env!("L4H_AMDVI_IVHD_TEST_SRC"));

fn dev() -> DevInfo {
    DevInfo { flags: vec![0; DEVICES], covered: vec![0; DEVICES / 64], special: vec![0; DEVICES / 64], alias: vec![0; DEVICES] }
}

/// A 4-byte entry (types below 0x40).
fn e4(kind: u8, id: u16, flags: u8) -> Vec<u8> {
    let mut e = vec![kind];
    e.extend(id.to_le_bytes());
    e.push(flags);
    e
}

/// An 8-byte entry with a second device ID at byte 5 (alias, special).
fn e8(kind: u8, id: u16, flags: u8, other: u16, variety: u8) -> Vec<u8> {
    let mut e = e4(kind, id, flags);
    e.push(0);
    e.extend(other.to_le_bytes());
    e.push(variety);
    e
}

#[test]
fn known_entries_are_read() {
    let mut d = dev();
    let entries = [e4(0x02, 0x0008, 0), e8(0x42, 0x0100, 0, 0x00f8, 0), e8(0x48, 0, 0xd7, 0x00a0, 1)].concat();
    assert_eq!(AmdVi::devices(&entries, &mut d), Some(()));
    assert!(d.covered(0x0008) && d.covered(0x0100) && d.covered(0x00f8));
    assert_eq!(d.alias[0x0100], 0x00f8);
    assert_ne!(d.special[0x00a0 / 64] & 1 << (0x00a0 % 64), 0);
}

#[test]
fn an_unknown_entry_fails_the_ivhd() {
    // An entry of a type the parser does not know (0x80..=0xef, 0xf1..):
    // the length of what follows is unknown, and with it an alias or the
    // I/O APIC's special entry after it.  Read as far as that, the
    // IOMMU would be enabled with the device behind the bridge in its own
    // domain while its DMA arrives as the bridge's.
    for kind in [0x80u8, 0xbf, 0xc0, 0xef, 0xf1, 0xff] {
        let mut d = dev();
        let mut entries = e4(0x02, 0x0008, 0);
        entries.extend(e4(kind, 0x0010, 0));
        entries.extend(e8(0x42, 0x0100, 0, 0x00f8, 0));
        assert_eq!(AmdVi::devices(&entries, &mut d), None, "type {kind:#x}");
    }
}

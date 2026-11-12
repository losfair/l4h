// Run with tests/run-acstest.sh; no seL4 runtime is needed.
#[path = "../host/l4h-root/src/acs.rs"]
mod acs;

use acs::{Acs, Bits, Config, CR, RR, SV, TB, UF};
use std::cell::RefCell;
use std::collections::HashMap;

const EC: u16 = 1 << 5;
const DT: u16 = 1 << 6;

/// A function's configuration space, and which ACS control bits stick.
#[derive(Clone)]
struct Func {
    space: [u32; 1024],
    acs: Option<u16>,
    sticks: u16,
}

impl Func {
    /// A PCIe function of Device/Port Type `ty`, with an AER capability
    /// at 0x100 and, if `acs` is (cap, ctrl), ACS at 0x148.
    fn pcie(ty: u8, acs: Option<(u16, u16)>) -> Func {
        let mut space = [0u32; 1024];
        space[0] = 0x1234_8086;
        space[1] = 1 << 20; // capability list
        space[0x34 / 4] = 0x40;
        space[0x40 / 4] = 0x10 | (ty as u32) << 20;
        space[0x100 / 4] = 0x0001 | 1 << 16 | (if acs.is_some() { 0x148 } else { 0 }) << 20;
        if let Some((cap, ctrl)) = acs {
            space[0x148 / 4] = 0x000d | 1 << 16;
            space[0x14c / 4] = cap as u32 | (ctrl as u32) << 16;
        }
        Func { space, acs: acs.map(|_| 0x148), sticks: 0x7f }
    }

    /// A bridge whose secondary bus is `secondary`.
    fn bridge(mut self, secondary: u8) -> Func {
        self.space[0x18 / 4] = (secondary as u32) << 8 | (secondary as u32) << 16;
        self
    }

    fn ctrl(&self) -> u16 {
        (self.space[self.acs.unwrap() as usize / 4 + 1] >> 16) as u16
    }
}

struct Model {
    funcs: RefCell<HashMap<u16, Func>>,
    /// Extended space can be read, and written.
    ext: bool,
    writable: bool,
    writes: RefCell<usize>,
}

impl Model {
    fn new(funcs: &[(u16, Func)]) -> Model {
        Model { funcs: RefCell::new(funcs.iter().cloned().collect()), ext: true, writable: true, writes: RefCell::new(0) }
    }
    fn func(&self, bdf: u16) -> Func {
        self.funcs.borrow()[&bdf].clone()
    }
}

impl Config for Model {
    fn read(&self, bdf: u16, off: u8) -> u32 {
        self.funcs.borrow().get(&bdf).map_or(u32::MAX, |f| f.space[off as usize / 4])
    }
    fn read_ext(&self, bdf: u16, off: u16) -> Option<u32> {
        if !self.ext || off >= 4096 {
            return None;
        }
        Some(self.funcs.borrow().get(&bdf).map_or(u32::MAX, |f| f.space[off as usize / 4]))
    }
    fn write_ext(&self, bdf: u16, off: u16, val: u32) -> bool {
        if !self.writable {
            return false;
        }
        *self.writes.borrow_mut() += 1;
        let mut funcs = self.funcs.borrow_mut();
        let f = funcs.get_mut(&bdf).unwrap();
        let i = off as usize / 4;
        if Some(off) == f.acs.map(|a| a + 4) {
            // The capability half is read-only; control keeps what sticks.
            let ctrl = (val >> 16) as u16 & f.sticks;
            f.space[i] = f.space[i] & 0xffff | (ctrl as u32) << 16;
        } else {
            f.space[i] = val;
        }
        true
    }
}

const PORT: u16 = 0x0008; // 00:01.0

#[test]
fn a_port_gets_every_bit_it_implements() {
    let m = Model::new(&[(PORT, Func::pcie(acs::DOWNSTREAM_PORT, Some((SV | TB | RR | CR | UF | EC | DT, 0))))]);
    let r = acs::enable(&m, PORT);
    assert_eq!(r, Acs::Present { cap: SV | TB | RR | CR | UF | EC | DT, before: 0, after: SV | TB | RR | CR | UF });
    assert_eq!(m.func(PORT).ctrl(), SV | TB | RR | CR | UF);
    // The capability register is unchanged.
    assert_eq!(m.func(PORT).space[0x14c / 4] as u16, SV | TB | RR | CR | UF | EC | DT);
    assert!(r.isolates());
}

#[test]
fn only_implemented_bits_are_set_and_count() {
    // A root port that implements no Upstream Forwarding (it has nothing
    // above it to forward to) nor Translation Blocking.
    let m = Model::new(&[(PORT, Func::pcie(acs::ROOT_PORT, Some((SV | RR | CR, 0))))]);
    let r = acs::enable(&m, PORT);
    assert_eq!(r, Acs::Present { cap: SV | RR | CR, before: 0, after: SV | RR | CR });
    assert!(r.isolates());
}

#[test]
fn bits_firmware_set_are_kept() {
    let m = Model::new(&[(PORT, Func::pcie(acs::DOWNSTREAM_PORT, Some((SV | RR | CR | UF | EC, EC))))]);
    assert_eq!(acs::enable(&m, PORT), Acs::Present { cap: SV | RR | CR | UF | EC, before: EC, after: SV | RR | CR | UF | EC });
}

#[test]
fn nothing_is_written_when_all_is_on() {
    let all = SV | TB | RR | CR | UF;
    let m = Model::new(&[(PORT, Func::pcie(acs::DOWNSTREAM_PORT, Some((all, all))))]);
    assert!(acs::enable(&m, PORT).isolates());
    assert_eq!(*m.writes.borrow(), 0);
}

#[test]
fn a_bit_that_does_not_stick_is_reported() {
    let mut f = Func::pcie(acs::DOWNSTREAM_PORT, Some((SV | RR | CR | UF, 0)));
    f.sticks = SV | CR | UF;
    let m = Model::new(&[(PORT, f)]);
    let r = acs::enable(&m, PORT);
    assert_eq!(r, Acs::Present { cap: SV | RR | CR | UF, before: 0, after: SV | CR | UF });
    assert!(!r.isolates());
}

#[test]
fn a_function_without_acs() {
    let m = Model::new(&[(PORT, Func::pcie(acs::ROOT_PORT, None))]);
    let r = acs::enable(&m, PORT);
    assert_eq!(r, Acs::Absent);
    assert!(!r.isolates());
    assert_eq!(*m.writes.borrow(), 0);
}

#[test]
fn unreachable_or_read_only_extended_space() {
    let mut m = Model::new(&[(PORT, Func::pcie(acs::ROOT_PORT, Some((SV | RR | CR, 0))))]);
    m.ext = false;
    assert_eq!(acs::enable(&m, PORT), Acs::Unreachable);
    m.ext = true;
    m.writable = false;
    assert_eq!(acs::enable(&m, PORT), Acs::Unreachable);
    assert!(!Acs::Unreachable.isolates());
}

#[test]
fn hostile_extended_lists_end() {
    let lists: [&[(usize, u32)]; 5] = [
        // Points at itself.
        &[(0x100, 0x0001 | 0x100 << 20)],
        // A loop of two.
        &[(0x100, 0x0001 | 0x200 << 20), (0x200, 0x0002 | 0x100 << 20)],
        // Into the first 256 bytes.
        &[(0x100, 0x0001 | 0x040 << 20)],
        // All ones: no function, or nothing there.
        &[(0x100, u32::MAX)],
        // The last dword, then an unaligned pointer (masked) to a loop.
        &[(0x100, 0x0001 | 0xffc << 20), (0xffc, 0x0001 | 0xffe << 20)],
    ];
    for list in lists {
        let mut f = Func::pcie(acs::DOWNSTREAM_PORT, None);
        for &(off, v) in list {
            f.space[off / 4] = v;
        }
        let m = Model::new(&[(PORT, f)]);
        assert_eq!(acs::enable(&m, PORT), Acs::Absent);
        assert_eq!(*m.writes.borrow(), 0);
    }
}

#[test]
fn an_empty_extended_space_has_no_acs() {
    let mut f = Func::pcie(acs::DOWNSTREAM_PORT, None);
    f.space[0x100 / 4] = 0;
    assert_eq!(acs::enable(&Model::new(&[(PORT, f)]), PORT), Acs::Absent);
}

#[test]
fn pcie_type_follows_only_sane_lists() {
    let m = Model::new(&[(PORT, Func::pcie(acs::DOWNSTREAM_PORT, None))]);
    assert_eq!(acs::pcie_type(&m, PORT), Some(acs::DOWNSTREAM_PORT));
    let mut f = Func::pcie(acs::ROOT_PORT, None);
    f.space[0x40 / 4] = 0x01 | 0x40 << 8; // a power management capability pointing at itself
    assert_eq!(acs::pcie_type(&Model::new(&[(PORT, f)]), PORT), None);
    let mut f = Func::pcie(acs::ROOT_PORT, None);
    f.space[0x34 / 4] = 0x20; // into the header
    assert_eq!(acs::pcie_type(&Model::new(&[(PORT, f)]), PORT), None);
    let mut f = Func::pcie(acs::ROOT_PORT, None);
    f.space[1] = 0; // no capability list
    assert_eq!(acs::pcie_type(&Model::new(&[(PORT, f)]), PORT), None);
    assert_eq!(acs::pcie_type(&m, 0x0010), None); // no function
}

#[test]
fn children_are_functions_on_the_secondary_bus() {
    let port = Func::pcie(acs::ROOT_PORT, None).bridge(2);
    let child = Func::pcie(0, None);
    assert!(!acs::has_children(&Model::new(&[(PORT, port.clone())]), PORT));
    assert!(acs::has_children(&Model::new(&[(PORT, port), (0x0218, child)]), PORT)); // 02:03.0
    // A disabled bridge, and one naming its own bus.
    let m = Model::new(&[(PORT, Func::pcie(acs::ROOT_PORT, None)), (0x0000, Func::pcie(0, None))]);
    assert!(!acs::has_children(&m, PORT));
    let looped = Func::pcie(acs::ROOT_PORT, None).bridge(1);
    assert!(!acs::has_children(&Model::new(&[(0x0108, looped.clone()), (0x0100, looped)]), 0x0108));
}

#[test]
fn bits_print_by_name() {
    assert_eq!(Bits(SV | RR | CR | UF).to_string(), "SV RR CR UF");
    assert_eq!(Bits(TB | EC | DT).to_string(), "TB EC DT");
    assert_eq!(Bits(0).to_string(), "none");
}

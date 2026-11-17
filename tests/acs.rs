// Run with tests/run-acstest.sh; no seL4 runtime is needed.
#[path = "../host/l4h-root/src/acs.rs"]
mod acs;

use acs::{Acs, Bits, Config, CR, DT, RR, SV, TB, UF};
use std::cell::RefCell;
use std::collections::HashMap;

const EC: u16 = 1 << 5;

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
        self.space[0x0c / 4] |= 1 << 16;
        self.space[0x18 / 4] = (secondary as u32) << 8 | (secondary as u32) << 16;
        self
    }

    /// Function 0 of a device with several (the multi-function bit).
    fn multi(mut self) -> Func {
        self.space[0x0c / 4] |= 0x80 << 16;
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
    assert!(r.isolates(Some(acs::DOWNSTREAM_PORT)));
}

#[test]
fn only_implemented_bits_are_set_and_count() {
    // A root port that implements no Upstream Forwarding (it has nothing
    // above it to forward to) nor Translation Blocking.
    let m = Model::new(&[(PORT, Func::pcie(acs::ROOT_PORT, Some((SV | RR | CR, 0))))]);
    let r = acs::enable(&m, PORT);
    assert_eq!(r, Acs::Present { cap: SV | RR | CR, before: 0, after: SV | RR | CR });
    assert!(r.isolates(Some(acs::ROOT_PORT)));
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
    assert!(acs::enable(&m, PORT).isolates(Some(acs::DOWNSTREAM_PORT)));
    assert_eq!(*m.writes.borrow(), 0);
}

#[test]
fn a_bit_that_does_not_stick_is_reported() {
    let mut f = Func::pcie(acs::DOWNSTREAM_PORT, Some((SV | RR | CR | UF, 0)));
    f.sticks = SV | CR | UF;
    let m = Model::new(&[(PORT, f)]);
    let r = acs::enable(&m, PORT);
    assert_eq!(r, Acs::Present { cap: SV | RR | CR | UF, before: 0, after: SV | CR | UF });
    assert!(!r.isolates(Some(acs::DOWNSTREAM_PORT)));
}

#[test]
fn a_function_without_acs() {
    let m = Model::new(&[(PORT, Func::pcie(acs::ROOT_PORT, None))]);
    let r = acs::enable(&m, PORT);
    assert_eq!(r, Acs::Absent);
    assert!(!r.isolates(Some(acs::ROOT_PORT)));
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
    assert!(!Acs::Unreachable.isolates(Some(acs::ROOT_PORT)));
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
    // Only function 1 below it visible (a partition's).
    let m = Model::new(&[(PORT, Func::pcie(acs::ROOT_PORT, None).bridge(2)), (0x0201, Func::pcie(0, None))]);
    assert!(acs::has_children(&m, PORT));
    let looped = Func::pcie(acs::ROOT_PORT, None).bridge(1);
    assert!(!acs::has_children(&Model::new(&[(0x0108, looped.clone()), (0x0100, looped)]), 0x0108));
}

#[test]
fn bits_print_by_name() {
    assert_eq!(Bits(SV | RR | CR | UF).to_string(), "SV RR CR UF");
    assert_eq!(Bits(TB | EC | DT).to_string(), "TB EC DT");
    assert_eq!(Bits(0).to_string(), "none");
}

#[test]
fn state_reads_without_writing() {
    let m = Model::new(&[(PORT, Func::pcie(acs::ROOT_PORT, Some((SV | RR | CR, SV))))]);
    let r = acs::state(&m, PORT);
    assert_eq!(r, Acs::Present { cap: SV | RR | CR, before: SV, after: SV });
    assert!(!r.isolates(Some(acs::ROOT_PORT)));
    assert_eq!(*m.writes.borrow(), 0);
    assert_eq!(acs::state(&Model::new(&[(PORT, Func::pcie(acs::ROOT_PORT, None))]), PORT), Acs::Absent);
}

/// Every byte of [start, end) once, in order, each block aligned to its
/// size physically and at its offset from `base` (where it is mapped),
/// and within `limit`.
fn check_blocks_in(start: u64, end: u64, base: u64, limit: impl Fn(u64) -> u32 + Copy) -> Vec<(u64, u32)> {
    let blocks: Vec<_> = acs::blocks(start, end, base, limit).collect();
    let mut at = start;
    for &(b, bits) in &blocks {
        assert_eq!(b, at);
        assert!(bits >= 12 && bits <= limit(b));
        assert_eq!(b % (1 << bits), 0);
        assert_eq!((b - base) % (1 << bits), 0);
        at += 1 << bits;
    }
    assert_eq!(at, end.max(start));
    blocks
}

fn check_blocks(start: u64, end: u64) -> Vec<(u64, u32)> {
    check_blocks_in(start, end, start & !0xfff_ffff, |_| 63)
}

#[test]
fn ecam_windows_map_in_few_aligned_blocks() {
    // A whole 256 MiB window, at an aligned base: one block.
    assert_eq!(check_blocks(0xb000_0000, 0xc000_0000), [(0xb000_0000, 28)]);
    // Buses 00-7f and 80-ff of a split window.
    assert_eq!(check_blocks(0xe000_0000, 0xe800_0000), [(0xe000_0000, 27)]);
    assert_eq!(check_blocks(0xf000_0000 + (0x80 << 20), 0xf000_0000 + (0x100 << 20)), [(0xf800_0000, 27)]);
    // Odd first and last buses, at a 1 MiB-aligned position: 1 MiB of
    // 4 KiB frames at each end, 2 MiB frames between.
    let b = check_blocks(0x8000_0000 + (1 << 20), 0x8000_0000 + (0x40 << 20) - (1 << 20));
    assert_eq!(b.first(), Some(&(0x8010_0000, 20)));
    assert_eq!(b.last(), Some(&(0x83e0_0000, 20)));
    assert!(b.iter().filter(|&&(_, bits)| bits < 21).count() == 2);
    assert!(b.len() <= 12);
    // One bus; nothing.
    assert_eq!(check_blocks(0x9000_0000, 0x9010_0000), [(0x9000_0000, 20)]);
    assert!(check_blocks(0x9000_0000, 0x9000_0000).is_empty());
    // Every window of whole buses ends where it should.
    for lo in 0..=255u64 {
        for hi in (lo..=255).step_by(7) {
            check_blocks(0xc000_0000 + (lo << 20), 0xc000_0000 + ((hi + 1) << 20));
        }
    }
    // A base 1 MiB but not 2 MiB aligned: no block may be 2 MiB aligned
    // physically but not virtually, which seL4 would refuse (and root
    // would panic on), so it is all 1 MiB blocks of 4 KiB frames.
    let b = check_blocks_in(0x8010_0000, 0x8010_0000 + (4 << 20), 0x8010_0000, |_| 63);
    assert!(b.iter().all(|&(_, bits)| bits == 20), "{b:x?}");
    // Two free Untypeds of 64 MiB meeting at 0xa400_0000: no block
    // crosses them.
    let b = check_blocks_in(0xa000_0000, 0xa800_0000, 0xa000_0000, |_| 26);
    assert_eq!(b, [(0xa000_0000, 26), (0xa400_0000, 26)]);
    // No free memory at a block: the list ends with it, under 12 bits.
    let b: Vec<_> = acs::blocks(0xa000_0000, 0xa800_0000, 0xa000_0000, |at| if at >= 0xa400_0000 { 0 } else { 26 }).collect();
    assert_eq!(b, [(0xa000_0000, 26), (0xa400_0000, 0)]);
}

fn group_in(m: &Model, inventory: &[u16], me: u16) -> Vec<u16> {
    let mut g = Vec::new();
    acs::group(m, || inventory.iter().copied(), me, |b| if !g.contains(&b) { g.push(b) });
    g.sort();
    g
}

#[test]
fn a_function_shares_its_group_with_function_0_without_acs() {
    // virtio-blk at 00:05.0 says it has several functions; e1000e at
    // 00:05.1 does not, as only function 0 need.
    let m = Model::new(&[(0x0028, Func::pcie(0, None).multi()), (0x0029, Func::pcie(0, None))]);
    assert_eq!(group_in(&m, &[0x0028, 0x0029], 0x0029), [0x0028, 0x0029]);
    assert_eq!(group_in(&m, &[0x0028, 0x0029], 0x0028), [0x0028, 0x0029]);
    // ACS on one function alone does not keep it apart: the other still
    // reaches it, whichever is asked about.
    let all = SV | RR | CR | UF;
    let m = Model::new(&[(0x0028, Func::pcie(0, None).multi()), (0x0029, Func::pcie(0, Some((all, all))))]);
    assert_eq!(group_in(&m, &[0x0028, 0x0029], 0x0029), [0x0028, 0x0029]);
    assert_eq!(group_in(&m, &[0x0028, 0x0029], 0x0028), [0x0028, 0x0029]);
    let m = Model::new(&[(0x0028, Func::pcie(0, Some((all, all))).multi()), (0x0029, Func::pcie(0, None))]);
    assert_eq!(group_in(&m, &[0x0028, 0x0029], 0x0029), [0x0028, 0x0029]);
    assert_eq!(group_in(&m, &[0x0028, 0x0029], 0x0028), [0x0028, 0x0029]);
    // ACS on both does.
    let m = Model::new(&[(0x0028, Func::pcie(0, Some((all, all))).multi()), (0x0029, Func::pcie(0, Some((all, all))))]);
    assert_eq!(group_in(&m, &[0x0028, 0x0029], 0x0029), [0x0029]);
    assert_eq!(group_in(&m, &[0x0028, 0x0029], 0x0028), [0x0028]);
}

#[test]
fn an_endpoint_that_routes_between_its_functions_must_redirect() {
    let m = |cap| Model::new(&[(0x0028, Func::pcie(0, Some((cap, cap))).multi()), (0x0029, Func::pcie(0, Some((cap, cap))))]);
    // Direct Translated P2P without Redirect: a path between them.
    assert_eq!(group_in(&m(DT), &[0x0028, 0x0029], 0x0029), [0x0028, 0x0029]);
    assert_eq!(group_in(&m(DT | RR | CR), &[0x0028, 0x0029], 0x0029), [0x0029]);
    // A capability with no bits says there is no path between them.
    assert_eq!(group_in(&m(0), &[0x0028, 0x0029], 0x0029), [0x0029]);
    // Implemented but off.
    let m = Model::new(&[(0x0028, Func::pcie(0, Some((RR | CR, RR))).multi()), (0x0029, Func::pcie(0, Some((0, 0))))]);
    assert_eq!(group_in(&m, &[0x0028, 0x0029], 0x0029), [0x0028, 0x0029]);
}

#[test]
fn a_port_must_implement_what_its_type_needs() {
    let present = |cap: u16| Acs::Present { cap, before: 0, after: cap };
    // A root port without Source Validation, whatever else it has.
    assert!(!present(TB | EC).isolates(Some(acs::ROOT_PORT)));
    assert!(!present(0).isolates(Some(acs::ROOT_PORT)));
    assert!(!present(TB | RR | CR | UF).isolates(Some(acs::ROOT_PORT)));
    assert!(present(SV).isolates(Some(acs::ROOT_PORT)));
    assert!(present(SV | TB | RR | CR).isolates(Some(acs::ROOT_PORT)));
    // A downstream port without Upstream Forwarding or Source Validation.
    assert!(!present(SV | RR | CR).isolates(Some(acs::DOWNSTREAM_PORT)));
    assert!(!present(RR | CR | UF).isolates(Some(acs::DOWNSTREAM_PORT)));
    assert!(!present(TB | EC | DT).isolates(Some(acs::DOWNSTREAM_PORT)));
    assert!(present(SV | UF).isolates(Some(acs::DOWNSTREAM_PORT)));
    assert!(present(SV | RR | CR | UF).isolates(Some(acs::DOWNSTREAM_PORT)));
    // Implemented and needed, but off.
    assert!(!Acs::Present { cap: SV | UF, before: 0, after: SV }.isolates(Some(acs::DOWNSTREAM_PORT)));
    // An upstream port, a PCI bridge, a PCIe-to-PCI bridge: never.
    let all = SV | TB | RR | CR | UF;
    for ty in [Some(acs::UPSTREAM_PORT), None, Some(7), Some(8), Some(10)] {
        assert!(!present(all).isolates(ty), "{ty:?}");
    }
    // Endpoints.
    for ty in [acs::ENDPOINT, acs::LEGACY_ENDPOINT, acs::RC_ENDPOINT] {
        assert!(present(0).isolates(Some(ty)));
        assert!(!present(DT).isolates(Some(ty)));
        assert!(!present(DT | RR).isolates(Some(ty)));
        assert!(present(DT | RR | CR).isolates(Some(ty)));
        assert!(!Acs::Present { cap: RR | CR, before: 0, after: RR }.isolates(Some(ty)));
        assert!(!Acs::Absent.isolates(Some(ty)));
    }
}

#[test]
fn a_port_missing_a_needed_bit_does_not_isolate_its_children() {
    // A root port with ACS that has only TB and EC, a downstream port
    // without UF: neither isolates.
    for (cap, ty) in [(TB | EC, acs::ROOT_PORT), (SV | RR | CR, acs::DOWNSTREAM_PORT)] {
        // Two devices below it, each alone in its slot.
        let m = Model::new(&[(0x0008, Func::pcie(ty, Some((cap, cap))).bridge(2)), (0x0200, Func::pcie(0, None)),
            (0x0208, Func::pcie(0, None))]);
        let inventory = [0x0008, 0x0200, 0x0208];
        assert_eq!(group_in(&m, &inventory, 0x0200), [0x0200, 0x0208], "{ty}");
        assert!(!acs::state(&m, 0x0008).isolates(Some(ty)));
    }
}

const ALL: u16 = SV | RR | CR | UF;

/// Two root ports on bus 0, 00:01.0 (bus 2) and 00:02.0 (bus 3), each
/// with an endpoint below it, and a root complex integrated endpoint at
/// 00:14.0 and a multi-function one at 00:1f.0/2.
fn two_root_ports(a: Option<(u16, u16)>, b: Option<(u16, u16)>) -> (Model, Vec<u16>) {
    let m = Model::new(&[(0x0008, Func::pcie(acs::ROOT_PORT, a).bridge(2)), (0x0010, Func::pcie(acs::ROOT_PORT, b).bridge(3)),
        (0x0200, Func::pcie(0, None)), (0x0300, Func::pcie(0, None)), (0x00a0, Func::pcie(acs::RC_ENDPOINT, None)),
        (0x00f8, Func::pcie(acs::RC_ENDPOINT, None).multi()), (0x00fa, Func::pcie(acs::RC_ENDPOINT, None))]);
    (m, vec![0x0008, 0x0010, 0x0200, 0x0300, 0x00a0, 0x00f8, 0x00fa])
}

#[test]
fn a_root_port_without_acs_reaches_across_the_root_bus() {
    // Neither isolates: one group of everything below and on bus 0.
    let (m, inv) = two_root_ports(None, None);
    let every = [0x00a0, 0x00f8, 0x00fa, 0x0200, 0x0300];
    assert_eq!(group_in(&m, &inv, 0x0200), every);
    assert_eq!(group_in(&m, &inv, 0x0300), every);
    // Only 00:01.0 does not: what is below it reaches across bus 0, to
    // the other port's endpoint and the integrated ones, and the other
    // port's endpoint is reached by it.
    let (m, inv) = two_root_ports(None, Some((ALL, ALL)));
    assert_eq!(group_in(&m, &inv, 0x0200), every);
    assert_eq!(group_in(&m, &inv, 0x0300), [0x0200, 0x0300]);
    let (m, inv) = two_root_ports(Some((ALL, ALL)), None);
    assert_eq!(group_in(&m, &inv, 0x0200), [0x0200, 0x0300]);
    // An integrated endpoint is reached from below one without ACS.
    let (m, inv) = two_root_ports(None, Some((ALL, ALL)));
    assert_eq!(group_in(&m, &inv, 0x00a0), [0x00a0, 0x0200]);
    // Both isolate: each endpoint alone.
    let (m, inv) = two_root_ports(Some((ALL, ALL)), Some((SV | RR | CR, SV | RR | CR)));
    assert_eq!(group_in(&m, &inv, 0x0200), [0x0200]);
    assert_eq!(group_in(&m, &inv, 0x0300), [0x0300]);
    assert_eq!(group_in(&m, &inv, 0x00a0), [0x00a0]);
    // The integrated multi-function device without ACS is one group.
    assert_eq!(group_in(&m, &inv, 0x00fa), [0x00f8, 0x00fa]);
    // Closures agree whichever member is asked about.
    let (m, inv) = two_root_ports(None, Some((ALL, ALL)));
    for me in [0x0200u16, 0x0300, 0x00a0, 0x00f8] {
        let mut out = [0u16; 16];
        let n = acs::closure(&m, || inv.iter().copied(), |f| f, me, &mut out).unwrap();
        let mut g = out[..n].to_vec();
        g.sort();
        assert_eq!(g, every, "{me:#06x}");
    }
}

#[test]
fn an_endpoint_on_the_root_bus_beside_an_empty_bridge_is_alone() {
    // QEMU q35: an e1000e at 00:02.0, and a root port without ACS and a
    // PCI bridge with nothing below them.
    let m = Model::new(&[(0x0010, Func::pcie(acs::ENDPOINT, None)), (0x0008, Func::pcie(acs::ROOT_PORT, None).bridge(2)),
        (0x00f0, Func::pcie(0, None).bridge(3)), (0x0000, Func::pcie(0, None))]);
    let inv = [0x0000, 0x0008, 0x0010, 0x00f0];
    assert_eq!(group_in(&m, &inv, 0x0010), [0x0010]);
}

/// A switch: root port 00:01.0 (bus 1), its upstream port 01:00.0 (bus 2),
/// downstream ports 02:00.0 (bus 3) and 02:01.0 (bus 4), an endpoint
/// below each, and another root port 00:02.0 (bus 5) with one below it.
fn switch(root: Option<(u16, u16)>, d3: Option<(u16, u16)>, d4: Option<(u16, u16)>) -> (Model, Vec<u16>) {
    let funcs = [(0x0008, Func::pcie(acs::ROOT_PORT, root).bridge(1)), (0x0100, Func::pcie(acs::UPSTREAM_PORT, None).bridge(2)),
        (0x0200, Func::pcie(acs::DOWNSTREAM_PORT, d3).bridge(3)), (0x0208, Func::pcie(acs::DOWNSTREAM_PORT, d4).bridge(4)),
        (0x0300, Func::pcie(0, None)), (0x0400, Func::pcie(0, None)),
        (0x0010, Func::pcie(acs::ROOT_PORT, Some((ALL, ALL)))), (0x0500, Func::pcie(0, None))];
    let mut m = Model::new(&funcs);
    // The upstream port routes buses 2-4.
    m.funcs.get_mut().get_mut(&0x0100).unwrap().space[0x18 / 4] = 2 << 8 | 4 << 16;
    m.funcs.get_mut().get_mut(&0x0008).unwrap().space[0x18 / 4] = 1 << 8 | 4 << 16;
    m.funcs.get_mut().get_mut(&0x0010).unwrap().space[0x0c / 4] |= 1 << 16;
    m.funcs.get_mut().get_mut(&0x0010).unwrap().space[0x18 / 4] = 5 << 8 | 5 << 16;
    (m, funcs.iter().map(|f| f.0).collect())
}

#[test]
fn a_switch_isolates_with_acs_on_its_downstream_ports() {
    // Every port isolates: each endpoint alone, the upstream port walked
    // past.
    let (m, inv) = switch(Some((ALL, ALL)), Some((ALL, ALL)), Some((ALL, ALL)));
    assert_eq!(group_in(&m, &inv, 0x0300), [0x0300]);
    assert_eq!(group_in(&m, &inv, 0x0400), [0x0400]);
    assert_eq!(group_in(&m, &inv, 0x0500), [0x0500]);
    // One downstream port without ACS: its endpoint reaches across the
    // switch, and is reached in turn.
    let (m, inv) = switch(Some((ALL, ALL)), None, Some((ALL, ALL)));
    assert_eq!(group_in(&m, &inv, 0x0300), [0x0300, 0x0400]);
    assert_eq!(group_in(&m, &inv, 0x0400), [0x0300, 0x0400]);
    assert_eq!(group_in(&m, &inv, 0x0500), [0x0500]);
    // A downstream port without UF.
    let (m, inv) = switch(Some((ALL, ALL)), Some((ALL, ALL)), Some((SV | RR | CR, SV | RR | CR)));
    assert_eq!(group_in(&m, &inv, 0x0300), [0x0300, 0x0400]);
    // The root port without ACS: the whole switch, and across bus 0.
    let (m, inv) = switch(None, Some((ALL, ALL)), Some((ALL, ALL)));
    assert_eq!(group_in(&m, &inv, 0x0300), [0x0300, 0x0400, 0x0500]);
    assert_eq!(group_in(&m, &inv, 0x0500), [0x0300, 0x0400, 0x0500]);
}

#[test]
fn the_whole_inventory_is_walked() {
    // 1024 functions before the bridge: a bridge without ACS routing bus
    // 5, with the NIC and a disk below it.
    let mut funcs: Vec<(u16, Func)> = (0..1024u16).map(|i| (0x1000 + i, Func::pcie(0, None))).collect();
    funcs.push((0x0400, Func::pcie(acs::DOWNSTREAM_PORT, None).bridge(5)));
    funcs.push((0x0500, Func::pcie(0, None)));
    funcs.push((0x0508, Func::pcie(0, None)));
    let inventory: Vec<u16> = funcs.iter().map(|f| f.0).collect();
    let m = Model::new(&funcs);
    assert_eq!(group_in(&m, &inventory, 0x0500), [0x0500, 0x0508]);
}

#[test]
fn a_port_with_acs_isolates_its_children() {
    let port = |acs| Func::pcie(acs::ROOT_PORT, acs).bridge(2);
    let inventory = [PORT, 0x0009, 0x0010, 0x0200, 0x0300];
    for (acs, sib, peers) in [
        // Both functions isolate: alone.
        (Some((ALL, ALL)), Some((ALL, ALL)), vec![0x0200]),
        // The sibling port 00:01.1 (bus 3) does not: what is below it
        // reaches what is below this one.
        (Some((ALL, ALL)), None, vec![0x0009, 0x0200, 0x0300]),
        // This port does not: across bus 0 too.
        (None, Some((ALL, ALL)), vec![0x0009, 0x0010, 0x0200, 0x0300]),
        (None, None, vec![0x0009, 0x0010, 0x0200, 0x0300]),
    ] {
        let m = Model::new(&[(PORT, port(acs).multi()), (0x0009, Func::pcie(acs::ROOT_PORT, sib).bridge(3)),
            (0x0010, Func::pcie(0, None)), (0x0200, Func::pcie(0, None)), (0x0300, Func::pcie(0, None))]);
        assert_eq!(group_in(&m, &inventory, 0x0200), peers);
    }
}

#[test]
fn an_endpoint_beside_a_bridge_without_acs_shares_its_group() {
    // A bridge at 00:05.0 routing bus 2, a disk at 00:05.1 and the NIC
    // at 02:00.0.
    let m = Model::new(&[(0x0028, Func::pcie(acs::DOWNSTREAM_PORT, None).bridge(2).multi()),
        (0x0029, Func::pcie(0, None)), (0x0200, Func::pcie(0, None))]);
    assert_eq!(group_in(&m, &[0x0028, 0x0029, 0x0200], 0x0200), [0x0029, 0x0200]);
}

#[test]
fn a_bridge_beside_a_function_without_acs_shares_what_is_below_it() {
    // A bridge at 00:05.0 routing bus 2, the NIC at 00:05.1 and a disk
    // at 02:00.0.
    let m = Model::new(&[(0x0028, Func::pcie(acs::DOWNSTREAM_PORT, None).bridge(2).multi()),
        (0x0029, Func::pcie(0, None)), (0x0200, Func::pcie(0, None))]);
    assert_eq!(group_in(&m, &[0x0028, 0x0029, 0x0200], 0x0029), [0x0028, 0x0029, 0x0200]);
}

#[test]
fn a_group_is_closed_under_reach_and_requester_aliases() {
    // NIC A at 00:05.0 shares a slot without ACS with B at 00:05.1, which
    // the IOMMU translates as disk C at 00:06.0; D at 00:07.0 is alone.
    let m = Model::new(&[(0x0028, Func::pcie(0, None).multi()), (0x0029, Func::pcie(0, None)),
        (0x0030, Func::pcie(0, None)), (0x0038, Func::pcie(0, None))]);
    let inventory = [0x0028u16, 0x0029, 0x0030, 0x0038];
    let alias = |f: u16| if f == 0x0029 { 0x0030 } else { f };
    let mut out = [0u16; 8];
    let n = acs::closure(&m, || inventory.iter().copied(), alias, 0x0028, &mut out).unwrap();
    let mut g = out[..n].to_vec();
    g.sort();
    assert_eq!(g, [0x0028, 0x0029, 0x0030]);
    // Too many members for `out`.
    assert_eq!(acs::closure(&m, || inventory.iter().copied(), alias, 0x0028, &mut [0u16; 2]), None);
}

#[test]
fn the_shim_refuses_a_group_split_between_partitions() {
    let owners = |p1: &'static [u16]| move |b: u16| if p1.contains(&b) { 1 } else { 0 };
    let other = |m: &Model, inv: &[u16], p1: &'static [u16], me: u16| {
        acs::other_owner(m, || inv.iter().copied(), |f| f, owners(p1), me, &mut [0u16; 16]).unwrap()
    };
    // 00:02.0's endpoint below a root port without ACS reaches across the
    // root bus, to 00:01.0's: they cannot be in two partitions.
    let (m, inv) = two_root_ports(None, Some((ALL, ALL)));
    assert_eq!(other(&m, &inv, &[0x0300], 0x0300), Some(0x0200));
    // With ACS on both ports each is alone, and may go anywhere.
    let (m, inv) = two_root_ports(Some((ALL, ALL)), Some((ALL, ALL)));
    assert_eq!(other(&m, &inv, &[0x0300], 0x0300), None);
    // A multi-function device without ACS: its functions go together.
    assert_eq!(other(&m, &inv, &[0x00fa], 0x00fa), Some(0x00f8));
    assert_eq!(other(&m, &inv, &[0x00f8, 0x00fa], 0x00fa), None);
    // A dual-port NIC whose functions both isolate with ACS may be split.
    let both = SV | RR | CR | UF;
    let m = Model::new(&[(0x0028, Func::pcie(0, Some((both, both))).multi()), (0x0029, Func::pcie(0, Some((both, both))))]);
    assert_eq!(other(&m, &[0x0028, 0x0029], &[0x0029], 0x0029), None);
    // A bridge in the slot takes no part: only what is below it does.
    let m = Model::new(&[(0x0028, Func::pcie(0, None).multi()), (0x0029, Func::pcie(acs::DOWNSTREAM_PORT, None).bridge(2)),
        (0x0200, Func::pcie(0, None))]);
    let inv = [0x0028, 0x0029, 0x0200];
    assert_eq!(other(&m, &inv, &[0x0028], 0x0028), Some(0x0200));
    assert_eq!(other(&m, &inv, &[0x0028, 0x0200], 0x0028), None);
    // A group larger than the caller's room is an error, not a pass.
    let (m, inv) = two_root_ports(None, None);
    assert_eq!(acs::other_owner(&m, || inv.iter().copied(), |f| f, owners(&[0x0300]), 0x0300, &mut [0u16; 2]), Err(()));
}

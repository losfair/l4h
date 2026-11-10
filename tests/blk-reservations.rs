//! l4h-root's side of dom0 reservations: planning boot ranges, and keeping
//! their records across detach, with mocked driver/IOMMU calls.  blkd
//! decides who may use which sectors (tests/blk-windows.rs).
#![allow(dead_code)]
use l4h_host::blk::{self, DiskWindow};

include!(env!("L4H_BLK_RESERVATIONS_TEST_SRC"));

pub struct Pci;
#[derive(Clone, Copy, PartialEq, Eq)]
struct Domain(u8);
impl Domain { const NONE: Self = Self(0); }
pub struct Iommu { unmapped: Vec<(usize, usize)> }
impl Iommu {
    fn unmap(&mut self, _: Domain, pa: usize, len: usize) { self.unmapped.push((pa, len)); }
}
struct Slot;
impl Slot { fn delete(&self) -> Result<(), ()> { Ok(()) } }
struct Component;
impl Component { fn slot(&self, _: u64) -> Slot { Slot } }
struct Driver { comp: Component }
pub struct Controller {
    clients: Vec<Option<Attachment>>, driver: Option<Driver>, failed: bool, dom: Domain,
}
fn quarantine(c: &mut Controller, _: &Pci) { c.failed = true; }
pub struct Host { ctrls: Vec<Controller>, pci: Pci, iommu: Iommu, released: Vec<(Option<usize>, bool)> }
mod vmmgr {
    /// What a deleted guest's memory waits for: a disk's removal, and
    /// whether its pool can be reused.
    pub fn zombie_disk_done(h: &mut crate::Host, zombie: Option<usize>, reusable: bool) {
        h.released.push((zombie, reusable));
    }
}

fn reservation() -> Attachment {
    Attachment { vm: 0, disk: 0, window: DiskWindow::new(8, 16, 1024).unwrap(), extents: 0,
        read_only: false, volatile: false, reserved: true, pool: None, remove: None }
}

#[test]
fn unusable_whole_disk_geometry_stays_reserved() {
    for capacity in [0, 1, 7, 131073, u64::MAX] {
        // The actual whole-disk attachment fails, but planning must succeed
        // and keep every attachable range owned while dom0 has a dummy disk.
        assert!(DiskWindow::new(0, 0, capacity).is_none());
        let window = dom0_reservation(0, 0, capacity).unwrap();
        for start in [0, 8, UNKNOWN_CAPACITY - 8] {
            assert!(window.overlaps(DiskWindow::new(start, 8, UNKNOWN_CAPACITY).unwrap()));
        }
        // blkd accepts it: it lies within the largest aligned capacity.
        assert_eq!(DiskWindow::new(window.start, window.sectors, u64::MAX & !7), Some(window));
    }
}

#[test]
fn explicit_ranges_still_use_the_known_capacity() {
    assert_eq!(dom0_reservation(0, 0, 131072), DiskWindow::new(0, 0, 131072));
    // An aligned prefix of an odd-sized disk remains usable, as does the
    // last complete block. Explicit unaligned or out-of-bounds plans fail.
    for (start, sectors) in [(0, 2048), (131064, 8)] {
        assert_eq!(dom0_reservation(start, sectors, 131073), Some(DiskWindow { start, sectors }));
    }
    for (start, sectors) in [(1, 8), (8, 7), (0, 131073), (131072, 8), (u64::MAX - 7, 16)] {
        assert!(dom0_reservation(start, sectors, 131073).is_none());
    }
    assert_eq!(dom0_reservation(8, 16, 0), Some(DiskWindow { start: 8, sectors: 16 }));
}

#[test]
fn detach_keeps_boot_reservations_and_releases_normal_attachments() {
    for reserved in [false, true] {
        for fails in [false, true] {
            for dom in [Domain(1), Domain::NONE] {
                let mut a = reservation();
                a.reserved = reserved;
                a.pool = Some((0x100000, 0x400000));
                a.remove = Some(Removal { zombie: Some(3), posted: true });
                let c = Controller { clients: vec![Some(a)], failed: false, dom, driver: Some(Driver { comp: Component }) };
                let mut h = Host { ctrls: vec![c], pci: Pci, iommu: Iommu { unmapped: Vec::new() }, released: Vec::new() };
                // The pool leaves the domain at once; blkd drains later.
                assert_eq!(cut_off(&mut h, 0, 0), dom != Domain::NONE);
                assert_eq!(h.iommu.unmapped, [(0x100000, 0x400000)]);
                removed(&mut h, 0, 0, !fails);
                assert_eq!(h.ctrls[0].failed, fails);
                // Without a domain, a disk that did not drain keeps the pool.
                assert_eq!(h.released, [(Some(3), !fails || dom != Domain::NONE)]);
                if reserved {
                    // Still listed as dom0's, without a pool or removal.
                    let kept = h.ctrls[0].clients[0].as_ref().unwrap();
                    assert!(kept.pool.is_none() && kept.remove.is_none() && kept.vm == 0 && kept.window == reservation().window);
                } else {
                    assert!(h.ctrls[0].clients[0].is_none());
                }
            }
        }
    }
}

#[test]
fn windows_beyond_a_small_disk_are_planned_and_reserved_not_fatal() {
    let text = "2048:8192,16384:8192";
    // They fit the disk: planned and reserved as they are.
    let (w, len, fits) = dom0_windows::<4>(text, 1 << 20).unwrap();
    assert_eq!((len, fits), (2, true));
    assert_eq!(w[..2], [DiskWindow { start: 2048, sectors: 8192 }, DiskWindow { start: 16384, sectors: 8192 }]);
    assert_eq!(dom0_plan_reservation(16384, 8192, 1 << 20), Some(w[1]));
    // The disk (its blkd says) ends inside the first window, or before
    // both: the same plan, which root must not stop for.  Each window
    // stays reserved; attaching one beyond the disk is refused later.
    for capacity in [8, 4096, 20000] {
        let (small, len, fits) = dom0_windows::<4>(text, capacity).unwrap();
        assert_eq!((len, fits, &small[..2]), (2, false, &w[..2]));
        for win in &small[..2] {
            assert_eq!(dom0_plan_reservation(win.start, win.sectors, capacity), Some(*win));
            // blkd reserves it: within the largest aligned capacity.
            assert_eq!(DiskWindow::new(win.start, win.sectors, u64::MAX & !7), Some(*win));
        }
    }
    assert!(DiskWindow::new(16384, 8192, 20000).is_none());
    // An unknown capacity fits any list.
    assert_eq!(dom0_windows::<4>(text, UNKNOWN_CAPACITY).map(|(_, len, fits)| (len, fits)), Some((2, true)));
    // What is no list of windows of any disk is still refused.
    for invalid in ["", "8:0", "1:8", "8:16,16:16", "8:8,16:8,24:8,32:8,40:8", "8:18446744073709551608"] {
        assert!(dom0_windows::<4>(invalid, 1 << 20).is_none(), "{invalid}");
        assert!(dom0_windows::<4>(invalid, 8).is_none(), "{invalid}");
    }
    // The automatic plan is as before: the whole disk, whatever it is.
    for capacity in [0, 7, 131072, 131073] {
        assert_eq!(dom0_plan_reservation(0, 0, capacity), dom0_reservation(0, 0, capacity));
    }
    assert!(dom0_plan_reservation(1, 8, 131072).is_none());
}

#[test]
fn only_dom0_claims_a_boot_range_and_only_as_it_was_reserved() {
    let r = reservation();
    let (disk, window) = (r.disk, r.window);
    assert!(r.claimed_by(true, disk, window));
    // Another guest, another disk, another window: blkd gives the slot to
    // none of them.
    assert!(!r.claimed_by(false, disk, window));
    assert!(!r.claimed_by(true, disk + 1, window));
    assert!(!r.claimed_by(true, disk, DiskWindow { start: window.start, sectors: window.sectors + 8 }));
    assert!(!r.claimed_by(true, disk, DiskWindow { start: window.start + 8, sectors: window.sectors }));
    // A slot with a client, or one being removed, is no one's to take; nor
    // is an attachment that is no reservation.
    let mut busy = reservation();
    busy.pool = Some((0x100000, 0x400000));
    assert!(!busy.claimed_by(true, disk, window));
    let mut going = reservation();
    going.remove = Some(Removal { zombie: None, posted: false });
    assert!(!going.claimed_by(true, disk, window));
    let mut plain = reservation();
    plain.reserved = false;
    assert!(!plain.claimed_by(true, disk, window));
}

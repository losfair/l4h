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
    /// What a deleted guest's memory waits for: the removal, and whether
    /// its pool can be reused.
    pub fn zombie_done(h: &mut crate::Host, zombie: Option<usize>, reusable: bool) {
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

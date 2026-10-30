//! Production reservation selection and detach, with mocked driver/IOMMU calls.
#![allow(dead_code)]
use l4h_host::blk::{self, DiskWindow};

mod ctl { pub const EBUSY: i64 = 16; pub const ENOSPC: i64 = 28; }

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
struct Component { service_ep: u64 }
impl Component { fn slot(&self, _: u64) -> Slot { Slot } }
struct Driver { comp: Component }
pub struct Controller {
    clients: Vec<Option<Attachment>>, driver: Option<Driver>, failed: bool, dom: Domain,
}
fn call(ep: u64, _: u64, _: &[u64]) -> u64 { ep }
fn quarantine(c: &mut Controller, _: &Pci) { c.failed = true; }

fn reservation() -> Attachment {
    Attachment { vm: 0, disk: 0, window: DiskWindow::new(8, 16, 1024).unwrap(),
        read_only: false, volatile: false, reserved: true, pool: None }
}

#[test]
fn unusable_whole_disk_geometry_stays_reserved() {
    for capacity in [0, 1, 7, 131073, u64::MAX] {
        // The actual whole-disk attachment fails, but planning must succeed
        // and keep every attachable range owned while dom0 has a dummy disk.
        assert!(DiskWindow::new(0, 0, capacity).is_none());
        let window = dom0_reservation(0, 0, capacity).unwrap();
        let clients = [Some(Attachment { window, ..reservation() })];
        for start in [0, 8, UNKNOWN_CAPACITY - 8] {
            let w = DiskWindow::new(start, 8, UNKNOWN_CAPACITY).unwrap();
            assert!(window.overlaps(w)); // Provisioning checks overlap too.
            for ro in [false, true] {
                assert_eq!(attachment_slot(&clients, 0, w, ro, false), Err(ctl::EBUSY));
            }
        }
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
fn only_dom0_can_claim_the_exact_reserved_range_even_when_table_is_full() {
    let clients = [Some(reservation())];
    let w = clients[0].as_ref().unwrap().window;
    assert_eq!(attachment_slot(&clients, 0, w, false, true), Ok(0));
    for ro in [false, true] {
        assert_eq!(attachment_slot(&clients, 0, w, ro, false), Err(ctl::EBUSY));
        for other in [DiskWindow::new(8, 8, 1024).unwrap(), DiskWindow::new(0, 32, 1024).unwrap()] {
            assert_eq!(attachment_slot(&clients, 0, other, ro, true), Err(ctl::EBUSY));
        }
    }
    assert_eq!(attachment_slot(&clients, 1, w, false, true), Err(ctl::ENOSPC));
}

#[test]
fn an_active_dom0_window_cannot_be_claimed_twice() {
    let mut a = reservation();
    let w = a.window;
    a.pool = Some((0x100000, 0x400000));
    assert_eq!(attachment_slot(&[Some(a)], 0, w, false, true), Err(ctl::EBUSY));
}

#[test]
fn detach_keeps_boot_reservations_and_releases_normal_attachments() {
    for reserved in [false, true] {
        for fails in [false, true] {
            let mut a = reservation();
            let w = a.window;
            a.reserved = reserved;
            a.pool = Some((0x100000, 0x400000));
            let mut c = Controller { clients: vec![Some(a)], failed: false, dom: Domain(1),
                driver: Some(Driver { comp: Component { service_ep: if fails { u64::MAX } else { 0 } } }) };
            let mut iommu = Iommu { unmapped: Vec::new() };
            assert!(remove(&mut c, 0, &Pci, &mut iommu));
            assert_eq!(c.failed, fails);
            assert_eq!(iommu.unmapped, [(0x100000, 0x400000)]);
            if reserved {
                assert!(c.clients[0].as_ref().unwrap().pool.is_none());
                assert_eq!(attachment_slot(&c.clients, 0, w, false, false), Err(ctl::EBUSY));
                assert_eq!(attachment_slot(&c.clients, 0, w, false, true), Ok(0));
            } else {
                assert!(c.clients[0].is_none());
            }
        }
    }
}

//! Production reservation selection and detach, with mocked driver/IOMMU calls.
#![allow(dead_code)]
use l4h_host::blk::{self, DiskWindow};
use l4h_host::MAX_GUEST_DEVICES;

mod ctl { pub const EIO: i64 = 5; pub const EBUSY: i64 = 16; pub const ENOSPC: i64 = 28; pub const EOPNOTSUPP: i64 = 95; }

macro_rules! log { ($($args:tt)*) => { LOGS.with_borrow_mut(|l| l.push(format!($($args)*))) }; }

include!(env!("L4H_BLK_RESERVATIONS_TEST_SRC"));

pub struct Pci;
#[derive(Clone, Copy, PartialEq, Eq)]
struct Domain(u8);
impl Domain { const NONE: Self = Self(0); }
pub struct Iommu { unmapped: Vec<(usize, usize)> }
impl Iommu {
    fn unmap(&mut self, _: Domain, pa: usize, len: usize) { self.unmapped.push((pa, len)); }
}
mod cap { pub type CNode = usize; }
fn abs_of(_: usize) -> Slot { Slot }
struct Slot;
impl Slot { fn delete(&self) -> Result<(), ()> { Ok(()) } }
struct Component { service_ep: u64 }
impl Component { fn slot(&self, _: u64) -> Slot { Slot } }
struct Driver { comp: Component }
pub struct Controller {
    clients: Vec<Option<Attachment>>, driver: Option<Driver>, failed: bool, dom: Domain,
}
thread_local! {
    static LOGS: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
    static APPLIED: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static MRS: std::cell::RefCell<[u64; 16]> = const { std::cell::RefCell::new([0; 16]) };
}
fn mr(i: usize) -> u64 { MRS.with_borrow(|m| m[i]) }
fn set_mr(i: usize, v: u64) { MRS.with_borrow_mut(|m| m[i] = v); }
mod sel4 {
    pub struct IpcBuffer<'a>(&'a mut [u64]);
    impl IpcBuffer<'_> { pub fn msg_regs_mut(&mut self) -> &mut [u64] { self.0 } }
    pub fn with_ipc_buffer_mut<R>(f: impl FnOnce(&mut IpcBuffer<'_>) -> R) -> R {
        super::MRS.with_borrow_mut(|m| f(&mut IpcBuffer(m)))
    }
}
fn call(ep: u64, label: u64, args: &[u64]) -> u64 {
    for (i, &a) in args.iter().enumerate() { set_mr(i, a); }
    if label == blk::BLKD_ADD { set_mr(1, APPLIED.get()); }
    ep
}
fn quarantine(c: &mut Controller, _: &Pci) { c.failed = true; }

pub struct RootGuest { id: usize, pool: blk::Pool, disks: Vec<(usize, usize)>, ports: Vec<usize>, device_limit_logged: bool, arena: Vec<usize> }
fn guest() -> RootGuest {
    RootGuest { id: 7, pool: blk::Pool { gpa: 0, paddr: 0x100000, size: 0x400000 }, disks: vec![(0, 0)], ports: Vec::new(), device_limit_logged: false, arena: Vec::new() }
}
pub type Channel = Vec<usize>;
mod blkd { pub use super::{Channel, remove}; }
struct Alloc { released: usize }
struct Host { ctrls: Vec<Controller>, pci: Pci, iommu: Iommu, alloc: Alloc }
trait ChannelMemory { fn keep(self, arena: &mut Vec<usize>); fn release(self, alloc: &mut Alloc); }
impl ChannelMemory for Channel {
    fn keep(self, arena: &mut Vec<usize>) { arena.extend(self); }
    fn release(self, alloc: &mut Alloc) { alloc.released += self.len(); }
}
pub struct Window { page: Box<blk::Channel> }
impl Window {
    fn with_frame(&mut self, _: &Slot, f: impl FnOnce(*mut u8)) { f((&mut *self.page as *mut blk::Channel).cast()); }
}

#[test]
fn failed_rollback_retains_the_record_needed_to_pin_the_pool() {
    for dom in [Domain::NONE, Domain(1)] {
        let mut g = guest();
        let mut c = Controller { clients: vec![Some(Attachment { encrypted: true,
            pool: Some((g.pool.paddr as usize, g.pool.size as usize)), ..reservation() })],
            driver: Some(Driver { comp: Component { service_ep: 0 } }), failed: false, dom };
        let mut win = Window { page: Box::new(unsafe { core::mem::zeroed() }) };
        APPLIED.set(0);
        assert_eq!(activate(&mut c, 0, 0, &g, &vec![0], &mut win, &Pci, &[0x12; 64]), Err(ctl::EOPNOTSUPP));
        assert!(!c.failed);
        c.driver.as_mut().unwrap().comp.service_ep = u64::MAX; // REMOVE now times out.
        let mut h = Host { ctrls: vec![c], pci: Pci, iommu: Iommu { unmapped: Vec::new() }, alloc: Alloc { released: 0 } };
        rollback_disk_attach(&mut h, &mut g, 0, vec![0]);
        assert!(h.ctrls[0].failed);
        assert_eq!(g.disks.len(), usize::from(dom == Domain::NONE));
        assert_eq!(g.arena.len(), usize::from(dom == Domain::NONE));
        assert_eq!(h.alloc.released, usize::from(dom != Domain::NONE));
        // guest_del drains these retained records before deciding whether
        // the pool can return to the allocator, even after remove took its mapping.
        let mut quiet = true;
        for &(ctrl, client) in &g.disks { quiet &= remove(&mut h.ctrls[ctrl], client, &h.pci, &mut h.iommu); }
        assert_eq!(quiet, dom != Domain::NONE, "an unconfined failed controller must keep the pool pinned");
    }
}

#[test]
fn activation_requires_blkd_to_confirm_exactly_the_requested_flags() {
    for (encrypted, applied, expected) in [
        (false, 0, Ok(0)), (true, blk::ENCRYPT, Ok(blk::ENCRYPT)),
        (true, 0, Err(ctl::EOPNOTSUPP)), (false, blk::ENCRYPT, Err(ctl::EOPNOTSUPP)),
        (true, blk::ENCRYPT | 2, Err(ctl::EOPNOTSUPP)),
    ] {
        let mut c = Controller { clients: vec![Some(Attachment { encrypted, ..reservation() })],
            driver: Some(Driver { comp: Component { service_ep: 0 } }), failed: false, dom: Domain(1) };
        let g = guest();
        let mut win = Window { page: Box::new(unsafe { core::mem::zeroed() }) };
        APPLIED.set(applied);
        assert_eq!(activate(&mut c, 0, 0, &g, &vec![0], &mut win, &Pci, &[0x12; 64]), expected);
        assert!(!c.failed, "a rejected acknowledgment must use normal attach cleanup");
        for i in 0..11 { assert_eq!(mr(i), 0, "transient key words must be cleared"); }
    }
}

#[test]
fn quarantined_disk_attaches_count_against_the_shared_root_device_budget() {
    for disk_count in [1, MAX_GUEST_DEVICES / 2, MAX_GUEST_DEVICES] {
        let mut c = Controller { clients: vec![Some(reservation())], failed: false, dom: Domain(1),
            driver: Some(Driver { comp: Component { service_ep: u64::MAX } }) };
        let mut g = guest();
        let mut win = Window { page: Box::new(unsafe { core::mem::zeroed() }) };
        assert_eq!(activate(&mut c, 0, 0, &g, &vec![0], &mut win, &Pci, &[0; 64]), Err(ctl::EIO));
        assert!(c.failed); // Root retains this disk; vmmgr has no device for it.
        while g.disks.len() < disk_count {
            g.check_device_room().unwrap();
            g.disks.push((g.disks.len(), 0));
        }
        for port in 0..MAX_GUEST_DEVICES - disk_count {
            g.check_device_room().unwrap();
            g.ports.push(port);
        }
        assert_eq!(g.check_device_room(), Err(ctl::ENOSPC), "retained disks and ports share one root budget");
        LOGS.with_borrow(|logs| {
            let message = logs.last().unwrap();
            assert!(message.contains("guest 7") && message.contains("root disk/NIC limit"), "{message}");
        });
        assert!(g.disks.len() - 1 + g.ports.len() < MAX_GUEST_DEVICES, "successful disk/port attaches alone miss the retained disk");
        g.disks.pop();
        assert_eq!(g.check_device_room(), Ok(()), "a fully released attach gives its slot back");
    }
}

#[test]
fn device_limit_log_is_neutral_and_emitted_once_per_guest() {
    for id in [7, 8] {
        let mut g = guest();
        g.id = id;
        g.disks.resize(MAX_GUEST_DEVICES, (0, 0)); // All healthy attachments.
        LOGS.with_borrow_mut(Vec::clear);
        for _ in 0..512 { assert_eq!(g.check_device_room(), Err(ctl::ENOSPC)); }
        LOGS.with_borrow(|logs| {
            assert_eq!(logs.len(), 1, "retries must not flood the root log");
            assert_eq!(logs[0], format!("l4h-root: guest {id}: root disk/NIC limit {MAX_GUEST_DEVICES} reached ({MAX_GUEST_DEVICES} disks, 0 NICs)"));
        });
    }
}

fn reservation() -> Attachment {
    Attachment { vm: 0, disk: 0, window: DiskWindow::new(8, 16, 1024).unwrap(),
        read_only: false, volatile: false, encrypted: false, reserved: true, pool: None, mappings: None }
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

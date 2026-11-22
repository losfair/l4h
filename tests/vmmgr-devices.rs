//! The production device-attach handlers of vmmgr (create_nic,
//! attach_dummy_disk) and Guest::max_devices, with a guest that counts its
//! devices as hvm::add_device and Guest::add_device do: an HVM guest's
//! devices end at its PCI bus, before a PV guest's.
use l4h_host::errno::{EBUSY, EINVAL, ENOENT, ENOMEM, ENOSPC, Errno};
use l4h_host as host;

pub const MAX_GUEST_DEVICES: usize = host::MAX_GUEST_DEVICES;

mod ctl {
    pub use l4h_host::errno::{EBUSY, EINVAL, ENOENT, ENOMEM, ENOSPC};
}
mod proto {
    pub fn nic_mac_ok(_: u64) -> bool { true }
    pub fn nic_flags_ok(f: u64) -> bool { f == 0 }
}
mod guest {
    pub const DEVICE_BYTES: usize = 4096;
    pub const DEVICE_SLOTS: usize = 4;
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum DevKind { Virtio(u32) }
}
mod vmm {
    #[derive(Debug)]
    pub enum Backend { Net { mac: [u8; 6] }, UnavailableBlk }
}
mod root {
    use super::*;
    pub fn port_keep(_: &mut (), _: &mut ()) -> Option<u32> { Some(1) }
    /// netd's port, which the test counts: one given for a device that is
    /// then not added would be lost to the guest.
    pub fn nic_add(_: &mut (), _: u32, _: usize, _: u32, _: u64, _: u64) -> Result<vmm::Backend, Errno> {
        PORTS.with(|p| p.set(p.get() + 1));
        Ok(vmm::Backend::Net { mac: [2, 0, 0, 0, 0, 1] })
    }
    std::thread_local! { pub static PORTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }
}
#[derive(PartialEq, Eq)]
enum State { Created }
struct Guest {
    state: State,
    vmm: Option<()>,
    root_pending: bool,
    hvm: Option<()>,
    devices: Vec<guest::DevKind>,
    backends: Vec<(usize, vmm::Backend)>,
    port_spare: Option<u32>,
    arena: (),
}
trait MustPush<T> { fn must_push(&mut self, v: T); }
impl<T> MustPush<T> for Vec<T> { fn must_push(&mut self, v: T) { self.push(v) } }
impl Guest {
    fn reserve(&mut self, _: &mut (), _: usize) -> bool { true }
    /// As Guest::add_device and hvm::add_device: none past the guest's room.
    fn add_device(&mut self, _: &mut (), kind: guest::DevKind) -> Option<usize> {
        let d = self.devices.len();
        let room = if self.hvm.is_some() { host::hvm::MAX_DEVICES + 1 } else { MAX_GUEST_DEVICES };
        if d >= room { return None; }
        self.devices.push(kind);
        Some(d)
    }
}
include!(env!("L4H_MAX_DEVICES_SRC"));
struct Vmmgr { guests: Vec<Option<Guest>>, alloc: () }
impl Vmmgr {
    fn can_afford(&self, _: usize, _: usize, _: usize) -> bool { true }
    fn with_guest<R>(&mut self, id: usize, f: impl FnOnce(&mut Self, &mut Guest) -> R) -> Option<R> {
        let mut g = self.guests[id].take()?;
        let r = f(self, &mut g);
        self.guests[id] = Some(g);
        Some(r)
    }
}
include!(env!("L4H_DEVICES_SRC"));

fn vmmgr(hvm: bool) -> Vmmgr {
    let g = Guest { state: State::Created, vmm: None, root_pending: false, hvm: hvm.then_some(()),
        devices: vec![guest::DevKind::Virtio(3)], backends: vec![], port_spare: None, arena: () };
    Vmmgr { guests: vec![None, Some(g)], alloc: () }
}

#[test]
fn an_hvm_guest_refuses_devices_past_its_pci_bus_without_panicking() {
    let mut h = vmmgr(true);
    for _ in 0..host::hvm::MAX_DEVICES {
        assert!(h.create_nic(1, 0, 0, 0).is_ok());
    }
    let ports = root::PORTS.with(|p| p.get());
    assert_eq!(h.create_nic(1, 0, 0, 0), Err(ENOSPC));
    assert_eq!(h.attach_dummy_disk(1), Err(ENOSPC));
    assert_eq!(root::PORTS.with(|p| p.get()), ports, "no netd port given for a NIC that cannot be added");
    assert_eq!(h.guests[1].as_ref().unwrap().devices.len(), host::hvm::MAX_DEVICES + 1);
}

#[test]
fn a_pv_guest_keeps_its_larger_room() {
    let mut h = vmmgr(false);
    for _ in 0..MAX_GUEST_DEVICES - 1 {
        assert!(h.create_nic(1, 0, 0, 0).is_ok());
    }
    assert_eq!(h.create_nic(1, 0, 0, 0), Err(ENOSPC));
    assert_eq!(h.attach_dummy_disk(1), Err(ENOSPC));
    assert_eq!(h.create_nic(1, 0, 0, 1), Err(EINVAL));
    assert_eq!(h.create_nic(0, 0, 0, 0), Err(ENOENT));
    let _ = (EBUSY, ENOMEM);
}

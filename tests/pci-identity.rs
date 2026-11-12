//! Production PCI identity reader and service handoff bookkeeping against
//! configuration-space fixtures. No configuration writes or MMIO reads.
use std::cell::Cell;
use l4h_abi as abi;

#[derive(Clone, Copy)]
pub struct Device {
    bus: u8, dev: u8, func: u8, vendor: u16, device: u16,
    class: u8, subclass: u8, prog_if: u8, revision: u8,
}

fn device() -> Device {
    Device { bus: 0xff, dev: 0x1f, func: 7, vendor: 0x1234, device: 0x5678,
        class: 0x0c, subclass: 3, prog_if: 0x30, revision: 2 }
}

pub struct Pci { config: [u8; 256], reads: Cell<usize> }
impl Pci {
    fn new(header: u8) -> Self {
        let mut config = [0; 256];
        config[0x0e] = header;
        Self { config, reads: Cell::new(0) }
    }
    fn read32(&self, bus: u8, dev: u8, func: u8, off: u8) -> u32 {
        assert_eq!((bus, dev, func), (0xff, 0x1f, 7));
        self.reads.set(self.reads.get() + 1);
        let off = off as usize;
        u32::from_le_bytes(self.config[off..off + 4].try_into().unwrap())
    }
    fn read16(&self, bus: u8, dev: u8, func: u8, off: u8) -> u16 {
        (self.read32(bus, dev, func, off & !3) >> ((off & 2) * 8)) as u16
    }
    fn read8(&self, bus: u8, dev: u8, func: u8, off: u8) -> u8 {
        (self.read32(bus, dev, func, off & !3) >> ((off & 3) * 8)) as u8
    }
    fn subsystem(&mut self, off: usize) {
        self.config[off..off + 4].copy_from_slice(&0x9876_abcd_u32.to_le_bytes());
    }
}
include!(env!("L4H_PCI_IDENTITY_TEST_SRC"));

mod netd {
    pub fn bdf(p: &super::Device) -> u32 { (p.bus as u32) << 8 | (p.dev as u32) << 3 | p.func as u32 }
}
/// The NICs root found (their BDFs and pins), and the owner each reports.
mod nicd {
    use super::*;
    pub struct Ids;
    pub fn ids_of(_: &Device, _: &Pci) -> Ids { Ids }
    pub type Pin = Option<Option<&'static str>>;
    pub fn found(d: Device, _: Ids, pin: Pin, _: &Pci) -> bool {
        FOUND.lock().unwrap().push((netd::bdf(&d) as u16, pin));
        true
    }
    pub static FOUND: std::sync::Mutex<Vec<(u16, Pin)>> = std::sync::Mutex::new(Vec::new());
    pub fn pci_owner(bdf: u16) -> Option<u16> {
        (bdf == 24).then_some(abi::PCI_OWNER_NICD)
    }
}
/// l4h.conf: NIC pins by BDF.
struct Cfg { pin: Option<(u32, Option<&'static str>)> }
impl Cfg {
    fn nic_pin(&self, bdf: u32) -> nicd::Pin {
        self.pin.filter(|&(b, _)| b == bdf).map(|(_, d)| d)
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum State { Firmware, Idle, Vm, Failed, Unsupported }
struct Ctrl { pci: Device, state: State, driver: Option<()> }
fn ctrls() -> std::sync::MutexGuard<'static, Vec<Ctrl>> {
    static CTRLS: std::sync::Mutex<Vec<Ctrl>> = std::sync::Mutex::new(Vec::new());
    CTRLS.lock().unwrap()
}
struct DiskCtrl { pci: Device, failed: bool }
struct Host { pci_inventory: Vec<abi::CtlPci>, ctrls: Vec<DiskCtrl> }
mod usb {
    pub fn pci_owner(bdf: u16) -> u16 { super::pci_owner(bdf) }
}
include!(env!("L4H_PCI_OWNERS_TEST_SRC"));

#[test]
fn disk_owner_queries_report_boot_failures_and_later_quarantine() {
    let row = |bdf, owner| abi::CtlPci { bdf, owner, ..Default::default() };
    let mut h = Host {
        pci_inventory: vec![row(8, abi::PCI_OWNER_BLKD), row(16, abi::PCI_OWNER_BLKD),
            row(24, abi::PCI_OWNER_ROOT), row(u16::MAX, abi::PCI_OWNER_NONE)],
        ctrls: vec![DiskCtrl { pci: Device { bus: 0, dev: 1, func: 0, ..device() }, failed: false },
            DiskCtrl { pci: Device { bus: 0, dev: 2, func: 0, ..device() }, failed: true }],
    };
    let read = |h: &mut Host, first| {
        let mut data = [0; abi::CTL_DATA_MAX];
        let n = pci_page(h, first, &mut data);
        (0..n).map(|i| unsafe {
            std::ptr::read_unaligned(data.as_ptr().add(i * size_of::<abi::CtlPci>()).cast::<abi::CtlPci>())
        }).collect::<Vec<_>>()
    };
    // Controller 1 failed before blkd could publish any disks. It is
    // still listed, and its failure does not change controller 0's owner.
    let entries = read(&mut h, 0);
    assert_eq!(entries.iter().map(|p| p.owner).collect::<Vec<_>>(),
        [abi::PCI_OWNER_BLKD, abi::PCI_OWNER_ROOT, abi::PCI_OWNER_NICD, abi::PCI_OWNER_NONE]);
    // A later reset, bad reply or drain failure sets the same sticky
    // Controller::failed flag. Re-query the original boot snapshot.
    h.ctrls[0].failed = true;
    assert_eq!(read(&mut h, 0)[0].owner, abi::PCI_OWNER_ROOT);
    assert_eq!(h.pci_inventory[0].owner, abi::PCI_OWNER_BLKD);
    assert_eq!(read(&mut h, 9).len(), 3);
    assert_eq!(read(&mut h, u16::MAX as u64).len(), 1);
    assert!(read(&mut h, u16::MAX as u64 + 1).is_empty());
    assert!(read(&mut h, u64::MAX).is_empty());
}

#[test]
fn failed_usb_controllers_belong_to_root_even_when_the_driver_remains() {
    for (state, driver, owner) in [(State::Firmware, None, abi::PCI_OWNER_FIRMWARE),
        (State::Unsupported, None, abi::PCI_OWNER_FIRMWARE), (State::Idle, Some(()), abi::PCI_OWNER_USBD),
        (State::Vm, Some(()), abi::PCI_OWNER_USBD), (State::Failed, Some(()), abi::PCI_OWNER_ROOT),
        (State::Failed, None, abi::PCI_OWNER_ROOT)] {
        *ctrls() = vec![Ctrl { pci: device(), state, driver }];
        assert_eq!(pci_owner(0xffff), owner);
    }
    assert_eq!(pci_owner(0), abi::PCI_OWNER_FIRMWARE);
}

#[test]
fn nics_belong_to_root_until_their_nicd_takes_them() {
    let pci = Pci::new(0);
    // Every NIC found is root's (bound, and its nicd started, once the
    // host is up), with its pin from l4h.conf.
    for (pin, want) in [(None, None), (Some((0xffff, Some("e1000e"))), Some(Some("e1000e"))),
        (Some((0xffff, None)), Some(None)), (Some((8, Some("ixgbe"))), None)] {
        nicd::FOUND.lock().unwrap().clear();
        assert_eq!(record_nic(device(), &pci, &Cfg { pin }).owner, abi::PCI_OWNER_ROOT);
        assert_eq!(*nicd::FOUND.lock().unwrap(), [(0xffff, want)]);
    }
}

#[test]
fn endpoint_and_cardbus_subsystem_ids_use_their_own_header_offsets() {
    for (header, off) in [(0x80, 0x2c), (2, 0x40)] {
        let mut pci = Pci::new(header);
        pci.subsystem(off);
        assert_eq!(pci.identity(&device()), abi::CtlPci { bdf: 0xffff, vendor: 0x1234,
            device: 0x5678, subsystem_vendor: 0xabcd, subsystem_device: 0x9876,
            class: 0x0c, subclass: 3, prog_if: 0x30, revision: 2, owner: abi::PCI_OWNER_NONE });
    }
    assert_eq!(std::mem::size_of::<abi::CtlPci>(), 16);
    assert_eq!(std::mem::offset_of!(abi::CtlPci, class), 10);
    assert_eq!(std::mem::offset_of!(abi::CtlPci, owner), 14);
}

#[test]
fn a_bridge_uses_its_subsystem_capability_instead_of_its_window_registers() {
    let mut pci = Pci::new(1);
    pci.subsystem(0x2c); // This is not a subsystem field on a bridge.
    assert_eq!(pci.identity(&device()).subsystem_vendor, 0);
    pci.config[6] = 0x10;
    pci.config[0x34] = 0x40;
    pci.config[0x40] = 0x05;
    pci.config[0x41] = 0x48;
    pci.config[0x48] = 0x0d;
    pci.subsystem(0x4c);
    let p = pci.identity(&device());
    assert_eq!((p.subsystem_vendor, p.subsystem_device), (0xabcd, 0x9876));
}

#[test]
fn corrupt_capability_chains_are_bounded_and_do_not_read_past_config_space() {
    for (first, id, next) in [(0x40, 5, 0x40), (0xfc, 0x0d, 0), (0x10, 0x0d, 0)] {
        let mut pci = Pci::new(1);
        pci.config[6] = 0x10;
        pci.config[0x34] = first;
        pci.config[first as usize] = id;
        pci.config[first as usize + 1] = next;
        assert_eq!(pci.identity(&device()).subsystem_vendor, 0);
        assert!(pci.reads.get() < 110);
    }
}

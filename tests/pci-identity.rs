//! Production PCI identity reader against configuration-space fixtures.
//! There are deliberately no configuration-write or MMIO methods here.
use std::cell::Cell;
use l4h_abi as abi;

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

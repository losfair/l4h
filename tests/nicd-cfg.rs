//! Root's filter of a nicd's configuration-space writes
//! (host/l4h-root/src/nicd.rs `cap_write_bits`), extracted unchanged by
//! tests/run-devicetest.sh.
include!(env!("L4H_NICD_CFG_TEST_SRC"));

const PCIE: u16 = 0x10;
const C: u16 = 0x60;

#[test]
fn device_control_takes_relaxed_ordering_only() {
    // A dword write over Device Control and Status: of Device Control,
    // relaxed ordering alone.  No Snoop (11), Phantom Functions (9),
    // Max_Payload_Size (5..7), Extended Tag (8) and Max_Read_Request_Size
    // (12..14), and the status bits, stay as root left them.
    assert_eq!(cap_write_bits(PCIE, C, C + 8, 0x8086, u32::MAX), Some(1 << 4));
    for bit in [5, 6, 7, 8, 9, 11, 12, 13, 14, 15, 16, 17] {
        assert_eq!(cap_write_bits(PCIE, C, C + 8, 0x8086, 1 << bit), None, "Device Control bit {bit}");
    }
    // Link Control's ASPM bits, nothing else of the capability.
    assert_eq!(cap_write_bits(PCIE, C, C + 0x10, 0x10ec, u32::MAX), Some(0b11));
    for dword in [C, C + 4, C + 0xc, C + 0x14, C + 0x28, C + 0x30] {
        assert_eq!(cap_write_bits(PCIE, C, dword, 0x8086, u32::MAX), None, "{dword:#x}");
    }
}

#[test]
fn other_capabilities() {
    // AER: the status registers only.
    assert_eq!(cap_write_bits(0x8001, 0x100, 0x104, 0x8086, u32::MAX), Some(u32::MAX));
    assert_eq!(cap_write_bits(0x8001, 0x100, 0x110, 0x8086, u32::MAX), Some(u32::MAX));
    for dword in [0x108, 0x10c, 0x114, 0x118] {
        assert_eq!(cap_write_bits(0x8001, 0x100, dword, 0x8086, u32::MAX), None, "AER {dword:#x}");
    }
    // A vendor-specific capability, but not virtio's (PCI_CFG reaches a
    // whole BAR).
    assert_eq!(cap_write_bits(0x09, 0x50, 0x54, 0x15b3, u32::MAX), Some(u32::MAX));
    assert_eq!(cap_write_bits(0x09, 0x50, 0x54, 0x1af4, u32::MAX), None);
    // MSI, MSI-X, power management: root's.
    for id in [0x01, 0x05, 0x11] {
        assert_eq!(cap_write_bits(id, 0x50, 0x50, 0x8086, u32::MAX), None, "capability {id:#x}");
    }
}

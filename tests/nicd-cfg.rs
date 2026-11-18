//! Root's filter of a nicd's configuration-space writes
//! (host/l4h-root/src/nicd.rs `cap_holding`, `cap_len`, `cap_write_bits`),
//! extracted unchanged by tests/run-devicetest.sh.
include!(env!("L4H_NICD_CFG_TEST_SRC"));

const PCIE: u16 = 0x10;
const C: u16 = 0x60;

/// A function's configuration space, as dwords.
struct Space([u32; 1024]);

impl Space {
    /// With a capability list (Status bit 4).
    fn new() -> Self {
        let mut s = Space([0; 1024]);
        s.0[1] = 1 << 20;
        s
    }
    fn set(&mut self, off: u16, v: u32) -> &mut Self {
        self.0[off as usize / 4] = v;
        self
    }
    /// A standard capability `id` at `c`, `next` the next one's.
    fn cap(&mut self, c: u16, id: u8, next: u16, rest: u16) -> &mut Self {
        self.set(c, (rest as u32) << 16 | (next as u32) << 8 | id as u32)
    }
    /// An extended capability `id` at `c`, `next` the next one's.
    fn ext(&mut self, c: u16, id: u16, next: u16) -> &mut Self {
        self.set(c, (next as u32) << 20 | 1 << 16 | id as u32)
    }
    fn holding(&self, off: u16, size: u16) -> Option<(u16, u16, u16)> {
        cap_holding(|at| {
            assert!(at < 0x1000, "a read past the space, at {at:#x}");
            Some(self.0[at as usize / 4])
        }, off, off + size)
    }
    /// What root lets a write of `size` bytes at `off` change, as
    /// `write_allowed` does past the manifest's windows.
    fn allowed(&self, off: u16, size: u16, virtio: bool) -> Option<u32> {
        let (c, id, len) = self.holding(off, size)?;
        let shift = (off & 3) * 8;
        let bits = if size == 4 { u32::MAX } else { ((1u32 << (size * 8)) - 1) << shift };
        cap_write_bits(id, c, len, off & !3, virtio, bits)
    }
}

#[test]
fn device_control_takes_relaxed_ordering_only() {
    // A dword write over Device Control and Status: of Device Control,
    // relaxed ordering alone.  No Snoop (11), Phantom Functions (9),
    // Max_Payload_Size (5..7), Extended Tag (8) and Max_Read_Request_Size
    // (12..14), and the status bits, stay as root left them.
    assert_eq!(cap_write_bits(PCIE, C, 0x3c, C + 8, false, u32::MAX), Some(1 << 4));
    for bit in [5, 6, 7, 8, 9, 11, 12, 13, 14, 15, 16, 17] {
        assert_eq!(cap_write_bits(PCIE, C, 0x3c, C + 8, false, 1 << bit), None, "Device Control bit {bit}");
    }
    // Link Control's ASPM bits, nothing else of the capability.
    assert_eq!(cap_write_bits(PCIE, C, 0x3c, C + 0x10, false, u32::MAX), Some(0b11));
    for dword in [C, C + 4, C + 0xc, C + 0x14, C + 0x28, C + 0x30] {
        assert_eq!(cap_write_bits(PCIE, C, 0x3c, dword, false, u32::MAX), None, "{dword:#x}");
    }
}

#[test]
fn other_capabilities() {
    // AER: the status registers only.
    assert_eq!(cap_write_bits(0x8001, 0x100, 0x48, 0x104, false, u32::MAX), Some(u32::MAX));
    assert_eq!(cap_write_bits(0x8001, 0x100, 0x48, 0x110, false, u32::MAX), Some(u32::MAX));
    for dword in [0x100, 0x108, 0x10c, 0x114, 0x118] {
        assert_eq!(cap_write_bits(0x8001, 0x100, 0x48, dword, false, u32::MAX), None, "AER {dword:#x}");
    }
    // A vendor-specific capability, but not a virtio device's (PCI_CFG
    // reaches a whole BAR), whatever its vendor.
    assert_eq!(cap_write_bits(0x09, 0x50, 0x10, 0x54, false, u32::MAX), Some(u32::MAX));
    assert_eq!(cap_write_bits(0x09, 0x50, 0x10, 0x54, true, u32::MAX), None);
    // MSI, MSI-X, power management: root's.
    for id in [0x01, 0x05, 0x11] {
        assert_eq!(cap_write_bits(id, 0x50, 0x10, 0x50, false, u32::MAX), None, "capability {id:#x}");
    }
}

#[test]
fn headers_are_never_writable() {
    // A vendor-specific capability's id, next pointer and length: only
    // its first vendor byte of that dword.
    assert_eq!(cap_write_bits(0x09, 0x50, 0x10, 0x50, false, u32::MAX), Some(0xff00_0000));
    assert_eq!(cap_write_bits(0x09, 0x50, 0x10, 0x50, false, 0x00ff_ffff), None);
    // An extended one's header, and the vendor-specific header after it.
    assert_eq!(cap_write_bits(0x800b, 0x100, 0x20, 0x100, false, u32::MAX), None);
    assert_eq!(cap_write_bits(0x800b, 0x100, 0x20, 0x104, false, u32::MAX), None);
    assert_eq!(cap_write_bits(0x800b, 0x100, 0x20, 0x108, false, u32::MAX), Some(u32::MAX));
    // LTR: its latencies only.
    assert_eq!(cap_write_bits(0x8018, 0x200, 8, 0x200, false, u32::MAX), None);
    assert_eq!(cap_write_bits(0x8018, 0x200, 8, 0x204, false, u32::MAX), Some(u32::MAX));
    // L1 PM substates: its controls, not its header or capabilities.
    for (dword, ok) in [(0x300, false), (0x304, false), (0x308, true), (0x30c, true), (0x310, false)] {
        assert_eq!(cap_write_bits(0x801e, 0x300, 0x10, dword, false, u32::MAX).is_some(), ok, "{dword:#x}");
    }
}

#[test]
fn capabilities_end_where_they_say() {
    // Power management, then a 12-byte vendor-specific capability, last
    // of the standard list: the bytes past it, to 0x100, are no
    // capability's.
    let mut s = Space::new();
    s.set(0x34, 0x40).cap(0x40, 0x01, 0x50, 0).cap(0x50, 0x09, 0, 12);
    assert_eq!(s.holding(0x58, 4), Some((0x50, 0x09, 12)));
    assert_eq!(s.allowed(0x58, 4, false), Some(u32::MAX));
    for off in [0x5c, 0x60, 0x80, 0xfc] {
        assert_eq!(s.holding(off, 4), None, "{off:#x}");
        assert_eq!(s.allowed(off, 4, false), None, "{off:#x}");
    }
    // LTR and L1 PM substates last of the extended list: nothing past
    // their registers, up to 0x1000.
    let mut s = Space::new();
    s.ext(0x100, 0x0001, 0x148).ext(0x148, 0x0018, 0x150).ext(0x150, 0x001e, 0);
    assert_eq!(s.allowed(0x14c, 4, false), Some(u32::MAX));
    assert_eq!(s.allowed(0x158, 4, false), Some(u32::MAX));
    assert_eq!(s.allowed(0x15c, 4, false), Some(u32::MAX));
    for off in [0x160, 0x200, 0x800, 0xffc] {
        assert_eq!(s.allowed(off, 4, false), None, "{off:#x}");
    }
    // A vendor-specific extended capability of 0x18 bytes, then a gap
    // to an SR-IOV capability: the gap is no capability's.
    let mut s = Space::new();
    s.ext(0x100, 0x000b, 0x200).set(0x104, 0x18 << 20 | 0x1234).ext(0x200, 0x0010, 0);
    assert_eq!(s.allowed(0x114, 4, false), Some(u32::MAX));
    for off in [0x118, 0x180, 0x1fc, 0x200, 0x208] {
        assert_eq!(s.allowed(off, 4, false), None, "{off:#x}");
    }
}

#[test]
fn malformed_lengths_and_lists_fail_closed() {
    // A vendor-specific capability declaring more than reaches the next
    // one, or less than its own header.
    let mut s = Space::new();
    s.set(0x34, 0x50).cap(0x50, 0x09, 0x60, 0x20).cap(0x60, 0x10, 0, 0);
    assert_eq!(s.allowed(0x54, 4, false), None);
    s.cap(0x50, 0x09, 0x60, 2);
    assert_eq!(s.allowed(0x50, 4, false), None);
    // An extended one past the space's end, or shorter than its headers.
    let mut s = Space::new();
    s.ext(0xff0, 0x000b, 0).set(0x100, 0xff0 << 20 | 1 << 16 | 0x0001).set(0xff4, 0x20 << 20);
    assert_eq!(s.allowed(0xff8, 4, false), None);
    s.set(0xff4, 4 << 20);
    assert_eq!(s.allowed(0xff8, 4, false), None);
    // LTR with the next capability inside it.
    let mut s = Space::new();
    s.ext(0x100, 0x0018, 0x104).ext(0x104, 0x0001, 0);
    assert_eq!(s.holding(0x100, 4), None);
    s.ext(0x100, 0x0018, 0x108);
    assert_eq!(s.holding(0x100, 4), Some((0x100, 0x8018, 8)));
    // A loop, a pointer into the header, a standard pointer from the
    // extended list: nothing is writable.
    let mut s = Space::new();
    s.set(0x34, 0x40).cap(0x40, 0x09, 0x50, 0x10).cap(0x50, 0x10, 0x40, 0);
    assert_eq!(s.allowed(0x44, 4, false), None);
    s.cap(0x50, 0x10, 0x20, 0);
    assert_eq!(s.allowed(0x44, 4, false), None);
    let mut s = Space::new();
    s.ext(0x100, 0x0018, 0x80);
    assert_eq!(s.allowed(0x104, 4, false), None);
    // A vendor-specific extended capability in the space's last dword:
    // its second header would be past the space, and is not read.
    let mut s = Space::new();
    s.set(0x100, 0xffc << 20 | 1 << 16 | 0x0001).ext(0xffc, 0x000b, 0);
    assert_eq!(s.holding(0xffc, 4), None);
    // An extended pointer with its reserved low bits set.
    let mut s = Space::new();
    s.set(0x100, 0x149 << 20 | 1 << 16 | 0x0001).ext(0x148, 0x0018, 0);
    assert_eq!(s.allowed(0x14c, 4, false), None);
    s.set(0x100, 0x148 << 20 | 1 << 16 | 0x0001);
    assert_eq!(s.allowed(0x14c, 4, false), Some(u32::MAX));
    // No capability list in Status: 0x34 is no pointer.
    let mut s = Space::new();
    s.set(0x34, 0x50).cap(0x50, 0x09, 0, 0x10);
    assert_eq!(s.allowed(0x54, 4, false), Some(u32::MAX));
    s.set(0x04, 0);
    assert_eq!(s.allowed(0x54, 4, false), None);
    // Extended ids past 0x7fff are none of root's kinds (0x8018 is not
    // LTR).
    let mut s = Space::new();
    s.ext(0x100, 0x8018, 0);
    assert_eq!(s.allowed(0x104, 4, false), None);
}

#[test]
fn long_lists_are_walked_whole() {
    // 200 extended capabilities: an ACS one far down the list stays out
    // of reach of the LTR before it, however many came first.
    let mut s = Space::new();
    let mut c = 0x100;
    for _ in 0..200 {
        s.ext(c, 0x0001, c + 0x10);
        c += 0x10;
    }
    s.ext(c, 0x0018, c + 0x10).ext(c + 0x10, 0x000d, 0);
    assert_eq!(s.holding(c + 4, 4), Some((c, 0x8018, 8)));
    assert_eq!(s.allowed(c + 0x10, 4, false), None);
    assert_eq!(s.allowed(c + 0x14, 4, false), None);
    assert_eq!(s.allowed(c + 8, 4, false), None);
}

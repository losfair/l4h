//! PCI configuration space (DESIGN.md §5.11): bus 0, through ECAM at
//! 0xe000_0000 (MCFG) and the legacy 0xcf8/0xcfc ports.  Its functions
//! are the host bridge at 00:00.0 and a virtio device at each of 00:01.0
//! and up, whose BARs the "firmware" (we) assigns in the 32-bit window
//! [0xc000_0000, 0xe000_0000).  Only the I/O thread touches it.  Free of
//! seL4.

pub const ECAM_BASE: u64 = 0xe000_0000;
/// Bus 0's 32 devices of 8 functions, 4 KiB each.
pub const ECAM_SIZE: u64 = 1 << 20;
pub const MMIO_BASE: u64 = 0xc000_0000;
pub const MMIO_SIZE: u64 = 0x2000_0000;
/// Each device's share of the window: its BARs.
pub const SLOT_MMIO: u64 = 0x10_0000;
pub const SLOTS: usize = 32;

pub const CAP_MSIX: u8 = 0x11;
pub const CAP_VENDOR: u8 = 0x09;

const COMMAND: usize = 0x04;
const STATUS: usize = 0x06;
const BAR0: usize = 0x10;
const CAP_PTR: usize = 0x34;
const INT_LINE: usize = 0x3c;
const INT_PIN: usize = 0x3d;

pub const CMD_MEM: u16 = 1 << 1;
pub const CMD_INTX_DISABLE: u16 = 1 << 10;

/// The legacy configuration address (0xcf8) as an ECAM offset of bus 0,
/// with the byte `port` (0xcfc-0xcff) selects: None if it is disabled,
/// or names another bus.
pub fn cf8_offset(cf8: u32, port: u16) -> Option<u64> {
    if cf8 & (1 << 31) == 0 || (cf8 >> 16) & 0xff != 0 {
        return None;
    }
    let (dev, func, reg) = ((cf8 >> 11) & 0x1f, (cf8 >> 8) & 7, cf8 & 0xfc);
    Some(((dev as u64) << 15) | ((func as u64) << 12) | reg as u64 | (port as u64 & 3))
}

#[derive(Clone, Copy, Default)]
struct Bar {
    size: u64,
    is64: bool,
}

/// A function's configuration space: the first 256 bytes (the extended
/// space reads 0: no extended capabilities).
pub struct Config {
    data: [u8; 256],
    /// Bits the guest may write.
    wmask: [u8; 256],
    bars: [Bar; 6],
    /// Where the next capability goes, and the last one's next pointer.
    next_cap: usize,
    last_next: usize,
}

impl Config {
    /// A type-0 header: vendor, device, revision, class (base, sub,
    /// interface), subsystem vendor and id, interrupt pin (1 INTA, 0 none).
    pub fn new(vendor: u16, device: u16, revision: u8, class: u32, subsys: (u16, u16), pin: u8) -> Self {
        let mut c = Config { data: [0; 256], wmask: [0; 256], bars: [Bar::default(); 6], next_cap: 0x40, last_next: CAP_PTR };
        c.put(0x00, 2, vendor as u32);
        c.put(0x02, 2, device as u32);
        c.put(0x08, 4, (class << 8) | revision as u32);
        c.put(0x2c, 2, subsys.0 as u32);
        c.put(0x2e, 2, subsys.1 as u32);
        c.data[INT_PIN] = pin;
        c.data[INT_LINE] = 0xff;
        c.wmask[INT_LINE] = 0xff;
        // Memory space, bus master, INTx disable.
        c.wmask[COMMAND] = 0x06;
        c.wmask[COMMAND + 1] = 0x04;
        c
    }

    /// Store `size` bytes of `v` at `off`, as the device.
    pub fn put(&mut self, off: usize, size: usize, v: u32) {
        for i in 0..size {
            self.data[off + i] = (v >> (8 * i)) as u8;
        }
    }

    pub fn get(&self, off: usize, size: usize) -> u32 {
        (0..size).fold(0, |v, i| v | (self.data[off + i] as u32) << (8 * i))
    }

    /// A 64-bit memory BAR `i` (and i + 1) of `size` bytes (a power of
    /// two), at `addr`.
    pub fn bar64(&mut self, i: usize, size: u64, addr: u64) {
        self.bars[i] = Bar { size, is64: true };
        self.put(BAR0 + 4 * i, 4, (addr as u32 & !0xf) | 0x4);
        self.put(BAR0 + 4 * i + 4, 4, (addr >> 32) as u32);
    }

    /// Append a capability of `id` with `body` after its two header bytes:
    /// its offset.
    pub fn add_cap(&mut self, id: u8, body: &[u8]) -> usize {
        let at = self.next_cap;
        assert!(at + 2 + body.len() <= 256, "PCI capabilities overflow");
        self.data[at] = id;
        self.data[at + 1] = 0;
        self.data[at + 2..at + 2 + body.len()].copy_from_slice(body);
        self.data[self.last_next] = at as u8;
        self.last_next = at + 1;
        // Status: capabilities list.
        self.data[STATUS] |= 1 << 4;
        self.next_cap = (at + 2 + body.len()).next_multiple_of(4);
        at
    }

    /// Let the guest write `mask` at `off` (a capability's fields).
    pub fn writable(&mut self, off: usize, size: usize, mask: u32) {
        for i in 0..size {
            self.wmask[off + i] = (mask >> (8 * i)) as u8;
        }
    }

    /// The guest reads `size` bytes at `off`.
    pub fn read(&self, off: u64, size: u8) -> u32 {
        let off = off as usize;
        if off + size as usize > 256 {
            return 0;
        }
        self.get(off, size as usize)
    }

    /// The guest writes `size` bytes of `v` at `off`.
    pub fn write(&mut self, off: u64, size: u8, v: u32) {
        let off = off as usize;
        if off + size as usize > 256 {
            return;
        }
        for i in 0..size as usize {
            let b = off + i;
            let byte = (v >> (8 * i)) as u8;
            self.data[b] = (self.data[b] & !self.wmask[b]) | (byte & self.wmask[b]);
        }
        // BARs: the address bits a size allows, the flags stay.
        let first = off.saturating_sub(BAR0) / 4;
        let last = (off + size as usize - 1).saturating_sub(BAR0) / 4;
        if off + size as usize > BAR0 && off < BAR0 + 24 {
            for reg in first..=last.min(5) {
                self.write_bar_reg(reg, off, size as usize, v);
            }
        }
    }

    fn write_bar_reg(&mut self, reg: usize, off: usize, size: usize, v: u32) {
        // Which BAR, and whether this register is its upper half.
        let (i, upper) = if reg > 0 && self.bars[reg - 1].is64 && self.bars[reg - 1].size != 0 { (reg - 1, true) } else { (reg, false) };
        let bar = self.bars[i];
        if bar.size == 0 {
            return;
        }
        // Merge the bytes written into the register's current value.
        let at = BAR0 + 4 * reg;
        let mut cur = self.get(at, 4);
        for k in 0..size {
            let b = off + k;
            if b >= at && b < at + 4 {
                let shift = 8 * (b - at);
                cur = (cur & !(0xff << shift)) | (((v >> (8 * k)) & 0xff) << shift);
            }
        }
        if upper {
            let mask = !((bar.size - 1) >> 32) as u32;
            self.put(at, 4, cur & mask);
        } else {
            let mask = !(bar.size.min(1 << 32) - 1) as u32;
            self.put(at, 4, (cur & mask & !0xf) | if bar.is64 { 0x4 } else { 0 });
        }
    }

    /// BAR `i`'s address, if memory decoding is on.
    pub fn bar_addr(&self, i: usize) -> Option<u64> {
        let bar = self.bars[i];
        if bar.size == 0 || self.command() & CMD_MEM == 0 {
            return None;
        }
        let lo = (self.get(BAR0 + 4 * i, 4) & !0xf) as u64;
        let hi = if bar.is64 { self.get(BAR0 + 4 * i + 4, 4) as u64 } else { 0 };
        Some(lo | hi << 32)
    }

    pub fn bar_size(&self, i: usize) -> u64 {
        self.bars[i].size
    }

    pub fn command(&self) -> u16 {
        self.get(COMMAND, 2) as u16
    }

}

/// The host bridge, 00:00.0: Red Hat's generic PCIe host bridge (QEMU's
/// GPEX), as guests know it.
pub fn host_bridge() -> Config {
    Config::new(0x1b36, 0x0008, 0, 0x06_0000, (0x1af4, 0x1100), 0)
}

/// The GSI of slot `slot`'s INTx pin `pin` (1-4), as the DSDT's _PRT
/// routes it: the I/O APIC's pins 16-23.
pub const fn intx_gsi(slot: usize, pin: u8) -> usize {
    16 + (slot + pin as usize - 1) % 8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_bars_and_caps() {
        let mut c = Config::new(0x1af4, 0x1042, 1, 0x01_0000, (0x1af4, 2), 1);
        c.bar64(0, 0x4000, 0xc010_0000);
        c.bar64(2, 0x2000, 0xc010_4000);
        assert_eq!(c.read(0, 4), 0x1042_1af4);
        assert_eq!(c.read(8, 4), 0x0100_0001);
        assert_eq!(c.read(0x10, 4), 0xc010_0004);
        assert_eq!(c.bar_addr(0), None, "decoding off");
        c.write(4, 2, 0xffff);
        assert_eq!(c.command(), 0x0406);
        assert_eq!(c.bar_addr(0), Some(0xc010_0000));
        // Sizing: all ones reads back the size mask, then the address
        // is restored.
        c.write(0x10, 4, 0xffff_ffff);
        c.write(0x14, 4, 0xffff_ffff);
        assert_eq!(c.read(0x10, 4), 0xffff_c004);
        assert_eq!(c.read(0x14, 4), 0xffff_ffff);
        c.write(0x10, 4, 0xd000_0000);
        c.write(0x14, 4, 0);
        assert_eq!(c.bar_addr(0), Some(0xd000_0000));
        // An unaligned address is rounded down to the BAR's size.
        c.write(0x18, 4, 0xd000_1234);
        assert_eq!(c.bar_addr(2), Some(0xd000_0000));
        // Unused BARs and the vendor fields are read-only.
        c.write(0x20, 4, 0xffff_ffff);
        assert_eq!(c.read(0x20, 4), 0);
        c.write(0, 4, 0);
        assert_eq!(c.read(0, 2), 0x1af4);
        // Capabilities: a chain from 0x34.
        let a = c.add_cap(CAP_MSIX, &[0; 10]);
        let b = c.add_cap(CAP_VENDOR, &[16, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!((c.read(0x34, 1), c.read(a as u64 + 1, 1), c.read(b as u64 + 1, 1)), (a as u32, b as u32, 0));
        assert!(c.read(6, 2) & 0x10 != 0);
        assert_eq!(c.read(0x100, 4), 0, "no extended capabilities");
        // Interrupt line is the guest's.
        c.write(0x3c, 1, 11);
        assert_eq!(c.read(0x3c, 2), 0x010b);
    }

    #[test]
    fn legacy_addresses() {
        assert_eq!(cf8_offset(0x8000_0800 | 0x10, 0xcfd), Some((1 << 15) | 0x11));
        assert_eq!(cf8_offset(0x0000_0800, 0xcfc), None, "disabled");
        assert_eq!(cf8_offset(0x8001_0000, 0xcfc), None, "bus 1");
        assert_eq!(intx_gsi(1, 1), 17);
        assert_eq!(intx_gsi(7, 2), 16);
    }
}

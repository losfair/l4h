// Run with tests/run-acstest.sh; no seL4 runtime is needed.
// BAR sizing (host/l4h-root/src/barsize.rs, also the shim's) against a
// model of a type 0 function's BAR registers.
#[path = "../host/l4h-root/src/barsize.rs"]
mod barsize;

use barsize::{size_bars, Sized};
use std::cell::RefCell;

/// Registers 0x10..0x2c: each a value and the mask of its writable bits.
struct Func {
    regs: RefCell<[(u32, u32); 7]>,
    writes: RefCell<Vec<u8>>,
}

impl Func {
    fn new() -> Func {
        Func { regs: RefCell::new([(0, 0); 7]), writes: RefCell::new(Vec::new()) }
    }
    fn set(&self, off: u8, value: u32, writable: u32) {
        self.regs.borrow_mut()[(off as usize - 0x10) / 4] = (value, writable);
    }
    fn read(&self, off: u8) -> u32 {
        self.regs.borrow()[(off as usize - 0x10) / 4].0
    }
    fn write(&self, off: u8, v: u32) {
        self.writes.borrow_mut().push(off);
        let r = &mut self.regs.borrow_mut()[(off as usize - 0x10) / 4];
        r.0 = (r.0 & !r.1) | (v & r.1);
    }
    /// A 64-bit memory BAR of `size` at `addr`, in `off` and `off + 4`.
    fn bar64(&self, off: u8, addr: u64, size: u64, prefetch: bool) {
        let mask = !(size - 1);
        let flags = 4 | if prefetch { 8 } else { 0 };
        self.set(off, addr as u32 | flags, mask as u32 & !0xf);
        self.set(off + 4, (addr >> 32) as u32, (mask >> 32) as u32);
    }
    fn size(&self, n: usize) -> [Option<Sized>; 6] {
        let before = *self.regs.borrow();
        let bars = size_bars(n, |o| self.read(o), |o, v| self.write(o, v));
        assert_eq!(*self.regs.borrow(), before, "BAR registers not restored");
        bars
    }
}

fn mem(addr: u64, size: u64, is64: bool, prefetch: bool) -> Option<Sized> {
    Some(Sized { addr, size, is_io: false, is64, prefetch })
}

#[test]
fn bar_32bit_and_io() {
    let f = Func::new();
    f.set(0x10, 0xfe00_0000, 0xfff0_0000); // 1 MiB
    f.set(0x14, 0xc001, 0xffe0); // 32 ports
    let bars = f.size(6);
    assert_eq!(bars[0], mem(0xfe00_0000, 1 << 20, false, false));
    assert_eq!(bars[1], Some(Sized { addr: 0xc000, size: 32, is_io: true, is64: false, prefetch: false }));
    assert!(bars[2..].iter().all(Option::is_none));
}

#[test]
fn bar_64bit_below_4g() {
    let f = Func::new();
    f.bar64(0x10, 0x38_0000_0000, 16 << 20, true);
    let bars = f.size(6);
    assert_eq!(bars[0], mem(0x38_0000_0000, 16 << 20, true, true));
    assert_eq!(bars[1], None);
}

/// The low register of a BAR of 4 GiB or more has no writable bits.
#[test]
fn bar_64bit_4g_and_larger() {
    for size in [4u64 << 30, 8 << 30, 16 << 30, 1 << 40] {
        let f = Func::new();
        let addr = 0x400_0000_0000u64;
        f.bar64(0x10, addr, size, true);
        f.bar64(0x18, 0x80_0000_0000, 1 << 20, false);
        let bars = f.size(6);
        assert_eq!(bars[0], mem(addr, size, true, true), "size {size:#x}");
        assert_eq!(bars[2], mem(0x80_0000_0000, 1 << 20, true, false));
    }
}

/// BAR5 cannot be the low half of a 64-bit BAR: 0x28 is not a BAR.
#[test]
fn bar5_claiming_64bit() {
    let f = Func::new();
    f.set(0x10, 0xfe00_0000, 0xffff_f000);
    f.set(0x24, 0xfd00_0004, 0xffff_f000);
    f.set(0x28, 0x1234_5678, 0xffff_ffff);
    let bars = f.size(6);
    assert_eq!(bars[0], mem(0xfe00_0000, 4096, false, false));
    assert_eq!(bars[5], None);
    assert!(!f.writes.borrow().iter().any(|&o| o == 0x24 || o == 0x28), "wrote {:x?}", f.writes.borrow());
    assert_eq!(f.read(0x28), 0x1234_5678);
    // Also when the shim sizes fewer BARs.
    let f = Func::new();
    f.set(0x14, 0xfd00_0004, 0xffff_f000);
    let bars = f.size(2);
    assert_eq!(bars[1], None);
    assert!(!f.writes.borrow().iter().any(|&o| o >= 0x14), "wrote {:x?}", f.writes.borrow());
}

/// Not implemented, or a mask that is not a size.
#[test]
fn bar_unimplemented_or_bogus() {
    let f = Func::new();
    f.set(0x10, 0, 0); // 32-bit, nothing writable
    f.set(0x14, 4, 0);
    f.set(0x18, 0, 0); // 64-bit, nothing writable in either half
    f.set(0x1c, 0xfe00_0000, 0xff0f_f000); // not contiguous
    let bars = f.size(6);
    assert!(bars.iter().all(Option::is_none), "{bars:?}");
}

/// A base that puts the end past 2^64.
#[test]
fn bar_64bit_end_overflow() {
    let f = Func::new();
    f.set(0x10, 0xffff_f004, 0xffff_f000);
    f.set(0x14, 0xffff_ffff, 0xffff_ffff);
    // Every address bit writable but the low 12: 4 KiB at 2^64 - 4 KiB ends at 2^64.
    let bars = f.size(6);
    assert_eq!(bars[0], None);
    let f = Func::new();
    f.bar64(0x10, 0xffff_ffff_ffff_e000, 4096, false);
    assert_eq!(f.size(6)[0], mem(0xffff_ffff_ffff_e000, 4096, true, false));
}

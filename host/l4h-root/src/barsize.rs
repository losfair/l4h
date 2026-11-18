//! Sizing the BARs of a type 0 function, shared by root (pci.rs) and the
//! multikernel shim (boot/l4h-mkshim/src/pci.rs), which sizes them for every
//! partition.  Tested by tests/barsize.rs (tests/run-acstest.sh).
//!
//! The caller turns decoding off around it.  A 64-bit memory BAR takes two
//! registers and its size is that of the 64-bit mask: one of 4 GiB or more
//! reads back zero in its low register.  A 64-bit BAR in the last register
//! has no upper half among the BARs (BAR5's next dword, 0x28, is the
//! CardBus CIS pointer): it is left alone, unwritten and not reported.

/// A BAR the function implements.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sized {
    pub addr: u64,
    /// A power of two; the BAR ends below 2^64.
    pub size: u64,
    pub is_io: bool,
    pub is64: bool,
    pub prefetch: bool,
}

/// The first `n` (at most 6) BARs, through `read` and `write` of a dword of
/// configuration space at an offset.  Each BAR register is restored.
pub fn size_bars(n: usize, read: impl Fn(u8) -> u32, write: impl Fn(u8, u32)) -> [Option<Sized>; 6] {
    let mut bars = [None; 6];
    let n = n.min(6);
    let mut i = 0;
    while i < n {
        let off = 0x10 + 4 * i as u8;
        let orig = read(off);
        if orig & 1 != 0 {
            write(off, 0xffff_ffff);
            let sz = read(off) & !3;
            write(off, orig);
            if sz != 0 {
                bars[i] = Some(Sized {
                    addr: (orig & !3) as u64,
                    size: ((!sz).wrapping_add(1) & 0xffff) as u64,
                    is_io: true,
                    is64: false,
                    prefetch: false,
                });
            }
            i += 1;
            continue;
        }
        let is64 = (orig >> 1) & 3 == 2;
        if is64 && i + 1 >= n {
            break;
        }
        write(off, 0xffff_ffff);
        let lo = read(off) & !0xf;
        write(off, orig);
        let mut addr = (orig & !0xf) as u64;
        let mut mask = lo as u64 | 0xffff_ffff_0000_0000;
        if is64 {
            let orig_hi = read(off + 4);
            write(off + 4, 0xffff_ffff);
            let hi = read(off + 4);
            write(off + 4, orig_hi);
            addr |= (orig_hi as u64) << 32;
            mask = (hi as u64) << 32 | lo as u64;
        }
        // A 32-bit BAR reading back zero is not implemented; a 64-bit one
        // is if its upper half is.  The writable bits are the high ones.
        let size = (!mask).wrapping_add(1);
        if (is64 || lo != 0) && size.is_power_of_two() && addr.checked_add(size).is_some() {
            bars[i] = Some(Sized { addr, size, is_io: false, is64, prefetch: orig & 8 != 0 });
        }
        i += if is64 { 2 } else { 1 };
    }
    bars
}

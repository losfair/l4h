//! The I/O APIC at 0xfec0_0000 (24 pins), which routes the guest's wired
//! interrupts (the UART's IRQ 4, the SCI on 9, PCI INTx when a virtio
//! device has no MSI-X) to the local APICs.  Its vCPU threads share it,
//! under a lock (hvm.rs); the I/O thread only changes lines' levels
//! (`Lines`), which a vCPU then applies.  Free of seL4.

use super::apic::{Message, Shorthand};

pub const PINS: usize = 24;
pub const BASE: u64 = 0xfec0_0000;
pub const END: u64 = BASE + 0x1000;

const REGSEL: u64 = 0x00;
const WINDOW: u64 = 0x10;
const EOI: u64 = 0x40;

const VECTOR: u64 = 0xff;
const DEST_LOGICAL: u64 = 1 << 11;
const REMOTE_IRR: u64 = 1 << 14;
const LEVEL: u64 = 1 << 15;
const MASKED: u64 = 1 << 16;
/// What the guest may write of an entry: vector, delivery and destination
/// mode, polarity, trigger mode, mask and destination (not delivery
/// status, remote IRR, nor the reserved bits).
const WRITABLE: u64 = 0xff00_0000_0001_afff;

pub struct IoApic {
    id: u32,
    sel: u32,
    redir: [u64; PINS],
    /// Lines asserted (level), as their sources say.
    lines: u32,
}

impl Default for IoApic {
    fn default() -> Self {
        Self::new()
    }
}

impl IoApic {
    pub const fn new() -> Self {
        IoApic { id: 0, sel: 0, redir: [MASKED; PINS], lines: 0 }
    }

    fn message(e: u64) -> Message {
        Message {
            dest: (e >> 56) as u32,
            logical: e & DEST_LOGICAL != 0,
            shorthand: Shorthand::None,
            mode: ((e >> 8) & 7) as u8,
            vector: (e & VECTOR) as u8,
            level: e & LEVEL != 0,
        }
    }

    /// Deliver pin `pin` if it is asserted and may be: unmasked, and for a
    /// level-triggered pin not yet in service.
    fn service(&mut self, pin: usize, out: &mut impl FnMut(Message)) {
        let e = self.redir[pin];
        if self.lines & (1 << pin) == 0 || e & MASKED != 0 || (e & LEVEL != 0 && e & REMOTE_IRR != 0) {
            return;
        }
        if e & LEVEL != 0 {
            self.redir[pin] |= REMOTE_IRR;
        }
        out(Self::message(e));
    }

    /// Set line `pin` to `level` (asserted or not): an edge-triggered pin
    /// delivers on assertion, a level-triggered one while asserted.
    pub fn set_line(&mut self, pin: usize, level: bool, out: &mut impl FnMut(Message)) {
        if pin >= PINS {
            return;
        }
        let was = self.lines & (1 << pin) != 0;
        if level {
            self.lines |= 1 << pin;
        } else {
            self.lines &= !(1 << pin);
        }
        let e = self.redir[pin];
        if level && (e & LEVEL != 0 || !was) {
            self.service(pin, out);
        }
    }

    /// The lines' levels, as `set_line` would set them one by one.
    pub fn set_lines(&mut self, lines: u32, out: &mut impl FnMut(Message)) {
        for pin in 0..PINS {
            self.set_line(pin, lines & (1 << pin) != 0, out);
        }
    }

    /// A local APIC ended level-triggered interrupt `vector`.
    pub fn eoi(&mut self, vector: u8, out: &mut impl FnMut(Message)) {
        for pin in 0..PINS {
            let e = self.redir[pin];
            if e & LEVEL != 0 && e & REMOTE_IRR != 0 && (e & VECTOR) as u8 == vector {
                self.redir[pin] &= !REMOTE_IRR;
                self.service(pin, out);
            }
        }
    }

    /// Read `size` bytes at offset `off` of its page.
    pub fn read(&self, off: u64) -> u32 {
        match off {
            REGSEL => self.sel,
            WINDOW => match self.sel {
                0 => self.id << 24,
                // Version 0x20 (with the EOI register), PINS - 1 entries.
                1 => 0x20 | ((PINS as u32 - 1) << 16),
                2 => self.id << 24,
                r @ 0x10..=0x3f => {
                    let pin = ((r - 0x10) / 2) as usize;
                    let e = self.redir[pin];
                    if r % 2 == 0 { e as u32 } else { (e >> 32) as u32 }
                }
                _ => 0,
            },
            _ => 0,
        }
    }

    pub fn write(&mut self, off: u64, val: u32, out: &mut impl FnMut(Message)) {
        match off {
            REGSEL => self.sel = val & 0xff,
            WINDOW => match self.sel {
                0 => self.id = (val >> 24) & 0xf,
                r @ 0x10..=0x3f => {
                    let pin = ((r - 0x10) / 2) as usize;
                    let old = self.redir[pin];
                    let new = if r % 2 == 0 { (old & !0xffff_ffff) | val as u64 } else { (old & 0xffff_ffff) | ((val as u64) << 32) };
                    self.redir[pin] = (old & !WRITABLE) | (new & WRITABLE);
                    // An edge-triggered entry holds no remote IRR.
                    if self.redir[pin] & LEVEL == 0 {
                        self.redir[pin] &= !REMOTE_IRR;
                    }
                    // Unmasking, or making level-triggered, an asserted pin.
                    if self.redir[pin] & LEVEL != 0 || (old & MASKED != 0 && self.redir[pin] & MASKED == 0) {
                        self.service(pin, out);
                    }
                }
                _ => {}
            },
            EOI => self.eoi(val as u8, out),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    fn entry(io: &mut IoApic, pin: u32, lo: u32, hi: u32, out: &mut Vec<Message>) {
        io.write(REGSEL, 0x10 + 2 * pin, &mut |m| out.push(m));
        io.write(WINDOW, lo, &mut |m| out.push(m));
        io.write(REGSEL, 0x11 + 2 * pin, &mut |m| out.push(m));
        io.write(WINDOW, hi, &mut |m| out.push(m));
    }

    #[test]
    fn edge_and_level() {
        let mut io = IoApic::new();
        let mut out = Vec::new();
        io.write(REGSEL, 1, &mut |_| {});
        assert_eq!(io.read(WINDOW), 0x0017_0020);
        // Masked at reset: an edge is lost.
        io.set_line(4, true, &mut |m| out.push(m));
        io.set_line(4, false, &mut |m| out.push(m));
        assert!(out.is_empty());
        // Edge, to APIC 2.
        entry(&mut io, 4, 0x34, 2 << 24, &mut out);
        io.set_line(4, true, &mut |m| out.push(m));
        io.set_line(4, true, &mut |m| out.push(m));
        assert_eq!(out.len(), 1, "one edge, one interrupt");
        assert_eq!((out[0].vector, out[0].dest, out[0].level), (0x34, 2, false));
        out.clear();
        // Level, logical: delivered while asserted, again after EOI.
        entry(&mut io, 9, 0x8000 | 0x800 | 0x41, 1 << 24, &mut out);
        io.set_line(9, true, &mut |m| out.push(m));
        io.set_line(9, true, &mut |m| out.push(m));
        assert_eq!(out.len(), 1, "remote IRR holds it");
        io.write(REGSEL, 0x10 + 18, &mut |_| {});
        assert!(io.read(WINDOW) & (1 << 14) != 0, "remote IRR reads set");
        io.eoi(0x41, &mut |m| out.push(m));
        assert_eq!(out.len(), 2, "still asserted: again");
        io.set_line(9, false, &mut |m| out.push(m));
        io.write(EOI, 0x41, &mut |m| out.push(m));
        assert_eq!(out.len(), 2, "deasserted: done");
        assert!(out[1].logical && out[1].level);
        // Unmasking an asserted level pin delivers it.
        out.clear();
        entry(&mut io, 11, 0x1_8000 | 0x51, 0, &mut out);
        io.set_line(11, true, &mut |m| out.push(m));
        assert!(out.is_empty());
        entry(&mut io, 11, 0x8000 | 0x51, 0, &mut out);
        assert_eq!(out.len(), 1);
        // Out of range pins and registers are ignored.
        io.set_line(30, true, &mut |m| out.push(m));
        io.write(REGSEL, 0x50, &mut |_| {});
        assert_eq!(io.read(WINDOW), 0);
    }
}

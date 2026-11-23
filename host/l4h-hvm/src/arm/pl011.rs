//! A PL011 UART, the guest's console (DESIGN.md §5.11): what it transmits
//! goes to the console ring, what vmmgr writes to the console page is what
//! it receives (console.rs).  The transmitter is always ready.  Its vCPU
//! threads share it under a lock.  Free of seL4.

use crate::console::ConsoleIo as Io;

const DR: u64 = 0x000;
const RSR: u64 = 0x004;
const FR: u64 = 0x018;
const ILPR: u64 = 0x020;
const IBRD: u64 = 0x024;
const FBRD: u64 = 0x028;
const LCR_H: u64 = 0x02c;
const CR: u64 = 0x030;
const IFLS: u64 = 0x034;
const IMSC: u64 = 0x038;
const RIS: u64 = 0x03c;
const MIS: u64 = 0x040;
const ICR: u64 = 0x044;
const DMACR: u64 = 0x048;

const FR_RXFE: u32 = 1 << 4;
const FR_TXFE: u32 = 1 << 7;
const INT_RX: u32 = 1 << 4;
const INT_TX: u32 = 1 << 5;
const INT_RT: u32 = 1 << 6;
const INT_ALL: u32 = 0x7ff;
const CR_RESET: u32 = 0x300;
const IFLS_RESET: u32 = 0x12;

/// The PrimeCell identification registers from 0xfe0: PL011 r1p5.
const ID: [u8; 8] = [0x11, 0x10, 0x14, 0x00, 0x0d, 0xf0, 0x05, 0xb1];

pub struct Pl011 {
    ibrd: u32,
    fbrd: u32,
    lcr_h: u32,
    cr: u32,
    ifls: u32,
    imsc: u32,
    ilpr: u32,
    dmacr: u32,
    /// TX's raw interrupt, until cleared; RX's follows the input.
    tx: bool,
}

impl Default for Pl011 {
    fn default() -> Self {
        Self::new()
    }
}

impl Pl011 {
    pub const fn new() -> Self {
        Pl011 { ibrd: 0, fbrd: 0, lcr_h: 0, cr: CR_RESET, ifls: IFLS_RESET, imsc: 0, ilpr: 0, dmacr: 0, tx: false }
    }

    fn ris(&self, io: &mut impl Io) -> u32 {
        let rx = if io.peek().is_some() { INT_RX | INT_RT } else { 0 };
        rx | if self.tx { INT_TX } else { 0 }
    }

    /// The interrupt line's level.
    pub fn irq(&self, io: &mut impl Io) -> bool {
        self.ris(io) & self.imsc != 0
    }

    pub fn read(&mut self, off: u64, io: &mut impl Io) -> u32 {
        match off {
            DR => match io.peek() {
                Some(b) => {
                    io.take();
                    b as u32
                }
                None => 0,
            },
            RSR => 0,
            FR => FR_TXFE | if io.peek().is_none() { FR_RXFE } else { 0 },
            ILPR => self.ilpr,
            IBRD => self.ibrd,
            FBRD => self.fbrd,
            LCR_H => self.lcr_h,
            CR => self.cr,
            IFLS => self.ifls,
            IMSC => self.imsc,
            RIS => self.ris(io),
            MIS => self.ris(io) & self.imsc,
            DMACR => self.dmacr,
            0xfe0..=0xffc => ID[((off - 0xfe0) / 4) as usize] as u32,
            _ => 0,
        }
    }

    pub fn write(&mut self, off: u64, v: u32, io: &mut impl Io) {
        match off {
            DR => {
                io.transmit(v as u8);
                self.tx = true;
            }
            ILPR => self.ilpr = v & 0xff,
            IBRD => self.ibrd = v & 0xffff,
            FBRD => self.fbrd = v & 0x3f,
            LCR_H => self.lcr_h = v & 0xff,
            CR => self.cr = v & 0xff87,
            IFLS => self.ifls = v & 0x3f,
            IMSC => self.imsc = v & INT_ALL,
            ICR if v & INT_TX != 0 => self.tx = false,
            DMACR => self.dmacr = v & 7,
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::vec::Vec;

    #[derive(Default)]
    struct Term {
        out: Vec<u8>,
        input: VecDeque<u8>,
    }

    impl Io for Term {
        fn transmit(&mut self, b: u8) {
            self.out.push(b);
        }
        fn peek(&mut self) -> Option<u8> {
            self.input.front().copied()
        }
        fn take(&mut self) {
            self.input.pop_front();
        }
    }

    #[test]
    fn identifies_as_a_primecell() {
        let (mut u, mut t) = (Pl011::new(), Term::default());
        let id: Vec<u32> = (0..8).map(|i| u.read(0xfe0 + 4 * i, &mut t)).collect();
        assert_eq!(id, [0x11, 0x10, 0x14, 0x00, 0x0d, 0xf0, 0x05, 0xb1]);
    }

    #[test]
    fn transmit_and_its_interrupt() {
        let (mut u, mut t) = (Pl011::new(), Term::default());
        assert_eq!(u.read(FR, &mut t) & FR_TXFE, FR_TXFE, "always ready");
        u.write(DR, b'h' as u32, &mut t);
        u.write(DR, b'i' as u32, &mut t);
        assert_eq!(t.out, b"hi");
        assert!(!u.irq(&mut t), "masked");
        u.write(IMSC, INT_TX, &mut t);
        assert!(u.irq(&mut t));
        assert_eq!(u.read(MIS, &mut t), INT_TX);
        u.write(ICR, INT_TX, &mut t);
        assert!(!u.irq(&mut t), "cleared");
        u.write(DR, b'!' as u32, &mut t);
        assert!(u.irq(&mut t), "raised by the next byte");
    }

    #[test]
    fn receive_follows_the_input() {
        let (mut u, mut t) = (Pl011::new(), Term::default());
        assert_ne!(u.read(FR, &mut t) & FR_RXFE, 0);
        t.input.extend(b"ok");
        assert_eq!(u.read(FR, &mut t) & FR_RXFE, 0);
        u.write(IMSC, INT_RX | INT_RT, &mut t);
        assert!(u.irq(&mut t));
        assert_eq!(u.read(RIS, &mut t) & (INT_RX | INT_RT), INT_RX | INT_RT);
        assert_eq!(u.read(DR, &mut t), b'o' as u32);
        assert!(u.irq(&mut t), "one left");
        assert_eq!(u.read(DR, &mut t), b'k' as u32);
        assert!(!u.irq(&mut t));
        assert_ne!(u.read(FR, &mut t) & FR_RXFE, 0);
        assert_eq!(u.read(DR, &mut t), 0, "nothing there");
    }

    #[test]
    fn registers_read_back() {
        let (mut u, mut t) = (Pl011::new(), Term::default());
        assert_eq!(u.read(CR, &mut t), CR_RESET);
        assert_eq!(u.read(IFLS, &mut t), IFLS_RESET);
        for (r, v) in [(IBRD, 13), (FBRD, 1), (LCR_H, 0x70), (CR, 0x301), (IFLS, 0x09), (IMSC, 0x50)] {
            u.write(r, v, &mut t);
            assert_eq!(u.read(r, &mut t), v, "{r:#x}");
        }
    }
}

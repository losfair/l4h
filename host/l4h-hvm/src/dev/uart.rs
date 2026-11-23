//! A 16550A UART (COM1: ports 0x3f8-0x3ff, IRQ 4), the guest's console:
//! what it transmits goes to its console ring, what vmmgr writes to its
//! console page is what it receives.  Its registers and interrupt logic
//! follow QEMU's serial.c: the transmitter is always ready (THRE), and
//! raises its interrupt again each time it empties; the receiver reports
//! data while the input has any.  Its vCPU threads share it under a lock;
//! output and input are behind the `Io` trait.  Free of seL4.

pub const BASE: u16 = 0x3f8;
pub const IRQ: usize = 4;

const IER_RDI: u8 = 1 << 0;
const IER_THRI: u8 = 1 << 1;
const IER_RLSI: u8 = 1 << 2;
const IER_MSI: u8 = 1 << 3;

const IIR_NO_INT: u8 = 0x01;
const IIR_THRI: u8 = 0x02;
const IIR_RDI: u8 = 0x04;
const IIR_FIFO: u8 = 0xc0;

const LCR_DLAB: u8 = 1 << 7;
const LSR_DR: u8 = 1 << 0;
const LSR_THRE: u8 = 1 << 5;
const LSR_TEMT: u8 = 1 << 6;
const MCR_LOOP: u8 = 1 << 4;
const MCR_OUT2: u8 = 1 << 3;
const FCR_ENABLE: u8 = 1 << 0;
const FCR_CLEAR_RX: u8 = 1 << 1;

/// Where the UART's bytes go and come from.
pub trait Io {
    fn transmit(&mut self, b: u8);
    /// The next received byte, if any, without taking it.
    fn peek(&mut self) -> Option<u8>;
    /// Take the byte `peek` gave.
    fn take(&mut self);
}

pub struct Uart {
    ier: u8,
    lcr: u8,
    mcr: u8,
    scr: u8,
    fcr: u8,
    dll: u8,
    dlm: u8,
    /// A THRE interrupt is pending (until IIR is read with it, or THR
    /// written).
    thr_ipending: bool,
    /// A byte the guest sent itself in loopback mode.
    loopback: Option<u8>,
}

impl Default for Uart {
    fn default() -> Self {
        Self::new()
    }
}

impl Uart {
    pub const fn new() -> Self {
        Uart { ier: 0, lcr: 0, mcr: MCR_OUT2, scr: 0, fcr: 0, dll: 1, dlm: 0, thr_ipending: false, loopback: None }
    }

    fn data_ready(&mut self, io: &mut impl Io) -> bool {
        if self.mcr & MCR_LOOP != 0 {
            self.loopback.is_some()
        } else {
            io.peek().is_some()
        }
    }

    fn iir(&mut self, io: &mut impl Io) -> u8 {
        let fifo = if self.fcr & FCR_ENABLE != 0 { IIR_FIFO } else { 0 };
        if self.ier & IER_RDI != 0 && self.data_ready(io) {
            IIR_RDI | fifo
        } else if self.ier & IER_THRI != 0 && self.thr_ipending {
            IIR_THRI | fifo
        } else {
            IIR_NO_INT | fifo
        }
    }

    /// The interrupt line's level.
    pub fn irq(&mut self, io: &mut impl Io) -> bool {
        self.iir(io) & IIR_NO_INT == 0
    }

    pub fn read(&mut self, off: u16, io: &mut impl Io) -> u8 {
        match off {
            0 if self.lcr & LCR_DLAB != 0 => self.dll,
            0 => {
                if self.mcr & MCR_LOOP != 0 {
                    return self.loopback.take().unwrap_or(0);
                }
                match io.peek() {
                    Some(b) => {
                        io.take();
                        b
                    }
                    None => 0,
                }
            }
            1 if self.lcr & LCR_DLAB != 0 => self.dlm,
            1 => self.ier,
            2 => {
                let v = self.iir(io);
                if v & 0x0f == IIR_THRI {
                    self.thr_ipending = false;
                }
                v
            }
            3 => self.lcr,
            4 => self.mcr,
            5 => {
                let dr = if self.data_ready(io) { LSR_DR } else { 0 };
                dr | LSR_THRE | LSR_TEMT
            }
            6 => {
                if self.mcr & MCR_LOOP != 0 {
                    // DTR, RTS, OUT1 and OUT2 looped back to DSR, CTS, RI
                    // and DCD.
                    let m = self.mcr;
                    ((m & 1) << 5) | ((m & 2) << 3) | ((m & 4) << 4) | ((m & 8) << 4)
                } else {
                    // DCD, DSR and CTS: a terminal is attached.
                    0xb0
                }
            }
            7 => self.scr,
            _ => 0xff,
        }
    }

    pub fn write(&mut self, off: u16, val: u8, io: &mut impl Io) {
        match off {
            0 if self.lcr & LCR_DLAB != 0 => self.dll = val,
            0 => {
                if self.mcr & MCR_LOOP != 0 {
                    self.loopback = Some(val);
                } else {
                    io.transmit(val);
                }
                // Sent at once: empty again, which interrupts.
                self.thr_ipending = true;
            }
            1 if self.lcr & LCR_DLAB != 0 => self.dlm = val,
            1 => {
                let old = self.ier;
                self.ier = val & (IER_RDI | IER_THRI | IER_RLSI | IER_MSI);
                // Enabling THRI with the transmitter empty interrupts.
                if self.ier & IER_THRI != 0 && old & IER_THRI == 0 {
                    self.thr_ipending = true;
                }
            }
            2 => {
                self.fcr = val & 0xc9;
                if val & FCR_CLEAR_RX != 0 {
                    self.loopback = None;
                }
            }
            3 => self.lcr = val,
            4 => self.mcr = val & 0x1f,
            7 => self.scr = val,
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
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
    fn transmit_and_thre() {
        let (mut u, mut t) = (Uart::new(), Term::default());
        // Divisor latch.
        u.write(3, LCR_DLAB, &mut t);
        u.write(0, 12, &mut t);
        assert_eq!(u.read(0, &mut t), 12);
        u.write(3, 3, &mut t);
        u.write(0, b'h', &mut t);
        u.write(0, b'i', &mut t);
        assert_eq!(t.out, b"hi");
        assert!(!u.irq(&mut t), "THRI off");
        assert_eq!(u.read(5, &mut t) & (LSR_THRE | LSR_TEMT), LSR_THRE | LSR_TEMT);
        // Enabling THRI interrupts at once; reading IIR acknowledges it.
        u.write(1, IER_THRI, &mut t);
        assert!(u.irq(&mut t));
        assert_eq!(u.read(2, &mut t), IIR_THRI);
        assert!(!u.irq(&mut t));
        u.write(0, b'!', &mut t);
        assert!(u.irq(&mut t), "empty again");
    }

    #[test]
    fn receive_and_loopback() {
        let (mut u, mut t) = (Uart::new(), Term::default());
        t.input.extend(b"ab");
        assert_eq!(u.read(5, &mut t) & LSR_DR, LSR_DR);
        assert!(!u.irq(&mut t));
        u.write(1, IER_RDI | IER_THRI, &mut t);
        assert_eq!(u.read(2, &mut t), IIR_RDI, "receive before transmit");
        assert_eq!((u.read(0, &mut t), u.read(0, &mut t), u.read(0, &mut t)), (b'a', b'b', 0));
        assert_eq!(u.read(5, &mut t) & LSR_DR, 0);
        assert_eq!(u.read(2, &mut t), IIR_THRI);
        // Loopback: what is sent comes back, and MSR mirrors MCR.
        u.write(4, MCR_LOOP | 0x3, &mut t);
        u.write(0, 0x55, &mut t);
        assert!(t.out.is_empty());
        assert_eq!(u.read(0, &mut t), 0x55);
        assert_eq!(u.read(6, &mut t), 0x30);
        // FIFO enabled: IIR says so.
        u.write(4, 0, &mut t);
        u.write(2, 0xc7, &mut t);
        assert_eq!(u.read(2, &mut t) & IIR_FIFO, IIR_FIFO);
    }
}

//! The registers of the port logd sends on. Root keeps the receive side.

use l4h_rt::host::serial::{self, LogdConfig, Port};

/// A 16550A's FIFO, and an older PL011's, hold 16 bytes. The kernel writes
/// the port too: leave it room for a byte.
const FIFO_BURST: usize = 15;

#[cfg(target_arch = "x86_64")]
pub struct Regs(l4h_rt::ioport::Ports);

#[cfg(target_arch = "x86_64")]
impl Regs {
    /// Line status register: the transmit FIFO, or holding register, is
    /// empty; and so is the shift register behind it.
    const LSR: u16 = 5;
    const LSR_THRE: u8 = 0x20;
    const LSR_TEMT: u8 = 0x40;
    /// FIFO control and interrupt identification registers.
    const FCR: u16 = 2;
    const IIR: u16 = 2;

    pub fn new(cfg: &LogdConfig) -> Self {
        Self(l4h_rt::ioport::Ports { cap: serial::SLOT_UART, base: cfg.uart_base })
    }

    /// Set the port up. How many bytes it takes once idle; None if it is
    /// not there.
    pub fn open(&self) -> Option<usize> {
        // seL4 leaves the FIFO off. Unmapped ports read as all ones.
        if self.0.in8(Self::LSR) == 0xff {
            return None;
        }
        self.0.out8(Self::FCR, 0x07);
        if self.0.in8(Self::IIR) & 0xc0 == 0xc0 {
            return Some(FIFO_BURST);
        }
        self.0.out8(Self::FCR, 0);
        Some(1)
    }
}

#[cfg(target_arch = "x86_64")]
impl Port for Regs {
    fn idle(&self) -> bool {
        self.0.in8(Self::LSR) & Self::LSR_THRE != 0
    }

    fn sent(&self) -> bool {
        self.0.in8(Self::LSR) & Self::LSR_TEMT != 0
    }

    fn put(&self, c: u8) {
        self.0.out8(0, c);
    }
}

#[cfg(target_arch = "aarch64")]
pub struct Regs(*mut u32);

#[cfg(target_arch = "aarch64")]
impl Regs {
    const DR: usize = 0x00;
    /// Flag register: the transmit FIFO is empty; the UART is sending.
    const FR: usize = 0x18;
    const FR_TXFE: u32 = 1 << 7;
    const FR_BUSY: u32 = 1 << 3;
    /// Line control register: FIFOs enabled.
    const LCR_H: usize = 0x2c;
    const LCR_FEN: u32 = 1 << 4;

    pub fn new(_cfg: &LogdConfig) -> Self {
        Self(serial::UART_VA as *mut u32)
    }

    // Root mapped the registers for good, as device memory.
    fn read(&self, reg: usize) -> u32 {
        unsafe { self.0.byte_add(reg).read_volatile() }
    }

    fn write(&self, reg: usize, v: u32) {
        unsafe { self.0.byte_add(reg).write_volatile(v) }
    }

    /// Set the port up. How many bytes it takes once idle. The kernel only
    /// waits for room, and receiving works with the FIFO on or off.
    pub fn open(&self) -> Option<usize> {
        let lcr = self.read(Self::LCR_H);
        if lcr & Self::LCR_FEN == 0 {
            self.write(Self::LCR_H, lcr | Self::LCR_FEN);
        }
        Some(FIFO_BURST)
    }
}

#[cfg(target_arch = "aarch64")]
impl Port for Regs {
    fn idle(&self) -> bool {
        self.read(Self::FR) & Self::FR_TXFE != 0
    }

    fn sent(&self) -> bool {
        self.read(Self::FR) & (Self::FR_TXFE | Self::FR_BUSY) == Self::FR_TXFE
    }

    fn put(&self, c: u8) {
        self.write(Self::DR, c as u32);
    }
}

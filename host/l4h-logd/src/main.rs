//! l4h-logd (DESIGN.md §10.4): the only host code that writes the serial
//! port.  Host tasks of every partition print whole lines into the serial
//! rings without any seL4 call, so nothing can wake this task: it looks at
//! the rings on a timer, and prints their records whole, in one order.
//!
//! It runs above guest vCPUs and below their VMMs, with a small budget, and
//! sleeps while the UART sends a burst, so it neither starves nor spins.
//! Root issues the port capability and keeps the receive side.  If this
//! task faults, root prints from where it left off.

#![no_std]
#![no_main]

use core::sync::atomic::{Ordering, compiler_fence};

use l4h_rt::host::font;
use l4h_rt::host::serial::{self, Line, LogdConfig, Merge, Ring};
use l4h_rt::ioport::Ports;
use l4h_rt::{Info, cap, host, sel4};

l4h_rt::component!(main, no_heap);

/// Line status register: the transmit FIFO, or holding register, is empty.
const LSR: u16 = 5;
const LSR_THRE: u8 = 0x20;
/// FIFO control and interrupt identification registers.
const FCR: u16 = 2;
const IIR: u16 = 2;
/// A 16550A's FIFO holds 16 bytes.  The kernel writes the port too, one
/// byte at a time once it finds the FIFO empty: leave it room for that byte.
const FIFO_BURST: usize = 15;
/// A byte takes 87 us at 115200 baud.
const BYTE_US: u64 = 90;
/// How long to wait for a UART that does not get ready, in bursts.
const STUCK_WAITS: u32 = 32;
const IDLE_MS: u64 = 10;

const BADGE_TIMER: u64 = 1;

fn sleep(ticks: u64) {
    let tcb = cap::<sel4::cap_type::Tcb>(host::SLOT_TCB);
    let deadline = host::ticks::now().saturating_add(ticks);
    let error = sel4::with_ipc_buffer_mut(|b| b.inner_mut().seL4_TCB_SetTimer(tcb.bits(), deadline, BADGE_TIMER));
    assert_eq!(error, 0, "logd timer");
    let ntfn = cap::<sel4::cap_type::Notification>(host::SLOT_NTFN);
    ntfn.wait();
}

struct Uart {
    ports: Ports,
    present: bool,
    burst: usize,
    wait: u64,
}

impl Uart {
    fn new(cfg: &LogdConfig) -> Self {
        let ports = Ports { cap: serial::SLOT_UART, base: cfg.uart_base };
        // seL4 leaves the FIFO off. Unmapped ports read as all ones.
        let present = ports.in8(LSR) != 0xff;
        let mut burst = 1;
        if present {
            ports.out8(FCR, 0x07);
            if ports.in8(IIR) & 0xc0 == 0xc0 {
                burst = FIFO_BURST;
            } else {
                ports.out8(FCR, 0);
            }
        }
        Uart { ports, present, burst, wait: BYTE_US * burst as u64 * (cfg.tsc_hz / 1_000_000) }
    }

    /// Send without spinning: a real UART takes 1.4 ms to send a burst,
    /// one in a VM often none at all.
    fn send(&self, bytes: &[u8]) {
        if !self.present {
            return;
        }
        for burst in bytes.chunks(self.burst) {
            let mut waits = 0;
            while self.ports.in8(LSR) & LSR_THRE == 0 && waits < STUCK_WAITS {
                sleep(self.wait);
                waits += 1;
            }
            for &c in burst {
                self.ports.out8(0, c);
            }
        }
    }
}

/// Host output on the lower half of the framebuffer (fb_console), as kernel
/// patch 0020 draws what the kernel prints: the same glyphs, wrapping to the
/// top rather than scrolling, so that the framebuffer is never read.
struct Screen {
    base: *mut u8,
    pitch: usize,
    cols: usize,
    rows: usize,
    row: usize,
    col: usize,
}

impl Screen {
    const CELL_W: usize = 8;
    const CELL_H: usize = 16;
    const FG: u32 = 0xd0d0d0;
    const BG: u32 = 0x000040;

    fn new(cfg: &LogdConfig) -> Option<Self> {
        if cfg.fb_pitch == 0 {
            return None;
        }
        let base = (serial::FB_VA + cfg.fb_offset as usize) as *mut u8;
        Some(Screen {
            base,
            pitch: cfg.fb_pitch as usize,
            cols: cfg.fb_width as usize / Self::CELL_W,
            rows: cfg.fb_height as usize / Self::CELL_H,
            row: 0,
            col: 0,
        })
    }

    fn glyph(&mut self, row: usize, col: usize, c: u8) {
        let index = c.checked_sub(font::FIRST).map_or(usize::MAX, usize::from);
        let glyph = font::GLYPHS.get(index).copied().unwrap_or([0; 8]);
        for y in 0..Self::CELL_H {
            // Only a row of pixels that fits the pitch is written.
            let line = unsafe { self.base.add((row * Self::CELL_H + y) * self.pitch) } as *mut u32;
            for x in 0..Self::CELL_W {
                let on = (glyph[y / 2] >> x) & 1 != 0;
                unsafe { line.add(col * Self::CELL_W + x).write_volatile(if on { Self::FG } else { Self::BG }) };
            }
        }
    }

    fn newline(&mut self) {
        self.col = 0;
        self.row = (self.row + 1) % self.rows;
        // What wrapped around would otherwise run into older text.
        for col in 0..self.cols {
            self.glyph(self.row, col, b' ');
        }
    }

    fn print(&mut self, bytes: &[u8]) {
        for &c in bytes {
            match c {
                b'\r' => {}
                b'\n' => self.newline(),
                c => {
                    if self.col == self.cols {
                        self.newline();
                    }
                    self.glyph(self.row, self.col, c);
                    self.col += 1;
                }
            }
        }
    }
}

fn main(info: &'static Info) -> ! {
    // Root wrote this configuration for KIND_LOGD.
    let cfg: &LogdConfig = unsafe { info.config() };
    let home = unsafe { &*(serial::VA as *const Ring) };
    let hz = cfg.tsc_hz;
    let mut merge = Merge::new(home, hz / 10);
    cfg.add_inputs(&mut merge, serial::RINGS_VA, serial::KERNEL_RINGS_VA);
    let uart = Uart::new(cfg);
    let mut screen = Screen::new(cfg);
    let mut line = Line::new();
    loop {
        merge.begin_pass();
        let mut printed = false;
        while merge.next(host::ticks::now(), &mut line) {
            if let Some(s) = &mut screen {
                s.print(line.bytes());
            }
            uart.send(line.bytes());
            compiler_fence(Ordering::SeqCst);
            merge.commit();
            printed = true;
        }
        if !printed {
            sleep(hz / 1000 * IDLE_MS);
        }
    }
}

//! An HVM guest's console is its UART (dev/uart.rs).  What it transmits a
//! vCPU thread writes into the console ring vmmgr reads (CTL_CONSOLE_READ),
//! under a short lock, and the I/O thread passes on to the host's serial
//! output by lines, a partial line after 100 ms (as l4h-vmm's console.rs).
//! What it receives is what vmmgr writes to the console page
//! (CTL_CONSOLE_WRITE).

use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering, fence};

use l4h_abi as abi;
use l4h_rt::host::{self, badges, hvm as hv};

use crate::dev::uart;
use crate::sync::SpinLock;

const LINE_SIZE: usize = 1024;

/// The guest's output, into the console ring.
pub struct Output {
    lock: SpinLock<()>,
    /// Bytes written (the ring's head, which only we write).
    head: AtomicU64,
    /// The I/O thread was signalled and has not looked since.
    signalled: AtomicBool,
}

impl Default for Output {
    fn default() -> Self {
        Self::new()
    }
}

impl Output {
    pub const fn new() -> Self {
        Output { lock: SpinLock::new(()), head: AtomicU64::new(0), signalled: AtomicBool::new(false) }
    }

    fn ring() -> *mut host::ConsoleRing {
        host::VMM_CONSOLE_RING_VA as *mut host::ConsoleRing
    }

    /// A byte the UART sent (a vCPU thread).
    pub fn put(&self, b: u8) {
        {
            let _g = self.lock.lock();
            let head = self.head.load(Ordering::Relaxed);
            unsafe {
                let r = Self::ring();
                addr_of_mut!((*r).data[(head % host::CONSOLE_RING_DATA as u64) as usize]).write_volatile(b);
                (*r).head.store(head + 1, Ordering::Release);
            }
            self.head.store(head + 1, Ordering::Release);
        }
        if !self.signalled.swap(true, Ordering::AcqRel) {
            crate::vm::signal_io(badges::hvm::CONSOLE);
        }
    }

    pub fn head(&self) -> u64 {
        self.head.load(Ordering::Acquire)
    }

    /// The I/O thread looks now: the next byte signals again.
    pub fn looked(&self) {
        self.signalled.store(false, Ordering::Release);
    }
}

/// The I/O thread's side: the ring's bytes, by lines, to the host's serial
/// output.
pub struct Serial {
    /// Ring bytes already passed on.
    tail: u64,
    line: [u8; LINE_SIZE],
    len: usize,
    /// When a partial line goes out (ticks), 0 if none waits.
    deadline: u64,
    gap: u64,
    source: u32,
    on: bool,
}

impl Serial {
    pub const fn new(guest: u32, tsc_hz: u64, on: bool) -> Self {
        Serial { tail: 0, line: [0; LINE_SIZE], len: 0, deadline: 0, gap: tsc_hz.div_ceil(10), source: host::serial::SOURCE_GUEST | guest, on }
    }

    fn send(&mut self, more: bool) {
        host::serial::write(self.source, &self.line[..self.len], more);
        self.len = 0;
        self.deadline = 0;
    }

    /// Pass on what the ring has (at most a ring's worth: a vCPU can keep
    /// adding); a partial line waits until `deadline`.
    pub fn drain(&mut self, out: &Output, now: u64) {
        out.looked();
        let head = out.head();
        // Lost if the guest wrote more than the ring holds since.
        self.tail = self.tail.max(head.saturating_sub(host::CONSOLE_RING_DATA as u64));
        while self.tail < head {
            let c = unsafe { addr_of!((*Output::ring()).data[(self.tail % host::CONSOLE_RING_DATA as u64) as usize]).read_volatile() };
            self.tail += 1;
            if !self.on {
                continue;
            }
            if c == b'\n' {
                if self.len != 0 && self.line[self.len - 1] == b'\r' {
                    self.len -= 1;
                }
                self.send(false);
            } else {
                self.line[self.len] = c;
                self.len += 1;
                if self.len == LINE_SIZE {
                    self.send(true);
                }
            }
        }
        if self.len != 0 {
            if self.deadline == 0 {
                self.deadline = now.saturating_add(self.gap);
            } else if now >= self.deadline {
                self.send(true);
            }
        }
    }

    /// When the I/O thread's timer is to look again (0: no need).
    pub fn deadline(&self) -> u64 {
        self.deadline
    }
}

/// The UART's input: the console page, which vmmgr writes.
pub struct Input;

fn page() -> *mut abi::ConsolePage {
    hv::CONSOLE_PAGE_VA as *mut abi::ConsolePage
}

impl uart::Io for Input {
    fn transmit(&mut self, b: u8) {
        crate::vm::vm().console.put(b);
    }

    fn peek(&mut self) -> Option<u8> {
        let p = page();
        unsafe {
            let head = addr_of!((*p).in_head).read_volatile();
            let tail = addr_of!((*p).in_tail).read_volatile();
            // vmmgr writes head; tail is ours (both in the page: no trust).
            if head == tail || head.wrapping_sub(tail) as usize > abi::CONSOLE_IN_SIZE {
                return None;
            }
            fence(Ordering::Acquire);
            Some(addr_of!((*p).input[tail as usize % abi::CONSOLE_IN_SIZE]).read_volatile())
        }
    }

    fn take(&mut self) {
        let p = page();
        unsafe {
            let tail = addr_of!((*p).in_tail).read_volatile();
            fence(Ordering::Release);
            addr_of_mut!((*p).in_tail).write_volatile(tail.wrapping_add(1));
        }
    }
}

/// A power request vmmgr left in the console page (CTL_VM_SHUTDOWN):
/// abi::POWER_*, taken.
pub fn power_request() -> Option<u64> {
    let p = page();
    unsafe {
        let r = addr_of!((*p).power_request).read_volatile();
        if r == 0 {
            return None;
        }
        addr_of_mut!((*p).power_request).write_volatile(0);
        Some(r as u64 - 1)
    }
}

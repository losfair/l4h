// SPDX-License-Identifier: GPL-2.0-only
//! l4h-hvm's models of an HVM guest's platform (DESIGN.md §5.11), on the
//! build host: the instruction decoder and page walker, the local APICs,
//! I/O APIC, PIT, RTC, UART and ACPI fixed hardware, PCI configuration
//! space and the virtio-pci transport over l4h-vmm's virtqueues, the
//! image loader and boot parameters, the ACPI tables, CPUID and MSRs, the
//! I/O pool's bounce allocator and the virtio backends' request handling;
//! and all of them together under the vCPU and I/O threads' code, with a
//! scripted guest (hvm/platform.rs).
//! The production files are included as they are (tests/run-hvmunit.sh);
//! seL4's side of them (sys.rs) is the model `sys` here.
#![allow(dead_code)]
extern crate self as l4h_rt;
pub mod host {
    pub use l4h_host::*;
}
/// A backend's kick (a notification in l4h-hvm): counted.
pub struct Kick;
pub static KICKS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
impl Kick {
    pub fn signal(&self) {
        KICKS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}
pub fn yield_now() {}
#[macro_export]
macro_rules! log {
    ($($t:tt)*) => { std::eprintln!($($t)*) };
}
#[macro_export]
macro_rules! info {
    ($($t:tt)*) => { std::eprintln!($($t)*) };
}
/// seL4's side (l4h-hvm's sys.rs) for tests/hvm/platform.rs: signals and
/// timers recorded, calls to the I/O thread made in-process.
pub mod sys {
    use std::cell::Cell;
    use std::sync::atomic::{AtomicU64, Ordering};
    std::thread_local! {
        static ME: Cell<Option<usize>> = const { Cell::new(None) };
    }
    pub fn me() -> Option<usize> {
        ME.with(|m| m.get())
    }
    pub fn set_me(v: usize) {
        ME.with(|m| m.set(Some(v)));
    }
    /// Run `f` as the I/O thread (Some: as vCPU `v`'s thread).
    pub fn as_thread<R>(v: Option<usize>, f: impl FnOnce() -> R) -> R {
        let old = me();
        ME.with(|m| m.set(v));
        let r = f();
        ME.with(|m| m.set(old));
        r
    }
    pub static NOW: AtomicU64 = AtomicU64::new(1_000_000);
    pub fn now() -> u64 {
        NOW.load(Ordering::SeqCst)
    }
    /// vCPUs woken, I/O thread badges signalled, since last taken.
    pub static WOKEN: AtomicU64 = AtomicU64::new(0);
    pub static IO_SIGNALS: AtomicU64 = AtomicU64::new(0);
    pub static WAITS: AtomicU64 = AtomicU64::new(0);
    pub static VCPU_TIMERS: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
    pub static IO_TIMER: AtomicU64 = AtomicU64::new(0);
    /// abi::POWER_* + 1 once the guest stopped.
    pub static POWER: AtomicU64 = AtomicU64::new(0);
    pub fn wake(v: usize) {
        WOKEN.fetch_or(1 << v, Ordering::SeqCst);
    }
    pub fn signal_io(badge: u64) {
        IO_SIGNALS.fetch_or(badge, Ordering::SeqCst);
    }
    pub fn poll(_v: usize) {}
    pub fn wait(_v: usize) {
        WAITS.fetch_add(1, Ordering::SeqCst);
    }
    pub fn vcpu_timer(v: usize, deadline: u64) {
        VCPU_TIMERS[v].store(deadline, Ordering::SeqCst);
    }
    pub fn io_timer(deadline: u64) {
        IO_TIMER.store(deadline, Ordering::SeqCst);
    }
    pub fn kick(_slot: u64) -> crate::Kick {
        crate::Kick
    }
    /// trustd kicked: counted.
    pub static TRUSTD_KICKS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    pub fn kick_trustd() {
        TRUSTD_KICKS.fetch_add(1, Ordering::SeqCst);
    }
    pub fn call_access(space: u32, addr: u64, size: u8, write: bool, value: u64) -> u64 {
        as_thread(None, || crate::io::access(space, addr, size, write, value))
    }
    pub fn map(b: usize) -> bool {
        crate::vm::vm().mem.set_mapped(b);
        true
    }
    pub fn power(how: u64) -> ! {
        POWER.store(how + 1, Ordering::SeqCst);
        panic!("the guest stopped: {how}");
    }
}
#[path = "../host/l4h-hvm/src/mem.rs"]
pub mod mem;
pub mod guest {
    pub use crate::mem::GuestMem;
}
#[path = "../host/l4h-vmm/src/virtq.rs"]
pub mod virtq;
#[path = "../host/l4h-hvm/src/dev/mod.rs"]
pub mod dev;
#[path = "../host/l4h-hvm/src/acpi.rs"]
pub mod acpi;
#[path = "../host/l4h-hvm/src/iopool.rs"]
pub mod iopool;
#[path = "../host/l4h-hvm/src/boot.rs"]
pub mod boot;
#[path = "../host/l4h-hvm/src/x86/mod.rs"]
pub mod x86;
#[path = "../host/l4h-hvm/src/sync.rs"]
pub mod sync;
#[path = "../host/l4h-hvm/src/console.rs"]
pub mod console;
#[path = "../host/l4h-hvm/src/vm.rs"]
pub mod vm;
#[path = "../host/l4h-hvm/src/io.rs"]
pub mod io;
#[path = "../host/l4h-hvm/src/hw/mod.rs"]
pub mod hw;
#[path = "../host/l4h-hvm/src/vcpu.rs"]
pub mod vcpu;
/// The whole machine on one test thread: vCPUs entering a scripted guest
/// (a model of seL4's VCPU), the I/O thread, and blkd and netd.
#[path = "hvm/platform.rs"]
mod platform;

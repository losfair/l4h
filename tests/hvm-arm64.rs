// SPDX-License-Identifier: GPL-2.0-only
//! l4h-hvm's AArch64 machine on the build host: the GIC (GICv3 with MBI,
//! GICv2 with GICv2m), PSCI, system registers, the PL011, PL031 and PL061,
//! the device tree and the Image and ELF loader; and all of them together
//! under the vCPU and I/O threads' code, with a scripted guest
//! (hvm/platform-arm64.rs).  The production files are included as they are
//! (tests/run-hvmunit.sh); seL4's side of them (sys.rs) is the model `sys`
//! here.
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
/// seL4's side (l4h-hvm's sys.rs) for tests/hvm/platform-arm64.rs: signals
/// and timers recorded, calls to the I/O thread made in-process.
pub mod sys {
    use std::cell::Cell;
    use std::sync::Mutex;
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
    /// What was made coherent for a guest with its caches off.
    pub static CLEANED: Mutex<Vec<(u64, u64)>> = Mutex::new(Vec::new());
    pub fn wake(v: usize) {
        WOKEN.fetch_or(1 << v, Ordering::SeqCst);
    }
    pub fn signal_io(badge: u64) {
        IO_SIGNALS.fetch_or(badge, Ordering::SeqCst);
    }
    pub fn wait(_v: usize) {
        WAITS.fetch_add(1, Ordering::SeqCst);
    }
    /// The vCPUs' event pages (vmmgr's, mapped in l4h-hvm): zeroed, as
    /// vmmgr makes them.
    #[repr(C, align(4096))]
    pub struct Page(pub [u8; 4096]);
    pub static mut PAGES: [Page; 4] = [const { Page([0; 4096]) }; 4];
    pub fn event_page(v: usize) -> *mut l4h_abi::EventPage {
        unsafe { core::ptr::addr_of_mut!(PAGES[v]) as *mut l4h_abi::EventPage }
    }
    pub fn io_flags() -> u64 {
        unsafe { core::ptr::addr_of!((*event_page(0)).io_flags).read_volatile() }
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
    pub fn clean_range(gpa: u64, len: u64) -> Result<(), ()> {
        CLEANED.lock().unwrap().push((gpa, len));
        Ok(())
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
// The devices every architecture has, where the shared code finds them.
#[path = "../host/l4h-hvm/src/dev/attest.rs"]
pub mod attest;
#[path = "../host/l4h-hvm/src/dev/blk.rs"]
pub mod blk;
#[path = "../host/l4h-hvm/src/dev/net.rs"]
pub mod net;
#[path = "../host/l4h-hvm/src/dev/pci.rs"]
pub mod pci;
#[path = "../host/l4h-hvm/src/dev/virtio_pci.rs"]
pub mod virtio_pci;
pub mod dev {
    pub use crate::{attest, blk, net, pci, virtio_pci};
}
#[path = "../host/l4h-hvm/src/iopool.rs"]
pub mod iopool;
#[path = "../host/l4h-hvm/src/sync.rs"]
pub mod sync;
#[path = "../host/l4h-hvm/src/console.rs"]
pub mod console;
#[path = "../host/l4h-hvm/src/arm/mod.rs"]
pub mod arm;
pub use arm::{vcpu, vm};
#[path = "../host/l4h-hvm/src/io.rs"]
pub mod io;
/// The whole machine on one test thread: vCPUs entering a scripted guest
/// (a model of FL4's VCPU), the I/O thread, and blkd.
#[path = "hvm/platform-arm64.rs"]
mod platform;

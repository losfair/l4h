//! What the vCPU threads and the device models ask of seL4: signals and
//! waits, timers, the clock, calls to the I/O thread, RAM blocks to map,
//! and the guest's end.  Everything else they do is plain memory, so that
//! tests/hvm.rs can run them on the build host with a model of this
//! module (DESIGN.md §5.11).

use core::cell::Cell;

use l4h_rt::host::badges::{hvm as recv, hvm_vcpu};
use l4h_rt::host::hvm::{self as hv, call};
use l4h_rt::host::vmmgr::call::Client as _;
use l4h_rt::host::{self, wiring};
use l4h_rt::ipc::Endpoint;
use l4h_rt::{cap, sel4};
use sel4::cap_type;

#[thread_local]
static ME: Cell<Option<usize>> = Cell::new(None);

/// The vCPU this thread runs (None: the I/O thread).
pub fn me() -> Option<usize> {
    ME.get()
}

pub fn set_me(v: usize) {
    ME.set(Some(v));
}

/// The host's TSC.
pub fn now() -> u64 {
    host::ticks::now()
}

/// vCPU `v`'s event page (vmmgr's, mapped here too): steal time and the
/// capacity hint from vmmgr, its idle time to vmmgr, and on vCPU 0 the
/// I/O thread's flags (abi::EVENT_IO_*).
pub fn event_page(v: usize) -> *mut l4h_abi::EventPage {
    host::vmm_event_page_va(v) as *mut l4h_abi::EventPage
}

/// What vmmgr asks of the I/O thread (abi::EVENT_IO_*, in vCPU 0's event
/// page; io::poll_allowed).
pub fn io_flags() -> u64 {
    let page = event_page(0);
    unsafe { core::ptr::addr_of!((*page).io_flags).read_volatile() }
}

/// Signal vCPU `v`'s thread: out of seL4_VMEnter, or out of its wait.
pub fn wake(v: usize) {
    cap::<cap_type::Notification>(hv::VCPU_NTFN_SLOT_BASE + v as u64).signal();
}

/// Signal the I/O thread (`badge`: badges::hvm::KICK or CONSOLE).
pub fn signal_io(badge: u64) {
    let slot = if badge == recv::KICK { hv::SLOT_SELF_KICK } else { hv::SLOT_SELF_CONSOLE };
    cap::<cap_type::Notification>(slot).signal();
}

/// Take vCPU `v`'s notification if it is signalled, without waiting.
#[cfg_attr(target_arch = "aarch64", allow(dead_code))] // x86-64's vCPU loop
pub fn poll(v: usize) {
    let _ = cap::<cap_type::Notification>(hv::SLOT_VCPU_WAIT + v as u64).poll();
}

/// vCPU `v`'s thread waits for its notification (wake, its timer).
pub fn wait(v: usize) {
    let _ = cap::<cap_type::Notification>(hv::SLOT_VCPU_WAIT + v as u64).wait();
}

/// vCPU `v`'s timer: its notification at `deadline` (ticks; 0: none).
pub fn vcpu_timer(v: usize, deadline: u64) {
    let tcb = hv::SLOT_VCPU_TCB + v as u64;
    let e = sel4::with_ipc_buffer_mut(|b| b.inner_mut().seL4_TCB_SetTimer(tcb, deadline, hvm_vcpu::TIMER));
    assert_eq!(e, 0, "vCPU timer");
}

/// The I/O thread's timer: CONSOLE at `deadline` (0: none).
pub fn io_timer(deadline: u64) {
    let e = sel4::with_ipc_buffer_mut(|b| b.inner_mut().seL4_TCB_SetTimer(host::SLOT_TCB, deadline, recv::CONSOLE));
    assert_eq!(e, 0, "I/O thread timer");
}

/// The kick of a backend's channel, at `slot`.
pub fn kick(slot: u64) -> crate::Kick {
    cap::<cap_type::Notification>(slot)
}

/// Kick trustd: the attestation port took a request into its page
/// (wiring::HVM_TRUSTD).
/// Root revokes the capability when trustd fails (its page then says so):
/// a signal there is lost, where Signal on the empty slot would fault us.
pub fn kick_trustd() {
    l4h_rt::mailbox::notify(cap::<cap_type::Notification>(hv::SLOT_TRUSTD_KICK));
}

fn io_thread() -> Endpoint<call::Proto> {
    Endpoint::of(&wiring::HVM_CALL, wiring::p::Hvm, 0)
}

/// A vCPU thread's access to device space `space` (hv::SPACE_*), which the
/// I/O thread owns.
pub fn call_access(space: u32, addr: u64, size: u8, write: bool, value: u64) -> u64 {
    use call::Client as _;
    blocked_on_io(|| io_thread().access(me().unwrap_or(0), space, addr, size, write, value).unwrap_or(u64::MAX))
}

/// A vCPU thread's call to the I/O thread, which answers for its own
/// guest's devices: the vCPU is blocked meanwhile, not runnable, so the
/// time is idle to vmmgr's steal estimate (wall - run - idle), as a wait
/// is (sync::idle_begin).
fn blocked_on_io<T>(f: impl FnOnce() -> T) -> T {
    match me() {
        Some(v) => unsafe { crate::sync::idle_during(event_page(v), now, f) },
        None => f(),
    }
}

/// GuestMem's `map`: RAM block `b`, which the I/O thread maps (a vCPU
/// thread asks it).
pub fn map(b: usize) -> bool {
    use call::Client as _;
    match me() {
        None => crate::ept::map_block(b),
        Some(_) => blocked_on_io(|| io_thread().map(b).is_ok()),
    }
}

/// Make what l4h-hvm wrote at [gpa, gpa + len) of RAM visible to a guest
/// with its caches off (arm/stage2.rs).
#[cfg(target_arch = "aarch64")]
pub fn clean_range(gpa: u64, len: u64) -> sel4::Result<()> {
    crate::ept::clean_range(gpa, len)
}

/// The guest stops (abi::POWER_*): vmmgr stops every thread of ours, the
/// caller's included, and never answers.
pub fn power(how: u64) -> ! {
    signal_io(recv::CONSOLE);
    let vmmgr = Endpoint::of(&wiring::HVM_VMMGR, wiring::p::Hvm, 0);
    let _ = vmmgr.guest_power(how);
    loop {
        sel4::r#yield();
    }
}

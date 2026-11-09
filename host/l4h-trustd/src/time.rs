//! Waiting without spinning: the TCB's deadline timer (kernel extension
//! E3, DESIGN.md §4) signals our bound notification, which nothing else
//! signals.

use l4h_rt::{cap, host, sel4};
use sel4::cap_type;

/// Block until the time counter reaches `deadline`.
pub fn sleep_until(deadline: u64) {
    let tcb = cap::<cap_type::Tcb>(host::SLOT_TCB);
    let ntfn = cap::<cap_type::Notification>(host::SLOT_NTFN);
    while host::ticks::now() < deadline {
        sel4::with_ipc_buffer_mut(|ipc| ipc.inner_mut().seL4_TCB_SetTimer(tcb.bits(), deadline, host::badges::trustd::TIMER));
        ntfn.wait();
    }
}

/// Block for `ns` nanoseconds of a counter running at `hz`.
pub fn sleep_ns(hz: u64, ns: u64) {
    sleep_until(host::ticks::now() + (ns as u128 * hz as u128 / 1_000_000_000) as u64);
}

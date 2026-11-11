// SPDX-License-Identifier: GPL-2.0-only
//! The production memory device, call budget and VMM timer. A busy state
//! query must retry even when the guest is idle at its previous target.
#![allow(dead_code)]
extern crate self as l4h_rt;
use l4h_abi as abi;
use std::cell::{Cell, RefCell};

pub mod host {
    pub use l4h_host::*;
    pub mod ticks {
        pub fn now() -> u64 { crate::MODEL.with(|m| m.borrow().now) }
    }
}
#[path = "../host/l4h-memd/src/bucket.rs"]
mod bucket;
#[path = "../host/l4h-vmm/src/memhp.rs"]
mod memhp;
#[path = "../host/l4h-vmm/src/timer.rs"]
mod timer;

pub mod guest {
    use super::Cell;
    #[derive(Default)]
    pub struct Vcpus { pub raised: Cell<u32> }
    impl Vcpus {
        pub fn raise(&self, _: usize, _: u32) { self.raised.set(self.raised.get() + 1); }
    }
}
struct Model {
    bucket: bucket::Bucket,
    now: u64,
    target: u64,
    calls: usize,
    error: u64,
    arms: Vec<u64>,
}
impl Model {
    fn new() -> Self {
        Self { bucket: bucket::Bucket::full(0), now: 0, target: 0, calls: 0, error: 0, arms: Vec::new() }
    }
}
thread_local! { static MODEL: RefCell<Model> = RefCell::new(Model::new()); }

pub mod ipc {
    use super::*;
    use host::wire::{Call, Protocol, Wire};
    use host::wiring::{E, o, p};
    pub struct Endpoint<P>(std::marker::PhantomData<P>);
    impl<P: Protocol> Endpoint<P> {
        pub fn of<H: p::IsParty, T>(_: &E<H, T, o::Endpoint, P>, _: H, _: usize) -> Self {
            Self(std::marker::PhantomData)
        }
    }
    impl<P: Protocol> Call for Endpoint<P> {
        type Proto = P;
        fn ipc(&self, label: u64, _: &[u64], reply: &mut [u64]) -> usize {
            assert_eq!(label, 18);
            MODEL.with(|m| {
                let mut m = m.borrow_mut();
                m.calls += 1;
                let now = m.now;
                if m.error != 0 || !m.bucket.call(now) {
                    reply[0] = if m.error != 0 { m.error } else { host::errno::EBUSY };
                    return 1;
                }
                reply[0] = 0;
                1 + host::memd::HpState { target: m.target, ..Default::default() }.put(&mut reply[1..])
            })
        }
    }
}

pub mod sel4 {
    pub mod cap_type { pub struct Tcb; }
    pub struct Cap<T>(pub u64, pub std::marker::PhantomData<T>);
    impl<T> Cap<T> { pub fn bits(&self) -> u64 { self.0 } }
    pub struct IpcBuffer;
    impl IpcBuffer {
        pub fn inner_mut(&mut self) -> &mut Self { self }
        #[allow(non_snake_case)]
        pub fn seL4_TCB_SetTimer(&mut self, tcb: u64, deadline: u64, badge: u64) -> u64 {
            assert_eq!((tcb, badge), (crate::host::SLOT_TCB, crate::host::badges::vmm::CONSOLE));
            crate::MODEL.with(|m| m.borrow_mut().arms.push(deadline));
            0
        }
    }
    pub fn with_ipc_buffer_mut<R>(f: impl FnOnce(&mut IpcBuffer) -> R) -> R { f(&mut IpcBuffer) }
}
pub fn cap<T>(bits: u64) -> sel4::Cap<T> { sel4::Cap(bits, std::marker::PhantomData) }

fn device() -> (Box<abi::MemPage>, memhp::MemDev, guest::Vcpus) {
    MODEL.with(|m| *m.borrow_mut() = Model::new());
    let mut page: Box<abi::MemPage> = Box::new(unsafe { std::mem::zeroed() });
    let dev = memhp::MemDev::new((&mut *page) as *mut _ as usize, 7, 4, 1_000_000);
    (page, dev, guest::Vcpus::default())
}

#[test]
fn idle_guest_gets_the_last_target_after_the_call_budget_refills() {
    let (page, mut dev, vcpus) = device();
    for _ in 0..host::memd::HP_CALLS { dev.target_changed(&vcpus); }
    MODEL.with(|m| m.borrow_mut().target = 1);
    dev.target_changed(&vcpus);
    assert_eq!(page.target, 0);
    let deadline = dev.deadline();
    assert_eq!(deadline, host::memd::HP_CALL_GAP_US);
    let mut timer = timer::Timer::new();
    timer.update(0, deadline);
    for now in [0, 1, deadline - 1] {
        MODEL.with(|m| m.borrow_mut().now = now);
        dev.retry(&vcpus);
    }
    assert_eq!(MODEL.with(|m| m.borrow().calls), 65);
    // Only the host timer runs; no guest MEM_REQ or new target arrives.
    MODEL.with(|m| m.borrow_mut().now = deadline);
    dev.retry(&vcpus);
    timer.update(0, dev.deadline());
    assert_eq!(page.target, 1);
    assert_eq!(vcpus.raised.get(), 66);
    assert_eq!(dev.deadline(), 0);
    assert_eq!(MODEL.with(|m| m.borrow().arms.clone()), [deadline, 0]);
}

#[test]
fn another_busy_reply_backs_off_and_a_failed_server_stops_retries() {
    let (_, mut dev, vcpus) = device();
    MODEL.with(|m| m.borrow_mut().error = host::errno::EBUSY);
    dev.target_changed(&vcpus);
    let first = dev.deadline();
    MODEL.with(|m| m.borrow_mut().now = first);
    dev.retry(&vcpus);
    assert_eq!(dev.deadline(), 2 * first);
    dev.retry(&vcpus);
    assert_eq!(MODEL.with(|m| m.borrow().calls), 2);
    MODEL.with(|m| { let mut m = m.borrow_mut(); m.now = 2 * first; m.error = host::wire::FAILED; });
    dev.retry(&vcpus);
    assert_eq!(dev.deadline(), 0);
    MODEL.with(|m| m.borrow_mut().now += 1_000_000);
    dev.retry(&vcpus);
    assert_eq!(MODEL.with(|m| m.borrow().calls), 3);
}

#[test]
fn one_timer_keeps_both_deadlines_and_rebinding_never_postpones_them() {
    let _ = device();
    let mut timer = timer::Timer::new();
    timer.update(100, 32);
    timer.update(100, 32);
    MODEL.with(|m| m.borrow_mut().now = 40);
    timer.rearm();
    timer.update(100, 64);
    timer.update(100, 0);
    timer.update(0, 0);
    timer.rearm();
    assert_eq!(MODEL.with(|m| m.borrow().arms.clone()), [32, 32, 64, 100, 0]);
}

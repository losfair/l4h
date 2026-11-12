// Production net/virtq code; model only the peer's
// writes between avail-index reads and the notification syscall.
#![allow(dead_code)]
extern crate self as l4h_rt;
pub use l4h_host as host;
use std::cell::Cell;

pub mod sel4 {
    pub mod cap {
        #[derive(Clone, Copy)]
        pub struct Notification;
        impl Notification { pub fn signal(self) {} }
    }
}

#[path = "../host/l4h-vmm/src/mem.rs"] mod memory;
mod guest {
    use super::*;
    pub struct GuestMem {
        pub inner: memory::GuestMem,
        pub reads: Cell<usize>,
        pub replenish: Cell<bool>,
        pub invalid: bool,
        pub rx_peer: Cell<*mut host::net::Port>,
    }
    impl GuestMem {
        pub fn valid(&self, gpa: u64, len: u64) -> bool { self.inner.valid(gpa, len) }
        pub fn bytes(&self, gpa: u64, len: usize) -> *mut u8 { self.inner.bytes(gpa, len) }
        pub fn write<T: Copy>(&self, gpa: u64, value: T) { self.inner.write(gpa, value); }
        pub fn read<T: Copy>(&self, gpa: u64) -> T {
            if gpa == 0x1002 {
                let n = self.reads.get();
                self.reads.set(n + 1);
                if n == 1000 { std::panic::panic_any(AuditStop); }
                if self.replenish.get() {
                    // Another vCPU publishes a new available descriptor
                    // between polls. The ring contains a zero-length frame,
                    // so it is dropped and never fills netd's TX ring.
                    self.inner.write(gpa, (n as u16).wrapping_add(1));
                    let chan = self.rx_peer.get();
                    if !chan.is_null() {
                        let head = unsafe { &(*chan).rx.head };
                        head.fetch_add(1, std::sync::atomic::Ordering::Release);
                    }
                }
            }
            if gpa == 0x1004 && self.invalid {
                self.inner.write(gpa, u16::MAX);
            }
            self.inner.read(gpa)
        }
    }
}
#[derive(Debug)] struct AuditStop;
#[path = "../host/l4h-vmm/src/virtq.rs"] mod virtq;
mod dev {
    use crate::{guest::GuestMem, virtq::Queue};
    include!(env!("L4H_VMM_BACKEND_TEST_SRC"));
}
#[path = "../host/l4h-vmm/src/net.rs"] mod network;

#[test]
fn continually_replenished_empty_packets_yield_and_resume() {
    transmit(false);
    transmit(true);
}

fn transmit(invalid: bool) {
    use dev::Backend;
    let mut bytes = vec![0u8; 0x4000];
    let mem = guest::GuestMem {
        inner: memory::GuestMem { base: bytes.as_mut_ptr() as usize, gpa: 0, size: bytes.len() as u64 },
        reads: Cell::new(0), replenish: Cell::new(true), invalid, rx_peer: Cell::new(std::ptr::null_mut()),
    };
    let layout = std::alloc::Layout::new::<host::net::Port>();
    let chan = unsafe { std::alloc::alloc_zeroed(layout).cast::<host::net::Port>() };
    assert!(!chan.is_null());
    let mut net = network::Net::new(chan as usize, sel4::cap::Notification, [2; 6], 256);
    let mut queues = [virtq::Queue::default(), virtq::Queue::default()];
    assert!(queues[1].setup(&mem, 1, 256, 0, 0x1000, 0x2000));
    assert!(net.kick(&mem, &mut queues, 1));
    let batch = mem.reads.get();
    assert!(batch > 0 && batch <= 256, "one handler must yield within a queue's size");
    assert_eq!(net.more, 1 << 1);
    assert_eq!(queues[1].used_idx(), batch as u16);
    // No fresh signal is needed to process the next batch.
    assert!(net.kick(&mem, &mut queues, 1));
    assert_eq!(mem.reads.get(), 2 * batch);
    mem.replenish.set(false);
    assert!(!net.kick(&mem, &mut queues, 1));
    assert_eq!(net.more, 0, "the idle queue must let the server sleep");
    assert_eq!(unsafe { (*chan).tx.head.load(std::sync::atomic::Ordering::Relaxed) }, 0);
    unsafe { std::alloc::dealloc(chan.cast(), layout); }
}

#[test]
fn a_replenished_receive_ring_yields_and_keeps_its_next_turn() {
    use dev::Backend;
    let mut bytes = vec![0u8; 0x4000];
    let layout = std::alloc::Layout::new::<host::net::Port>();
    let chan = unsafe { std::alloc::alloc_zeroed(layout).cast::<host::net::Port>() };
    assert!(!chan.is_null());
    unsafe { (*chan).rx.head.store(1, std::sync::atomic::Ordering::Release); }
    let mem = guest::GuestMem {
        inner: memory::GuestMem { base: bytes.as_mut_ptr() as usize, gpa: 0, size: bytes.len() as u64 },
        reads: Cell::new(0), replenish: Cell::new(true), invalid: true, rx_peer: Cell::new(chan),
    };
    let mut net = network::Net::new(chan as usize, sel4::cap::Notification, [2; 6], 256);
    let mut queues = [virtq::Queue::default(), virtq::Queue::default()];
    assert!(queues[0].setup(&mem, 1, 256, 0, 0x1000, 0x2000));
    assert!(net.kick(&mem, &mut queues, 0));
    let batch = mem.reads.get();
    assert!(batch > 0 && batch <= 256);
    assert_eq!(net.more, 1);
    assert!(net.kick(&mem, &mut queues, 0));
    assert_eq!(mem.reads.get(), 2 * batch);
    mem.replenish.set(false);
    mem.inner.write(0x1002, (2 * batch + 1) as u16);
    assert!(net.kick(&mem, &mut queues, 0));
    assert_eq!(net.more, 0);
    assert_eq!(unsafe { (*chan).rx.tail.load(std::sync::atomic::Ordering::Relaxed) }, (2 * batch + 1) as u32);
    net.more = 3;
    net.reset();
    assert_eq!(net.more, 0);
    unsafe { std::alloc::dealloc(chan.cast(), layout); }
}

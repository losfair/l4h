// Production net/virtq code; model only the peer's
// writes between avail-index reads and the notification syscall.
#![allow(dead_code)]
extern crate self as l4h_rt;
pub use l4h_host as host;
use l4h_abi as abi;
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
    pub struct Vcpus { pub n: usize }
    impl Vcpus { pub fn raise(&self, _: usize, _: u32) {} }
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
#[path = "../host/l4h-vmm/src/dev.rs"] mod dev;
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
    assert_eq!(batch, 32, "one handler must return after exactly one bounded batch");
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
    assert_eq!(batch, 32);
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

#[test]
fn simultaneous_done_kick_and_deferred_work_process_only_one_batch() {
    use dev::Backend;
    let mut bytes = vec![0u8; 0x4000];
    let mem = guest::GuestMem {
        inner: memory::GuestMem { base: bytes.as_mut_ptr() as usize, gpa: 0, size: bytes.len() as u64 },
        reads: Cell::new(0), replenish: Cell::new(false), invalid: true, rx_peer: Cell::new(std::ptr::null_mut()),
    };
    let layout = std::alloc::Layout::new::<host::net::Port>();
    let chan = unsafe { std::alloc::alloc_zeroed(layout).cast::<host::net::Port>() };
    assert!(!chan.is_null());
    let mut page = Box::new([0u64; 512]);
    let regs = page.as_mut_ptr().cast::<abi::VirtioRegs>();
    let backend = network::Net::new(chan as usize, sel4::cap::Notification, [2; 6], 256);
    let mut d = dev::Device::new(regs as usize, 16, backend);
    let cpus = guest::Vcpus { n: 1 };
    unsafe {
        (*regs).queues[1].ready = 1;
        (*regs).queues[1].num = 1;
        (*regs).queues[1].desc = 0;
        (*regs).queues[1].driver = 0x1000;
        (*regs).queues[1].device = 0x2000;
        (*regs).driver_features = dev::VIRTIO_F_VERSION_1 | dev::VIRTIO_F_ACCESS_PLATFORM;
        (*regs).status = 8;
    }
    assert_eq!(d.op(&mem, &cpus, abi::VIRTIO_OP_QUEUE, 1, 0), 0);
    assert_eq!(d.op(&mem, &cpus, abi::VIRTIO_OP_STATUS, 0, 0), 0);
    unsafe { (*regs).status = 12; }
    assert_eq!(d.op(&mem, &cpus, abi::VIRTIO_OP_STATUS, 0, 0), 0);
    mem.reads.set(0);
    mem.replenish.set(true);
    d.backend.more = 2;
    unsafe {
        (*chan).rx.head.store(1, std::sync::atomic::Ordering::Release);
        (*regs).kick = 2;
    }
    network::signal(&mut d, &mem, &cpus, true, true);
    assert_eq!(mem.reads.get(), 32, "DONE must not complete and then poll the same queue again");
    assert_eq!(d.backend.more, 2);
    network::signal(&mut d, &mem, &cpus, false, false);
    assert_eq!(mem.reads.get(), 64, "the next IPC turn resumes without a new kick");
    assert_eq!(d.backend.more, 2);
    // A DONE without a kick still services newly available backend data.
    d.backend.more = 0;
    network::signal(&mut d, &mem, &cpus, true, false);
    assert_eq!(mem.reads.get(), 96);
    d.backend.reset();
    unsafe {
        (*chan).rx.head.store(0, std::sync::atomic::Ordering::Release);
        (*chan).rx.tail.store(0, std::sync::atomic::Ordering::Release);
    }
    network::signal(&mut d, &mem, &cpus, true, false);
    assert_eq!(mem.reads.get(), 96, "another device's DONE must not read idle guest queue cache lines");
    unsafe { std::alloc::dealloc(chan.cast(), layout); }
}

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

/// Counts the queue work the device model hands it.
struct Kicks { kicks: usize, accepted: Option<u64> }
impl dev::Backend for Kicks {
    fn device_id(&self) -> u32 { 1 }
    fn features(&self) -> u64 { 0 }
    fn num_queues(&self) -> usize { 2 }
    fn queue_max(&self, _: usize) -> u32 { 256 }
    fn init_config(&self, _: &mut [u8]) {}
    fn kick(&mut self, _: &guest::GuestMem, _: &mut [virtq::Queue], _: usize) -> bool { self.kicks += 1; false }
    fn complete(&mut self, _: &guest::GuestMem, _: &mut [virtq::Queue]) -> bool { false }
    fn pending(&self) -> bool { false }
    fn reset(&mut self) { self.accepted = None; }
    fn features_accepted(&mut self, f: u64) { self.accepted = Some(f); }
}

const REQUIRED: u64 = dev::VIRTIO_F_VERSION_1 | dev::VIRTIO_F_ACCESS_PLATFORM;

/// A device with the counting backend: (device, its register page, memory).
fn kick_device() -> (dev::Device<Kicks>, Box<[u64; 512]>, guest::GuestMem, Vec<u8>) {
    let mut bytes = vec![0u8; 0x4000];
    let mem = guest::GuestMem {
        inner: memory::GuestMem { base: bytes.as_mut_ptr() as usize, gpa: 0, size: bytes.len() as u64 },
        reads: Cell::new(0), replenish: Cell::new(false), invalid: false, rx_peer: Cell::new(std::ptr::null_mut()),
    };
    let mut page = Box::new([0u64; 512]);
    let d = dev::Device::new(page.as_mut_ptr() as usize, 16, Kicks { kicks: 0, accepted: None });
    (d, page, mem, bytes)
}

fn regs(page: &mut [u64; 512]) -> *mut abi::VirtioRegs { page.as_mut_ptr().cast() }

/// The guest kicks queue 0: how many queue kicks the backend has had.
fn kick(d: &mut dev::Device<Kicks>, page: &mut [u64; 512], mem: &guest::GuestMem) -> usize {
    unsafe { (*regs(page)).kick = 1; }
    d.poll(mem, &guest::Vcpus { n: 1 }, 0);
    d.backend.kicks
}

/// The guest writes `status` to its page, then commits it.
fn status(d: &mut dev::Device<Kicks>, page: &mut [u64; 512], mem: &guest::GuestMem, status: u32) -> u64 {
    unsafe {
        (*regs(page)).driver_features = REQUIRED;
        (*regs(page)).status = status;
    }
    d.op(mem, &guest::Vcpus { n: 1 }, abi::VIRTIO_OP_STATUS, 0, 0)
}

#[test]
fn driver_ok_only_written_to_the_page_starts_no_queue_work() {
    let (mut d, mut page, mem, _bytes) = kick_device();
    // No status op at all: features were never accepted.
    unsafe { (*regs(&mut page)).status = 1 | 2 | 4; }
    assert_eq!(kick(&mut d, &mut page, &mem), 0, "a DRIVER_OK the device never accepted reached the backend");
    assert_eq!(d.backend.accepted, None);
    // The op refuses DRIVER_OK without FEATURES_OK (NEEDS_RESET); writing
    // it back to the page does not undo the refusal.
    assert_eq!(status(&mut d, &mut page, &mem, 1 | 2 | 4), u64::MAX);
    assert_ne!(unsafe { (*regs(&mut page)).status } & 64, 0);
    unsafe { (*regs(&mut page)).status = 1 | 2 | 4; }
    assert_eq!(kick(&mut d, &mut page, &mem), 0, "the refused DRIVER_OK came back through the page");
}

#[test]
fn a_refused_queue_keeps_driver_ok_out_until_reset() {
    let (mut d, mut page, mem, _bytes) = kick_device();
    assert_eq!(status(&mut d, &mut page, &mem, 1 | 2 | 8), 0);
    assert_eq!(d.backend.accepted, Some(REQUIRED));
    unsafe {
        (*regs(&mut page)).queues[0].ready = 1;
        (*regs(&mut page)).queues[0].num = 3;
    }
    assert_eq!(d.op(&mem, &guest::Vcpus { n: 1 }, abi::VIRTIO_OP_QUEUE, 0, 0), u64::MAX);
    assert_eq!(status(&mut d, &mut page, &mem, 1 | 2 | 8 | 4), u64::MAX);
    unsafe { (*regs(&mut page)).status = 1 | 2 | 8 | 4; }
    assert_eq!(kick(&mut d, &mut page, &mem), 0, "DRIVER_OK bypassed the queue error");
    // Reset clears the lockout.
    assert_eq!(status(&mut d, &mut page, &mem, 0), 0);
    assert_eq!(status(&mut d, &mut page, &mem, 1 | 2 | 8), 0);
    assert_eq!(status(&mut d, &mut page, &mem, 1 | 2 | 8 | 4), 0);
    assert!(kick(&mut d, &mut page, &mem) > 0);
}

#[test]
fn failed_or_cleared_driver_ok_stops_queue_work() {
    let (mut d, mut page, mem, _bytes) = kick_device();
    assert_eq!(status(&mut d, &mut page, &mem, 1 | 2 | 8), 0);
    // FAILED with DRIVER_OK: the driver gave up on the device.
    assert_eq!(status(&mut d, &mut page, &mem, 1 | 2 | 8 | 4 | 128), 0);
    assert_eq!(kick(&mut d, &mut page, &mem), 0, "a FAILED device still processed queues");
    // Accepted: DRIVER_OK polls every queue, then each kick is served.
    assert_eq!(status(&mut d, &mut page, &mem, 1 | 2 | 8 | 4), 0);
    let accepted = d.backend.kicks;
    assert!(accepted > 0, "DRIVER_OK polls the queues");
    assert_eq!(kick(&mut d, &mut page, &mem), accepted + 1);
    // Clearing DRIVER_OK through the op stops queue work again.
    assert_eq!(status(&mut d, &mut page, &mem, 1 | 2 | 8), 0);
    assert_eq!(kick(&mut d, &mut page, &mem), accepted + 1, "queue work after DRIVER_OK was cleared");
}

//! Run the production block service with mocked IPC, root's mailbox and
//! disk hardware.  Kernel invocations overwrite MRs just as the Rust seL4
//! stubs do.
#![allow(dead_code)]

extern crate self as l4h_rt;
pub use l4h_host as host;

use host::blk::{self, BlkdConfig, Channel};
use host::blk::call::{Request, reply};
use host::wire::{self, Message};
use host::errno;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

pub use production::{DevInfo, Driver, Seg};

#[macro_export]
macro_rules! info { ($($a:tt)*) => {{ let _ = format_args!($($a)*); }}; }
#[macro_export]
macro_rules! component { ($($a:tt)*) => {}; }

pub struct Header { id: u32, tsc_hz: u64 }
pub struct Info { header: Header, config: BlkdConfig }
impl Info {
    pub fn header(&self) -> &Header { &self.header }
    pub unsafe fn config<T>(&self) -> &T {
        unsafe { &*core::ptr::from_ref(&self.config).cast::<T>() }
    }
}

pub fn cap<T>(slot: u64) -> sel4::Cap<T> { sel4::Cap(slot, core::marker::PhantomData) }
pub fn test_hang() -> ! { unreachable!("host::TEST_INJECT is off") }

pub mod sel4 {
    pub mod cap_type {
        #[derive(Clone, Copy)] pub struct Endpoint;
        #[derive(Clone, Copy)] pub struct Reply;
        #[derive(Clone, Copy)] pub struct Notification;
        #[derive(Clone, Copy)] pub struct IrqHandler;
    }
    #[derive(Clone, Copy)]
    pub struct Cap<T>(pub u64, pub core::marker::PhantomData<T>);
    pub mod cap { pub type Notification = super::Cap<super::cap_type::Notification>; }
    #[derive(Clone, Copy)]
    pub struct MessageInfo { label: u64, length: usize }
    impl MessageInfo {
        pub fn new(label: u64, _: u64, _: u64, length: usize) -> Self { Self { label, length } }
        pub fn label(&self) -> u64 { self.label }
    }
    pub struct IpcBuffer(pub [u64; 120]);
    impl IpcBuffer {
        pub fn msg_regs(&self) -> &[u64] { &self.0 }
        pub fn msg_regs_mut(&mut self) -> &mut [u64] { &mut self.0 }
    }
    pub fn with_ipc_buffer<R>(f: impl FnOnce(&IpcBuffer) -> R) -> R {
        crate::KERNEL.with_borrow(|k| f(&k.ipc))
    }
    pub fn with_ipc_buffer_mut<R>(f: impl FnOnce(&mut IpcBuffer) -> R) -> R {
        crate::KERNEL.with_borrow_mut(|k| f(&mut k.ipc))
    }
    impl Cap<cap_type::Notification> {
        pub fn signal(self) { crate::KERNEL.with_borrow_mut(|k| k.signals += 1); }
        /// Root's signal (badges::driver::CALL); the test ends once every request
        /// is answered.
        pub fn wait(self) -> (MessageInfo, u64) {
            if crate::KERNEL.with_borrow(|k| k.requests.is_empty()) { std::panic::panic_any(crate::Finished); }
            (MessageInfo::new(0, 0, 0, 0), crate::host::badges::driver::CALL)
        }
    }
    impl Cap<cap_type::IrqHandler> { pub fn irq_handler_ack(self) -> Result<(), ()> { Ok(()) } }
}

/// Root's requests, as l4h_rt::mailbox gives them.
pub mod mailbox {
    use super::*;
    static PUBLISHED: [AtomicU64; 512] = [const { AtomicU64::new(0) }; 512];
    pub fn published<T>() -> &'static T {
        const { assert!(core::mem::size_of::<T>() <= 4096) };
        unsafe { &*PUBLISHED.as_ptr().cast::<T>() }
    }
    pub fn serve(mut f: impl FnMut(u64, &[u64; 6], &mut [u64; 5]) -> Option<usize>) -> bool {
        let mut answered = false;
        loop {
            let Some((label, args, pending_io)) = crate::KERNEL.with_borrow_mut(|k| k.requests.pop_front()) else {
                return answered;
            };
            if pending_io {
                // A client publishes work while root's request is taken.
                // submit() must notify the hardware.
                unsafe { (*crate::channel()).sq.head = 1; }
            }
            let mut words = [0; 5];
            if f(label, &args, &mut words).is_none() {
                words = [crate::host::wire::FAILED, 0, 0, 0, 0];
            }
            crate::KERNEL.with_borrow_mut(|k| k.replies.push(words));
            answered = true;
        }
    }
    pub fn signal() {}
}

mod production {
    use crate::{nvme, scsi, virtio};
    include!(env!("L4H_BLKD_TEST_SRC"));

    pub fn run(info: &'static crate::Info) -> ! {
        // Tests serialize access, and the previous loop has unwound.
        unsafe {
            CLIENTS = [const { None }; blk::MAX_CLIENTS];
            RESERVED = blk::Reservations::new();
        }
        main(info)
    }
}

mod nvme { pub type Nvme = crate::MockDriver; }
mod scsi { pub type VirtioScsi = crate::MockDriver; }
mod virtio { pub type VirtioBlk = crate::MockDriver; }

struct Kernel {
    ipc: sel4::IpcBuffer,
    requests: VecDeque<(u64, [u64; 6], bool)>,
    replies: Vec<[u64; 5]>,
    retry: bool,
    status: u32,
    kicks: usize,
    signals: usize,
    /// Requests the mock device holds at once.
    room: usize,
    /// Started requests: tag, sector, bytes.
    started: Vec<(u64, u64, u64)>,
}
thread_local! {
    static KERNEL: RefCell<Kernel> = RefCell::new(Kernel {
        ipc: sel4::IpcBuffer([0; 120]), requests: VecDeque::new(), replies: Vec::new(),
        retry: false, status: 0, kicks: 0, signals: 0, room: usize::MAX, started: Vec::new(),
    });
}

pub struct MockDriver { legacy_io: u32, queue: u16, provisioning: bool, in_flight: Vec<u64> }
impl MockDriver {
    pub fn new(_: u32, cfg: &BlkdConfig) -> Self {
        let queue = if cfg.kind == blk::BLKD_VIRTIO_SCSI { 2 } else { 0 };
        Self { legacy_io: cfg.legacy_io, queue, provisioning: false, in_flight: Vec::new() }
    }
    fn notify(&self) {
        KERNEL.with_borrow_mut(|k| {
            k.kicks += 1;
            if self.legacy_io != 0 {
                // seL4_X86_IOPort_Out16 marshals port and data into MR0/1.
                // A successful empty kernel reply leaves those arguments.
                k.ipc.0[..2].copy_from_slice(&[self.legacy_io as u64 + 0x10, self.queue as u64]);
            }
        });
    }
}
impl Driver for MockDriver {
    fn units(&self) -> usize { 1 }
    fn info(&self, _: usize) -> DevInfo {
        DevInfo { capacity: 131072, block_size: 512, read_only: false, flush: true, address: 0x301 }
    }
    fn can_start(&self) -> bool { KERNEL.with_borrow(|k| self.in_flight.len() < k.room) }
    fn start(&mut self, tag: u64, _: usize, _: u32, sector: u64, data: &[Seg]) -> Result<(), u32> {
        self.provisioning |= tag == u64::MAX;
        if tag != u64::MAX {
            self.in_flight.push(tag);
            let bytes = data.iter().map(|s| s.len as u64).sum();
            KERNEL.with_borrow_mut(|k| k.started.push((tag, sector, bytes)));
        }
        Ok(())
    }
    fn kick(&mut self) { self.notify(); }
    fn reap(&mut self, done: &mut dyn FnMut(u64, u32)) {
        if core::mem::take(&mut self.provisioning) {
            let (status, retry) = KERNEL.with_borrow(|k| (k.status, k.retry));
            done(u64::MAX, status);
            // VirtioScsi::reap notifies after all callbacks when another
            // completion in the batch needs retrying (BUSY/UNIT_ATTENTION).
            if retry { self.notify(); }
        }
        for tag in self.in_flight.drain(..) {
            done(tag, blk::STATUS_OK);
        }
    }
}

struct Finished;
static LOCK: Mutex<()> = Mutex::new(());
unsafe extern "C" {
    fn mmap(addr: usize, len: usize, prot: i32, flags: i32, fd: i32, off: i64) -> usize;
    fn munmap(addr: usize, len: usize) -> i32;
}
fn channel() -> *mut Channel { blk::channel_va(0) as *mut Channel }

/// Map client 0's channel and extent table, as root does.
fn map_client() {
    for (va, len) in [(channel() as usize, blk::CHANNEL_PAGES * 4096), (blk::extent_va(0), blk::EXTENT_STRIDE)] {
        // MAP_FIXED_NOREPLACE: never overwrite an unrelated mapping.
        assert_eq!(unsafe { mmap(va, len, 3, 0x100022, -1, 0) }, va);
    }
}

fn unmap_client() {
    for (va, len) in [(channel() as usize, blk::CHANNEL_PAGES * 4096), (blk::extent_va(0), blk::EXTENT_STRIDE)] {
        assert_eq!(unsafe { munmap(va, len) }, 0);
    }
}

/// A request as root posts it: label and argument words.
fn post(r: Request) -> (u64, [u64; 6]) {
    let mut args = [0; 6];
    r.encode(&mut args);
    (r.label(), args)
}

fn add() -> (u64, [u64; 6]) {
    post(Request::Add { client: 0, unit: 0, dom0: false, n: 0 })
}

/// Not a request of blkd's.
const UNKNOWN: (u64, [u64; 6]) = (u64::MAX, [0; 6]);

fn run(kind: u32, legacy: bool, (label, args): (u64, [u64; 6]), pending_io: bool, retry: bool, status: u32) -> [u64; 5] {
    let _lock = LOCK.lock().unwrap();
    map_client();
    unsafe {
        (*channel()).capacity_sectors = 8;
        (*channel()).pool = blk::Pool { gpa: 0x8000000, paddr: 0x10000000, size: 4096 };
        (*channel()).reqs[0] = blk::Req { op: blk::OP_READ, nr_segs: 1, ..Default::default() };
        (*channel()).reqs[0].segs[0] = blk::Seg { gpa: 0x8000000, len: 512, flags: blk::SEG_WRITE };
    }
    KERNEL.with_borrow_mut(|k| {
        k.ipc.0.fill(0);
        k.requests = [(add().0, add().1, false), (label, args, pending_io)].into();
        k.replies.clear();
        k.retry = retry;
        k.status = status;
        k.kicks = 0;
        k.room = usize::MAX;
        k.started.clear();
    });
    // BlkdConfig consists entirely of integer fields.
    let mut config: BlkdConfig = unsafe { core::mem::zeroed() };
    config.kind = kind;
    config.legacy_io = if legacy { 0xc000 } else { 0 };
    let info = Box::leak(Box::new(Info { header: Header { id: 1, tsc_hz: 1_000_000_000 }, config }));
    let stopped = std::panic::catch_unwind(|| production::run(info)).unwrap_err();
    unmap_client();
    assert!(stopped.is::<Finished>(), "service failed before sending every reply");
    KERNEL.with_borrow(|k| {
        assert_eq!(k.replies.len(), 2);
        assert_eq!(k.replies[0][0], 0, "client must attach successfully");
        assert!(k.kicks > 0, "the clobbering driver path must run");
        k.replies[1]
    })
}

#[test]
fn units_are_published_and_requests_survive_pending_io() {
    for kind in [blk::BLKD_VIRTIO, blk::BLKD_VIRTIO_SCSI] {
        for legacy in [false, true] {
            assert_eq!(run(kind, legacy, UNKNOWN, true, false, 0)[0], errno::EINVAL);
            let p = mailbox::published::<blk::Published>();
            let u = &p.unit[0];
            let unit = [&u.capacity, &u.block_size, &u.read_only, &u.address].map(|w| w.load(Ordering::Relaxed));
            assert_eq!((p.ready.load(Ordering::Relaxed), p.units.load(Ordering::Relaxed), unit), (1, 1, [131072, 512, 0, 0x301]));
        }
    }
}

#[test]
fn service_status_survives_pending_io() {
    for kind in [blk::BLKD_VIRTIO, blk::BLKD_VIRTIO_SCSI] {
        assert_eq!(wire::reply::<reply::Flush>(&run(kind, true, post(Request::Flush { unit: 0 }), true, false, 0)), Ok(0));
        assert_eq!(run(kind, true, UNKNOWN, true, false, 0)[0], errno::EINVAL);
    }
}

#[test]
fn provisioning_status_survives_scsi_retry() {
    for status in [blk::STATUS_OK, blk::STATUS_IOERR] {
        let r = run(blk::BLKD_VIRTIO_SCSI, true, post(Request::Flush { unit: 0 }), false, true, status);
        assert_eq!(wire::reply::<reply::Flush>(&r), Ok(status as u64));
    }
}

#[test]
fn refused_provisioning_reports_its_errno() {
    // Sector 0, length 0: not a flush, so not a valid range.
    let r = run(blk::BLKD_VIRTIO, true, post(Request::Write { sector: 0, length: 0, unit: 0 }), true, false, 0);
    assert_eq!(wire::reply::<reply::Write>(&r), Err(errno::EINVAL));
}

#[test]
fn a_split_request_waits_for_room_and_drains_on_remove() {
    let _lock = LOCK.lock().unwrap();
    map_client();
    // Guest sectors 0..8192 are disk sectors 40960.., then 8192...
    let staging: &'static [[u64; 2]] = Box::leak(Box::new([[40960, 8192], [8192, 8192]]));
    unsafe {
        (*channel()).pool = blk::Pool { gpa: 0x8000000, paddr: 0x10000000, size: 1 << 20 };
        (*channel()).reqs[0] = blk::Req { id: 7, op: blk::OP_READ, nr_segs: 1, sector: 8184, ..Default::default() };
        (*channel()).reqs[0].segs[0] = blk::Seg { gpa: 0x8000000, len: 8192, flags: blk::SEG_WRITE };
    }
    KERNEL.with_borrow_mut(|k| {
        k.ipc.0.fill(0);
        // Attach the two extents; the request arrives with an extent query;
        // the device has room for one piece; then remove the client.
        let (add, extent, remove) = (post(Request::Add { client: 0, unit: 0, dom0: false, n: 2 }),
            post(Request::Extent { client: 0, k: 0 }), post(Request::Remove { client: 0 }));
        k.requests = [(add.0, add.1, false), (extent.0, extent.1, true), (remove.0, remove.1, false)].into();
        k.replies.clear();
        (k.retry, k.status, k.kicks, k.room) = (false, 0, 0, 1);
        k.started.clear();
    });
    let mut config: BlkdConfig = unsafe { core::mem::zeroed() };
    config.dma_va = staging.as_ptr() as u64;
    let info = Box::leak(Box::new(Info { header: Header { id: 1, tsc_hz: 1_000_000_000 }, config }));
    let stopped = std::panic::catch_unwind(|| production::run(info)).unwrap_err();
    let (cq, resp) = unsafe { ((*channel()).cq.head, (*channel()).resps[0]) };
    unmap_client();
    assert!(stopped.is::<Finished>(), "service failed before sending every reply");
    KERNEL.with_borrow(|k| {
        assert_eq!(k.replies[0][0], 0, "the extents attach");
        assert_eq!(k.replies[2][0], 0, "remove drains the carried piece");
        // Pending slot 0: piece 0 at the end of the first extent, piece 1
        // at the start of the second, once the first completed.
        assert_eq!(k.started, [(0, 49144, 4096), (1, 8192, 4096)]);
    });
    assert_eq!((cq, resp.id, resp.status), (1, 7, blk::STATUS_OK));
}

#[test]
fn completion_batch_wakes_the_client_once_and_returns_every_request() {
    let _lock = LOCK.lock().unwrap();
    map_client();
    unsafe {
        (*channel()).pool = blk::Pool { gpa: 0x8000000, paddr: 0x10000000, size: 4096 };
        for i in 0..4 {
            (*channel()).reqs[i] = blk::Req { id: i as u64, op: blk::OP_READ, nr_segs: 1, ..Default::default() };
            (*channel()).reqs[i].segs[0] = blk::Seg { gpa: 0x8000000, len: 512, flags: blk::SEG_WRITE };
        }
        (*channel()).sq.head = 4;
    }
    KERNEL.with_borrow_mut(|k| {
        k.ipc.0.fill(0);
        let remove = post(Request::Remove { client: 0 });
        k.requests = [(add().0, add().1, false), (remove.0, remove.1, false)].into();
        k.replies.clear();
        (k.retry, k.status, k.kicks, k.signals, k.room) = (false, 0, 0, 0, usize::MAX);
        k.started.clear();
    });
    let config: BlkdConfig = unsafe { core::mem::zeroed() };
    let info = Box::leak(Box::new(Info { header: Header { id: 1, tsc_hz: 1_000_000_000 }, config }));
    let stopped = std::panic::catch_unwind(|| production::run(info)).unwrap_err();
    assert!(stopped.is::<Finished>());
    unsafe {
        assert_eq!((*channel()).cq.head, 4);
        for i in 0..4 { assert_eq!(((*channel()).resps[i].id, (*channel()).resps[i].status), (i as u64, blk::STATUS_OK)); }
    }
    unmap_client();
    KERNEL.with_borrow(|k| { assert_eq!(k.started.len(), 4); assert_eq!(k.signals, 1); });
}

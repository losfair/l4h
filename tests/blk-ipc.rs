//! Run the production block service with mocked IPC and disk hardware.
//! Kernel invocations overwrite MRs just as the Rust seL4 stubs do.
#![allow(dead_code)]

extern crate self as l4h_rt;
pub use l4h_host as host;

use host::blk::{self, BlkdConfig, Channel};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::sync::Mutex;

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
    impl Cap<cap_type::Endpoint> {
        pub fn recv(self, _: Cap<cap_type::Reply>) -> (MessageInfo, u64) {
            crate::KERNEL.with_borrow_mut(|k| {
                let (label, args, pending_io) = k.requests.pop_front().expect("unexpected receive");
                k.ipc.0[..args.len()].copy_from_slice(&args);
                if pending_io {
                    // A client publishes work while root's service call is
                    // being received. submit() must notify the hardware.
                    unsafe { (*crate::channel()).sq.head = 1; }
                }
                (MessageInfo::new(label, 0, 0, args.len()), 0)
            })
        }
        pub fn reply_recv(self, msg: MessageInfo, reply: Cap<cap_type::Reply>) -> (MessageInfo, u64) {
            let finished = crate::KERNEL.with_borrow_mut(|k| {
                assert_eq!(msg.length, 5);
                k.replies.push(k.ipc.0[..5].try_into().unwrap());
                k.requests.is_empty()
            });
            if finished { std::panic::panic_any(crate::Finished); }
            self.recv(reply)
        }
    }
    impl Cap<cap_type::Notification> { pub fn signal(self) {} }
    impl Cap<cap_type::IrqHandler> { pub fn irq_handler_ack(self) -> Result<(), ()> { Ok(()) } }
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
    requests: VecDeque<(u64, [u64; 3], bool)>,
    replies: Vec<[u64; 5]>,
    retry: bool,
    status: u32,
    kicks: usize,
}
thread_local! {
    static KERNEL: RefCell<Kernel> = RefCell::new(Kernel {
        ipc: sel4::IpcBuffer([0; 120]), requests: VecDeque::new(), replies: Vec::new(),
        retry: false, status: 0, kicks: 0,
    });
}

pub struct MockDriver { legacy_io: u32, queue: u16, provisioning: bool }
impl MockDriver {
    pub fn new(_: u32, cfg: &BlkdConfig) -> Self {
        Self { legacy_io: cfg.legacy_io, queue: if cfg.kind == blk::BLKD_VIRTIO_SCSI { 2 } else { 0 }, provisioning: false }
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
    fn can_start(&self) -> bool { true }
    fn start(&mut self, tag: u64, _: usize, _: u32, _: u64, _: &[Seg]) -> Result<(), u32> {
        self.provisioning |= tag == u64::MAX;
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
    }
}

struct Finished;
static LOCK: Mutex<()> = Mutex::new(());
unsafe extern "C" {
    fn mmap(addr: usize, len: usize, prot: i32, flags: i32, fd: i32, off: i64) -> usize;
    fn munmap(addr: usize, len: usize) -> i32;
}
fn channel() -> *mut Channel { blk::channel_va(0) as *mut Channel }

fn run(kind: u32, legacy: bool, label: u64, pending_io: bool, retry: bool, status: u32) -> [u64; 5] {
    let _lock = LOCK.lock().unwrap();
    let len = blk::CHANNEL_PAGES * 4096;
    // MAP_FIXED_NOREPLACE: never overwrite an unrelated mapping.
    assert_eq!(unsafe { mmap(channel() as usize, len, 3, 0x100022, -1, 0) }, channel() as usize);
    unsafe {
        (*channel()).capacity_sectors = 8;
        (*channel()).pool = blk::Pool { gpa: 0x8000000, paddr: 0x10000000, size: 4096 };
        (*channel()).reqs[0] = blk::Req { op: blk::OP_READ, nr_segs: 1, ..Default::default() };
        (*channel()).reqs[0].segs[0] = blk::Seg { gpa: 0x8000000, len: 512, flags: blk::SEG_WRITE };
    }
    KERNEL.with_borrow_mut(|k| {
        k.ipc.0.fill(0);
        k.requests = [(blk::BLKD_ADD, [0; 3], false), (label, [0; 3], pending_io)].into();
        k.replies.clear();
        k.retry = retry;
        k.status = status;
        k.kicks = 0;
    });
    // BlkdConfig consists entirely of integer fields.
    let mut config: BlkdConfig = unsafe { core::mem::zeroed() };
    config.kind = kind;
    config.legacy_io = if legacy { 0xc000 } else { 0 };
    let info = Box::leak(Box::new(Info { header: Header { id: 1, tsc_hz: 1_000_000_000 }, config }));
    let stopped = std::panic::catch_unwind(|| production::run(info)).unwrap_err();
    assert_eq!(unsafe { munmap(channel() as usize, len) }, 0);
    assert!(stopped.is::<Finished>(), "service failed before sending every reply");
    KERNEL.with_borrow(|k| {
        assert_eq!(k.replies.len(), 2);
        assert_eq!(k.replies[0][0], 0, "client must attach successfully");
        assert!(k.kicks > 0, "the clobbering driver path must run");
        k.replies[1]
    })
}

#[test]
fn disk_info_survives_pending_io() {
    for kind in [blk::BLKD_VIRTIO, blk::BLKD_VIRTIO_SCSI] {
        for legacy in [false, true] {
            assert_eq!(run(kind, legacy, blk::BLKD_INFO, true, false, 0), [131072, 512, 0, 1, 0x301]);
        }
    }
}

#[test]
fn service_status_survives_pending_io() {
    for kind in [blk::BLKD_VIRTIO, blk::BLKD_VIRTIO_SCSI] {
        assert_eq!(run(kind, true, blk::BLKD_FLUSH, true, false, 0)[0], 0);
        assert_eq!(run(kind, true, u64::MAX, true, false, 0)[0], u64::MAX);
    }
}

#[test]
fn provisioning_status_survives_scsi_retry() {
    for status in [blk::STATUS_OK, blk::STATUS_IOERR] {
        assert_eq!(run(blk::BLKD_VIRTIO_SCSI, true, blk::BLKD_FLUSH, false, true, status)[0], status as u64);
    }
}

#[test]
fn refused_provisioning_reports_its_errno() {
    // Sector 0, length 0: not a flush, so not a valid range.
    let r = run(blk::BLKD_VIRTIO, true, blk::BLKD_WRITE, true, false, 0);
    assert_eq!(r[..2], [blk::BLKD_REFUSED, blk::EINVAL]);
}

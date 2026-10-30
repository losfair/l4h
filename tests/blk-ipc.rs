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
#[path = "../host/l4h-blkd/src/crypt.rs"]
mod crypt;
#[path = "../host/l4h-blkd/src/data.rs"]
mod data;
#[path = "../host/l4h-blkd/src/bounce.rs"]
mod bounce;

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
        pub fn length(&self) -> usize { self.length }
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
    use crate::{bounce, crypt, data, nvme, scsi, virtio};
    include!(env!("L4H_BLKD_TEST_SRC"));

    pub fn run(info: &'static crate::Info) -> ! {
        // Tests serialize access, and the previous loop has unwound.
        unsafe { CLIENTS = [const { None }; blk::MAX_CLIENTS]; PENDING = [None; MAX_INFLIGHT]; }
        main(info)
    }
    fn service(info: &'static crate::Info) -> Blkd {
        unsafe { CLIENTS = [const { None }; blk::MAX_CLIENTS]; PENDING = [None; MAX_INFLIGHT]; }
        let cfg = &info.config;
        let drv = crate::MockDriver::new(1, cfg);
        let dev = [drv.info(0)].into_iter().collect();
        Blkd { clients: unsafe { &mut *addr_of_mut!(CLIENTS) },
            pending: unsafe { &mut *addr_of_mut!(PENDING) }, active: ArrayVec::new(), waiting: ArrayVec::new(),
            bounce: bounce::Bounce::new(), cfg, drv: Drv::Virtio(drv), dev, next: 0, ticks_per_sec: 1_000_000_000 }
    }

    pub fn pipeline(info: &'static crate::Info) {
        let mut b = service(info);
        let cfg = b.cfg;
        let key = core::array::from_fn(|i| i as u8);
        assert_eq!(b.add(0, 0, blk::ENCRYPT, &key, 11), 0);
        assert_eq!(b.add(1, 0, 0, &[0; 64], 11), 0);
        b.submit();
        unsafe {
            assert_eq!((*crate::channel()).sq.tail, 1, "second write remains queued while bounce space is full");
            let peer = blk::channel_va(1) as *mut Channel;
            assert_eq!((*peer).sq.tail, 2, "other client's read and flush bypass the deferred write");
            assert_eq!((*crate::channel()).block_size, 4096);
        }
        let Drv::Virtio(drv) = &mut b.drv else { unreachable!() };
        assert_eq!(drv.commands.len(), 3);
        let (tag, op, sector, segs) = &drv.commands[0];
        assert_eq!((*op, *sector), (blk::OP_WRITE, 16));
        assert_eq!(segs[0].pa, cfg.bounce_paddr);
        let snapshot = unsafe { core::slice::from_raw_parts(cfg.bounce_va as *const u8, 4096) }.to_vec();
        unsafe { core::ptr::write_bytes(blk::pool_va(0, 4 << 20) as *mut u8, 0xab, 14 * 256 * 1024); }
        assert_eq!(snapshot, unsafe { core::slice::from_raw_parts(cfg.bounce_va as *const u8, 4096) });
        assert!(snapshot.iter().any(|&b| b != 0x5a));
        let mut plain = [0; 4096];
        unsafe { b.clients[0].as_ref().unwrap().keys.decrypt(snapshot.as_ptr(), plain.as_mut_ptr(), 0); }
        assert_eq!(plain, [0x5a; 4096], "tweak is relative to window start");
        drv.completed.push((*tag, blk::STATUS_IOERR));
        b.reap(); b.submit();
        unsafe { assert_eq!((*crate::channel()).sq.tail, 2, "failed completion also frees its run"); }
        let Drv::Virtio(drv) = &mut b.drv else { unreachable!() };
        for (tag, ..) in &drv.commands[1..] { drv.completed.push((*tag, blk::STATUS_OK)); }
        b.reap();
        assert_eq!(b.clients[0].as_ref().unwrap().outstanding, 0);
        // A rejected hardware submission must also release the reserved run.
        let Drv::Virtio(drv) = &mut b.drv else { unreachable!() };
        drv.fail_start = true;
        unsafe { (*crate::channel()).reqs[2] = (*crate::channel()).reqs[0]; (*crate::channel()).sq.head = 3; }
        b.submit();
        let run = b.bounce.alloc(bounce::SIZE).expect("failed start leaked bounce memory");
        b.bounce.free(run);
        assert_eq!(b.remove(0), 0);
        assert!(b.clients[0].is_none());
        // Plain and encrypted reuse of the same channel, including
        // unsupported feature flags and malformed key rejection.
        assert_eq!(b.add(0, 0, blk::ENCRYPT, &[0; 64], 11), 22);
        assert_eq!(b.add(0, 0, 2, &key, 11), 22);
        assert_eq!(b.add(0, 0, 0, &[0; 64], 11), 0);
        let Drv::Virtio(drv) = &mut b.drv else { unreachable!() };
        drv.fail_start = false;
        unsafe {
            core::ptr::write_bytes(blk::pool_va(0, 4 << 20) as *mut u8, 0x3c, 14 * 256 * 1024);
            (*crate::channel()).reqs[3] = (*crate::channel()).reqs[0];
            (*crate::channel()).sq.head = 4;
        }
        b.submit();
        let Drv::Virtio(drv) = &mut b.drv else { unreachable!() };
        let (tag, op, _, segs) = drv.commands.last().unwrap();
        assert_eq!(*op, blk::OP_WRITE);
        assert_eq!(segs[0].pa, cfg.bounce_paddr, "plain writes also use private DMA memory");
        unsafe { core::ptr::write_bytes(blk::pool_va(0, 4 << 20) as *mut u8, 0xa7, 14 * 256 * 1024); }
        let snapshot = unsafe { core::slice::from_raw_parts(cfg.bounce_va as *const u8, 14 * 256 * 1024) };
        assert!(snapshot.iter().all(|&b| b == 0x3c), "guest mutation must not reach an in-flight plain write");
        drv.completed.push((*tag, blk::STATUS_OK));
        b.reap();
        assert_eq!(b.remove(0), 0);
    }

    pub fn split_writes(info: &'static crate::Info) {
        let mut b = service(info);
        b.dev[0].block_size = 4096;
        let key = core::array::from_fn(|i| i as u8);
        for flags in [0, blk::ENCRYPT] {
            if flags != 0 && !std::is_x86_feature_detected!("aes") { continue; }
            assert_eq!(b.add(0, 0, flags, &key, 11), 0);
            for lengths in [&[512, 3584][..], &[1, 4095], &[4095, 1], &[1, 4094, 1]] {
                let mut plain = Vec::new();
                unsafe {
                    let c = &mut *crate::channel();
                    let mut req = blk::Req { op: blk::OP_WRITE, nr_segs: lengths.len() as u32, ..Default::default() };
                    for (i, &len) in lengths.iter().enumerate() {
                        req.segs[i] = blk::Seg { gpa: (i * 4096) as u64, len, flags: 0 };
                        let byte = 0x40 + i as u8;
                        core::ptr::write_bytes((blk::pool_va(0, 4 << 20) + i * 4096) as *mut u8, byte, len as usize);
                        plain.extend(core::iter::repeat_n(byte, len as usize));
                    }
                    c.reqs[c.sq.head as usize % blk::RING_SIZE] = req;
                    c.sq.head += 1;
                }
                b.submit();
                let Drv::Virtio(drv) = &mut b.drv else { unreachable!() };
                let (tag, op, sector, segs) = drv.commands.last().unwrap();
                assert_eq!((*op, *sector), (blk::OP_WRITE, 16));
                assert_eq!(segs.len(), 1, "packed writes must not become sub-LBA NVMe commands");
                assert_eq!((segs[0].pa, segs[0].len), (b.cfg.bounce_paddr, 4096));
                let source = b.cfg.bounce_va as *const u8;
                let mut actual = [0; 4096];
                unsafe {
                    if flags != 0 { b.clients[0].as_ref().unwrap().keys.decrypt(source, actual.as_mut_ptr(), 0); }
                    else { core::ptr::copy_nonoverlapping(source, actual.as_mut_ptr(), 4096); }
                }
                assert_eq!(actual.as_slice(), plain);
                drv.completed.push((*tag, blk::STATUS_OK));
                b.reap();
            }
            assert_eq!(b.remove(0), 0);
        }
    }

    fn enqueue(i: usize, op: u32, bytes: u32) {
        unsafe {
            let c = &mut *(blk::channel_va(i) as *mut Channel);
            let mut req = blk::Req { op, nr_segs: if op == blk::OP_FLUSH { 0 } else { 1 }, ..Default::default() };
            req.segs[0] = blk::Seg { gpa: 0, len: bytes, flags: if op == blk::OP_READ { blk::SEG_WRITE } else { 0 } };
            c.reqs[c.sq.head as usize % blk::RING_SIZE] = req;
            c.sq.head += 1;
            c.cq.tail = c.cq.head;
        }
    }

    pub fn fair_writes(info: &'static crate::Info) {
        let mut b = service(info);
        for i in 0..4 { assert_eq!(b.add(i, 0, 0, &[0; 64], 11), 0); }
        for _ in 0..8 { enqueue(1, blk::OP_WRITE, 256 << 10); enqueue(2, blk::OP_WRITE, 256 << 10); }
        b.submit(); // Small writes occupy all 4 MiB.
        enqueue(0, blk::OP_WRITE, 14 * 256 * 1024);
        enqueue(0, blk::OP_WRITE, 14 * 256 * 1024);
        enqueue(1, blk::OP_WRITE, 256 << 10);
        enqueue(2, blk::OP_WRITE, 256 << 10);
        enqueue(3, blk::OP_READ, 4096);
        enqueue(3, blk::OP_FLUSH, 0);
        b.next = 0;
        b.submit();
        assert_eq!(&*b.waiting, [0, 1, 2]);
        let Drv::Virtio(drv) = &b.drv else { unreachable!() };
        assert_eq!(drv.commands.len(), 18, "reads and flushes must bypass waiting writers");
        let old: Vec<_> = drv.commands[..16].iter().map(|c| c.0).collect();
        for (n, &tag) in old[..14].iter().enumerate() {
            let Drv::Virtio(drv) = &mut b.drv else { unreachable!() };
            drv.completed.push((tag, blk::STATUS_OK));
            b.reap(); b.submit();
            let Drv::Virtio(drv) = &b.drv else { unreachable!() };
            assert_eq!(drv.commands.len(), if n == 13 { 19 } else { 18 },
                "small writes must not keep consuming the space the oldest writer needs");
        }
        let Drv::Virtio(drv) = &mut b.drv else { unreachable!() };
        assert_eq!(drv.commands[18].2, 16, "the large write must run first");
        assert_eq!(&*b.waiting, [1, 2, 0], "a second large write joins the back of the queue");
        drv.completed.push((drv.commands[18].0, blk::STATUS_OK));
        b.reap(); b.submit();
        let Drv::Virtio(drv) = &b.drv else { unreachable!() };
        assert_eq!(drv.commands.len(), 21);
        let sectors: Vec<_> = drv.commands[19..].iter().map(|c| c.2).collect();
        assert_eq!(sectors, [16384, 32768], "both smaller waiters run before another large write");
        assert_eq!(&*b.waiting, [0]);
        assert_eq!(b.remove(0), 0); // A destroyed waiter cannot keep reserving space.
        enqueue(1, blk::OP_WRITE, 256 << 10);
        b.submit();
        assert!(b.waiting.is_empty());
        let Drv::Virtio(drv) = &b.drv else { unreachable!() };
        assert_eq!(drv.commands.len(), 22);
    }

    pub fn abandoned_waiter(info: &'static crate::Info) {
        let mut b = service(info);
        for i in 0..3 { assert_eq!(b.add(i, 0, 0, &[0; 64], 11), 0); }
        for _ in 0..4 { enqueue(2, blk::OP_WRITE, 256 << 10); }
        b.submit(); // 1 MiB in flight prevents a 3.5 MiB allocation.
        enqueue(0, blk::OP_WRITE, 14 * 256 * 1024);
        enqueue(1, blk::OP_WRITE, 256 << 10);
        b.next = 0;
        b.submit();
        assert_eq!(&*b.waiting, [0, 1]);
        unsafe {
            let c = &mut *crate::channel();
            c.sq.head = c.sq.tail;
        }
        b.submit();
        assert!(b.waiting.is_empty(), "a withdrawn request cannot reserve space indefinitely");
        let Drv::Virtio(drv) = &b.drv else { unreachable!() };
        assert_eq!(drv.commands.len(), 5, "the smaller write made progress");
        assert_eq!(b.remove(0), 0);
    }

    pub fn cq_blocked_waiter(info: &'static crate::Info) {
        let mut b = service(info);
        for i in 0..3 { assert_eq!(b.add(i, 0, 0, &[0; 64], 11), 0); }
        for _ in 0..4 { enqueue(2, blk::OP_WRITE, 256 << 10); }
        b.submit(); // 1 MiB prevents the large write from finding space.
        for _ in 0..blk::RING_SIZE - 1 { enqueue(0, blk::OP_READ, 4096); }
        b.submit();
        assert_eq!(b.clients[0].as_ref().unwrap().outstanding, blk::RING_SIZE - 1);
        enqueue(0, blk::OP_WRITE, 14 * 256 * 1024);
        enqueue(1, blk::OP_WRITE, 256 << 10);
        b.next = 0;
        b.submit();
        assert_eq!(&*b.waiting, [0, 1]);
        // Inject transient CQ back-pressure with 127 reads in flight.
        unsafe {
            let c = &mut *crate::channel();
            c.cq.tail = c.cq.head.wrapping_sub(1);
        }
        let Drv::Virtio(drv) = &mut b.drv else { unreachable!() };
        let before = drv.commands.len();
        drv.completed.extend(drv.commands[..4].iter().map(|c| (c.0, blk::STATUS_OK)));
        b.reap(); // All bounce memory is now free.
        for n in 0..3 {
            enqueue(1, blk::OP_WRITE, 256 << 10);
            b.submit();
            assert_eq!(&*b.waiting, [0], "CQ back-pressure preserves rank without reserving bounce space");
            let Drv::Virtio(drv) = &b.drv else { unreachable!() };
            assert_eq!(drv.commands.len(), before + n + 2, "another writer keeps making progress while the head is paused");
        }
        // These four small writes now hold 1 MiB. A second large writer
        // waits behind the CQ-blocked client, which still has its old rank.
        enqueue(1, blk::OP_WRITE, 14 * 256 * 1024);
        enqueue(2, blk::OP_READ, 4096);
        enqueue(2, blk::OP_FLUSH, 0);
        b.submit();
        let Drv::Virtio(drv) = &b.drv else { unreachable!() };
        assert_eq!(drv.commands.len(), before + 6, "other clients' reads and flushes still run");
        assert_eq!(&*b.waiting, [0, 1]);
        unsafe {
            let c = &mut *crate::channel();
            c.cq.tail = c.cq.head;
        }
        b.submit();
        assert_eq!(&*b.waiting, [0, 1]);
        let Drv::Virtio(drv) = &mut b.drv else { unreachable!() };
        drv.completed.extend(drv.commands[before..before + 4].iter().map(|c| (c.0, blk::STATUS_OK)));
        b.reap(); b.submit();
        assert_eq!(&*b.waiting, [1], "the resumed writer gets the first large run");
        let Drv::Virtio(drv) = &mut b.drv else { unreachable!() };
        assert_eq!(drv.commands.last().unwrap().2, 16);
        drv.completed.push((drv.commands.last().unwrap().0, blk::STATUS_OK));
        b.reap(); b.submit();
        assert!(b.waiting.is_empty());
        let Drv::Virtio(drv) = &b.drv else { unreachable!() };
        let writes: Vec<_> = drv.commands[before + 6..].iter().map(|c| (c.1, c.2)).collect();
        assert_eq!(writes, [(blk::OP_WRITE, 16), (blk::OP_WRITE, 16384)], "large write keeps priority after the CQ drains");
    }

    pub fn malformed_waiter(info: &'static crate::Info, distance: u32) {
        let mut b = service(info);
        for i in 0..3 { assert_eq!(b.add(i, 0, 0, &[0; 64], 11), 0); }
        for _ in 0..4 { enqueue(2, blk::OP_WRITE, 256 << 10); }
        b.submit();
        enqueue(0, blk::OP_WRITE, 14 * 256 * 1024);
        enqueue(1, blk::OP_WRITE, 256 << 10);
        b.next = 0;
        b.submit();
        assert_eq!(&*b.waiting, [0, 1]);
        unsafe {
            let c = &mut *crate::channel();
            c.sq.head = c.sq.tail.wrapping_add(distance);
        }
        b.next = 1; // Other writers are visited before the malformed head.
        b.submit();
        assert!(b.waiting.is_empty(), "malformed indices must lose their reservation");
        enqueue(2, blk::OP_WRITE, 256 << 10);
        b.submit();
        let Drv::Virtio(drv) = &b.drv else { unreachable!() };
        assert_eq!(drv.commands.len(), 6, "both peer writers progress while the malicious head remains malformed");
    }

    pub fn priority_change_wakes_parked_writers(info: &'static crate::Info, invalid: bool) {
        let mut b = service(info);
        for i in 0..3 { assert_eq!(b.add(i, 0, 0, &[0; 64], 11), 0); }
        for _ in 0..4 { enqueue(2, blk::OP_WRITE, 1 << 20); }
        b.submit();
        enqueue(0, blk::OP_WRITE, 14 * 256 * 1024);
        for i in 1..3 { enqueue(i, blk::OP_WRITE, 4096); }
        b.next = 0;
        b.submit();
        assert_eq!(&*b.waiting, [0, 1, 2]);
        if invalid { unsafe { (*crate::channel()).reqs[0].nr_segs = 0; } }
        let Drv::Virtio(drv) = &mut b.drv else { unreachable!() };
        drv.completed.extend(drv.commands.iter().map(|c| (c.0, blk::STATUS_OK)));
        b.reap();
        b.next = 1; // Park both peers before visiting the priority writer.
        b.submit();
        assert!(b.waiting.is_empty(), "priority changes must wake peers within the same pass");
        let Drv::Virtio(drv) = &b.drv else { unreachable!() };
        let sectors: Vec<_> = drv.commands[4..].iter().map(|c| c.2).collect();
        assert_eq!(sectors, if invalid { vec![16384, 32768] } else { vec![16, 16384, 32768] });
    }

    pub fn blocked_writers_checked_once(info: &'static crate::Info) {
        let mut b = service(info);
        for i in 0..3 { assert_eq!(b.add(i, 0, 0, &[0; 64], 11), 0); }
        for _ in 0..4 { enqueue(2, blk::OP_WRITE, 256 << 10); }
        b.submit();
        enqueue(0, blk::OP_WRITE, 14 * 256 * 1024);
        for i in 1..3 { enqueue(i, blk::OP_WRITE, 256 << 10); }
        b.next = 0;
        b.submit();
        assert_eq!(&*b.waiting, [0, 1, 2]);
        for cq_blocked in [false, true] {
            if cq_blocked {
                unsafe {
                    let c = &mut *crate::channel();
                    c.cq.tail = c.cq.head.wrapping_sub(blk::RING_SIZE as u32);
                    // The next runnable waiter also needs a large run.
                    let c = &mut *(blk::channel_va(1) as *mut Channel);
                    c.reqs[c.sq.tail as usize % blk::RING_SIZE].segs[0].len = 14 * 256 * 1024;
                }
            }
            for next in 0..3 {
                let Drv::Virtio(drv) = &b.drv else { unreachable!() };
                drv.can_start_calls.set(0);
                b.next = next;
                b.submit();
                assert_eq!(&*b.waiting, [0, 1, 2]);
                let Drv::Virtio(drv) = &b.drv else { unreachable!() };
                assert_eq!(drv.can_start_calls.get(), if cq_blocked { 2 } else { 3 },
                    "blocked writers are checked at most once regardless of rotation and CQ state");
            }
        }
    }

}

mod nvme { pub type Nvme = crate::MockDriver; }
mod scsi { pub type VirtioScsi = crate::MockDriver; }
mod virtio { pub type VirtioBlk = crate::MockDriver; }

struct Kernel {
    ipc: sel4::IpcBuffer,
    requests: VecDeque<(u64, Vec<u64>, bool)>,
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

pub struct MockDriver {
    legacy_io: u32, queue: u16, provisioning: bool,
    commands: Vec<(u64, u32, u64, Vec<Seg>)>,
    completed: Vec<(u64, u32)>, fail_start: bool,
    can_start_calls: std::cell::Cell<usize>,
}
impl MockDriver {
    pub fn new(_: u32, cfg: &BlkdConfig) -> Self {
        Self { legacy_io: cfg.legacy_io, queue: if cfg.kind == blk::BLKD_VIRTIO_SCSI { 2 } else { 0 }, provisioning: false, commands: Vec::new(), completed: Vec::new(), fail_start: false, can_start_calls: std::cell::Cell::new(0) }
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
    fn can_start(&self) -> bool { self.can_start_calls.set(self.can_start_calls.get() + 1); true }
    fn start(&mut self, tag: u64, _: usize, op: u32, sector: u64, data: &[Seg]) -> Result<(), u32> {
        if self.fail_start { return Err(blk::STATUS_IOERR); }
        if tag != u64::MAX { self.commands.push((tag, op, sector, data.to_vec())); }
        self.provisioning |= tag == u64::MAX;
        Ok(())
    }
    fn kick(&mut self) { self.notify(); }
    fn reap(&mut self, done: &mut dyn FnMut(u64, u32)) {
        for (tag, status) in self.completed.drain(..) { done(tag, status); }
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

fn run(kind: u32, legacy: bool, label: u64, pending_io: bool, retry: bool, status: u32, flags: u64) -> [u64; 5] {
    let _lock = LOCK.lock().unwrap();
    let len = blk::CHANNEL_PAGES * 4096;
    // MAP_FIXED_NOREPLACE: never overwrite an unrelated mapping.
    assert_eq!(unsafe { mmap(channel() as usize, len, 3, 0x100022, -1, 0) }, channel() as usize);
    unsafe {
        (*channel()).capacity_sectors = 8;
        (*channel()).pool = blk::Pool { gpa: 0x8000000, paddr: 0x10000000, size: 4096 };
        (*channel()).reqs[0] = blk::Req { op: blk::OP_READ, nr_segs: 1, ..Default::default() };
        (*channel()).reqs[0].segs[0] = blk::Seg { gpa: 0x8000000, len: if flags == 0 { 512 } else { 4096 }, flags: blk::SEG_WRITE };
    }
    KERNEL.with_borrow_mut(|k| {
        k.ipc.0.fill(0);
        let mut add = vec![0; 11];
        add[2] = flags;
        for i in 0..8 { add[3 + i] = i as u64; }
        k.requests = [(blk::BLKD_ADD, add, pending_io), (label, vec![0; 3], pending_io)].into();
        k.replies.clear();
        k.retry = retry;
        k.status = status;
        k.kicks = 0;
    });
    // BlkdConfig consists entirely of integer fields.
    let mut config: BlkdConfig = unsafe { core::mem::zeroed() };
    config.bounce_size = blk::BOUNCE_SIZE as u64;
    config.features = blk::FEATURE_AES;
    config.kind = kind;
    config.legacy_io = if legacy { 0xc000 } else { 0 };
    let info = Box::leak(Box::new(Info { header: Header { id: 1, tsc_hz: 1_000_000_000 }, config }));
    let stopped = std::panic::catch_unwind(|| production::run(info)).unwrap_err();
    assert_eq!(unsafe { munmap(channel() as usize, len) }, 0);
    assert!(stopped.is::<Finished>(), "service failed before sending every reply");
    KERNEL.with_borrow(|k| {
        assert_eq!(k.replies.len(), 2);
        assert_eq!(k.replies[0][0], 0, "client must attach successfully");
        assert_eq!(k.replies[0][1], flags, "applied flags must survive nested IPC while submitting work");
        assert!(k.kicks > 0, "the clobbering driver path must run");
        k.replies[1]
    })
}

#[test]
fn disk_info_survives_pending_io() {
    for kind in [blk::BLKD_VIRTIO, blk::BLKD_VIRTIO_SCSI] {
        for legacy in [false, true] {
            assert_eq!(run(kind, legacy, blk::BLKD_INFO, true, false, 0, 0), [131072, 512, 0, 1, 0x301]);
        }
    }
}

#[test]
fn service_status_survives_pending_io() {
    for kind in [blk::BLKD_VIRTIO, blk::BLKD_VIRTIO_SCSI] {
        assert_eq!(run(kind, true, blk::BLKD_FLUSH, true, false, 0, 0)[0], 0);
        assert_eq!(run(kind, true, u64::MAX, true, false, 0, 0)[0], u64::MAX);
    }
}

#[test]
fn provisioning_status_survives_scsi_retry() {
    for status in [blk::STATUS_OK, blk::STATUS_IOERR] {
        assert_eq!(run(blk::BLKD_VIRTIO_SCSI, true, blk::BLKD_FLUSH, false, true, status, 0)[0], status as u64);
    }
}

#[test]
fn production_bounce_defer_completion_errors_and_reuse() {
    if !std::is_x86_feature_detected!("aes") { eprintln!("SKIP: no AES-NI"); return; }
    with_pools(2, |info| {
        for i in 0..2 {
            unsafe {
                let c = &mut *(blk::channel_va(i) as *mut Channel);
                c.reqs[0] = blk::Req { op: if i == 0 { blk::OP_WRITE } else { blk::OP_READ }, nr_segs: 1, ..Default::default() };
                c.reqs[0].segs[0] = blk::Seg { gpa: 0, len: if i == 0 { 14 * 256 * 1024 } else { 4096 }, flags: if i == 0 { 0 } else { blk::SEG_WRITE } };
                c.reqs[1] = if i == 0 { c.reqs[0] } else { blk::Req { op: blk::OP_FLUSH, ..Default::default() } };
                c.sq.head = 2;
            }
        }
        production::pipeline(info);
    });
}

#[test]
fn sub_block_segments_pack_into_one_aligned_4kn_write() { with_pools(1, production::split_writes); }

#[test]
fn deferred_writers_get_fifo_priority_while_reads_and_flushes_run() { with_pools(4, production::fair_writes); }

#[test]
fn withdrawn_waiters_do_not_block_other_writers() { with_pools(3, production::abandoned_waiter); }

#[test]
fn cq_backpressure_preserves_rank_but_allows_peer_writes() { with_pools(3, production::cq_blocked_waiter); }

#[test]
fn malformed_waiters_cannot_stall_peer_writes() {
    for distance in [blk::RING_SIZE as u32 + 1, u32::MAX] {
        with_pools(3, |info| production::malformed_waiter(info, distance));
    }
}

#[test]
fn parked_writers_wake_after_the_head_is_submitted_or_rejected() {
    for invalid in [false, true] { with_pools(3, |info| production::priority_change_wakes_parked_writers(info, invalid)); }
}

#[test]
fn writers_blocked_by_a_failed_allocation_are_checked_once_per_pass() { with_pools(3, production::blocked_writers_checked_once); }

#[test]
fn applied_encryption_flags_survive_legacy_driver_ipc() {
    if !std::is_x86_feature_detected!("aes") { return; }
    run(blk::BLKD_VIRTIO_SCSI, true, blk::BLKD_INFO, true, false, 0, blk::ENCRYPT);
}

fn with_pools(clients: usize, test: impl FnOnce(&'static Info)) {
    let _lock = LOCK.lock().unwrap();
    let mut mappings = Vec::new();
    for i in 0..clients {
        for (va, len) in [(blk::channel_va(i), blk::CHANNEL_PAGES * 4096), (blk::pool_va(i, 4 << 20), 4 << 20)] {
            assert_eq!(unsafe { mmap(va, len, 3, 0x100022, -1, 0) }, va);
            mappings.push((va, len));
        }
        unsafe {
            let c = &mut *(blk::channel_va(i) as *mut Channel);
            c.lba_start = if i == 0 { 16 } else { i as u64 * 16384 };
            c.capacity_sectors = 8192;
            c.pool = blk::Pool { gpa: 0, paddr: 0x10000000 + i as u64 * (4 << 20), size: 4 << 20 };
            core::ptr::write_bytes(blk::pool_va(i, 4 << 20) as *mut u8, 0x5a, 4 << 20);
        }
    }
    assert_eq!(unsafe { mmap(blk::BOUNCE_VA, blk::BOUNCE_SIZE, 3, 0x100022, -1, 0) }, blk::BOUNCE_VA);
    mappings.push((blk::BOUNCE_VA, blk::BOUNCE_SIZE));
    let mut config: BlkdConfig = unsafe { core::mem::zeroed() };
    config.features = blk::FEATURE_AES;
    config.pool_va = blk::POOL_VA as u64;
    config.bounce_va = blk::BOUNCE_VA as u64;
    config.bounce_paddr = 0x20000000;
    config.bounce_size = blk::BOUNCE_SIZE as u64;
    let info = Box::leak(Box::new(Info { header: Header { id: 1, tsc_hz: 1_000_000_000 }, config }));
    test(info);
    for (va, len) in mappings { assert_eq!(unsafe { munmap(va, len) }, 0); }
}

//! virtio-blk queue reset against a guest that lists chain heads at random,
//! including heads already in flight: when `drain` returns, blkd must have
//! completed every request it was given (it may still DMA into the
//! buffers of any other), and that no chain with a buffer outside the
//! guest's I/O pool ever reaches blkd.

use std::cell::RefCell;

use crate::Rng;
use crate::blk::Blk;
use crate::dev::Backend;
use crate::guest::GuestMem;
use crate::host::blk::{self as chan, Channel, Resp};
use crate::virtq::Queue;

thread_local! { pub static IRQ_EVENTS: RefCell<Vec<(usize, u32)>> = const { RefCell::new(Vec::new()) }; }

/// The fake blkd: the channel and the requests it took but has not
/// completed (ids).
struct Blkd {
    chan: *mut Channel,
    pending: Vec<u64>,
    rng: Rng,
    /// Chain heads with a buffer outside the I/O pool: the VMM must refuse
    /// them.
    bad: u64,
}

thread_local! {
    static BLKD: RefCell<Option<Blkd>> = const { RefCell::new(None) };
}

impl Blkd {
    /// Take every submitted request.
    fn take(&mut self) {
        unsafe {
            let c = &mut *self.chan;
            while c.sq.tail != c.sq.head {
                let id = c.reqs[c.sq.tail as usize % chan::RING_SIZE].id;
                assert!(self.bad & (1 << (id as u16)) == 0, "chain {} outside the I/O pool reached blkd", id as u16);
                self.pending.push(id);
                c.sq.tail = c.sq.tail.wrapping_add(1);
            }
        }
    }

    /// Complete one pending request, in any order.  The completion ring
    /// has room for every request the VMM may have in flight.
    fn complete_one(&mut self) -> bool {
        if self.pending.is_empty() { return false; }
        unsafe {
            if (*self.chan).cq.head.wrapping_sub((*self.chan).cq.tail) >= chan::RING_SIZE as u32 { return false; }
        }
        let i = self.rng.below(self.pending.len() as u64) as usize;
        let id = self.pending.swap_remove(i);
        unsafe {
            let c = &mut *self.chan;
            assert!(c.cq.head.wrapping_sub(c.cq.tail) < chan::RING_SIZE as u32, "completion ring overflows");
            c.resps[c.cq.head as usize % chan::RING_SIZE] = Resp { id, status: chan::STATUS_OK, reserved: 0 };
            c.cq.head = c.cq.head.wrapping_add(1);
        }
        true
    }
}

/// blkd runs while the VMM yields in `drain`.
pub fn blkd_run() {
    BLKD.with_borrow_mut(|b| {
        let b = b.as_mut().unwrap();
        b.take();
        assert!(b.complete_one(), "drain waits for requests blkd does not have");
    });
}

const NUM: u16 = 128;
const CHAINS: u16 = 64;
/// The I/O pool, above the guest's RAM.
const POOL: u64 = 0x4020_0000;
const DESC: u64 = POOL;
const AVAIL: u64 = POOL + 0x1000;
const USED: u64 = POOL + 0x2000;
const HDR: u64 = POOL + 0x3000;
const STATUS: u64 = POOL + 0x4000;

#[test]
fn unavailable_disk_has_zero_capacity_and_completes_io_without_a_backend() {
    for op in [chan::OP_READ, chan::OP_WRITE, chan::OP_FLUSH, chan::OP_GET_ID, chan::OP_DISCARD] {
        let mut ram = vec![0u64; 0x8000 / 8];
        let mem = GuestMem { base: ram.as_mut_ptr() as usize, gpa: POOL, size: 0x8000 };
        let mut disk = Blk::unavailable(mem.size);
        let mut config = [0u8; 32];
        disk.init_config(&mut config);
        assert_eq!(u64::from_le_bytes(config[..8].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(config[20..24].try_into().unwrap()), 512);
        assert_eq!(disk.device_id(), 2);
        assert_eq!(disk.num_queues(), 1);
        let mut queues = [Queue::default()];
        assert!(queues[0].setup(&mem, NUM as u32, disk.queue_max(0), DESC, AVAIL, USED));
        // A valid request header, optional data buffer, then a status byte.
        mem.write::<u64>(DESC, HDR);
        mem.write::<u32>(DESC + 8, 16);
        mem.write::<u16>(DESC + 12, crate::virtq::VIRTQ_DESC_F_NEXT);
        mem.write::<u16>(DESC + 14, if op == chan::OP_FLUSH { 2 } else { 1 });
        mem.write::<u64>(DESC + 16, POOL + 0x5000);
        mem.write::<u32>(DESC + 24, 512);
        mem.write::<u16>(DESC + 28, crate::virtq::VIRTQ_DESC_F_NEXT |
            if op == chan::OP_WRITE { 0 } else { crate::virtq::VIRTQ_DESC_F_WRITE });
        mem.write::<u16>(DESC + 30, 2);
        mem.write::<u64>(DESC + 32, STATUS);
        mem.write::<u32>(DESC + 40, 1);
        mem.write::<u16>(DESC + 44, crate::virtq::VIRTQ_DESC_F_WRITE);
        mem.write::<u32>(HDR, op);
        mem.write::<u8>(STATUS, 0xff);
        mem.write::<u64>(POOL + 0x5000, 0x12345678);
        mem.write::<u16>(AVAIL + 4, 0);
        mem.write::<u16>(AVAIL + 2, 1);
        assert!(disk.kick(&mem, &mut queues, 0));
        assert_eq!(queues[0].used_idx(), 1);
        assert_eq!(mem.read::<u8>(STATUS), 1, "operation {op} must fail with I/O error");
        assert_eq!(mem.read::<u64>(POOL + 0x5000), 0x12345678);
        assert!(!disk.pending());
        assert!(!disk.complete(&mem, &mut queues));
        // There is no fake blkd installed: any yield/channel access fails.
        disk.drain();
        disk.reset();
        assert!(!disk.pending());
    }
}

/// Returns the number of requests drained and of chains refused because a
/// buffer was outside the pool.
pub fn drain_check(rng: &mut Rng, iterations: u64) -> (u64, u64) {
    let (mut drained, mut refused) = (0, 0);
    for _ in 0..iterations {
        let mut ram = vec![0u64; 0x20000 / 8];
        let mem = GuestMem { base: ram.as_mut_ptr() as usize, gpa: POOL, size: 0x20000 };
        let header = POOL + 0x8000;
        let status_base = POOL + 0x1c000;
        let nr_queues = if rng.below(2) == 0 { 1 } else { 4 };
        // Some chains have their status byte outside the pool: in guest
        // RAM below it, or just past its end.
        let bad: u64 = rng.next() & rng.next();
        // Chain h: a FLUSH header (descriptor h), then the status byte
        // (descriptor h + CHAINS).
        for h in 0..CHAINS as u64 {
            let (d, s) = (DESC + 16 * h, DESC + 16 * (h + CHAINS as u64));
            mem.write::<u64>(d, header + 1024 * h);
            mem.write::<u32>(d + 8, if h % 2 == 0 { 16 } else { 528 });
            mem.write::<u16>(d + 12, crate::virtq::VIRTQ_DESC_F_NEXT);
            mem.write::<u16>(d + 14, h as u16 + CHAINS);
            mem.write::<u32>(header + 1024 * h, if h % 2 == 0 { chan::OP_FLUSH } else { chan::OP_WRITE });
            let status = match (bad >> h & 1, h % 2) {
                (0, _) => status_base + h,
                (_, 0) => POOL - 0x1000 + h,
                _ => POOL + mem.size + h,
            };
            mem.write::<u64>(s, status);
            mem.write::<u32>(s + 8, 1);
            mem.write::<u16>(s + 12, crate::virtq::VIRTQ_DESC_F_WRITE);
        }
        let mut channel: Box<Channel> = unsafe { Box::new_zeroed().assume_init() };
        channel.capacity_sectors = 1 << 20;
        channel.block_size = 512;
        let chan_ptr: *mut Channel = &mut *channel;
        let seed = rng.next() | 1;
        BLKD.with_borrow_mut(|b| *b = Some(Blkd { chan: chan_ptr, pending: Vec::new(), rng: Rng(seed), bad }));
        let mut blk = Blk::new(chan_ptr as usize, crate::sel4::cap::Notification, 0x8000);
        blk.features_accepted(if nr_queues == 4 { 1 << 12 } else { 0 });
        let mut queues = core::array::from_fn::<_, 4, _>(|_| Queue::default());
        for (q, queue) in queues.iter_mut().enumerate().take(nr_queues) {
            assert!(queue.setup(&mem, NUM as u32, NUM as u32, DESC, AVAIL + q as u64 * 0x200, USED + q as u64 * 0x500));
        }
        let mut avail_idx = [0u16; 4];
        for _ in 0..rng.below(8) + 1 {
            // The guest offers some chains: mostly fresh ones, sometimes
            // one that is still in flight.
            let q = rng.below(nr_queues as u64) as usize;
            for _ in 0..rng.below(CHAINS as u64) {
                let h = rng.below(CHAINS as u64) as u16;
                refused += bad >> h & 1;
                mem.write::<u16>(AVAIL + q as u64 * 0x200 + 4 + 2 * (avail_idx[q] % NUM) as u64, h);
                avail_idx[q] = avail_idx[q].wrapping_add(1);
            }
            mem.write::<u16>(AVAIL + q as u64 * 0x200 + 2, avail_idx[q]);
            blk.kick(&mem, &mut queues, q);
            // blkd completes some of what it has.
            BLKD.with_borrow_mut(|b| {
                let b = b.as_mut().unwrap();
                b.take();
                for _ in 0..rng.below(b.pending.len() as u64 + 1) {
                    b.complete_one();
                }
            });
            if rng.below(2) == 0 {
                blk.complete(&mem, &mut queues);
            }
        }
        blk.drain();
        BLKD.with_borrow_mut(|b| {
            let b = b.as_mut().unwrap();
            b.take();
            assert!(b.pending.is_empty(), "drain returned with {} requests in blkd", b.pending.len());
        });
        drained += channel.cq.tail as u64;
        blk.reset();
        for queue in &mut queues { queue.reset(); }
        BLKD.with_borrow_mut(|b| *b = None);
        drop(ram);
    }
    (drained, refused)
}


fn offer(mem: &GuestMem, queue: &mut Queue, q: usize, op: u32) {
    let base = POOL + q as u64 * 0x8000;
    assert!(queue.setup(mem, NUM as u32, NUM as u32, base, base + 0x1000, base + 0x2000));
    for (slot, address, len, flags, next) in [
        (0, base + 0x3000, 16, 1, if op == chan::OP_FLUSH { 2 } else { 1 }),
        (1, base + 0x5000, 512, 1 | if op == chan::OP_READ { 2 } else { 0 }, 2),
        (2, base + 0x4000, 1, 2, 0),
    ] {
        let d = base + slot * 16;
        mem.write::<u64>(d, address);
        mem.write::<u32>(d + 8, len);
        mem.write::<u16>(d + 12, flags);
        mem.write::<u16>(d + 14, next);
    }
    mem.write::<u32>(base + 0x3000, op);
    mem.write::<u64>(base + 0x3008, 0);
    mem.write::<u8>(base + 0x4000, 0xff);
    mem.write::<u16>(base + 0x1004, 0);
    mem.write::<u16>(base + 0x1002, 1);
}

fn reply(channel: &mut Channel, id: u64) {
    channel.resps[channel.cq.head as usize % chan::RING_SIZE] = Resp { id, status: chan::STATUS_OK, reserved: 0 };
    channel.cq.head = channel.cq.head.wrapping_add(1);
}

#[test]
fn same_chain_head_on_two_queues_completes_on_its_own_queue() {
    let mut ram = vec![0u64; 0x20000 / 8];
    let mem = GuestMem { base: ram.as_mut_ptr() as usize, gpa: POOL, size: 0x20000 };
    let mut channel: Box<Channel> = unsafe { Box::new_zeroed().assume_init() };
    channel.capacity_sectors = 131072;
    channel.block_size = 512;
    let mut disk = Blk::new(&mut *channel as *mut Channel as usize, crate::sel4::cap::Notification, mem.size);
    disk.features_accepted(1 << 12);
    let mut queues = core::array::from_fn::<_, 4, _>(|_| Queue::default());
    offer(&mem, &mut queues[0], 0, chan::OP_READ);
    offer(&mem, &mut queues[1], 1, chan::OP_READ);
    disk.kick(&mem, &mut queues, 0);
    disk.kick(&mem, &mut queues, 1);
    assert_eq!(channel.sq.head, 2, "both queues must submit their own head 0");
    let first = channel.reqs[0].id;
    let second = channel.reqs[1].id;
    assert_ne!(first, second);
    reply(&mut channel, second);
    reply(&mut channel, first);
    disk.complete(&mem, &mut queues);
    for (q, queue) in queues.iter().enumerate().take(2) {
        assert_eq!(queue.used_idx(), 1, "completion belongs to queue {q}");
        assert_eq!(mem.read::<u8>(POOL + q as u64 * 0x8000 + 0x4000), 0);
    }
    assert!(!disk.pending());
}

#[test]
fn flush_fences_other_queues_until_writes_and_flush_complete() {
    let mut ram = vec![0u64; 0x20000 / 8];
    let mem = GuestMem { base: ram.as_mut_ptr() as usize, gpa: POOL, size: 0x20000 };
    let mut channel: Box<Channel> = unsafe { Box::new_zeroed().assume_init() };
    channel.capacity_sectors = 131072;
    channel.block_size = 512;
    let mut disk = Blk::new(&mut *channel as *mut Channel as usize, crate::sel4::cap::Notification, mem.size);
    disk.features_accepted(1 << 12);
    let mut queues = core::array::from_fn::<_, 4, _>(|_| Queue::default());
    offer(&mem, &mut queues[0], 0, chan::OP_WRITE);
    offer(&mem, &mut queues[1], 1, chan::OP_FLUSH);
    offer(&mem, &mut queues[2], 2, chan::OP_WRITE);
    disk.kick(&mem, &mut queues, 0);
    disk.kick(&mem, &mut queues, 1);
    disk.kick(&mem, &mut queues, 2);
    assert_eq!(channel.sq.head, 1, "flush waits for the accepted write");
    let write = channel.reqs[0].id;
    reply(&mut channel, write);
    disk.complete(&mem, &mut queues);
    disk.kick(&mem, &mut queues, 1);
    assert_eq!(channel.sq.head, 2);
    assert_eq!(channel.reqs[1].op, chan::OP_FLUSH);
    disk.kick(&mem, &mut queues, 2);
    assert_eq!(channel.sq.head, 2, "later writes wait for flush completion");
    let flush = channel.reqs[1].id;
    reply(&mut channel, flush);
    disk.complete(&mem, &mut queues);
    disk.kick(&mem, &mut queues, 2);
    assert_eq!(channel.sq.head, 3);
    assert_eq!(channel.reqs[2].op, chan::OP_WRITE);
    let later = channel.reqs[2].id;
    reply(&mut channel, later);
    disk.complete(&mem, &mut queues);
    for q in queues.iter().take(3) { assert_eq!(q.used_idx(), 1); }
}

#[test]
fn resetting_one_queue_returns_other_queues_and_fences_old_completions() {
    let mut ram = vec![0u64; 0x20000 / 8];
    let mem = GuestMem { base: ram.as_mut_ptr() as usize, gpa: POOL, size: 0x20000 };
    let mut channel: Box<Channel> = unsafe { Box::new_zeroed().assume_init() };
    channel.capacity_sectors = 131072;
    channel.block_size = 512;
    let mut disk = Blk::new(&mut *channel as *mut Channel as usize, crate::sel4::cap::Notification, mem.size);
    disk.features_accepted(1 << 12);
    let mut queues = core::array::from_fn::<_, 4, _>(|_| Queue::default());
    offer(&mem, &mut queues[0], 0, chan::OP_READ);
    offer(&mem, &mut queues[1], 1, chan::OP_READ);
    disk.kick(&mem, &mut queues, 0);
    disk.kick(&mem, &mut queues, 1);
    let old = channel.reqs[0].id;
    let other = channel.reqs[1].id;
    reply(&mut channel, other);
    reply(&mut channel, old);
    assert_eq!(disk.drain_queue(&mem, &mut queues, 0), 1 << 1);
    assert_eq!(queues[0].used_idx(), 0);
    assert_eq!(queues[1].used_idx(), 1);
    offer(&mem, &mut queues[0], 0, chan::OP_READ);
    disk.kick(&mem, &mut queues, 0);
    let fresh = channel.reqs[2].id;
    assert_ne!(fresh, old);
    reply(&mut channel, old);
    disk.complete(&mem, &mut queues);
    assert_eq!(queues[0].used_idx(), 0, "stale completion cannot retire the new head");
    reply(&mut channel, fresh);
    disk.complete(&mem, &mut queues);
    assert_eq!(queues[0].used_idx(), 1);
}


struct DeviceFixture {
    _ram: Vec<u64>,
    _page: Box<[u64; 512]>,
    mem: GuestMem,
    channel: Box<Channel>,
    device: crate::dev::Device<Blk>,
    vcpus: crate::guest::Vcpus,
}

impl DeviceFixture {
    fn new(ops: &[u32]) -> Self {
        IRQ_EVENTS.with_borrow_mut(Vec::clear);
        let mut ram = vec![0u64; 0x20000 / 8];
        let mem = GuestMem { base: ram.as_mut_ptr() as usize, gpa: POOL, size: 0x20000 };
        let mut channel: Box<Channel> = unsafe { Box::new_zeroed().assume_init() };
        channel.capacity_sectors = 131072;
        channel.block_size = 512;
        let backend = Blk::new(&mut *channel as *mut Channel as usize, crate::sel4::cap::Notification, mem.size);
        let mut page = Box::new([0u64; 512]);
        let regs = page.as_mut_ptr().cast::<l4h_abi::VirtioRegs>();
        let mut device = crate::dev::Device::new(page.as_mut_ptr() as usize, 20, backend);
        let vcpus = crate::guest::Vcpus { n: 4 };
        unsafe { (*regs).driver_features = (*regs).device_features; (*regs).status = 8; }
        assert_eq!(device.op(&mem, &vcpus, l4h_abi::VIRTIO_OP_STATUS, 0, 0), 0);
        for (q, op) in ops.iter().enumerate() {
            offer(&mem, &mut Queue::default(), q, *op);
            unsafe {
                (*regs).queues[q] = l4h_abi::VirtqRegs {
                    num_max: NUM as u32, num: NUM as u32, ready: 1, reserved: 0,
                    desc: POOL + q as u64 * 0x8000,
                    driver: POOL + q as u64 * 0x8000 + 0x1000,
                    device: POOL + q as u64 * 0x8000 + 0x2000,
                };
                (*regs).queue_irq_vcpu[q] = q as u32;
            }
            assert_eq!(device.op(&mem, &vcpus, l4h_abi::VIRTIO_OP_QUEUE, q as u64, 0), 0);
            assert_eq!(device.op(&mem, &vcpus, l4h_abi::VIRTIO_OP_IRQ_VCPU, q as u64 + 1, 0), 0);
        }
        unsafe { (*regs).status = 12; }
        device.op(&mem, &vcpus, l4h_abi::VIRTIO_OP_STATUS, 0, 0);
        Self { _ram: ram, _page: page, mem, channel, device, vcpus }
    }

    fn complete(&mut self, index: usize) {
        let id = self.channel.reqs[index].id;
        reply(&mut self.channel, id);
        self.device.complete(&self.mem, &self.vcpus);
    }
}

#[test]
fn device_notifies_only_the_completed_queue_on_its_selected_cpu() {
    let mut f = DeviceFixture::new(&[chan::OP_READ, chan::OP_READ]);
    assert_eq!(f.channel.sq.head, 2);
    f.complete(1);
    IRQ_EVENTS.with_borrow(|events| assert_eq!(events.as_slice(), &[(1, 97)]));
    f.complete(0);
    IRQ_EVENTS.with_borrow(|events| assert_eq!(events.as_slice(), &[(1, 97), (0, 96)]));
}

#[test]
fn device_resumes_unpopped_queues_after_flush_without_another_guest_kick() {
    let mut f = DeviceFixture::new(&[chan::OP_WRITE, chan::OP_FLUSH, chan::OP_WRITE]);
    assert_eq!(f.channel.sq.head, 1);
    f.complete(0);
    assert_eq!(f.channel.sq.head, 2);
    assert_eq!(f.channel.reqs[1].op, chan::OP_FLUSH);
    f.complete(1);
    assert_eq!(f.channel.sq.head, 3);
    assert_eq!(f.channel.reqs[2].op, chan::OP_WRITE);
    f.complete(2);
    assert!(!f.device.backend.pending());
    for q in 0..3 { assert_eq!(f.mem.read::<u16>(POOL + q * 0x8000 + 0x2002), 1); }
    IRQ_EVENTS.with_borrow(|events| assert_eq!(events.as_slice(), &[(0, 96), (1, 97), (2, 98)]));
}

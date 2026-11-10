//! virtio-blk device backed by a blkd channel.  Data buffers are passed
//! to blkd by guest-physical address (they lie in the guest's I/O pool);
//! nothing is copied here.

use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{Ordering, fence};

use l4h_rt::host::{self, blk::{self, Channel}};
use l4h_rt::host::fixed::ArrayVec;
use l4h_rt::host::spsc::{Consumer, Producer};
use l4h_rt::sel4;

use crate::dev::{Backend, VIRTIO_RING_F_INDIRECT_DESC};
use crate::guest::GuestMem;
use crate::virtq::{Buf, Queue};

const VIRTIO_ID_BLOCK: u32 = 2;
const VIRTIO_BLK_F_SIZE_MAX: u64 = 1 << 1;
const VIRTIO_BLK_F_SEG_MAX: u64 = 1 << 2;
const VIRTIO_BLK_F_RO: u64 = 1 << 5;
const VIRTIO_BLK_F_BLK_SIZE: u64 = 1 << 6;
const VIRTIO_BLK_F_FLUSH: u64 = 1 << 9;
const VIRTIO_BLK_F_MQ: u64 = 1 << 12;
pub const MAX_QUEUES: usize = l4h_abi::VIRTIO_QUEUE_IRQS;

const VIRTIO_BLK_S_OK: u8 = 0;
const VIRTIO_BLK_S_IOERR: u8 = 1;
const VIRTIO_BLK_S_UNSUPP: u8 = 2;

const QUEUE_SIZE: u32 = blk::RING_SIZE as u32;
/// Data segments of a request at most, counting what shares the header's
/// and the status byte's buffers.  The guest is offered this or what the
/// disk's device takes, if that is fewer (Blk::seg_max), and held to it.
const SEG_MAX: u32 = blk::SEG_MAX as u32;
/// The largest segment the guest's DMA layer maps at once (swiotlb).
const SEG_SIZE_LIMIT: u32 = blk::SEG_SIZE_MAX;
/// How long a reset waits for blkd to complete the requests it has
/// (DESIGN.md §9.2).  One that root quarantined never does: it is
/// suspended.
const DRAIN_SECS: u64 = 5;

/// Largest segment for a guest whose I/O pool has `pool` bytes.  Every
/// request bounces through the pool, so one must never need more than a
/// part of it: a request that cannot fit even in an empty pool would be
/// retried forever.  seg_max * size_max is at most a quarter of the pool.
pub fn size_max(pool: u64) -> u32 {
    let per_seg = (pool / 4 / SEG_MAX as u64).min(SEG_SIZE_LIMIT as u64) as u32;
    (per_seg & !4095).max(4096)
}

#[derive(Clone, Copy)]
struct Inflight {
    status_gpa: u64,
    written: u32,
}

pub struct Blk {
    chan: *mut Channel,
    /// Our indices of the channel's rings: blkd can write over the
    /// channel's copies.
    sq: Producer,
    cq: Consumer,
    kick: Option<sel4::cap::Notification>,
    capacity: u64,
    read_only: bool,
    /// Offer no flush: the guest treats the disk as write-through
    /// (l4h_abi::BLK_VOLATILE).
    volatile: bool,
    /// Logical block size of the disk: the guest aligns requests to it.
    block_size: u32,
    /// Largest data segment (see size_max).
    size_max: u32,
    /// Data segments of a request: SEG_MAX, or fewer if blkd says so.
    seg_max: u32,
    /// Requests submitted to blkd, by queue and chain head.
    inflight: [[Option<Inflight>; QUEUE_SIZE as usize]; MAX_QUEUES],
    nr_queues: usize,
    kick_pending: bool,
    /// Requests of this generation blkd has not completed yet.
    outstanding: usize,
    /// Bumped on reset, so completions of earlier requests are dropped.
    generation: u32,
    /// A popped chain per queue that waits for channel space or a flush.
    stalled: [Option<u16>; MAX_QUEUES],
    /// A flush waits for earlier requests, then excludes later requests.
    fence: Option<usize>,
    flush_inflight: bool,
    deferred: u64,
    /// Counter ticks per second (host::ticks).
    tsc_hz: u64,
}

impl Blk {
    /// A failed boot attachment. It advertises zero sectors and completes
    /// every request locally with an I/O error, without touching hardware.
    pub fn unavailable(pool: u64) -> Self {
        Blk {
            chan: core::ptr::null_mut(), sq: Producer::new(blk::RING_SIZE), cq: Consumer::new(blk::RING_SIZE),
            kick: None, capacity: 0, read_only: true, volatile: false,
            block_size: 512, size_max: size_max(pool), seg_max: SEG_MAX,
            inflight: [[None; QUEUE_SIZE as usize]; MAX_QUEUES], nr_queues: 1, kick_pending: false,
            outstanding: 0, generation: 0, stalled: [None; MAX_QUEUES],
            fence: None, flush_inflight: false, deferred: 0, tsc_hz: 0,
        }
    }

    /// The channel must be ready.  `pool` is the size of the guest's I/O
    /// pool, `tsc_hz` the rate of host::ticks.
    pub fn new(chan_va: usize, kick: sel4::cap::Notification, pool: u64, tsc_hz: u64) -> Self {
        let chan = chan_va as *mut Channel;
        let (capacity, read_only, volatile, block_size, seg_max) = unsafe {
            fence(Ordering::Acquire);
            (
                addr_of!((*chan).capacity_sectors).read_volatile(),
                addr_of!((*chan).read_only).read_volatile() != 0,
                addr_of!((*chan).volatile).read_volatile() != 0,
                addr_of!((*chan).block_size).read_volatile().max(512),
                addr_of!((*chan).seg_max).read_volatile(),
            )
        };
        Blk {
            chan,
            // A fresh channel: both rings start empty.
            sq: Producer::new(blk::RING_SIZE),
            cq: Consumer::new(blk::RING_SIZE),
            kick: Some(kick),
            capacity,
            read_only,
            volatile,
            block_size,
            size_max: size_max(pool).max(block_size),
            // blkd's word, read once: never more than SEG_MAX.
            seg_max: if seg_max == 0 { SEG_MAX } else { seg_max.min(SEG_MAX) },
            inflight: [[None; QUEUE_SIZE as usize]; MAX_QUEUES],
            nr_queues: MAX_QUEUES,
            kick_pending: false,
            outstanding: 0,
            generation: 0,
            stalled: [None; MAX_QUEUES], fence: None, flush_inflight: false, deferred: 0, tsc_hz,
        }
    }

    /// Full, or blkd broke the tail.
    fn sq_full(&self) -> bool {
        unsafe { self.sq.free(&(*self.chan).sq) == 0 }
    }

    /// The oldest response blkd has published, taken off the ring.
    fn next_resp(&mut self) -> Option<blk::Resp> {
        unsafe {
            if self.cq.ready(&(*self.chan).cq) == 0 { return None; }
            let resp = addr_of!((*self.chan).resps[self.cq.slot()]).read_volatile();
            self.cq.pop(&(*self.chan).cq);
            Some(resp)
        }
    }

    /// Responses were taken off the completion ring.  blkd takes a request
    /// only while its response has room there, and nothing else tells it
    /// when there is room again: with requests waiting in the submission
    /// ring, kick it (`notify_submissions`).
    fn made_room(&mut self) {
        if unsafe { self.sq.used(&(*self.chan).sq) != 0 } {
            self.kick_pending = true;
        }
    }

    /// Complete a chain locally with `status`.
    fn finish(mem: &GuestMem, q: &mut Queue, head: u16, status_gpa: u64, status: u8, written: u32) {
        mem.write::<u8>(status_gpa, status);
        q.push_deferred(mem, head, written);
    }

    /// The response `id` of this generation arrived: the request it
    /// identifies, if it was in flight.
    fn retire(&mut self, id: u64) -> Option<(usize, u16, Inflight)> {
        if (id >> 32) as u32 != self.generation { return None; }
        let q = ((id >> 16) & 0xffff) as usize;
        let h = id as u16;
        let inf = self.inflight.get_mut(q)?.get_mut(h as usize)?.take()?;
        self.outstanding -= 1;
        if self.flush_inflight && self.fence == Some(q) {
            self.flush_inflight = false;
            self.fence = None;
        }
        Some((q, h, inf))
    }

    /// Handle one chain.  Returns false if it must wait for channel space.
    fn submit(&mut self, mem: &GuestMem, q: &mut Queue, qi: usize, head: u16) -> bool {
        // The driver offered a chain blkd still owns.  Requests are known
        // by their head, so drop this one: the head returns to the driver
        // once, when the first request completes.  A correct driver never
        // does this.
        if self.inflight[qi].get(head as usize).is_some_and(|i| i.is_some()) {
            return true;
        }
        let mut bufs = ArrayVec::<Buf, { QUEUE_SIZE as usize }>::new();
        let ok = q.chain(mem, head, &mut bufs).is_ok();
        self.submit_bufs(mem, q, qi, head, ok, &bufs)
    }

    fn submit_bufs(&mut self, mem: &GuestMem, q: &mut Queue, qi: usize, head: u16, ok: bool, bufs: &[Buf]) -> bool {
        // Header first (16 bytes, readable), status byte last (writable).
        let last = bufs.last();
        let valid = ok
            && bufs.len() >= 2
            && !bufs[0].write
            && bufs[0].len >= 16
            && last.is_some_and(|b| b.write && b.len >= 1);
        if !valid {
            // Malformed: if there is a writable last byte, report an error
            // there; otherwise just return the chain.
            match last {
                Some(b) if ok && b.write && b.len >= 1 => {
                    Self::finish(mem, q, head, b.gpa + b.len as u64 - 1, VIRTIO_BLK_S_IOERR, 1)
                }
                _ => q.push_deferred(mem, head, 0),
            }
            return true;
        }
        let st = last.unwrap();
        let status_gpa = st.gpa + st.len as u64 - 1;
        if self.chan.is_null() {
            Self::finish(mem, q, head, status_gpa, VIRTIO_BLK_S_IOERR, 1);
            return true;
        }
        let ty = mem.read::<u32>(bufs[0].gpa);
        let sector = mem.read::<u64>(bufs[0].gpa + 8);

        let mut req = blk::Req { id: 0, op: ty, nr_segs: 0, sector, segs: Default::default() };
        let mut data_len: u64 = 0;
        // Bytes the device writes, the status byte included (u64: a
        // hostile chain can describe more than 4 GiB).
        let mut written: u64 = 1;
        // The guest is held to the seg_max and size_max it was offered: a
        // request is then no more than blkd takes from any client
        // (blk::MAX_REQUEST_BYTES), nor than the pool can bounce.
        let (seg_max, size_max) = (self.seg_max, self.size_max);
        let mut seg = |gpa: u64, len: u32, write: bool, req: &mut blk::Req| -> bool {
            if len == 0 {
                return true;
            }
            if req.nr_segs >= seg_max || len > size_max {
                return false;
            }
            req.segs[req.nr_segs as usize] = blk::Seg { gpa, len, flags: if write { blk::SEG_WRITE } else { 0 } };
            req.nr_segs += 1;
            data_len += len as u64;
            if write {
                written += len as u64;
            }
            true
        };
        let mut fits = true;
        if bufs[0].len > 16 {
            fits &= seg(bufs[0].gpa + 16, bufs[0].len - 16, false, &mut req);
        }
        for b in &bufs[1..bufs.len() - 1] {
            fits &= seg(b.gpa, b.len, b.write, &mut req);
        }
        if st.len > 1 {
            fits &= seg(st.gpa, st.len - 1, true, &mut req);
        }

        let status = match ty {
            blk::OP_READ | blk::OP_WRITE => {
                let dir_ok = req.segs[..req.nr_segs as usize]
                    .iter()
                    .all(|s| (s.flags & blk::SEG_WRITE != 0) == (ty == blk::OP_READ));
                let sectors = data_len / 512;
                if !fits || !dir_ok || data_len % 512 != 0 {
                    Some(VIRTIO_BLK_S_IOERR)
                } else if sector.checked_add(sectors).is_none_or(|end| end > self.capacity) {
                    Some(VIRTIO_BLK_S_IOERR)
                } else if ty == blk::OP_WRITE && self.read_only {
                    Some(VIRTIO_BLK_S_IOERR)
                } else {
                    None
                }
            }
            blk::OP_FLUSH => if req.nr_segs == 0 { None } else { Some(VIRTIO_BLK_S_IOERR) },
            // Everything else (GET_ID, DISCARD, WRITE_ZEROES, ...): blkd
            // takes reads, writes and flushes only.
            _ => Some(VIRTIO_BLK_S_UNSUPP),
        };
        if let Some(s) = status {
            Self::finish(mem, q, head, status_gpa, s, 1);
            return true;
        }
        if ty == blk::OP_FLUSH {
            self.fence = Some(qi);
            if self.outstanding != 0 { return false; }
        }
        if self.sq_full() { return false; }
        req.id = ((self.generation as u64) << 32) | ((qi as u64) << 16) | head as u64;
        let written = u32::try_from(written).unwrap_or(u32::MAX);
        self.inflight[qi][head as usize] = Some(Inflight { status_gpa, written });
        if ty == blk::OP_FLUSH { self.flush_inflight = true; }
        self.outstanding += 1;
        unsafe {
            addr_of_mut!((*self.chan).reqs[self.sq.slot()]).write_volatile(req);
            self.sq.push(&(*self.chan).sq);
        }
        true
    }

    /// Pass each response to `f` until blkd has none outstanding: false
    /// if that takes more than DRAIN_SECS, or blkd gives more responses
    /// than it was given requests.  The time is checked whether or not
    /// there is a response, so a blkd that keeps publishing them cannot
    /// hold the VMM here.
    fn wait_outstanding(&mut self, mut f: impl FnMut(&mut Self, blk::Resp)) -> bool {
        if self.outstanding == 0 { return true; }
        // An unknown rate is taken as 1 GHz: the wait stays finite.
        let hz = if self.tsc_hz == 0 { 1_000_000_000 } else { self.tsc_hz };
        let end = host::ticks::now().saturating_add(DRAIN_SECS.saturating_mul(hz));
        // blkd owes one response for each request.  A ring's worth of
        // others is let through, as many as `complete` takes in a turn.
        let mut budget = self.outstanding.saturating_add(blk::RING_SIZE);
        let mut taken = false;
        while self.outstanding != 0 {
            if host::ticks::now() > end || budget == 0 {
                return false;
            }
            let Some(resp) = self.next_resp() else {
                if core::mem::take(&mut taken) {
                    self.made_room();
                    self.notify_submissions();
                }
                // blkd runs at a higher priority, on its own core or as
                // soon as we yield.
                sel4::r#yield();
                continue;
            };
            (taken, budget) = (true, budget - 1);
            f(self, resp);
        }
        true
    }

    fn response(&mut self, mem: &GuestMem, queues: &mut [Queue], resp: blk::Resp, drop_queue: Option<usize>) -> u64 {
        let Some((q, head, inf)) = self.retire(resp.id) else { return 0; };
        if drop_queue == Some(q) || !queues[q].ready { return 0; }
        let status = match resp.status {
            blk::STATUS_OK => VIRTIO_BLK_S_OK,
            blk::STATUS_UNSUPP => VIRTIO_BLK_S_UNSUPP,
            _ => VIRTIO_BLK_S_IOERR,
        };
        let written = if status == VIRTIO_BLK_S_OK { inf.written } else { 1 };
        Self::finish(mem, &mut queues[q], head, inf.status_gpa, status, written);
        1 << q
    }
}

impl Backend for Blk {
    fn device_id(&self) -> u32 {
        VIRTIO_ID_BLOCK
    }

    fn features(&self) -> u64 {
        let mut f = VIRTIO_BLK_F_SIZE_MAX | VIRTIO_BLK_F_SEG_MAX | VIRTIO_BLK_F_BLK_SIZE | VIRTIO_RING_F_INDIRECT_DESC;
        if !self.volatile { f |= VIRTIO_BLK_F_FLUSH; }
        if self.read_only { f |= VIRTIO_BLK_F_RO; }
        if !self.chan.is_null() { f |= VIRTIO_BLK_F_MQ; }
        f
    }

    fn num_queues(&self) -> usize { self.nr_queues }

    fn queue_irqs(&self) -> bool { !self.chan.is_null() }

    fn features_accepted(&mut self, features: u64) {
        self.nr_queues = if features & VIRTIO_BLK_F_MQ != 0 { MAX_QUEUES } else { 1 };
    }

    fn queue_max(&self, _q: usize) -> u32 {
        QUEUE_SIZE
    }

    fn init_config(&self, config: &mut [u8]) {
        config[0..8].copy_from_slice(&self.capacity.to_le_bytes());
        config[8..12].copy_from_slice(&self.size_max.to_le_bytes());
        config[12..16].copy_from_slice(&self.seg_max.to_le_bytes());

        config[20..24].copy_from_slice(&self.block_size.to_le_bytes());
        if !self.chan.is_null() { config[34..36].copy_from_slice(&(MAX_QUEUES as u16).to_le_bytes()); }
    }

    fn kick(&mut self, mem: &GuestMem, queues: &mut [Queue], q: usize) -> bool {
        let bit = 1 << q;
        if !queues[q].ready { self.deferred &= !bit; return false; }
        if self.flush_inflight || self.fence.is_some_and(|owner| owner != q) {
            self.deferred |= bit;
            return false;
        }
        self.deferred &= !bit;
        let queue = &mut queues[q];
        let mut returned = false;
        let mut submitted = false;
        loop {
            let head = match self.stalled[q].take() {
                Some(h) => h,
                None => match queue.pop(mem) {
                    Some(h) => h,
                    None => break,
                },
            };
            let used_before = queue_used_count(queue);
            if !self.submit(mem, queue, q, head) {
                self.stalled[q] = Some(head);
                break;
            }
            if queue_used_count(queue) != used_before {
                returned = true;
            } else {
                submitted = true;
            }
            if self.fence.is_some() { self.deferred |= bit; break; }
        }
        if submitted {
            self.kick_pending = true;
        }
        queue.publish_used(mem);
        returned
    }

    fn notify_submissions(&mut self) {
        if core::mem::take(&mut self.kick_pending) {
            self.kick.as_ref().expect("live block backend").signal();
        }
    }

    fn complete(&mut self, mem: &GuestMem, queues: &mut [Queue]) -> bool {
        if self.chan.is_null() { return false; }
        let mut returned = 0;
        let mut taken = false;
        // At most a ring's worth: what blkd publishes meanwhile is pending.
        for _ in 0..blk::RING_SIZE {
            let Some(resp) = self.next_resp() else { break };
            taken = true;
            returned |= self.response(mem, queues, resp, None);
        }
        if taken { self.made_room(); }
        for (q, queue) in queues.iter_mut().enumerate().take(self.nr_queues) {
            if returned & (1 << q) != 0 { queue.publish_used(mem); }
        }
        returned != 0
    }

    fn pending(&self) -> bool {
        !self.chan.is_null() && (self.deferred != 0 || self.stalled.iter().any(Option::is_some)
            || unsafe { self.cq.ready(&(*self.chan).cq) != 0 })
    }

    fn retry_queues(&self) -> u64 {
        self.stalled.iter().enumerate().fold(self.deferred, |mask, (q, head)| {
            if head.is_some() { mask | (1 << q) } else { mask }
        })
    }

    fn drain(&mut self) {
        self.notify_submissions();
        self.stalled = [None; MAX_QUEUES];
        self.fence = None;
        self.flush_inflight = false;
        self.deferred = 0;
        if !self.wait_outstanding(|b, resp| { b.retire(resp.id); }) {
            // No reset reply: blkd or its device may still DMA into these
            // buffers. The VMM's fault stops the guest (vmmgr::end_guest);
            // teardown cuts off DMA before root reuses its I/O pool.
            panic!("block reset could not drain DMA; stopping guest");
        }
        // Requests completed from now on belong to the next generation.
        self.generation = self.generation.wrapping_add(1);
    }

    fn drain_queue(&mut self, mem: &GuestMem, queues: &mut [Queue], q: usize) -> u64 {
        self.notify_submissions();
        self.stalled[q] = None;
        self.deferred &= !(1 << q);
        let mut completed = 0;
        if !self.wait_outstanding(|b, resp| completed |= b.response(mem, queues, resp, Some(q))) {
            // Completing another queue with an error would let its driver
            // reuse buffers too, while the old device request still owns
            // them. Stop the guest as for a whole-device drain failure.
            panic!("block queue reset could not drain DMA; stopping guest");
        }
        if self.fence == Some(q) { self.fence = None; self.flush_inflight = false; }
        for (q, queue) in queues.iter_mut().enumerate().take(self.nr_queues) {
            if completed & (1 << q) != 0 { queue.publish_used(mem); }
        }
        self.generation = self.generation.wrapping_add(1);
        completed
    }

    fn reset(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.inflight = [[None; QUEUE_SIZE as usize]; MAX_QUEUES];
        self.outstanding = 0;
        self.nr_queues = if self.chan.is_null() { 1 } else { MAX_QUEUES };
        self.stalled = [None; MAX_QUEUES];
        self.fence = None;
        self.flush_inflight = false;
        self.deferred = 0;
    }
}

fn queue_used_count(q: &Queue) -> u16 {
    q.used_idx()
}

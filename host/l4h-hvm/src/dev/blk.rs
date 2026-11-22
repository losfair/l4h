//! virtio-blk over a blkd channel for an HVM guest (DESIGN.md §5.11).  As
//! l4h-vmm's (l4h-vmm/src/blk.rs), but the guest's buffers are in its RAM,
//! which no device reaches: each request's data bounces through the I/O
//! pool (iopool.rs), copied in before a write is submitted and out after a
//! read completes; a request that finds no room waits, and its queue with
//! it, for the completions that free some.  Requests are held to the
//! size_max and seg_max offered, which keep each within a quarter of the
//! pool and blk::MAX_REQUEST_BYTES.  Free of seL4 but the kick.

use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{Ordering, fence};

use l4h_rt::host::blk::{self, Channel};
use l4h_rt::host::fixed::ArrayVec;
use l4h_rt::host::spsc::{Consumer, Producer};

use super::virtio_pci::Backend;
use crate::guest::GuestMem;
use crate::iopool::{self, Pool};
use crate::virtq::{Buf, Queue};
use crate::Kick;

const VIRTIO_BLK_F_SIZE_MAX: u64 = 1 << 1;
const VIRTIO_BLK_F_SEG_MAX: u64 = 1 << 2;
const VIRTIO_BLK_F_RO: u64 = 1 << 5;
const VIRTIO_BLK_F_BLK_SIZE: u64 = 1 << 6;
const VIRTIO_BLK_F_FLUSH: u64 = 1 << 9;

const VIRTIO_BLK_T_GET_ID: u32 = 8;
const VIRTIO_BLK_S_OK: u8 = 0;
const VIRTIO_BLK_S_IOERR: u8 = 1;
const VIRTIO_BLK_S_UNSUPP: u8 = 2;

pub const QUEUE_SIZE: u16 = blk::RING_SIZE as u16;
const SEG_MAX: u32 = blk::SEG_MAX as u32;
/// How long a reset waits for blkd's outstanding requests (blkd's
/// quarantine never answers: the guest is stopped then).
const DRAIN_SECS: u64 = 5;

/// The largest data segment the guest is offered for a pool of `pool`
/// bytes: seg_max of them take at most a quarter of it.
pub fn size_max(pool: u64) -> u32 {
    let per_seg = (pool / 4 / SEG_MAX as u64).min(blk::SEG_SIZE_MAX as u64) as u32;
    (per_seg & !4095).max(4096)
}

#[derive(Clone, Copy)]
struct Inflight {
    status_gpa: u64,
    written: u32,
    /// Its bounce pages, and whether the device writes them (a read),
    /// for the copy back.
    first: u32,
    pages: u32,
    read: bool,
}

pub struct Blk {
    chan: *mut Channel,
    sq: Producer,
    cq: Consumer,
    kick: Option<Kick>,
    capacity: u64,
    read_only: bool,
    volatile: bool,
    block_size: u32,
    size_max: u32,
    seg_max: u32,
    /// The pool's allocator, which every disk of the guest shares (the I/O
    /// thread's, as the disks are).
    pool: *mut Pool,
    /// The pool, mapped here, and as blkd addresses it.
    pool_va: usize,
    pool_gpa: u64,
    inflight: [Option<Inflight>; QUEUE_SIZE as usize],
    outstanding: usize,
    generation: u32,
    /// A popped chain that waits for room (the ring or the pool) or a
    /// flush.
    stalled: Option<u16>,
    /// A flush is with blkd: later requests wait for it.
    flush_inflight: bool,
    kick_pending: bool,
    /// What the queue's last turn left (retry).
    more: bool,
    config: [u8; 64],
    /// For GET_ID.
    serial: [u8; 20],
    tsc_hz: u64,
    now: fn() -> u64,
}

impl Blk {
    /// A disk on the ready channel at `chan_va` (none: zero sectors, every
    /// request failing), its data bouncing through the pool at `pool_va`
    /// (`pool_gpa` for blkd), whose allocator is `pool`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(chan_va: usize, kick: Option<Kick>, pool_va: usize, pool_gpa: u64, pool: *mut Pool, id: u32, tsc_hz: u64, now: fn() -> u64) -> Self {
        let pool_bytes = unsafe { (*pool).bytes() };
        let chan = chan_va as *mut Channel;
        let (capacity, read_only, volatile, block_size, seg_max) = if chan.is_null() {
            (0, true, false, 512, SEG_MAX)
        } else {
            unsafe {
                fence(Ordering::Acquire);
                let seg_max = addr_of!((*chan).seg_max).read_volatile();
                (
                    addr_of!((*chan).capacity_sectors).read_volatile(),
                    addr_of!((*chan).read_only).read_volatile() != 0,
                    addr_of!((*chan).volatile).read_volatile() != 0,
                    addr_of!((*chan).block_size).read_volatile().max(512),
                    if seg_max == 0 { SEG_MAX } else { seg_max.min(SEG_MAX) },
                )
            }
        };
        let size_max = size_max(pool_bytes).max(block_size);
        let mut config = [0u8; 64];
        config[0..8].copy_from_slice(&capacity.to_le_bytes());
        config[8..12].copy_from_slice(&size_max.to_le_bytes());
        config[12..16].copy_from_slice(&seg_max.to_le_bytes());
        config[20..24].copy_from_slice(&block_size.to_le_bytes());
        let mut serial = [0u8; 20];
        let mut w = ArrayVec::<u8, 20>::new();
        let _ = w.extend_from_slice(b"l4h-hvm-");
        let mut digits = [0u8; 10];
        let mut n = id;
        let mut k = 0;
        loop {
            digits[k] = b'0' + (n % 10) as u8;
            k += 1;
            n /= 10;
            if n == 0 {
                break;
            }
        }
        for i in (0..k).rev() {
            let _ = w.push(digits[i]);
        }
        serial[..w.len()].copy_from_slice(&w);
        Blk {
            chan, sq: Producer::new(blk::RING_SIZE), cq: Consumer::new(blk::RING_SIZE), kick, capacity, read_only, volatile,
            block_size, size_max, seg_max, pool, pool_va, pool_gpa,
            inflight: [None; QUEUE_SIZE as usize], outstanding: 0, generation: 0, stalled: None,
            flush_inflight: false, kick_pending: false, more: false, config, serial, tsc_hz, now,
        }
    }

    fn sq_full(&self) -> bool {
        unsafe { self.sq.free(&(*self.chan).sq) == 0 }
    }

    fn next_resp(&mut self) -> Option<blk::Resp> {
        unsafe {
            if self.cq.ready(&(*self.chan).cq) == 0 {
                return None;
            }
            let resp = addr_of!((*self.chan).resps[self.cq.slot()]).read_volatile();
            self.cq.pop(&(*self.chan).cq);
            Some(resp)
        }
    }

    fn bounce(&self, page: u32) -> *mut u8 {
        (self.pool_va + page as usize * iopool::PAGE as usize) as *mut u8
    }

    fn finish(mem: &GuestMem, q: &mut Queue, head: u16, status_gpa: u64, status: u8, written: u32) {
        if mem.valid(status_gpa, 1) {
            mem.write::<u8>(status_gpa, status);
        }
        q.push_deferred(mem, head, written);
    }

    /// The data segments of a well-formed chain: what follows the 16-byte
    /// header, and what precedes the status byte.
    fn segments(bufs: &[Buf]) -> impl Iterator<Item = Buf> + '_ {
        let n = bufs.len();
        bufs.iter().enumerate().filter_map(move |(i, b)| {
            let (mut gpa, mut len) = (b.gpa, b.len);
            if i == 0 {
                gpa += 16;
                len -= 16;
            }
            if i == n - 1 {
                len -= 1;
            }
            (len != 0).then_some(Buf { gpa, len, write: b.write })
        })
    }

    /// Copy between a chain's data segments and its bounce pages: into the
    /// pages (`into_pool`, a write) or out of them, at most `bytes`.
    fn copy(&self, mem: &GuestMem, bufs: &[Buf], first: u32, bytes: u64, into_pool: bool) {
        let mut at = 0u64;
        for s in Self::segments(bufs) {
            let n = (s.len as u64).min(bytes - at);
            if n == 0 || !mem.valid(s.gpa, n) {
                break;
            }
            let (g, p) = (mem.bytes(s.gpa, n as usize), unsafe { self.bounce(first).add(at as usize) });
            unsafe {
                if into_pool {
                    l4h_rt::host::gpu::copy_volatile(g, p, n as usize);
                } else {
                    l4h_rt::host::gpu::copy_volatile(p, g, n as usize);
                }
            }
            at += n;
        }
    }

    /// Take one chain: false if it must wait (for room or a flush).
    fn submit(&mut self, mem: &GuestMem, q: &mut Queue, head: u16) -> bool {
        if self.inflight.get(head as usize).is_none_or(|i| i.is_some()) {
            // A chain blkd still has: dropped (a correct driver never
            // offers one).
            return true;
        }
        let mut bufs = ArrayVec::<Buf, { QUEUE_SIZE as usize }>::new();
        let ok = q.chain(mem, head, &mut bufs).is_ok();
        let last = bufs.last().copied();
        let valid = ok && bufs.len() >= 2 && !bufs[0].write && bufs[0].len >= 16 && last.is_some_and(|b| b.write && b.len >= 1);
        if !valid {
            match last {
                Some(b) if ok && b.write && b.len >= 1 => Self::finish(mem, q, head, b.gpa + b.len as u64 - 1, VIRTIO_BLK_S_IOERR, 1),
                _ => q.push_deferred(mem, head, 0),
            }
            return true;
        }
        let st = last.unwrap();
        let status_gpa = st.gpa + st.len as u64 - 1;
        let ty = mem.read::<u32>(bufs[0].gpa);
        let sector = mem.read::<u64>(bufs[0].gpa + 8);
        let (mut bytes, mut nsegs, mut fits) = (0u64, 0u32, true);
        let dir_read = ty == blk::OP_READ || ty == VIRTIO_BLK_T_GET_ID;
        let mut dir_ok = true;
        for s in Self::segments(&bufs) {
            nsegs += 1;
            bytes += s.len as u64;
            fits &= s.len <= self.size_max;
            dir_ok &= s.write == dir_read;
        }
        fits &= nsegs <= self.seg_max;
        let status = if self.chan.is_null() {
            Some(VIRTIO_BLK_S_IOERR)
        } else {
            match ty {
                blk::OP_READ | blk::OP_WRITE => {
                    if !fits || !dir_ok || bytes == 0 || bytes % 512 != 0 || bytes % self.block_size as u64 != 0
                        || sector.checked_add(bytes / 512).is_none_or(|end| end > self.capacity)
                        || (ty == blk::OP_WRITE && self.read_only)
                    {
                        Some(VIRTIO_BLK_S_IOERR)
                    } else {
                        None
                    }
                }
                blk::OP_FLUSH if bytes == 0 => None,
                blk::OP_FLUSH => Some(VIRTIO_BLK_S_IOERR),
                VIRTIO_BLK_T_GET_ID => {
                    // The serial, NUL-padded, in the first 20 bytes given.
                    let mut at = 0;
                    for s in Self::segments(&bufs).filter(|s| s.write) {
                        let n = (s.len as usize).min(20 - at);
                        mem.write_bytes(s.gpa, &self.serial[at..at + n]);
                        at += n;
                        if at == 20 {
                            break;
                        }
                    }
                    Self::finish(mem, q, head, status_gpa, VIRTIO_BLK_S_OK, at as u32 + 1);
                    return true;
                }
                _ => Some(VIRTIO_BLK_S_UNSUPP),
            }
        };
        if let Some(s) = status {
            Self::finish(mem, q, head, status_gpa, s, 1);
            return true;
        }
        if ty == blk::OP_FLUSH {
            // After every earlier request.
            if self.outstanding != 0 {
                return false;
            }
        }
        if self.sq_full() {
            return false;
        }
        let pages = bytes.div_ceil(iopool::PAGE) as u32;
        let first = if pages == 0 { 0 } else {
            match unsafe { (*self.pool).alloc(pages as usize) } {
                Some(p) => p as u32,
                None => return false,
            }
        };
        if ty == blk::OP_WRITE {
            self.copy(mem, &bufs, first, bytes, true);
        }
        // The bounce pages, in segments of at most SEG_SIZE_MAX.
        let mut req = blk::Req { id: ((self.generation as u64) << 32) | head as u64, op: ty, nr_segs: 0, sector, segs: Default::default() };
        let mut at = 0u64;
        while at < bytes {
            let n = (bytes - at).min(blk::SEG_SIZE_MAX as u64);
            req.segs[req.nr_segs as usize] = blk::Seg {
                gpa: self.pool_gpa + first as u64 * iopool::PAGE + at,
                len: n as u32,
                flags: if ty == blk::OP_READ { blk::SEG_WRITE } else { 0 },
            };
            req.nr_segs += 1;
            at += n;
        }
        let written = if ty == blk::OP_READ { bytes as u32 + 1 } else { 1 };
        self.inflight[head as usize] = Some(Inflight { status_gpa, written, first, pages, read: ty == blk::OP_READ });
        if ty == blk::OP_FLUSH {
            self.flush_inflight = true;
        }
        self.outstanding += 1;
        unsafe {
            addr_of_mut!((*self.chan).reqs[self.sq.slot()]).write_volatile(req);
            self.sq.push(&(*self.chan).sq);
        }
        self.kick_pending = true;
        true
    }

    /// Response `id` of this generation: its request, if in flight.
    fn retire(&mut self, id: u64) -> Option<(u16, Inflight)> {
        if (id >> 32) as u32 != self.generation {
            return None;
        }
        let head = id as u16;
        let inf = self.inflight.get_mut(head as usize)?.take()?;
        self.outstanding -= 1;
        if inf.pages != 0 {
            unsafe { (*self.pool).free(inf.first as usize, inf.pages as usize) };
        }
        Some((head, inf))
    }

    fn notify(&mut self) {
        if core::mem::take(&mut self.kick_pending)
            && let Some(k) = &self.kick
        {
            k.signal();
        }
    }

    /// Wait until blkd has none outstanding (DRAIN_SECS at most, then the
    /// guest is stopped: blkd or its device may still write the pool).
    fn drain(&mut self) {
        self.notify();
        let hz = if self.tsc_hz == 0 { 1_000_000_000 } else { self.tsc_hz };
        let end = (self.now)().saturating_add(DRAIN_SECS.saturating_mul(hz));
        let mut budget = self.outstanding.saturating_add(blk::RING_SIZE);
        while self.outstanding != 0 {
            assert!((self.now)() <= end && budget != 0, "block reset could not drain DMA; stopping guest");
            match self.next_resp() {
                Some(r) => {
                    budget -= 1;
                    self.retire(r.id);
                }
                None => crate::yield_now(),
            }
        }
    }
}

impl Backend for Blk {
    fn device_type(&self) -> u16 {
        2
    }

    fn features(&self) -> u64 {
        let mut f = VIRTIO_BLK_F_SIZE_MAX | VIRTIO_BLK_F_SEG_MAX | VIRTIO_BLK_F_BLK_SIZE;
        if !self.volatile {
            f |= VIRTIO_BLK_F_FLUSH;
        }
        if self.read_only {
            f |= VIRTIO_BLK_F_RO;
        }
        f
    }

    fn num_queues(&self) -> usize {
        1
    }

    fn queue_max(&self, _: usize) -> u16 {
        QUEUE_SIZE
    }

    fn config(&self) -> &[u8] {
        &self.config
    }

    fn kick(&mut self, mem: &GuestMem, queues: &mut [Queue], q: usize) -> u64 {
        if q != 0 || !queues[0].ready {
            return 0;
        }
        self.more = false;
        if self.flush_inflight {
            self.more = true;
            return 0;
        }
        let queue = &mut queues[0];
        let before = queue.used_idx();
        loop {
            let head = match self.stalled.take() {
                Some(h) => h,
                None => match queue.pop(mem) {
                    Some(h) => h,
                    None => break,
                },
            };
            if !self.submit(mem, queue, head) {
                self.stalled = Some(head);
                self.more = true;
                break;
            }
            if self.flush_inflight {
                // Later requests wait for the flush.
                self.more = true;
                break;
            }
        }
        queue.publish_used(mem);
        self.notify();
        if queue.used_idx() != before { 1 } else { 0 }
    }

    fn complete(&mut self, mem: &GuestMem, queues: &mut [Queue]) -> u64 {
        if self.chan.is_null() {
            return 0;
        }
        let queue = &mut queues[0];
        let before = queue.used_idx();
        let mut taken = false;
        for _ in 0..blk::RING_SIZE {
            let Some(resp) = self.next_resp() else { break };
            taken = true;
            let Some((head, inf)) = self.retire(resp.id) else { continue };
            if self.flush_inflight && self.outstanding == 0 {
                self.flush_inflight = false;
            }
            if !queue.ready {
                continue;
            }
            let status = match resp.status {
                blk::STATUS_OK => VIRTIO_BLK_S_OK,
                blk::STATUS_UNSUPP => VIRTIO_BLK_S_UNSUPP,
                _ => VIRTIO_BLK_S_IOERR,
            };
            if status == VIRTIO_BLK_S_OK && inf.read {
                // The chain again, for where the data goes: a guest that
                // changed it meanwhile only misdirects its own data.
                let mut bufs = ArrayVec::<Buf, { QUEUE_SIZE as usize }>::new();
                if queue.chain(mem, head, &mut bufs).is_ok() && bufs.len() >= 2 {
                    self.copy(mem, &bufs, inf.first, inf.written as u64 - 1, false);
                }
            }
            let written = if status == VIRTIO_BLK_S_OK { inf.written } else { 1 };
            Self::finish(mem, queue, head, inf.status_gpa, status, written);
        }
        // blkd takes a request only while its response has room: with
        // requests waiting, kick it.
        if taken && unsafe { self.sq.used(&(*self.chan).sq) } != 0 {
            self.kick_pending = true;
        }
        queue.publish_used(mem);
        self.notify();
        if queue.used_idx() != before { 1 } else { 0 }
    }

    fn retry(&self) -> u64 {
        if self.more || self.stalled.is_some() { 1 } else { 0 }
    }

    fn reset(&mut self) {
        if !self.chan.is_null() {
            self.drain();
        }
        self.generation = self.generation.wrapping_add(1);
        self.inflight = [None; QUEUE_SIZE as usize];
        self.outstanding = 0;
        self.stalled = None;
        self.flush_inflight = false;
        self.more = false;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::mem::tests::fake;
    use std::boxed::Box;

    fn now() -> u64 {
        0
    }

    /// A channel, a 64 KiB pool and a queue at 0x1000 of guest RAM.
    fn setup(capacity: u64) -> (Box<Channel>, std::vec::Vec<u8>, Blk) {
        let mut chan: Box<Channel> = unsafe { Box::new(core::mem::zeroed()) };
        chan.capacity_sectors = capacity;
        chan.block_size = 512;
        let pool = std::vec![0u8; 64 << 10];
        let alloc = Box::leak(Box::new(Pool::new(64 << 10)));
        let b = Blk::new(&mut *chan as *mut Channel as usize, Some(Kick), pool.as_ptr() as usize, 1 << 46, alloc, 3, 1, now);
        (chan, pool, b)
    }

    /// Put a chain of (gpa, len, write) descriptors at slot `i` of the
    /// avail ring (desc at 0x1000, avail 0x2000, used 0x3000).
    fn offer(mem: &GuestMem, head: u16, descs: &[(u64, u32, bool)], avail_idx: u16) {
        for (k, &(gpa, len, w)) in descs.iter().enumerate() {
            let d = 0x1000 + 16 * (head as u64 + k as u64);
            mem.write::<u64>(d, gpa);
            mem.write::<u32>(d + 8, len);
            let flags = if w { 2 } else { 0 } | if k + 1 < descs.len() { 1 } else { 0 };
            mem.write::<u16>(d + 12, flags);
            mem.write::<u16>(d + 14, head + k as u16 + 1);
        }
        mem.write::<u16>(0x2000 + 4 + 2 * ((avail_idx - 1) % QUEUE_SIZE) as u64, head);
        mem.write::<u16>(0x2002, avail_idx);
    }

    #[test]
    fn write_bounces_then_read_copies_back() {
        let (mem, _buf) = fake(1 << 20, 0);
        let (chan, pool, mut b) = setup(1 << 20);
        let mut qs: [Queue; 1] = Default::default();
        assert!(qs[0].setup(&mem, 16, 128, 0x1000, 0x2000, 0x3000));
        // A write of 1024 bytes from two buffers at sector 8.
        mem.write::<u32>(0x8000, blk::OP_WRITE);
        mem.write::<u64>(0x8008, 8);
        mem.write_bytes(0x9000, &[0xaa; 512]);
        mem.write_bytes(0xa000, &[0xbb; 512]);
        offer(&mem, 0, &[(0x8000, 16, false), (0x9000, 512, false), (0xa000, 512, false), (0xb000, 1, true)], 1);
        assert_eq!(b.kick(&mem, &mut qs, 0), 0, "submitted, not done");
        let req = chan.reqs[0];
        assert_eq!((req.op, req.sector, req.nr_segs, req.segs[0].len, req.segs[0].flags), (blk::OP_WRITE, 8, 1, 1024, 0));
        assert_eq!(req.segs[0].gpa, 1 << 46);
        assert!(pool[..512].iter().all(|&x| x == 0xaa) && pool[512..1024].iter().all(|&x| x == 0xbb));
        // blkd completes it.
        let chan = Box::leak(chan);
        chan.resps[0] = blk::Resp { id: req.id, status: blk::STATUS_OK, reserved: 0 };
        chan.cq.head.store(1, Ordering::Release);
        assert_eq!(b.complete(&mem, &mut qs), 1);
        assert_eq!(mem.read::<u8>(0xb000), 0);
        assert_eq!(mem.read::<u16>(0x3002), 1);
        assert_eq!(unsafe { (*b.pool).free_pages() }, 16, "bounce pages freed");
        // A read of 512 bytes at sector 0: copied into guest RAM at completion.
        mem.write::<u32>(0x8000, blk::OP_READ);
        mem.write::<u64>(0x8008, 0);
        offer(&mem, 4, &[(0x8000, 16, false), (0xc000, 512, true), (0xb000, 1, true)], 2);
        b.kick(&mem, &mut qs, 0);
        let req = chan.reqs[1];
        assert_eq!((req.op, req.segs[0].flags), (blk::OP_READ, blk::SEG_WRITE));
        let bounce = (pool.as_ptr() as usize + (req.segs[0].gpa - (1 << 46)) as usize) as *mut u8;
        unsafe { core::ptr::write_bytes(bounce, 0x5a, 512) };
        chan.resps[1] = blk::Resp { id: req.id, status: blk::STATUS_OK, reserved: 0 };
        chan.cq.head.store(2, Ordering::Release);
        b.complete(&mem, &mut qs);
        let mut got = [0u8; 512];
        mem.read_bytes(0xc000, &mut got);
        assert!(got.iter().all(|&x| x == 0x5a));
        assert_eq!(mem.read::<u32>(0x3000 + 4 + 8 + 4), 513, "used length");
    }

    #[test]
    fn refusals_and_backpressure() {
        let (mem, _buf) = fake(1 << 20, 0);
        let (chan, _pool, mut b) = setup(16);
        let mut qs: [Queue; 1] = Default::default();
        assert!(qs[0].setup(&mem, 16, 128, 0x1000, 0x2000, 0x3000));
        // Past the end of the disk; out of RAM; not sector-sized; unknown.
        mem.write::<u32>(0x8000, blk::OP_READ);
        mem.write::<u64>(0x8008, 16);
        offer(&mem, 0, &[(0x8000, 16, false), (0xc000, 512, true), (0xb000, 1, true)], 1);
        b.kick(&mem, &mut qs, 0);
        assert_eq!(mem.read::<u8>(0xb000), VIRTIO_BLK_S_IOERR);
        mem.write::<u64>(0x8008, 0);
        offer(&mem, 3, &[(0x8000, 16, false), (1 << 40, 512, true), (0xb000, 1, true)], 2);
        b.kick(&mem, &mut qs, 0);
        assert_eq!(mem.read::<u16>(0x3002), 2, "a chain outside RAM is returned");
        // The I/O pool's own GPA, which blkd would reach: not RAM either.
        offer(&mem, 13, &[(0x8000, 16, false), (l4h_rt::host::hvm::IO_POOL_GPA, 512, true), (0xb000, 1, true)], 3);
        b.kick(&mem, &mut qs, 0);
        assert_eq!(mem.read::<u16>(0x3002), 3, "a chain into the I/O pool is returned");
        offer(&mem, 6, &[(0x8000, 16, false), (0xc000, 100, true), (0xb000, 1, true)], 4);
        mem.write::<u8>(0xb000, 0xff);
        b.kick(&mem, &mut qs, 0);
        assert_eq!(mem.read::<u8>(0xb000), VIRTIO_BLK_S_IOERR);
        mem.write::<u32>(0x8000, 11);
        offer(&mem, 9, &[(0x8000, 16, false), (0xb000, 1, true)], 5);
        b.kick(&mem, &mut qs, 0);
        assert_eq!(mem.read::<u8>(0xb000), VIRTIO_BLK_S_UNSUPP);
        // GET_ID.
        mem.write::<u32>(0x8000, VIRTIO_BLK_T_GET_ID);
        offer(&mem, 11, &[(0x8000, 16, false), (0xd000, 20, true), (0xb000, 1, true)], 6);
        b.kick(&mem, &mut qs, 0);
        let mut id = [0u8; 9];
        mem.read_bytes(0xd000, &mut id);
        assert_eq!(&id, b"l4h-hvm-3");
        assert_eq!(chan.sq.head.load(Ordering::Relaxed), 0, "nothing reached blkd");
        // A pool too small for the request: it waits.
        let (mem2, _buf2) = fake(1 << 20, 0);
        let mut chan2: Box<Channel> = unsafe { Box::new(core::mem::zeroed()) };
        chan2.capacity_sectors = 1 << 20;
        chan2.block_size = 512;
        let pool2 = std::vec![0u8; 16 << 10];
        let alloc2 = Box::leak(Box::new(Pool::new(16 << 10)));
        let mut b2 = Blk::new(&mut *chan2 as *mut Channel as usize, Some(Kick), pool2.as_ptr() as usize, 0, alloc2, 1, 1, now);
        let mut q2: [Queue; 1] = Default::default();
        assert!(q2[0].setup(&mem2, 16, 128, 0x1000, 0x2000, 0x3000));
        mem2.write::<u32>(0x8000, blk::OP_READ);
        mem2.write::<u64>(0x8008, 0);
        offer(&mem2, 0, &[(0x8000, 16, false), (0xc000, 4096, true), (0xb000, 1, true)], 1);
        offer(&mem2, 3, &[(0x8000, 16, false), (0xe000, 4096, true), (0xb100, 1, true)], 2);
        offer(&mem2, 6, &[(0x8000, 16, false), (0x10000, 4096, true), (0xb200, 1, true)], 3);
        offer(&mem2, 9, &[(0x8000, 16, false), (0x12000, 4096, true), (0xb300, 1, true)], 4);
        offer(&mem2, 12, &[(0x8000, 16, false), (0x14000, 4096, true), (0xb400, 1, true)], 5);
        b2.kick(&mem2, &mut q2, 0);
        assert_eq!(chan2.sq.head.load(Ordering::Relaxed), 4, "four fit");
        assert_eq!(b2.retry(), 1);
        assert!(b2.stalled.is_some());
    }
}

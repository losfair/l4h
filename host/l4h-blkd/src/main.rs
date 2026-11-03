//! blkd: drives one disk controller (virtio-blk, virtio-scsi or NVMe PCI
//! device) for multiple clients (a guest's l4h-vmm).  A virtio-scsi
//! controller has a unit per logical unit; the others have one.  Requests carry guest-physical segments, which are
//! validated against the client's I/O pool and its LBA window and handed to
//! the device by physical address. Reads DMA into the pool; every write
//! is snapshotted into private bounce memory. Encrypted windows use
//! hardware AES-256-XTS, with reads decrypted before completing them.  See DESIGN.md §9.2.

#![no_std]
#![no_main]

mod bounce;
mod crypt;
mod data;
mod nvme;
mod scsi;
mod virtio;

use core::ops::{Deref, DerefMut};
use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{Ordering, fence};

use l4h_rt::host;
use l4h_rt::host::wipe;
use l4h_rt::host::blk::{self, BlkdConfig, Channel, Pool};
use l4h_rt::host::fixed::ArrayVec;
use l4h_rt::sel4;
use l4h_rt::{Info, cap};
use sel4::cap_type;

/// A physically contiguous piece of a request's data.
#[derive(Clone, Copy, Debug)]
pub struct Seg {
    pub pa: u64,
    pub len: u32,
}

/// Pieces of one request: one per guest segment (the pool is physically
/// contiguous).
pub const MAX_PIECES: usize = blk::MAX_SEGS;

/// Requests in flight on the controller: as many as the deepest queue
/// (NVMe's) holds commands, which is more than the others.
const MAX_INFLIGHT: usize = 256;

#[derive(Clone, Copy)]
pub struct DevInfo {
    /// In 512-byte sectors.
    pub capacity: u64,
    pub block_size: u32,
    pub read_only: bool,
    pub flush: bool,
    /// Where the unit is on its controller (blk::BLKD_INFO).
    pub address: u64,
}

/// A disk driver.  Requests are identified by the caller's tag.
pub trait Driver {
    /// Number of units (disks) the controller has.
    fn units(&self) -> usize;
    fn info(&self, unit: usize) -> DevInfo;
    /// Room for one more request.
    fn can_start(&self) -> bool;
    /// Start a request on `unit`: `op` is blk::OP_READ, OP_WRITE or
    /// OP_FLUSH, `sector` in 512-byte units, already checked against the
    /// capacity and aligned to the block size.  Errors are blk::STATUS_*.
    fn start(&mut self, tag: u64, unit: usize, op: u32, sector: u64, data: &[Seg]) -> Result<(), u32>;
    /// Tell the device about started requests.
    fn kick(&mut self);
    /// Report completed requests.
    fn reap(&mut self, done: &mut dyn FnMut(u64, u32));
}

/// The controller's driver.
enum Drv {
    Nvme(nvme::Nvme),
    Scsi(scsi::VirtioScsi),
    Virtio(virtio::VirtioBlk),
}

impl Deref for Drv {
    type Target = dyn Driver;

    fn deref(&self) -> &(dyn Driver + 'static) {
        match self {
            Drv::Nvme(d) => d,
            Drv::Scsi(d) => d,
            Drv::Virtio(d) => d,
        }
    }
}

impl DerefMut for Drv {
    fn deref_mut(&mut self) -> &mut (dyn Driver + 'static) {
        match self {
            Drv::Nvme(d) => d,
            Drv::Scsi(d) => d,
            Drv::Virtio(d) => d,
        }
    }
}

struct Client {
    chan: *mut Channel,
    unit: usize,
    pool: Pool,
    window: blk::DiskWindow,
    read_only: bool,
    /// Flushes complete at once (l4h_abi::BLK_VOLATILE).
    volatile: bool,
    block_size: u32,
    pool_va: usize,
    encrypted: bool,
    keys: crypt::Xts,
    done: sel4::cap::Notification,
    outstanding: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum QueueState { Ineligible, CqBlocked, Ready }

fn select_writer(waiting: &[usize], states: &[QueueState; blk::MAX_CLIENTS],
    first: &mut Option<usize>, first_no_space: &mut bool, parked: &mut [bool; blk::MAX_CLIENTS]) {
    let next = waiting.iter().copied().find(|&i| states[i] == QueueState::Ready);
    if next != *first {
        *first = next;
        *first_no_space = false;
        parked.fill(false);
    }
}

struct Pending {
    client: usize,
    id: u64,
    unit: u64,
    /// Translated segments only for reads that need completion decryption.
    read: ArrayVec<Seg, MAX_PIECES>,
    bounce: Option<bounce::Run>,
}

/// Client slots, in .bss: too large for the stack.
static mut PENDING: [Option<Pending>; MAX_INFLIGHT] = [const { None }; MAX_INFLIGHT];
static mut CLIENTS: [Option<Client>; blk::MAX_CLIENTS] = [const { None }; blk::MAX_CLIENTS];

struct Blkd {
    clients: &'static mut [Option<Client>; blk::MAX_CLIENTS],
    /// Indices of the attached clients, in attach order: the submit loop
    /// visits only these.
    active: ArrayVec<usize, { blk::MAX_CLIENTS }>,
    /// FIFO of clients waiting for write space. Only its first runnable
    /// member reserves space; CQ-blocked clients keep rank without blocking peers.
    waiting: ArrayVec<usize, { blk::MAX_CLIENTS }>,
    // Tags are allocated here, never taken from a client. Slots are not
    // reusable until the hardware has completed every command of a request.
    pending: &'static mut [Option<Pending>; MAX_INFLIGHT],
    free_tags: ArrayVec<usize, MAX_INFLIGHT>,
    bounce: bounce::Bounce,
    cfg: &'static BlkdConfig,
    drv: Drv,
    dev: ArrayVec<DevInfo, { blk::MAX_UNITS }>,
    next: usize,
    ticks_per_sec: u64,
}

impl Client {
    fn queue_state(&self) -> (u32, QueueState) {
        unsafe {
            let tail = addr_of!((*self.chan).sq.tail).read_volatile();
            let head = addr_of!((*self.chan).sq.head).read_volatile();
            let cq_used = addr_of!((*self.chan).cq.head).read_volatile()
                .wrapping_sub(addr_of!((*self.chan).cq.tail).read_volatile()) as usize;
            // Empty queues and malformed SQ/CQ indices lose FIFO rank.
            let state = if head == tail || head.wrapping_sub(tail) as usize > blk::RING_SIZE
                || cq_used > blk::RING_SIZE { QueueState::Ineligible }
                // Reserve completion space for every in-flight request.
                else if cq_used.saturating_add(self.outstanding) >= blk::RING_SIZE { QueueState::CqBlocked }
                else { QueueState::Ready };
            (tail, state)
        }
    }

    fn respond(&self, id: u64, status: u32) {
        unsafe {
            let h = addr_of!((*self.chan).cq.head).read_volatile();
            addr_of_mut!((*self.chan).resps[h as usize % blk::RING_SIZE])
                .write_volatile(blk::Resp { id, status, reserved: 0 });
            fence(Ordering::Release);
            addr_of_mut!((*self.chan).cq.head).write_volatile(h.wrapping_add(1));
        }
        self.done.signal();
    }

    fn prepare(&self, req: &blk::Req, block_size: u32, pieces: &mut ArrayVec<Seg, MAX_PIECES>) -> Result<u64, u32> {
        let sector = self.window.check_request(req, self.pool, block_size, self.read_only)?;
        pieces.clear();
        if req.op != blk::OP_FLUSH {
            // check_request allows at most MAX_SEGS segments.
            for s in &req.segs[..req.nr_segs as usize] {
                let _ = pieces.push(Seg { pa: self.pool.translate(s.gpa, s.len as u64).unwrap(), len: s.len });
            }
        }
        Ok(sector)
    }
}

impl Blkd {
    fn reap(&mut self) -> Option<u32> {
        let mut completed = ArrayVec::<(u64, u32), MAX_INFLIGHT>::new();
        let mut provision = None;
        self.drv.reap(&mut |tag, status| {
            if tag == u64::MAX { provision = Some(status); }
            else { completed.must_push((tag, status)); }
        });
        // Drivers finish their bookkeeping (including legacy retry I/O)
        // before any decryption, notification or client response occurs.
        for &(tag, status) in &completed {
            if let Some(p) = self.pending.get_mut(tag as usize).and_then(|p| p.take()) {
                self.free_tags.must_push(tag as usize);
                if let Some(run) = p.bounce { self.bounce.free(run); }
                if let Some(c) = self.clients[p.client].as_mut() {
                    if status == blk::STATUS_OK && !p.read.is_empty() {
                        unsafe { data::Data { segs: &p.read, pool_pa: c.pool.paddr, pool_va: c.pool_va }
                            .crypt(&c.keys, p.unit, None); }
                    }
                    c.outstanding -= 1;
                    c.respond(p.id, status);
                }
            }
        }
        provision
    }

    fn submit(&mut self) {
        let mut pieces = ArrayVec::new();
        let mut started = false;
        // No completions are reaped inside this pass. Remember a failed
        // allocation until priority changes or the next submit call.
        let mut first_no_space = false;
        let mut parked = [false; blk::MAX_CLIENTS];
        let mut states = [QueueState::Ineligible; blk::MAX_CLIENTS];
        // Select priority before round-robin visits, including when the
        // oldest waiter comes last. Ineligible clients cannot reserve space.
        for &i in &self.waiting {
            states[i] = self.clients[i].as_ref().unwrap().queue_state().1;
        }
        self.waiting.retain(|&i| states[i] != QueueState::Ineligible);
        let mut first = None;
        select_writer(&self.waiting, &states, &mut first, &mut first_no_space, &mut parked);
        // Bounded work per client and round-robin starting point. A busy
        // ring cannot occupy every hardware slot before others get a turn.
        let n = self.active.len();
        'rounds: for _round in 0..blk::RING_SIZE / 4 {
            // Capacity only returns when reap runs between submit passes.
            // Stop before polling client rings if no request can start.
            if !self.drv.can_start() || self.free_tags.is_empty() { break; }
            for off in 0..n {
                let i = self.active[(self.next + off) % n];
                if (first_no_space && first == Some(i)) || parked[i] { continue; }
                let Some(c) = self.clients[i].as_mut() else { continue };
                for _ in 0..4 {
                    // Recheck empty/CQ-blocked clients each round: a guest
                    // may publish work or drain completions during this pass.
                    let (tail, state) = c.queue_state();
                    if states[i] != state {
                        states[i] = state;
                        if state == QueueState::Ineligible {
                            self.waiting.retain(|&w| w != i);
                        }
                        select_writer(&self.waiting, &states, &mut first, &mut first_no_space, &mut parked);
                    }
                    if state != QueueState::Ready { break; }
                    if !self.drv.can_start() { break 'rounds; }
                    let Some(&tag) = self.free_tags.last() else { break 'rounds };
                    let req = unsafe {
                        fence(Ordering::Acquire);
                        addr_of!((*c.chan).reqs[tail as usize % blk::RING_SIZE]).read_volatile()
                    };
                    if req.op == blk::OP_WRITE && first.is_some_and(|w| w != i) {
                        if !self.waiting.contains(&i) { self.waiting.must_push(i); }
                        // Retry only when priority changes. This avoids
                        // validating/translating the same blocked request in
                        // every round, even before the first writer is visited.
                        parked[i] = true;
                        break;
                    }
                    let dev = &self.dev[c.unit];
                    let mut run = None;
                    let mut deferred = false;
                    let result = c.prepare(&req, c.block_size, &mut pieces).and_then(|sector| {
                        if req.op == blk::OP_FLUSH {
                            pieces.clear();
                            if !dev.flush || c.volatile { return Err(blk::STATUS_OK); }
                        }
                        if req.op == blk::OP_WRITE {
                            let bytes: usize = pieces.iter().map(|s| s.len as usize).sum();
                            let Some(r) = self.bounce.alloc(bytes) else {
                                if !self.waiting.contains(&i) { self.waiting.must_push(i); }
                                first = Some(i);
                                first_no_space = true;
                                deferred = true;
                                return Err(blk::STATUS_OK);
                            };
                            run = Some(r);
                            let dst = (self.cfg.bounce_va as usize + r.offset()) as *mut u8;
                            let data = data::Data { segs: &pieces, pool_pa: c.pool.paddr, pool_va: c.pool_va };
                            unsafe {
                                if c.encrypted { data.crypt(&c.keys, req.sector / 8, Some(dst)); }
                                else { data.copy_to(dst); }
                            }
                            pieces.clear();
                            pieces.must_push(Seg { pa: self.cfg.bounce_paddr + r.offset() as u64, len: bytes as u32 });
                        }
                        self.drv.start(tag as u64, c.unit, req.op, sector, &pieces)
                    });
                    // Do not consume a write until a contiguous run is
                    // available. Other clients' reads/flushes still run.
                    if deferred { break; }
                    if self.waiting.contains(&i) {
                        self.waiting.retain(|&w| w != i);
                        select_writer(&self.waiting, &states, &mut first, &mut first_no_space, &mut parked);
                    }
                    unsafe { addr_of_mut!((*c.chan).sq.tail).write_volatile(tail.wrapping_add(1)); }
                    match result {
                        Ok(()) => {
                            self.free_tags.pop();
                            self.pending[tag] = Some(Pending { client: i, id: req.id, unit: req.sector / 8,
                                read: if req.op == blk::OP_READ && c.encrypted { pieces.clone() } else { ArrayVec::new() },
                                bounce: run });
                            c.outstanding += 1;
                            started = true;
                        }
                        Err(status) => {
                            if let Some(run) = run { self.bounce.free(run); }
                            c.respond(req.id, status);
                        }
                    }
                }
            }
        }
        self.next = if n == 0 { 0 } else { (self.next + 1) % n };
        if started { self.drv.kick(); }
    }

    fn add(&mut self, i: usize, unit: usize, flags: u64, key: &[u8; 64], len: usize) -> u64 {
        if len != 11 || flags & !blk::ENCRYPT != 0 || i >= blk::MAX_CLIENTS
            || self.clients[i].is_some() || unit >= self.dev.len() { return 22; }
        let encrypted = flags & blk::ENCRYPT != 0;
        if encrypted && self.cfg.features & blk::FEATURE_AES == 0 { return 95; }
        if encrypted && !blk::valid_xts_key(key) { return 22; }
        let dev = self.dev[unit];
        let chan = blk::channel_va(i) as *mut Channel;
        let (start, count, ro, volatile, pool) = unsafe {
            (addr_of!((*chan).lba_start).read_volatile(), addr_of!((*chan).capacity_sectors).read_volatile(),
             addr_of!((*chan).read_only).read_volatile(), addr_of!((*chan).volatile).read_volatile() != 0,
             addr_of!((*chan).pool).read_volatile())
        };
        let read_only = ro != 0 || dev.read_only;
        let Some(window) = blk::DiskWindow::new(start, count, dev.capacity) else { return 22 };
        if self.clients.iter().flatten().any(|c| c.unit == unit && window.overlaps(c.window)
            && (window.conflicts(read_only, c.window, c.read_only)
                || ((encrypted || c.encrypted) && (encrypted != c.encrypted || window.start != c.window.start)))) {
            return 16;
        }
        let block_size = if encrypted { crypt::UNIT as u32 } else { dev.block_size };
        self.clients[i] = Some(Client { chan, unit, pool, window, read_only, volatile, block_size,
            pool_va: self.cfg.pool_va as usize + blk::pool_offset(i, pool.size as usize),
            encrypted, keys: crypt::Xts::empty(),
            done: cap::<cap_type::Notification>(blk::BLKD_SLOT_CLIENT_DONE + i as u64), outstanding: 0 });
        // Expand once, in the final slot. A rejected shared key is wiped
        // there by Drop before publishing the client or marking it ready.
        if encrypted { unsafe { self.clients[i].as_mut().unwrap().keys.init(key); } }
        if encrypted && self.clients.iter().enumerate().any(|(other, c)| other != i && c.as_ref().is_some_and(|c|
            c.unit == unit && window.overlaps(c.window) && !self.clients[i].as_ref().unwrap().keys.same_key(&c.keys))) {
            self.clients[i] = None;
            return 16;
        }
        self.active.must_push(i);
        unsafe {
            addr_of_mut!((*chan).read_only).write_volatile(read_only as u32);
            addr_of_mut!((*chan).block_size).write_volatile(block_size);
            fence(Ordering::Release);
            addr_of_mut!((*chan).ready).write_volatile(1);
        }
        0
    }

    fn deadline(&self) -> u64 { host::ticks::now().saturating_add(5 * self.ticks_per_sec) }

    fn remove(&mut self, i: usize) -> u64 {
        if i >= self.clients.len() { return u64::MAX; }
        self.waiting.retain(|&w| w != i);
        // Stop consuming this channel first. Polling the hardware drains
        // only submitted work; no controller reset disrupts other clients.
        let end = self.deadline();
        while self.clients[i].as_ref().is_some_and(|c| c.outstanding != 0) {
            self.reap();
            if host::ticks::now() > end { return u64::MAX; }
            core::hint::spin_loop();
        }
        self.clients[i] = None;
        self.active.retain(|&a| a != i);
        0
    }

    fn provision(&mut self, cfg: &BlkdConfig, unit: usize, sector: u64, len: usize, flush: bool) -> u64 {
        let Some(&dev) = self.dev.get(unit) else { return u64::MAX };
        if dev.read_only { return blk::STATUS_IOERR as u64; }
        if !flush {
            let Some(w) = blk::DiskWindow::new(sector, (len / 512) as u64, dev.capacity) else { return u64::MAX };
            if len == 0 || len > blk::STAGING_SIZE || len % dev.block_size as usize != 0
                || self.clients.iter().flatten().any(|c| c.unit == unit && c.window.overlaps(w)) { return u64::MAX; }
        }
        if flush && !dev.flush { return blk::STATUS_OK as u64; }
        let end = self.deadline();
        while !self.drv.can_start() {
            self.reap();
            if host::ticks::now() > end { return u64::MAX; }
        }
        let data = [Seg { pa: cfg.staging_paddr, len: len as u32 }];
        let result = self.drv.start(u64::MAX, unit, if flush { blk::OP_FLUSH } else { blk::OP_WRITE },
            sector, if flush { &[] } else { &data });
        if let Err(status) = result { return status as u64; }
        self.drv.kick();
        loop {
            if let Some(status) = self.reap() { return status as u64; }
            if host::ticks::now() > end { return u64::MAX; }
            core::hint::spin_loop();
        }
    }
}

fn mr(i: usize) -> u64 { sel4::with_ipc_buffer(|b| b.msg_regs()[i]) }
fn set_mr(i: usize, v: u64) { sel4::with_ipc_buffer_mut(|b| b.msg_regs_mut()[i] = v); }

fn main(info: &'static Info) -> ! {
    let cfg: &BlkdConfig = unsafe { info.config() };
    assert_eq!(cfg.bounce_size as usize, bounce::SIZE);
    let id = info.header().id;
    let drv = match cfg.kind {
        blk::BLKD_NVME => Drv::Nvme(nvme::Nvme::new(id, cfg)),
        blk::BLKD_VIRTIO_SCSI => Drv::Scsi(scsi::VirtioScsi::new(id, cfg)),
        _ => Drv::Virtio(virtio::VirtioBlk::new(id, cfg)),
    };
    // A driver has at most blk::MAX_UNITS units.
    let mut dev = ArrayVec::new();
    for u in 0..drv.units() {
        let _ = dev.push(drv.info(u));
    }
    for (u, d) in dev.iter().enumerate() {
        l4h_rt::info!("blkd {:#x}: shared controller, unit {}: {} sectors, {}-byte blocks", id, u, d.capacity, d.block_size);
    }
    let mut b = Blkd {
        // The only reference to CLIENTS.
        clients: unsafe { &mut *addr_of_mut!(CLIENTS) },
        active: ArrayVec::new(),
        waiting: ArrayVec::new(),
        pending: unsafe { &mut *addr_of_mut!(PENDING) },
        free_tags: (0..MAX_INFLIGHT).rev().collect(),
        bounce: bounce::Bounce::new(), cfg,
        drv, dev, next: 0, ticks_per_sec: info.header().tsc_hz,
    };
    let ep = cap::<cap_type::Endpoint>(host::SLOT_SERVICE_EP);
    let reply = cap::<cap_type::Reply>(host::SLOT_REPLY);
    let irq = cap::<cap_type::IrqHandler>(blk::BLKD_SLOT_IRQ);
    let (mut msg, mut badge) = ep.recv(reply);
    loop {
        if badge != 0 {
            b.reap();
            b.submit();
            if badge & blk::BLKD_BADGE_IRQ != 0 { irq.irq_handler_ack().expect("blkd IRQ ack"); }
            (msg, badge) = ep.recv(reply);
            continue;
        }
        let mut response = [0; 5];
        let result = match msg.label() {
            blk::BLKD_INFO => {
                response[3] = b.dev.len() as u64;
                match b.dev.get(mr(0) as usize) {
                    Some(d) => {
                        response[1] = d.block_size as u64;
                        response[2] = d.read_only as u64;
                        response[4] = d.address;
                        d.capacity
                    }
                    None => u64::MAX,
                }
            }
            blk::BLKD_ADD => {
                let (i, unit, flags) = (mr(0) as usize, mr(1) as usize, mr(2));
                let mut key = [0u8; 64];
                if msg.length() == 11 {
                    for n in 0..8 { key[8 * n..8 * n + 8].copy_from_slice(&mr(3 + n).to_le_bytes()); }
                }
                // Clear incoming key words before any other IPC can use them.
                sel4::with_ipc_buffer_mut(|b| wipe::words(&mut b.msg_regs_mut()[..msg.length()]));
                let result = b.add(i, unit, flags, &key, msg.length());
                if result == 0 {
                    response[1] = if b.clients[i].as_ref().unwrap().encrypted { blk::ENCRYPT } else { 0 };
                }
                wipe::bytes(&mut key);
                if result == 0 && flags & blk::ENCRYPT != 0 {
                    l4h_rt::info!("blkd {:#x}: unit {} client {}: aes-256-xts ({})", id, unit, i, crypt::BACKEND);
                }
                result
            }
            blk::BLKD_REMOVE => b.remove(mr(0) as usize),
            blk::BLKD_WRITE => b.provision(cfg, mr(2) as usize, mr(0), mr(1) as usize, false),
            blk::BLKD_FLUSH => b.provision(cfg, mr(0) as usize, 0, 0, true),
            _ => u64::MAX,
        };
        response[0] = result;
        // Service calls can have reaped completions while polling. A kick
        // may have been coalesced, so always revisit all pending channels.
        b.submit();
        // Legacy virtio kicks invoke IOPort capabilities and overwrite MRs.
        // Marshal the whole reply only after that work has finished.
        for (i, v) in response.into_iter().enumerate() { set_mr(i, v); }
        (msg, badge) = ep.reply_recv(sel4::MessageInfo::new(0, 0, 0, 5), reply);
    }
}

l4h_rt::component!(main, no_heap);

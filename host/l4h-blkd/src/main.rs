//! blkd: drives one disk controller (virtio-blk, virtio-scsi or NVMe PCI
//! device) for multiple clients (a guest's l4h-vmm).  A virtio-scsi
//! controller has a unit per logical unit; the others have one.  A client's
//! disk is a window of a unit or a list of extents of one (blk::Volume).
//! Requests carry guest-physical segments, which are validated against the
//! client's I/O pool and its disk, mapped to one or two device requests and
//! handed to the device by physical address: the device reads and writes
//! the pool directly, never guest RAM (the guest bounces through the pool
//! with swiotlb).  blkd alone decides which clients may use which sectors
//! (blk::Reservations); l4h-root asks with BLKD_CHECK.  See DESIGN.md §8.2.

#![no_std]
#![no_main]

mod nvme;
mod scsi;
mod virtio;

use core::ops::{Deref, DerefMut};
use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{Ordering, fence};

use l4h_rt::host;
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
    /// In the client's table at extent_va(i), which only blkd maps.
    vol: blk::Volume<'static>,
    read_only: bool,
    done: sel4::cap::Notification,
    outstanding: usize,
}

/// A request in flight: its pieces have tags `t << 1` and `t << 1 | 1`
/// for pending slot t.
#[derive(Clone, Copy)]
struct Pending {
    client: usize,
    id: u64,
    /// Pieces not yet completed.
    left: u8,
    /// The first error of a piece.
    status: u32,
}

/// The second piece of a split request, started as soon as the device has
/// room and before any new request.
struct Carry {
    t: usize,
    unit: usize,
    op: u32,
    sector: u64,
    segs: ArrayVec<Seg, MAX_PIECES>,
}

/// A piece of pending request `t` completed with `status`: the client gets
/// the first error once all pieces have.
fn finish(pending: &mut [Option<Pending>], clients: &mut [Option<Client>], t: usize, status: u32) {
    let Some(slot) = pending.get_mut(t) else { return };
    let Some(p) = slot.as_mut() else { return };
    if p.status == blk::STATUS_OK { p.status = status; }
    p.left -= 1;
    if p.left == 0 {
        let p = slot.take().unwrap();
        if let Some(c) = clients[p.client].as_mut() {
            c.outstanding -= 1;
            c.respond(p.id, p.status);
        }
    }
}

/// Client slots, in .bss: too large for the stack.
static mut CLIENTS: [Option<Client>; blk::MAX_CLIENTS] = [const { None }; blk::MAX_CLIENTS];
/// dom0's boot ranges, in the same slots.
static mut RESERVED: blk::Reservations<{ blk::MAX_CLIENTS }> = blk::Reservations::new();
/// Where BLKD_CHECK builds the disk it checks.
static mut SCRATCH_ORDER: [u16; blk::MAX_EXTENTS] = [0; blk::MAX_EXTENTS];
static mut SCRATCH_EXTENTS: [blk::Extent; blk::MAX_EXTENTS] =
    [blk::Extent { start: 0, sectors: 0, offset: 0 }; blk::MAX_EXTENTS];

struct Blkd {
    clients: &'static mut [Option<Client>; blk::MAX_CLIENTS],
    reserved: &'static mut blk::Reservations<{ blk::MAX_CLIENTS }>,
    /// Indices of the attached clients, in attach order: the submit loop
    /// visits only these.
    active: ArrayVec<usize, { blk::MAX_CLIENTS }>,
    // Tags are allocated here, never taken from a client. Slots are not
    // reusable until the hardware has completed every command of a request.
    pending: [Option<Pending>; MAX_INFLIGHT],
    carry: Option<Carry>,
    drv: Drv,
    dev: ArrayVec<DevInfo, { blk::MAX_UNITS }>,
    next: usize,
    ticks_per_sec: u64,
}

/// What each slot's client holds, for blk::Reservations.
fn holds(clients: &[Option<Client>]) -> impl Fn(usize) -> Option<blk::Hold<'static>> + '_ {
    |i| clients[i].as_ref().map(|c| blk::Hold { unit: c.unit, extents: c.vol.extents, read_only: c.read_only })
}

impl Client {
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

    /// Map a request to its device requests: their sectors and segments,
    /// and how many there are (none for a flush).
    fn prepare(&self, req: &blk::Req, block_size: u32, groups: &mut [ArrayVec<Seg, MAX_PIECES>; 2])
        -> Result<([u64; 2], usize), u32> {
        let (pieces, n) = self.vol.map(req, self.pool, block_size, self.read_only)?;
        groups.iter_mut().for_each(|g| g.clear());
        // map allows at most MAX_SEGS segments; splitting the one that
        // crosses the boundary leaves each piece at most MAX_SEGS.
        let (mut k, mut left) = (0, pieces[0].1);
        for s in &req.segs[..req.nr_segs as usize] {
            let (mut pa, mut len) = (self.pool.translate(s.gpa, s.len as u64).unwrap(), s.len as u64);
            while len > 0 {
                let take = len.min(left);
                let _ = groups[k].push(Seg { pa, len: take as u32 });
                (pa, len, left) = (pa + take, len - take, left - take);
                if left == 0 && k + 1 < n {
                    k += 1;
                    left = pieces[k].1;
                }
            }
        }
        Ok(([pieces[0].0, pieces[1].0], n))
    }
}

impl Blkd {
    fn reap(&mut self) -> Option<u32> {
        let Blkd { drv, pending, clients, .. } = self;
        let mut provision = None;
        drv.reap(&mut |tag, status| {
            if tag == u64::MAX {
                // Provisioning is serialized by l4h-root. Keep its result
                // outside the IPC buffer: the driver may still invoke the
                // kernel after this callback (e.g. a legacy SCSI retry).
                provision = Some(status);
                return;
            }
            finish(&mut pending[..], &mut clients[..], (tag >> 1) as usize, status);
        });
        provision
    }

    /// Start the carried piece if the device has room: whether it did.
    fn start_carry(&mut self) -> bool {
        if self.carry.is_none() || !self.drv.can_start() { return false; }
        let c = self.carry.take().unwrap();
        let r = self.drv.start((c.t as u64) << 1 | 1, c.unit, c.op, c.sector, &c.segs);
        if let Err(status) = r { finish(&mut self.pending[..], &mut self.clients[..], c.t, status); }
        r.is_ok()
    }

    fn submit(&mut self) {
        let mut groups = [ArrayVec::new(), ArrayVec::new()];
        let mut started = self.start_carry();
        // Bounded work per client and round-robin starting point. A busy
        // ring cannot occupy every hardware slot before others get a turn.
        let n = self.active.len();
        for _round in 0..blk::RING_SIZE / 4 {
            for off in 0..n {
                let i = self.active[(self.next + off) % n];
                let Some(c) = self.clients[i].as_mut() else { continue };
                for _ in 0..4 {
                    if self.carry.is_some() || !self.drv.can_start() { break; }
                    let Some(t) = self.pending.iter().position(Option::is_none) else { break };
                    let req = unsafe {
                        let tail = addr_of!((*c.chan).sq.tail).read_volatile();
                        let head = addr_of!((*c.chan).sq.head).read_volatile();
                        let cq_used = addr_of!((*c.chan).cq.head).read_volatile()
                            .wrapping_sub(addr_of!((*c.chan).cq.tail).read_volatile()) as usize;
                        // Reserve completion space for every in-flight request.
                        if head == tail || head.wrapping_sub(tail) as usize > blk::RING_SIZE
                            || cq_used.saturating_add(c.outstanding) >= blk::RING_SIZE { break; }
                        fence(Ordering::Acquire);
                        let req = addr_of!((*c.chan).reqs[tail as usize % blk::RING_SIZE]).read_volatile();
                        addr_of_mut!((*c.chan).sq.tail).write_volatile(tail.wrapping_add(1));
                        req
                    };
                    let dev = &self.dev[c.unit];
                    let (sectors, n) = match c.prepare(&req, dev.block_size, &mut groups) {
                        Ok((_, 0)) if !dev.flush => {
                            c.respond(req.id, blk::STATUS_OK);
                            continue;
                        }
                        Ok(p) => p,
                        Err(status) => {
                            c.respond(req.id, status);
                            continue;
                        }
                    };
                    // A flush is one device request without data.
                    if let Err(status) = self.drv.start((t as u64) << 1, c.unit, req.op, sectors[0], &groups[0]) {
                        c.respond(req.id, status);
                        continue;
                    }
                    self.pending[t] = Some(Pending { client: i, id: req.id, left: n.max(1) as u8, status: blk::STATUS_OK });
                    c.outstanding += 1;
                    started = true;
                    if n == 2 {
                        let segs = core::mem::replace(&mut groups[1], ArrayVec::new());
                        let carry = Carry { t, unit: c.unit, op: req.op, sector: sectors[1], segs };
                        if !self.drv.can_start() {
                            self.carry = Some(carry);
                        } else if let Err(status) = self.drv.start((t as u64) << 1 | 1, c.unit, req.op, carry.sector, &carry.segs) {
                            // The first piece is still in flight.
                            let p = self.pending[t].as_mut().unwrap();
                            (p.status, p.left) = (status, 1);
                        }
                    }
                }
            }
        }
        self.next = if n == 0 { 0 } else { (self.next + 1) % n };
        if started { self.drv.kick(); }
    }

    fn deadline(&self) -> u64 { host::ticks::now().saturating_add(5 * self.ticks_per_sec) }

    fn remove(&mut self, i: usize) -> u64 {
        if i >= self.clients.len() { return u64::MAX; }
        // Stop consuming this channel first. Polling the hardware drains
        // only submitted work; no controller reset disrupts other clients.
        let end = self.deadline();
        while self.clients[i].as_ref().is_some_and(|c| c.outstanding != 0) {
            if self.start_carry() { self.drv.kick(); }
            self.reap();
            if host::ticks::now() > end { return u64::MAX; }
            core::hint::spin_loop();
        }
        self.clients[i] = None;
        self.active.retain(|&a| a != i);
        0
    }

    /// A blk::STATUS_* (u64::MAX: the device failed), or the errno the
    /// range is refused with.
    fn provision(&mut self, cfg: &BlkdConfig, unit: usize, sector: u64, len: usize, flush: bool) -> Result<u64, u64> {
        let Some(&dev) = self.dev.get(unit) else { return Ok(u64::MAX) };
        if dev.read_only { return Err(blk::EPERM); }
        if !flush {
            // Whole 4 KiB blocks, which every block size divides.
            let w = blk::DiskWindow::new(sector, (len / 512) as u64, dev.capacity)
                .filter(|_| len != 0 && len <= blk::STAGING_SIZE && len % 4096 == 0).ok_or(blk::EINVAL)?;
            if !self.reserved.unattached(&holds(&self.clients[..]), unit, w) { return Err(blk::EBUSY); }
        }
        if flush && !dev.flush { return Ok(blk::STATUS_OK as u64); }
        let end = self.deadline();
        while !self.drv.can_start() {
            self.reap();
            if host::ticks::now() > end { return Ok(u64::MAX); }
        }
        let data = [Seg { pa: cfg.dma_paddr + cfg.dma_size, len: len as u32 }];
        let result = self.drv.start(u64::MAX, unit, if flush { blk::OP_FLUSH } else { blk::OP_WRITE },
            sector, if flush { &[] } else { &data });
        if let Err(status) = result { return Ok(status as u64); }
        self.drv.kick();
        loop {
            if let Some(status) = self.reap() { return Ok(status as u64); }
            if host::ticks::now() > end { return Ok(u64::MAX); }
            core::hint::spin_loop();
        }
    }

    /// Build the disk a client of `unit` would get, the window `start`,
    /// `sectors` (0: to the end) or the n extents in staging, into `order`
    /// and `extents`: the slot it may attach in, the disk and whether it is
    /// read-only, or the errno it is refused with.
    #[allow(clippy::too_many_arguments)]
    fn check<'a>(&self, cfg: &BlkdConfig, unit: usize, start: u64, sectors: u64, n: usize, read_only: bool, dom0: bool,
        order: &'a mut [u16], extents: &'a mut [blk::Extent]) -> Result<(usize, blk::Volume<'a>, bool), u64> {
        let dev = self.dev.get(unit).ok_or(blk::EINVAL)?;
        let read_only = read_only || dev.read_only;
        let vol = if n == 0 {
            let w = blk::DiskWindow::new(start, sectors, dev.capacity).ok_or(blk::EINVAL)?;
            blk::Volume::build(core::iter::once((w.start, w.sectors)), &mut order[..1], &mut extents[..1], dev.capacity)?
        } else {
            if n > blk::MAX_EXTENTS { return Err(blk::EINVAL); }
            // Each pair is read once, into `extents`, before it is checked.
            let staging = (cfg.dma_va + cfg.dma_size) as *const [u64; 2];
            let raw = (0..n).map(|k| unsafe { staging.add(k).read_volatile() }).map(|[s, c]| (s, c));
            blk::Volume::build(raw, &mut order[..n], &mut extents[..n], dev.capacity)?
        };
        let hold = blk::Hold { unit, extents: vol.extents, read_only };
        Ok((self.reserved.slot(&holds(&self.clients[..]), &hold, dom0)?, vol, read_only))
    }
}

fn mr(i: usize) -> u64 { sel4::with_ipc_buffer(|b| b.msg_regs()[i]) }
fn set_mr(i: usize, v: u64) { sel4::with_ipc_buffer_mut(|b| b.msg_regs_mut()[i] = v); }

fn main(info: &'static Info) -> ! {
    let cfg: &BlkdConfig = unsafe { info.config() };
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
        // The only reference to RESERVED.
        reserved: unsafe { &mut *addr_of_mut!(RESERVED) },
        active: ArrayVec::new(),
        pending: [None; MAX_INFLIGHT],
        carry: None,
        drv, dev, next: 0, ticks_per_sec: info.header().tsc_hz,
    };
    // The only references to the scratch table.
    let scratch_order = unsafe { &mut *addr_of_mut!(SCRATCH_ORDER) };
    let scratch_extents = unsafe { &mut *addr_of_mut!(SCRATCH_EXTENTS) };
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
                let (i, unit, dom0, n) = (mr(0) as usize, mr(1) as usize, mr(2) != 0, mr(3) as usize);
                if i >= blk::MAX_CLIENTS || b.clients[i].is_some() || unit >= b.dev.len() || n > blk::MAX_EXTENTS { u64::MAX } else {
                    let dev = b.dev[unit];
                    let chan = blk::channel_va(i) as *mut Channel;
                    let (start, count, ro, pool) = unsafe {
                        (addr_of!((*chan).lba_start).read_volatile(), addr_of!((*chan).capacity_sectors).read_volatile(),
                         addr_of!((*chan).read_only).read_volatile(), addr_of!((*chan).pool).read_volatile())
                    };
                    // Root mapped table_pages(n.max(1)) of the client's
                    // table for blkd alone; they stay until BLKD_REMOVE.
                    let table = blk::extent_va(i) as *mut blk::ExtentTable;
                    let (order, extents) = unsafe {
                        (core::slice::from_raw_parts_mut(addr_of_mut!((*table).order).cast(), n.max(1)),
                         core::slice::from_raw_parts_mut(addr_of_mut!((*table).extents).cast(), n.max(1)))
                    };
                    // Exactly what BLKD_CHECK allowed: root serializes
                    // checks and attachments.
                    match b.check(cfg, unit, start, count, n, ro != 0, dom0, order, extents) {
                        Ok((slot, vol, read_only)) if slot == i => {
                            b.clients[i] = Some(Client { chan, unit, pool, vol, read_only,
                                done: cap::<cap_type::Notification>(blk::BLKD_SLOT_CLIENT_DONE + i as u64), outstanding: 0 });
                            // Not attached yet, so not in active.
                            let _ = b.active.push(i);
                            unsafe {
                                addr_of_mut!((*chan).capacity_sectors).write_volatile(vol.sectors());
                                addr_of_mut!((*chan).read_only).write_volatile(read_only as u32);
                                addr_of_mut!((*chan).block_size).write_volatile(dev.block_size);
                                fence(Ordering::Release);
                                addr_of_mut!((*chan).ready).write_volatile(1);
                            }
                            0
                        }
                        _ => u64::MAX,
                    }
                }
            }
            blk::BLKD_REMOVE => b.remove(mr(0) as usize),
            blk::BLKD_RESERVE => {
                // Boot ranges may lie beyond an unknown or unaligned
                // capacity: they keep sectors from others, never address them.
                match blk::DiskWindow::new(mr(1), mr(2), u64::MAX & !7) {
                    Some(window) if mr(2) != 0 && (mr(0) as usize) < blk::MAX_UNITS => {
                        let r = blk::Reserved { unit: mr(0) as usize, window, read_only: mr(3) != 0 };
                        b.reserved.reserve(&holds(&b.clients[..]), r).map_or(u64::MAX, |i| i as u64)
                    }
                    _ => u64::MAX,
                }
            }
            blk::BLKD_CHECK => {
                let (order, extents) = (&mut *scratch_order, &mut *scratch_extents);
                match b.check(cfg, mr(0) as usize, mr(1), mr(2), mr(5) as usize, mr(3) != 0, mr(4) != 0, order, extents) {
                    Ok((slot, vol, read_only)) => {
                        response[1] = slot as u64;
                        response[2] = vol.sectors();
                        response[3] = read_only as u64;
                        0
                    }
                    Err(errno) => errno,
                }
            }
            blk::BLKD_EXTENT => match b.clients.get(mr(0) as usize).and_then(|c| c.as_ref()?.vol.nth(mr(1) as usize)) {
                Some(e) => {
                    response[1] = e.start;
                    response[2] = e.sectors;
                    0
                }
                None => u64::MAX,
            },
            blk::BLKD_WRITE | blk::BLKD_FLUSH => {
                let flush = msg.label() == blk::BLKD_FLUSH;
                let r = if flush { b.provision(cfg, mr(0) as usize, 0, 0, true) }
                    else { b.provision(cfg, mr(2) as usize, mr(0), mr(1) as usize, false) };
                r.unwrap_or_else(|errno| {
                    response[1] = errno;
                    blk::BLKD_REFUSED
                })
            }
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

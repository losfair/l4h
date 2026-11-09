//! blkd: drives one disk controller (virtio-blk, virtio-scsi or NVMe PCI
//! device) for multiple clients (a guest's l4h-vmm).  A virtio-scsi
//! controller has a unit per logical unit; the others have one.  A client's
//! disk is a window of a unit or a list of extents of one (blk::Volume).
//! Requests carry guest-physical segments, which are validated against the
//! client's I/O pool and its disk, mapped to one or two device requests and
//! handed to the device by physical address: the device reads and writes
//! the pool directly, never guest RAM (the guest bounces through the pool
//! with swiotlb).  blkd alone decides which clients may use which sectors
//! (blk::Reservations); l4h-root asks with `blk::call::check`.  See DESIGN.md §9.2.

#![no_std]
#![no_main]

mod nvme;
mod scsi;
mod virtio;

use core::ops::{Deref, DerefMut};
use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{Ordering, fence};

use l4h_rt::host::errno::{self, Errno};
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
    /// Where the unit is on its controller (blk::PublishedUnit).
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
    /// Flushes complete at once (l4h_abi::BLK_VOLATILE).
    volatile: bool,
    done: sel4::cap::Notification,
    outstanding: usize,
    notify_pending: bool,
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
/// Where `check` builds the disk it checks.
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
    fn respond(&mut self, id: u64, status: u32) {
        unsafe {
            let h = addr_of!((*self.chan).cq.head).read_volatile();
            addr_of_mut!((*self.chan).resps[h as usize % blk::RING_SIZE])
                .write_volatile(blk::Resp { id, status, reserved: 0 });
            fence(Ordering::Release);
            addr_of_mut!((*self.chan).cq.head).write_volatile(h.wrapping_add(1));
        }
        self.notify_pending = true;
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
    fn notify_completions(&mut self) {
        for &i in &self.active {
            if let Some(c) = self.clients[i].as_mut() {
                if core::mem::take(&mut c.notify_pending) { c.done.signal(); }
            }
        }
    }

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
        self.notify_completions();
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
            let mut progress = false;
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
                    progress = true;
                    let dev = &self.dev[c.unit];
                    let (sectors, n) = match c.prepare(&req, dev.block_size, &mut groups) {
                        // A flush the device or the attachment does not need.
                        Ok((_, 0)) if !dev.flush || c.volatile => {
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
            if !progress { break; }
        }
        self.next = if n == 0 { 0 } else { (self.next + 1) % n };
        if started { self.drv.kick(); }
        self.notify_completions();
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
    fn provision(&mut self, cfg: &BlkdConfig, unit: usize, sector: u64, len: usize, flush: bool) -> Result<u64, Errno> {
        let Some(&dev) = self.dev.get(unit) else { return Ok(u64::MAX) };
        if dev.read_only { return Err(errno::EPERM); }
        if !flush {
            // Whole 4 KiB blocks, which every block size divides.
            let w = blk::DiskWindow::new(sector, (len / 512) as u64, dev.capacity)
                .filter(|_| len != 0 && len <= blk::STAGING_SIZE && len % 4096 == 0).ok_or(errno::EINVAL)?;
            if !self.reserved.unattached(&holds(&self.clients[..]), unit, w) { return Err(errno::EBUSY); }
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
        let dev = self.dev.get(unit).ok_or(errno::EINVAL)?;
        let read_only = read_only || dev.read_only;
        let vol = if n == 0 {
            let w = blk::DiskWindow::new(start, sectors, dev.capacity).ok_or(errno::EINVAL)?;
            blk::Volume::build(core::iter::once((w.start, w.sectors)), &mut order[..1], &mut extents[..1], dev.capacity)?
        } else {
            if n > blk::MAX_EXTENTS { return Err(errno::EINVAL); }
            // Each pair is read once, into `extents`, before it is checked.
            let staging = (cfg.dma_va + cfg.dma_size) as *const [u64; 2];
            let raw = (0..n).map(|k| unsafe { staging.add(k).read_volatile() }).map(|[s, c]| (s, c));
            blk::Volume::build(raw, &mut order[..n], &mut extents[..n], dev.capacity)?
        };
        let hold = blk::Hold { unit, extents: vol.extents, read_only };
        Ok((self.reserved.slot(&holds(&self.clients[..]), &hold, dom0)?, vol, read_only))
    }
}

/// Root's requests, as l4h_host::blk::call declares them.  Arguments and
/// answers never pass through the message registers, which legacy virtio
/// kicks (IOPort invocations) overwrite.
struct Requests<'a> {
    b: &'a mut Blkd,
    cfg: &'a BlkdConfig,
    order: &'a mut [u16; blk::MAX_EXTENTS],
    extents: &'a mut [blk::Extent; blk::MAX_EXTENTS],
}

impl blk::call::Server for Requests<'_> {
    fn add(&mut self, _: blk::Sender, i: usize, unit: usize, dom0: bool, n: usize) -> Result<(), Errno> {
        let b = &mut *self.b;
        if i >= blk::MAX_CLIENTS || b.clients[i].is_some() || unit >= b.dev.len() || n > blk::MAX_EXTENTS {
            return Err(errno::EINVAL);
        }
        let dev = b.dev[unit];
        let chan = blk::channel_va(i) as *mut Channel;
        let (start, count, ro, volatile, pool) = unsafe {
            (addr_of!((*chan).lba_start).read_volatile(), addr_of!((*chan).capacity_sectors).read_volatile(),
             addr_of!((*chan).read_only).read_volatile(), addr_of!((*chan).volatile).read_volatile() != 0,
             addr_of!((*chan).pool).read_volatile())
        };
        // Root mapped table_pages(n.max(1)) of the client's table for blkd
        // alone; they stay until `remove`.
        let table = blk::extent_va(i) as *mut blk::ExtentTable;
        let (order, extents) = unsafe {
            (core::slice::from_raw_parts_mut(addr_of_mut!((*table).order).cast(), n.max(1)),
             core::slice::from_raw_parts_mut(addr_of_mut!((*table).extents).cast(), n.max(1)))
        };
        // Exactly what `check` allowed: root serializes checks and
        // attachments.
        match b.check(self.cfg, unit, start, count, n, ro != 0, dom0, order, extents) {
            Ok((slot, vol, read_only)) if slot == i => {
                b.clients[i] = Some(Client { chan, unit, pool, vol, read_only, volatile,
                    done: cap::<cap_type::Notification>(blk::BLKD_SLOT_CLIENT_DONE + i as u64), outstanding: 0, notify_pending: false });
                // Not attached yet, so not in active.
                let _ = b.active.push(i);
                unsafe {
                    addr_of_mut!((*chan).capacity_sectors).write_volatile(vol.sectors());
                    addr_of_mut!((*chan).read_only).write_volatile(read_only as u32);
                    addr_of_mut!((*chan).block_size).write_volatile(dev.block_size);
                    fence(Ordering::Release);
                    addr_of_mut!((*chan).ready).write_volatile(1);
                }
                Ok(())
            }
            _ => Err(errno::EINVAL),
        }
    }

    fn remove(&mut self, _: blk::Sender, client: usize) -> Result<(), Errno> {
        if self.b.remove(client) == 0 { Ok(()) } else { Err(errno::EBUSY) }
    }

    fn write(&mut self, _: blk::Sender, sector: u64, length: usize, unit: usize) -> Result<u64, Errno> {
        self.b.provision(self.cfg, unit, sector, length, false)
    }

    fn flush(&mut self, _: blk::Sender, unit: usize) -> Result<u64, Errno> {
        self.b.provision(self.cfg, unit, 0, 0, true)
    }

    fn reserve(&mut self, _: blk::Sender, unit: usize, start: u64, sectors: u64, read_only: bool) -> Result<usize, Errno> {
        // Boot ranges may lie beyond an unknown or unaligned capacity:
        // they keep sectors from others, never address them.
        match blk::DiskWindow::new(start, sectors, u64::MAX & !7) {
            Some(window) if sectors != 0 && unit < blk::MAX_UNITS => {
                let r = blk::Reserved { unit, window, read_only };
                let b = &mut *self.b;
                b.reserved.reserve(&holds(&b.clients[..]), r)
            }
            _ => Err(errno::EINVAL),
        }
    }

    fn check(&mut self, _: blk::Sender, unit: usize, start: u64, sectors: u64, read_only: bool, dom0: bool, n: usize)
        -> Result<blk::Checked, Errno> {
        let (slot, vol, read_only) = self.b.check(self.cfg, unit, start, sectors, n, read_only, dom0, self.order, self.extents)?;
        Ok(blk::Checked { slot, sectors: vol.sectors(), read_only })
    }

    fn extent(&mut self, _: blk::Sender, client: usize, k: usize) -> Result<(u64, u64), Errno> {
        let e = self.b.clients.get(client).and_then(|c| c.as_ref()?.vol.nth(k)).ok_or(errno::EINVAL)?;
        Ok((e.start, e.sectors))
    }

    fn test_hang(&mut self, _: blk::Sender) -> Result<(), Errno> {
        if host::TEST_INJECT {
            l4h_rt::test_hang();
        }
        Err(errno::EINVAL)
    }
}

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
    // Root reads the units here, and asks nothing before.
    let published = l4h_rt::mailbox::published::<blk::Published>();
    for (u, d) in b.dev.iter().enumerate() {
        let p = &published.unit[u];
        p.capacity.store(d.capacity, Ordering::Relaxed);
        p.block_size.store(d.block_size as u64, Ordering::Relaxed);
        p.read_only.store(d.read_only as u64, Ordering::Relaxed);
        p.address.store(d.address, Ordering::Relaxed);
    }
    published.units.store(b.dev.len() as u64, Ordering::Relaxed);
    published.ready.store(1, Ordering::Release);
    l4h_rt::mailbox::signal();
    let (_, mut badge) = ep.recv(reply);
    loop {
        b.reap();
        b.submit();
        if badge & host::badges::blkd::IRQ != 0 { irq.irq_handler_ack().expect("blkd IRQ ack"); }
        // Root's requests (host::mailbox), even if their signal was
        // coalesced.
        let answered = l4h_rt::mailbox::serve(|label, args, out| {
            let mut req = Requests { b: &mut b, cfg, order: &mut *scratch_order, extents: &mut *scratch_extents };
            let n = blk::call::serve(&mut req, label, args, blk::Sender::Root, out);
            // Service calls can have reaped completions while polling. A kick
            // may have been coalesced, so always revisit all pending channels.
            b.submit();
            n
        });
        if answered { l4h_rt::mailbox::signal(); }
        (_, badge) = ep.recv(reply);
    }
}

l4h_rt::component!(main, no_heap);

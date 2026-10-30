//! blkd <-> client (l4h-vmm) block request queue.
//!
//! A channel is one shared region: a header, a submission ring and a
//! completion ring of fixed-size entries.  Data is never copied here:
//! requests carry guest-physical segments, which blkd validates against
//! the client's I/O pool (configured by l4h-root) and translates for DMA.
//! Guest RAM is never a DMA target.

pub const MAX_SEGS: usize = 16;
pub const RING_SIZE: usize = 128;

pub const OP_READ: u32 = 0;
pub const OP_WRITE: u32 = 1;
pub const OP_FLUSH: u32 = 4;
pub const OP_DISCARD: u32 = 11;
pub const OP_WRITE_ZEROES: u32 = 13;
pub const OP_GET_ID: u32 = 8;

pub const STATUS_OK: u32 = 0;
pub const STATUS_IOERR: u32 = 1;
pub const STATUS_UNSUPP: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Seg {
    pub gpa: u64,
    pub len: u32,
    /// SEG_WRITE: the device writes this segment (reads from the disk).
    pub flags: u32,
}

pub const SEG_WRITE: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Req {
    pub id: u64,
    pub op: u32,
    pub nr_segs: u32,
    pub sector: u64,
    pub segs: [Seg; MAX_SEGS],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Resp {
    pub id: u64,
    pub status: u32,
    pub reserved: u32,
}

/// Single-producer single-consumer ring indices.  `head` is written by the
/// producer, `tail` by the consumer; both increase monotonically.
#[repr(C)]
pub struct RingIdx {
    pub head: u32,
    pub pad0: [u32; 15],
    pub tail: u32,
    pub pad1: [u32; 15],
}

#[repr(C)]
pub struct Channel {
    pub sq: RingIdx,
    pub cq: RingIdx,
    /// Written by blkd before it sets `ready`.
    pub capacity_sectors: u64,
    pub read_only: u32,
    pub ready: u32,
    /// Logical block size in bytes (512 or 4096); requests must be aligned.
    pub block_size: u32,
    pub reserved: [u32; 11],
    /// Written by l4h-root before BLKD_ADD; copied into private driver state.
    pub lba_start: u64,
    pub pool: Pool,
    pub reqs: [Req; RING_SIZE],
    pub resps: [Resp; RING_SIZE],
}

/// Notification badges of blkd: the client kicked the channel, the device
/// interrupted.
pub const BLKD_BADGE_KICK: u64 = 1 << 0;
pub const BLKD_BADGE_IRQ: u64 = 1 << 1;

/// blkd CSpace slots (beyond the common ones).
pub const BLKD_SLOT_IRQ: u64 = 16;
/// I/O port capability of a legacy virtio device (BlkdConfig::legacy_io).
pub const BLKD_SLOT_IOPORT: u64 = 17;
/// Notification of the client, badged with its "done" bit.
pub const BLKD_SLOT_CLIENT_DONE: u64 = 32;
/// Attachments per disk: a node's sandboxes each take one or two windows of
/// a disk, and read-only windows may be shared by many.
pub const MAX_CLIENTS: usize = 512;
pub const CHANNEL_PAGES: usize = core::mem::size_of::<Channel>().div_ceil(4096);
pub const STAGING_SIZE: usize = 1 << 20;
/// Service calls of blkd (message registers; the result is in MR 0).
/// unit -> capacity (u64::MAX if no such unit), block size, read-only,
/// number of units, unit address (blkd_scsi_addr for virtio-scsi, else 0).
pub const BLKD_INFO: u64 = 1;
/// client, unit, dom0, n -> 0: what BLKD_CHECK allowed in that slot, the
/// channel's window (n = 0) or the n extents in staging.  blkd builds the
/// client's ExtentTable at extent_va(client).
pub const BLKD_ADD: u64 = 2;
/// client -> 0, or u64::MAX if it did not drain
pub const BLKD_REMOVE: u64 = 3;
/// sector, length, unit -> blk::STATUS_*, or u64::MAX
pub const BLKD_WRITE: u64 = 4;
/// unit -> blk::STATUS_*, or u64::MAX
pub const BLKD_FLUSH: u64 = 5;
/// unit, start, sectors, read-only -> slot of the dom0 boot range, or
/// u64::MAX (conflicting or no slot).  Before anything attaches.
pub const BLKD_RESERVE: u64 = 6;
/// unit, start, sectors (0 = to the end), read-only, dom0, n -> 0 or an
/// errno (EINVAL, EBUSY, ENOSPC); then the slot BLKD_ADD must use, the
/// guest disk's sectors and whether it is read-only.  With n > 0 the disk
/// is the n extents in staging, (start, sectors) pairs in guest order,
/// instead of the window.  Changes nothing.
pub const BLKD_CHECK: u64 = 7;
/// client, k -> 0 and the start and sectors of its kth extent in guest
/// order, or u64::MAX if it has none.
pub const BLKD_EXTENT: u64 = 8;
/// BLKD_WRITE and BLKD_FLUSH refused the range: MR1 is the errno.
pub const BLKD_REFUSED: u64 = u64::MAX - 1;

/// Errnos of blkd's range decisions, as the control API returns them.
pub const EPERM: u64 = 1;
pub const EBUSY: u64 = 16;
pub const EINVAL: u64 = 22;
pub const ENOSPC: u64 = 28;
/// Units per controller, at most.
pub const MAX_UNITS: usize = 16;

/// A virtio-scsi unit address: target and LUN.
pub const fn blkd_scsi_addr(target: u8, lun: u16) -> u64 {
    target as u64 | (lun as u64) << 8
}

/// Client channels have their own range: SHARED_VA holds other mappings
/// (e.g. the console ring 8 MiB in).
pub const CHANNEL_VA: usize = 0x2800_0000_0000;
pub const CHANNEL_STRIDE: usize = 0x20000;
const _: () = assert!(CHANNEL_PAGES * 4096 <= CHANNEL_STRIDE);

pub const fn channel_va(client: usize) -> usize {
    CHANNEL_VA + client * CHANNEL_STRIDE
}

/// A virtio-pci structure: BAR-relative location, mapped by l4h-root.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct PciRegion {
    pub va: u64,
    pub len: u64,
}

pub const BLKD_VIRTIO: u32 = 0;
pub const BLKD_NVME: u32 = 1;
pub const BLKD_VIRTIO_SCSI: u32 = 2;

/// Configuration of one persistent physical-controller driver.
#[repr(C)]
pub struct BlkdConfig {
    pub kind: u32,
    /// Legacy virtio device: base of its I/O BAR 0, reached with the
    /// capability in BLKD_SLOT_IOPORT; 0 for a modern device.
    pub legacy_io: u32,
    /// NVMe: BAR0 (controller registers and doorbells).
    pub bar0: PciRegion,
    pub pci_bdf: u32,
    /// MSI data of MSI-X table entry 0 (the queue interrupt).
    pub msi_data: u32,
    pub msi_address: u64,
    pub common: PciRegion,
    pub notify: PciRegion,
    pub notify_off_multiplier: u32,
    pub reserved0: u32,
    pub isr: PciRegion,
    pub device: PciRegion,
    pub msix_table: PciRegion,
    /// DMA memory: physically contiguous, mapped at dma_va.
    pub dma_va: u64,
    pub dma_paddr: u64,
    pub dma_size: u64,

}

/// The data region of a client: segments must lie in its I/O pool, and are
/// translated with one offset.  Shared with tests/fuzz-virtq.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Pool {
    pub gpa: u64,
    pub paddr: u64,
    pub size: u64,
}

impl Pool {
    /// The physical address of guest-physical [gpa, gpa + len), if it lies
    /// in the pool (len > 0).
    pub fn translate(&self, gpa: u64, len: u64) -> Option<u64> {
        let off = gpa.checked_sub(self.gpa)?;
        let end = off.checked_add(len)?;
        if len > 0 && end <= self.size { self.paddr.checked_add(off) } else { None }
    }
}

/// A checked, finite, 4 KiB aligned window in 512-byte sectors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiskWindow {
    pub start: u64,
    pub sectors: u64,
}

impl DiskWindow {
    pub fn new(start: u64, sectors: u64, capacity: u64) -> Option<Self> {
        let sectors = if sectors == 0 { capacity.checked_sub(start)? } else { sectors };
        (start % 8 == 0 && sectors > 0 && sectors % 8 == 0
            && start.checked_add(sectors)? <= capacity).then_some(Self { start, sectors })
    }

    /// Explicit partition ranges, in 512-byte sectors: start:count,... .
    /// Invalid input never expands a range to the rest of the disk.
    pub fn parse_list<const N: usize>(text: &str, capacity: u64) -> Option<([Self; N], usize)> {
        let mut windows = [Self { start: 0, sectors: 0 }; N];
        let mut len = 0;
        for entry in text.split(',') {
            if len == N { return None; }
            let (start, sectors) = entry.split_once(':')?;
            let start = start.parse::<u64>().ok()?;
            let sectors = sectors.parse::<u64>().ok()?;
            if sectors == 0 { return None; }
            let window = Self::new(start, sectors, capacity)?;
            if windows[..len].iter().any(|w| window.overlaps(*w)) { return None; }
            windows[len] = window;
            len += 1;
        }
        Some((windows, len))
    }

    pub fn overlaps(self, other: Self) -> bool {
        self.start < other.start + other.sectors && other.start < self.start + self.sectors
    }

    /// Whether a window may not be attached next to `other`: they overlap
    /// and either can write. Read-only windows may share sectors, e.g. one
    /// system image used by many guests.
    pub fn conflicts(self, read_only: bool, other: Self, other_read_only: bool) -> bool {
        self.overlaps(other) && !(read_only && other_read_only)
    }
}

impl DiskWindow {
    /// Validate a snapshotted request before it reaches a hardware driver.
    /// Both the window and pool come from l4h-root, never from the guest.
    pub fn check_request(self, req: &Req, pool: Pool, block_size: u32, read_only: bool) -> Result<u64, u32> {
        if req.nr_segs as usize > MAX_SEGS || !matches!(block_size, 512 | 4096) {
            return Err(STATUS_IOERR);
        }
        let device_writes = match req.op {
            OP_READ => true,
            OP_WRITE if !read_only => false,
            OP_FLUSH if req.nr_segs == 0 => return Ok(0),
            _ => return Err(STATUS_IOERR),
        };
        let segs = &req.segs[..req.nr_segs as usize];
        let bytes: u64 = segs.iter().map(|s| s.len as u64).sum();
        let sector = self.start.checked_add(req.sector).ok_or(STATUS_IOERR)?;
        if bytes == 0 || bytes % block_size as u64 != 0 || sector % (block_size as u64 / 512) != 0
            || req.sector.checked_add(bytes / 512).is_none_or(|end| end > self.sectors) {
            return Err(STATUS_IOERR);
        }
        for seg in segs {
            if seg.flags & !SEG_WRITE != 0 || (seg.flags & SEG_WRITE != 0) != device_writes
                || pool.translate(seg.gpa, seg.len as u64).is_none() {
                return Err(STATUS_IOERR);
            }
        }
        Ok(sector)
    }
}

/// A 4 KiB aligned physical range of a unit, in 512-byte sectors, and
/// where it starts in its guest's disk.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Extent {
    pub start: u64,
    pub sectors: u64,
    pub offset: u64,
}

impl Extent {
    fn end(&self) -> u64 { self.start + self.sectors }
}

/// Extents of one guest disk.  LVM has no small limit: a long-lived LV
/// that was extended many times has hundreds of segments.
pub const MAX_EXTENTS: usize = 4096;
/// Every extent of a disk with more than one is at least this long (4 MiB,
/// LVM's default physical extent).  A request is at most 3.5 MiB
/// (l4h-vmm's SEG_MAX * SEG_SIZE_LIMIT), so it crosses at most one
/// boundary.
pub const MIN_EXTENT_SECTORS: u64 = 8192;

/// A client's extent table, built by blkd at extent_va(client) in frames
/// only blkd maps: the extents sorted by start, and their indices in guest
/// order.  Only the pages holding the first n entries of each are mapped
/// (table_pages).
#[repr(C)]
pub struct ExtentTable {
    pub n: u32,
    pub reserved: u32,
    pub order: [u16; MAX_EXTENTS],
    pub extents: [Extent; MAX_EXTENTS],
}

pub const EXTENT_VA: usize = 0x2c00_0000_0000;
pub const EXTENT_STRIDE: usize = 0x20000;
const _: () = assert!(core::mem::size_of::<ExtentTable>() <= EXTENT_STRIDE);

pub const fn extent_va(client: usize) -> usize {
    EXTENT_VA + client * EXTENT_STRIDE
}

/// The pages of an ExtentTable that hold n entries: two runs, the second
/// starting where the first ends at the earliest.
pub fn table_pages(n: usize) -> [core::ops::Range<usize>; 2] {
    let order = core::mem::offset_of!(ExtentTable, order) + 2 * n;
    let extents = core::mem::offset_of!(ExtentTable, extents);
    let first = 0..order.div_ceil(4096);
    let second = (extents / 4096).max(first.end)..(extents + 24 * n).div_ceil(4096);
    [first, second]
}

/// Up to two pieces of one request, in different extents: (device sector,
/// bytes), and how many there are.
pub type Pieces = ([(u64, u64); 2], usize);

/// A guest disk: `extents` sorted by start, `order` their indices in guest
/// order.  Checked with `check` before anything reads it as a disk.
#[derive(Clone, Copy)]
pub struct Volume<'a> {
    pub order: &'a [u16],
    pub extents: &'a [Extent],
}

impl<'a> Volume<'a> {
    /// The table at `p`, with `n` entries: none beyond them is read.
    ///
    /// # Safety
    /// The pages table_pages(n) of `p` are mapped and stay so for 'a.
    pub unsafe fn at(p: *const ExtentTable, n: usize) -> Self {
        unsafe {
            Volume {
                order: core::slice::from_raw_parts(core::ptr::addr_of!((*p).order).cast(), n),
                extents: core::slice::from_raw_parts(core::ptr::addr_of!((*p).extents).cast(), n),
            }
        }
    }

    /// Fill `order` and `extents` (as long as `raw`) from `raw`, (start,
    /// sectors) in guest order, and check them against a unit of `capacity`
    /// sectors.  EINVAL if they are no disk.
    pub fn build(raw: impl Iterator<Item = (u64, u64)>, order: &'a mut [u16], extents: &'a mut [Extent],
        capacity: u64) -> Result<Volume<'a>, u64> {
        let mut offset = 0u64;
        for ((e, o), (i, (start, sectors))) in extents.iter_mut().zip(order.iter_mut()).zip(raw.enumerate()) {
            *e = Extent { start, sectors, offset };
            *o = i as u16;
            offset = offset.checked_add(sectors).ok_or(EINVAL)?;
        }
        extents.sort_unstable_by_key(|e| e.start);
        // `order` holds 0..n: sorted by offset, it is the guest order.
        order.sort_unstable_by_key(|&o| extents[o as usize].offset);
        let v = Volume { order, extents };
        v.check(capacity)?;
        Ok(v)
    }

    /// Whether this is a disk on a unit of `capacity` sectors: 1 to
    /// MAX_EXTENTS extents, each a valid window and, if there are several,
    /// at least MIN_EXTENT_SECTORS; sorted and disjoint; and each extent in
    /// `order` starting where the one before it ends.
    pub fn check(&self, capacity: u64) -> Result<(), u64> {
        let (n, e) = (self.extents.len(), self.extents);
        let ok = (1..=MAX_EXTENTS).contains(&n) && self.order.len() == n
            && e.iter().all(|x| DiskWindow::new(x.start, x.sectors, capacity).is_some_and(|w| w.sectors == x.sectors)
                && (n == 1 || x.sectors >= MIN_EXTENT_SECTORS))
            && e.windows(2).all(|w| w[0].end() <= w[1].start)
            && self.order.iter().all(|&o| (o as usize) < n)
            && e[self.order[0] as usize].offset == 0
            && self.order.windows(2).all(|w| {
                let (a, b) = (&e[w[0] as usize], &e[w[1] as usize]);
                a.offset.checked_add(a.sectors) == Some(b.offset)
            });
        // Offsets grow strictly along `order`, so no index repeats.
        if ok && self.last().offset.checked_add(self.last().sectors).is_some() { Ok(()) } else { Err(EINVAL) }
    }

    fn last(&self) -> &Extent { &self.extents[self.order[self.order.len() - 1] as usize] }

    /// Guest sectors.
    pub fn sectors(&self) -> u64 { self.last().offset + self.last().sectors }

    /// The extent that is `k`th in guest order.
    pub fn nth(&self, k: usize) -> Option<Extent> {
        self.order.get(k).map(|&o| self.extents[o as usize])
    }

    /// Validate a snapshotted request (as DiskWindow::check_request) and
    /// map it to the device: one piece, or two if it crosses an extent
    /// boundary.  A request that would need more fails.  A flush has none.
    pub fn map(&self, req: &Req, pool: Pool, block_size: u32, read_only: bool) -> Result<Pieces, u32> {
        let whole = DiskWindow { start: 0, sectors: self.sectors() };
        let g = whole.check_request(req, pool, block_size, read_only)?;
        if req.op == OP_FLUSH { return Ok(([(0, 0); 2], 0)); }
        let bytes: u64 = req.segs[..req.nr_segs as usize].iter().map(|s| s.len as u64).sum();
        let k = self.order.partition_point(|&o| self.extents[o as usize].offset <= g) - 1;
        let e = self.nth(k).unwrap();
        let first = bytes.min((e.offset + e.sectors - g) * 512);
        let mut pieces = ([(e.start + (g - e.offset), first), (0, 0)], 1);
        if first < bytes {
            let next = self.nth(k + 1).ok_or(STATUS_IOERR)?;
            if bytes - first > next.sectors * 512 { return Err(STATUS_IOERR); }
            pieces.0[1] = (next.start, bytes - first);
            pieces.1 = 2;
        }
        Ok(pieces)
    }
}

/// Whether two lists of extents, each sorted and disjoint, share a sector.
pub fn overlap(a: &[Extent], b: &[Extent]) -> bool {
    let (mut i, mut j) = (0, 0);
    while i < a.len() && j < b.len() {
        if a[i].end() <= b[j].start { i += 1 }
        else if b[j].end() <= a[i].start { j += 1 }
        else { return true }
    }
    false
}

/// What a slot holds of a unit: a client's extents (sorted), or a dom0
/// boot range.
#[derive(Clone, Copy, Debug)]
pub struct Hold<'a> {
    pub unit: usize,
    pub extents: &'a [Extent],
    pub read_only: bool,
}

/// A dom0 boot range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reserved {
    pub unit: usize,
    pub window: DiskWindow,
    pub read_only: bool,
}

/// blkd's record of dom0's boot ranges.  With the attached clients
/// (`active`: what slot i's client holds), it is the one place that
/// decides who may use which sectors; l4h-root only asks.  A reservation
/// lives until host reboot.  Only dom0 can claim it, and only for exactly
/// its range; while unclaimed it occupies its sectors for attachments and
/// provisioning.  Slots are shared with clients: a claim attaches in the
/// reservation's slot.
pub struct Reservations<const N: usize> {
    pub slots: [Option<Reserved>; N],
    /// The slots' ranges as extents, for overlap.
    ranges: [Extent; N],
}

impl<const N: usize> Default for Reservations<N> {
    fn default() -> Self { Self::new() }
}

impl<const N: usize> Reservations<N> {
    pub const fn new() -> Self {
        Self { slots: [None; N], ranges: [Extent { start: 0, sectors: 0, offset: 0 }; N] }
    }

    fn hold(&self, i: usize) -> Option<Hold<'_>> {
        self.slots[i].map(|r| Hold { unit: r.unit, extents: core::slice::from_ref(&self.ranges[i]), read_only: r.read_only })
    }

    fn claimable<'a>(&self, i: usize, active: &impl Fn(usize) -> Option<Hold<'a>>, want: &Hold, dom0: bool) -> bool {
        dom0 && active(i).is_none() && want.extents.len() == 1 && self.slots[i].is_some_and(|r| r.unit == want.unit
            && (r.window.start, r.window.sectors) == (want.extents[0].start, want.extents[0].sectors))
    }

    /// The slot `want` may attach in: EBUSY if it conflicts with a client
    /// or with a reservation it cannot claim, ENOSPC if no slot is free.
    pub fn slot<'a>(&self, active: &impl Fn(usize) -> Option<Hold<'a>>, want: &Hold, dom0: bool) -> Result<usize, u64> {
        let conflicts = |h: &Hold| h.unit == want.unit && !(want.read_only && h.read_only) && overlap(want.extents, h.extents);
        // A claimed reservation is represented by its client.
        let busy = (0..N).any(|i| match active(i) {
            Some(a) => conflicts(&a),
            None => self.hold(i).is_some_and(|r| conflicts(&r) && !self.claimable(i, active, want, dom0)),
        });
        if busy { return Err(EBUSY); }
        (0..N).find(|&i| self.claimable(i, active, want, dom0))
            .or_else(|| (0..N).find(|&i| active(i).is_none() && self.slots[i].is_none()))
            .ok_or(ENOSPC)
    }

    /// Keep `r` (a range of dom0's boot plan) from other users.
    pub fn reserve<'a>(&mut self, active: &impl Fn(usize) -> Option<Hold<'a>>, r: Reserved) -> Result<usize, u64> {
        let range = Extent { start: r.window.start, sectors: r.window.sectors, offset: 0 };
        let want = Hold { unit: r.unit, extents: core::slice::from_ref(&range), read_only: r.read_only };
        let i = self.slot(active, &want, false)?;
        self.slots[i] = Some(r);
        self.ranges[i] = range;
        Ok(i)
    }

    /// Whether provisioning may write `window` of `unit`: no client and no
    /// reservation touches it, read-only or not.
    pub fn unattached<'a>(&self, active: &impl Fn(usize) -> Option<Hold<'a>>, unit: usize, window: DiskWindow) -> bool {
        let w = [Extent { start: window.start, sectors: window.sectors, offset: 0 }];
        !(0..N).flat_map(|i| [active(i), self.hold(i)]).flatten().any(|h| h.unit == unit && overlap(&w, h.extents))
    }
}

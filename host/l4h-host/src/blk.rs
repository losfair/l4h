//! blkd <-> client (l4h-vmm) block request queue.
//!
//! A channel is one shared region: a header, a submission ring and a
//! completion ring of fixed-size entries.  Data is never copied here:
//! requests carry guest-physical segments, which blkd validates against
//! the client's I/O pool (configured by l4h-root) and translates for DMA.
//! Guest RAM is never a DMA target.

pub const MAX_SEGS: usize = 16;
pub const RING_SIZE: usize = 128;
/// The advertised maximum: 14 data segments of 256 KiB. Bound work even
/// for a hostile guest that ignores virtio size_max/seg_max.
pub const MAX_REQUEST_BYTES: u64 = (MAX_SEGS as u64 - 2) * (256 << 10);

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
    /// Written by l4h-root before BLKD_ADD: blkd completes flushes at once
    /// and the VMM offers the guest none (l4h_abi::BLK_VOLATILE).
    pub volatile: u32,
    pub reserved: [u32; 10],
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
pub const QUEUE_SIZE: usize = 3 << 20;
pub const BOUNCE_SIZE: usize = 4 << 20;
pub const BOUNCE_VA: usize = 0x2900_0000_0000;
pub const POOL_VA: usize = 0x4000_0000_0000;
// Separate subranges for 2 MiB frames and the 1 MiB pool's 4 KiB
// frames: retained last-level tables must never block a later large map.
pub const POOL_STRIDE: usize = 512 << 20;
pub const FEATURE_AES: u64 = 1;
pub const ENCRYPT: u64 = 1;

/// XTS requires distinct key halves. Inspect every byte without an
/// early-exit comparison of secret data.
pub fn valid_xts_key(key: &[u8; 64]) -> bool {
    key[..32].iter().zip(&key[32..]).fold(0, |diff, (a, b)| diff | (a ^ b)) != 0
}

/// Pools are powers of two, physically aligned, and never handed to the
/// guest as capabilities. Use large frames wherever the whole pool fits.
pub const fn pool_frame_bits(size: usize) -> usize { if size >= 1 << 21 { 21 } else { 12 } }

pub const fn pool_offset(client: usize, size: usize) -> usize {
    client * POOL_STRIDE + if pool_frame_bits(size) == 12 { POOL_STRIDE / 2 } else { 0 }
}
pub const fn pool_va(client: usize, size: usize) -> usize { POOL_VA + pool_offset(client, size) }
/// Service calls of blkd (message registers; the result is in MR 0).
/// unit -> capacity (u64::MAX if no such unit), block size, read-only,
/// number of units, unit address (blkd_scsi_addr for virtio-scsi, else 0).
pub const BLKD_INFO: u64 = 1;
/// client, unit, flags, key[8] -> 0 or a positive errno.
/// The key is little-endian words; u64::MAX means a failed driver.
pub const BLKD_ADD: u64 = 2;
/// client -> 0, or u64::MAX if it did not drain
pub const BLKD_REMOVE: u64 = 3;
/// sector, length, unit -> blk::STATUS_*, or u64::MAX
pub const BLKD_WRITE: u64 = 4;
/// unit -> blk::STATUS_*, or u64::MAX
pub const BLKD_FLUSH: u64 = 5;
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
    pub features: u64,
    pub bounce_va: u64,
    pub bounce_paddr: u64,
    pub bounce_size: u64,
    pub pool_va: u64,
    pub staging_paddr: u64,
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
        if bytes == 0 || bytes > MAX_REQUEST_BYTES || bytes % block_size as u64 != 0 || sector % (block_size as u64 / 512) != 0
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

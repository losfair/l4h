//! virtio-scsi PCI driver, for modern (virtio 1.x) and legacy (0.9.5, as on
//! GCE) devices.  Every direct-access logical unit found at start is a unit
//! of blkd: the LUNs of each target (REPORT LUNS, or LUN 0 alone), in
//! target and LUN order, up to blk::MAX_UNITS.
//!
//! Each command is one descriptor chain (indirect if the device offers it):
//! request header, data pieces, response; data the device reads comes
//! before the response, data it writes after.  A request becomes several
//! READ/WRITE commands when it exceeds the device's segment or transfer
//! limits.  Unit attentions and busy conditions are retried.

use l4h_rt::host::blk::{self, BlkdConfig};
use l4h_rt::host::fixed::ArrayVec;
use l4h_rt::ioport::Ports;
use l4h_virtio::{
    DESC_F_INDIRECT, DESC_F_NEXT, DESC_F_WRITE, Device, Dma, F_ACCESS_PLATFORM, F_INDIRECT_DESC, F_VERSION_1, Mmio, NO_VECTOR,
    STATUS_ACK, STATUS_DRIVER, STATUS_DRIVER_OK, STATUS_FAILED, Virtq, legacy, legacy_ring_size,
};

use crate::{DevInfo, Driver, MAX_PIECES, Seg};

/// The request queue; 0 and 1 are the control and event queues, unused.
const REQUEST_QUEUE: u16 = 2;
const MAX_QUEUES: usize = 4;
const CFG_NUM_QUEUES: usize = 0;
/// Commands in flight.
const MAX_SLOTS: usize = blk::RING_SIZE;
/// Descriptors of a command: header, data pieces, response.
const MAX_DESCS: usize = 2 + MAX_PIECES;
/// Requests up to this size are split into as many commands as the
/// device's limits need (clients send at most 14 segments of 256 KiB).
const MAX_REQUEST: u64 = 4 << 20;

// Device configuration.
const CFG_SEG_MAX: usize = 4;
const CFG_MAX_SECTORS: usize = 8;
const CFG_SENSE_SIZE: usize = 20;
const CFG_CDB_SIZE: usize = 24;
const CFG_MAX_TARGET: usize = 30;

/// The sizes Linux sets; the request header and response must fit
/// HDR_BYTES and RESP_BYTES.
const CDB_SIZE: u32 = 32;
const SENSE_SIZE: u32 = 96;
const HDR_BYTES: usize = 64;
const RESP_BYTES: usize = 128;

// struct virtio_scsi_resp_cmd.
const RESP_SENSE_LEN: usize = 0;
const RESP_RESIDUAL: usize = 4;
const RESP_STATUS: usize = 10;
const RESP_RESPONSE: usize = 11;
const RESP_SENSE: usize = 12;

const S_OK: u8 = 0;
const S_RESET: u8 = 4;
const S_BUSY: u8 = 5;

// SCSI status and sense keys.
const GOOD: u8 = 0x00;
const CHECK_CONDITION: u8 = 0x02;
const BUSY: u8 = 0x08;
const TASK_SET_FULL: u8 = 0x28;
const NOT_READY: u8 = 0x2;
const ILLEGAL_REQUEST: u8 = 0x5;
const UNIT_ATTENTION: u8 = 0x6;

const INQUIRY: u8 = 0x12;
const REPORT_LUNS: u8 = 0xa0;
const TEST_UNIT_READY: u8 = 0x00;
const MODE_SENSE_6: u8 = 0x1a;
const READ_CAPACITY_10: u8 = 0x25;
const READ_CAPACITY_16: u8 = 0x9e;
const READ_10: u8 = 0x28;
const WRITE_10: u8 = 0x2a;
const READ_16: u8 = 0x88;
const WRITE_16: u8 = 0x8a;
const SYNCHRONIZE_CACHE_10: u8 = 0x35;

const RETRIES: u8 = 5;

enum Transport {
    Modern(Device),
    Legacy(Ports),
}

impl Transport {
    fn cfg16(&self, off: usize) -> u16 {
        match self {
            Transport::Modern(d) => d.device.r16(off),
            Transport::Legacy(p) => p.in16(legacy::DEVICE_CONFIG + off as u16),
        }
    }

    fn cfg32(&self, off: usize) -> u32 {
        match self {
            Transport::Modern(d) => d.device.r32(off),
            Transport::Legacy(p) => p.in32(legacy::DEVICE_CONFIG + off as u16),
        }
    }

    fn set_cfg32(&self, off: usize, v: u32) {
        match self {
            Transport::Modern(d) => d.device.w32(off, v),
            Transport::Legacy(p) => p.out32(legacy::DEVICE_CONFIG + off as u16, v),
        }
    }

    fn notify(&self, q: &Virtq) {
        q.notify();
        if let Transport::Legacy(p) = self {
            p.out16(legacy::QUEUE_NOTIFY, q.idx);
        }
    }
}

struct Slot {
    /// Request this command belongs to.
    req: u16,
    busy: bool,
    queue: usize,
    retries: u8,
    /// Head descriptor in the ring.
    head: u16,
    /// Indirect table (unused without INDIRECT_DESC).
    table_va: usize,
    table_pa: u64,
    /// Request header, then the response at HDR_BYTES.
    hdr_va: usize,
    hdr_pa: u64,
}

#[derive(Clone, Copy, Default)]
struct Request {
    tag: u64,
    pending: u16,
    status: u32,
}

/// A direct-access logical unit.
struct Unit {
    /// virtio-scsi LUN field.
    lun: [u8; 8],
    target: u8,
    number: u16,
    blocks: u64,
    block_size: u32,
    /// Largest transfer of one command, a multiple of the block size.
    max_bytes: u64,
    read_only: bool,
    flush: bool,
}

/// The virtio-scsi LUN field of a single-level LUN (flat addressing).
fn lun_field(target: u8, lun: u16) -> [u8; 8] {
    [1, target, 0x40 | (lun >> 8) as u8, lun as u8, 0, 0, 0, 0]
}

/// How a command ended.
struct Outcome {
    response: u8,
    status: u8,
    residual: u32,
    sense_key: Option<u8>,
}

pub struct VirtioScsi {
    id: u32,
    io_errors: l4h_rt::ErrorLimit,
    t: Transport,
    vqs: ArrayVec<Virtq, MAX_QUEUES>,
    next_queue: usize,
    kick_queues: u8,
    indirect: bool,
    slots: ArrayVec<Slot, MAX_SLOTS>,
    free: ArrayVec<u16, MAX_SLOTS>,
    /// By request id, below the number of slots.
    reqs: [Request; MAX_SLOTS],
    free_reqs: ArrayVec<u16, MAX_SLOTS>,
    units: ArrayVec<Unit, { blk::MAX_UNITS }>,
    seg_max: usize,
    max_sectors: u64,
    max_cmds: usize,
}

fn spin_until(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..200_000_000u64 {
        if f() {
            return;
        }
        core::hint::spin_loop();
    }
    panic!("virtio-scsi: timeout waiting for {}", what);
}

impl VirtioScsi {
    pub fn new(id: u32, cfg: &BlkdConfig) -> Self {
        let mut dma = Dma::new(cfg.dma_va as usize, cfg.dma_paddr, cfg.dma_size as usize);
        // MSI-X table entry 0 -> our interrupt, unmasked.
        let msix = Mmio(cfg.msix_table.va as usize);
        msix.w32(0, cfg.msi_address as u32);
        msix.w32(4, (cfg.msi_address >> 32) as u32);
        msix.w32(8, cfg.msi_data);
        msix.w32(12, 0);
        let (t, indirect, vq) = if cfg.legacy_io != 0 {
            let p = Ports { cap: blk::BLKD_SLOT_IOPORT, base: cfg.legacy_io as u16 };
            p.out8(legacy::STATUS, 0);
            p.out8(legacy::STATUS, STATUS_ACK | STATUS_DRIVER);
            let features = p.in32(legacy::DEVICE_FEATURES) as u64 & F_INDIRECT_DESC;
            p.out32(legacy::GUEST_FEATURES, features as u32);
            p.out16(legacy::CONFIG_VECTOR, NO_VECTOR);
            p.out16(legacy::QUEUE_SELECT, REQUEST_QUEUE);
            let num = p.in16(legacy::QUEUE_SIZE);
            // A legacy queue has the device's size.
            let (va, pa) = dma.alloc(legacy_ring_size(num), 4096);
            p.out32(legacy::QUEUE_PFN, (pa >> 12) as u32);
            p.out16(legacy::QUEUE_VECTOR, 0);
            if num == 0 || p.in16(legacy::QUEUE_VECTOR) != 0 {
                p.out8(legacy::STATUS, STATUS_FAILED);
                panic!("blkd {:#x}: virtio-scsi request queue unusable (size {})", id, num);
            }
            (Transport::Legacy(p), features != 0, Virtq::legacy(REQUEST_QUEUE, num, va))
        } else {
            let dev = Device {
                common: Mmio(cfg.common.va as usize),
                notify: Mmio(cfg.notify.va as usize),
                notify_mult: cfg.notify_off_multiplier,
                device: Mmio(cfg.device.va as usize),
            };
            dev.reset();
            let offered = dev.features();
            if offered & F_VERSION_1 == 0 {
                dev.fail();
                panic!("blkd {:#x}: device lacks VERSION_1 (features {:#x})", id, offered);
            }
            let features = F_VERSION_1 | (offered & (F_INDIRECT_DESC | F_ACCESS_PLATFORM));
            if !dev.set_features(features) {
                dev.fail();
                panic!("blkd {:#x}: features rejected", id);
            }
            let indirect = features & F_INDIRECT_DESC != 0;
            let want = if indirect { MAX_SLOTS } else { MAX_SLOTS * MAX_DESCS };
            let vq = dev.setup_queue(&mut dma, REQUEST_QUEUE, want.min(u16::MAX as usize) as u16, 0)
                .expect("blkd: virtio-scsi request queue");
            (Transport::Modern(dev), indirect, vq)
        };
        let mut vqs = ArrayVec::new();
        let _ = vqs.push(vq);
        let count = (t.cfg32(CFG_NUM_QUEUES) as usize).clamp(1, MAX_QUEUES);
        for q in 1..count {
            let index = REQUEST_QUEUE + q as u16;
            let queue = match &t {
                Transport::Modern(dev) => dev.setup_queue(&mut dma, index, vqs[0].num, 0),
                Transport::Legacy(p) => {
                    p.out16(legacy::QUEUE_SELECT, index);
                    let num = p.in16(legacy::QUEUE_SIZE);
                    if num == 0 { break; }
                    let (va, pa) = dma.alloc(legacy_ring_size(num), 4096);
                    p.out32(legacy::QUEUE_PFN, (pa >> 12) as u32);
                    p.out16(legacy::QUEUE_VECTOR, 0);
                    if p.in16(legacy::QUEUE_VECTOR) != 0 {
                        p.out32(legacy::QUEUE_PFN, 0);
                        break;
                    }
                    Some(Virtq::legacy(index, num, va))
                }
            };
            let Some(queue) = queue else { break; };
            let _ = vqs.push(queue);
        }
        l4h_rt::info!("blkd {:#x}: virtio-scsi {} request queues", id, vqs.len());
        t.set_cfg32(CFG_CDB_SIZE, CDB_SIZE);
        t.set_cfg32(CFG_SENSE_SIZE, SENSE_SIZE);
        let (cdb_size, sense_size) = (t.cfg32(CFG_CDB_SIZE), t.cfg32(CFG_SENSE_SIZE));
        if !(16..=(HDR_BYTES - 19) as u32).contains(&cdb_size) || 12 + sense_size as usize > RESP_BYTES {
            panic!("blkd {:#x}: unsupported CDB/sense sizes {}/{}", id, cdb_size, sense_size);
        }
        let seg_max = match t.cfg32(CFG_SEG_MAX) as usize {
            0 => MAX_PIECES,
            n => n.min(MAX_PIECES),
        };
        let max_sectors = match t.cfg32(CFG_MAX_SECTORS) {
            0 => 0xffff,
            n => n as u64,
        };
        let max_target = t.cfg16(CFG_MAX_TARGET).min(255) as u8;

        // Without indirect descriptors, each slot owns MAX_DESCS ring entries.
        let num = vqs.iter().map(|q| q.num as usize).min().unwrap();
        let nslots = if indirect { num } else { num / MAX_DESCS }.min(MAX_SLOTS);
        assert!(nslots > 0, "blkd {:#x}: virtio-scsi queue of {} entries too small", id, num);
        let (mut slots, mut free, mut free_reqs) = (ArrayVec::new(), ArrayVec::new(), ArrayVec::new());
        for s in 0..nslots {
            let (table_va, table_pa) = if indirect { dma.alloc(MAX_DESCS * 16, 16) } else { (0, 0) };
            let (hdr_va, hdr_pa) = dma.alloc(HDR_BYTES + RESP_BYTES, 64);
            let head = if indirect { s } else { s * MAX_DESCS } as u16;
            let _ = slots.push(Slot { req: 0, busy: false, queue: 0, retries: 0, head, table_va, table_pa, hdr_va, hdr_pa });
            let _ = free.push((nslots - 1 - s) as u16);
            let _ = free_reqs.push((nslots - 1 - s) as u16);
        }
        match &t {
            Transport::Modern(d) => d.driver_ok(),
            Transport::Legacy(p) => p.out8(legacy::STATUS, STATUS_ACK | STATUS_DRIVER | STATUS_DRIVER_OK),
        }
        let (buf_va, buf_pa) = dma.alloc(4096, 4096);
        let mut s = VirtioScsi {
            id, t, vqs, next_queue: 0, kick_queues: 0, indirect,
            io_errors: l4h_rt::ErrorLimit::new(),
            free,
            slots,
            reqs: [Request::default(); MAX_SLOTS],
            free_reqs,
            units: ArrayVec::new(),
            seg_max,
            max_sectors,
            max_cmds: MAX_PIECES.min(nslots),
        };
        s.scan(max_target, (buf_va, buf_pa));
        // Every piece may start a command, and every max_bytes.
        for u in &s.units {
            s.max_cmds = s.max_cmds.max(MAX_PIECES + MAX_REQUEST.div_ceil(u.max_bytes) as usize).min(nslots);
        }
        l4h_rt::info!(
            "blkd {:#x}: virtio-scsi, {} disk(s) on targets 0-{}, {} slots{}",
            id, s.units.len(), max_target, nslots,
            if indirect { "" } else { " (direct descriptors)" },
        );
        s
    }

    /// Find the direct-access logical units.
    fn scan(&mut self, max_target: u8, buf: (usize, u64)) {
        let byte = |i: usize| Mmio(buf.0).r8(i);
        let be = |off: usize, n: usize| (0..n).fold(0u64, |v, i| (v << 8) | byte(off + i) as u64);
        for target in 0..=max_target {
            // Absent targets fail at the transport (BAD_TARGET).
            let o = self.exec(lun_field(target, 0), &[INQUIRY, 0, 0, 0, 36, 0], Some((buf.1, 36)));
            if o.response != S_OK {
                continue;
            }
            // At most (4096 - 8) / 8 entries fit the REPORT LUNS data.
            let mut luns = ArrayVec::<u16, { (4096 - 8) / 8 }>::new();
            let mut cdb = [0u8; 12];
            cdb[0] = REPORT_LUNS;
            cdb[6..10].copy_from_slice(&4096u32.to_be_bytes());
            let o = self.exec(lun_field(target, 0), &cdb, Some((buf.1, 4096)));
            if o.response == S_OK && o.status == GOOD {
                let n = (be(0, 4) as usize / 8).min((4096 - 8) / 8);
                for i in 0..n {
                    let e = 8 + 8 * i;
                    // Single-level LUNs: peripheral (bus 0) or flat addressing.
                    if (2..8).any(|j| byte(e + j) != 0) {
                        continue;
                    }
                    match byte(e) >> 6 {
                        0 if byte(e) == 0 => { let _ = luns.push(byte(e + 1) as u16); }
                        1 => { let _ = luns.push(((byte(e) as u16 & 0x3f) << 8) | byte(e + 1) as u16); }
                        _ => {}
                    }
                }
                // Sorted, then without the (now adjacent) duplicates.
                luns.sort_unstable();
                let mut prev = None;
                luns.retain(|&l| prev.replace(l) != Some(l));
            } else {
                let _ = luns.push(0);
            }
            for &lun in luns.iter() {
                if self.units.len() == blk::MAX_UNITS {
                    l4h_rt::log!("blkd {:#x}: more than {} disks, ignoring target {} LUN {}", self.id, blk::MAX_UNITS, target, lun);
                    return;
                }
                if let Some(u) = self.probe(target, lun, buf) {
                    let _ = self.units.push(u);
                }
            }
        }
    }

    /// Read the geometry of a logical unit, if it is a disk.
    fn probe(&mut self, target: u8, number: u16, buf: (usize, u64)) -> Option<Unit> {
        let id = self.id;
        let lun = lun_field(target, number);
        let byte = |i: usize| Mmio(buf.0).r8(i);
        let be = |off: usize, n: usize| (0..n).fold(0u64, |v, i| (v << 8) | byte(off + i) as u64);
        let o = self.exec(lun, &[INQUIRY, 0, 0, 0, 36, 0], Some((buf.1, 36)));
        // Peripheral qualifier 0, direct-access device.
        if o.response != S_OK || o.status != GOOD || byte(0) != 0 {
            return None;
        }

        // Clear the unit attention of the reset, wait for the unit to be ready.
        for _ in 0..50 {
            let o = self.exec(lun, &[TEST_UNIT_READY, 0, 0, 0, 0, 0], None);
            if o.response == S_OK && o.status == GOOD {
                break;
            }
        }

        let mut rc16 = [0u8; 16];
        rc16[0] = READ_CAPACITY_16;
        rc16[1] = 0x10;
        rc16[13] = 32;
        let o = self.exec(lun, &[READ_CAPACITY_10, 0, 0, 0, 0, 0, 0, 0, 0, 0], Some((buf.1, 8)));
        let (last, block_size) = if o.response == S_OK && o.status == GOOD && be(0, 4) != 0xffff_ffff {
            (be(0, 4), be(4, 4))
        } else {
            let o = self.exec(lun, &rc16, Some((buf.1, 32)));
            if o.response != S_OK || o.status != GOOD {
                l4h_rt::log!("blkd {:#x}: target {} LUN {}: READ CAPACITY failed: response {} status {:#x}",
                    id, target, number, o.response, o.status);
                return None;
            }
            (be(0, 8), be(8, 4))
        };
        if !matches!(block_size, 512 | 4096) {
            l4h_rt::log!("blkd {:#x}: target {} LUN {}: unsupported block size {}", id, target, number, block_size);
            return None;
        }
        let mut u = Unit {
            lun, target, number,
            blocks: last + 1,
            block_size: block_size as u32,
            max_bytes: (self.max_sectors * 512 / block_size).max(1) * block_size,
            read_only: false,
            flush: true,
        };

        // Write protection (mode parameter header) and the write cache
        // (caching page); without them, assume writable with a cache.
        let o = self.exec(lun, &[MODE_SENSE_6, 0x08, 0x08, 0, 255, 0], Some((buf.1, 255)));
        if o.response == S_OK && o.status == GOOD {
            let len = (byte(0) as usize + 1).min(255usize.saturating_sub(o.residual as usize));
            u.read_only = byte(2) & 0x80 != 0;
            let page = 4 + byte(3) as usize;
            if page + 3 <= len && byte(page) & 0x3f == 0x08 {
                u.flush = byte(page + 2) & 0x04 != 0;
            }
        }
        l4h_rt::info!(
            "blkd {:#x}: virtio-scsi unit {}: target {} LUN {}, {} {}-byte blocks{}{}",
            id, self.units.len(), target, number, u.blocks, block_size,
            if u.read_only { ", write-protected" } else { "" },
            if u.flush { ", write cache" } else { "" },
        );
        Some(u)
    }

    /// Run one command to completion by polling (during probing).
    fn exec(&mut self, lun: [u8; 8], cdb: &[u8], data_in: Option<(u64, u32)>) -> Outcome {
        let s = self.free.pop().expect("idle slot");
        let data = data_in.map(|(pa, len)| Seg { pa, len });
        self.fill(s, lun, cdb, data.as_slice(), data_in.is_some());
        self.slots[s as usize].busy = true;
        self.vqs[0].submit(self.slots[s as usize].head);
        self.t.notify(&self.vqs[0]);
        let head = self.slots[s as usize].head as u32;
        let vq = &mut self.vqs[0];
        spin_until("probe command", || matches!(vq.pop_used(), Some((id, _)) if id == head));
        self.slots[s as usize].busy = false;
        let _ = self.free.push(s);
        self.outcome(s)
    }

    /// Write slot `s`'s command: header, descriptors.  Not yet submitted.
    fn fill(&mut self, s: u16, lun: [u8; 8], cdb: &[u8], data: &[Seg], data_in: bool) {
        let slot = &mut self.slots[s as usize];
        slot.retries = 0;
        let hdr = Mmio(slot.hdr_va);
        for i in 0..HDR_BYTES / 4 {
            hdr.w32(4 * i, 0);
        }
        for (i, &b) in lun.iter().enumerate() {
            hdr.w8(i, b);
        }
        hdr.w64(8, s as u64);
        // Task attribute SIMPLE, priority and CRN 0.
        for (i, &b) in cdb.iter().enumerate() {
            hdr.w8(19 + i, b);
        }
        // A completion the device never wrote reads as a failure.
        hdr.w8(HDR_BYTES + RESP_RESPONSE, 0xff);

        let n = data.len() + 2;
        let (indirect, head, table_va) = (self.indirect, slot.head, slot.table_va);
        let vq = &self.vqs[slot.queue];
        let desc = |i: usize, addr: u64, len: u32, flags: u16| {
            let last = i + 1 == n;
            let flags = if last { flags } else { flags | DESC_F_NEXT };
            if indirect {
                let d = Mmio(table_va + 16 * i);
                d.w64(0, addr);
                d.w32(8, len);
                d.w16(12, flags);
                d.w16(14, if last { 0 } else { (i + 1) as u16 });
            } else {
                vq.set_desc(head + i as u16, addr, len, flags, if last { 0 } else { head + i as u16 + 1 });
            }
        };
        let req_len = 19 + CDB_SIZE;
        let resp_len = 12 + SENSE_SIZE;
        desc(0, slot.hdr_pa, req_len, 0);
        if data_in {
            desc(1, slot.hdr_pa + HDR_BYTES as u64, resp_len, DESC_F_WRITE);
            for (i, p) in data.iter().enumerate() {
                desc(2 + i, p.pa, p.len, DESC_F_WRITE);
            }
        } else {
            for (i, p) in data.iter().enumerate() {
                desc(1 + i, p.pa, p.len, 0);
            }
            desc(n - 1, slot.hdr_pa + HDR_BYTES as u64, resp_len, DESC_F_WRITE);
        }
        if indirect {
            self.vqs[slot.queue].set_desc(head, slot.table_pa, (16 * n) as u32, DESC_F_INDIRECT, 0);
        }
    }

    fn outcome(&self, s: u16) -> Outcome {
        let r = Mmio(self.slots[s as usize].hdr_va + HDR_BYTES);
        let sense_len = (r.r32(RESP_SENSE_LEN) as usize).min(SENSE_SIZE as usize);
        let sense = |i: usize| r.r8(RESP_SENSE + i);
        let sense_key = match sense(0) & 0x7f {
            0x70 | 0x71 if sense_len >= 3 => Some(sense(2) & 0xf),
            0x72 | 0x73 if sense_len >= 2 => Some(sense(1) & 0xf),
            _ => None,
        };
        Outcome { response: r.r8(RESP_RESPONSE), status: r.r8(RESP_STATUS), residual: r.r32(RESP_RESIDUAL), sense_key }
    }

    /// Fill a free slot with a READ or WRITE of `data` at `lba` of `unit`.
    fn rw(&mut self, r: u16, unit: usize, queue: usize, write: bool, lba: u64, data: &[Seg], bytes: u64) -> u16 {
        let blocks = bytes / self.units[unit].block_size as u64;
        let mut cdb = [0u8; 16];
        let len = if lba + blocks <= 1 << 32 && blocks <= 0xffff {
            cdb[0] = if write { WRITE_10 } else { READ_10 };
            cdb[2..6].copy_from_slice(&(lba as u32).to_be_bytes());
            cdb[7..9].copy_from_slice(&(blocks as u16).to_be_bytes());
            10
        } else {
            cdb[0] = if write { WRITE_16 } else { READ_16 };
            cdb[2..10].copy_from_slice(&lba.to_be_bytes());
            cdb[10..14].copy_from_slice(&(blocks as u32).to_be_bytes());
            16
        };
        let s = self.free.pop().unwrap();
        self.slots[s as usize].queue = queue;
        self.fill(s, self.units[unit].lun, &cdb[..len], data, !write);
        self.slots[s as usize].req = r;
        s
    }
}

impl Driver for VirtioScsi {
    fn units(&self) -> usize {
        self.units.len()
    }

    fn info(&self, unit: usize) -> DevInfo {
        let u = &self.units[unit];
        DevInfo {
            capacity: u.blocks * (u.block_size as u64 / 512),
            block_size: u.block_size,
            read_only: u.read_only,
            flush: u.flush,
            address: blk::blkd_scsi_addr(u.target, u.number),
        }
    }

    fn can_start(&self) -> bool {
        !self.free_reqs.is_empty() && self.free.len() >= self.max_cmds
    }

    fn start(&mut self, tag: u64, unit: usize, op: u32, sector: u64, data: &[Seg]) -> Result<(), u32> {
        if !self.can_start() || unit >= self.units.len() {
            return Err(blk::STATUS_IOERR);
        }
        let r = self.free_reqs.pop().unwrap();
        let queue = if tag == u64::MAX { 0 } else { self.next_queue };
        let mut issued = [0u16; MAX_SLOTS];
        let mut n_issued = 0;
        let result = (|| {
            if op == blk::OP_FLUSH {
                let s = self.free.pop().unwrap();
                self.slots[s as usize].queue = queue;
                self.fill(s, self.units[unit].lun, &[SYNCHRONIZE_CACHE_10, 0, 0, 0, 0, 0, 0, 0, 0, 0], &[], false);
                self.slots[s as usize].req = r;
                issued[0] = s;
                n_issued = 1;
                return Ok(());
            }
            let (bs, max_bytes) = (self.units[unit].block_size as u64, self.units[unit].max_bytes);
            // Never round a sector down to the block holding it.
            if !(sector * 512).is_multiple_of(bs) {
                return Err(blk::STATUS_IOERR);
            }
            let write = op == blk::OP_WRITE;
            let mut lba = sector * 512 / bs;
            // The pieces of the command being built.
            let mut cmd = [Seg { pa: 0, len: 0 }; MAX_PIECES];
            let (mut n, mut bytes) = (0usize, 0u64);
            let mut pieces = data.iter().copied();
            let mut cur = pieces.next();
            loop {
                let full = n == self.seg_max || bytes == max_bytes;
                if cur.is_none() || full {
                    if n == 0 {
                        break;
                    }
                    // Cut on a block: the tail of the last piece starts the next command.
                    let excess = bytes % bs;
                    if excess >= cmd[n - 1].len as u64 || n_issued == self.max_cmds {
                        return Err(blk::STATUS_IOERR);
                    }
                    cmd[n - 1].len -= excess as u32;
                    let tail = Seg { pa: cmd[n - 1].pa + cmd[n - 1].len as u64, len: excess as u32 };
                    issued[n_issued] = self.rw(r, unit, queue, write, lba, &cmd[..n], bytes - excess);
                    n_issued += 1;
                    lba += (bytes - excess) / bs;
                    (n, bytes) = (0, 0);
                    if excess != 0 {
                        (cmd[0], n, bytes) = (tail, 1, excess);
                    }
                    continue;
                }
                let p = cur.as_mut().unwrap();
                let take = (p.len as u64).min(max_bytes - bytes);
                cmd[n] = Seg { pa: p.pa, len: take as u32 };
                n += 1;
                bytes += take;
                p.pa += take;
                p.len -= take as u32;
                if p.len == 0 {
                    cur = pieces.next();
                }
            }
            Ok(())
        })();
        if let Err(e) = result {
            // Nothing was submitted: give the slots back.
            let _ = self.free.extend_from_slice(&issued[..n_issued]);
            let _ = self.free_reqs.push(r);
            return Err(e);
        }
        self.reqs[r as usize] = Request { tag, pending: n_issued as u16, status: blk::STATUS_OK };
        for &s in &issued[..n_issued] {
            self.slots[s as usize].busy = true;
            self.vqs[queue].submit(self.slots[s as usize].head);
            self.kick_queues |= 1 << queue;
        }
        Ok(())
    }

    fn kick(&mut self) {
        let queues = core::mem::take(&mut self.kick_queues);
        if queues != 0 { self.next_queue = (self.next_queue + 1) % self.vqs.len(); }
        for q in 0..self.vqs.len() {
            if queues & (1 << q) != 0 { self.t.notify(&self.vqs[q]); }
        }
    }

    fn reap(&mut self, done: &mut dyn FnMut(u64, u32)) {
        let mut resubmitted = false;
        for q in 0..self.vqs.len() {
            while let Some((head, _len)) = self.vqs[q].pop_used() {
                let s = if self.indirect { head as usize } else { head as usize / MAX_DESCS };
                let Some(slot) = self.slots.get(s) else { continue };
                if !slot.busy || slot.queue != q || slot.head as u32 != head {
                    continue;
                }
                let o = self.outcome(s as u16);
                let retry = match (o.response, o.status) {
                    (S_RESET | S_BUSY, _) => true,
                    (S_OK, BUSY | TASK_SET_FULL) => true,
                    (S_OK, CHECK_CONDITION) => matches!(o.sense_key, Some(UNIT_ATTENTION | NOT_READY)),
                    _ => false,
                };
                let slot = &mut self.slots[s];
                if retry && slot.retries < RETRIES {
                    slot.retries += 1;
                    Mmio(slot.hdr_va).w8(HDR_BYTES + RESP_RESPONSE, 0xff);
                    self.vqs[q].submit(slot.head);
                    self.kick_queues |= 1 << q;
                    resubmitted = true;
                    continue;
                }
                slot.busy = false;
                let r = slot.req as usize;
                let status = match (o.response, o.status) {
                    (S_OK, GOOD) if o.residual == 0 => blk::STATUS_OK,
                    (S_OK, CHECK_CONDITION) if o.sense_key == Some(ILLEGAL_REQUEST) => blk::STATUS_UNSUPP,
                    _ => blk::STATUS_IOERR,
                };
                // Unsupported commands come from guests: not an error of the host.
                if status == blk::STATUS_UNSUPP {
                    l4h_rt::info!("blkd {:#x}: virtio-scsi command unsupported by the device", self.id);
                } else if status != blk::STATUS_OK && self.io_errors.allow() {
                    l4h_rt::log!(
                        "blkd {:#x}: virtio-scsi command failed: response {} status {:#x} sense key {:?} residual {}",
                        self.id, o.response, o.status, o.sense_key, o.residual
                    );
                }
                let _ = self.free.push(s as u16);
                let req = &mut self.reqs[r];
                if req.status == blk::STATUS_OK {
                    req.status = status;
                }
                req.pending -= 1;
                if req.pending == 0 {
                    done(req.tag, req.status);
                    let _ = self.free_reqs.push(r as u16);
                }
            }
        }
        if resubmitted { self.kick(); }
    }
}

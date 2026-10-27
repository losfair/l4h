//! virtio-blk PCI driver, for modern (virtio 1.x) and legacy (0.9.5)
//! devices.  Each request is one indirect descriptor table: header, data
//! pieces, status byte.

use l4h_rt::host::blk::{self, BlkdConfig};
use l4h_rt::host::fixed::ArrayVec;
use l4h_rt::ioport::Ports;
use l4h_virtio::{
    DESC_F_INDIRECT, DESC_F_NEXT, DESC_F_WRITE, Device, Dma, F_ACCESS_PLATFORM, F_INDIRECT_DESC, F_VERSION_1, Mmio, NO_VECTOR,
    STATUS_ACK, STATUS_DRIVER, STATUS_DRIVER_OK, STATUS_FAILED, Virtq, legacy, legacy_ring_size,
};

use crate::{DevInfo, Driver, MAX_PIECES, Seg};

const VIRTIO_BLK_F_RO: u64 = 1 << 5;
const VIRTIO_BLK_F_BLK_SIZE: u64 = 1 << 6;
const VIRTIO_BLK_F_FLUSH: u64 = 1 << 9;
/// Device configuration: capacity in sectors, block size.
const CFG_CAPACITY: u16 = 0;
const CFG_BLK_SIZE: u16 = 20;

const MAX_DESCS: usize = 2 + MAX_PIECES;
const SLOT_TABLE: usize = MAX_DESCS * 16;

struct Slot {
    tag: u64,
    busy: bool,
    /// Indirect table, request header and status byte.
    table_va: usize,
    table_pa: u64,
    hdr_va: usize,
    hdr_pa: u64,
}

pub struct VirtioBlk {
    vq: Virtq,
    /// Legacy devices are notified through I/O ports.
    ports: Option<Ports>,
    /// One per queue entry (the queue has at most blk::RING_SIZE).
    slots: ArrayVec<Slot, { blk::RING_SIZE }>,
    free: ArrayVec<u16, { blk::RING_SIZE }>,
    features: u64,
    capacity: u64,
    block_size: u32,
}

impl VirtioBlk {
    pub fn new(id: u32, cfg: &BlkdConfig) -> Self {
        let mut dma = Dma::new(cfg.dma_va as usize, cfg.dma_paddr, cfg.dma_size as usize);
        // MSI-X table entry 0 -> our interrupt, unmasked.
        let msix = Mmio(cfg.msix_table.va as usize);
        msix.w32(0, cfg.msi_address as u32);
        msix.w32(4, (cfg.msi_address >> 32) as u32);
        msix.w32(8, cfg.msi_data);
        msix.w32(12, 0);
        let wanted = |offered: u64| offered & (VIRTIO_BLK_F_RO | VIRTIO_BLK_F_FLUSH | VIRTIO_BLK_F_BLK_SIZE);
        let modern = (cfg.legacy_io == 0).then(|| Device {
            common: Mmio(cfg.common.va as usize),
            notify: Mmio(cfg.notify.va as usize),
            notify_mult: cfg.notify_off_multiplier,
            device: Mmio(cfg.device.va as usize),
        });
        let (vq, features, ports, capacity, block_size) = if let Some(dev) = &modern {
            dev.reset();
            let offered = dev.features();
            let want = F_VERSION_1 | F_INDIRECT_DESC;
            if offered & want != want {
                dev.fail();
                panic!("blkd {:#x}: device lacks VERSION_1/INDIRECT_DESC (features {:#x})", id, offered);
            }
            let features = want | wanted(offered) | (offered & F_ACCESS_PLATFORM);
            if !dev.set_features(features) {
                dev.fail();
                panic!("blkd {:#x}: features rejected", id);
            }
            let vq = dev.setup_queue(&mut dma, 0, blk::RING_SIZE as u16, 0).expect("blkd: queue 0");
            let capacity = dev.device.r64(CFG_CAPACITY as usize);
            let block_size =
                if features & VIRTIO_BLK_F_BLK_SIZE != 0 { dev.device.r32(CFG_BLK_SIZE as usize).max(512) } else { 512 };
            (vq, features, None, capacity, block_size)
        } else {
            let p = Ports { cap: blk::BLKD_SLOT_IOPORT, base: cfg.legacy_io as u16 };
            p.out8(legacy::STATUS, 0);
            p.out8(legacy::STATUS, STATUS_ACK | STATUS_DRIVER);
            let offered = p.in32(legacy::DEVICE_FEATURES) as u64;
            if offered & F_INDIRECT_DESC == 0 {
                p.out8(legacy::STATUS, STATUS_FAILED);
                panic!("blkd {:#x}: device lacks INDIRECT_DESC (features {:#x})", id, offered);
            }
            let features = F_INDIRECT_DESC | wanted(offered);
            p.out32(legacy::GUEST_FEATURES, features as u32);
            p.out16(legacy::CONFIG_VECTOR, NO_VECTOR);
            p.out16(legacy::QUEUE_SELECT, 0);
            let num = p.in16(legacy::QUEUE_SIZE);
            // A legacy queue has the device's size, and a 32-bit page number.
            let (va, pa) = dma.alloc(legacy_ring_size(num), 4096);
            p.out32(legacy::QUEUE_PFN, (pa >> 12) as u32);
            p.out16(legacy::QUEUE_VECTOR, 0);
            if num == 0 || pa >> 12 > u32::MAX as u64 || p.in16(legacy::QUEUE_VECTOR) != 0 {
                p.out8(legacy::STATUS, STATUS_FAILED);
                panic!("blkd {:#x}: virtio-blk queue unusable (size {})", id, num);
            }
            let cfg32 = |off: u16| p.in32(legacy::DEVICE_CONFIG + off);
            let capacity = cfg32(CFG_CAPACITY) as u64 | (cfg32(CFG_CAPACITY + 4) as u64) << 32;
            let block_size = if features & VIRTIO_BLK_F_BLK_SIZE != 0 { cfg32(CFG_BLK_SIZE).max(512) } else { 512 };
            (Virtq::legacy(0, num, va), features, Some(p), capacity, block_size)
        };
        // A slot per queue entry, up to blk::RING_SIZE: a legacy queue may
        // be larger.
        let nslots = vq.num.min(blk::RING_SIZE as u16);
        let (mut slots, mut free) = (ArrayVec::new(), ArrayVec::new());
        for s in 0..nslots {
            let (table_va, table_pa) = dma.alloc(SLOT_TABLE, 16);
            let (hdr_va, hdr_pa) = dma.alloc(32, 32);
            let _ = slots.push(Slot { tag: 0, busy: false, table_va, table_pa, hdr_va, hdr_pa });
            let _ = free.push(nslots - 1 - s);
        }
        if let Some(dev) = &modern {
            dev.driver_ok();
        } else if let Some(p) = &ports {
            p.out8(legacy::STATUS, STATUS_ACK | STATUS_DRIVER | STATUS_DRIVER_OK);
            l4h_rt::info!("blkd {:#x}: legacy virtio-blk, {} queue entries", id, vq.num);
        }
        VirtioBlk { free, vq, ports, slots, features, capacity, block_size }
    }
}

impl Driver for VirtioBlk {
    fn units(&self) -> usize {
        1
    }

    fn info(&self, _unit: usize) -> DevInfo {
        DevInfo {
            capacity: self.capacity,
            block_size: self.block_size,
            read_only: self.features & VIRTIO_BLK_F_RO != 0,
            flush: self.features & VIRTIO_BLK_F_FLUSH != 0,
            address: 0,
        }
    }

    fn can_start(&self) -> bool {
        !self.free.is_empty()
    }

    fn start(&mut self, tag: u64, _unit: usize, op: u32, sector: u64, data: &[Seg]) -> Result<(), u32> {
        let s = self.free.pop().ok_or(blk::STATUS_IOERR)?;
        let slot = &mut self.slots[s as usize];
        let hdr = Mmio(slot.hdr_va);
        hdr.w32(0, op);
        hdr.w32(4, 0);
        hdr.w64(8, sector);
        hdr.w8(16, 0xff);
        let data_flags = if op == blk::OP_READ { DESC_F_WRITE } else { 0 };
        let n = data.len() + 2;
        let desc = |i: usize, addr: u64, len: u32, flags: u16| {
            let d = Mmio(slot.table_va + 16 * i);
            let last = i + 1 == n;
            d.w64(0, addr);
            d.w32(8, len);
            d.w16(12, if last { flags } else { flags | DESC_F_NEXT });
            d.w16(14, if last { 0 } else { (i + 1) as u16 });
        };
        desc(0, slot.hdr_pa, 16, 0);
        for (i, p) in data.iter().enumerate() {
            desc(1 + i, p.pa, p.len, data_flags);
        }
        desc(n - 1, slot.hdr_pa + 16, 1, DESC_F_WRITE);
        slot.tag = tag;
        slot.busy = true;
        self.vq.set_desc(s, slot.table_pa, (16 * n) as u32, DESC_F_INDIRECT, 0);
        self.vq.submit(s);
        Ok(())
    }

    fn kick(&mut self) {
        self.vq.notify();
        if let Some(p) = &self.ports {
            p.out16(legacy::QUEUE_NOTIFY, self.vq.idx);
        }
    }

    fn reap(&mut self, done: &mut dyn FnMut(u64, u32)) {
        while let Some((id, _len)) = self.vq.pop_used() {
            let Some(slot) = self.slots.get_mut(id as usize) else { continue };
            if !slot.busy {
                continue;
            }
            slot.busy = false;
            let status = match Mmio(slot.hdr_va).r8(16) {
                0 => blk::STATUS_OK,
                2 => blk::STATUS_UNSUPP,
                _ => blk::STATUS_IOERR,
            };
            done(slot.tag, status);
            // Only busy slots come back, so there is room.
            let _ = self.free.push(id as u16);
        }
    }
}

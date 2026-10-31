//! virtio-balloon free page reporting (DESIGN.md §8.6).  When l4h runs in
//! a VM whose hypervisor offers it (QEMU's `free-page-reporting=on`), memd
//! tells the hypervisor which memory is free, so that the hypervisor can
//! drop it and back it again only when it is used.
//!
//! Free memory is the free blocks (`mem::Mem`), which decide what to
//! report and when; this is only the device, which l4h-root found on PCI
//! and mapped here.  A report is one chain of device-writable buffers, one
//! per block (or per 2 GiB of one).  The device returns the chain when it
//! is done with it, and the blocks must not be used before.  Their
//! contents are lost: they read as zero afterwards, as seL4 would make
//! them anyway when it hands them out again.
//!
//! There is no interrupt: memd's timer polls for the end of a report, and
//! an allocation that needs a block in flight waits for it.  So a legacy
//! (0.9.5) device, whose registers are I/O ports, runs without MSI-X, and
//! has no vector registers.

use l4h_rt::host::memd::{BalloonConfig, DMA_PAGES, DMA_VA, SLOT_BALLOON_IOPORT};
use l4h_rt::ioport::Ports;
use l4h_virtio::{
    self as virtio, DESC_F_NEXT, DESC_F_WRITE, Dma, Mmio, NO_VECTOR, STATUS_ACK, STATUS_DRIVER, STATUS_DRIVER_OK, STATUS_FAILED, Virtq,
    legacy, legacy_ring_size,
};

const F_STATS_VQ: u64 = 1 << 1;
const F_FREE_PAGE_HINT: u64 = 1 << 3;
const F_REPORTING: u64 = 1 << 5;

const PAGE: usize = 4096;

/// Most bytes in one descriptor (lengths are 32 bits).
pub const MAX_DESC_BITS: usize = 31;
/// A block counts as free once it stayed free this long (as Linux does),
/// so that memory freed and soon allocated again is not reported.
pub const REPORT_DELAY_MS: u64 = 2000;
/// Buffers of the reporting queue: the most a report holds.
pub const QUEUE_SIZE: usize = 32;
/// Longest wait for the device to return a report.
const WAIT_MS: u64 = 2000;

/// Queues: inflate, deflate, then the statistics and free page hinting
/// queues if the device has them, then reporting.  QEMU numbers its queues
/// by what it offers, whatever is negotiated; the statistics queue is
/// negotiated too, so that a device that numbers them by what is
/// negotiated agrees.
fn reporting_queue(offered: u64) -> u16 {
    2 + (offered & F_STATS_VQ != 0) as u16 + (offered & F_FREE_PAGE_HINT != 0) as u16
}

pub struct Balloon {
    vq: Virtq,
    /// Legacy devices are notified through I/O ports.
    ports: Option<Ports>,
    busy: bool,
    ticks_per_ms: u64,
}

impl Balloon {
    /// Set up the device for free page reporting.  None if it cannot
    /// report (the hypervisor did not enable it), or is unusable.
    pub fn new(cfg: &BalloonConfig, ticks_per_ms: u64) -> Option<Self> {
        let mut dma = Dma::new(DMA_VA, cfg.dma_paddr, DMA_PAGES * PAGE);
        if cfg.legacy_io != 0 {
            let p = Ports { cap: SLOT_BALLOON_IOPORT, base: cfg.legacy_io as u16 };
            let vq = Self::legacy(&p, &mut dma)?;
            return Some(Balloon { vq, ports: Some(p), busy: false, ticks_per_ms });
        }
        let dev = virtio::Device {
            common: Mmio(BalloonConfig::va(cfg.common)),
            notify: Mmio(BalloonConfig::va(cfg.notify)),
            notify_mult: cfg.notify_mult as u32,
            device: Mmio(BalloonConfig::va(cfg.device)),
        };
        dev.reset();
        let offered = dev.features();
        if offered & virtio::F_VERSION_1 == 0 || offered & F_REPORTING == 0 {
            l4h_rt::info!("memd: balloon: no free page reporting (features {:#x})", offered);
            dev.fail();
            return None;
        }
        if !dev.set_features(virtio::F_VERSION_1 | F_REPORTING | (offered & F_STATS_VQ)) {
            dev.fail();
            return None;
        }
        let idx = reporting_queue(offered);
        let Some(vq) = dev.setup_queue(&mut dma, idx, QUEUE_SIZE as u16, NO_VECTOR) else {
            dev.fail();
            return None;
        };
        dev.driver_ok();
        l4h_rt::info!("memd: balloon: free page reporting on queue {}, {} buffers", idx, vq.num);
        Some(Balloon { vq, ports: None, busy: false, ticks_per_ms })
    }

    /// The reporting queue of a legacy device.
    fn legacy(p: &Ports, dma: &mut Dma) -> Option<Virtq> {
        p.out8(legacy::STATUS, 0);
        p.out8(legacy::STATUS, STATUS_ACK | STATUS_DRIVER);
        let offered = p.in32(legacy::DEVICE_FEATURES) as u64;
        if offered & F_REPORTING == 0 {
            l4h_rt::info!("memd: balloon: no free page reporting (legacy, features {:#x})", offered);
            p.out8(legacy::STATUS, STATUS_FAILED);
            return None;
        }
        p.out32(legacy::GUEST_FEATURES, (F_REPORTING | (offered & F_STATS_VQ)) as u32);
        let idx = reporting_queue(offered);
        p.out16(legacy::QUEUE_SELECT, idx);
        // A legacy queue has the device's size, and a 32-bit page number.
        let num = p.in16(legacy::QUEUE_SIZE);
        if num == 0 || legacy_ring_size(num) > dma.remaining() {
            p.out8(legacy::STATUS, STATUS_FAILED);
            return None;
        }
        let (va, pa) = dma.alloc(legacy_ring_size(num), PAGE);
        if pa >> 12 > u32::MAX as u64 {
            p.out8(legacy::STATUS, STATUS_FAILED);
            return None;
        }
        p.out32(legacy::QUEUE_PFN, (pa >> 12) as u32);
        p.out8(legacy::STATUS, STATUS_ACK | STATUS_DRIVER | STATUS_DRIVER_OK);
        l4h_rt::info!("memd: balloon: free page reporting on legacy queue {}, {} entries", idx, num);
        Some(Virtq::legacy(idx, num, va))
    }

    /// Buffers one report can hold.
    pub fn capacity(&self) -> usize {
        (self.vq.num as usize).min(QUEUE_SIZE)
    }

    /// A report is in flight.
    pub fn busy(&self) -> bool {
        self.busy
    }

    /// Report `ranges` (physical address, length) as free.  Nothing may
    /// use them until `done`.
    pub fn report(&mut self, ranges: &[(usize, usize)]) {
        assert!(!self.busy && !ranges.is_empty() && ranges.len() <= self.capacity());
        for (i, &(addr, len)) in ranges.iter().enumerate() {
            assert!(len < 1 << 32);
            let next = i + 1 < ranges.len();
            let flags = DESC_F_WRITE | if next { DESC_F_NEXT } else { 0 };
            self.vq.set_desc(i as u16, addr as u64, len as u32, flags, if next { i as u16 + 1 } else { 0 });
        }
        self.vq.submit(0);
        self.vq.notify();
        if let Some(p) = &self.ports {
            p.out16(legacy::QUEUE_NOTIFY, self.vq.idx);
        }
        self.busy = true;
    }

    /// Whether the report in flight (if any) is done; `wait` waits for it,
    /// for a while.
    pub fn done(&mut self, wait: bool) -> bool {
        if !self.busy {
            return true;
        }
        let end = l4h_rt::host::ticks::now() + WAIT_MS * self.ticks_per_ms;
        loop {
            if self.vq.pop_used().is_some() {
                self.busy = false;
                return true;
            }
            if !wait || l4h_rt::host::ticks::now() > end {
                return false;
            }
            core::hint::spin_loop();
        }
    }
}

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
//! an allocation that needs a block in flight waits for it, for WAIT_MS at
//! most and for one report only: a device that holds a report longer gets
//! no more (mem.rs).  So a legacy
//! (0.9.5) device, whose registers are I/O ports, runs without MSI-X, and
//! has no vector registers.

use l4h_rt::host::memd::{BalloonConfig, DMA_PAGES, DMA_VA, SLOT_BALLOON_IOPORT};
use l4h_rt::ioport::Ports;
use l4h_virtio::{
    self as virtio, DESC_F_NEXT, DESC_F_WRITE, Dma, Mmio, NO_VECTOR, STATUS_ACK, STATUS_DRIVER, STATUS_DRIVER_OK, STATUS_FAILED, Virtq,
    legacy, legacy_ring_size,
};

const F_MUST_TELL_HOST: u64 = 1 << 0;
const F_STATS_VQ: u64 = 1 << 1;
const F_DEFLATE_ON_OOM: u64 = 1 << 2;
const F_FREE_PAGE_HINT: u64 = 1 << 3;
const F_REPORTING: u64 = 1 << 5;

const CFG_NUM_PAGES: usize = 0;
const CFG_ACTUAL: usize = 4;

const PAGE: usize = 4096;

/// Most 4 KiB PFNs in one traditional balloon inflate/deflate batch (16 KiB = 4 pages = 8 x 2 MiB blocks).
pub const MAX_PFNS: usize = 4096;
/// Most 4 KiB PFNs per individual virtqueue descriptor (matches Linux VIRTIO_BALLOON_ARRAY_PFNS_MAX = 256 = 1 KiB).
const DESC_PFNS: usize = 256;
/// Most bytes in one descriptor (lengths are 32 bits).
pub const MAX_DESC_BITS: usize = 31;
/// A block counts as free once it stayed free this long (as Linux does),
/// so that memory freed and soon allocated again is not reported.
pub const REPORT_DELAY_MS: u64 = 2000;
/// Buffers of the reporting queue: the most a report holds.
pub const QUEUE_SIZE: usize = 32;
/// Longest wait for the device to return a report or inflate/deflate ACK.
const WAIT_MS: u64 = 2000;

/// Queues: inflate, deflate, then the statistics and free page hinting
/// queues if the device has them, then reporting.  QEMU numbers its queues
/// by what it offers, whatever is negotiated; the statistics queue is
/// negotiated too, so that a device that numbers them by what is
/// negotiated agrees.
fn reporting_queue(offered: u64) -> u16 {
    2 + (offered & F_STATS_VQ != 0) as u16 + (offered & F_FREE_PAGE_HINT != 0) as u16
}

enum Kind {
    Reporting {
        vq: Virtq,
        /// Legacy devices are notified through I/O ports.
        ports: Option<Ports>,
    },
    Traditional {
        inflateq: Virtq,
        deflateq: Virtq,
        device: Mmio,
        pfn_va: usize,
        pfn_pa: u64,
        actual_pages: u32,
        in_flight_pfns: u32,
        in_flight_descs: usize,
        logged_first_inflate: bool,
    },
}

pub struct Balloon {
    kind: Kind,
    busy: bool,
    ticks_per_ms: u64,
}

impl Balloon {
    /// Set up the device for free page reporting or traditional ballooning.
    /// None if unusable.
    pub fn new(cfg: &BalloonConfig, ticks_per_ms: u64) -> Option<Self> {
        let mut dma = Dma::new(DMA_VA, cfg.dma_paddr, DMA_PAGES * PAGE);
        if cfg.legacy_io != 0 {
            let p = Ports { cap: SLOT_BALLOON_IOPORT, base: cfg.legacy_io as u16 };
            let vq = Self::legacy(&p, &mut dma)?;
            return Some(Balloon { kind: Kind::Reporting { vq, ports: Some(p) }, busy: false, ticks_per_ms });
        }
        let dev = virtio::Device {
            common: Mmio(BalloonConfig::va(cfg.common)),
            notify: Mmio(BalloonConfig::va(cfg.notify)),
            notify_mult: cfg.notify_mult as u32,
            notify_len: cfg.notify_len as usize,
            device: Mmio(BalloonConfig::va(cfg.device)),
        };
        if !dev.reset(l4h_rt::timeout_ms(virtio::RESET_MS)) { return None; }
        let offered = dev.features();
        if offered & virtio::F_VERSION_1 == 0 {
            l4h_rt::info!("memd: balloon: no VIRTIO_F_VERSION_1 (features {:#x})", offered);
            dev.fail();
            return None;
        }
        if offered & F_REPORTING != 0 {
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
            return Some(Balloon { kind: Kind::Reporting { vq, ports: None }, busy: false, ticks_per_ms });
        }

        l4h_rt::log!(
            "memd: balloon: traditional mode, offered features {:#x} (must_tell_host={}, deflate_on_oom={}, stats_vq={})",
            offered,
            offered & F_MUST_TELL_HOST != 0,
            offered & F_DEFLATE_ON_OOM != 0,
            offered & F_STATS_VQ != 0,
        );
        let want = virtio::F_VERSION_1 | (offered & (F_MUST_TELL_HOST | F_DEFLATE_ON_OOM | F_STATS_VQ));
        if !dev.set_features(want) {
            dev.fail();
            return None;
        }
        let Some(inflateq) = dev.setup_queue(&mut dma, 0, QUEUE_SIZE as u16, NO_VECTOR) else {
            dev.fail();
            return None;
        };
        let Some(deflateq) = dev.setup_queue(&mut dma, 1, QUEUE_SIZE as u16, NO_VECTOR) else {
            dev.fail();
            return None;
        };
        let (pfn_va, pfn_pa) = dma.alloc(MAX_PFNS * 4, PAGE);
        dev.driver_ok();
        let num_pages = u32::from_le(dev.device.r32(CFG_NUM_PAGES));
        l4h_rt::log!(
            "memd: balloon: traditional ready (inflateq={}, deflateq={}, num_pages={})",
            inflateq.num,
            deflateq.num,
            num_pages,
        );
        Some(Balloon {
            kind: Kind::Traditional {
                inflateq,
                deflateq,
                device: dev.device,
                pfn_va,
                pfn_pa,
                actual_pages: 0,
                in_flight_pfns: 0,
                in_flight_descs: 0,
                logged_first_inflate: false,
            },
            busy: false,
            ticks_per_ms,
        })
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

    pub fn is_traditional(&self) -> bool {
        matches!(self.kind, Kind::Traditional { .. })
    }

    /// Target inflated 4 KiB pages requested by the hypervisor (traditional mode).
    pub fn num_pages(&self) -> u32 {
        match &self.kind {
            Kind::Traditional { device, .. } => u32::from_le(device.r32(CFG_NUM_PAGES)),
            Kind::Reporting { .. } => 0,
        }
    }

    /// Currently inflated 4 KiB pages acknowledged by the hypervisor (traditional mode).
    pub fn actual_pages(&self) -> u32 {
        match &self.kind {
            Kind::Traditional { actual_pages, .. } => *actual_pages,
            Kind::Reporting { .. } => 0,
        }
    }

    /// Buffers one report can hold.
    pub fn capacity(&self) -> usize {
        match &self.kind {
            Kind::Reporting { vq, .. } => (vq.num as usize).min(QUEUE_SIZE),
            Kind::Traditional { .. } => QUEUE_SIZE,
        }
    }

    /// A report or inflate request is in flight.
    pub fn busy(&self) -> bool {
        self.busy
    }

    /// Report `ranges` (physical address, length) as free (free page reporting mode).
    /// Nothing may use them until `done`.
    pub fn report(&mut self, ranges: &[(usize, usize)]) {
        assert!(!self.busy && !ranges.is_empty() && ranges.len() <= self.capacity());
        let Kind::Reporting { vq, ports } = &mut self.kind else {
            panic!("memd: balloon: report called in traditional mode");
        };
        for (i, &(addr, len)) in ranges.iter().enumerate() {
            assert!(len < 1 << 32);
            let next = i + 1 < ranges.len();
            let flags = DESC_F_WRITE | if next { DESC_F_NEXT } else { 0 };
            vq.set_desc(i as u16, addr as u64, len as u32, flags, if next { i as u16 + 1 } else { 0 });
        }
        vq.submit(0);
        vq.notify();
        if let Some(p) = ports {
            p.out16(legacy::QUEUE_NOTIFY, vq.idx);
        }
        self.busy = true;
    }

    /// Inflate `ranges` (physical address, length) in traditional balloon mode.
    /// Total 4 KiB pages across `ranges` must be in `1..=MAX_PFNS`.
    /// Each virtqueue descriptor carries at most `DESC_PFNS` (256) PFNs to match
    /// Linux's `VIRTIO_BALLOON_ARRAY_PFNS_MAX`.
    pub fn inflate(&mut self, ranges: &[(usize, usize)]) {
        assert!(!self.busy && !ranges.is_empty());
        let Kind::Traditional {
            inflateq,
            device,
            pfn_va,
            pfn_pa,
            in_flight_pfns,
            in_flight_descs,
            logged_first_inflate,
            ..
        } = &mut self.kind
        else {
            panic!("memd: balloon: inflate called in reporting mode");
        };
        let max_pfns = MAX_PFNS.min((inflateq.num as usize) * DESC_PFNS);
        let buf = unsafe { core::slice::from_raw_parts_mut(*pfn_va as *mut u32, MAX_PFNS) };
        let mut count = 0usize;
        for &(addr, len) in ranges {
            debug_assert!(addr % PAGE == 0 && len % PAGE == 0);
            let pages = len >> 12;
            let base_pfn = addr >> 12;
            assert!(count + pages <= max_pfns);
            for p in 0..pages {
                buf[count + p] = ((base_pfn + p) as u32).to_le();
            }
            count += pages;
        }
        assert!(count > 0);
        if !*logged_first_inflate {
            *logged_first_inflate = true;
            let num_pages = u32::from_le(device.r32(CFG_NUM_PAGES));
            l4h_rt::log!(
                "memd: balloon: first inflate count={} pfns, first_pfn={:#x}, num_pages={}",
                count,
                u32::from_le(buf[0]),
                num_pages,
            );
        }
        let mut off = 0usize;
        let mut desc_idx = 0u16;
        while off < count {
            let chunk = (count - off).min(DESC_PFNS);
            // Traditional balloon inflateq descriptors are device-readable only (no DESC_F_WRITE).
            inflateq.set_desc(desc_idx, *pfn_pa + (off * 4) as u64, (chunk * 4) as u32, 0, 0);
            inflateq.submit(desc_idx);
            off += chunk;
            desc_idx += 1;
        }
        inflateq.notify();
        *in_flight_pfns = count as u32;
        *in_flight_descs = desc_idx as usize;
        self.busy = true;
    }

    /// Synchronously deflate `[paddr, paddr + len)` in traditional balloon mode,
    /// chunking by `DESC_PFNS` per descriptor and updating `actual` after used ACKs.
    /// Returns false on timeout.
    pub fn deflate_sync(&mut self, paddr: usize, len: usize) -> bool {
        assert!(!self.busy && paddr % PAGE == 0 && len % PAGE == 0 && len > 0);
        let Kind::Traditional { deflateq, device, pfn_va, pfn_pa, actual_pages, .. } = &mut self.kind else {
            return true;
        };
        let max_batch = MAX_PFNS.min((deflateq.num as usize) * DESC_PFNS);
        let buf = unsafe { core::slice::from_raw_parts_mut(*pfn_va as *mut u32, MAX_PFNS) };
        let total_pages = len >> 12;
        let base_pfn = paddr >> 12;
        let mut done_pages = 0usize;
        while done_pages < total_pages {
            let batch = (total_pages - done_pages).min(max_batch);
            for p in 0..batch {
                buf[p] = ((base_pfn + done_pages + p) as u32).to_le();
            }
            let mut off = 0usize;
            let mut desc_idx = 0u16;
            while off < batch {
                let chunk = (batch - off).min(DESC_PFNS);
                // Traditional balloon deflateq descriptors are device-readable only (no DESC_F_WRITE).
                deflateq.set_desc(desc_idx, *pfn_pa + (off * 4) as u64, (chunk * 4) as u32, 0, 0);
                deflateq.submit(desc_idx);
                off += chunk;
                desc_idx += 1;
            }
            deflateq.notify();
            let mut remaining = desc_idx as usize;
            let end = l4h_rt::host::ticks::now() + WAIT_MS * self.ticks_per_ms;
            while remaining > 0 {
                if deflateq.pop_used().is_some() {
                    remaining -= 1;
                    continue;
                }
                if l4h_rt::host::ticks::now() > end {
                    return false;
                }
                core::hint::spin_loop();
            }
            *actual_pages = actual_pages.saturating_sub(batch as u32);
            device.w32(CFG_ACTUAL, actual_pages.to_le());
            done_pages += batch;
        }
        true
    }

    /// Whether the report or inflate in flight (if any) is done; `wait` waits
    /// for it, for WAIT_MS at most.
    pub fn done(&mut self, wait: bool) -> bool {
        if !self.busy {
            return true;
        }
        let end = l4h_rt::host::ticks::now() + WAIT_MS * self.ticks_per_ms;
        loop {
            let finished = match &mut self.kind {
                Kind::Reporting { vq, .. } => vq.pop_used().is_some(),
                Kind::Traditional {
                    inflateq,
                    device,
                    actual_pages,
                    in_flight_pfns,
                    in_flight_descs,
                    ..
                } => {
                    while *in_flight_descs > 0 && inflateq.pop_used().is_some() {
                        *in_flight_descs -= 1;
                    }
                    if *in_flight_descs == 0 {
                        *actual_pages = actual_pages.saturating_add(*in_flight_pfns);
                        *in_flight_pfns = 0;
                        device.w32(CFG_ACTUAL, actual_pages.to_le());
                        true
                    } else {
                        false
                    }
                }
            };
            if finished {
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

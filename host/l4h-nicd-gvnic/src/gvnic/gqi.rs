//! GQI queues with registered page lists, as used on N2D Confidential VMs.
//! Rings and the page lists live in the driver's DMA region. Packet
//! descriptors contain offsets in their queue's page list.

use core::sync::atomic::Ordering;

use l4h_virtio::{dma_fence, Dma, Mmio};

use super::{be16, rd16, wr, wr64, Cmd, Gvnic, AQ_CREATE_RX_QUEUE, AQ_CREATE_TX_QUEUE, NTFY_RX, NTFY_TX, TX_DESC};
use crate::sdk::{Frame, Offer, Partial};

pub(super) const QUEUE_FORMAT: u8 = 2;
const AQ_REGISTER_PAGE_LIST: u32 = 3;
const TX_QPL: u32 = 0;
const RX_QPL: u32 = 1;
const PAGE: usize = 4096;
const RX_BUFFER: usize = 2048;
const RX_PAD: usize = 2;
const RX_DESC: usize = 64;
const RX_ERROR: u16 = 1 << 11;
const RX_CONT: u16 = 1 << 13;
const IRQ_MASK: u32 = 1 << 30;
const IRQ_ACK_EVENT: u32 = 1 << 31 | 1 << 29;

pub(super) struct Gqi {
    doorbells: Mmio,
    irq_db: [u32; 2],
    mtu: u16,
    tx_ring: usize,
    tx_buf: usize,
    tx_counter: Mmio,
    tx_db: u32,
    tx_mask: u32,
    tx_slots: u32,
    tx_head: u32,
    tx_tail: u32,
    tx_posted: u32,
    rx_ring: usize,
    rx_buf: usize,
    rx_db: u32,
    rx_mask: u32,
    rx_head: u32,
    rx_posted: u32,
    rx_seq: u16,
    rx_more: bool,
    rx_bad: bool,
}

impl Gqi {
    pub(super) fn new(
        g: &mut Gvnic, dma: &mut Dma, desc: &[u8], blocks: [usize; 2], counters: usize,
        db_index: impl Fn(usize) -> u32,
    ) -> Self {
        let tx_entries = be16(desc, 10) as usize;
        let rx_entries = be16(desc, 12) as usize;
        let tx_pages = be16(desc, 20) as usize;
        let max_pages = u64::from_be_bytes(desc[0..8].try_into().unwrap());
        assert!(tx_pages > 0 && (tx_pages + rx_entries) as u64 <= max_pages, "gVNIC: invalid page counts");

        let tx_buf = Self::register(g, dma, TX_QPL, tx_pages);
        let rx_buf = Self::register(g, dma, RX_QPL, rx_entries);
        let (tx_ring, tx_ring_pa) = dma.alloc(tx_entries * TX_DESC, PAGE);
        let (rx_ring, rx_ring_pa) = dma.alloc(rx_entries * RX_DESC, PAGE);
        let (rx_data, rx_data_pa) = dma.alloc(rx_entries * 8, PAGE);
        let (tx_res, tx_res_pa) = dma.alloc(64, 64);
        let (rx_res, rx_res_pa) = dma.alloc(64, 64);
        for i in 0..rx_entries {
            wr64(rx_data + i * 8, ((i * PAGE) as u64).to_be());
        }

        g.exec(
            "create GQI TX queue",
            Cmd::new(AQ_CREATE_TX_QUEUE).u64(8, tx_res_pa).u64(16, tx_ring_pa)
                .u32(24, TX_QPL).u32(28, blocks[0] as u32).u16(40, tx_entries as u16),
        );
        g.exec(
            "create GQI RX queue",
            Cmd::new(AQ_CREATE_RX_QUEUE).u32(12, blocks[1] as u32).u64(16, rx_res_pa)
                .u64(24, rx_ring_pa).u64(32, rx_data_pa).u32(40, RX_QPL)
                .u16(44, rx_entries as u16).u16(46, RX_BUFFER as u16),
        );
        let counter_index = u32::from_be(Mmio(tx_res).r32(4)) as usize;
        assert!(counter_index < be16(desc, 18) as usize, "gVNIC: invalid TX counter index");
        // Keep the buffer index valid across the wrapping descriptor counter.
        let tx_slots = 1 << tx_entries.min(tx_pages).ilog2();
        let q = Self {
            doorbells: g.doorbells, irq_db: g.irq_db, mtu: be16(desc, 16),
            tx_ring, tx_buf, tx_counter: Mmio(counters + counter_index * 4),
            tx_db: db_index(tx_res), tx_mask: tx_entries as u32 - 1, tx_slots,
            tx_head: 0, tx_tail: 0, tx_posted: 0,
            rx_ring, rx_buf, rx_db: db_index(rx_res), rx_mask: rx_entries as u32 - 1,
            rx_head: 0, rx_posted: rx_entries as u32, rx_seq: 1, rx_more: false, rx_bad: false,
        };
        q.ring(q.irq_db[NTFY_TX], IRQ_MASK);
        q.ring(q.rx_db, q.rx_posted);
        q.ring(q.irq_db[NTFY_RX], IRQ_ACK_EVENT);
        q
    }

    fn register(g: &mut Gvnic, dma: &mut Dma, id: u32, pages: usize) -> usize {
        let (buf, pa) = dma.alloc(pages * PAGE, PAGE);
        let (list, list_pa) = dma.alloc(pages * 8, 64);
        for i in 0..pages {
            wr64(list + i * 8, (pa + (i * PAGE) as u64).to_be());
        }
        g.exec(
            "register queue page list",
            Cmd::new(AQ_REGISTER_PAGE_LIST).u32(0, id).u32(4, pages as u32)
                .u64(8, list_pa).u64(16, PAGE as u64),
        );
        buf
    }

    pub(super) fn offer(&self, mac: [u8; 6]) -> Offer {
        let mut offer = Offer::plain(mac);
        // One packet descriptor and one registered page per transmitted frame.
        offer.tx_frame_max = (PAGE as u32).min(self.mtu as u32 + 18);
        offer
    }

    fn ring(&self, index: u32, value: u32) {
        self.doorbells.w32(index as usize * 4, value.to_be());
    }

    fn tx_completion(&self) -> u32 {
        let head = u32::from_be(self.tx_counter.r32(0));
        if head.wrapping_sub(self.tx_head) <= self.tx_posted.wrapping_sub(self.tx_head) {
            head
        } else {
            self.tx_head
        }
    }

    pub(super) fn transmit(&mut self, frame: &(impl Frame + ?Sized)) -> bool {
        let capacity = self.tx_slots.min(self.tx_mask);
        if self.tx_tail.wrapping_sub(self.tx_head) >= capacity {
            self.tx_head = self.tx_completion();
            dma_fence(Ordering::Acquire);
            if self.tx_tail.wrapping_sub(self.tx_head) >= capacity {
                self.kick_tx();
                return false;
            }
        }
        let offset = ((self.tx_tail & (self.tx_slots - 1)) as usize) * PAGE;
        let data = unsafe { core::slice::from_raw_parts_mut((self.tx_buf + offset) as *mut u8, PAGE) };
        frame.copy_to(&mut data[..frame.len()]);
        let mut d = [0; TX_DESC];
        d[3] = 1; // One standard descriptor for the entire frame.
        let len = (frame.len() as u16).to_be_bytes();
        d[4..6].copy_from_slice(&len);
        d[6..8].copy_from_slice(&len);
        d[8..16].copy_from_slice(&(offset as u64).to_be_bytes());
        wr(self.tx_ring + (self.tx_tail & self.tx_mask) as usize * TX_DESC, &d);
        self.tx_tail = self.tx_tail.wrapping_add(1);
        true
    }

    pub(super) fn tx_interrupts(&mut self, on: bool) -> bool {
        self.ring(self.irq_db[NTFY_TX], if on { IRQ_ACK_EVENT } else { IRQ_MASK });
        dma_fence(Ordering::SeqCst);
        on && self.tx_completion() != self.tx_head
    }

    pub(super) fn kick_tx(&mut self) {
        if self.tx_posted != self.tx_tail {
            self.tx_posted = self.tx_tail;
            dma_fence(Ordering::Release);
            self.ring(self.tx_db, self.tx_posted);
        }
    }

    fn rx_next(&self) -> Option<(usize, u16)> {
        let slot = (self.rx_head & self.rx_mask) as usize;
        let flags = u16::from_be(rd16(self.rx_ring + slot * RX_DESC + 62));
        (flags & 7 == self.rx_seq).then_some((slot, flags))
    }

    pub(super) fn rx_begin(&self) {
        self.ring(self.irq_db[NTFY_RX], IRQ_MASK);
    }

    pub(super) fn rx_done(&mut self) -> bool {
        let fill = self.rx_head.wrapping_add(self.rx_mask + 1);
        if self.rx_posted != fill {
            self.rx_posted = fill;
            dma_fence(Ordering::Release);
            self.ring(self.rx_db, fill);
        }
        self.ring(self.irq_db[NTFY_RX], IRQ_ACK_EVENT);
        dma_fence(Ordering::SeqCst);
        if self.rx_next().is_some() {
            self.rx_begin();
            return false;
        }
        true
    }

    pub(super) fn receive(&mut self, out: &mut [u8], partial: &mut Partial) -> Option<usize> {
        while let Some((slot, flags)) = self.rx_next() {
            dma_fence(Ordering::Acquire);
            let len = u16::from_be(rd16(self.rx_ring + slot * RX_DESC + 60)) as usize;
            let pad = if self.rx_more { 0 } else { RX_PAD };
            let more = flags & RX_CONT != 0;
            self.rx_head = self.rx_head.wrapping_add(1);
            self.rx_seq = self.rx_seq % 7 + 1;
            self.rx_more = more;
            self.rx_bad |= flags & RX_ERROR != 0 || len < pad || len > RX_BUFFER;
            if !self.rx_bad {
                let va = self.rx_buf + slot * PAGE + pad;
                let data = unsafe { core::slice::from_raw_parts(va as *const u8, len - pad) };
                if !more && partial.is_empty() && data.len() <= out.len() {
                    out[..data.len()].copy_from_slice(data);
                    return Some(data.len());
                }
                self.rx_bad = partial.extend_from_slice(data).is_err();
            }
            if !more {
                let ok = !core::mem::take(&mut self.rx_bad) && partial.len() <= out.len();
                let len = partial.len();
                if ok {
                    out[..len].copy_from_slice(partial);
                }
                partial.clear();
                if ok {
                    return Some(len);
                }
            }
        }
        None
    }
}

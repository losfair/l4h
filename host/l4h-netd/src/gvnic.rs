//! Google Virtual NIC (gVNIC) driver, after Linux `gve`.  GCE machine
//! types from the third generation on (C3, N4, C4, ...) have only this NIC.
//! The driver uses the DQO queue format with raw DMA addressing (DQO_RDA),
//! which those machines offer: one TX queue with its completion queue and
//! one RX buffer queue with its completion queue.  Frames are copied
//! between the switch and DMA buffers owned by this driver, as for
//! virtio-net.
//!
//! The device is configured through big-endian registers in BAR 0 and an
//! admin queue of 64-byte commands; queue and interrupt doorbells are
//! little-endian words in BAR 2.  Each notification block is an MSI-X
//! entry and an interrupt doorbell; as Linux, the driver configures one
//! per MSI-X entry but the last (the management vector, left masked),
//! puts the TX queue on the first and the RX queue on the first of the
//! second half.  netd has one interrupt per NIC, so both raise the same
//! vector.  A DQO block masks itself when it fires and is re-armed
//! through its doorbell.

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::Ordering;

use l4h_rt::host::fixed::ArrayVec;
use l4h_rt::host::{self, net::{self, NicConfig}};
use l4h_virtio::{Dma, Mmio, dma_fence};

use crate::nic::Partial;
use crate::offload;
use crate::pool::Frame;

const HDR: usize = net::HDR_SIZE;

// Registers (BAR 0, big-endian).
const REG_DEVICE_STATUS: usize = 0x00;
const REG_DRIVER_STATUS: usize = 0x04;
const REG_ADMINQ_PFN: usize = 0x10;
const REG_ADMINQ_DOORBELL: usize = 0x14;
const REG_ADMINQ_EVENT_COUNTER: usize = 0x18;
const REG_DRIVER_VERSION: usize = 0x1f;
const REG_ADMINQ_BASE_HI: usize = 0x20;
const REG_ADMINQ_BASE_LO: usize = 0x24;
const REG_ADMINQ_LENGTH: usize = 0x28;
const DEVICE_STATUS_LINK: u32 = 1 << 2;
const DEVICE_STATUS_IS_RESET: u32 = 1 << 4;
const DRIVER_STATUS_RUN: u32 = 1 << 0;
const DRIVER_STATUS_RESET: u32 = 1 << 1;

// Admin queue.
const ADMINQ_SIZE: usize = 4096;
const CMD_SIZE: usize = 64;
const AQ_DESCRIBE_DEVICE: u32 = 0x1;
const AQ_VERIFY_DRIVER_COMPATIBILITY: u32 = 0xf;
const AQ_CONFIGURE_DEVICE_RESOURCES: u32 = 0x2;
const AQ_CREATE_TX_QUEUE: u32 = 0x5;
const AQ_CREATE_RX_QUEUE: u32 = 0x6;
const AQ_GET_PTYPE_MAP: u32 = 0xe;
const AQ_PASSED: u32 = 1;
const AQ_UNIMPLEMENTED: u32 = 0xffff_fffe;
/// Driver capability flags (word 1): the DQO RDA queue format.
const DRIVER_CAP_DQO_RDA: u64 = 1 << 3;
const DEVICE_DESCRIPTOR_VERSION: u32 = 1;
const OPT_GQI_RAW_ADDRESSING: u16 = 0x1;
const OPT_GQI_RDA: u16 = 0x2;
const OPT_GQI_QPL: u16 = 0x3;
const OPT_DQO_RDA: u16 = 0x4;
const OPT_DQO_QPL: u16 = 0x7;
const QUEUE_FORMAT_DQO_RDA: u8 = 0x3;
const RAW_ADDRESSING_QPL_ID: u32 = 0xffff_ffff;
/// irq_db entries: the notification blocks of the TX and RX queues.
const NTFY_TX: usize = 0;
const NTFY_RX: usize = 1;
/// struct gve_irq_db is cache-line aligned.
const IRQ_DB_STRIDE: usize = 64;
const NUM_PTYPES: usize = 1024;
const L3_IPV4: u8 = 2;
const L3_IPV6: u8 = 3;
const L4_TCP: u8 = 2;
const L4_UDP: u8 = 3;
const L4_ICMP: u8 = 4;
const L4_SCTP: u8 = 5;

// Interrupt doorbell values (DQO).
const ITR_ENABLE: u32 = 1 << 0;
const ITR_NO_UPDATE: u32 = 3 << 3;
const ITR_INTERVAL_SHIFT: u32 = 5;
/// Interrupt coalescing, as Linux: µs (2 µs granularity).
const RX_ITR_US: u32 = 20;
const TX_ITR_US: u32 = 50;

// TX descriptors (16 bytes) and completions (8 bytes).
const TX_DESC: usize = 16;
const TX_COMPL: usize = 8;
const DTYPE_PKT: u8 = 0xc;
const DTYPE_TSO_CTX: u8 = 0x5;
const DTYPE_GENERAL_CTX: u8 = 0x4;
const PKT_EOP: u8 = 1 << 5;
const PKT_CSUM: u8 = 1 << 6;
const PKT_REPORT_EVENT: u8 = 1 << 7;
const TX_MAX_BUF: usize = 16 * 1024 - 1;
const TSO_MIN_MSS: usize = 88;
const TSO_MAX_MSS: usize = 9728;
const TSO_MAX_HDR: usize = 255;
/// Descriptor completions may be asked for at most this often.
const MIN_RE_INTERVAL: u32 = 32;
/// Free descriptors kept between tail and head.
const TX_RING_SLACK: u32 = 4;
const COMPL_MISS: u16 = 0x1;
const COMPL_PKT: u16 = 0x2;
const COMPL_REINJECTION: u16 = 0x3;
const COMPL_DESC: u16 = 0x4;
const ALT_MISS_BIT: u16 = 1 << 15;
/// A buffer whose packet took the miss path is reused once reinjected, or
/// after this long without (Linux frees its completion tag after 60 s).
const MISS_TIMEOUT_SECS: u64 = 60;
/// Transmit buffers: whole TSO frames.
const TX_BUFS: usize = 24;

// RX buffer descriptors and completions (32 bytes each).
const RX_DESC: usize = 32;
const RX_COMPL: usize = 32;
const RX_BUF: usize = 2048;
const RX_BUFS: u32 = 512;
/// The buffer queue doorbell is rung when its tail crosses a multiple of
/// this (it must be at least 8).
const RX_BUF_THRESH: u32 = 32;

fn rd8(va: usize) -> u8 {
    unsafe { read_volatile(va as *const u8) }
}
fn rd16(va: usize) -> u16 {
    unsafe { read_volatile(va as *const u16) }
}
fn wr(va: usize, b: &[u8]) {
    for (i, &x) in b.iter().enumerate() {
        unsafe { write_volatile((va + i) as *mut u8, x) };
    }
}
fn wr64(va: usize, v: u64) {
    unsafe { write_volatile(va as *mut u64, v) }
}
fn be16(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([b[off], b[off + 1]])
}

/// A 64-byte admin queue command: opcode, status, then its fields, all
/// big-endian.
struct Cmd([u8; CMD_SIZE]);

impl Cmd {
    fn new(opcode: u32) -> Self {
        let mut c = Cmd([0; CMD_SIZE]);
        c.0[0..4].copy_from_slice(&opcode.to_be_bytes());
        c
    }
    /// Fields are at `off` from the start of the command's body.
    fn u8(mut self, off: usize, v: u8) -> Self {
        self.0[8 + off] = v;
        self
    }
    fn u16(mut self, off: usize, v: u16) -> Self {
        self.0[8 + off..10 + off].copy_from_slice(&v.to_be_bytes());
        self
    }
    fn u32(mut self, off: usize, v: u32) -> Self {
        self.0[8 + off..12 + off].copy_from_slice(&v.to_be_bytes());
        self
    }
    fn u64(mut self, off: usize, v: u64) -> Self {
        self.0[8 + off..16 + off].copy_from_slice(&v.to_be_bytes());
        self
    }
}

#[derive(Clone, Copy, PartialEq)]
enum TxBuf {
    Free,
    /// With the device, which sends a packet completion.
    Sent,
    /// The packet took the miss path; a reinjection completion follows.
    Missed(u64),
}

pub struct Gvnic {
    n: usize,
    pub mac: [u8; 6],
    pub csum: bool,
    pub tso: bool,
    regs: Mmio,
    doorbells: Mmio,
    tsc_hz: u64,
    adminq: (usize, u64),
    adminq_prod: u32,
    /// Interrupt doorbell index of each notification block.
    irq_db: [u32; 2],
    ptypes: [(u8, u8); NUM_PTYPES],

    tx_ring: usize,
    tx_mask: u32,
    tx_tail: u32,
    /// Last descriptor the device fetched + 1, from descriptor completions.
    tx_head: u32,
    tx_last_re: u32,
    tx_compl: usize,
    tx_compl_head: u32,
    tx_compl_gen: u16,
    tx_db: u32,
    tx_bufs: ArrayVec<(usize, u64), TX_BUFS>,
    tx_state: ArrayVec<TxBuf, TX_BUFS>,
    tx_free: ArrayVec<u16, TX_BUFS>,
    tx_kick: bool,

    rx_bufq: usize,
    rx_mask: u32,
    rx_tail: u32,
    rx_compl: usize,
    rx_compl_head: u32,
    rx_compl_gen: u16,
    rx_db: u32,
    rx_bufs: ArrayVec<(usize, u64), { RX_BUFS as usize }>,
    /// A frame that spans buffers, while its completions arrive.
    rx_partial: &'static mut Partial,
    rx_partial_bad: bool,
}

impl Gvnic {
    pub fn new(n: usize, c: &NicConfig, tsc_hz: u64, rx_partial: &'static mut Partial) -> Self {
        let mut dma = Dma::new(net::nic_dma_va(n), c.dma_paddr, c.dma_size as usize);
        let regs = Mmio(c.regs.va as usize);
        let doorbells = Mmio(c.doorbells.va as usize);
        // MSI-X: the queues' notification blocks on netd's vector, the
        // others and the management vector (link and reset events, which
        // netd does not act on) masked.
        let msix = Mmio(c.msix_table.va as usize);
        let entries = (c.msix_table.len / 16) as usize;
        let blocks = (entries - 1) & !1;
        let (tx_blk, rx_blk) = (0, blocks / 2);
        for e in 0..entries {
            msix.w32(e * 16, c.msi_address as u32);
            msix.w32(e * 16 + 4, (c.msi_address >> 32) as u32);
            msix.w32(e * 16 + 8, c.msi_data);
            msix.w32(e * 16 + 12, (e != tx_blk && e != rx_blk) as u32);
        }
        let mut g = Gvnic {
            n,
            mac: [0; 6],
            csum: true,
            tso: true,
            regs,
            doorbells,
            tsc_hz,
            adminq: dma.alloc(ADMINQ_SIZE, 4096),
            adminq_prod: 0,
            irq_db: [0; 2],
            ptypes: [(0, 0); NUM_PTYPES],
            tx_ring: 0,
            tx_mask: 0,
            tx_tail: 0,
            tx_head: 0,
            tx_last_re: 0,
            tx_compl: 0,
            tx_compl_head: 0,
            tx_compl_gen: 0,
            tx_db: 0,
            tx_bufs: ArrayVec::new(),
            tx_state: ArrayVec::new(),
            tx_free: ArrayVec::new(),
            tx_kick: false,
            rx_bufq: 0,
            rx_mask: 0,
            rx_tail: 0,
            rx_compl: 0,
            rx_compl_head: 0,
            rx_compl_gen: 0,
            rx_db: 0,
            rx_bufs: ArrayVec::new(),
            rx_partial,
            rx_partial_bad: false,
        };
        for &b in b"GVE-l4h\n" {
            regs.w8(REG_DRIVER_VERSION, b);
        }
        g.reset(c.revision);
        // Admin queue.
        let (_, aq_pa) = g.adminq;
        if c.revision < 1 {
            g.w32(REG_ADMINQ_PFN, (aq_pa / 4096) as u32);
        } else {
            regs.w16(REG_ADMINQ_LENGTH, (ADMINQ_SIZE as u16).to_be());
            g.w32(REG_ADMINQ_BASE_HI, (aq_pa >> 32) as u32);
            g.w32(REG_ADMINQ_BASE_LO, aq_pa as u32);
            g.w32(REG_DRIVER_STATUS, DRIVER_STATUS_RUN);
        }

        // What this driver is (the device may not know the command).
        let (info_va, info_pa) = dma.alloc(304, 64);
        let mut info = [0u8; 304];
        // Unknown OS type 0 (Linux is 1), driver version 1.0.0.
        info[1] = 1;
        info[16..24].copy_from_slice(&DRIVER_CAP_DQO_RDA.to_be_bytes());
        info[48..51].copy_from_slice(b"l4h");
        info[176..179].copy_from_slice(b"l4h");
        wr(info_va, &info);
        match g.try_exec("verify driver compatibility", Cmd::new(AQ_VERIFY_DRIVER_COMPATIBILITY).u64(0, 304).u64(8, info_pa)) {
            AQ_PASSED | AQ_UNIMPLEMENTED => {}
            st => panic!("netd: NIC {}: gVNIC rejects this driver: status {:#x}", n, st),
        }

        // The device's description and options.
        let (desc_va, desc_pa) = dma.alloc(4096, 4096);
        g.exec(
            "describe device",
            Cmd::new(AQ_DESCRIBE_DEVICE).u64(0, desc_pa).u32(8, DEVICE_DESCRIPTOR_VERSION).u32(12, 4096),
        );
        let d: [u8; 4096] = core::array::from_fn(|i| rd8(desc_va + i));
        let tx_entries = be16(&d, 10) as u32;
        let rx_entries = be16(&d, 12) as u32;
        let mtu = be16(&d, 16);
        let counters = be16(&d, 18) as usize;
        g.mac.copy_from_slice(&d[24..30]);
        let (mut off, mut formats) = (40, 0u32);
        for _ in 0..be16(&d, 30) {
            if off + 8 > d.len() {
                break;
            }
            let (id, len) = (be16(&d, off), be16(&d, off + 2) as usize);
            if id < 32 {
                formats |= 1 << id;
            }
            off += 8 + len;
        }
        if formats & (1 << OPT_DQO_RDA) == 0 {
            panic!(
                "netd: NIC {}: gVNIC without the DQO RDA queue format (options {:#x}: gqi raw {} gqi rda {} gqi qpl {} dqo qpl {})",
                n, formats, formats >> OPT_GQI_RAW_ADDRESSING & 1, formats >> OPT_GQI_RDA & 1,
                formats >> OPT_GQI_QPL & 1, formats >> OPT_DQO_QPL & 1
            );
        }
        if !tx_entries.is_power_of_two() || !rx_entries.is_power_of_two() || tx_entries < 64 || rx_entries < 64 {
            panic!("netd: NIC {}: gVNIC ring sizes tx {} rx {}", n, tx_entries, rx_entries);
        }

        // Event counters and interrupt doorbell indices, written by the
        // device.
        let (_, counters_pa) = dma.alloc(counters.max(1) * 4, 4096);
        let (irq_db_va, irq_db_pa) = dma.alloc(blocks * IRQ_DB_STRIDE, 4096);
        g.exec(
            "configure device resources",
            Cmd::new(AQ_CONFIGURE_DEVICE_RESOURCES)
                .u64(0, counters_pa)
                .u64(8, irq_db_pa)
                .u32(16, counters as u32)
                .u32(20, blocks as u32)
                .u32(24, IRQ_DB_STRIDE as u32)
                .u32(28, 0)
                .u8(32, QUEUE_FORMAT_DQO_RDA),
        );
        for (db, blk) in g.irq_db.iter_mut().zip([tx_blk, rx_blk]) {
            *db = u32::from_be(unsafe { read_volatile((irq_db_va + blk * IRQ_DB_STRIDE) as *const u32) });
        }
        // Packet types: which received frames had their checksums checked.
        let (ptype_va, ptype_pa) = dma.alloc(NUM_PTYPES * 2, 4096);
        g.exec("get ptype map", Cmd::new(AQ_GET_PTYPE_MAP).u64(0, (NUM_PTYPES * 2) as u64).u64(8, ptype_pa));
        g.ptypes = core::array::from_fn(|i| (rd8(ptype_va + 2 * i), rd8(ptype_va + 2 * i + 1)));

        // The queues' rings grow with the sizes the device asks for: all
        // they and the buffers take (with alignment) must fit.  Each TX
        // packet has at most two completions (miss, reinjection) and there
        // is a descriptor completion per MIN_RE_INTERVAL descriptors: the
        // completion queue cannot overflow.
        let bufs = TX_BUFS.min((tx_entries - tx_entries / MIN_RE_INTERVAL) as usize / 2);
        let rx_bufs = RX_BUFS.min(rx_entries - 1) as usize;
        let rings = tx_entries as usize * (TX_DESC + TX_COMPL) + rx_entries as usize * (RX_DESC + RX_COMPL);
        let need = rings + 4 * 4096 + 2 * 128 + bufs * (net::MAX_FRAME + 64) + rx_bufs * (RX_BUF + 64);
        if need > dma.remaining() {
            panic!("netd: NIC {}: gVNIC ring sizes tx {} rx {} need {} KiB of DMA memory, {} KiB left",
                n, tx_entries, rx_entries, need >> 10, dma.remaining() >> 10);
        }

        // TX queue.
        let (tx_ring, tx_ring_pa) = dma.alloc(tx_entries as usize * TX_DESC, 4096);
        let (tx_compl, tx_compl_pa) = dma.alloc(tx_entries as usize * TX_COMPL, 4096);
        let (tx_res, tx_res_pa) = dma.alloc(64, 64);
        for i in 0..bufs {
            let _ = g.tx_bufs.push(dma.alloc(net::MAX_FRAME, 64));
            let _ = g.tx_state.push(TxBuf::Free);
            let _ = g.tx_free.push((bufs - 1 - i) as u16);
        }
        (g.tx_ring, g.tx_compl, g.tx_mask) = (tx_ring, tx_compl, tx_entries - 1);
        g.exec(
            "create TX queue",
            Cmd::new(AQ_CREATE_TX_QUEUE)
                .u32(0, 0)
                .u64(8, tx_res_pa)
                .u64(16, tx_ring_pa)
                .u32(24, RAW_ADDRESSING_QPL_ID)
                .u32(28, tx_blk as u32)
                .u64(32, tx_compl_pa)
                .u16(40, tx_entries as u16)
                .u16(42, tx_entries as u16),
        );
        g.tx_db = u32::from_be(unsafe { read_volatile(tx_res as *const u32) });

        // RX queue.  At most one buffer per completion slot is posted.
        let (rx_bufq, rx_bufq_pa) = dma.alloc(rx_entries as usize * RX_DESC, 4096);
        let (rx_compl, rx_compl_pa) = dma.alloc(rx_entries as usize * RX_COMPL, 4096);
        let (rx_res, rx_res_pa) = dma.alloc(64, 64);
        for _ in 0..rx_bufs {
            let _ = g.rx_bufs.push(dma.alloc(RX_BUF, 64));
        }
        (g.rx_bufq, g.rx_compl, g.rx_mask) = (rx_bufq, rx_compl, rx_entries - 1);
        g.exec(
            "create RX queue",
            Cmd::new(AQ_CREATE_RX_QUEUE)
                .u32(0, 0)
                .u32(12, rx_blk as u32)
                .u64(16, rx_res_pa)
                .u64(24, rx_compl_pa)
                .u64(32, rx_bufq_pa)
                .u32(40, RAW_ADDRESSING_QPL_ID)
                .u16(44, rx_entries as u16)
                .u16(46, RX_BUF as u16)
                .u16(48, rx_entries as u16),
        );
        g.rx_db = u32::from_be(unsafe { read_volatile(rx_res as *const u32) });
        for id in 0..g.rx_bufs.len() as u16 {
            g.post_rx(id);
        }
        g.irq(NTFY_RX, ITR_ENABLE | (RX_ITR_US / 2) << ITR_INTERVAL_SHIFT);

        let mac = g.mac;
        let link = g.r32(REG_DEVICE_STATUS) & DEVICE_STATUS_LINK != 0;
        l4h_rt::info!(
            "netd: NIC {}: {:02x}:{:02x}.{} gVNIC rev {} dqo-rda, {} blocks, mac {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, mtu {}, rings tx {} rx {}, link {}",
            n, c.pci_bdf >> 8, (c.pci_bdf >> 3) & 0x1f, c.pci_bdf & 7, c.revision, blocks,
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
            mtu, tx_entries, rx_entries, if link { "up" } else { "down" },
        );
        g
    }

    fn r32(&self, off: usize) -> u32 {
        u32::from_be(self.regs.r32(off))
    }

    fn w32(&self, off: usize, v: u32) {
        self.regs.w32(off, v.to_be())
    }

    /// Ticks since boot.
    fn deadline(&self, secs: u64) -> u64 {
        host::ticks::now() + secs * self.tsc_hz
    }

    /// Release an admin queue that firmware left registered, which resets
    /// the device.  Only then: on C3 (revision 0), releasing when no queue
    /// is registered makes the device reset itself about a second later,
    /// dropping the admin queue registered meanwhile.
    fn reset(&self, revision: u32) {
        let end = self.deadline(5);
        if revision < 1 {
            if self.r32(REG_ADMINQ_PFN) == 0 {
                return;
            }
            self.w32(REG_ADMINQ_PFN, 0);
            while self.r32(REG_ADMINQ_PFN) != 0 {
                if host::ticks::now() > end {
                    panic!("netd: NIC {}: gVNIC does not release its admin queue", self.n);
                }
            }
        } else {
            if self.r32(REG_ADMINQ_BASE_HI) | self.r32(REG_ADMINQ_BASE_LO) == 0 {
                return;
            }
            self.w32(REG_DRIVER_STATUS, DRIVER_STATUS_RESET);
            while self.r32(REG_DEVICE_STATUS) & DEVICE_STATUS_IS_RESET == 0 {
                if host::ticks::now() > end {
                    // Setting up the admin queue fails if this mattered.
                    l4h_rt::log!("netd: NIC {}: gVNIC reports no reset (status {:#x})", self.n, self.r32(REG_DEVICE_STATUS));
                    return;
                }
            }
        }
    }

    /// Run one admin command and wait for it; a failure is fatal, as for a
    /// virtio-net device that refuses its setup.
    fn exec(&mut self, what: &str, cmd: Cmd) {
        let status = self.try_exec(what, cmd);
        if status != AQ_PASSED {
            panic!("netd: NIC {}: gVNIC admin command '{}' failed: status {:#x}", self.n, what, status);
        }
    }

    /// Run one admin command, wait for it and return its status.
    fn try_exec(&mut self, what: &str, cmd: Cmd) -> u32 {
        let (va, _) = self.adminq;
        let slot = va + (self.adminq_prod as usize % (ADMINQ_SIZE / CMD_SIZE)) * CMD_SIZE;
        wr(slot, &cmd.0);
        self.adminq_prod = self.adminq_prod.wrapping_add(1);
        dma_fence(Ordering::Release);
        self.w32(REG_ADMINQ_DOORBELL, self.adminq_prod);
        let end = self.deadline(10);
        while self.r32(REG_ADMINQ_EVENT_COUNTER) != self.adminq_prod {
            if host::ticks::now() > end {
                panic!(
                    "netd: NIC {}: gVNIC admin command '{}' timed out (device status {:#x}, events {})",
                    self.n, what, self.r32(REG_DEVICE_STATUS), self.r32(REG_ADMINQ_EVENT_COUNTER)
                );
            }
        }
        dma_fence(Ordering::Acquire);
        u32::from_be(unsafe { read_volatile((slot + 4) as *const u32) })
    }

    fn doorbell(&self, index: u32, v: u32) {
        self.doorbells.w32(index as usize * 4, v.to_le());
    }

    fn irq(&self, block: usize, v: u32) {
        self.doorbell(self.irq_db[block], v);
    }

    // ---- receive

    /// Give buffer `id` to the device.
    fn post_rx(&mut self, id: u16) {
        let d = self.rx_bufq + self.rx_tail as usize * RX_DESC;
        let (_, pa) = self.rx_bufs[id as usize];
        unsafe { write_volatile(d as *mut u16, id.to_le()) };
        wr64(d + 8, pa.to_le());
        wr64(d + 16, 0);
        self.rx_tail = (self.rx_tail + 1) & self.rx_mask;
        if self.rx_tail % RX_BUF_THRESH == 0 {
            dma_fence(Ordering::Release);
            self.doorbell(self.rx_db, self.rx_tail);
        }
    }

    /// The next RX completion, if the device has written it.
    fn rx_pending(&self) -> Option<usize> {
        let d = self.rx_compl + self.rx_compl_head as usize * RX_COMPL;
        (u16::from_le(rd16(d + 4)) >> 14 & 1 != self.rx_compl_gen).then_some(d)
    }

    pub fn rx_begin(&self) {
        // The block masked itself when it fired.
    }

    pub fn rx_done(&mut self) -> bool {
        if self.rx_pending().is_some() {
            return false;
        }
        self.irq(NTFY_RX, ITR_ENABLE | ITR_NO_UPDATE);
        // Completions written before the block was armed raise it again
        // (the device keeps them pending), so this is only a shortcut.
        self.rx_pending().is_none()
    }

    /// Whether the device checked the frame's L3 and L4 checksums.
    fn csum_ok(&self, d: usize) -> bool {
        let status = rd8(d + 8);
        let (l3, l4) = self.ptypes[(u16::from_le(rd16(d + 2)) & 0x3ff) as usize];
        // l3_l4_processed, and no IP, L4 or outer IP checksum error.
        if status & 1 << 3 == 0 || status & (1 << 4 | 1 << 5 | 1 << 6) != 0 {
            return false;
        }
        // An IPv6 destination options or routing header (ipv6_ex_add).
        if l3 == L3_IPV6 && rd8(d + 1) & 1 << 1 != 0 {
            return false;
        }
        (l3 == L3_IPV4 || l3 == L3_IPV6) && matches!(l4, L4_TCP | L4_UDP | L4_ICMP | L4_SCTP)
    }

    pub fn receive(&mut self, out: &mut [u8], hdr: &mut [u8; HDR]) -> Option<usize> {
        loop {
            let d = self.rx_pending()?;
            dma_fence(Ordering::Acquire);
            let len = (u16::from_le(rd16(d + 4)) & 0x3fff) as usize;
            let eop = rd8(d + 8) & 1 << 1 != 0;
            let error = rd8(d + 1) & 1 << 2 != 0;
            let id = u16::from_le(rd16(d + 12));
            self.rx_compl_head = (self.rx_compl_head + 1) & self.rx_mask;
            if self.rx_compl_head == 0 {
                self.rx_compl_gen ^= 1;
            }
            let Some(&(va, _)) = self.rx_bufs.get(id as usize) else {
                // Not a buffer of ours: the frame it belongs to is lost.
                self.rx_partial_bad = true;
                continue;
            };
            let len = len.min(RX_BUF);
            let data = unsafe { core::slice::from_raw_parts(va as *const u8, len) };
            let n = if eop && self.rx_partial.is_empty() && !self.rx_partial_bad {
                // The usual case: a frame in one buffer.
                let n = len.min(out.len());
                out[..n].copy_from_slice(&data[..n]);
                (!error && n == len).then_some(n)
            } else {
                if self.rx_partial.extend_from_slice(data).is_err() {
                    self.rx_partial_bad = true;
                }
                self.rx_partial_bad |= error;
                if eop {
                    let p = &*self.rx_partial;
                    let ok = !core::mem::take(&mut self.rx_partial_bad) && p.len() <= out.len();
                    let n = ok.then(|| {
                        out[..p.len()].copy_from_slice(p);
                        p.len()
                    });
                    self.rx_partial.clear();
                    n
                } else {
                    None
                }
            };
            let valid = n.is_some() && self.csum_ok(d);
            self.post_rx(id);
            let Some(n) = n else { continue };
            *hdr = [0; HDR];
            if valid {
                hdr[0] = offload::F_DATA_VALID;
            }
            return Some(n);
        }
    }

    // ---- transmit

    /// Whether the device can segment this GSO frame (whole MSS and header
    /// ranges); others are segmented by netd.
    pub fn takes_gso(&self, hdr: &[u8; HDR]) -> bool {
        let get16 = |off: usize| u16::from_le_bytes([hdr[off], hdr[off + 1]]) as usize;
        (TSO_MIN_MSS..=TSO_MAX_MSS).contains(&get16(4)) && get16(2) <= TSO_MAX_HDR
    }

    /// Handle the TX completions the device has written.
    fn reap_tx(&mut self) {
        loop {
            let c = self.tx_compl + self.tx_compl_head as usize * TX_COMPL;
            let w = u16::from_le(rd16(c));
            if w >> 15 == self.tx_compl_gen {
                return;
            }
            dma_fence(Ordering::Acquire);
            let v = u16::from_le(rd16(c + 2));
            match (w >> 11) & 7 {
                COMPL_DESC => self.tx_head = v as u32 & self.tx_mask,
                COMPL_PKT if v & ALT_MISS_BIT != 0 => self.tx_miss(v & !ALT_MISS_BIT),
                COMPL_PKT => self.tx_done(v, TxBuf::Sent),
                COMPL_MISS => self.tx_miss(v),
                COMPL_REINJECTION => self.tx_done(v, TxBuf::Missed(0)),
                _ => {}
            }
            self.tx_compl_head = (self.tx_compl_head + 1) & self.tx_mask;
            if self.tx_compl_head == 0 {
                self.tx_compl_gen ^= 1;
            }
        }
    }

    fn tx_done(&mut self, tag: u16, from: TxBuf) {
        let Some(s) = self.tx_state.get_mut(tag as usize) else { return };
        if core::mem::discriminant(s) == core::mem::discriminant(&from) {
            *s = TxBuf::Free;
            let _ = self.tx_free.push(tag);
        }
    }

    fn tx_miss(&mut self, tag: u16) {
        if let Some(s @ TxBuf::Sent) = self.tx_state.get_mut(tag as usize) {
            *s = TxBuf::Missed(host::ticks::now());
        }
    }

    /// Buffers whose reinjection completion never came.
    fn reclaim_missed(&mut self) {
        let now = host::ticks::now();
        for (i, s) in self.tx_state.iter_mut().enumerate() {
            if let TxBuf::Missed(t) = *s {
                if now.wrapping_sub(t) > MISS_TIMEOUT_SECS * self.tsc_hz {
                    *s = TxBuf::Free;
                    let _ = self.tx_free.push(i as u16);
                }
            }
        }
    }

    fn tx_has_compl(&self) -> bool {
        let w = u16::from_le(rd16(self.tx_compl + self.tx_compl_head as usize * TX_COMPL));
        w >> 15 != self.tx_compl_gen
    }

    pub fn tx_interrupts(&mut self, on: bool) -> bool {
        if on {
            self.irq(NTFY_TX, ITR_ENABLE | (TX_ITR_US / 2) << ITR_INTERVAL_SHIFT);
        }
        // Off: the block masks itself the next time it fires.
        self.tx_has_compl()
    }

    fn tx_room(&self) -> u32 {
        self.tx_mask - (self.tx_tail.wrapping_sub(self.tx_head) & self.tx_mask)
    }

    fn put_desc(&mut self, d: [u8; TX_DESC]) {
        let va = self.tx_ring + self.tx_tail as usize * TX_DESC;
        wr64(va, u64::from_le_bytes(d[0..8].try_into().unwrap()));
        wr64(va + 8, u64::from_le_bytes(d[8..16].try_into().unwrap()));
        self.tx_tail = (self.tx_tail + 1) & self.tx_mask;
    }

    pub fn transmit(&mut self, frame: &(impl Frame + ?Sized), hdr: &[u8; HDR]) -> bool {
        let get16 = |off: usize| u16::from_le_bytes([hdr[off], hdr[off + 1]]) as usize;
        let gso = offload::is_gso(hdr);
        let descs = 1 + gso as u32 + frame.len().div_ceil(TX_MAX_BUF) as u32;
        if self.tx_free.is_empty() || self.tx_room() < descs + TX_RING_SLACK {
            self.reap_tx();
            if self.tx_free.is_empty() {
                self.reclaim_missed();
            }
        }
        if self.tx_free.is_empty() || self.tx_room() < descs + TX_RING_SLACK {
            // Let the device start on what is queued.
            self.kick_tx();
            return false;
        }
        let tag = self.tx_free.pop().unwrap();
        self.tx_state[tag as usize] = TxBuf::Sent;
        let (va, pa) = self.tx_bufs[tag as usize];
        let buf = unsafe { core::slice::from_raw_parts_mut(va as *mut u8, frame.len()) };
        frame.copy_to(buf);
        let csum = hdr[0] & offload::F_NEEDS_CSUM != 0;
        if gso {
            // The device wants the TCP pseudo-header checksum without the
            // length, which differs per segment (Linux gve_prep_tso).
            let (hdr_len, mss, tcp) = (get16(2), get16(4), get16(6));
            let paylen = (frame.len() - tcp) as u32;
            let c = tcp + 16;
            let old = u16::from_be_bytes([buf[c], buf[c + 1]]) as u32;
            let mut sum = (!old & 0xffff) + (paylen >> 16) + (paylen & 0xffff);
            sum = (sum & 0xffff) + (sum >> 16);
            sum = (sum & 0xffff) + (sum >> 16);
            buf[c..c + 2].copy_from_slice(&(!sum as u16).to_be_bytes());
            let mut d = [0u8; TX_DESC];
            d[0..4].copy_from_slice(&((frame.len() - hdr_len) as u32 & 0xff_ffff).to_le_bytes());
            d[4..6].copy_from_slice(&(mss as u16 & 0x3fff).to_le_bytes());
            d[6] = hdr_len as u8;
            d[8] = DTYPE_TSO_CTX | 1 << 5;
            self.put_desc(d);
        }
        // Metadata (version 0, no flow hash), as Linux sends with every
        // packet.
        let mut d = [0u8; TX_DESC];
        d[8] = DTYPE_GENERAL_CTX;
        self.put_desc(d);
        let mut off = 0;
        while off < frame.len() {
            let len = (frame.len() - off).min(TX_MAX_BUF);
            let mut d = [0u8; TX_DESC];
            d[0..8].copy_from_slice(&(pa + off as u64).to_le_bytes());
            d[8] = DTYPE_PKT | if off + len == frame.len() { PKT_EOP } else { 0 } | if csum { PKT_CSUM } else { 0 };
            d[12..14].copy_from_slice(&tag.to_le_bytes());
            d[14..16].copy_from_slice(&(len as u16).to_le_bytes());
            self.put_desc(d);
            off += len;
        }
        // A descriptor completion (the device's ring head) at most every
        // MIN_RE_INTERVAL descriptors, on the last one of a packet.
        let last = self.tx_tail.wrapping_sub(1) & self.tx_mask;
        if last.wrapping_sub(self.tx_last_re) & self.tx_mask >= MIN_RE_INTERVAL {
            let b = self.tx_ring + last as usize * TX_DESC + 8;
            unsafe { write_volatile(b as *mut u8, rd8(b) | PKT_REPORT_EVENT) };
            self.tx_last_re = last;
        }
        self.tx_kick = true;
        true
    }

    pub fn kick_tx(&mut self) {
        if core::mem::take(&mut self.tx_kick) {
            dma_fence(Ordering::Release);
            self.doorbell(self.tx_db, self.tx_tail);
        }
    }
}

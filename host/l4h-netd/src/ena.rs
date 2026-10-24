//! Amazon Elastic Network Adapter (ENA) driver, after Linux `ena`.  Nitro
//! EC2 instance types have only this NIC.  The driver uses one TX and one
//! RX queue, each a submission queue (SQ) with its completion queue (CQ).
//! Frames are copied between the switch and DMA buffers owned by this
//! driver, as for virtio-net.
//!
//! The device is configured through little-endian registers in BAR 0 and
//! an admin queue of 64-byte commands with its completion queue; events
//! (link changes, keep-alives, errors) come through the asynchronous event
//! notification queue (AENQ).  Unless the PCI revision says otherwise,
//! registers are read "readless": the device writes the value to memory.
//!
//! TX descriptors go, as Linux prefers, to the low-latency queue (LLQ) in
//! BAR 2, mapped write-combining: one 128-byte entry per frame with the
//! metadata and buffer descriptors and the frame's first 96 bytes.  Without
//! that BAR or the feature, they go to a ring in host memory.  The device
//! does no TSO here: netd segments.
//!
//! MSI-X entry 0 is the management vector (admin completions and the AENQ)
//! and entry 1 the I/O queues'; both carry netd's one vector for the NIC.
//! The device masks the I/O vector when it fires, until the driver
//! unmasks it through the CQ's unmask register.

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::Ordering;

use l4h_rt::host::fixed::ArrayVec;
use l4h_rt::host::{self, net::{self, NicConfig}};
use l4h_rt::sel4;
use l4h_virtio::{Dma, Mmio, dma_fence};

use crate::nic::Partial;
use crate::offload;
use crate::pool::Frame;

const HDR: usize = net::HDR_SIZE;

// Registers (BAR 0).
const REG_VERSION: usize = 0x00;
const REG_CONTROLLER_VERSION: usize = 0x04;
const REG_CAPS: usize = 0x08;
const REG_AQ_BASE_LO: usize = 0x10;
const REG_AQ_BASE_HI: usize = 0x14;
const REG_AQ_CAPS: usize = 0x18;
const REG_ACQ_BASE_LO: usize = 0x20;
const REG_ACQ_BASE_HI: usize = 0x24;
const REG_ACQ_CAPS: usize = 0x28;
const REG_AQ_DB: usize = 0x2c;
const REG_AENQ_CAPS: usize = 0x34;
const REG_AENQ_BASE_LO: usize = 0x38;
const REG_AENQ_BASE_HI: usize = 0x3c;
const REG_AENQ_HEAD_DB: usize = 0x40;
const REG_DEV_CTL: usize = 0x54;
const REG_DEV_STS: usize = 0x58;
const REG_MMIO_REG_READ: usize = 0x5c;
const REG_MMIO_RESP_LO: usize = 0x60;
const REG_MMIO_RESP_HI: usize = 0x64;
const DEV_CTL_RESET: u32 = 1 << 0;
const DEV_STS_READY: u32 = 1 << 0;
const DEV_STS_RESET_IN_PROGRESS: u32 = 1 << 3;
const DEV_STS_FATAL_ERROR: u32 = 1 << 5;
/// PCI revision bit: registers are read directly, not readless.
const REVISION_NO_READLESS: u32 = 1 << 0;
/// Readless reads that take longer fail (Linux ENA_REG_READ_TIMEOUT).
const REG_READ_TIMEOUT_US: u64 = 200_000;
/// Admin commands without a timeout in CAPS (Linux ADMIN_CMD_TIMEOUT_US).
const ADMIN_TIMEOUT_MS: u64 = 3000;

// Admin queue, its completion queue and the AENQ: 64-byte entries.
const AQ_DEPTH: u16 = 32;
const AENQ_DEPTH: u16 = 16;
const ENTRY: usize = 64;
const AQ_CREATE_SQ: u8 = 1;
const AQ_CREATE_CQ: u8 = 3;
const AQ_GET_FEATURE: u8 = 8;
const AQ_SET_FEATURE: u8 = 9;
const AQ_PHASE: u8 = 1 << 0;
const AQ_CTRL_DATA_INDIRECT: u8 = 1 << 2;
const FEAT_DEVICE_ATTRIBUTES: u8 = 1;
const FEAT_MAX_QUEUES_NUM: u8 = 2;
const FEAT_LLQ: u8 = 4;
const FEAT_MAX_QUEUES_EXT: u8 = 7;
const FEAT_STATELESS_OFFLOAD: u8 = 11;
const FEAT_RSS_INDIRECTION_TABLE: u8 = 12;
const FEAT_MTU: u8 = 14;
const FEAT_INTERRUPT_MODERATION: u8 = 20;
const FEAT_AENQ_CONFIG: u8 = 26;
const FEAT_HOST_ATTR: u8 = 28;
const MAX_QUEUES_EXT_VERSION: u8 = 1;

// AENQ groups.
const AENQ_LINK_CHANGE: u16 = 0;
const AENQ_FATAL_ERROR: u16 = 1;
const AENQ_WARNING: u16 = 2;
const AENQ_NOTIFICATION: u16 = 3;
const AENQ_KEEP_ALIVE: u16 = 4;

// Queues.
const PLACEMENT_HOST: u8 = 1;
const PLACEMENT_DEV: u8 = 3;
const SQ_TX: u8 = 1;
const SQ_RX: u8 = 2;
/// The I/O queues' MSI-X entry.
const IO_VECTOR: u32 = 1;
/// Interrupt register of a CQ: delays (in the device's resolution) and
/// the unmask bit.
const INTR_TX_DELAY_SHIFT: u32 = 15;
const INTR_UNMASK: u32 = 1 << 30;
/// Interrupt coalescing, as Linux: µs.
const RX_INTR_US: u32 = 20;
const TX_INTR_US: u32 = 64;

// LLQ: the configuration Linux asks for.
const LLQ_INLINE_HEADER: u16 = 1;
const LLQ_ENTRY_128B: u16 = 1;
const LLQ_ENTRY: usize = 128;
const LLQ_DESCS_BEFORE_HEADER_2: u16 = 2;
const LLQ_MULTIPLE_DESCS_PER_ENTRY: u16 = 2;
const LLQ_ACCEL_DISABLE_META_CACHING: u16 = 1 << 0;
const LLQ_ACCEL_LIMIT_TX_BURST: u16 = 1 << 1;
/// The frame's first bytes, after the two descriptors of its entry.
const LLQ_HEADER: usize = LLQ_ENTRY - 2 * TX_DESC;

// TX descriptors (16 bytes) and completions (8 bytes).
const TX_DESC: usize = 16;
const TX_CDESC: usize = 8;
const TX_DEPTH: u16 = 256;
const DESC_META: u32 = 1 << 23;
const DESC_PHASE_SHIFT: u32 = 24;
const DESC_FIRST: u32 = 1 << 26;
const DESC_LAST: u32 = 1 << 27;
const DESC_COMP_REQ: u32 = 1 << 28;
const META_EXT_VALID: u32 = 1 << 14;
const META_ETH_META_TYPE: u32 = 1 << 20;
const META_STORE: u32 = 1 << 21;
const TX_DF: u32 = 1 << 4;
const TX_L4_PROTO_SHIFT: u32 = 8;
const TX_L4_CSUM_EN: u32 = 1 << 14;
const TX_L4_CSUM_PARTIAL: u32 = 1 << 17;
const TX_REQ_ID_LO_SHIFT: u32 = 22;
const TX_HEADER_LENGTH_SHIFT: u32 = 24;
const L3_IPV4: u32 = 8;
const L3_IPV6: u32 = 11;
const L4_TCP: u32 = 12;
const L4_UDP: u32 = 13;
// Offload features: TX partial checksums, RX checksums.
const OFFLOAD_TX_L4_IPV4_PART: u32 = 1 << 1;
const OFFLOAD_TX_L4_IPV6_PART: u32 = 1 << 3;
/// Transmit buffers: whole frames up to the device's MTU.
const TX_BUFS: usize = 96;

// RX descriptors and completions (16 bytes each).
const RX_DESC: usize = 16;
const RX_CDESC: usize = 16;
const RX_DEPTH: u16 = 512;
const RX_BUF: usize = 2048;
const RX_BUFS: usize = RX_DEPTH as usize - 1;
const RX_DESC_PHASE: u8 = 1 << 0;
const RX_DESC_FIRST: u8 = 1 << 2;
const RX_DESC_LAST: u8 = 1 << 3;
const RX_DESC_COMP_REQ: u8 = 1 << 4;
const RX_L3_CSUM_ERR: u32 = 1 << 13;
const RX_L4_CSUM_ERR: u32 = 1 << 14;
const RX_IPV4_FRAG: u32 = 1 << 15;
const RX_L4_CSUM_CHECKED: u32 = 1 << 16;
const RX_PHASE_SHIFT: u32 = 24;
const RX_FIRST: u32 = 1 << 26;
const RX_LAST: u32 = 1 << 27;
/// The RX doorbell is rung after this many buffers, and when netd is done.
const RX_REFILL_BATCH: u32 = 64;
/// RSS indirection table: Linux's size, every entry the RX queue.
const RSS_TABLE_LOG: u16 = 7;

fn rd8(va: usize) -> u8 {
    unsafe { read_volatile(va as *const u8) }
}
fn rd16(va: usize) -> u16 {
    u16::from_le(unsafe { read_volatile(va as *const u16) })
}
fn rd32(va: usize) -> u32 {
    u32::from_le(unsafe { read_volatile(va as *const u32) })
}
fn wr(va: usize, b: &[u8]) {
    for (i, &x) in b.iter().enumerate() {
        unsafe { write_volatile((va + i) as *mut u8, x) };
    }
}
/// `b` in 64-bit stores, as LLQ entries must be written.
fn wr64s(va: usize, b: &[u8]) {
    for (i, c) in b.chunks_exact(8).enumerate() {
        unsafe { write_volatile((va + i * 8) as *mut u64, u64::from_le_bytes(c.try_into().unwrap())) };
    }
}
fn le16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}
fn le32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}
fn put16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
fn put32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
/// A struct ena_common_mem_addr: low word, then the high 16 bits.
fn put_addr(b: &mut [u8], off: usize, pa: u64) {
    put32(b, off, pa as u32);
    put16(b, off + 4, (pa >> 32) as u16);
}

/// Drain write-combined LLQ entries before the doorbell that hands them
/// to the device (Linux's wmb()).
fn wc_fence() {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("sfence", options(nostack, preserves_flags))
    };
    dma_fence(Ordering::Release);
}

/// A 64-byte admin command: the common descriptor (command id, opcode,
/// flags), then its fields at their offsets in the command.
struct Cmd([u8; ENTRY]);

impl Cmd {
    fn new(opcode: u8) -> Self {
        let mut c = Cmd([0; ENTRY]);
        c.0[2] = opcode;
        c
    }
    /// A get or set feature command: feature id at 17, version at 18.
    fn feature(opcode: u8, id: u8, version: u8) -> Self {
        let mut c = Cmd::new(opcode);
        c.0[17] = id;
        c.0[18] = version;
        c
    }
    fn u8(mut self, off: usize, v: u8) -> Self {
        self.0[off] = v;
        self
    }
    fn u16(mut self, off: usize, v: u16) -> Self {
        put16(&mut self.0, off, v);
        self
    }
    fn u32(mut self, off: usize, v: u32) -> Self {
        put32(&mut self.0, off, v);
        self
    }
    fn addr(mut self, off: usize, pa: u64) -> Self {
        put_addr(&mut self.0, off, pa);
        self
    }
    /// The control buffer (struct ena_admin_ctrl_buff_info at 4) of an
    /// indirect command.
    fn indirect(mut self, pa: u64, len: u32) -> Self {
        self.0[3] |= AQ_CTRL_DATA_INDIRECT;
        put32(&mut self.0, 4, len);
        put_addr(&mut self.0, 8, pa);
        self
    }
}

/// A queue's position: a free-running index and the phase bit the entry
/// it points at carries in this pass.
#[derive(Clone, Copy)]
struct Ring {
    idx: u16,
    phase: u8,
    mask: u16,
}

impl Ring {
    fn new(depth: u16) -> Self {
        Ring { idx: 0, phase: 1, mask: depth - 1 }
    }
    fn slot(&self) -> usize {
        (self.idx & self.mask) as usize
    }
    fn advance(&mut self) {
        self.idx = self.idx.wrapping_add(1);
        if self.idx & self.mask == 0 {
            self.phase ^= 1;
        }
    }
}

pub struct Ena {
    n: usize,
    pub mac: [u8; 6],
    pub csum: bool,
    pub tso: bool,
    regs: Mmio,
    tsc_hz: u64,
    /// The readless response (struct ena_admin_ena_mmio_req_read_less_resp),
    /// if registers are read so.
    readless: Option<usize>,
    mmio_seq: u16,
    admin_timeout_ms: u64,
    aq: usize,
    aq_ring: Ring,
    acq: usize,
    acq_ring: Ring,
    aenq: usize,
    aenq_ring: Ring,
    supported: u32,
    /// The I/O vector's unmask register (in BAR 0) and the delays to write.
    unmask_reg: usize,
    intr: u32,

    /// LLQ: the queue's entries in BAR 2; otherwise the ring in host
    /// memory.
    tx_llq: Option<usize>,
    tx_ring: usize,
    tx_sq: Ring,
    /// Descriptors (LLQ entries) the device has completed: they free
    /// their slots.
    tx_next_to_comp: u16,
    tx_db: usize,
    tx_cq: usize,
    tx_cq_ring: Ring,
    tx_max_header: usize,
    /// LLQ entries the device takes between doorbells (0: no limit), and
    /// those left until the next.
    tx_burst_max: u16,
    tx_burst_left: u16,
    tx_csum_v4: bool,
    tx_csum_v6: bool,
    tx_buf: usize,
    tx_bufs: ArrayVec<(usize, u64), TX_BUFS>,
    /// Descriptors each buffer's frame took; 0 while it is free.
    tx_descs: ArrayVec<u16, TX_BUFS>,
    tx_free: ArrayVec<u16, TX_BUFS>,
    tx_kick: bool,
    tx_too_long: bool,

    rx_ring: usize,
    rx_sq: Ring,
    rx_db: usize,
    rx_unrung: u32,
    rx_cq: usize,
    rx_cq_ring: Ring,
    rx_bufs: ArrayVec<(usize, u64), RX_BUFS>,
    /// A frame that spans buffers, while its completions arrive.
    rx_partial: &'static mut Partial,
    rx_in_frame: bool,
    rx_partial_bad: bool,
}

impl Ena {
    pub fn new(n: usize, c: &NicConfig, tsc_hz: u64, rx_partial: &'static mut Partial) -> Self {
        let mut dma = Dma::new(net::nic_dma_va(n), c.dma_paddr, c.dma_size as usize);
        let regs = Mmio(c.regs.va as usize);
        let (resp, resp_pa) = dma.alloc(8, 8);
        let mut e = Ena {
            n,
            mac: [0; 6],
            csum: false,
            tso: false,
            regs,
            tsc_hz,
            readless: (c.revision & REVISION_NO_READLESS == 0).then_some(resp),
            mmio_seq: 0,
            admin_timeout_ms: ADMIN_TIMEOUT_MS,
            aq: 0,
            aq_ring: Ring::new(AQ_DEPTH),
            acq: 0,
            acq_ring: Ring::new(AQ_DEPTH),
            aenq: 0,
            aenq_ring: Ring::new(AENQ_DEPTH),
            supported: 0,
            unmask_reg: 0,
            intr: 0,
            tx_llq: None,
            tx_ring: 0,
            tx_sq: Ring::new(TX_DEPTH),
            tx_next_to_comp: 0,
            tx_db: 0,
            tx_cq: 0,
            tx_cq_ring: Ring::new(TX_DEPTH),
            tx_max_header: 0,
            tx_burst_max: 0,
            tx_burst_left: 0,
            tx_csum_v4: false,
            tx_csum_v6: false,
            tx_buf: 0,
            tx_bufs: ArrayVec::new(),
            tx_descs: ArrayVec::new(),
            tx_free: ArrayVec::new(),
            tx_kick: false,
            tx_too_long: false,
            rx_ring: 0,
            rx_sq: Ring::new(RX_DEPTH),
            rx_db: 0,
            rx_unrung: 0,
            rx_cq: 0,
            rx_cq_ring: Ring::new(RX_DEPTH),
            rx_bufs: ArrayVec::new(),
            rx_partial,
            rx_in_frame: false,
            rx_partial_bad: false,
        };
        // Where readless reads land, set again after the reset.
        regs.w32(REG_MMIO_RESP_LO, resp_pa as u32);
        regs.w32(REG_MMIO_RESP_HI, (resp_pa >> 32) as u32);
        e.reset(resp_pa);
        // MSI-X, as Linux after the reset: the management and I/O vectors
        // on netd's vector, any others masked.
        let msix = Mmio(c.msix_table.va as usize);
        for i in 0..(c.msix_table.len / 16) as usize {
            msix.w32(i * 16, c.msi_address as u32);
            msix.w32(i * 16 + 4, (c.msi_address >> 32) as u32);
            msix.w32(i * 16 + 8, c.msi_data);
            msix.w32(i * 16 + 12, (i > IO_VECTOR as usize) as u32);
        }
        let (ver, ctrl_ver) = (e.r32(REG_VERSION), e.r32(REG_CONTROLLER_VERSION));
        let caps = e.r32(REG_CAPS);
        let width = (caps >> 8) & 0xff;
        if !(32..=64).contains(&width) || (width < 64 && c.dma_paddr + c.dma_size > 1 << width) {
            panic!("netd: NIC {}: ENA DMA width {} does not reach memory at {:#x}", n, width, c.dma_paddr);
        }

        // Admin queue, its completion queue and the AENQ.
        let (aq, aq_pa) = dma.alloc(AQ_DEPTH as usize * ENTRY, 4096);
        let (acq, acq_pa) = dma.alloc(AQ_DEPTH as usize * ENTRY, 4096);
        let (aenq, aenq_pa) = dma.alloc(AENQ_DEPTH as usize * ENTRY, 4096);
        (e.aq, e.acq, e.aenq) = (aq, acq, aenq);
        if e.r32(REG_DEV_STS) & DEV_STS_READY == 0 {
            panic!("netd: NIC {}: ENA not ready after its reset", n);
        }
        let caps_of = |depth: u16| depth as u32 | (ENTRY as u32) << 16;
        regs.w32(REG_AQ_BASE_LO, aq_pa as u32);
        regs.w32(REG_AQ_BASE_HI, (aq_pa >> 32) as u32);
        regs.w32(REG_ACQ_BASE_LO, acq_pa as u32);
        regs.w32(REG_ACQ_BASE_HI, (acq_pa >> 32) as u32);
        regs.w32(REG_AQ_CAPS, caps_of(AQ_DEPTH));
        regs.w32(REG_ACQ_CAPS, caps_of(AQ_DEPTH));
        regs.w32(REG_AENQ_BASE_LO, aenq_pa as u32);
        regs.w32(REG_AENQ_BASE_HI, (aenq_pa >> 32) as u32);
        regs.w32(REG_AENQ_CAPS, caps_of(AENQ_DEPTH));

        // What this driver is.  The device may refuse it: Linux carries on.
        let (info_va, info_pa) = dma.alloc(4096, 4096);
        let mut info = [0u8; 196];
        // Unknown OS type 0 (Linux is 1), driver version 1.0.0.
        info[4..7].copy_from_slice(b"l4h");
        info[136..139].copy_from_slice(b"l4h");
        put32(&mut info, 172, 1);
        put16(&mut info, 186, c.pci_bdf as u16);
        put16(&mut info, 188, 1);
        wr(info_va, &info);
        if let Err(st) = e.try_exec(Cmd::feature(AQ_SET_FEATURE, FEAT_HOST_ATTR, 0).addr(20, info_pa)) {
            l4h_rt::info!("netd: NIC {}: ENA refuses the host attributes: status {}", n, st);
        }

        // The device's attributes, queue limits and offloads.
        let attr = e.exec("get device attributes", Cmd::feature(AQ_GET_FEATURE, FEAT_DEVICE_ATTRIBUTES, 0));
        e.supported = le32(&attr, 16);
        e.mac.copy_from_slice(&attr[32..38]);
        let max_mtu = le32(&attr, 40) as usize;
        let (max_tx_depth, max_rx_depth, max_header, max_rx_descs) = if e.has(FEAT_MAX_QUEUES_EXT) {
            let q = e.exec("get queue limits", Cmd::feature(AQ_GET_FEATURE, FEAT_MAX_QUEUES_EXT, MAX_QUEUES_EXT_VERSION));
            if q[8] != MAX_QUEUES_EXT_VERSION {
                panic!("netd: NIC {}: ENA queue limits version {}", n, q[8]);
            }
            let (tx_sq, tx_cq) = (le32(&q, 28), le32(&q, 32));
            let (rx_sq, rx_cq) = (le32(&q, 36), le32(&q, 40));
            (tx_sq.min(tx_cq), rx_sq.min(rx_cq), le32(&q, 44), le16(&q, 50))
        } else {
            let q = e.exec("get queue limits", Cmd::feature(AQ_GET_FEATURE, FEAT_MAX_QUEUES_NUM, 0));
            let (sq, cq) = (le32(&q, 12), le32(&q, 20));
            (sq.min(cq), sq.min(cq), le32(&q, 32), le16(&q, 38))
        };
        let aenq_cfg = e.exec("get AENQ groups", Cmd::feature(AQ_GET_FEATURE, FEAT_AENQ_CONFIG, 0));
        let groups = [AENQ_LINK_CHANGE, AENQ_FATAL_ERROR, AENQ_WARNING, AENQ_NOTIFICATION, AENQ_KEEP_ALIVE]
            .iter()
            .fold(0, |g, &b| g | 1 << b)
            & le32(&aenq_cfg, 8);
        e.exec("set AENQ groups", Cmd::feature(AQ_SET_FEATURE, FEAT_AENQ_CONFIG, 0).u32(24, groups));
        // All AENQ entries are the device's.
        e.aenq_ring.idx = AENQ_DEPTH;
        regs.w32(REG_AENQ_HEAD_DB, AENQ_DEPTH as u32);
        let offload = e.exec("get offloads", Cmd::feature(AQ_GET_FEATURE, FEAT_STATELESS_OFFLOAD, 0));
        let tx_offload = le32(&offload, 8);
        e.tx_csum_v4 = tx_offload & OFFLOAD_TX_L4_IPV4_PART != 0;
        e.tx_csum_v6 = tx_offload & OFFLOAD_TX_L4_IPV6_PART != 0;
        e.csum = e.tx_csum_v4 || e.tx_csum_v6;

        // TX descriptors in the LLQ if the device has one, else in host
        // memory.
        let mut tx_depth = TX_DEPTH.min(pow2_floor(max_tx_depth));
        let llq_bar = (c.doorbells.len != 0).then_some((c.doorbells.va as usize, c.doorbells.len as usize));
        let llq = match llq_bar {
            Some(_) if e.has(FEAT_LLQ) => e.config_llq(),
            _ => None,
        };
        if let Some((depth, burst)) = llq {
            tx_depth = tx_depth.min(pow2_floor(depth));
            e.tx_burst_max = burst;
            e.tx_max_header = LLQ_HEADER;
        } else {
            e.tx_max_header = max_header as usize;
        }
        let rx_depth = RX_DEPTH.min(pow2_floor(max_rx_depth));
        if tx_depth < 64 || rx_depth < 64 {
            panic!("netd: NIC {}: ENA queue depths tx {} rx {}", n, tx_depth, rx_depth);
        }
        (e.tx_sq, e.tx_cq_ring) = (Ring::new(tx_depth), Ring::new(tx_depth));
        (e.rx_sq, e.rx_cq_ring) = (Ring::new(rx_depth), Ring::new(rx_depth));

        // Interrupt coalescing, if the device has it.
        if e.has(FEAT_INTERRUPT_MODERATION) {
            let m = e.exec("get interrupt moderation", Cmd::feature(AQ_GET_FEATURE, FEAT_INTERRUPT_MODERATION, 0));
            let res = (le16(&m, 8) as u32).max(1);
            e.intr = RX_INTR_US / res | (TX_INTR_US / res) << INTR_TX_DELAY_SHIFT;
        }

        // Frames up to the MTU, which RX buffers must hold too.
        let max_frame = (max_mtu.max(1500) + 18)
            .min(net::MAX_FRAME)
            .min(if max_rx_descs != 0 { max_rx_descs as usize * RX_BUF } else { usize::MAX });
        e.tx_buf = max_frame.next_multiple_of(64);
        let bufs = TX_BUFS.min(tx_depth as usize / 2 - 1);
        let rx_bufs = RX_BUFS.min(rx_depth as usize - 1);
        let rings = tx_depth as usize * (TX_DESC + TX_CDESC) + rx_depth as usize * (RX_DESC + RX_CDESC);
        let need = rings + 4 * 4096 + bufs * e.tx_buf + rx_bufs * RX_BUF;
        if need > dma.remaining() {
            panic!("netd: NIC {}: ENA queue depths tx {} rx {} need {} KiB of DMA memory, {} KiB left",
                n, tx_depth, rx_depth, need >> 10, dma.remaining() >> 10);
        }

        // TX queue: its CQ, then the SQ.
        let (tx_cq, tx_cq_pa) = dma.alloc(tx_depth as usize * TX_CDESC, 4096);
        let (cq_idx, unmask) = e.create_cq(tx_cq_pa, tx_depth, TX_CDESC);
        e.tx_cq = tx_cq;
        // Linux unmasks the shared vector through the TX CQ.
        e.unmask_reg = unmask;
        let (tx_ring, tx_ring_pa) = if llq.is_some() { (0, 0) } else { dma.alloc(tx_depth as usize * TX_DESC, 4096) };
        e.tx_ring = tx_ring;
        let placement = if llq.is_some() { PLACEMENT_DEV } else { PLACEMENT_HOST };
        let (_, db, llq_off) = e.create_sq(SQ_TX, placement, cq_idx, tx_depth, tx_ring_pa);
        e.tx_db = db;
        if let (Some(_), Some((va, len))) = (llq, llq_bar) {
            if llq_off as usize + tx_depth as usize * LLQ_ENTRY > len {
                panic!("netd: NIC {}: ENA LLQ at {:#x} outside its BAR ({} KiB)", n, llq_off, len >> 10);
            }
            e.tx_llq = Some(va + llq_off as usize);
            e.tx_burst_left = e.tx_burst_max;
        }
        for i in 0..bufs {
            let _ = e.tx_bufs.push(dma.alloc(e.tx_buf, 64));
            let _ = e.tx_descs.push(0);
            let _ = e.tx_free.push((bufs - 1 - i) as u16);
        }

        // RX queue.
        let (rx_cq, rx_cq_pa) = dma.alloc(rx_depth as usize * RX_CDESC, 4096);
        let (cq_idx, _) = e.create_cq(rx_cq_pa, rx_depth, RX_CDESC);
        e.rx_cq = rx_cq;
        let (rx_ring, rx_ring_pa) = dma.alloc(rx_depth as usize * RX_DESC, 4096);
        e.rx_ring = rx_ring;
        let (rx_sq, rx_db, _) = e.create_sq(SQ_RX, PLACEMENT_HOST, cq_idx, rx_depth, rx_ring_pa);
        e.rx_db = rx_db;
        for _ in 0..rx_bufs {
            let _ = e.rx_bufs.push(dma.alloc(RX_BUF, 64));
        }

        // Received frames all go to the one RX queue, and up to the MTU.
        if e.has(FEAT_RSS_INDIRECTION_TABLE) {
            e.set_rss_table(&mut dma, rx_sq);
        }
        let mtu = (max_frame - 18) as u32;
        if e.has(FEAT_MTU) {
            if let Err(st) = e.try_exec(Cmd::feature(AQ_SET_FEATURE, FEAT_MTU, 0).u32(20, mtu)) {
                sel4::debug_println!("netd: NIC {}: ENA refuses MTU {}: status {}", n, mtu, st);
            }
        }
        for id in 0..e.rx_bufs.len() as u16 {
            e.post_rx(id);
        }
        e.ring_rx();
        e.unmask();

        let mac = e.mac;
        l4h_rt::info!(
            "netd: NIC {}: {:02x}:{:02x}.{} ENA {}.{} ctrl {:#x} rev {}, mac {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, mtu {}, tx {} ({}) rx {}, csum v4 {} v6 {}",
            n, c.pci_bdf >> 8, (c.pci_bdf >> 3) & 0x1f, c.pci_bdf & 7, (ver >> 8) & 0xff, ver & 0xff, ctrl_ver, c.revision,
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], mtu, tx_depth,
            if e.tx_llq.is_some() { "llq" } else { "host" }, rx_depth, e.tx_csum_v4, e.tx_csum_v6,
        );
        e
    }

    fn has(&self, feature: u8) -> bool {
        self.supported & 1 << feature != 0
    }

    /// Ticks since boot.
    fn deadline_us(&self, us: u64) -> u64 {
        host::ticks::now() + us * self.tsc_hz / 1_000_000
    }

    /// A register, read directly or readless (the device writes the value
    /// to memory, Linux ena_com_reg_bar_read32).
    fn r32(&mut self, off: usize) -> u32 {
        let Some(resp) = self.readless else {
            return self.regs.r32(off);
        };
        self.mmio_seq = self.mmio_seq.wrapping_add(1);
        let seq = self.mmio_seq;
        unsafe { write_volatile(resp as *mut u16, seq.wrapping_add(0xdead)) };
        dma_fence(Ordering::Release);
        self.regs.w32(REG_MMIO_REG_READ, (off as u32) << 16 | seq as u32);
        let end = self.deadline_us(REG_READ_TIMEOUT_US);
        while rd16(resp) != seq {
            if host::ticks::now() > end {
                panic!("netd: NIC {}: ENA readless read of register {:#x} timed out", self.n, off);
            }
        }
        dma_fence(Ordering::Acquire);
        if rd16(resp + 2) as usize != off {
            panic!("netd: NIC {}: ENA readless read of register {:#x} answered {:#x}", self.n, off, rd16(resp + 2));
        }
        rd32(resp + 4)
    }

    /// Reset the device, which firmware may have used (Linux
    /// ena_com_dev_reset).
    fn reset(&mut self, resp_pa: u64) {
        let sts = self.r32(REG_DEV_STS);
        if sts & DEV_STS_READY == 0 {
            panic!("netd: NIC {}: ENA not ready (status {:#x})", self.n, sts);
        }
        let caps = self.r32(REG_CAPS);
        // In 100 ms.
        let timeout = ((caps >> 1) & 0x1f).max(1) as u64 * 100_000;
        self.regs.w32(REG_DEV_CTL, DEV_CTL_RESET);
        self.regs.w32(REG_MMIO_RESP_LO, resp_pa as u32);
        self.regs.w32(REG_MMIO_RESP_HI, (resp_pa >> 32) as u32);
        self.wait_reset(timeout, true);
        self.regs.w32(REG_DEV_CTL, 0);
        self.wait_reset(timeout, false);
        let admin = (caps >> 16) & 0xf;
        if admin != 0 {
            self.admin_timeout_ms = admin as u64 * 100;
        }
    }

    fn wait_reset(&mut self, timeout_us: u64, on: bool) {
        let end = self.deadline_us(timeout_us);
        while (self.r32(REG_DEV_STS) & DEV_STS_RESET_IN_PROGRESS != 0) != on {
            if host::ticks::now() > end {
                panic!("netd: NIC {}: ENA reset indication did not turn {}", self.n, if on { "on" } else { "off" });
            }
        }
    }

    /// Run one admin command and wait for its completion; a failure is
    /// fatal, as for a virtio-net device that refuses its setup.
    fn exec(&mut self, what: &str, cmd: Cmd) -> [u8; ENTRY] {
        self.try_exec(cmd)
            .unwrap_or_else(|st| panic!("netd: NIC {}: ENA admin command '{}' failed: status {}", self.n, what, st))
    }

    /// Run one admin command and wait for it: its completion, or the
    /// failed status.
    fn try_exec(&mut self, mut cmd: Cmd) -> Result<[u8; ENTRY], u8> {
        let id = self.aq_ring.slot() as u16;
        put16(&mut cmd.0, 0, id);
        cmd.0[3] |= self.aq_ring.phase & AQ_PHASE;
        wr(self.aq + id as usize * ENTRY, &cmd.0);
        self.aq_ring.advance();
        dma_fence(Ordering::Release);
        self.regs.w32(REG_AQ_DB, self.aq_ring.idx as u32);
        let c = self.acq + self.acq_ring.slot() * ENTRY;
        let end = self.deadline_us(self.admin_timeout_ms * 1000);
        while rd8(c + 3) & AQ_PHASE != self.acq_ring.phase {
            if host::ticks::now() > end {
                let sts = self.r32(REG_DEV_STS);
                panic!(
                    "netd: NIC {}: ENA admin command {} (feature {}) timed out (status {:#x}{})",
                    self.n, cmd.0[2], cmd.0[17], sts, if sts & DEV_STS_FATAL_ERROR != 0 { ", fatal error" } else { "" }
                );
            }
        }
        dma_fence(Ordering::Acquire);
        let r: [u8; ENTRY] = core::array::from_fn(|i| rd8(c + i));
        self.acq_ring.advance();
        if le16(&r, 0) & 0xfff != id {
            panic!("netd: NIC {}: ENA completed admin command {}, not {}", self.n, le16(&r, 0) & 0xfff, id);
        }
        match r[2] {
            0 => Ok(r),
            st => Err(st),
        }
    }

    /// Ask for the LLQ as Linux does (inline headers in 128-byte entries,
    /// two descriptors before the header); its depth and the entries the
    /// device takes per doorbell, or None if it has another layout.
    fn config_llq(&mut self) -> Option<(u32, u16)> {
        let l = self.exec("get LLQ", Cmd::feature(AQ_GET_FEATURE, FEAT_LLQ, 0));
        let (num, depth) = (le32(&l, 8), le32(&l, 12));
        let fits = |off: usize, want: u16| le16(&l, off) & want != 0;
        if num == 0
            || !fits(16, LLQ_INLINE_HEADER)
            || !fits(20, LLQ_ENTRY_128B)
            || !fits(24, LLQ_DESCS_BEFORE_HEADER_2)
            || !fits(28, LLQ_MULTIPLE_DESCS_PER_ENTRY)
        {
            l4h_rt::info!(
                "netd: NIC {}: ENA LLQ unusable (queues {}, header {:#x} entry {:#x} descs {:#x} stride {:#x}): TX descriptors in host memory",
                self.n, num, le16(&l, 16), le16(&l, 20), le16(&l, 24), le16(&l, 28)
            );
            return None;
        }
        let (accel, burst_bytes) = (le16(&l, 36), le16(&l, 38));
        let set = Cmd::feature(AQ_SET_FEATURE, FEAT_LLQ, 0)
            .u16(30, LLQ_INLINE_HEADER)
            .u16(34, LLQ_ENTRY_128B)
            .u16(38, LLQ_DESCS_BEFORE_HEADER_2)
            .u16(42, LLQ_MULTIPLE_DESCS_PER_ENTRY)
            .u16(48, LLQ_ACCEL_DISABLE_META_CACHING | LLQ_ACCEL_LIMIT_TX_BURST);
        if let Err(st) = self.try_exec(set) {
            sel4::debug_println!("netd: NIC {}: ENA refuses the LLQ layout: status {}: TX descriptors in host memory", self.n, st);
            return None;
        }
        let burst = if accel & LLQ_ACCEL_LIMIT_TX_BURST != 0 { burst_bytes / LLQ_ENTRY as u16 } else { 0 };
        Some((depth, burst))
    }

    /// Create a completion queue on the I/O vector: its index and unmask
    /// register.
    fn create_cq(&mut self, pa: u64, depth: u16, entry: usize) -> (u16, usize) {
        let r = self.exec(
            "create CQ",
            Cmd::new(AQ_CREATE_CQ)
                .u8(4, 1 << 5)
                .u8(5, (entry / 4) as u8)
                .u16(6, depth)
                .u32(8, IO_VECTOR)
                .addr(12, pa),
        );
        (le16(&r, 8), self.regs.0 + le32(&r, 20) as usize)
    }

    /// Create a submission queue with a completion for each frame (Linux's
    /// policy): its index, its doorbell and, for the LLQ, where its entries
    /// are in BAR 2.
    fn create_sq(&mut self, dir: u8, placement: u8, cq: u16, depth: u16, pa: u64) -> (u16, usize, u32) {
        let r = self.exec(
            "create SQ",
            Cmd::new(AQ_CREATE_SQ)
                .u8(4, dir << 5)
                .u8(6, placement)
                .u8(7, 1)
                .u16(8, cq)
                .u16(10, depth)
                .addr(12, pa),
        );
        (le16(&r, 8), self.regs.0 + le32(&r, 12) as usize, le32(&r, 16))
    }

    /// Send every received frame to RX queue `sq` (Linux sets the table
    /// for its queues, naming each by its SQ; the device's default need not
    /// name this one).
    fn set_rss_table(&mut self, dma: &mut Dma, sq: u16) {
        let Ok(t) = self.try_exec(Cmd::feature(AQ_GET_FEATURE, FEAT_RSS_INDIRECTION_TABLE, 0)) else {
            return;
        };
        let log = RSS_TABLE_LOG.clamp(le16(&t, 8), le16(&t, 10).max(le16(&t, 8)));
        let len = (1usize << log) * 4;
        let (va, pa) = dma.alloc(len, 64);
        for i in 0..1 << log {
            unsafe { write_volatile((va + i * 4) as *mut u16, sq.to_le()) };
        }
        let set = Cmd::feature(AQ_SET_FEATURE, FEAT_RSS_INDIRECTION_TABLE, 0)
            .indirect(pa, len as u32)
            .u16(24, log)
            .u32(28, u32::MAX);
        if let Err(st) = self.try_exec(set) {
            sel4::debug_println!("netd: NIC {}: ENA refuses the RSS table: status {}", self.n, st);
        }
    }

    fn unmask(&self) {
        unsafe { write_volatile(self.unmask_reg as *mut u32, (self.intr | INTR_UNMASK).to_le()) };
    }

    /// Handle the events the device has posted: link changes and errors
    /// are reported, keep-alives and notifications only acknowledged.
    fn poll_aenq(&mut self) {
        let mut seen = false;
        loop {
            let e = self.aenq + self.aenq_ring.slot() * ENTRY;
            if rd8(e + 4) & 1 != self.aenq_ring.phase {
                break;
            }
            dma_fence(Ordering::Acquire);
            match rd16(e) {
                AENQ_LINK_CHANGE => {
                    let up = rd32(e + 16) & 1 != 0;
                    l4h_rt::info!("netd: NIC {}: ENA link {}", self.n, if up { "up" } else { "down" });
                }
                AENQ_FATAL_ERROR => sel4::debug_println!("netd: NIC {}: ENA reports a fatal error ({})", self.n, rd16(e + 2)),
                AENQ_WARNING => sel4::debug_println!("netd: NIC {}: ENA warning {}", self.n, rd16(e + 2)),
                _ => {}
            }
            self.aenq_ring.advance();
            seen = true;
        }
        if seen {
            dma_fence(Ordering::SeqCst);
            self.regs.w32(REG_AENQ_HEAD_DB, self.aenq_ring.idx as u32);
        }
    }

    // ---- receive

    /// Give buffer `id` to the device.
    fn post_rx(&mut self, id: u16) {
        let d = self.rx_ring + self.rx_sq.slot() * RX_DESC;
        let (_, pa) = self.rx_bufs[id as usize];
        let mut b = [0u8; RX_DESC];
        put16(&mut b, 0, RX_BUF as u16);
        b[3] = RX_DESC_FIRST | RX_DESC_LAST | RX_DESC_COMP_REQ | self.rx_sq.phase & RX_DESC_PHASE;
        put16(&mut b, 4, id);
        put_addr(&mut b, 8, pa);
        wr64s(d, &b);
        self.rx_sq.advance();
        self.rx_unrung += 1;
        if self.rx_unrung >= RX_REFILL_BATCH {
            self.ring_rx();
        }
    }

    fn ring_rx(&mut self) {
        if self.rx_unrung != 0 {
            self.rx_unrung = 0;
            dma_fence(Ordering::Release);
            unsafe { write_volatile(self.rx_db as *mut u32, (self.rx_sq.idx as u32).to_le()) };
        }
    }

    /// The next RX completion, if the device has written it.
    fn rx_pending(&self) -> Option<usize> {
        let c = self.rx_cq + self.rx_cq_ring.slot() * RX_CDESC;
        ((rd32(c) >> RX_PHASE_SHIFT) as u8 & 1 == self.rx_cq_ring.phase).then_some(c)
    }

    pub fn rx_begin(&mut self) {
        // The I/O vector masked itself when it fired.  Events come on the
        // management vector, which raises the same interrupt.
        self.poll_aenq();
    }

    pub fn rx_done(&mut self) -> bool {
        self.ring_rx();
        if self.rx_pending().is_some() {
            return false;
        }
        self.unmask();
        // Completions written while the vector was masked raise it once it
        // is unmasked, so this is only a shortcut.
        self.rx_pending().is_none()
    }

    /// Whether the device checked the frame's L4 checksum and found it
    /// good (Linux ena_rx_checksum).
    fn csum_ok(status: u32) -> bool {
        let (l3, l4) = (status & 0x1f, (status >> 8) & 0x1f);
        if status & RX_IPV4_FRAG != 0 || (l3 == L3_IPV4 && status & RX_L3_CSUM_ERR != 0) {
            return false;
        }
        (l4 == L4_TCP || l4 == L4_UDP) && status & (RX_L4_CSUM_ERR | RX_L4_CSUM_CHECKED) == RX_L4_CSUM_CHECKED
    }

    pub fn receive(&mut self, out: &mut [u8], hdr: &mut [u8; HDR]) -> Option<usize> {
        loop {
            let c = self.rx_pending()?;
            dma_fence(Ordering::Acquire);
            let status = rd32(c);
            let (len, id, offset) = (rd16(c + 4) as usize, rd16(c + 6), rd8(c + 14) as usize);
            self.rx_cq_ring.advance();
            let (first, last) = (status & RX_FIRST != 0, status & RX_LAST != 0);
            if first {
                // A frame whose last buffer never came is lost.
                self.rx_partial.clear();
                self.rx_partial_bad = false;
            } else if !self.rx_in_frame {
                self.rx_partial_bad = true;
            }
            self.rx_in_frame = !last;
            // The packet offset applies to the first buffer.
            let start = if first { offset } else { 0 };
            let Some(&(va, _)) = self.rx_bufs.get(id as usize) else {
                // Not a buffer of ours: the frame it belongs to is lost.
                self.rx_partial_bad = true;
                if last {
                    self.rx_partial.clear();
                }
                continue;
            };
            // A length past the buffer loses the frame too.
            let fits = start + len <= RX_BUF;
            self.rx_partial_bad |= !fits;
            let data = if fits { unsafe { core::slice::from_raw_parts((va + start) as *const u8, len) } } else { &[] };
            let n = if first && last && fits {
                // The usual case: a frame in one buffer.
                let n = len.min(out.len());
                out[..n].copy_from_slice(&data[..n]);
                (n == len).then_some(n)
            } else {
                if self.rx_partial.extend_from_slice(data).is_err() {
                    self.rx_partial_bad = true;
                }
                if last {
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
            self.post_rx(id);
            let Some(n) = n else { continue };
            *hdr = [0; HDR];
            if Self::csum_ok(status) {
                hdr[0] = offload::F_DATA_VALID;
            }
            return Some(n);
        }
    }

    // ---- transmit

    /// Handle the TX completions the device has written: one per frame.
    fn reap_tx(&mut self) {
        loop {
            let c = self.tx_cq + self.tx_cq_ring.slot() * TX_CDESC;
            if rd8(c + 3) & 1 != self.tx_cq_ring.phase {
                return;
            }
            dma_fence(Ordering::Acquire);
            let id = rd16(c);
            self.tx_cq_ring.advance();
            if let Some(d) = self.tx_descs.get_mut(id as usize).filter(|d| **d != 0) {
                self.tx_next_to_comp = self.tx_next_to_comp.wrapping_add(core::mem::take(d));
                let _ = self.tx_free.push(id);
            }
        }
    }

    fn tx_has_compl(&self) -> bool {
        rd8(self.tx_cq + self.tx_cq_ring.slot() * TX_CDESC + 3) & 1 == self.tx_cq_ring.phase
    }

    pub fn tx_interrupts(&mut self, on: bool) -> bool {
        if on {
            self.unmask();
        }
        // Off: the vector masks itself the next time it fires.
        self.tx_has_compl()
    }

    /// Free SQ slots.
    fn tx_room(&self) -> u16 {
        self.tx_sq.mask - self.tx_sq.idx.wrapping_sub(self.tx_next_to_comp)
    }

    /// The device can complete this frame's checksum: the metadata
    /// descriptor's word 2 (L3 header offset and length) and the buffer
    /// descriptor's offload bits (Linux ena_tx_csum, partial checksum as
    /// virtio-net leaves it).
    fn csum_offload(&self, buf: &[u8], hdr: &[u8; HDR]) -> Option<(u32, u32)> {
        let get16 = |off: usize| u16::from_le_bytes([hdr[off], hdr[off + 1]]) as usize;
        let (start, off) = (get16(6), get16(8));
        let (ethertype, ip) = offload::ethertype(buf)?;
        let (l3, df) = match ethertype {
            0x0800 if self.tx_csum_v4 => (L3_IPV4, buf.get(ip + 6)? & 0x40 != 0),
            0x86dd if self.tx_csum_v6 => (L3_IPV6, false),
            _ => return None,
        };
        let l3_len = start.checked_sub(ip).filter(|&l| (20..256).contains(&l))?;
        let l4 = match off {
            16 => L4_TCP,
            6 => L4_UDP,
            _ => return None,
        };
        let ctrl = l3 | if df { TX_DF } else { 0 } | l4 << TX_L4_PROTO_SHIFT | TX_L4_CSUM_EN | TX_L4_CSUM_PARTIAL;
        Some((ctrl, l3_len as u32 | (ip as u32) << 8))
    }

    pub fn transmit(&mut self, frame: &(impl Frame + ?Sized), hdr: &[u8; HDR]) -> bool {
        let len = frame.len();
        if len > self.tx_buf {
            // Longer than the device's MTU: it cannot be sent.
            if !core::mem::replace(&mut self.tx_too_long, true) {
                sel4::debug_println!("netd: NIC {}: ENA drops frames longer than {} bytes ({})", self.n, self.tx_buf, len);
            }
            return true;
        }
        // A metadata and a buffer descriptor, or one LLQ entry (Linux
        // keeps two more free).
        let (descs, need) = if self.tx_llq.is_some() { (1, 3) } else { (2, 2) };
        if self.tx_free.is_empty() || self.tx_room() < need {
            self.reap_tx();
        }
        if self.tx_free.is_empty() || self.tx_room() < need {
            // Let the device start on what is queued.
            self.kick_tx();
            return false;
        }
        let tag = self.tx_free.pop().unwrap();
        self.tx_descs[tag as usize] = descs;
        let (va, pa) = self.tx_bufs[tag as usize];
        let buf = unsafe { core::slice::from_raw_parts_mut(va as *mut u8, len) };
        frame.copy_to(buf);
        let mut ctrl = 0;
        let mut word2 = 0;
        if hdr[0] & offload::F_NEEDS_CSUM != 0 {
            match self.csum_offload(buf, hdr) {
                Some((c, w)) => (ctrl, word2) = (c, w),
                None => {
                    let mut h = *hdr;
                    offload::complete_csum(buf, &mut h);
                }
            }
        }
        // As Linux with meta caching disabled, every frame starts with a
        // metadata descriptor; the buffer descriptor ends it.
        let tag32 = tag as u32;
        let push = if self.tx_llq.is_some() { len.min(LLQ_HEADER) } else { 0 };
        let header = if self.tx_llq.is_some() { push } else { len.min(self.tx_max_header) };
        let mut meta = [0u8; TX_DESC];
        let mut data = [0u8; TX_DESC];
        let phase = |r: &Ring| (r.phase as u32) << DESC_PHASE_SHIFT;
        put32(&mut meta, 0, DESC_META | META_EXT_VALID | META_ETH_META_TYPE | META_STORE | DESC_FIRST | phase(&self.tx_sq));
        put32(&mut meta, 8, word2);
        let (rest, rest_pa) = (len - push, if len > push { pa + push as u64 } else { 0 });
        let fill_data = |d: &mut [u8; TX_DESC], ph: u32| {
            put32(d, 0, rest as u32 & 0xffff | (tag32 >> 10 & 0x3f) << 16 | ph | DESC_LAST | DESC_COMP_REQ);
            put32(d, 4, ctrl | (tag32 & 0x3ff) << TX_REQ_ID_LO_SHIFT);
            put32(d, 8, rest_pa as u32);
            put32(d, 12, (rest_pa >> 32) as u32 & 0xffff | (header as u32) << TX_HEADER_LENGTH_SHIFT);
        };
        if let Some(llq) = self.tx_llq {
            // One entry: both descriptors, then the frame's first bytes.
            if self.tx_burst_max != 0 && self.tx_burst_left == 0 {
                self.kick_tx();
            }
            fill_data(&mut data, phase(&self.tx_sq));
            let mut entry = [0u8; LLQ_ENTRY];
            entry[..TX_DESC].copy_from_slice(&meta);
            entry[TX_DESC..2 * TX_DESC].copy_from_slice(&data);
            entry[2 * TX_DESC..2 * TX_DESC + push].copy_from_slice(&buf[..push]);
            wr64s(llq + self.tx_sq.slot() * LLQ_ENTRY, &entry);
            self.tx_sq.advance();
            self.tx_burst_left = self.tx_burst_left.saturating_sub(1);
        } else {
            wr64s(self.tx_ring + self.tx_sq.slot() * TX_DESC, &meta);
            self.tx_sq.advance();
            fill_data(&mut data, phase(&self.tx_sq));
            wr64s(self.tx_ring + self.tx_sq.slot() * TX_DESC, &data);
            self.tx_sq.advance();
        }
        self.tx_kick = true;
        true
    }

    pub fn kick_tx(&mut self) {
        if core::mem::take(&mut self.tx_kick) {
            wc_fence();
            unsafe { write_volatile(self.tx_db as *mut u32, (self.tx_sq.idx as u32).to_le()) };
            self.tx_burst_left = self.tx_burst_max;
        }
    }
}

/// The largest power of two at most `v` (and at most 32768), 0 for 0.
fn pow2_floor(v: u32) -> u16 {
    if v == 0 { 0 } else { 1 << (31 - v.leading_zeros()).min(15) }
}

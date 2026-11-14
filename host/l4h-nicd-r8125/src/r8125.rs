//! Realtek RTL8125B 2.5 GbE driver (Linux `r8169`, its RTL_GIGA_MAC_VER_63
//! paths), for the RTL8125B and RTL8125BG (10ec:8125, and 10ec:3000 as the
//! Killer E3000).  The RTL8125A and RTL8125D share the PCI ID; their MAC
//! and PHY setup differ, and the driver refuses them (by the chip's XID).
//!
//! Registers are little-endian in BAR 2 (BAR 0 is I/O ports, not used);
//! the MSI-X table is in BAR 4, which root maps for it.  One RX and one TX
//! ring of the chip's 16-byte descriptors, the ownership bit handing each
//! to the other side.  Frames are copied between the switch and DMA memory
//! owned by this driver: 2 KiB RX buffers, and a circular TX area that
//! frames take in order and give back as the chip completes them.
//!
//! Bring-up follows Linux's probe and open: the MAC's own init, a MAC
//! reset, the PHY's parameters (and its firmware patch, if the bundle has
//! `rtl_nic/rtl8125b-2.fw`), a PHY reset, the MAC start sequence, then
//! autonegotiation advertising 10 to 2500 Mb/s with pause.  The PHY is
//! reached through the GPHY OCP window (MDIO_MMD_VEND2 register r is OCP
//! address r; page p, register r of the paged C22 view is p * 16 + (r -
//! 16) * 2, page 0 the standard registers at 0xa400).  The chip's ASPM
//! stays off and the link's L1 is disabled, as Linux does unless the
//! system vendor marked ASPM safe.
//!
//! Every cause shares MSI-X entry 0 (the chip's single-vector mode).  RX
//! (RxOK, RxErr) and TX (TxOK, TxErr) causes are masked separately in
//! IntrMask; their status bits are acknowledged before they are unmasked,
//! so that a completion after the drain raises a fresh interrupt.  The
//! link is read on root's tick (F_TIMER).  As in Linux, the chip's own
//! interrupt coalescing is off.
//!
//! Offloads: the chip's RX checksum verdict becomes DATA_VALID; TSO for
//! TCP over IPv4 and IPv6 (untagged frames, MSS up to 2047, at most 64
//! segments as Linux's RTL_GSO_MAX_SEGS_V2).  Linux 6.18 sends no other
//! frame with checksum offload on this chip (rtl8169_features_check with
//! rtl_quirk_packet_padto), so neither does this driver: NEEDS_CSUM frames
//! are completed here, and short frames padded as Linux pads them.

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::Ordering;

use l4h_rt::host::{self, net};
use crate::sdk::{Hw, LinkState, Offer};
use l4h_virtio::{Mmio, dma_fence};

use crate::sdk::offload;

/// The PHY firmware patch Linux applies to the RTL8125B, from
/// linux-firmware, if the driver bundle has it (Linux works without it,
/// with a warning).
const FW_8125B: &str = "rtl_nic/rtl8125b-2.fw";

/// What the driver drives and needs (l4h_host::nicd::Manifest).
pub const MANIFEST: crate::sdk::Manifest = crate::sdk::Manifest {
    bars: 1 << 2,
    dma_bits: 22,
    flags: crate::sdk::nicd::F_TIMER,
    // The standard capabilities: root lets the driver write Link
    // Control's ASPM bits there and nothing else.
    config_writes: [
        crate::sdk::nicd::CfgWindow { offset: 0x40, len: 0xc0 },
        crate::sdk::nicd::CfgWindow::NONE,
        crate::sdk::nicd::CfgWindow::NONE,
        crate::sdk::nicd::CfgWindow::NONE,
    ],
    // RTL8125 (A, B, D: the XID tells), Killer E3000 (RTL8125BG).
    ..crate::sdk::Manifest::empty()
        .with_name("r8125")
        .with_matches(&[crate::sdk::PciMatch::id(0x10ec, 0x8125), crate::sdk::PciMatch::id(0x10ec, 0x3000)])
        .with_firmware(&[FW_8125B])
};

const HDR: usize = net::HDR_SIZE;

// Registers (BAR 2).
const MAC0: usize = 0x00;
const MAC4: usize = 0x04;
const MAR0: usize = 0x08;
const TX_DESC_LO: usize = 0x20;
const TX_DESC_HI: usize = 0x24;
const INT_CFG0: usize = 0x34;
const CHIP_CMD: usize = 0x37;
const IMR: usize = 0x38;
const ISR: usize = 0x3c;
const TX_CONFIG: usize = 0x40;
const RX_CONFIG: usize = 0x44;
const CFG9346: usize = 0x50;
const CONFIG1: usize = 0x52;
const CONFIG2: usize = 0x53;
const CONFIG3: usize = 0x54;
const CONFIG5: usize = 0x56;
const INT_CFG1: usize = 0x7a;
const EPHYAR: usize = 0x80;
const TX_POLL: usize = 0x90;
const OCPDR: usize = 0xb0;
const GPHY_OCP: usize = 0xb8;
const MCU: usize = 0xd3;
const RX_MAX_SIZE: usize = 0xda;
const CPLUS_CMD: usize = 0xe0;
const INTR_MITIGATE: usize = 0xe2;
const RX_DESC_LO: usize = 0xe4;
const RX_DESC_HI: usize = 0xe8;
const MISC: usize = 0xf0;
const MAC0_BKP: usize = 0x19e0;
const RSS_CTRL: usize = 0x4500;
const Q_NUM_CTRL: usize = 0x4800;
const EEE_TXIDLE_TIMER: usize = 0x6048;

/// TxConfig bits 30:20, masked as Linux's chip table masks them: the
/// RTL8125B is 0x641 (RTL8125A 0x609, RTL8125D 0x688/0x689).
const XID_MASK: u32 = 0x7cf;
const XID_8125B: u32 = 0x641;

const CMD_STOP_REQ: u8 = 0x80;
const CMD_RESET: u8 = 0x10;
const CMD_RX_EN: u8 = 0x08;
const CMD_TX_EN: u8 = 0x04;
const CFG9346_UNLOCK: u8 = 0xc0;
const CFG9346_LOCK: u8 = 0x00;
const CONFIG2_CLKREQ_EN: u8 = 1 << 7;
const CONFIG3_RDY_TO_L23: u8 = 1 << 1;
const CONFIG5_ASPM_EN: u8 = 1 << 0;
const MCU_NOW_IS_OOB: u8 = 1 << 7;
const MCU_RXTX_EMPTY: u8 = 0x30;
const MCU_LINK_LIST_RDY: u8 = 1 << 1;
const MISC_RXDV_GATED_EN: u32 = 1 << 19;
/// RxConfig: Linux's rtl_init_rxcfg for VER_63 (fetch, burst, pause
/// slot), the accept bits and the 8125's VLAN stripping (left off: netd
/// takes tags in the frame).
const RX_FETCH_DFLT: u32 = 8 << 27;
const RX_DMA_BURST: u32 = 7 << 8;
const RX_PAUSE_SLOT_ON: u32 = 1 << 11;
const RX_VLAN: u32 = 3 << 22;
const RX_ACCEPT_ERR: u32 = 0x30;
const RX_ACCEPT_ALL: u32 = 0x0f;
const RX_ACCEPT_MASK: u32 = 0x3f;
/// TxConfig: unlimited DMA burst, the shortest inter-frame gap.
const TX_CONFIG_VAL: u32 = 7 << 8 | 3 << 24;
/// C+ command: what Linux keeps of it (CPCMD_MASK), RX checksums on.
const CPCMD_MASK: u16 = 1 << 13 | 1 << 6 | 1 << 5 | 3;
const CPCMD_RX_VLAN: u16 = 1 << 6;
const CPCMD_RX_CSUM: u16 = 1 << 5;
const OCP_FLAG: u32 = 1 << 31;
const EPHYAR_FLAG: u32 = 1 << 31;

/// Interrupt causes (IntrMask/IntrStatus).
const CAUSE_RX: u32 = 1 << 0 | 1 << 1;
const CAUSE_TX: u32 = 1 << 2 | 1 << 3;

// Descriptors: opts1, opts2, buffer address.
const DESC: usize = 16;
const DESC_OWN: u32 = 1 << 31;
const RING_END: u32 = 1 << 30;
const FIRST_FRAG: u32 = 1 << 29;
const LAST_FRAG: u32 = 1 << 28;

// RX: 2 KiB buffers (the length in opts1 includes the FCS); a frame that
// spans buffers is longer than the standard MTU and dropped.
const RX_RING: usize = 512;
const RX_BUF: usize = 2048;
const RX_RES: u32 = 1 << 21;
const RX_PROTO_TCP: u32 = 1 << 17;
const RX_PROTO_UDP: u32 = 1 << 18;
const RX_PROTO_MASK: u32 = 3 << 17;
const RX_CS_FAIL: u32 = 7 << 14;
const RX_LEN: u32 = 0x3fff;
const FCS: usize = 4;

// TX: one descriptor a frame, its bytes in the circular area.
const TX_RING: usize = 256;
const TX_AREA: usize = 1 << 20;
const TX_ALIGN: usize = 64;
const TD_GTSENV4: u32 = 1 << 26;
const TD_GTSENV6: u32 = 1 << 25;
const GTTCPHO_SHIFT: u32 = 18;
const GTTCPHO_MAX: usize = 0x7f;
const TD_MSS_SHIFT: u32 = 18;
const TD_MSS_MAX: usize = 0x7ff;
/// Linux's RTL_GSO_MAX_SIZE_V2 and RTL_GSO_MAX_SEGS_V2: the smallest MSS
/// keeps a frame within 64 segments.
const TSO_MAX: usize = 64000;
const TSO_MIN_MSS: usize = TSO_MAX.div_ceil(64);
/// A segment cut here (a GSO frame the chip does not take): headers and
/// payload.
const SEG_BUF: usize = 4096;
const ETH_ZLEN: usize = 60;
/// The longest plain frame: 1500 bytes of MTU, Ethernet header and tag.
const TX_FRAME_MAX: usize = 1518;
/// rtl8125_quirk_udp_padto's RTL_MIN_PATCH_LEN.
const MIN_PATCH_LEN: usize = 47;

// PHY registers (OCP addresses).
const PHY_BASE: u32 = 0xa400;
const BMCR: u32 = PHY_BASE;
const BMSR: u32 = PHY_BASE + 2;
const ANAR: u32 = PHY_BASE + 4 * 2;
const GBCR: u32 = PHY_BASE + 9 * 2;
const PHYSR: u32 = 0xa434;
const AN_10GBT_CTRL: u32 = 0xa5d4;
const BMCR_RESET: u16 = 1 << 15;
const BMCR_ANENABLE: u16 = 1 << 12;
const BMCR_PDOWN: u16 = 1 << 11;
const BMCR_ISOLATE: u16 = 1 << 10;
const BMCR_ANRESTART: u16 = 1 << 9;
const BMSR_LSTATUS: u16 = 1 << 2;
/// 10/100 half and full, pause and asymmetric pause, selector 802.3.
const ANAR_ADV: u16 = 0x0de1;
const ANAR_MASK: u16 = 0x0fe0;
const GBCR_1000FULL: u16 = 1 << 9;
const GBCR_MASK: u16 = 3 << 8;
const ADV_2500: u16 = 1 << 7;
const ADV_NBASET_MASK: u16 = 1 << 7 | 1 << 8 | 1 << 12;

/// How long the link may take to come up in start (2.5G autonegotiation
/// takes about 3 s); later, root's tick sees it.
const LINK_WAIT_MS: u64 = 4000;
/// Steps of the PHY firmware program, at most (its loops poll the PHY).
const FW_MAX_STEPS: usize = 1 << 22;

fn rd32(va: usize) -> u32 {
    unsafe { read_volatile(va as *const u32) }
}
fn wr32(va: usize, v: u32) {
    unsafe { write_volatile(va as *mut u32, v) }
}
fn wr64(va: usize, v: u64) {
    unsafe { write_volatile(va as *mut u64, v) }
}

/// The OCP address of register `reg` of PHY page `page` (Linux
/// r8168g_mdio_write).
const fn phy_paged(page: u32, reg: u32) -> u32 {
    if page == 0 { PHY_BASE + reg * 2 } else { page * 16 + (reg - 16) * 2 }
}

/// PHYSR as a link speed (Linux rtlgen_decode_physr).
fn physr_speed(v: u16) -> u32 {
    match v & 0x0630 {
        0x0000 => 10,
        0x0010 => 100,
        0x0020 => 1000,
        0x0210 => 2500,
        0x0220 => 5000,
        0x0200 => 10000,
        _ => 0,
    }
}

fn csum_add(mut s: u32, data: &[u8]) -> u32 {
    for c in data.chunks(2) {
        s += (c[0] as u32) << 8 | *c.get(1).unwrap_or(&0) as u32;
    }
    s
}
fn csum_fold(mut s: u32) -> u16 {
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    s as u16
}

/// The length Linux pads a frame without checksum offload to on the
/// RTL8125B (rtl_quirk_packet_padto): ETH_ZLEN, and more for short UDP
/// packets (rtl8125_quirk_udp_padto: PTP event and general messages, and
/// a UDP header the frame cuts short).
fn pad_to(frame: &[u8]) -> usize {
    let len = frame.len();
    let mut padto = 0;
    let udp = || -> Option<usize> {
        let (ethertype, ip) = offload::ethertype(frame)?;
        match ethertype {
            0x0800 if *frame.get(ip + 9)? == 17 => Some(ip + (*frame.get(ip)? & 0x0f) as usize * 4),
            0x86dd if *frame.get(ip + 6)? == 17 => Some(ip + 40),
            _ => None,
        }
    };
    if len < 128 + MIN_PATCH_LEN
        && let Some(t) = udp().filter(|&t| t <= len)
    {
        let data = len - t;
        if (4..MIN_PATCH_LEN).contains(&data) {
            let dest = u16::from_be_bytes([frame[t + 2], frame[t + 3]]);
            if dest == 319 || dest == 320 {
                padto = len + MIN_PATCH_LEN - data;
            }
        }
        if data < 8 {
            padto = padto.max(len + 8 - data);
        }
    }
    padto.max(ETH_ZLEN)
}

pub struct R8125 {
    pub mac: [u8; 6],
    regs: Mmio,
    tsc_hz: u64,
    link: LinkState,
    /// IntrMask as written.
    imr: u32,
    /// The OCP base of the paged PHY (and MAC MCU) view the firmware
    /// program writes through (Linux tp->ocp_base).
    ocp_base: u32,

    rx_ring: usize,
    rx_bufs: [(usize, u64); RX_RING],
    /// Next descriptor the chip completes.
    rx_next: usize,

    tx_ring: usize,
    tx_area: (usize, u64),
    /// Descriptors queued and completed (wrapping counts).
    tx_prod: usize,
    tx_cons: usize,
    /// Bytes of the area taken and given back (wrapping counts), and
    /// where each queued descriptor's frame ends (tx_put after it).
    tx_put: usize,
    tx_got: usize,
    tx_end: [usize; TX_RING],
    tx_kick: bool,
    /// SEG_BUF bytes for segments cut here.
    seg: usize,
}

impl R8125 {
    pub fn offer(&self) -> Offer {
        let mut o = Offer::plain(self.mac);
        o.tx_csum = 1;
        o.tx_gso_mask = 1 << 1 | 1 << 4;
        o.tx_gso_max = TSO_MAX as u32;
        o.tx_mss_min = TSO_MIN_MSS as u32;
        o.tx_mss_max = TD_MSS_MAX as u32;
        o.tx_hdr_max = GTTCPHO_MAX as u32;
        // GSO frames are bounded by it too (Offer::checked); transmit
        // drops plain frames past TX_FRAME_MAX.
        o.tx_frame_max = TSO_MAX as u32;
        o
    }

    // ---- register access

    fn udelay(&self, us: u64) {
        let end = host::ticks::now() + us * self.tsc_hz / 1_000_000;
        while host::ticks::now() < end {
            core::hint::spin_loop();
        }
    }

    /// Check `cond` up to `n` times, `us` apart (Linux rtl_loop_wait).
    fn wait(&self, us: u64, n: usize, cond: impl Fn(&Self) -> bool) -> bool {
        for _ in 0..n {
            if cond(self) {
                return true;
            }
            self.udelay(us);
        }
        false
    }

    /// Read back a register: earlier writes have reached the chip.
    fn commit(&self) {
        self.regs.r8(CHIP_CMD);
    }

    fn mac_ocp_w(&self, reg: u32, v: u16) {
        self.regs.w32(OCPDR, OCP_FLAG | reg << 15 | v as u32);
    }

    fn mac_ocp_r(&self, reg: u32) -> u16 {
        self.regs.w32(OCPDR, reg << 15);
        self.regs.r32(OCPDR) as u16
    }

    fn mac_ocp_modify(&self, reg: u32, mask: u16, set: u16) {
        let v = self.mac_ocp_r(reg);
        self.mac_ocp_w(reg, (v & !mask) | set);
    }

    fn phy_w(&self, reg: u32, v: u16) {
        self.regs.w32(GPHY_OCP, OCP_FLAG | reg << 15 | v as u32);
        self.wait(25, 10, |s| s.regs.r32(GPHY_OCP) & OCP_FLAG == 0);
    }

    fn phy_r(&self, reg: u32) -> u16 {
        self.regs.w32(GPHY_OCP, reg << 15);
        self.wait(25, 10, |s| s.regs.r32(GPHY_OCP) & OCP_FLAG != 0);
        self.regs.r32(GPHY_OCP) as u16
    }

    fn phy_modify(&self, reg: u32, mask: u16, set: u16) {
        let v = self.phy_r(reg);
        self.phy_w(reg, (v & !mask) | set);
    }

    fn phy_modify_paged(&self, page: u32, reg: u32, mask: u16, set: u16) {
        self.phy_modify(phy_paged(page, reg), mask, set);
    }

    /// Linux r8168g_phy_param: an indirect PHY parameter through page
    /// 0xa43 registers 0x13 and 0x14.
    fn phy_param_a43(&self, parm: u16, mask: u16, set: u16) {
        self.phy_w(phy_paged(0xa43, 0x13), parm);
        self.phy_modify(phy_paged(0xa43, 0x14), mask, set);
    }

    /// Linux rtl8125_phy_param: one through 0xb87c and 0xb87e.
    fn phy_param_b87(&self, parm: u16, mask: u16, set: u16) {
        self.phy_w(0xb87c, parm);
        self.phy_modify(0xb87e, mask, set);
    }

    /// Linux rtl_ephy_write and rtl_ephy_read.  The address is masked to 5
    /// bits as Linux masks it (EPHYAR_REG_MASK).
    fn ephy_w(&self, reg: u32, v: u16) {
        self.regs.w32(EPHYAR, EPHYAR_FLAG | v as u32 | (reg & 0x1f) << 16);
        self.wait(10, 100, |s| s.regs.r32(EPHYAR) & EPHYAR_FLAG == 0);
        self.udelay(10);
    }

    fn ephy_r(&self, reg: u32) -> u16 {
        self.regs.w32(EPHYAR, (reg & 0x1f) << 16);
        if self.wait(10, 100, |s| s.regs.r32(EPHYAR) & EPHYAR_FLAG != 0) { self.regs.r32(EPHYAR) as u16 } else { 0xffff }
    }

    fn unlock_config(&self) {
        self.regs.w8(CFG9346, CFG9346_UNLOCK);
    }

    fn lock_config(&self) {
        self.regs.w8(CFG9346, CFG9346_LOCK);
    }

    // ---- bring-up

    pub fn new(hw: &Hw) -> Result<Self, &'static str> {
        let c = hw.config;
        let n = c.uplink as usize;
        let regs = Mmio(c.bars[2].va as usize);
        let txconfig = regs.r32(TX_CONFIG);
        if txconfig == u32::MAX {
            return Err("the device does not answer");
        }
        let xid = (txconfig >> 20) & 0xfcf;
        if xid & XID_MASK != XID_8125B {
            l4h_rt::info!("nicd {}: RTL8125 XID {:03x} is not an RTL8125B", n, xid);
            return Err("not an RTL8125B");
        }
        let mut dma = hw.dma();
        let (rx_ring, rx_ring_pa) = dma.alloc(RX_RING * DESC, 4096);
        let rx_bufs: [_; RX_RING] = core::array::from_fn(|_| dma.alloc(RX_BUF, 128));
        let (tx_ring, tx_ring_pa) = dma.alloc(TX_RING * DESC, 4096);
        let tx_area = dma.alloc(TX_AREA, 4096);
        let (seg, _) = dma.alloc(SEG_BUF, 64);
        let mut r = R8125 {
            mac: [0; 6],
            regs,
            tsc_hz: hw.tsc_hz,
            link: LinkState::ethernet(false, 0),
            imr: 0,
            ocp_base: PHY_BASE,
            rx_ring,
            rx_bufs,
            rx_next: 0,
            tx_ring,
            tx_area,
            tx_prod: 0,
            tx_cons: 0,
            tx_put: 0,
            tx_got: 0,
            tx_end: [0; TX_RING],
            tx_kick: false,
            seg,
        };

        // Probe (rtl_init_one): the link's L1 off, RX defaults, interrupts
        // off, the MAC's own init, a reset, the MAC address.
        r.disable_l1(hw);
        let cp_cmd = (r.regs.r16(CPLUS_CMD) & CPCMD_MASK & !CPCMD_RX_VLAN) | CPCMD_RX_CSUM;
        r.init_rxcfg();
        r.irq_mask_and_ack();
        r.hw_init();
        r.hw_reset();
        r.mac = r.read_mac();
        r.set_mac();

        // Open (rtl8169_up): the PHY, then the MAC.
        r.phy_w(BMCR, r.phy_r(BMCR) & !BMCR_PDOWN);
        r.udelay(20_000);
        let fw = c.firmware[0];
        let fw = (fw.len != 0).then(|| unsafe { core::slice::from_raw_parts(fw.va as *const u8, fw.len as usize) });
        r.hw_phy_config(n, fw)?;
        r.phy_soft_reset();
        hw.program_msix(1);
        r.cleanup();
        for i in 0..RX_RING {
            r.post_rx(i);
        }
        r.hw_start(cp_cmd, rx_ring_pa, tx_ring_pa, hw);
        r.config_aneg();

        // Wait for the link a while; the tick sees it later otherwise.
        for _ in 0..LINK_WAIT_MS / 10 {
            if r.read_link().up() {
                break;
            }
            r.udelay(10_000);
        }
        r.link = r.read_link();
        let mac = r.mac;
        l4h_rt::info!(
            "nicd {}: {:02x}:{:02x}.{} RTL8125B, mac {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, PHY firmware {}, link {} {}M",
            n, c.pci_bdf >> 8, (c.pci_bdf >> 3) & 0x1f, c.pci_bdf & 7,
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
            if fw.is_some() { "patched" } else { "not in the bundle" },
            if r.link.up() { "up" } else { "down" }, r.link.speed(),
        );
        Ok(r)
    }

    /// Linux rtl_init_rxcfg (VER_63).
    fn init_rxcfg(&self) {
        self.regs.w32(RX_CONFIG, RX_FETCH_DFLT | RX_DMA_BURST | RX_PAUSE_SLOT_ON);
    }

    fn irq_mask_and_ack(&mut self) {
        self.imr = 0;
        self.regs.w32(IMR, 0);
        self.regs.w32(ISR, u32::MAX);
        self.commit();
    }

    /// Linux rtl_wait_txrx_fifo_empty (VER_63).
    fn wait_fifo_empty(&self) {
        self.regs.w8(CHIP_CMD, self.regs.r8(CHIP_CMD) | CMD_STOP_REQ);
        self.wait(100, 42, |s| s.regs.r8(MCU) & MCU_RXTX_EMPTY == MCU_RXTX_EMPTY);
        self.wait(100, 42, |s| s.regs.r16(INTR_MITIGATE) & 0x0103 == 0x0103);
    }

    fn enable_rxdvgate(&self) {
        self.regs.w32(MISC, self.regs.r32(MISC) | MISC_RXDV_GATED_EN);
        self.udelay(2000);
        self.wait_fifo_empty();
    }

    fn wait_ll_share_fifo_ready(&self) {
        self.wait(100, 42, |s| s.regs.r8(MCU) & MCU_LINK_LIST_RDY != 0);
    }

    /// Linux rtl_hw_init_8125.
    fn hw_init(&self) {
        self.enable_rxdvgate();
        self.regs.w8(CHIP_CMD, self.regs.r8(CHIP_CMD) & !(CMD_TX_EN | CMD_RX_EN));
        self.udelay(1000);
        self.regs.w8(MCU, self.regs.r8(MCU) & !MCU_NOW_IS_OOB);
        self.mac_ocp_modify(0xe8de, 1 << 14, 0);
        self.wait_ll_share_fifo_ready();
        self.mac_ocp_w(0xc0aa, 0x07d0);
        self.mac_ocp_w(0xc0a6, 0x0150);
        self.mac_ocp_w(0xc01e, 0x5555);
        self.wait_ll_share_fifo_ready();
    }

    fn hw_reset(&self) {
        self.regs.w8(CHIP_CMD, CMD_RESET);
        self.wait(100, 100, |s| s.regs.r8(CHIP_CMD) & CMD_RESET == 0);
    }

    /// The permanent address (MAC0_BKP), else what MAC0 holds (Linux
    /// rtl_init_mac_address; it falls back to a random one, which an
    /// uplink must not have: root checks the address stays the NIC's).
    fn read_mac(&self) -> [u8; 6] {
        let read = |base: usize| core::array::from_fn(|i| self.regs.r8(base + i));
        let valid = |m: &[u8; 6]| m[0] & 1 == 0 && m.iter().any(|&b| b != 0);
        let m = read(MAC0_BKP);
        if valid(&m) { m } else { read(MAC0) }
    }

    /// Linux rtl_rar_set.
    fn set_mac(&self) {
        let m = self.mac;
        self.unlock_config();
        self.regs.w32(MAC4, u16::from_le_bytes([m[4], m[5]]) as u32);
        self.commit();
        self.regs.w32(MAC0, u32::from_le_bytes([m[0], m[1], m[2], m[3]]));
        self.commit();
        self.lock_config();
    }

    /// Linux rtl8125b_hw_phy_config, with r8169_apply_firmware first.
    fn hw_phy_config(&mut self, n: usize, fw: Option<&[u8]>) -> Result<(), &'static str> {
        if let Some(fw) = fw {
            let Some(code) = fw_code(fw).filter(|c| fw_check(c)) else {
                l4h_rt::info!("nicd {}: {} is not a valid PHY firmware: not applied", n, FW_8125B);
                return self.phy_params();
            };
            if !self.fw_run(code) {
                return Err("the PHY firmware does not finish");
            }
            // At least one firmware leaves another page selected.
            self.ocp_base = PHY_BASE;
            // A PHY reset may still be under way.
            self.wait(50_000, 12, |s| s.phy_r(BMCR) & BMCR_RESET == 0);
        }
        self.phy_params()
    }

    fn phy_params(&self) -> Result<(), &'static str> {
        // rtl8168g_enable_gphy_10m.
        self.phy_modify_paged(0xa44, 0x11, 0, 1 << 11);

        self.phy_modify_paged(0xac4, 0x13, 0x00f0, 0x0090);
        self.phy_modify_paged(0xad3, 0x10, 0x0003, 0x0001);

        self.phy_param_b87(0x80f5, 0xffff, 0x760e);
        self.phy_param_b87(0x8107, 0xffff, 0x360e);
        self.phy_param_b87(0x8551, 0xff00, 0x0800);

        self.phy_modify_paged(0xbf0, 0x10, 0xe000, 0xa000);
        self.phy_modify_paged(0xbf4, 0x13, 0x0f00, 0x0300);

        for parm in (0x8044..=0x807a).step_by(6) {
            self.phy_param_a43(parm, 0xffff, 0x2417);
        }

        self.phy_modify_paged(0xa4c, 0x15, 0x0000, 0x0040);
        self.phy_modify_paged(0xbf8, 0x12, 0xe000, 0xa000);

        // rtl8125_legacy_force_mode.
        self.phy_modify_paged(0xa5b, 0x12, 1 << 15, 0);
        // rtl8168g_disable_aldps.
        self.phy_modify_paged(0xa43, 0x10, 1 << 2, 0);
        // rtl8125_config_eee_phy.
        self.phy_modify_paged(0xa43, 0x11, 0, 1 << 4);
        self.phy_modify_paged(0xa6d, 0x14, 0x0010, 0x0000);
        self.phy_modify_paged(0xa42, 0x14, 0x0080, 0x0000);
        self.phy_modify_paged(0xa4a, 0x11, 0x0200, 0x0000);
        Ok(())
    }

    /// Linux genphy_soft_reset, autonegotiation on.
    fn phy_soft_reset(&self) {
        self.phy_modify(BMCR, BMCR_ISOLATE, BMCR_RESET | BMCR_ANRESTART);
        if !self.wait(50_000, 12, |s| s.phy_r(BMCR) & BMCR_RESET == 0) {
            l4h_rt::info!("r8125: PHY reset does not complete");
        }
    }

    /// What Linux's PHY driver advertises for this PHY (rtl822x_config_aneg,
    /// genphy_config_advert): 10/100 half and full, 1000 full, 2500 full,
    /// pause and asymmetric pause; then autonegotiation restarts.
    fn config_aneg(&self) {
        self.phy_modify(AN_10GBT_CTRL, ADV_NBASET_MASK, ADV_2500);
        self.phy_modify(ANAR, ANAR_MASK, ANAR_ADV);
        self.phy_modify(GBCR, GBCR_MASK, GBCR_1000FULL);
        self.phy_modify(BMCR, BMCR_ISOLATE, BMCR_ANENABLE | BMCR_ANRESTART);
    }

    /// The link as the PHY has it: BMSR (read twice: its link bit latches
    /// low) and the speed it negotiated (PHYSR).
    fn read_link(&self) -> LinkState {
        self.phy_r(BMSR);
        let up = self.phy_r(BMSR) & BMSR_LSTATUS != 0;
        let speed = if up { physr_speed(self.phy_r(PHYSR)) } else { 0 };
        LinkState::ethernet(up, speed)
    }

    /// Turn the link's ASPM L1 off (Linux pci_disable_link_state, which it
    /// does unless the system vendor flagged ASPM safe).  Root's filter
    /// lets only the ASPM bits of Link Control through.
    fn disable_l1(&self, hw: &Hw) {
        let cfg = hw.cfg_snapshot();
        let mut cap = (cfg[0x34] & 0xfc) as usize;
        for _ in 0..48 {
            if cap < 0x40 {
                return;
            }
            if cfg[cap] == 0x10 {
                let lnkctl = u16::from_le_bytes([cfg[cap + 0x10], cfg[cap + 0x11]]);
                if lnkctl & 2 != 0 && hw.cfg_write((cap + 0x10) as u16, 2, (lnkctl & !2) as u32).is_err() {
                    l4h_rt::info!("nicd {}: could not turn ASPM L1 off", hw.config.uplink);
                }
                return;
            }
            cap = (cfg[cap + 1] & 0xfc) as usize;
        }
    }

    /// Linux rtl8169_cleanup (VER_63): interrupts off, receive closed, the
    /// FIFOs drained, a reset.
    fn cleanup(&mut self) {
        self.irq_mask_and_ack();
        self.regs.w32(RX_CONFIG, self.regs.r32(RX_CONFIG) & !RX_ACCEPT_MASK);
        self.enable_rxdvgate();
        self.udelay(2000);
        self.hw_reset();
    }

    /// Linux rtl_hw_start with rtl_hw_start_8125 and rtl_hw_start_8125b
    /// (ASPM and clock requests off, which Linux turns on only when it
    /// controls the link's ASPM).
    fn hw_start(&mut self, cp_cmd: u16, rx_pa: u64, tx_pa: u64, hw: &Hw) {
        let regs = self.regs;
        self.unlock_config();
        // rtl_hw_aspm_clkreq_enable(false).
        self.mac_ocp_modify(0xe092, 0x00ff, 0);
        regs.w8(CONFIG2, regs.r8(CONFIG2) & !CONFIG2_CLKREQ_EN);
        regs.w8(CONFIG5, regs.r8(CONFIG5) & !CONFIG5_ASPM_EN);
        regs.w16(CPLUS_CMD, cp_cmd);
        // rtl_set_eee_txidle_timer: MTU + ETH_HLEN + 0x20.
        regs.w16(EEE_TXIDLE_TIMER, 1500 + 14 + 0x20);

        // rtl_hw_start_8125: no interrupt coalescing, extended tally
        // counters.
        regs.w8(INT_CFG0, 0);
        for r in (0xa00..0xa80).step_by(4) {
            regs.w32(r, 0);
        }
        regs.w16(INT_CFG1, 0);
        self.mac_ocp_modify(0xea84, 0, 3);

        // rtl_hw_start_8125b.  Linux also sets the ASPM entry latency
        // (configuration byte 0x70f), which only matters with ASPM on.
        for &(reg, mask, bits) in &[
            (0x0b, 0xffff, 0xa908),
            (0x1e, 0xffff, 0x20eb),
            (0x4b, 0xffff, 0xa908),
            (0x5e, 0xffff, 0x20eb),
            (0x22, 0x0030, 0x0020),
            (0x62, 0x0030, 0x0020),
        ] {
            self.ephy_w(reg, (self.ephy_r(reg) & !mask) | bits);
        }

        // rtl_hw_start_8125_common.
        regs.w8(CONFIG3, regs.r8(CONFIG3) & !CONFIG3_RDY_TO_L23);
        regs.w16(0x382, 0x221b);
        regs.w32(RSS_CTRL, 0);
        regs.w16(Q_NUM_CTRL, 0);
        // UPS off.
        self.mac_ocp_modify(0xd40a, 0x0010, 0);
        regs.w8(CONFIG1, regs.r8(CONFIG1) & !0x10);
        self.mac_ocp_w(0xc140, 0xffff);
        self.mac_ocp_w(0xc142, 0xffff);
        self.mac_ocp_modify(0xd3e2, 0x0fff, 0x03a9);
        self.mac_ocp_modify(0xd3e4, 0x00ff, 0x0000);
        self.mac_ocp_modify(0xe860, 0x0000, 0x0080);
        // The legacy TX descriptor format.
        self.mac_ocp_modify(0xeb58, 0x0001, 0x0000);
        self.mac_ocp_modify(0xe614, 0x0700, 0x0200);
        self.mac_ocp_modify(0xe63e, 0x0c30, 0x0000);
        self.mac_ocp_modify(0xc0b4, 0x0000, 0x000c);
        self.mac_ocp_modify(0xeb6a, 0x00ff, 0x0033);
        self.mac_ocp_modify(0xeb50, 0x03e0, 0x0040);
        self.mac_ocp_modify(0xe056, 0x00f0, 0x0000);
        self.mac_ocp_modify(0xe040, 0x1000, 0x0000);
        self.mac_ocp_modify(0xea1c, 0x0003, 0x0001);
        self.mac_ocp_modify(0xea1c, 0x0004, 0x0000);
        self.mac_ocp_modify(0xe0c0, 0x4f0f, 0x4403);
        self.mac_ocp_modify(0xe052, 0x0080, 0x0068);
        self.mac_ocp_modify(0xd430, 0x0fff, 0x047f);
        self.mac_ocp_modify(0xea1c, 0x0004, 0x0000);
        self.mac_ocp_modify(0xeb54, 0x0000, 0x0001);
        self.udelay(1);
        self.mac_ocp_modify(0xeb54, 0x0001, 0x0000);
        regs.w16(0x1880, regs.r16(0x1880) & !0x0030);
        self.mac_ocp_w(0xe098, 0xc302);
        if !self.wait(1000, 10, |s| s.mac_ocp_r(0xe00e) & 1 << 13 == 0) {
            l4h_rt::info!("nicd {}: MAC OCP 0xe00e stays busy", hw.config.uplink);
        }
        // rtl8125b_config_eee_mac.
        self.mac_ocp_modify(0xe040, 0, 3);
        // rtl_disable_rxdvgate.
        regs.w32(MISC, regs.r32(MISC) & !MISC_RXDV_GATED_EN);

        // rtl_enable_exit_l1.
        self.mac_ocp_modify(0xc0ac, 0, 0x1f80);
        regs.w16(RX_MAX_SIZE, (RX_BUF + 1) as u16);
        regs.w32(TX_DESC_HI, (tx_pa >> 32) as u32);
        regs.w32(TX_DESC_LO, tx_pa as u32);
        regs.w32(RX_DESC_HI, (rx_pa >> 32) as u32);
        regs.w32(RX_DESC_LO, rx_pa as u32);
        self.lock_config();
        self.commit();

        dma_fence(Ordering::Release);
        regs.w8(CHIP_CMD, CMD_TX_EN | CMD_RX_EN);
        self.init_rxcfg();
        regs.w32(TX_CONFIG, TX_CONFIG_VAL);
        // rtl_set_rx_config_features: no error frames, tags kept.
        regs.w32(RX_CONFIG, regs.r32(RX_CONFIG) & !(RX_ACCEPT_ERR | RX_VLAN));
        // rtl_set_rx_mode: every frame (the switch decides, as with
        // netd's other uplinks).
        regs.w32(MAR0 + 4, u32::MAX);
        regs.w32(MAR0, u32::MAX);
        regs.w32(RX_CONFIG, (regs.r32(RX_CONFIG) & !RX_ACCEPT_ALL) | RX_ACCEPT_ALL);
        regs.w32(ISR, u32::MAX);
        self.imr = CAUSE_RX;
        regs.w32(IMR, self.imr);
    }

    // ---- PHY firmware (Linux r8169_firmware.c)

    /// The chip's PHY or MAC MCU register `reg` through the paged view the
    /// firmware programs (Linux r8168g_mdio_write, mac_mcu_write): None
    /// for an address the OCP window does not take.
    fn fw_reg(&self, mac: bool, reg: u32) -> Option<u32> {
        let a = if mac {
            self.ocp_base.wrapping_add(reg)
        } else if self.ocp_base == PHY_BASE {
            PHY_BASE + reg * 2
        } else {
            self.ocp_base.wrapping_add(reg.wrapping_sub(0x10).wrapping_mul(2))
        };
        (a & 0xffff_0001 == 0).then_some(a)
    }

    fn fw_write(&mut self, mac: bool, reg: u32, v: u32) {
        if reg == 0x1f {
            // Page 0 of the PHY is its standard registers; the MAC MCU has
            // no such page.
            self.ocp_base = if v != 0 || mac { v << 4 } else { PHY_BASE };
            return;
        }
        match self.fw_reg(mac, reg) {
            Some(a) if mac => self.mac_ocp_w(a, v as u16),
            Some(a) => self.phy_w(a, v as u16),
            None => {}
        }
    }

    fn fw_read(&self, mac: bool, reg: u32) -> u32 {
        if reg == 0x1f && !mac {
            return if self.ocp_base == PHY_BASE { 0 } else { self.ocp_base >> 4 };
        }
        match self.fw_reg(mac, reg) {
            Some(a) if mac => self.mac_ocp_r(a) as u32,
            Some(a) => self.phy_r(a) as u32,
            None => 0,
        }
    }

    /// Run a firmware program (rtl_fw_write_firmware); false if it does
    /// not end within FW_MAX_STEPS.
    fn fw_run(&mut self, code: &[u8]) -> bool {
        let word = |i: usize| u32::from_le_bytes([code[4 * i], code[4 * i + 1], code[4 * i + 2], code[4 * i + 3]]);
        let size = code.len() / 4;
        let (mut predata, mut count, mut mac) = (0u32, 0u32, false);
        let mut index = 0usize;
        for _ in 0..FW_MAX_STEPS {
            if index >= size {
                return true;
            }
            let action = word(index);
            let data = action & 0xffff;
            let regno = (action >> 16) & 0x0fff;
            match action >> 28 {
                0x0 => {
                    predata = self.fw_read(mac, regno);
                    count += 1;
                }
                0x1 => predata |= data,
                0x2 => predata &= data,
                // Checked: regno <= index.
                0x3 => index = index.wrapping_sub(regno as usize + 1),
                0x4 => mac = data != 0,
                0x7 => count = 0,
                0x8 => self.fw_write(mac, regno, data),
                0x9 if count == data => index += 1,
                0xa if predata == data => index += regno as usize,
                0xb if predata != data => index += regno as usize,
                0xc => self.fw_write(mac, regno, predata),
                0xd => index += regno as usize,
                0xe => self.udelay(data as u64 * 1000),
                _ => {}
            }
            index = index.wrapping_add(1);
        }
        false
    }

    // ---- receive

    fn rx_status(&self, i: usize) -> u32 {
        rd32(self.rx_ring + i * DESC)
    }

    /// Give descriptor `i` back to the chip (Linux rtl8169_mark_to_asic).
    fn post_rx(&mut self, i: usize) {
        let d = self.rx_ring + i * DESC;
        let eor = if i == RX_RING - 1 { RING_END } else { 0 };
        wr64(d + 8, self.rx_bufs[i].1);
        wr32(d + 4, 0);
        dma_fence(Ordering::Release);
        wr32(d, DESC_OWN | eor | RX_BUF as u32);
    }

    fn set_imr(&mut self, causes: u32, on: bool) {
        self.imr = if on { self.imr | causes } else { self.imr & !causes };
        self.regs.w32(IMR, self.imr);
    }

    pub fn rx_begin(&mut self) {
        self.set_imr(CAUSE_RX, false);
    }

    pub fn rx_done(&mut self) -> bool {
        // Statuses set by what was drained; one set later interrupts.
        self.regs.w32(ISR, CAUSE_RX);
        self.set_imr(CAUSE_RX, true);
        if self.rx_status(self.rx_next) & DESC_OWN == 0 {
            self.set_imr(CAUSE_RX, false);
            return false;
        }
        true
    }

    pub fn receive(&mut self, out: &mut [u8], hdr: &mut [u8; HDR]) -> Option<usize> {
        loop {
            let i = self.rx_next;
            let status = self.rx_status(i);
            if status & DESC_OWN != 0 {
                return None;
            }
            dma_fence(Ordering::Acquire);
            self.rx_next = (i + 1) % RX_RING;
            // A frame in several buffers (longer than the chip should take)
            // is dropped buffer by buffer, as Linux drops it.
            let whole = status & (FIRST_FRAG | LAST_FRAG) == FIRST_FRAG | LAST_FRAG;
            let len = ((status & RX_LEN) as usize).saturating_sub(FCS).min(RX_BUF);
            let n = (whole && status & RX_RES == 0 && len <= out.len()).then(|| {
                let data = unsafe { core::slice::from_raw_parts(self.rx_bufs[i].0 as *const u8, len) };
                out[..len].copy_from_slice(data);
                len
            });
            // Linux rtl8169_rx_csum: a TCP or UDP checksum the chip checked
            // and found good (and the IPv4 header's).
            let valid = matches!(status & (RX_PROTO_MASK | RX_CS_FAIL), RX_PROTO_TCP | RX_PROTO_UDP);
            self.post_rx(i);
            let Some(n) = n else { continue };
            *hdr = [0; HDR];
            if valid {
                hdr[0] = offload::F_DATA_VALID;
            }
            return Some(n);
        }
    }

    // ---- transmit

    fn tx_done(&self, slot: usize) -> bool {
        rd32(self.tx_ring + slot * DESC) & DESC_OWN == 0
    }

    fn reap_tx(&mut self) {
        let before = self.tx_cons;
        while self.tx_cons != self.tx_prod && self.tx_done(self.tx_cons % TX_RING) {
            self.tx_got = self.tx_end[self.tx_cons % TX_RING];
            self.tx_cons = self.tx_cons.wrapping_add(1);
        }
        // Linux rtl_tx: the chip may miss a doorbell rung too soon after
        // another; ring again while frames wait.
        if self.tx_cons != before && self.tx_cons != self.tx_prod {
            self.regs.w16(TX_POLL, 1);
        }
    }

    /// Room for `descs` frames of `bytes` (aligned) in all, the largest
    /// `largest`: the area may waste up to one frame where it wraps.
    fn tx_room(&self, descs: usize, bytes: usize, largest: usize) -> bool {
        TX_RING - self.tx_prod.wrapping_sub(self.tx_cons) >= descs
            && TX_AREA - self.tx_put.wrapping_sub(self.tx_got) >= bytes + largest
    }

    fn make_room(&mut self, descs: usize, bytes: usize, largest: usize) -> bool {
        if !self.tx_room(descs, bytes, largest) {
            self.reap_tx();
        }
        if !self.tx_room(descs, bytes, largest) {
            // Let the chip start on what is queued.
            self.kick_tx();
            return false;
        }
        true
    }

    pub fn tx_interrupts(&mut self, on: bool) -> bool {
        if on {
            self.regs.w32(ISR, CAUSE_TX);
        }
        self.set_imr(CAUSE_TX, on);
        self.tx_cons != self.tx_prod && self.tx_done(self.tx_cons % TX_RING)
    }

    /// Queue `frame`, padded with zeros to `len`, after `fix` changes its
    /// copy; the caller made room.
    fn post_tx(&mut self, frame: &[u8], len: usize, opts1: u32, opts2: u32, fix: impl FnOnce(&mut [u8])) {
        let take = len.next_multiple_of(TX_ALIGN);
        let at = self.tx_put % TX_AREA;
        if at + take > TX_AREA {
            self.tx_put = self.tx_put.wrapping_add(TX_AREA - at);
        }
        let off = self.tx_put % TX_AREA;
        self.tx_put = self.tx_put.wrapping_add(take);
        let buf = unsafe { core::slice::from_raw_parts_mut((self.tx_area.0 + off) as *mut u8, len) };
        buf[..frame.len()].copy_from_slice(frame);
        buf[frame.len()..].fill(0);
        fix(buf);
        let slot = self.tx_prod % TX_RING;
        let d = self.tx_ring + slot * DESC;
        let eor = if slot == TX_RING - 1 { RING_END } else { 0 };
        wr64(d + 8, self.tx_area.1 + off as u64);
        wr32(d + 4, opts2);
        dma_fence(Ordering::Release);
        wr32(d, DESC_OWN | FIRST_FRAG | LAST_FRAG | eor | opts1 | len as u32);
        self.tx_end[slot] = self.tx_put;
        self.tx_prod = self.tx_prod.wrapping_add(1);
        self.tx_kick = true;
    }

    /// The descriptor bits for a GSO frame the chip segments (Linux
    /// rtl8169_tso_csum_v2), and whether it is IPv6; None for one it does
    /// not take (802.1Q-tagged, ECN, headers past GTTCPHO_MAX).
    fn tso(frame: &[u8], hdr: &[u8; HDR]) -> Option<(u32, u32, bool)> {
        let get16 = |off: usize| u16::from_le_bytes([hdr[off], hdr[off + 1]]) as usize;
        let (ethertype, ip) = offload::ethertype(frame)?;
        let f = offload::parse_tcp(frame)?;
        let mss = get16(4);
        // ECN frames are segmented here: Linux gives r8169 no TSO_ECN, so
        // that CWR stays on the first segment alone.
        let v6 = match (ethertype, hdr[1]) {
            (0x0800, offload::GSO_TCPV4) => false,
            (0x86dd, offload::GSO_TCPV6) => true,
            _ => return None,
        };
        if ip != 14 || f.tcp != get16(6) || f.tcp > GTTCPHO_MAX || !(1..=TD_MSS_MAX).contains(&mss) || frame.len() > TSO_MAX {
            return None;
        }
        let opts1 = if v6 { TD_GTSENV6 } else { TD_GTSENV4 } | (f.tcp as u32) << GTTCPHO_SHIFT;
        Some((opts1, (mss as u32) << TD_MSS_SHIFT, v6))
    }

    pub fn transmit(&mut self, frame: &[u8], hdr: &[u8; HDR]) -> bool {
        if offload::is_gso(hdr) {
            if let Some((opts1, opts2, v6)) = Self::tso(frame, hdr) {
                let take = frame.len().next_multiple_of(TX_ALIGN);
                if !self.make_room(1, take, take) {
                    return false;
                }
                self.post_tx(frame, frame.len(), opts1, opts2, |b| {
                    if v6 {
                        // tcp_v6_gso_csum_prep: no payload length, and the
                        // pseudo-header sum without it.
                        let (ip, tcp) = (14, 14 + 40);
                        b[ip + 4..ip + 6].fill(0);
                        let s = csum_fold(csum_add(6, &b[ip + 8..ip + 40]));
                        b[tcp + 16..tcp + 18].copy_from_slice(&s.to_be_bytes());
                    }
                });
                return true;
            }
            // Segmented here: every segment, or none, while there is room.
            let Some(f) = offload::parse_tcp(frame) else { return true };
            let mss = (u16::from_le_bytes([hdr[4], hdr[5]]) as usize).max(1);
            let segs = (frame.len() - f.hdrs).div_ceil(mss).max(1);
            let take = (f.hdrs + mss).next_multiple_of(TX_ALIGN);
            // Within the offer a frame has 64 segments at most: one past
            // what the ring could ever take is dropped, not waited for.
            if f.hdrs + mss > SEG_BUF || segs > TX_RING / 2 {
                return true;
            }
            if !self.make_room(segs, segs * take, take) {
                return false;
            }
            let buf = unsafe { core::slice::from_raw_parts_mut(self.seg as *mut u8, SEG_BUF) };
            offload::segment(frame, hdr, buf, |s, _| {
                let len = s.len().max(pad_to(s));
                self.post_tx(s, len, 0, 0, |_| {});
            });
            return true;
        }
        // The offer's frame bound is the GSO one; a plain frame is at most
        // the MTU and a tag, as Linux sends it (no jumbo frames here).
        if frame.len() > TX_FRAME_MAX {
            return true;
        }
        let len = frame.len().max(pad_to(frame));
        let take = len.next_multiple_of(TX_ALIGN);
        if !self.make_room(1, take, take) {
            return false;
        }
        let mut h = *hdr;
        self.post_tx(frame, len, 0, 0, |b| offload::complete_csum(&mut b[..frame.len()], &mut h));
        true
    }

    pub fn kick_tx(&mut self) {
        if core::mem::take(&mut self.tx_kick) {
            dma_fence(Ordering::Release);
            self.regs.w16(TX_POLL, 1);
        }
    }

    pub fn stop(&mut self) {
        self.cleanup();
    }
}

// ---- PHY firmware files (Linux rtl_fw_format_ok, rtl_fw_data_ok)

/// The program in a firmware file: after its header (magic 0: checksum,
/// start and length), or the whole file.
fn fw_code(fw: &[u8]) -> Option<&[u8]> {
    const INFO: usize = 4 + 32 + 4 + 4 + 1;
    if fw.len() < 4 {
        return None;
    }
    let le32 = |o: usize| u32::from_le_bytes([fw[o], fw[o + 1], fw[o + 2], fw[o + 3]]) as usize;
    if le32(0) == 0 {
        if fw.len() < INFO || fw.iter().fold(0u8, |s, &b| s.wrapping_add(b)) != 0 {
            return None;
        }
        let (start, size) = (le32(36), le32(40));
        if start > fw.len() || size > (fw.len() - start) / 4 {
            return None;
        }
        Some(&fw[start..start + size * 4])
    } else {
        (fw.len() % 4 == 0).then_some(fw)
    }
}

/// Every action known and every jump inside the program.
fn fw_check(code: &[u8]) -> bool {
    let size = code.len() / 4;
    (0..size).all(|i| {
        let action = u32::from_le_bytes([code[4 * i], code[4 * i + 1], code[4 * i + 2], code[4 * i + 3]]);
        let (data, regno) = (action & 0xffff, ((action >> 16) & 0x0fff) as usize);
        match action >> 28 {
            0x0 | 0x1 | 0x2 | 0x7 | 0x8 | 0xc | 0xe => true,
            0x4 => data <= 1,
            0x3 => regno <= i,
            0x9 => i + 2 < size,
            0xa | 0xb | 0xd => i + 1 + regno < size,
            _ => false,
        }
    })
}

/// The SDK's view of the driver (l4h_nicdrv::NicDriver).
impl crate::sdk::NicDriver for R8125 {
    fn start(hw: &Hw) -> Result<Self, &'static str> {
        R8125::new(hw)
    }
    fn offer(&self) -> Offer {
        R8125::offer(self)
    }
    fn rx_begin(&mut self) {
        R8125::rx_begin(self)
    }
    fn rx_done(&mut self) -> bool {
        R8125::rx_done(self)
    }
    fn receive(&mut self, out: &mut [u8], hdr: &mut [u8; HDR]) -> Option<usize> {
        R8125::receive(self, out, hdr)
    }
    fn transmit(&mut self, frame: &[u8], hdr: &[u8; HDR]) -> bool {
        R8125::transmit(self, frame, hdr)
    }
    fn tx_interrupts(&mut self, on: bool) -> bool {
        R8125::tx_interrupts(self, on)
    }
    fn kick_tx(&mut self) {
        R8125::kick_tx(self)
    }
    fn link(&self) -> LinkState {
        self.link
    }
    fn timer(&mut self) {
        // A chip that fell off the bus reads all ones: root restarts the
        // driver, and so the device.
        if self.regs.r32(TX_CONFIG) == u32::MAX {
            panic!("r8125: the device does not answer");
        }
        self.link = self.read_link();
    }
    fn stop(&mut self) {
        R8125::stop(self)
    }
}

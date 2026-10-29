//! Intel X550 10GbE driver (Linux `ixgbe`), as on Latitude.sh m4.metal
//! servers: one RX and one TX queue with advanced descriptors, frames
//! copied between the switch and DMA buffers owned by this driver, as for
//! virtio-net.
//!
//! Registers are little-endian words in BAR 0.  The driver resets the MAC
//! (not the PHY: autonegotiation restarts with the settings the firmware
//! left), then sets up queue 0 in each direction.  The RX queue raises MSI-X entry 0 and
//! the TX queue entry 1; both entries carry netd's one vector for the NIC,
//! so the two causes are masked and unmasked separately (EIMS/EIMC bits 0
//! and 1) while sharing the interrupt.

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::Ordering;

use l4h_rt::host::fixed::ArrayVec;
use l4h_rt::host::{self, net::{self, NicConfig}};
use l4h_virtio::{Dma, Mmio, dma_fence};

use crate::offload;
use crate::pool::Frame;

const HDR: usize = net::HDR_SIZE;

// Registers (BAR 0).
const CTRL: usize = 0x00000;
const STATUS: usize = 0x00008;
const CTRL_EXT: usize = 0x00018;
const EICR: usize = 0x00800;
const EIAC: usize = 0x00810;
const EIMS: usize = 0x00880;
const EIMC: usize = 0x00888;
const GPIE: usize = 0x00898;
const IVAR0: usize = 0x00900;
const fn eitr(i: usize) -> usize {
    0x00820 + i * 4
}
const fn rdbal(i: usize) -> usize {
    0x01000 + i * 0x40
}
const fn rdbah(i: usize) -> usize {
    0x01004 + i * 0x40
}
const fn rdlen(i: usize) -> usize {
    0x01008 + i * 0x40
}
const fn rdh(i: usize) -> usize {
    0x01010 + i * 0x40
}
const fn rdt(i: usize) -> usize {
    0x01018 + i * 0x40
}
const fn rxdctl(i: usize) -> usize {
    0x01028 + i * 0x40
}
const fn srrctl(i: usize) -> usize {
    0x02100 + i * 4
}
const RDRXCTL: usize = 0x02F00;
const RXCTRL: usize = 0x03000;
const RSCDBU: usize = 0x03028;
const RXPBSIZE0: usize = 0x03C00;
const HLREG0: usize = 0x04240;
const MHADD: usize = 0x04268;
const LINKS: usize = 0x042A4;
const DMATXCTL: usize = 0x04A80;
const RFCTL: usize = 0x05008;
const FCTRL: usize = 0x05080;
const RAL0: usize = 0x05400;
const RAH0: usize = 0x05404;
const MRQC: usize = 0x05818;
const fn tdbal(i: usize) -> usize {
    0x06000 + i * 0x40
}
const fn tdbah(i: usize) -> usize {
    0x06004 + i * 0x40
}
const fn tdlen(i: usize) -> usize {
    0x06008 + i * 0x40
}
const fn tdh(i: usize) -> usize {
    0x06010 + i * 0x40
}
const fn tdt(i: usize) -> usize {
    0x06018 + i * 0x40
}
const fn txdctl(i: usize) -> usize {
    0x06028 + i * 0x40
}
const SWSM: usize = 0x10140;
const SWFW_SYNC: usize = 0x10160;

const CTRL_GIO_DIS: u32 = 1 << 2;
const CTRL_LNK_RST: u32 = 1 << 3;
const CTRL_RST: u32 = 1 << 26;
const STATUS_GIO: u32 = 1 << 19;
const CTRL_EXT_NS_DIS: u32 = 1 << 16;
const CTRL_EXT_DRV_LOAD: u32 = 1 << 28;
const GPIE_MSIX_MODE: u32 = 1 << 4;
const GPIE_OCD: u32 = 1 << 5;
const GPIE_PBA_SUPPORT: u32 = 1 << 31;
const IVAR_VALID: u32 = 0x80;
const EITR_CNT_WDIS: u32 = 1 << 31;
const RXDCTL_ENABLE: u32 = 1 << 25;
const RXDCTL_SWFLSH: u32 = 1 << 26;
const TXDCTL_ENABLE: u32 = 1 << 25;
const TXDCTL_SWFLSH: u32 = 1 << 26;
const SRRCTL_DESCTYPE_ADV_ONEBUF: u32 = 1 << 25;
const SRRCTL_DROP_EN: u32 = 1 << 28;
const RDRXCTL_CRCSTRIP: u32 = 1 << 1;
const RDRXCTL_DMAIDONE: u32 = 1 << 3;
const RDRXCTL_RSCFRSTSIZE: u32 = 0x1f << 17;
const RDRXCTL_RSCACKC: u32 = 1 << 25;
const RDRXCTL_FCOE_WRFIX: u32 = 1 << 26;
const RSCDBU_RSCACKDIS: u32 = 1 << 7;
const RXCTRL_RXEN: u32 = 1 << 0;
const HLREG0_TXCRCEN: u32 = 1 << 0;
const HLREG0_RXCRCSTRP: u32 = 1 << 1;
const HLREG0_JUMBOEN: u32 = 1 << 2;
const HLREG0_TXPADEN: u32 = 1 << 10;
const HLREG0_LPBK: u32 = 1 << 15;
const LINKS_UP: u32 = 1 << 30;
const DMATXCTL_TE: u32 = 1 << 0;
const RFCTL_RSC_DIS: u32 = 1 << 5;
const RFCTL_NFSW_DIS: u32 = 1 << 6;
const RFCTL_NFSR_DIS: u32 = 1 << 7;
const FCTRL_MPE: u32 = 1 << 8;
const FCTRL_UPE: u32 = 1 << 9;
const FCTRL_BAM: u32 = 1 << 10;
const RAH_AV: u32 = 1 << 31;
const SWSM_SMBI: u32 = 1 << 0;
const SWFW_REGSMP: u32 = 1 << 31;
/// PHY semaphores of LAN functions 0 and 1 (GSSR).
const GSSR_PHY0_SM: u32 = 1 << 1;

/// Interrupt causes (EICR bits, MSI-X entries in MSI-X mode).
const CAUSE_RX: u32 = 1 << 0;
const CAUSE_TX: u32 = 1 << 1;
/// Interrupt moderation, as Linux's default: about 20,000 per second
/// (EITR interval in 2 µs units, bits 11:3).
const ITR: u32 = 200;

// RX descriptors (advanced, one buffer).
const RX_DESC: usize = 16;
const RX_BUF: usize = 2048;
const RX_BUFS: usize = 512;
const RXD_STAT_DD: u32 = 1 << 0;
const RXD_STAT_EOP: u32 = 1 << 1;
const RXD_STAT_L4CS: u32 = 1 << 5;
const RXD_STAT_IPCS: u32 = 1 << 6;
/// CRC, length, packet, oversize and undersize errors.
const RXD_ERR_FRAME: u32 = 0x3B00_0000;
const RXD_ERR_TCPE: u32 = 1 << 30;
const RXD_ERR_IPE: u32 = 1 << 31;

// TX descriptors (advanced data and context descriptors).
const TX_DESC: usize = 16;
const TX_RING: usize = 256;
const TX_BUFS: usize = 24;
const TX_BUF: usize = net::MAX_FRAME;
/// Bytes per data descriptor (IXGBE_MAX_DATA_PER_TXD).
const TX_MAX_DATA: usize = 16 * 1024;
const TXD_DTYP_DATA: u32 = 0x3 << 20;
const TXD_DTYP_CTXT: u32 = 0x2 << 20;
const TXD_CMD_EOP: u32 = 1 << 24;
const TXD_CMD_IFCS: u32 = 1 << 25;
const TXD_CMD_RS: u32 = 1 << 27;
const TXD_CMD_DEXT: u32 = 1 << 29;
const TXD_CMD_TSE: u32 = 1 << 31;
const TXD_STAT_DD: u32 = 1 << 0;
const TXD_POPTS_IXSM: u32 = 1 << 8;
const TXD_POPTS_TXSM: u32 = 1 << 9;
const TXD_PAYLEN_SHIFT: u32 = 14;
const TXD_MACLEN_SHIFT: u32 = 9;
const TUCMD_IPV4: u32 = 1 << 10;
const TUCMD_L4T_TCP: u32 = 1 << 11;
/// Checksum and TCP segmentation offload.
const TX_OFFLOADS: bool = true;
const TSO_MIN_MSS: usize = 64;
const TSO_MAX_MSS: usize = 9216;
/// MACLEN has 7 bits and L4LEN 8.
const TSO_MAX_HDR: usize = 127 + 60 + 255;

fn rd32(va: usize) -> u32 {
    unsafe { read_volatile(va as *const u32) }
}
fn rd16(va: usize) -> u16 {
    unsafe { read_volatile(va as *const u16) }
}
fn wr64(va: usize, v: u64) {
    unsafe { write_volatile(va as *mut u64, v) }
}

pub struct Ixgbe {
    pub mac: [u8; 6],
    pub csum: bool,
    pub tso: bool,
    regs: Mmio,
    n: usize,
    tsc_hz: u64,

    rx_ring: usize,
    rx_bufs: [(usize, u64); RX_BUFS],
    /// Next descriptor the device completes.
    rx_next: usize,
    /// Descriptors given back since the last tail write.
    rx_kick: bool,
    /// Pieces of a frame that spans several buffers.
    rx_partial: &'static mut ArrayVec<u8, { net::MAX_FRAME }>,
    rx_partial_bad: bool,

    tx_ring: usize,
    tx_tail: usize,
    /// First descriptor not yet known to be done.
    tx_clean: usize,
    tx_bufs: [(usize, u64); TX_BUFS],
    tx_free: ArrayVec<u16, TX_BUFS>,
    /// Packets in flight, oldest first: (last descriptor, buffer).
    tx_sent: ArrayVec<(usize, u16), TX_BUFS>,
    tx_kick: bool,
}

fn wait_us(us: u64, tsc_hz: u64) {
    let end = host::ticks::now() + us * tsc_hz / 1_000_000;
    while host::ticks::now() < end {
        core::hint::spin_loop();
    }
}

fn poll(regs: &Mmio, reg: usize, mask: u32, want: u32, ms: u64, tsc_hz: u64) -> bool {
    for _ in 0..ms * 10 {
        if regs.r32(reg) & mask == want {
            return true;
        }
        wait_us(100, tsc_hz);
    }
    regs.r32(reg) & mask == want
}

/// Stop and reset an X550, returning its MAC address. `handoff` leaves the
/// port unowned by a driver until the next host starts netd.
fn reset(n: usize, regs: Mmio, tsc_hz: u64, handoff: bool) -> Option<[u8; 6]> {
    regs.w32(EIMC, 0x7fff_ffff);
    regs.r32(EICR);
    regs.w32(RXCTRL, regs.r32(RXCTRL) & !RXCTRL_RXEN);
    for q in 0..128 {
        regs.w32(txdctl(q), TXDCTL_SWFLSH);
        regs.w32(rxdctl(q), (regs.r32(rxdctl(q)) & !RXDCTL_ENABLE) | RXDCTL_SWFLSH);
    }
    wait_us(2000, tsc_hz);
    regs.w32(CTRL, regs.r32(CTRL) | CTRL_GIO_DIS);
    if !poll(&regs, STATUS, STATUS_GIO, 0, 100, tsc_hz) {
        l4h_rt::info!("netd: NIC {}: GIO primary still enabled; resetting anyway", n);
    }
    let lan = (regs.r32(STATUS) >> 2) & 3;
    let phy_sm = GSSR_PHY0_SM << lan.min(1);
    let held = swfw_acquire(&regs, phy_sm, &|us| wait_us(us, tsc_hz));
    regs.w32(CTRL, regs.r32(CTRL) | CTRL_RST);
    regs.r32(STATUS);
    if held {
        swfw_release(&regs, phy_sm, &|us| wait_us(us, tsc_hz));
    }
    wait_us(1000, tsc_hz);
    if !poll(&regs, CTRL, CTRL_RST | CTRL_LNK_RST, 0, 10, tsc_hz) {
        l4h_rt::info!("netd: NIC {}: reset does not complete", n);
        return None;
    }
    wait_us(100_000, tsc_hz);
    if !poll(&regs, RDRXCTL, RDRXCTL_DMAIDONE, RDRXCTL_DMAIDONE, 100, tsc_hz) {
        l4h_rt::info!("netd: NIC {}: DMA init not done after reset", n);
    }
    regs.w32(EIMC, 0x7fff_ffff);
    regs.r32(EICR);
    regs.w32(RXPBSIZE0, 384 << 10);
    let (ral, rah) = (regs.r32(RAL0), regs.r32(RAH0));
    let mac = [ral as u8, (ral >> 8) as u8, (ral >> 16) as u8, (ral >> 24) as u8, rah as u8, (rah >> 8) as u8];
    regs.w32(RAH0, (rah & 0xffff) | RAH_AV);
    let ctrl_ext = regs.r32(CTRL_EXT) | CTRL_EXT_NS_DIS;
    regs.w32(CTRL_EXT, if handoff { ctrl_ext & !CTRL_EXT_DRV_LOAD } else { ctrl_ext | CTRL_EXT_DRV_LOAD });
    Some(mac)
}

impl Ixgbe {
    pub fn new(n: usize, c: &NicConfig, tsc_hz: u64, rx_partial: &'static mut ArrayVec<u8, { net::MAX_FRAME }>) -> Self {
        let regs = Mmio(c.regs.va as usize);
        let mac = reset(n, regs, tsc_hz, false).expect("netd: X550 reset");
        let mut dma = Dma::new(net::nic_dma_va(n), c.dma_paddr, c.dma_size as usize);

        // Receive: CRC stripped, frames up to MAX_FRAME accepted (they span
        // buffers), no RSC, RSS or NFS filtering.
        regs.w32(HLREG0, (regs.r32(HLREG0) | HLREG0_TXCRCEN | HLREG0_RXCRCSTRP | HLREG0_JUMBOEN | HLREG0_TXPADEN) & !HLREG0_LPBK);
        regs.w32(MHADD, (regs.r32(MHADD) & 0xffff) | ((net::MTU_FRAME as u32 + 4 + 4) << 16));
        let rdrxctl = regs.r32(RDRXCTL) & !RDRXCTL_RSCFRSTSIZE;
        regs.w32(RDRXCTL, rdrxctl | RDRXCTL_CRCSTRIP | RDRXCTL_RSCACKC | RDRXCTL_FCOE_WRFIX);
        regs.w32(RSCDBU, regs.r32(RSCDBU) | RSCDBU_RSCACKDIS);
        regs.w32(RFCTL, regs.r32(RFCTL) | RFCTL_RSC_DIS | RFCTL_NFSW_DIS | RFCTL_NFSR_DIS);
        regs.w32(MRQC, 0);

        let (rx_ring, rx_ring_pa) = dma.alloc(RX_BUFS * RX_DESC, 4096);
        let rx_bufs: [_; RX_BUFS] = core::array::from_fn(|_| dma.alloc(RX_BUF, 128));
        for (i, &(_, pa)) in rx_bufs.iter().enumerate() {
            wr64(rx_ring + i * RX_DESC, pa);
            wr64(rx_ring + i * RX_DESC + 8, 0);
        }
        regs.w32(rxdctl(0), 0);
        regs.w32(rdbal(0), rx_ring_pa as u32);
        regs.w32(rdbah(0), (rx_ring_pa >> 32) as u32);
        regs.w32(rdlen(0), (RX_BUFS * RX_DESC) as u32);
        regs.w32(rdh(0), 0);
        regs.w32(rdt(0), 0);
        regs.w32(srrctl(0), (RX_BUF >> 10) as u32 | SRRCTL_DESCTYPE_ADV_ONEBUF | SRRCTL_DROP_EN);
        regs.w32(rxdctl(0), RXDCTL_ENABLE);
        if !poll(&regs, rxdctl(0), RXDCTL_ENABLE, RXDCTL_ENABLE, 10, tsc_hz) {
            panic!("netd: NIC {}: RX queue does not enable", n);
        }
        dma_fence(Ordering::Release);
        // All buffers but one: head == tail means empty.
        regs.w32(rdt(0), (RX_BUFS - 1) as u32);
        // Every frame: the switch decides (netd's other uplinks behave so).
        regs.w32(FCTRL, regs.r32(FCTRL) | FCTRL_BAM | FCTRL_MPE | FCTRL_UPE);
        regs.w32(RXCTRL, regs.r32(RXCTRL) | RXCTRL_RXEN);

        // Transmit: the DMA engine before the queue (82599 and later).
        let (tx_ring, tx_ring_pa) = dma.alloc(TX_RING * TX_DESC, 4096);
        let tx_bufs: [_; TX_BUFS] = core::array::from_fn(|_| dma.alloc(TX_BUF, 128));
        regs.w32(DMATXCTL, regs.r32(DMATXCTL) | DMATXCTL_TE);
        regs.w32(txdctl(0), 0);
        regs.w32(tdbal(0), tx_ring_pa as u32);
        regs.w32(tdbah(0), (tx_ring_pa >> 32) as u32);
        regs.w32(tdlen(0), (TX_RING * TX_DESC) as u32);
        regs.w32(tdh(0), 0);
        regs.w32(tdt(0), 0);
        // WTHRESH 1, HTHRESH 1, PTHRESH 32, as Linux.
        regs.w32(txdctl(0), TXDCTL_ENABLE | 1 << 16 | 1 << 8 | 32);
        if !poll(&regs, txdctl(0), TXDCTL_ENABLE, TXDCTL_ENABLE, 10, tsc_hz) {
            panic!("netd: NIC {}: TX queue does not enable", n);
        }

        // Interrupts: MSI-X entries 0 (RX) and 1 (TX), both netd's vector.
        let msix = Mmio(c.msix_table.va as usize);
        for e in 0..2 {
            msix.w32(e * 16, c.msi_address as u32);
            msix.w32(e * 16 + 4, (c.msi_address >> 32) as u32);
            msix.w32(e * 16 + 8, c.msi_data);
            msix.w32(e * 16 + 12, 0);
        }
        regs.w32(GPIE, GPIE_MSIX_MODE | GPIE_OCD | GPIE_PBA_SUPPORT);
        // IVAR 0: RX queue 0 (bits 7:0) on entry 0, TX queue 0 (15:8) on 1.
        regs.w32(IVAR0, IVAR_VALID | (IVAR_VALID | 1) << 8);
        regs.w32(eitr(0), ITR | EITR_CNT_WDIS);
        regs.w32(eitr(1), ITR | EITR_CNT_WDIS);
        // Causes clear themselves when their message is sent.
        regs.w32(EIAC, CAUSE_RX | CAUSE_TX);
        regs.w32(EIMS, CAUSE_RX);

        // The MAC reset restarts autonegotiation, which takes a few seconds
        // on 10GBASE-T.
        let up = poll(&regs, LINKS, LINKS_UP, LINKS_UP, 15_000, tsc_hz);
        let links = regs.r32(LINKS);
        let speed = match (links >> 28) & 3 {
            3 => "10G",
            2 => "1G",
            1 => "100M",
            _ => "?",
        };
        l4h_rt::info!(
            "netd: NIC {}: {:02x}:{:02x}.{} X550, mac {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, link {} {}",
            n, c.pci_bdf >> 8, (c.pci_bdf >> 3) & 0x1f, c.pci_bdf & 7,
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
            if up { "up" } else { "down" }, speed,
        );

        Ixgbe {
            mac,
            n,
            tsc_hz,
            csum: TX_OFFLOADS,
            tso: TX_OFFLOADS,
            regs,
            rx_ring,
            rx_bufs,
            rx_next: 0,
            rx_kick: false,
            rx_partial,
            rx_partial_bad: false,
            tx_ring,
            tx_tail: 0,
            tx_clean: 0,
            tx_bufs,
            tx_free: {
                let mut f = ArrayVec::new();
                for i in (0..TX_BUFS as u16).rev() {
                    let _ = f.push(i);
                }
                f
            },
            tx_sent: ArrayVec::new(),
            tx_kick: false,
        }
    }

    pub fn reset(&mut self) -> bool {
        reset(self.n, self.regs, self.tsc_hz, true).is_some()
    }

    // ---- receive

    fn rx_status(&self, i: usize) -> u32 {
        rd32(self.rx_ring + i * RX_DESC + 8)
    }

    pub fn rx_begin(&mut self) {
        self.regs.w32(EIMC, CAUSE_RX);
    }

    pub fn rx_done(&mut self) -> bool {
        if core::mem::take(&mut self.rx_kick) {
            dma_fence(Ordering::Release);
            // The descriptor before the next one to complete is the last
            // the device may fill.
            self.regs.w32(rdt(0), ((self.rx_next + RX_BUFS - 1) % RX_BUFS) as u32);
        }
        self.regs.w32(EIMS, CAUSE_RX);
        if self.rx_status(self.rx_next) & RXD_STAT_DD != 0 {
            self.regs.w32(EIMC, CAUSE_RX);
            return false;
        }
        true
    }

    /// Give descriptor `i`'s buffer back to the device (after the tail
    /// write in rx_done).
    fn post_rx(&mut self, i: usize) {
        let d = self.rx_ring + i * RX_DESC;
        wr64(d, self.rx_bufs[i].1);
        wr64(d + 8, 0);
        self.rx_kick = true;
    }

    pub fn receive(&mut self, out: &mut [u8], hdr: &mut [u8; HDR]) -> Option<usize> {
        loop {
            let i = self.rx_next;
            let status = self.rx_status(i);
            if status & RXD_STAT_DD == 0 {
                return None;
            }
            dma_fence(Ordering::Acquire);
            let d = self.rx_ring + i * RX_DESC;
            let len = (rd16(d + 12) as usize).min(RX_BUF);
            let eop = status & RXD_STAT_EOP != 0;
            let error = status & RXD_ERR_FRAME != 0;
            let data = unsafe { core::slice::from_raw_parts(self.rx_bufs[i].0 as *const u8, len) };
            self.rx_next = (i + 1) % RX_BUFS;
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
            // The device checked the L4 (TCP or UDP) checksum, and the IPv4
            // header checksum if there is one (Linux ixgbe_rx_checksum).
            let valid = n.is_some()
                && status & RXD_STAT_L4CS != 0
                && status & RXD_ERR_TCPE == 0
                && !(status & RXD_STAT_IPCS != 0 && status & RXD_ERR_IPE != 0);
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

    /// Whether the device can segment this GSO frame.
    pub fn takes_gso(&self, hdr: &[u8; HDR]) -> bool {
        let get16 = |off: usize| u16::from_le_bytes([hdr[off], hdr[off + 1]]) as usize;
        self.tso && (TSO_MIN_MSS..=TSO_MAX_MSS).contains(&get16(4)) && get16(2) <= TSO_MAX_HDR
    }

    fn reap_tx(&mut self) {
        while let Some(&(last, buf)) = self.tx_sent.first() {
            if rd32(self.tx_ring + last * TX_DESC + 12) & TXD_STAT_DD == 0 {
                break;
            }
            self.tx_sent.remove(0);
            let _ = self.tx_free.push(buf);
            self.tx_clean = (last + 1) % TX_RING;
        }
    }

    fn tx_room(&self) -> usize {
        TX_RING - 1 - (self.tx_tail + TX_RING - self.tx_clean) % TX_RING
    }

    pub fn tx_interrupts(&mut self, on: bool) -> bool {
        self.regs.w32(if on { EIMS } else { EIMC }, CAUSE_TX);
        self.tx_sent.first().is_some_and(|&(last, _)| rd32(self.tx_ring + last * TX_DESC + 12) & TXD_STAT_DD != 0)
    }

    fn put_desc(&mut self, lo: u64, hi: u64) {
        let va = self.tx_ring + self.tx_tail * TX_DESC;
        wr64(va, lo);
        wr64(va + 8, hi);
        self.tx_tail = (self.tx_tail + 1) % TX_RING;
    }

    /// The context descriptor for a frame's checksum or segmentation
    /// offload, and the data descriptors' POPTS; None for offloads the
    /// device cannot do (netd's software paths handle those).
    fn offload(&self, buf: &mut [u8], hdr: &[u8; HDR]) -> Option<(u64, u64, u32, usize)> {
        let get16 = |off: usize| u16::from_le_bytes([hdr[off], hdr[off + 1]]) as usize;
        let (start, off) = (get16(6), get16(8));
        let (ethertype, ip) = offload::ethertype(buf)?;
        let v4 = match ethertype {
            0x0800 => true,
            0x86dd => false,
            _ => return None,
        };
        let iplen = start.checked_sub(ip).filter(|&l| (20..512).contains(&l))?;
        let mut tucmd = if v4 { TUCMD_IPV4 } else { 0 };
        let mut popts = TXD_POPTS_TXSM;
        let mut mss_l4len = 0;
        let mut hdr_len = 0;
        if offload::is_gso(hdr) {
            // TCP: the device fills in each segment's IP length and
            // checksum, and wants the TCP pseudo-header checksum without
            // the length (Linux ixgbe_tso).
            let f = offload::parse_tcp(buf).filter(|f| f.tcp == start && f.ip == ip)?;
            let (mss, l4len) = (get16(4), f.hdrs - f.tcp);
            let paylen = (buf.len() - f.tcp) as u32;
            let c = f.tcp + 16;
            let old = u16::from_be_bytes([buf[c], buf[c + 1]]) as u32;
            let mut sum = (!old & 0xffff) + (paylen >> 16) + (paylen & 0xffff);
            sum = (sum & 0xffff) + (sum >> 16);
            sum = (sum & 0xffff) + (sum >> 16);
            buf[c..c + 2].copy_from_slice(&(!sum as u16).to_be_bytes());
            if v4 {
                buf[ip + 2..ip + 4].fill(0);
                buf[ip + 10..ip + 12].fill(0);
                popts |= TXD_POPTS_IXSM;
            } else {
                buf[ip + 4..ip + 6].fill(0);
            }
            tucmd |= TUCMD_L4T_TCP;
            mss_l4len = (mss as u32) << 16 | (l4len as u32) << 8;
            hdr_len = f.hdrs;
        } else {
            match off {
                16 => tucmd |= TUCMD_L4T_TCP,
                6 => {}
                _ => return None,
            }
        }
        let macip = iplen as u32 | (ip as u32) << TXD_MACLEN_SHIFT;
        let ctx_hi = (TXD_CMD_DEXT | TXD_DTYP_CTXT | tucmd) as u64 | (mss_l4len as u64) << 32;
        Some((macip as u64, ctx_hi, popts, hdr_len))
    }

    pub fn transmit(&mut self, frame: &(impl Frame + ?Sized), hdr: &[u8; HDR]) -> bool {
        let need = 1 + frame.len().div_ceil(TX_MAX_DATA);
        if self.tx_free.is_empty() || self.tx_room() < need {
            self.reap_tx();
        }
        if self.tx_free.is_empty() || self.tx_room() < need {
            // Let the device start on what is queued.
            self.kick_tx();
            return false;
        }
        let tag = self.tx_free.pop().unwrap();
        let (va, pa) = self.tx_bufs[tag as usize];
        let buf = unsafe { core::slice::from_raw_parts_mut(va as *mut u8, frame.len()) };
        frame.copy_to(buf);
        let mut popts = 0;
        let mut paylen = frame.len();
        let mut tse = 0;
        let wants = self.csum && (hdr[0] & offload::F_NEEDS_CSUM != 0 || offload::is_gso(hdr));
        if wants {
            match self.offload(buf, hdr) {
                Some((lo, hi, p, hdr_len)) => {
                    self.put_desc(lo, hi);
                    popts = p;
                    if hdr_len != 0 {
                        paylen -= hdr_len;
                        tse = TXD_CMD_TSE;
                    }
                }
                None => {
                    // Only NEEDS_CSUM frames come here (netd segments GSO
                    // frames this device declines): finish in software.
                    let mut h = *hdr;
                    offload::complete_csum(buf, &mut h);
                }
            }
        }
        let olinfo = (paylen as u32) << TXD_PAYLEN_SHIFT | popts;
        let mut off = 0;
        while off < frame.len() {
            let len = (frame.len() - off).min(TX_MAX_DATA);
            let last = off + len == frame.len();
            let cmd = TXD_DTYP_DATA | TXD_CMD_DEXT | TXD_CMD_IFCS | tse | len as u32
                | if last { TXD_CMD_EOP | TXD_CMD_RS } else { 0 };
            self.put_desc(pa + off as u64, cmd as u64 | (olinfo as u64) << 32);
            off += len;
        }
        // One entry per buffer in flight: there is room.
        let _ = self.tx_sent.push(((self.tx_tail + TX_RING - 1) % TX_RING, tag));
        self.tx_kick = true;
        true
    }

    pub fn kick_tx(&mut self) {
        if core::mem::take(&mut self.tx_kick) {
            dma_fence(Ordering::Release);
            self.regs.w32(tdt(0), self.tx_tail as u32);
        }
    }
}

/// Take the SW/FW semaphore for `mask` (Linux acquire_swfw_sync_X540,
/// without its recovery of a semaphore other software left held).
fn swfw_acquire(regs: &Mmio, mask: u32, wait_us: &impl Fn(u64)) -> bool {
    for _ in 0..200 {
        if !swsm_acquire(regs, wait_us) {
            return false;
        }
        let sync = regs.r32(SWFW_SYNC);
        if sync & (mask | mask << 5) == 0 {
            regs.w32(SWFW_SYNC, sync | mask);
            swsm_release(regs);
            return true;
        }
        swsm_release(regs);
        wait_us(5000);
    }
    false
}

fn swfw_release(regs: &Mmio, mask: u32, wait_us: &impl Fn(u64)) {
    if swsm_acquire(regs, wait_us) {
        regs.w32(SWFW_SYNC, regs.r32(SWFW_SYNC) & !mask);
        swsm_release(regs);
    }
}

fn swsm_acquire(regs: &Mmio, wait_us: &impl Fn(u64)) -> bool {
    let mut ok = false;
    for _ in 0..2000 {
        // Reading SMBI as 0 sets it: the semaphore is ours.
        if regs.r32(SWSM) & SWSM_SMBI == 0 {
            ok = true;
            break;
        }
        wait_us(50);
    }
    if !ok {
        return false;
    }
    for _ in 0..2000 {
        if regs.r32(SWFW_SYNC) & SWFW_REGSMP == 0 {
            return true;
        }
        wait_us(50);
    }
    swsm_release(regs);
    false
}

fn swsm_release(regs: &Mmio) {
    regs.w32(SWFW_SYNC, regs.r32(SWFW_SYNC) & !SWFW_REGSMP);
    regs.w32(SWSM, regs.r32(SWSM) & !SWSM_SMBI);
}

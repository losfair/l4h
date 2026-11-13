//! Intel 82574L / 82583V gigabit driver (Linux `e1000e`), as QEMU's
//! `e1000e` device: one RX and one TX queue with legacy descriptors,
//! frames copied between the switch and DMA buffers owned by this driver,
//! as for virtio-net.
//!
//! Registers are little-endian words in BAR 0; the MSI-X table is in
//! BAR 3, which root maps for it.  The driver resets the MAC (not the PHY,
//! which keeps the link it negotiated), then sets up queue 0 in each
//! direction.  The RX queue raises MSI-X entry 0 and the TX queue entry 1;
//! both entries carry the driver's one vector for the NIC, so the two causes
//! are masked and unmasked separately (IMS/IMC bits RXQ0 and TXQ0) while
//! sharing the interrupt.  The link is read on root's tick (F_TIMER).
//!
//! The older 8254x parts (QEMU's `e1000`, 82540EM) have no MSI-X and are
//! not driven: a nicd takes MSI-X only.

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::Ordering;

use l4h_rt::host::fixed::ArrayVec;
use l4h_rt::host::{self, net};
use crate::sdk::{Hw, LinkState, Offer};
use l4h_virtio::{Mmio, dma_fence};

use crate::sdk::offload;

/// What the driver drives and needs (l4h_host::nicd::Manifest).
pub const MANIFEST: crate::sdk::Manifest = crate::sdk::Manifest {
    bars: 1 << 0,
    msix_min: 3,
    dma_bits: 22,
    flags: crate::sdk::nicd::F_TIMER,
    // 82574L, 82583V.
    ..crate::sdk::Manifest::empty().with_name("e1000e").with_matches(&[crate::sdk::PciMatch::id(0x8086, 0x10d3), crate::sdk::PciMatch::id(0x8086, 0x150c)])
};

const HDR: usize = net::HDR_SIZE;

// Registers (BAR 0).
const CTRL: usize = 0x00000;
const STATUS: usize = 0x00008;
const EECD: usize = 0x00010;
const CTRL_EXT: usize = 0x00018;
const ICR: usize = 0x000C0;
const ITR: usize = 0x000C4;
const IMS: usize = 0x000D0;
const IMC: usize = 0x000D8;
const EIAC: usize = 0x000DC;
const IAM: usize = 0x000E0;
const IVAR: usize = 0x000E4;
const fn eitr(i: usize) -> usize {
    0x000E8 + i * 4
}
const RCTL: usize = 0x00100;
const TCTL: usize = 0x00400;
const TIPG: usize = 0x00410;
const EXTCNF_CTRL: usize = 0x00F00;
const RDBAL: usize = 0x02800;
const RDBAH: usize = 0x02804;
const RDLEN: usize = 0x02808;
const RDH: usize = 0x02810;
const RDT: usize = 0x02818;
const RDTR: usize = 0x02820;
const RADV: usize = 0x0282C;
const TDBAL: usize = 0x03800;
const TDBAH: usize = 0x03804;
const TDLEN: usize = 0x03808;
const TDH: usize = 0x03810;
const TDT: usize = 0x03818;
const TXDCTL: usize = 0x03828;
const RXCSUM: usize = 0x05000;
const RFCTL: usize = 0x05008;
const RAL0: usize = 0x05400;
const RAH0: usize = 0x05404;

const CTRL_GIO_DIS: u32 = 1 << 2;
const CTRL_SLU: u32 = 1 << 6;
const CTRL_FRCSPD: u32 = 1 << 11;
const CTRL_FRCDPX: u32 = 1 << 12;
const CTRL_RST: u32 = 1 << 26;
const STATUS_LU: u32 = 1 << 1;
const STATUS_GIO: u32 = 1 << 19;
const EECD_AUTO_RD: u32 = 1 << 9;
const CTRL_EXT_EIAME: u32 = 1 << 24;
const CTRL_EXT_DRV_LOAD: u32 = 1 << 28;
const CTRL_EXT_PBA_CLR: u32 = 1 << 31;
const EXTCNF_SWFLAG: u32 = 1 << 5;
const IVAR_VALID: u32 = 0x8;
const RCTL_EN: u32 = 1 << 1;
const RCTL_UPE: u32 = 1 << 3;
const RCTL_MPE: u32 = 1 << 4;
const RCTL_BAM: u32 = 1 << 15;
const RCTL_SECRC: u32 = 1 << 26;
const TCTL_EN: u32 = 1 << 1;
const TCTL_PSP: u32 = 1 << 3;
const TCTL_CT: u32 = 0xf << 4;
const TCTL_COLD: u32 = 0x3f << 12;
const TCTL_RTLC: u32 = 1 << 24;
/// IPGT 8, IPGR1 8, IPGR2 6: Linux's copper defaults.
const TIPG_COPPER: u32 = 8 | 8 << 10 | 6 << 20;
/// Descriptor granularity, WTHRESH 1 and the 82574's must-be-one bit 22
/// (Linux E1000_TXDCTL_FULL_TX_DESC_WB | E1000_TXDCTL_COUNT_DESC).
const TXDCTL_WB: u32 = 0x0141_0000;
const RXCSUM_IPOFL: u32 = 1 << 8;
const RXCSUM_TUOFL: u32 = 1 << 9;
const RFCTL_EXTEN: u32 = 1 << 15;
const RAH_AV: u32 = 1 << 31;

/// Interrupt causes (ICR/IMS bits in MSI-X mode).
const CAUSE_RX: u32 = 1 << 20;
const CAUSE_TX: u32 = 1 << 22;
/// Interrupt moderation, as Linux's default: about 20,000 per second
/// (ITR/EITR interval in 256 ns units).
const ITR_VAL: u32 = 195;

// RX descriptors (legacy): buffer address, then length, checksum,
// status, errors and VLAN tag.  Frames of the standard MTU (no long
// packets: RCTL.LPE clear) fit in one buffer.
const RX_DESC: usize = 16;
const RX_BUF: usize = 2048;
const RX_BUFS: usize = 512;
const RXD_STAT_DD: u32 = 1 << 0;
const RXD_STAT_EOP: u32 = 1 << 1;
const RXD_STAT_TCPCS: u32 = 1 << 5;
const RXD_STAT_IPCS: u32 = 1 << 6;
/// CRC, symbol, sequence, carrier extension and RX data errors (shifted
/// into the status word).
const RXD_ERR_FRAME: u32 = 0x97 << 8;
const RXD_ERR_TCPE: u32 = 1 << 13;
const RXD_ERR_IPE: u32 = 1 << 14;

// TX descriptors (extended data and context descriptors).
const TX_DESC: usize = 16;
const TX_RING: usize = 256;
const TX_BUFS: usize = 24;
const TX_BUF: usize = net::MAX_FRAME;
/// Bytes per data descriptor (Linux E1000_MAX_PER_TXD).
const TX_MAX_DATA: usize = 8 * 1024;
const TXD_DTYP_DATA: u32 = 1 << 20;
const TXD_CMD_EOP: u32 = 1 << 24;
const TXD_CMD_IFCS: u32 = 1 << 25;
const TXD_CMD_TCP: u32 = 1 << 24;
const TXD_CMD_IP: u32 = 1 << 25;
const TXD_CMD_TSE: u32 = 1 << 26;
const TXD_CMD_RS: u32 = 1 << 27;
const TXD_CMD_DEXT: u32 = 1 << 29;
const TXD_STAT_DD: u32 = 1 << 0;
const TXD_POPTS_IXSM: u32 = 1 << 8;
const TXD_POPTS_TXSM: u32 = 1 << 9;
/// Checksum and TCP segmentation offload.
const TX_OFFLOADS: bool = true;
const TSO_MIN_MSS: usize = 64;
const TSO_MAX_MSS: usize = 9000;
/// The context descriptor's offsets and HDRLEN have 8 bits.
const TSO_MAX_HDR: usize = 255;

fn rd32(va: usize) -> u32 {
    unsafe { read_volatile(va as *const u32) }
}
fn rd16(va: usize) -> u16 {
    unsafe { read_volatile(va as *const u16) }
}
fn wr64(va: usize, v: u64) {
    unsafe { write_volatile(va as *mut u64, v) }
}

pub struct E1000e {
    pub mac: [u8; 6],
    pub csum: bool,
    pub tso: bool,
    regs: Mmio,
    link: LinkState,

    rx_ring: usize,
    rx_bufs: [(usize, u64); RX_BUFS],
    /// Next descriptor the device completes.
    rx_next: usize,
    /// Descriptors given back since the last tail write.
    rx_kick: bool,
    /// Inside a frame that spans buffers (too long: dropped to its end).
    rx_discard: bool,

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

/// STATUS as a link state: speed in bits 7:6.
fn link_of(status: u32) -> LinkState {
    let speed = match (status >> 6) & 3 {
        0 => 10,
        1 => 100,
        _ => 1000,
    };
    LinkState::ethernet(status & STATUS_LU != 0, speed)
}

impl E1000e {
    pub fn offer(&self) -> Offer {
        let mut o = Offer::plain(self.mac);
        o.tx_csum = self.csum as u32;
        if self.tso {
            o.tx_gso_mask = 1 << 1 | 1 << 4;
            o.tx_gso_max = net::MAX_FRAME as u32;
            o.tx_mss_min = TSO_MIN_MSS as u32;
            o.tx_mss_max = TSO_MAX_MSS as u32;
            o.tx_hdr_max = TSO_MAX_HDR as u32;
        }
        o
    }

    pub fn new(hw: &Hw) -> Self {
        let (c, tsc_hz) = (hw.config, hw.tsc_hz);
        let n = c.uplink as usize;
        let regs = Mmio(c.bars[0].va as usize);
        let wait_us = |us: u64| {
            let end = host::ticks::now() + us * tsc_hz / 1_000_000;
            while host::ticks::now() < end {
                core::hint::spin_loop();
            }
        };
        let poll = |reg: usize, mask: u32, want: u32, ms: u64| -> bool {
            for _ in 0..ms * 10 {
                if regs.r32(reg) & mask == want {
                    return true;
                }
                wait_us(100);
            }
            regs.r32(reg) & mask == want
        };

        // Stop the device as Linux's reset_hw_82571: no interrupts, no
        // receive or transmit, then no more DMA from this function.
        regs.w32(IMC, 0xffff_ffff);
        regs.w32(RCTL, 0);
        regs.w32(TCTL, TCTL_PSP);
        regs.r32(STATUS);
        wait_us(10_000);
        regs.w32(CTRL, regs.r32(CTRL) | CTRL_GIO_DIS);
        if !poll(STATUS, STATUS_GIO, 0, 80) {
            l4h_rt::info!("nicd {}: GIO primary still enabled; resetting anyway", n);
        }

        // MAC reset, holding the software flag as Linux does (firmware
        // may be using the PHY).  The PHY keeps its link.
        let held = (0..500).any(|_| {
            regs.w32(EXTCNF_CTRL, regs.r32(EXTCNF_CTRL) | EXTCNF_SWFLAG);
            if regs.r32(EXTCNF_CTRL) & EXTCNF_SWFLAG != 0 {
                return true;
            }
            wait_us(2000);
            false
        });
        regs.w32(CTRL, regs.r32(CTRL) | CTRL_RST);
        wait_us(1000);
        if !poll(CTRL, CTRL_RST, 0, 10) {
            panic!("nicd {}: reset does not complete", n);
        }
        if held {
            regs.w32(EXTCNF_CTRL, regs.r32(EXTCNF_CTRL) & !EXTCNF_SWFLAG);
        }
        // The NVM is read back into the registers (the MAC address).
        if !poll(EECD, EECD_AUTO_RD, EECD_AUTO_RD, 10) {
            l4h_rt::info!("nicd {}: NVM auto-read not done after reset", n);
        }
        wait_us(25_000);
        regs.w32(IMC, 0xffff_ffff);
        regs.r32(ICR);

        let (ral, rah) = (regs.r32(RAL0), regs.r32(RAH0));
        let mac = [ral as u8, (ral >> 8) as u8, (ral >> 16) as u8, (ral >> 24) as u8, rah as u8, (rah >> 8) as u8];
        regs.w32(RAH0, (rah & 0xffff) | RAH_AV);
        regs.w32(CTRL_EXT, regs.r32(CTRL_EXT) | CTRL_EXT_DRV_LOAD | CTRL_EXT_PBA_CLR | CTRL_EXT_EIAME);
        // The MAC follows the PHY's autonegotiated speed and duplex.
        regs.w32(CTRL, (regs.r32(CTRL) | CTRL_SLU) & !(CTRL_FRCSPD | CTRL_FRCDPX));

        let mut dma = hw.dma();

        // Receive: legacy descriptors, 2 KiB buffers, CRC stripped, the
        // device's checksum results, no delay timers (EITR moderates).
        let (rx_ring, rx_ring_pa) = dma.alloc(RX_BUFS * RX_DESC, 4096);
        let rx_bufs: [_; RX_BUFS] = core::array::from_fn(|_| dma.alloc(RX_BUF, 128));
        for (i, &(_, pa)) in rx_bufs.iter().enumerate() {
            wr64(rx_ring + i * RX_DESC, pa);
            wr64(rx_ring + i * RX_DESC + 8, 0);
        }
        regs.w32(RFCTL, regs.r32(RFCTL) & !RFCTL_EXTEN);
        regs.w32(RDTR, 0);
        regs.w32(RADV, 0);
        regs.w32(RXCSUM, RXCSUM_IPOFL | RXCSUM_TUOFL);
        regs.w32(RDBAL, rx_ring_pa as u32);
        regs.w32(RDBAH, (rx_ring_pa >> 32) as u32);
        regs.w32(RDLEN, (RX_BUFS * RX_DESC) as u32);
        regs.w32(RDH, 0);
        regs.w32(RDT, 0);
        dma_fence(Ordering::Release);
        // Every frame: the switch decides (netd's other uplinks behave so).
        regs.w32(RCTL, RCTL_EN | RCTL_UPE | RCTL_MPE | RCTL_BAM | RCTL_SECRC);
        // All buffers but one: head == tail means empty.
        regs.w32(RDT, (RX_BUFS - 1) as u32);

        // Transmit.
        let (tx_ring, tx_ring_pa) = dma.alloc(TX_RING * TX_DESC, 4096);
        let tx_bufs: [_; TX_BUFS] = core::array::from_fn(|_| dma.alloc(TX_BUF, 128));
        regs.w32(TDBAL, tx_ring_pa as u32);
        regs.w32(TDBAH, (tx_ring_pa >> 32) as u32);
        regs.w32(TDLEN, (TX_RING * TX_DESC) as u32);
        regs.w32(TDH, 0);
        regs.w32(TDT, 0);
        regs.w32(TXDCTL, TXDCTL_WB);
        regs.w32(TIPG, TIPG_COPPER);
        regs.w32(TCTL, TCTL_EN | TCTL_PSP | TCTL_CT | TCTL_COLD | TCTL_RTLC);

        // Interrupts: MSI-X entries 0 (RX), 1 (TX) and 2 (other causes,
        // left masked), all the driver's vector.
        hw.program_msix(3);
        regs.w32(IVAR, IVAR_VALID | (IVAR_VALID | 1) << 8 | (IVAR_VALID | 2) << 16);
        regs.w32(ITR, ITR_VAL);
        for v in 0..3 {
            regs.w32(eitr(v), ITR_VAL);
        }
        // Causes clear (EIAC) and mask themselves (IAM) when their message
        // is sent.
        regs.w32(EIAC, CAUSE_RX | CAUSE_TX);
        regs.w32(IAM, CAUSE_RX | CAUSE_TX);
        regs.w32(IMS, CAUSE_RX);

        // The link the PHY had stays up across the MAC reset; one that is
        // still negotiating comes up later (timer).
        poll(STATUS, STATUS_LU, STATUS_LU, 3000);
        let link = link_of(regs.r32(STATUS));
        l4h_rt::info!(
            "nicd {}: {:02x}:{:02x}.{} 82574, mac {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, link {} {}M",
            n, c.pci_bdf >> 8, (c.pci_bdf >> 3) & 0x1f, c.pci_bdf & 7,
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
            if link.up() { "up" } else { "down" }, link.speed(),
        );

        E1000e {
            mac,
            csum: TX_OFFLOADS,
            tso: TX_OFFLOADS,
            regs,
            link,
            rx_ring,
            rx_bufs,
            rx_next: 0,
            rx_kick: false,
            rx_discard: false,
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

    // ---- receive

    /// Descriptor `i`'s status (bits 7:0) and errors (15:8).
    fn rx_status(&self, i: usize) -> u32 {
        rd32(self.rx_ring + i * RX_DESC + 12) & 0xffff
    }

    pub fn rx_begin(&mut self) {
        self.regs.w32(IMC, CAUSE_RX);
    }

    pub fn rx_done(&mut self) -> bool {
        if core::mem::take(&mut self.rx_kick) {
            dma_fence(Ordering::Release);
            // The descriptor before the next one to complete is the last
            // the device may fill.
            self.regs.w32(RDT, ((self.rx_next + RX_BUFS - 1) % RX_BUFS) as u32);
        }
        self.regs.w32(IMS, CAUSE_RX);
        if self.rx_status(self.rx_next) & RXD_STAT_DD != 0 {
            self.regs.w32(IMC, CAUSE_RX);
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
            let len = (rd16(d + 8) as usize).min(RX_BUF);
            let eop = status & RXD_STAT_EOP != 0;
            self.rx_next = (i + 1) % RX_BUFS;
            // A frame in several buffers is longer than the device should
            // accept: dropped, up to and including its last buffer.
            let whole = eop && !core::mem::take(&mut self.rx_discard);
            if !eop {
                self.rx_discard = true;
            }
            let n = (whole && status & RXD_ERR_FRAME == 0 && len <= out.len()).then(|| {
                let data = unsafe { core::slice::from_raw_parts(self.rx_bufs[i].0 as *const u8, len) };
                out[..len].copy_from_slice(data);
                len
            });
            // The device checked the L4 (TCP or UDP) checksum, and the IPv4
            // header checksum if there is one (Linux e1000_rx_checksum).
            let valid = status & RXD_STAT_TCPCS != 0
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

    fn tx_done(&self, last: usize) -> bool {
        rd32(self.tx_ring + last * TX_DESC + 12) & TXD_STAT_DD != 0
    }

    fn reap_tx(&mut self) {
        while let Some(&(last, buf)) = self.tx_sent.first() {
            if !self.tx_done(last) {
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
        self.regs.w32(if on { IMS } else { IMC }, CAUSE_TX);
        self.tx_sent.first().is_some_and(|&(last, _)| self.tx_done(last))
    }

    fn put_desc(&mut self, lo: u64, hi: u64) {
        let va = self.tx_ring + self.tx_tail * TX_DESC;
        wr64(va, lo);
        wr64(va + 8, hi);
        self.tx_tail = (self.tx_tail + 1) % TX_RING;
    }

    /// The context descriptor for a frame's checksum or segmentation
    /// offload, and the data descriptors' POPTS and TSE; None for offloads
    /// the device cannot do (netd's software paths handle those).
    fn offload(&self, buf: &mut [u8], hdr: &[u8; HDR]) -> Option<(u64, u64, u32, u32)> {
        let get16 = |off: usize| u16::from_le_bytes([hdr[off], hdr[off + 1]]) as usize;
        let (start, off) = (get16(6), get16(8));
        let (ethertype, ip) = offload::ethertype(buf)?;
        let v4 = match ethertype {
            0x0800 => true,
            0x86dd => false,
            _ => return None,
        };
        if !(off == 16 || off == 6) || start + off > 255 || start < ip + 20 {
            return None;
        }
        // TUCSS, TUCSO; TUCSE 0: to the end of the frame.
        let tu = (start | (start + off) << 8) as u64;
        if offload::is_gso(hdr) {
            // TCP: the device fills in each segment's IP length and
            // checksum, and wants the TCP pseudo-header checksum without
            // the length (Linux e1000_tso).
            let f = offload::parse_tcp(buf).filter(|f| f.tcp == start && f.ip == ip && f.hdrs <= TSO_MAX_HDR)?;
            let mss = get16(4) as u32;
            let paylen = (buf.len() - f.tcp) as u32;
            let c = f.tcp + 16;
            let old = u16::from_be_bytes([buf[c], buf[c + 1]]) as u32;
            let mut sum = (!old & 0xffff) + (paylen >> 16) + (paylen & 0xffff);
            sum = (sum & 0xffff) + (sum >> 16);
            sum = (sum & 0xffff) + (sum >> 16);
            buf[c..c + 2].copy_from_slice(&(!sum as u16).to_be_bytes());
            // IPCSS, IPCSO and IPCSE (IPv4: the header's last byte).
            let (ipcs, mut cmd, mut popts) = if v4 {
                buf[ip + 2..ip + 4].fill(0);
                buf[ip + 10..ip + 12].fill(0);
                ((ip | (ip + 10) << 8 | (f.tcp - 1) << 16) as u64, TXD_CMD_IP, TXD_POPTS_IXSM)
            } else {
                buf[ip + 4..ip + 6].fill(0);
                (ip as u64, 0, 0)
            };
            cmd |= TXD_CMD_DEXT | TXD_CMD_TSE | TXD_CMD_TCP | (buf.len() - f.hdrs) as u32;
            popts |= TXD_POPTS_TXSM;
            let seg = (f.hdrs as u32) << 8 | mss << 16;
            return Some((ipcs | tu << 32, cmd as u64 | (seg as u64) << 32, popts, TXD_CMD_TSE));
        }
        let cmd = TXD_CMD_DEXT | if off == 16 { TXD_CMD_TCP } else { 0 };
        Some((tu << 32, cmd as u64, TXD_POPTS_TXSM, 0))
    }

    pub fn transmit(&mut self, frame: &[u8], hdr: &[u8; HDR]) -> bool {
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
        buf.copy_from_slice(frame);
        let mut popts = 0;
        let mut tse = 0;
        let wants = self.csum && (hdr[0] & offload::F_NEEDS_CSUM != 0 || offload::is_gso(hdr));
        if wants {
            match self.offload(buf, hdr) {
                Some((lo, hi, p, t)) => {
                    self.put_desc(lo, hi);
                    popts = p;
                    tse = t;
                }
                None => {
                    // Only NEEDS_CSUM frames come here (netd segments GSO
                    // frames this device declines): finish in software.
                    let mut h = *hdr;
                    offload::complete_csum(buf, &mut h);
                }
            }
        }
        let mut off = 0;
        while off < frame.len() {
            let len = (frame.len() - off).min(TX_MAX_DATA);
            let last = off + len == frame.len();
            let cmd = TXD_DTYP_DATA | TXD_CMD_DEXT | TXD_CMD_IFCS | tse | len as u32
                | if last { TXD_CMD_EOP | TXD_CMD_RS } else { 0 };
            self.put_desc(pa + off as u64, cmd as u64 | (popts as u64) << 32);
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
            self.regs.w32(TDT, self.tx_tail as u32);
        }
    }

    pub fn stop(&mut self) {
        self.regs.w32(IMC, 0xffff_ffff);
        self.regs.w32(RCTL, 0);
        self.regs.w32(TCTL, TCTL_PSP);
        self.regs.r32(STATUS);
    }
}

/// The SDK's view of the driver (l4h_nicdrv::NicDriver).
impl crate::sdk::NicDriver for E1000e {
    fn start(hw: &Hw) -> Result<Self, &'static str> {
        Ok(E1000e::new(hw))
    }
    fn offer(&self) -> Offer {
        E1000e::offer(self)
    }
    fn rx_begin(&mut self) {
        E1000e::rx_begin(self)
    }
    fn rx_done(&mut self) -> bool {
        E1000e::rx_done(self)
    }
    fn receive(&mut self, out: &mut [u8], hdr: &mut [u8; HDR]) -> Option<usize> {
        E1000e::receive(self, out, hdr)
    }
    fn transmit(&mut self, frame: &[u8], hdr: &[u8; HDR]) -> bool {
        E1000e::transmit(self, frame, hdr)
    }
    fn tx_interrupts(&mut self, on: bool) -> bool {
        E1000e::tx_interrupts(self, on)
    }
    fn kick_tx(&mut self) {
        E1000e::kick_tx(self)
    }
    fn link(&self) -> LinkState {
        self.link
    }
    fn timer(&mut self) {
        self.link = link_of(self.regs.r32(STATUS));
    }
    fn stop(&mut self) {
        E1000e::stop(self)
    }
}

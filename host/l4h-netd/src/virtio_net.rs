//! virtio-net PCI driver, for modern (virtio 1.x) and legacy (0.9.5, as
//! on N2 GCE instances) devices.  Frames are copied between the switch and
//! DMA buffers owned by this driver.

use l4h_rt::host::fixed::ArrayVec;
use l4h_rt::host::net::{self, NicConfig};
use l4h_rt::ioport::Ports;
use l4h_virtio::{
    DESC_F_WRITE, Device, Dma, F_ACCESS_PLATFORM, F_VERSION_1, Mmio, STATUS_ACK, STATUS_DRIVER, STATUS_DRIVER_OK, STATUS_FAILED, Virtq, legacy,
};

use crate::pool::Frame;

const VIRTIO_NET_F_CSUM: u64 = 1 << 0;
const VIRTIO_NET_F_GUEST_CSUM: u64 = 1 << 1;
const VIRTIO_NET_F_MAC: u64 = 1 << 5;
const VIRTIO_NET_F_GUEST_TSO4: u64 = 1 << 7;
const VIRTIO_NET_F_GUEST_TSO6: u64 = 1 << 8;
const VIRTIO_NET_F_HOST_TSO4: u64 = 1 << 11;
const VIRTIO_NET_F_HOST_TSO6: u64 = 1 << 12;
const VIRTIO_NET_F_MRG_RXBUF: u64 = 1 << 15;
/// struct virtio_net_hdr_v1; legacy devices use the first 10 bytes
/// (struct virtio_net_hdr, without num_buffers).
const HDR: usize = net::HDR_SIZE;
const LEGACY_HDR: usize = 10;
/// Receive buffers.  With receive TSO, a frame of up to 64 KiB spans
/// several (MRG_RXBUF): one frame per 40 MTU segments is what makes
/// downloads fast, as every frame costs wakeups on its way to the guest.
const RX_BUF: usize = 4096;
/// Transmit buffers: whole TSO frames.
const TX_BUF: usize = HDR + net::MAX_FRAME;
const RX_QUEUE: u16 = 256;
const TX_BUFS: u16 = 24;
const _: () = assert!(TX_BUFS <= u32::BITS as u16);

pub struct VirtioNet {
    pub mac: [u8; 6],
    device: Option<Device>,
    /// The device takes NEEDS_CSUM frames / TSO frames.
    pub csum: bool,
    pub tso: bool,
    /// Received frames may span several buffers (num_buffers).
    mrg: bool,
    /// Legacy devices are notified through I/O ports.
    ports: Option<Ports>,
    /// Bytes of virtio-net header in front of each frame.
    hdr_len: usize,
    rxq: Virtq,
    txq: Virtq,
    rx_bufs: ArrayVec<(usize, u64), { RX_QUEUE as usize }>,
    tx_bufs: ArrayVec<(usize, u64), { TX_BUFS as usize }>,
    tx_free: ArrayVec<u16, { TX_BUFS as usize }>,
    /// TX buffers with the device: only these come back to tx_free.
    tx_busy: u32,
    /// Buffers were given to the device, which has not been notified.
    rx_kick: bool,
    tx_kick: bool,
}

/// Features this driver uses, of those the device offers.
fn wanted(offered: u64) -> u64 {
    let mut want = offered & (VIRTIO_NET_F_MAC | VIRTIO_NET_F_CSUM | VIRTIO_NET_F_GUEST_CSUM | VIRTIO_NET_F_MRG_RXBUF);
    if want & VIRTIO_NET_F_CSUM != 0 {
        want |= offered & (VIRTIO_NET_F_HOST_TSO4 | VIRTIO_NET_F_HOST_TSO6);
    }
    // Large received frames only into mergeable buffers.
    if want & (VIRTIO_NET_F_GUEST_CSUM | VIRTIO_NET_F_MRG_RXBUF) == VIRTIO_NET_F_GUEST_CSUM | VIRTIO_NET_F_MRG_RXBUF {
        want |= offered & (VIRTIO_NET_F_GUEST_TSO4 | VIRTIO_NET_F_GUEST_TSO6);
    }
    want
}

fn modern_device(c: &NicConfig) -> Device {
    Device {
        common: Mmio(c.common.va as usize),
        notify: Mmio(c.notify.va as usize),
        notify_mult: c.notify_off_multiplier,
        device: Mmio(c.device.va as usize),
    }
}

impl VirtioNet {
    pub fn new(n: usize, c: &NicConfig) -> Self {
        let mut dma = Dma::new(net::nic_dma_va(n), c.dma_paddr, c.dma_size as usize);
        let msix = Mmio(c.msix_table.va as usize);
        msix.w32(0, c.msi_address as u32);
        msix.w32(4, (c.msi_address >> 32) as u32);
        msix.w32(8, c.msi_data);
        msix.w32(12, 0);
        let (mut rxq, txq, want, mac, ports, hdr_len, device) = if c.legacy_io != 0 {
            let p = Ports { cap: net::NETD_SLOT_IOPORT_BASE + n as u64, base: c.legacy_io as u16 };
            p.out8(legacy::STATUS, 0);
            p.out8(legacy::STATUS, STATUS_ACK | STATUS_DRIVER);
            let want = wanted(p.in32(legacy::DEVICE_FEATURES) as u64);
            p.out32(legacy::GUEST_FEATURES, want as u32);
            p.out16(legacy::CONFIG_VECTOR, 0xffff);
            let mut queue = |idx: u16| {
                p.out16(legacy::QUEUE_SELECT, idx);
                let num = p.in16(legacy::QUEUE_SIZE);
                if num == 0 {
                    p.out8(legacy::STATUS, STATUS_FAILED);
                    panic!("netd: NIC {} has no queue {}", n, idx);
                }
                let (va, pa) = dma.alloc(l4h_virtio::legacy_ring_size(num), 4096);
                p.out32(legacy::QUEUE_PFN, (pa >> 12) as u32);
                p.out16(legacy::QUEUE_VECTOR, 0);
                if p.in16(legacy::QUEUE_VECTOR) != 0 {
                    panic!("netd: NIC {} refuses MSI-X vector for queue {}", n, idx);
                }
                Virtq::legacy(idx, num, va)
            };
            let (rxq, txq) = (queue(0), queue(1));
            let mac: [u8; 6] = core::array::from_fn(|i| p.in8(legacy::DEVICE_CONFIG + i as u16));
            // A legacy header has num_buffers only with MRG_RXBUF.
            (rxq, txq, want, mac, Some(p), if want & VIRTIO_NET_F_MRG_RXBUF != 0 { HDR } else { LEGACY_HDR }, None)
        } else {
            let dev = modern_device(c);
            dev.reset();
            let offered = dev.features();
            let want = F_VERSION_1 | wanted(offered) | (offered & F_ACCESS_PLATFORM);
            if offered & F_VERSION_1 == 0 || !dev.set_features(want) {
                dev.fail();
                panic!("netd: NIC {} rejects VERSION_1", n);
            }
            let rxq = dev.setup_queue(&mut dma, 0, RX_QUEUE, 0).expect("netd: rx queue");
            let txq = dev.setup_queue(&mut dma, 1, RX_QUEUE, 0).expect("netd: tx queue");
            let mac: [u8; 6] = core::array::from_fn(|i| dev.device.r8(i));
            (rxq, txq, want, mac, None, HDR, Some(dev))
        };
        // A legacy queue has the device's size: post at most RX_QUEUE.
        let (mut rx_bufs, mut tx_bufs, mut tx_free) = (ArrayVec::new(), ArrayVec::new(), ArrayVec::new());
        for _ in 0..rxq.num.min(RX_QUEUE) {
            let _ = rx_bufs.push(dma.alloc(RX_BUF, 64));
        }
        for i in 0..TX_BUFS.min(txq.num) {
            let _ = tx_bufs.push(dma.alloc(TX_BUF, 64));
            let _ = tx_free.push(TX_BUFS.min(txq.num) - 1 - i);
        }
        for (i, &(_, pa)) in rx_bufs.iter().enumerate() {
            rxq.set_desc(i as u16, pa, RX_BUF as u32, DESC_F_WRITE, 0);
            rxq.submit(i as u16);
        }
        let nic = VirtioNet {
            mac,
            device,
            csum: want & VIRTIO_NET_F_CSUM != 0,
            tso: want & (VIRTIO_NET_F_HOST_TSO4 | VIRTIO_NET_F_HOST_TSO6) == (VIRTIO_NET_F_HOST_TSO4 | VIRTIO_NET_F_HOST_TSO6),
            mrg: want & VIRTIO_NET_F_MRG_RXBUF != 0,
            ports,
            hdr_len,
            rxq,
            txq,
            rx_bufs,
            tx_bufs,
            tx_free,
            tx_busy: 0,
            rx_kick: false,
            tx_kick: false,
        };
        match &nic.ports {
            Some(p) => p.out8(legacy::STATUS, STATUS_ACK | STATUS_DRIVER | STATUS_DRIVER_OK),
            None => modern_device(c).driver_ok(),
        }
        // Interrupts per sent buffer only while frames wait for one
        // (Nic::flush_tx); each costs a VM exit, dear under nested
        // virtualization.
        nic.txq.set_interrupts(false);
        nic.kick(&nic.rxq);
        l4h_rt::info!(
            "netd: NIC {}: {:02x}:{:02x}.{} virtio-net {}, mac {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, offloads tx{}{} rx{}{}{}",
            n, c.pci_bdf >> 8, (c.pci_bdf >> 3) & 0x1f, c.pci_bdf & 7,
            if nic.ports.is_some() { "legacy" } else { "modern" },
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
            if nic.csum { " csum" } else { "" }, if nic.tso { " tso" } else { "" },
            if want & VIRTIO_NET_F_GUEST_CSUM != 0 { " csum" } else { "" },
            if want & (VIRTIO_NET_F_GUEST_TSO4 | VIRTIO_NET_F_GUEST_TSO6) != 0 { " tso" } else { "" },
            if nic.mrg { " mrg" } else { "" },
        );
        nic
    }

    /// Stop the device before an ownership handoff.
    pub fn reset(&mut self) -> bool {
        if let Some(device) = &self.device {
            device.reset();
        }
        if let Some(ports) = &self.ports {
            ports.out8(legacy::STATUS, 0);
        }
        true
    }

    fn kick(&self, q: &Virtq) {
        // A notification is a VM exit; skip it while the device is busy
        // with the queue anyway.
        if !q.wants_notify() {
            return;
        }
        q.notify();
        if let Some(p) = &self.ports {
            p.out16(legacy::QUEUE_NOTIFY, q.idx);
        }
    }

    pub fn rx_begin(&self) {
        self.rxq.set_interrupts(false);
    }

    pub fn rx_done(&mut self) -> bool {
        if core::mem::take(&mut self.rx_kick) {
            self.kick(&self.rxq);
        }
        self.rxq.set_interrupts(true);
        if self.rxq.has_used() {
            self.rxq.set_interrupts(false);
            return false;
        }
        true
    }

    pub fn receive(&mut self, out: &mut [u8], hdr: &mut [u8; HDR]) -> Option<usize> {
        let hl = self.hdr_len;
        loop {
            let (id, len) = self.rxq.pop_used()?;
            let Some(&(va, _)) = self.rx_bufs.get(id as usize) else { continue };
            let len = (len as usize).min(RX_BUF);
            *hdr = [0; HDR];
            unsafe { core::ptr::copy_nonoverlapping(va as *const u8, hdr.as_mut_ptr(), hl.min(len)) };
            let bufs = if self.mrg { u16::from_le_bytes([hdr[10], hdr[11]]) as usize } else { 1 };
            hdr[10] = 0;
            hdr[11] = 0;
            let mut n = len.saturating_sub(hl).min(out.len());
            unsafe { core::ptr::copy_nonoverlapping((va + hl) as *const u8, out.as_mut_ptr(), n) };
            // Give the buffer back to the device.
            self.rxq.submit(id as u16);
            let mut whole = len > hl && bufs >= 1;
            // The rest of a frame that spans buffers: the device makes them
            // all used at once.
            for _ in 1..bufs {
                let Some((id, len)) = self.rxq.pop_used() else { whole = false; break };
                let Some(&(va, _)) = self.rx_bufs.get(id as usize) else { whole = false; continue };
                let len = (len as usize).min(RX_BUF);
                let m = len.min(out.len() - n);
                unsafe { core::ptr::copy_nonoverlapping(va as *const u8, out.as_mut_ptr().add(n), m) };
                whole &= m == len;
                n += m;
                self.rxq.submit(id as u16);
            }
            self.rx_kick = true;
            if whole {
                return Some(n);
            }
        }
    }

    fn reap_tx(&mut self) {
        while let Some((id, _)) = self.txq.pop_used() {
            // A buffer the device returns twice, or one it never had, is
            // not freed again.
            if id < TX_BUFS as u32 && self.tx_busy & 1 << id != 0 {
                self.tx_busy &= !(1 << id);
                let _ = self.tx_free.push(id as u16);
            }
        }
    }

    pub fn tx_interrupts(&mut self, on: bool) -> bool {
        self.txq.set_interrupts(on);
        self.txq.has_used()
    }

    pub fn transmit(&mut self, frame: &(impl Frame + ?Sized), hdr: &[u8; HDR]) -> bool {
        let hl = self.hdr_len;
        if self.tx_free.is_empty() {
            self.reap_tx();
        }
        if self.tx_free.is_empty() {
            // Let the device start on what is queued.
            self.kick_tx();
        }
        let Some(i) = self.tx_free.pop() else { return false };
        self.tx_busy |= 1 << i;
        let (va, pa) = self.tx_bufs[i as usize];
        unsafe {
            core::ptr::copy_nonoverlapping(hdr.as_ptr(), va as *mut u8, hl);
            if hl == HDR {
                // num_buffers is only meaningful on receive.
                core::ptr::write_bytes((va + 10) as *mut u8, 0, 2);
            }
            frame.copy_to(core::slice::from_raw_parts_mut((va + hl) as *mut u8, frame.len()));
        }
        self.txq.set_desc(i, pa, (hl + frame.len()) as u32, 0, 0);
        self.txq.submit(i);
        self.tx_kick = true;
        true
    }

    pub fn kick_tx(&mut self) {
        if core::mem::take(&mut self.tx_kick) {
            self.kick(&self.txq);
        }
    }
}

//! Uplink NICs: a virtio-net, gVNIC, Amazon ENA or Intel X550 device, and the
//! frames waiting for one of its TX buffers.

use core::ptr::addr_of_mut;

use l4h_rt::host::fixed::ArrayVec;
use l4h_rt::host::net::{self, NicConfig};

use crate::ena::Ena;
use crate::gvnic::Gvnic;
use crate::ixgbe::Ixgbe;
use crate::pool::{Fifo, Pool};
use crate::virtio_net::VirtioNet;

const HDR: usize = net::HDR_SIZE;
/// Frames waiting for a TX buffer (rather than dropped), and the pool
/// chunks they may take: the guests' backlogs take from the same pool.
const TX_BACKLOG_FRAMES: usize = 512;
const TX_BACKLOG_CHUNKS: usize = (4 << 20) / crate::pool::CHUNK;

/// A frame that spans receive buffers, while they arrive (gVNIC, ENA, X550):
/// one per NIC, too large for the stack.
pub type Partial = ArrayVec<u8, { net::MAX_FRAME }>;
static mut RX_PARTIAL: [Partial; net::MAX_NICS] = [const { Partial::new() }; net::MAX_NICS];

enum Dev {
    Virtio(VirtioNet),
    Gvnic(Gvnic),
    Ena(Ena),
    Ixgbe(Ixgbe),
}

/// Calls the same method on whichever device this is.
macro_rules! dev {
    ($self:expr, $d:ident => $e:expr) => {
        match &mut $self.dev {
            Dev::Virtio($d) => $e,
            Dev::Gvnic($d) => $e,
            Dev::Ena($d) => $e,
            Dev::Ixgbe($d) => $e,
        }
    };
}

pub struct Nic {
    pub switch: Option<u32>,
    pub mac: [u8; 6],
    /// The device takes NEEDS_CSUM frames / TSO frames.
    pub csum: bool,
    pub tso: bool,
    dev: Dev,
    tx_backlog: Fifo,
    pub tx_drops: u64,
}

impl Nic {
    /// NIC `n` (< MAX_NICS), made once.
    pub fn new(n: usize, c: &NicConfig, tsc_hz: u64) -> Self {
        let partial = unsafe { &mut *addr_of_mut!(RX_PARTIAL[n]) };
        let (dev, mac, csum, tso) = match c.kind {
            net::NIC_GVNIC => {
                let g = Gvnic::new(n, c, tsc_hz, partial);
                let (mac, csum, tso) = (g.mac, g.csum, g.tso);
                (Dev::Gvnic(g), mac, csum, tso)
            }
            net::NIC_ENA => {
                let e = Ena::new(n, c, tsc_hz, partial);
                let (mac, csum, tso) = (e.mac, e.csum, e.tso);
                (Dev::Ena(e), mac, csum, tso)
            }
            net::NIC_IXGBE => {
                let x = Ixgbe::new(n, c, tsc_hz, partial);
                let (mac, csum, tso) = (x.mac, x.csum, x.tso);
                (Dev::Ixgbe(x), mac, csum, tso)
            }
            _ => {
                let v = VirtioNet::new(n, c);
                let (mac, csum, tso) = (v.mac, v.csum, v.tso);
                (Dev::Virtio(v), mac, csum, tso)
            }
        };
        Nic { switch: None, mac, csum, tso, dev, tx_backlog: Fifo::EMPTY, tx_drops: 0 }
    }

    /// Whether the device takes this GSO frame whole.
    pub fn takes_gso(&self, hdr: &[u8; HDR]) -> bool {
        match &self.dev {
            Dev::Virtio(_) => self.tso,
            Dev::Gvnic(g) => g.takes_gso(hdr),
            Dev::Ena(_) => false,
            Dev::Ixgbe(x) => x.takes_gso(hdr),
        }
    }

    /// RX interrupts off while netd drains the queue.
    pub fn rx_begin(&mut self) {
        dev!(self, d => d.rx_begin())
    }

    /// RX interrupts on again; false if frames arrived meanwhile, which the
    /// caller drains (interrupts off again).  Returns buffers to the device
    /// with one notification per batch.
    pub fn rx_done(&mut self) -> bool {
        dev!(self, d => d.rx_done())
    }

    /// Next received frame, copied to `out` with its virtio-net header in
    /// `hdr` (num_buffers cleared); returns its length.
    pub fn receive(&mut self, out: &mut [u8], hdr: &mut [u8; HDR]) -> Option<usize> {
        dev!(self, d => d.receive(out, hdr))
    }

    /// Send a frame, or hold it in `pool` until a TX buffer is free: a
    /// dropped frame costs TCP a retransmission timeout.
    pub fn send(&mut self, frame: &[u8], hdr: &[u8; HDR], pool: &mut Pool) {
        if frame.len() > net::MAX_FRAME {
            self.tx_drops += 1;
            return;
        }
        if self.tx_backlog.is_empty() && dev!(self, d => d.transmit(frame, hdr)) {
            return;
        }
        if !pool.push(&mut self.tx_backlog, frame, hdr, TX_BACKLOG_FRAMES, TX_BACKLOG_CHUNKS) {
            self.tx_drops += 1;
            return;
        }
        self.flush_tx(pool);
    }

    /// Send held frames while TX buffers are free.  While some remain,
    /// the device interrupts when it returns buffers.
    pub fn flush_tx(&mut self, pool: &mut Pool) {
        loop {
            while let Some(f) = pool.front(&self.tx_backlog) {
                if !dev!(self, d => d.transmit(&f, &f.hdr)) {
                    break;
                }
                pool.pop(&mut self.tx_backlog);
            }
            let waiting = !self.tx_backlog.is_empty();
            // Buffers returned before the interrupt was on: send again.
            if !dev!(self, d => d.tx_interrupts(waiting)) || !waiting {
                return;
            }
        }
    }

    /// Notify the device of the frames submitted since the last call: once
    /// per batch, not per frame.
    pub fn kick_tx(&mut self) {
        dev!(self, d => d.kick_tx())
    }
}

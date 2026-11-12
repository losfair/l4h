//! virtio-net device backed by a netd port.  Frames and their virtio-net
//! headers are copied between guest buffers and the port's slots; the
//! offload metadata in the header (checksum, TSO) passes through.

use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{Ordering, fence};

use l4h_rt::host::fixed::ArrayVec;
use l4h_rt::host::net::{self, Port};
use l4h_rt::host::spsc::{Consumer, Producer};
use l4h_rt::sel4;

use crate::dev::Backend;
use crate::guest::GuestMem;
use crate::virtq::{Buf, Queue};

const VIRTIO_ID_NET: u32 = 1;
const VIRTIO_NET_F_CSUM: u64 = 1 << 0;
const VIRTIO_NET_F_GUEST_CSUM: u64 = 1 << 1;
const VIRTIO_NET_F_MTU: u64 = 1 << 3;
const VIRTIO_NET_F_MAC: u64 = 1 << 5;
const VIRTIO_NET_F_GUEST_TSO4: u64 = 1 << 7;
const VIRTIO_NET_F_GUEST_TSO6: u64 = 1 << 8;
const VIRTIO_NET_F_HOST_TSO4: u64 = 1 << 11;
const VIRTIO_NET_F_HOST_TSO6: u64 = 1 << 12;
const VIRTIO_NET_F_STATUS: u64 = 1 << 16;
const VIRTIO_NET_F_SPEED_DUPLEX: u64 = 1 << 63;
const VIRTIO_NET_S_LINK_UP: u16 = 1;
const HDR: usize = net::HDR_SIZE;
const RX: usize = 0;
const TX: usize = 1;
const QUEUE_SIZE: u32 = 256;
/// Count every chain, including malformed packets: a producer on another
/// vCPU must not keep one handler from returning to the IPC loop.
const BATCH: usize = 32;

/// The buffers of one chain (see Queue::chain).
type Chain = ArrayVec<Buf, { QUEUE_SIZE as usize }>;

pub struct Net {
    chan: *mut Port,
    /// Our indices of the port's rings: netd can write over the port's
    /// copies.
    tx: Producer,
    rx: Consumer,
    kick: sel4::cap::Notification,
    mac: [u8; 6],
    /// The receive queue's size (host::iopool::rx_queue_size).
    rx_queue: u32,
    /// Transmit stopped at a full port ring: netd frees slots, then
    /// signals.
    tx_blocked: bool,
    /// Queues whose batch ended before they were found empty.
    pub more: u64,
    link: net::LinkState,
}

impl Net {
    pub fn new(chan_va: usize, kick: sel4::cap::Notification, mac: [u8; 6], rx_queue: u32) -> Self {
        let chan = chan_va as *mut Port;
        let link = net::LinkState(unsafe { addr_of!((*chan).link_state).read_volatile() });
        // Fresh port memory: both rings start empty.
        Net { chan, tx: Producer::new(net::RING_SIZE), rx: Consumer::new(net::RING_SIZE), kick, mac,
            rx_queue: rx_queue.min(QUEUE_SIZE), tx_blocked: false, more: 0, link }
    }

    fn link_config(&self, config: &mut [u8]) {
        let status = if self.link.up() { VIRTIO_NET_S_LINK_UP } else { 0 };
        config[6..8].copy_from_slice(&status.to_le_bytes());
        config[12..16].copy_from_slice(&self.link.speed().to_le_bytes());
        config[16] = self.link.duplex();
    }

    /// Full, or netd broke the tail.
    fn tx_full(&self) -> bool {
        unsafe { self.tx.free(&(*self.chan).tx) == 0 }
    }

    /// Guest -> port.  Returns (returned to guest, queued to the port).
    fn transmit(&mut self, mem: &GuestMem, q: &mut Queue) -> (bool, bool) {
        let (mut returned, mut queued) = (false, false);
        self.tx_blocked = false;
        self.more &= !(1 << TX);
        let mut left = BATCH;
        while left != 0 {
            if self.tx_full() {
                self.tx_blocked = true;
                break;
            }
            let Some(head) = q.pop(mem) else { break };
            left -= 1;
            let mut bufs = Chain::new();
            if q.chain(mem, head, &mut bufs).is_ok() {
                unsafe {
                    let slot = addr_of_mut!((*self.chan).tx_slots[self.tx.slot()]);
                    let hdr = addr_of_mut!((*slot).hdr) as *mut u8;
                    let data = addr_of_mut!((*slot).data) as *mut u8;
                    // The header first, then the frame.
                    let (mut off, mut n) = (0usize, 0usize);
                    let mut ok = true;
                    for b in bufs.iter().filter(|b| !b.write) {
                        let src = mem.bytes(b.gpa, b.len as usize);
                        let mut len = b.len as usize;
                        let mut s = 0;
                        if off < HDR {
                            let h = (HDR - off).min(len);
                            core::ptr::copy_nonoverlapping(src, hdr.add(off), h);
                            off += h;
                            s = h;
                            len -= h;
                        }
                        if n + len > net::MAX_FRAME {
                            ok = false;
                            break;
                        }
                        core::ptr::copy_nonoverlapping(src.add(s), data.add(n), len);
                        n += len;
                    }
                    if ok && off == HDR && n >= 14 {
                        addr_of_mut!((*slot).len).write_volatile(n as u32);
                        self.tx.push(&(*self.chan).tx);
                        queued = true;
                    }
                }
            }
            q.push(mem, head, 0);
            returned = true;
        }
        // One extra empty poll is harmless; reading avail again here
        // would let the producer race the decision to sleep.
        if left == 0 {
            self.more |= 1 << TX;
        }
        (returned, queued)
    }

    /// Port -> guest, while both have entries.
    fn receive(&mut self, mem: &GuestMem, q: &mut Queue) -> bool {
        let mut returned = false;
        self.more &= !(1 << RX);
        let mut left = BATCH;
        while left != 0 {
            if unsafe { self.rx.ready(&(*self.chan).rx) } == 0 {
                break;
            }
            let Some(chain) = q.pop(mem) else { break };
            left -= 1;
            let mut bufs = Chain::new();
            let mut written = 0usize;
            if q.chain(mem, chain, &mut bufs).is_ok() {
                unsafe {
                    let slot = addr_of!((*self.chan).rx_slots[self.rx.slot()]);
                    let len = (addr_of!((*slot).len).read_volatile() as usize).min(net::MAX_FRAME);
                    let data = addr_of!((*slot).data) as *const u8;
                    // The slot's header, with num_buffers = 1.
                    let mut hdr = addr_of!((*slot).hdr).read_volatile();
                    hdr[10] = 1;
                    hdr[11] = 0;
                    let total = HDR + len;
                    for b in bufs.iter().filter(|b| b.write) {
                        let n = (b.len as usize).min(total - written);
                        let dst = mem.bytes(b.gpa, n);
                        let mut i = 0;
                        while i < n && written + i < HDR {
                            *dst.add(i) = hdr[written + i];
                            i += 1;
                        }
                        if i < n {
                            core::ptr::copy_nonoverlapping(data.add(written + i - HDR), dst.add(i), n - i);
                        }
                        written += n;
                        if written == total {
                            break;
                        }
                    }
                    if written < total {
                        // Buffers too small: drop the frame.
                        written = 0;
                    }
                }
            }
            unsafe { self.rx.pop(&(*self.chan).rx) };
            q.push(mem, chain, written as u32);
            returned = true;
        }
        if left == 0 {
            self.more |= 1 << RX;
        }
        // netd holds frames for this port until we free slots: tell it.
        if returned {
            fence(Ordering::SeqCst);
            if unsafe { addr_of!((*self.chan).rx_wanted).read_volatile() } != 0 {
                self.kick.signal();
            }
        }
        returned
    }
}

impl Backend for Net {
    fn device_id(&self) -> u32 {
        VIRTIO_ID_NET
    }

    fn features(&self) -> u64 {
        VIRTIO_NET_F_MAC
            | VIRTIO_NET_F_SPEED_DUPLEX
            | VIRTIO_NET_F_STATUS
            | VIRTIO_NET_F_MTU
            | VIRTIO_NET_F_CSUM
            | VIRTIO_NET_F_GUEST_CSUM
            | VIRTIO_NET_F_HOST_TSO4
            | VIRTIO_NET_F_HOST_TSO6
            | VIRTIO_NET_F_GUEST_TSO4
            | VIRTIO_NET_F_GUEST_TSO6
    }

    fn num_queues(&self) -> usize {
        2
    }

    fn queue_max(&self, q: usize) -> u32 {
        if q == RX { self.rx_queue } else { QUEUE_SIZE }
    }

    fn init_config(&self, config: &mut [u8]) {
        config[0..6].copy_from_slice(&self.mac);
        self.link_config(config);
        config[10..12].copy_from_slice(&((net::MTU_FRAME - 14) as u16).to_le_bytes());
    }

    fn update_config(&mut self, config: &mut [u8]) -> bool {
        let link = net::LinkState(unsafe { addr_of!((*self.chan).link_state).read_volatile() });
        if link == self.link { return false; }
        self.link = link;
        self.link_config(config);
        true
    }

    fn features_accepted(&mut self, f: u64) {
        let gso = f & (VIRTIO_NET_F_GUEST_TSO4 | VIRTIO_NET_F_GUEST_TSO6) == (VIRTIO_NET_F_GUEST_TSO4 | VIRTIO_NET_F_GUEST_TSO6);
        unsafe {
            addr_of_mut!((*self.chan).rx_csum).write_volatile((f & VIRTIO_NET_F_GUEST_CSUM != 0) as u32);
            addr_of_mut!((*self.chan).rx_gso).write_volatile((gso && f & VIRTIO_NET_F_GUEST_CSUM != 0) as u32);
        }
    }

    fn kick(&mut self, mem: &GuestMem, queues: &mut [Queue], q: usize) -> bool {
        match q {
            TX => {
                let (returned, queued) = self.transmit(mem, &mut queues[TX]);
                if queued {
                    self.kick.signal();
                }
                returned
            }
            RX => self.receive(mem, &mut queues[RX]),
            _ => false,
        }
    }

    fn complete(&mut self, mem: &GuestMem, queues: &mut [Queue]) -> bool {
        let mut returned = false;
        if queues[RX].ready {
            returned |= self.receive(mem, &mut queues[RX]);
        }
        if queues[TX].ready {
            let (r, queued) = self.transmit(mem, &mut queues[TX]);
            returned |= r;
            if queued {
                self.kick.signal();
            }
        }
        returned
    }

    fn pending(&self) -> bool {
        self.tx_blocked
            || unsafe { self.rx.ready(&(*self.chan).rx) != 0 }
    }

    fn reset(&mut self) {
        self.tx_blocked = false;
        self.more = 0;
        unsafe {
            addr_of_mut!((*self.chan).rx_csum).write_volatile(0);
            addr_of_mut!((*self.chan).rx_gso).write_volatile(0);
        }
    }
}

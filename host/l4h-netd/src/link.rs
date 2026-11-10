//! Links to other partitions' netds (multikernel, DESIGN.md §11.4).
//!
//! A link is a channel of memory both partitions reach, with a message
//! ring each way (l4h_partition::MsgRing) that one netd writes and the
//! other reads.  The writer never waits: a frame that finds the reader a
//! whole ring behind overwrites what it did not read, which the reader
//! notices and skips, as a wire drops frames. The other netd receives
//! whole Ethernet frames or TCP GSO frames with their offload headers.
//!
//! Doorbells.  The peer's doorbell arrives as an interrupt whose handler
//! signals netd directly.  Ringing the peer takes IRQControl, which only
//! root holds, so netd signals root, which rings it: constant work, and
//! repeated signals merge in root's notification.  Even that stays off a
//! busy link: the reader sets the incoming ring's "wake me" flag only
//! when it found the ring empty and is about to sleep, and then looks
//! once more, since a frame published before the writer could see the
//! flag would otherwise wait for the next one. The writer checks the flag
//! during large batches and at the end of each batch. If the flag is set,
//! the writer clears it and asks root to ring. A busy reader does not set
//! the flag, so no doorbell rings.

use l4h_partition::{LINK_FRAME_MAX, MSG_FRAME, MSG_FRAME_GSO, MsgReader, MsgRing};
use l4h_rt::host::net;
use l4h_rt::{cap, sel4};
use sel4::cap_type;

use crate::offload::{MIN_MSS, is_gso, sanitize_rx};

const _: () = assert!(
    8 + net::HDR_SIZE as u64 + net::MAX_FRAME as u64
        <= MsgRing::max_room(l4h_partition::LINK_CHANNEL_SIZE / 2 - l4h_partition::MSG_RING_HEADER as u64)
);

/// What one look at a link's incoming ring gave (`Link::recv`).
pub enum Received<'a> {
    /// A frame, and its offload header.
    Frame(&'a mut [u8], [u8; net::HDR_SIZE]),
    /// A record that is no frame netd takes: unknown, of a wrong length,
    /// or with an offload header that does not describe it.
    Dropped,
    /// Nothing to read now.
    Empty,
}

pub struct Link {
    pub switch: u32,
    tx: MsgRing,
    rx: MsgReader,
    /// The doorbell's IRQ handler, root's notification badged for this
    /// link (ring the peer's doorbell), and netd's own (read on later).
    irq: sel4::cap::IrqHandler,
    ring: sel4::cap::Notification,
    kick: sel4::cap::Notification,
    /// Message bytes written since the last look at the peer's flag.
    pending_bytes: u64,
    pub rx_frames: u64,
    pub tx_frames: u64,
    pub drops: u64,
    /// Bytes the peer overwrote before they were read.
    pub lost: u64,
}

impl Link {
    /// Link `l`, its channel of `size` bytes mapped at net::link_va(l),
    /// between partitions `me` and `peer`.
    pub fn new(l: usize, switch: u32, size: u64, me: u32, peer: u32) -> Link {
        let (tx, rx) = MsgRing::pair(net::link_va(l), size, me, peer);
        let link = Link {
            switch,
            tx,
            // What came before netd started is stale.
            rx: MsgReader::new(rx),
            irq: cap::<cap_type::IrqHandler>(net::NETD_SLOT_LINK_IRQ_BASE + l as u64),
            ring: cap::<cap_type::Notification>(net::NETD_SLOT_LINK_RING_BASE + l as u64),
            kick: cap::<cap_type::Notification>(net::NETD_SLOT_LINK_KICK_BASE + l as u64),
            pending_bytes: 0,
            rx_frames: 0,
            tx_frames: 0,
            drops: 0,
            lost: 0,
        };
        link.rx.arm();
        link
    }

    /// Send a frame and check for a sleeping peer during long batches.
    pub fn send(&mut self, frame: &[u8]) {
        if frame.len() < 14 || frame.len() > LINK_FRAME_MAX {
            self.drops += 1;
            return;
        }
        self.send_record(MSG_FRAME, &[frame], frame.len());
    }

    pub fn can_send_gso(&self, len: usize) -> bool {
        (8 + net::HDR_SIZE as u64 + len as u64).next_multiple_of(8) <= MsgRing::max_room(self.tx.cap)
    }

    pub fn send_gso(&mut self, frame: &[u8], hdr: &[u8; net::HDR_SIZE]) {
        self.send_record(MSG_FRAME_GSO, &[hdr, frame], hdr.len() + frame.len());
    }

    fn send_record(&mut self, kind: u32, parts: &[&[u8]], len: usize) {
        self.tx.send(kind, parts);
        self.tx_frames += 1;
        self.pending_bytes += (8 + len as u64).next_multiple_of(8);
        // A batch can exceed the ring size. Give a sleeping peer a
        // chance to read before the batch can overwrite its messages.
        if self.pending_bytes >= MsgRing::max_room(self.tx.cap) {
            self.doorbell();
        }
    }

    /// After a batch: ring the peer if it sleeps.
    pub fn doorbell(&mut self) {
        if core::mem::take(&mut self.pending_bytes) != 0 && self.tx.take_wake() {
            self.ring.signal();
        }
    }

    /// One look at the incoming ring: a frame and its offload header, a
    /// record that was dropped, or nothing to read.  It reads at most two
    /// records (`MsgReader::recv`), so a caller that bounds its looks
    /// bounds the work the peer can give it.  The buffer has an extra
    /// byte so a truncated oversized record fails the length check.
    pub fn recv<'a>(&mut self, buf: &'a mut [u8]) -> Received<'a> {
        let Some((ty, n)) = self.rx.recv(buf, &mut self.lost) else { return Received::Empty };
        if ty == MSG_FRAME && (14..=LINK_FRAME_MAX).contains(&n) {
            self.rx_frames += 1;
            return Received::Frame(&mut buf[..n], [0; net::HDR_SIZE]);
        }
        if ty == MSG_FRAME_GSO && (net::HDR_SIZE + 14..=net::HDR_SIZE + net::MAX_FRAME).contains(&n) {
            let mut hdr = buf[..net::HDR_SIZE].try_into().unwrap();
            // The peer partition is not trusted with tiny segments.
            if is_gso(&hdr) && sanitize_rx(&mut hdr, &buf[net::HDR_SIZE..n], MIN_MSS) {
                self.rx_frames += 1;
                return Received::Frame(&mut buf[net::HDR_SIZE..n], hdr);
            }
        }
        self.drops += 1;
        Received::Dropped
    }

    /// The ring is empty: ask for a doorbell.  False if a frame came in
    /// meanwhile, to read before sleeping.
    pub fn sleep(&self) -> bool {
        self.rx.arm()
    }

    /// The doorbell rang (or netd kicked itself).
    pub fn ack(&self) {
        // No handler if root got no vector for it: then only the kicks.
        let _ = self.irq.irq_handler_ack();
    }

    /// Have netd come back to this link after its other work.
    pub fn kick(&self) {
        self.kick.signal();
    }
}

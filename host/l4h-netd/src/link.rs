//! Links to other partitions' netds (multikernel, DESIGN.md §11.4).
//!
//! A link is a channel of memory both partitions reach, with a message
//! ring each way (l4h_partition::MsgRing) that one netd writes and the
//! other reads.  The writer never waits: a frame that finds the reader a
//! whole ring behind overwrites what it did not read, which the reader
//! notices and skips, as a wire drops frames.  Only whole Ethernet frames
//! cross, checksums complete and at most LINK_FRAME_MAX bytes: the other
//! netd may hand them to any port.
//!
//! Doorbells.  The peer's doorbell arrives as an interrupt whose handler
//! signals netd directly.  Ringing the peer takes IRQControl, which only
//! root holds, so netd signals root, which rings it: constant work, and
//! repeated signals merge in root's notification.  Even that stays off a
//! busy link: the reader sets the incoming ring's "wake me" flag only
//! when it found the ring empty and is about to sleep, and then looks
//! once more, since a frame published before the writer could see the
//! flag would otherwise wait for the next one.  The writer, after a batch,
//! checks the flag and only when it is set clears it and asks root to
//! ring.  While frames keep coming the reader never sets the flag, and no
//! doorbell rings at all.

use l4h_partition::{LINK_FRAME_MAX, MSG_FRAME, MsgReader, MsgRing};
use l4h_rt::host::net;
use l4h_rt::{cap, sel4};
use sel4::cap_type;

pub struct Link {
    pub switch: u32,
    tx: MsgRing,
    rx: MsgReader,
    /// The doorbell's IRQ handler, root's notification badged for this
    /// link (ring the peer's doorbell), and netd's own (read on later).
    irq: sel4::cap::IrqHandler,
    ring: sel4::cap::Notification,
    kick: sel4::cap::Notification,
    /// Frames written since the last look at the peer's flag.
    sent: bool,
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
            sent: false,
            rx_frames: 0,
            tx_frames: 0,
            drops: 0,
            lost: 0,
        };
        link.rx.arm();
        link
    }

    /// Send a frame to the peer; the doorbell waits for `doorbell`.
    pub fn send(&mut self, frame: &[u8]) {
        if frame.len() < 14 || frame.len() > LINK_FRAME_MAX {
            self.drops += 1;
            return;
        }
        self.tx.send(MSG_FRAME, &[frame]);
        self.tx_frames += 1;
        self.sent = true;
    }

    /// After a batch: ring the peer if it sleeps.
    pub fn doorbell(&mut self) {
        if core::mem::take(&mut self.sent) && self.tx.take_wake() {
            self.ring.signal();
        }
    }

    /// The next frame from the peer, into `buf`: its length.  None when
    /// the ring is empty.
    pub fn recv(&mut self, buf: &mut [u8]) -> Option<usize> {
        loop {
            let (ty, n) = self.rx.recv(buf, &mut self.lost)?;
            if ty == MSG_FRAME && (14..=LINK_FRAME_MAX).contains(&n) {
                self.rx_frames += 1;
                return Some(n);
            }
            self.drops += 1;
        }
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

//! The indices of a single-producer single-consumer ring in memory shared
//! with a peer that may be hostile: a blkd channel's two rings
//! (blk::Channel), a netd port's (net::Port), and usbd's queues (usb::Sq,
//! usb::Cq, whose indices sit in the guest ABI's own layout).  Indices are
//! free-running u32s; entry k is in slot k % size.
//!
//! Each side keeps its own index privately (`Producer::head`,
//! `Consumer::tail`) and only publishes it: the peer can write over the
//! shared copy, which changes nothing this side does.  It reads the peer's
//! once per look and checks it against its own: one further from it than
//! the ring holds is broken, and gives nothing to consume and no room to
//! produce into.  The producer writes an entry before the head that
//! publishes it (Release), the consumer reads it after loading that head
//! (Acquire); the consumer's reads come before the tail that frees the
//! slot, the producer's next writes after loading that tail.

use core::sync::atomic::{AtomicU32, Ordering};

/// A ring's indices in the shared page, each on a cache line of its own:
/// `head` is the producer's, `tail` the consumer's.  Each side reads only
/// the other's.  All atomics, padding included, so that a reference to it
/// stays sound whatever the peer writes.
#[repr(C)]
pub struct RingIdx {
    pub head: AtomicU32,
    pad0: [AtomicU32; 15],
    pub tail: AtomicU32,
    pad1: [AtomicU32; 15],
}
const _: () = assert!(core::mem::size_of::<RingIdx>() == 128);

/// The consumer's side of a ring of `size` entries: its own tail.
#[derive(Clone, Copy, Debug)]
pub struct Consumer {
    pub tail: u32,
    pub size: u32,
}

impl Consumer {
    /// A ring the producer has not written to yet.
    pub const fn new(size: usize) -> Self {
        assert!(size > 0 && size <= u32::MAX as usize);
        Self { tail: 0, size: size as u32 }
    }

    /// Entries available at the producer's `head`, or None if it is
    /// further from our tail than the ring holds (the producer is broken).
    pub fn avail(&self, head: u32) -> Option<u32> {
        let n = head.wrapping_sub(self.tail);
        (n <= self.size).then_some(n)
    }

    /// The slot of the oldest entry not consumed.
    pub fn slot(&self) -> usize {
        (self.tail % self.size) as usize
    }

    /// Entries the producer of `idx` has published, or None if its head
    /// is broken.  They can be read once this returns.
    pub fn pending(&self, idx: &RingIdx) -> Option<u32> {
        self.avail(idx.head.load(Ordering::Acquire))
    }

    /// `pending`, with a broken head as none.
    pub fn ready(&self, idx: &RingIdx) -> u32 {
        self.pending(idx).unwrap_or(0)
    }

    /// Free the oldest entry (`slot`), which was read: the producer may
    /// write over it once it sees the tail.
    pub fn pop(&mut self, idx: &RingIdx) {
        self.tail = self.tail.wrapping_add(1);
        idx.tail.store(self.tail, Ordering::Release);
    }
}

/// The producer's side of a ring of `size` entries: its own head.
#[derive(Clone, Copy, Debug)]
pub struct Producer {
    pub head: u32,
    pub size: u32,
}

impl Producer {
    /// A ring the consumer has not read from yet.
    pub const fn new(size: usize) -> Self {
        assert!(size > 0 && size <= u32::MAX as usize);
        Self { head: 0, size: size as u32 }
    }

    /// Free entries given the consumer's `tail`, or None if the tail is
    /// not between our head minus the size and our head (the consumer is
    /// broken).
    pub fn room(&self, tail: u32) -> Option<u32> {
        let used = self.head.wrapping_sub(tail);
        (used <= self.size).then(|| self.size - used)
    }

    /// The slot the next entry goes in.
    pub fn slot(&self) -> usize {
        (self.head % self.size) as usize
    }

    /// Free entries in `idx`'s ring: none if the consumer's tail is broken.
    /// They can be written once this returns.
    pub fn free(&self, idx: &RingIdx) -> u32 {
        self.room(idx.tail.load(Ordering::Acquire)).unwrap_or(0)
    }

    /// Entries published that the consumer of `idx` has not freed: all of
    /// them if its tail is broken.
    pub fn used(&self, idx: &RingIdx) -> u32 {
        self.size - self.free(idx)
    }

    /// Publish the entry written at `slot`, which `free` said was free.
    pub fn push(&mut self, idx: &RingIdx) {
        self.head = self.head.wrapping_add(1);
        idx.head.store(self.head, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn idx() -> RingIdx {
        const Z: AtomicU32 = AtomicU32::new(0);
        RingIdx { head: Z, pad0: [Z; 15], tail: Z, pad1: [Z; 15] }
    }

    #[test]
    fn own_index_is_private() {
        let r = idx();
        let (mut p, mut c) = (Producer::new(4), Consumer::new(4));
        assert_eq!((p.free(&r), c.ready(&r)), (4, 0));
        p.push(&r);
        p.push(&r);
        // The consumer writes over the producer's head, and the producer
        // over the consumer's tail: neither changes what the other side
        // publishes next.
        r.head.store(1000, Ordering::Relaxed);
        assert_eq!(c.ready(&r), 0, "a head beyond the ring is broken");
        p.push(&r);
        assert_eq!((r.head.load(Ordering::Relaxed), c.ready(&r)), (3, 3));
        assert_eq!(c.slot(), 0);
        c.pop(&r);
        r.tail.store(7, Ordering::Relaxed);
        assert_eq!((p.free(&r), p.used(&r)), (0, 4), "a tail ahead of the head is broken");
        c.pop(&r);
        assert_eq!((r.tail.load(Ordering::Relaxed), p.free(&r), c.slot(), p.slot()), (2, 3, 2, 3));
    }

    #[test]
    fn wraps() {
        let r = idx();
        let mut p = Producer { head: u32::MAX - 1, size: 8 };
        let mut c = Consumer { tail: u32::MAX - 1, size: 8 };
        r.head.store(p.head, Ordering::Relaxed);
        r.tail.store(c.tail, Ordering::Relaxed);
        for _ in 0..8 {
            p.push(&r);
        }
        assert_eq!((p.free(&r), c.ready(&r)), (0, 8));
        for _ in 0..8 {
            c.pop(&r);
        }
        assert_eq!((p.free(&r), c.ready(&r), p.head, c.tail), (8, 0, 6, 6));
    }
}

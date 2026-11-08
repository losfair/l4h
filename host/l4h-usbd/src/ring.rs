//! Transfer rings, from a fixed pool of pages in the DMA region, and the
//! URBs in flight on them.  A ring is one page: TRBs 0..254, then a Link
//! TRB back to the start.  Each ring keeps its URBs in order, those on the
//! ring (posted) first, then those waiting for room.

use core::ptr::addr_of_mut;
use core::sync::atomic::Ordering;

use l4h_abi::usb as abi;
use l4h_rt::host::fixed::ArrayVec;
use l4h_rt::host::usb::{self as proto, TdEnds, Trb, Xfer, RING_TRBS, USB_RINGS};
use l4h_virtio::{Mmio, dma_fence};

use crate::xhci::Region;

pub const NONE: u16 = u16::MAX;
/// TRBs of a ring other than its Link TRB.
const USABLE: u16 = RING_TRBS as u16 - 1;

#[derive(Clone, Copy)]
pub struct Ring {
    pub used: bool,
    /// Where the next TRB goes, and the cycle bit it gets.
    pub enq: u16,
    pub cycle: u32,
    /// The first TRB the controller may still use: the oldest posted URB's.
    pub deq: u16,
    /// URBs, oldest first.
    pub head: u16,
    pub tail: u16,
    pub slot: u8,
    pub dci: u8,
    pub stream: u16,
}

const FREE_RING: Ring = Ring { used: false, enq: 0, cycle: 1, deq: 0, head: NONE, tail: NONE, slot: 0, dci: 0, stream: 0 };

static mut RINGS: [Ring; USB_RINGS] = [FREE_RING; USB_RINGS];

pub struct Rings {
    rings: &'static mut [Ring; USB_RINGS],
    free: ArrayVec<u16, USB_RINGS>,
}

impl Rings {
    pub fn new() -> Self {
        let mut free = ArrayVec::new();
        for r in (0..USB_RINGS as u16).rev() {
            free.must_push(r);
        }
        // The only reference to RINGS.
        Rings { rings: unsafe { &mut *addr_of_mut!(RINGS) }, free }
    }

    pub fn get(&self, r: u16) -> &Ring {
        &self.rings[r as usize]
    }

    pub fn get_mut(&mut self, r: u16) -> &mut Ring {
        &mut self.rings[r as usize]
    }

    pub fn free_count(&self) -> usize {
        self.free.len()
    }

    pub fn alloc(&mut self, slot: u8, dci: u8, stream: u16) -> Option<u16> {
        let r = self.free.pop()?;
        self.rings[r as usize] = Ring { used: true, slot, dci, stream, ..FREE_RING };
        Some(r)
    }

    /// Give ring `r` back; it has no URBs, and the controller no longer
    /// uses it.
    pub fn free(&mut self, r: u16) {
        if r == NONE || !self.rings[r as usize].used {
            return;
        }
        debug_assert!(self.rings[r as usize].head == NONE);
        self.rings[r as usize] = FREE_RING;
        self.free.must_push(r);
    }

    /// Empty ring `r`: zeroed, its Link TRB in place, the producer cycle 1.
    pub fn reinit(&mut self, dma: Region, r: u16) {
        let off = dma.ring(r as usize);
        unsafe { core::ptr::write_bytes(dma.va(off) as *mut u8, 0, RING_TRBS * 16) };
        let link = Mmio(dma.va(off + USABLE as usize * 16));
        link.w64(0, dma.pa(off));
        link.w32(12, (proto::TRB_LINK << 10) | proto::TRB_TC);
        let ring = &mut self.rings[r as usize];
        (ring.enq, ring.cycle, ring.deq) = (0, 1, 0);
    }

    /// Position `pos` as an offset from `first`, going round the ring.
    pub fn dist(&self, _r: u16, first: u16, pos: u16) -> u16 {
        (pos + USABLE - first) % USABLE
    }

    /// Whether an URB of `n` TRBs fits (with the no-ops before it, if it
    /// would cross the Link TRB), leaving one free so that a full ring is
    /// never mistaken for an empty one.
    pub fn room(&self, r: u16, n: usize) -> bool {
        let ring = &self.rings[r as usize];
        let used = (ring.enq + USABLE - ring.deq) % USABLE;
        let to_end = (USABLE - ring.enq) as usize;
        let pad = if n > to_end { to_end } else { 0 };
        n + pad + used as usize + 1 < USABLE as usize
    }

    /// Write `trbs` at the enqueue pointer: the first TRB's cycle bit last,
    /// so that the controller never sees half a TD.  An URB that would
    /// cross the Link TRB goes at the start of the ring instead, after
    /// no-ops to the end (`room` counted them).  Returns where it went.
    pub fn write(&mut self, dma: Region, r: u16, trbs: &[Trb]) -> u16 {
        let off = dma.ring(r as usize);
        let ring = &mut self.rings[r as usize];
        if trbs.len() > (USABLE - ring.enq) as usize {
            while ring.enq < USABLE {
                let e = Mmio(dma.va(off + ring.enq as usize * 16));
                e.w64(0, 0);
                e.w32(8, 0);
                e.w32(12, (proto::TRB_NOOP << 10) | ring.cycle);
                ring.enq += 1;
            }
            dma_fence(Ordering::SeqCst);
            Mmio(dma.va(off + USABLE as usize * 16)).w32(12, (proto::TRB_LINK << 10) | proto::TRB_TC | ring.cycle);
            ring.cycle ^= 1;
            ring.enq = 0;
        }
        let (first, first_cycle) = (ring.enq, ring.cycle);
        for (k, t) in trbs.iter().enumerate() {
            let e = Mmio(dma.va(off + ring.enq as usize * 16));
            e.w64(0, t.param);
            e.w32(8, t.status);
            let cycle = if k == 0 { ring.cycle ^ 1 } else { ring.cycle };
            e.w32(12, (t.control & !proto::TRB_CYCLE) | cycle);
            ring.enq += 1;
            if ring.enq == USABLE {
                // The URB ends right before the Link TRB: no TD goes on
                // past it.
                debug_assert!(k + 1 == trbs.len());
                Mmio(dma.va(off + USABLE as usize * 16)).w32(12, (proto::TRB_LINK << 10) | proto::TRB_TC | ring.cycle);
                ring.cycle ^= 1;
                ring.enq = 0;
            }
        }
        dma_fence(Ordering::SeqCst);
        let e = Mmio(dma.va(off + first as usize * 16));
        e.w32(12, (e.r32(12) & !proto::TRB_CYCLE) | first_cycle);
        first
    }

    /// TRB `k` of an URB at `first`.
    pub fn trb(&self, dma: Region, r: u16, first: u16, k: u16) -> Trb {
        let pos = (first + k) % USABLE;
        let e = Mmio(dma.va(dma.ring(r as usize) + pos as usize * 16));
        Trb { param: e.r64(0), status: e.r32(8), control: e.r32(12) }
    }

    /// Turn `n` TRBs at `first` into no-ops, keeping their cycle and chain
    /// bits: a cancelled URB the controller has not reached.
    pub fn noop(&mut self, dma: Region, r: u16, first: u16, n: u16) {
        for k in 0..n {
            let pos = (first + k) % USABLE;
            let e = Mmio(dma.va(dma.ring(r as usize) + pos as usize * 16));
            let c = e.r32(12);
            e.w32(12, (c & (proto::TRB_CYCLE | proto::TRB_CH)) | (proto::TRB_NOOP << 10));
        }
        dma_fence(Ordering::SeqCst);
    }

    /// Where a stopped ring resumes: the oldest posted URB, or the enqueue
    /// pointer; and the cycle bit there.
    pub fn resume_point(&self, dma: Region, urbs: &Urbs, r: u16) -> (u16, u32) {
        let ring = &self.rings[r as usize];
        match ring.head {
            u if u != NONE && urbs.get(u).posted => {
                let first = urbs.get(u).first;
                (first, self.trb(dma, r, first, 0).control & proto::TRB_CYCLE)
            }
            _ => (ring.enq, ring.cycle),
        }
    }

    pub fn append(&mut self, urbs: &mut Urbs, r: u16, u: u16) {
        let ring = &mut self.rings[r as usize];
        urbs.get_mut(u).next = NONE;
        if ring.tail == NONE {
            ring.head = u;
        } else {
            urbs.get_mut(ring.tail).next = u;
        }
        ring.tail = u;
    }

    /// The first URB not yet on the ring.
    pub fn first_waiting(&self, urbs: &Urbs, r: u16) -> u16 {
        let mut u = self.rings[r as usize].head;
        while u != NONE && urbs.get(u).posted {
            u = urbs.get(u).next;
        }
        u
    }

    /// Take URB `u` off ring `r`; the controller is done with its TRBs.
    /// Returns the URB after it.
    pub fn unlink(&mut self, urbs: &mut Urbs, r: u16, u: u16) -> u16 {
        let ring = &mut self.rings[r as usize];
        let next = urbs.get(u).next;
        let mut prev = NONE;
        let mut at = ring.head;
        while at != NONE && at != u {
            prev = at;
            at = urbs.get(at).next;
        }
        if at == NONE {
            return next;
        }
        if prev == NONE {
            ring.head = next;
        } else {
            urbs.get_mut(prev).next = next;
        }
        if ring.tail == u {
            ring.tail = prev;
        }
        ring.deq = match ring.head {
            h if h != NONE && urbs.get(h).posted => urbs.get(h).first,
            _ => ring.enq,
        };
        next
    }
}

/// An URB usbd accepted.
pub struct Urb {
    pub xfer: Xfer,
    pub ring: u16,
    pub posted: bool,
    /// Its TRBs on the ring, and the last TRB of each TD.
    pub first: u16,
    pub ntrbs: u16,
    pub ends: TdEnds,
    /// The next isoch TD to complete.
    pub td: u16,
    /// Bytes done so far (a control transfer's short data stage, a stopped
    /// TD).
    pub actual: u32,
    pub short: bool,
    pub iso: [abi::IsoStatus; abi::MAX_ISO],
    pub errors: u32,
    pub next: u16,
}

static mut URBS: [Option<Urb>; abi::CQ_SIZE] = [const { None }; abi::CQ_SIZE];

/// The URBs in flight: at most one per CQ entry.
pub struct Urbs {
    urbs: &'static mut [Option<Urb>; abi::CQ_SIZE],
    free: ArrayVec<u16, { abi::CQ_SIZE }>,
}

impl Urbs {
    pub fn new() -> Self {
        let mut free = ArrayVec::new();
        for u in (0..abi::CQ_SIZE as u16).rev() {
            free.must_push(u);
        }
        // The only reference to URBS.
        Urbs { urbs: unsafe { &mut *addr_of_mut!(URBS) }, free }
    }

    pub fn alloc(&mut self, xfer: Xfer, ring: u16) -> Option<u16> {
        let u = self.free.pop()?;
        self.urbs[u as usize] = Some(Urb {
            xfer, ring, posted: false, first: 0, ntrbs: 0, ends: TdEnds::new(), td: 0, actual: 0, short: false,
            iso: [abi::IsoStatus::default(); abi::MAX_ISO], errors: 0, next: NONE,
        });
        Some(u)
    }

    pub fn free(&mut self, u: u16) {
        if self.urbs[u as usize].take().is_some() {
            self.free.must_push(u);
        }
    }

    pub fn get(&self, u: u16) -> &Urb {
        self.urbs[u as usize].as_ref().expect("URB in flight")
    }

    pub fn get_mut(&mut self, u: u16) -> &mut Urb {
        self.urbs[u as usize].as_mut().expect("URB in flight")
    }

    /// The URB in flight with the guest's tag.
    pub fn find(&self, tag: u32) -> Option<u16> {
        self.urbs.iter().position(|u| u.as_ref().is_some_and(|u| u.xfer.tag == tag)).map(|u| u as u16)
    }
}

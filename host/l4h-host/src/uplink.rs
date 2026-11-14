//! The uplink channel: the one ABI between netd and a NIC driver
//! component (nicd, DESIGN.md §9.8), whatever the device is.  netd knows
//! nothing else about uplinks.
//!
//! A channel is one region of root's frames that netd and the driver map
//! (copies of root's capabilities: neither can revoke the other's
//! mapping).  It holds a header page, two descriptor rings and two data
//! areas:
//!
//! - TX: frames netd sends out, netd produces and the driver consumes;
//! - RX: frames the driver received, the driver produces and netd
//!   consumes.
//!
//! Each direction is an SPSC ring of descriptors (crate::spsc) and a
//! circular data area that the producer fills in order.  A descriptor has
//! a frame's length and its virtio-net header, and no offset: the consumer
//! computes where the frame is from its own cursor and the lengths it has
//! read (`Reader`), so a hostile producer cannot point it anywhere.  The
//! only value to check is the length.  A frame starts on a FRAME_ALIGN
//! boundary and never wraps: if it does not fit before the end of the
//! area, the producer writes a padding descriptor (length 0) first and
//! starts the frame at offset 0.  The producer reckons free bytes from its
//! own record of what it wrote (`Writer`), never from anything the
//! consumer writes but the ring's tail, which it checks.
//!
//! The data area stays writable by its producer while the consumer reads
//! it: a consumer that must trust a frame's bytes copies them first.
//! netd does (it validates the headers of what it copied).  The driver
//! trusts netd, which is in the TCB.
//!
//! Notifications follow the guest ports' protocol, with a flag for each
//! side that waits: a consumer that found its ring empty sets its `*_idle`
//! word before it sleeps and looks once more; a producer that found no
//! room sets its `*_full` word and looks once more.  The other side
//! signals only when it sees the flag set, once per batch.  netd signals
//! the driver's notification; the driver signals netd's, badged
//! badges::netd::UPLINK (netd then looks at every uplink).
//!
//! The header's offer is the driver's: it writes it once, before `ready`,
//! and netd copies it once and validates every frame against it.

use core::sync::atomic::{AtomicU32, Ordering, fence};

use crate::net::{HDR_SIZE, MAX_FRAME};
use crate::spsc::{Consumer, Producer, RingIdx};

pub const ABI_VERSION: u32 = 1;
pub const PAGE: usize = 4096;
/// Descriptors in each ring.
pub const DESCS: usize = 1024;
pub const DESC_SIZE: usize = 32;
/// Every frame starts at a multiple of this in its data area.
pub const FRAME_ALIGN: usize = 64;
/// Bounds of a data area's size, 2^bits bytes (manifest's channel_bits):
/// it must hold a few whole GSO frames.
pub const MIN_DATA_BITS: u32 = 20;
pub const MAX_DATA_BITS: u32 = 23;
pub const DEFAULT_DATA_BITS: u32 = 22;
const _: () = assert!((1 << MIN_DATA_BITS) >= 8 * MAX_FRAME);

/// header.mac_mode.  MULTI: Ethernet, frames of any source MAC cross.
/// SINGLE: only the uplink's own MAC works (a Wi-Fi station, a cloud VPC).
pub const MAC_MULTI: u32 = 0;
pub const MAC_SINGLE: u32 = 1;

/// Offsets in the channel.
pub const TX_DESC_OFFSET: usize = PAGE;
pub const RX_DESC_OFFSET: usize = TX_DESC_OFFSET + DESCS * DESC_SIZE;
pub const DATA_OFFSET: usize = RX_DESC_OFFSET + DESCS * DESC_SIZE;
const _: () = assert!(DATA_OFFSET % PAGE == 0);

/// Bytes of a channel whose data areas are 2^data_bits each.
pub const fn channel_size(data_bits: u32) -> usize {
    DATA_OFFSET + 2 * (1 << data_bits)
}
pub const MAX_CHANNEL_SIZE: usize = channel_size(MAX_DATA_BITS);

/// What the driver offers, which netd copies once `ready` is set.  netd
/// hands the driver no frame outside it: it checksums and segments
/// anything else itself.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Offer {
    /// Must be ABI_VERSION, or netd refuses the channel.
    pub abi: u32,
    /// MAC_MULTI or MAC_SINGLE.
    pub mac_mode: u32,
    /// The permanent MAC address, in the first six bytes.
    pub mac: [u8; 8],
    /// The device takes NEEDS_CSUM frames.
    pub tx_csum: u32,
    /// GSO types it takes whole: bit t for virtio-net GSO type t
    /// (GSO_TCPV4 1, GSO_TCPV6 4).  Only with tx_csum.
    pub tx_gso_mask: u32,
    /// The largest GSO frame, the MSS range and the largest header length
    /// (virtio hdr_len) it segments.
    pub tx_gso_max: u32,
    pub tx_mss_min: u32,
    pub tx_mss_max: u32,
    pub tx_hdr_max: u32,
    /// Lengths of the frames it sends that are not GSO frames
    /// (ConnectX-5: 14..=1518); tx_gso_max bounds those.
    pub tx_frame_min: u32,
    pub tx_frame_max: u32,
    /// It may deliver GSO frames (after GRO or device LRO).
    pub rx_gso: u32,
    /// Queue pairs: 1 in this version.
    pub queues: u32,
    pub reserved: [u32; 8],
}

impl Offer {
    /// A device that offloads nothing, with `mac`.
    pub const fn plain(mac: [u8; 6]) -> Self {
        Offer {
            abi: ABI_VERSION,
            mac_mode: MAC_MULTI,
            mac: [mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], 0, 0],
            tx_csum: 0,
            tx_gso_mask: 0,
            tx_gso_max: 0,
            tx_mss_min: 0,
            tx_mss_max: 0,
            tx_hdr_max: 0,
            tx_frame_min: 14,
            tx_frame_max: MAX_FRAME as u32,
            rx_gso: 0,
            queues: 1,
            reserved: [0; 8],
        }
    }

    /// The offer as netd uses it: none of it beyond what netd can do
    /// itself, and the frame bounds within Ethernet's and MAX_FRAME.
    /// None if netd refuses the channel (another ABI, nonsense bounds).
    pub fn checked(mut self) -> Option<Self> {
        if self.abi != ABI_VERSION || self.queues != 1 || self.mac_mode > MAC_SINGLE {
            return None;
        }
        let max = MAX_FRAME as u32;
        if self.tx_frame_min > self.tx_frame_max || self.tx_frame_max < 60 || self.tx_frame_min > 60 {
            return None;
        }
        self.tx_frame_min = self.tx_frame_min.max(14);
        self.tx_frame_max = self.tx_frame_max.min(max);
        self.tx_csum = (self.tx_csum != 0) as u32;
        self.rx_gso = (self.rx_gso != 0) as u32;
        // GSO only with checksum offload, TCP only, within a slot.
        self.tx_gso_mask &= (1 << 1) | (1 << 4);
        self.tx_gso_max = self.tx_gso_max.min(max);
        if self.tx_csum == 0 || self.tx_mss_min == 0 || self.tx_mss_min > self.tx_mss_max || self.tx_gso_max <= 1514 {
            self.tx_gso_mask = 0;
        }
        Some(self)
    }

    /// Whether the device takes GSO frame `hdr` of `len` bytes whole
    /// (a checked offer).
    pub fn takes_gso(&self, len: usize, hdr: &[u8; HDR_SIZE]) -> bool {
        let get16 = |off: usize| u16::from_le_bytes([hdr[off], hdr[off + 1]]) as u32;
        let ty = hdr[1] & 0x7f;
        ty < 32 && self.tx_gso_mask & (1 << ty) != 0
            && len <= self.tx_gso_max as usize
            && (self.tx_mss_min..=self.tx_mss_max).contains(&get16(4))
            && get16(2) <= self.tx_hdr_max
    }

    pub fn mac6(&self) -> [u8; 6] {
        [self.mac[0], self.mac[1], self.mac[2], self.mac[3], self.mac[4], self.mac[5]]
    }
}

/// The header page.  Words written by one side and read by the other are
/// atomics, so a reference stays sound whatever the peer writes.
#[repr(C)]
pub struct Header {
    /// The driver's offer, valid once `ready` is non-zero.  Plain words
    /// the driver writes before ready (Release) and netd reads after it
    /// (Acquire), once.
    pub offer: [AtomicU32; OFFER_WORDS],
    /// Set by the driver once the offer is written.
    pub ready: AtomicU32,
    /// net::LinkState, the driver's: one store, at any time.
    pub link_state: AtomicU32,
    pad0: [AtomicU32; 14],
    /// Ring indices: TX (netd produces), RX (the driver produces).
    pub tx: RingIdx,
    pub rx: RingIdx,
    /// Waiting flags, each written by one side: the TX consumer (driver)
    /// sleeps on an empty ring, the TX producer (netd) waits for room; the
    /// same for RX, with the sides swapped.
    pub tx_idle: AtomicU32,
    pad1: [AtomicU32; 15],
    pub tx_full: AtomicU32,
    pad2: [AtomicU32; 15],
    pub rx_idle: AtomicU32,
    pad3: [AtomicU32; 15],
    pub rx_full: AtomicU32,
    pad4: [AtomicU32; 15],
}
pub const OFFER_WORDS: usize = core::mem::size_of::<Offer>() / 4;
const _: () = assert!(core::mem::size_of::<Header>() <= PAGE && core::mem::size_of::<Offer>() % 4 == 0);

impl Header {
    /// Write `o` and set ready (the driver, once).
    pub fn publish_offer(&self, o: &Offer) {
        let words: [u32; OFFER_WORDS] = unsafe { core::mem::transmute(*o) };
        for (w, v) in self.offer.iter().zip(words) {
            w.store(v, Ordering::Relaxed);
        }
        self.ready.store(1, Ordering::Release);
    }

    /// The offer, if the driver has set ready (netd, once).
    pub fn read_offer(&self) -> Option<Offer> {
        if self.ready.load(Ordering::Acquire) == 0 {
            return None;
        }
        let mut words = [0u32; OFFER_WORDS];
        for (v, w) in words.iter_mut().zip(&self.offer) {
            *v = w.load(Ordering::Relaxed);
        }
        // Any bit pattern is an Offer (u32s and bytes).
        Some(unsafe { core::mem::transmute::<[u32; OFFER_WORDS], Offer>(words) })
    }
}

/// A descriptor: a frame's length (0: padding to the end of the area),
/// flags (reserved, 0) and virtio_net_hdr_v1, as on guest ports.
#[repr(C)]
pub struct Desc {
    pub len: AtomicU32,
    pub flags: AtomicU32,
    pub hdr: [AtomicU32; 3],
    pad: [AtomicU32; 3],
}
const _: () = assert!(core::mem::size_of::<Desc>() == DESC_SIZE);

/// One direction of a mapped channel: its ring indices, descriptors and
/// data area, as raw pointers into memory the peer also writes.
#[derive(Clone, Copy)]
pub struct Dir {
    pub idx: *const RingIdx,
    pub descs: *const Desc,
    pub data: *mut u8,
    pub size: usize,
}

/// A channel mapped at `base`, with data areas of 2^data_bits.
#[derive(Clone, Copy)]
pub struct Channel {
    pub base: *mut u8,
    pub data_bits: u32,
}

impl Channel {
    /// # Safety
    /// `base` must map channel_size(data_bits) bytes, page aligned, for as
    /// long as the Channel is used.
    pub const unsafe fn new(base: *mut u8, data_bits: u32) -> Self {
        Channel { base, data_bits }
    }

    pub fn header(&self) -> &Header {
        unsafe { &*(self.base as *const Header) }
    }

    fn data_size(&self) -> usize {
        1 << self.data_bits
    }

    pub fn tx(&self) -> Dir {
        let h = self.header();
        unsafe {
            Dir {
                idx: &h.tx,
                descs: self.base.add(TX_DESC_OFFSET) as *const Desc,
                data: self.base.add(DATA_OFFSET),
                size: self.data_size(),
            }
        }
    }

    pub fn rx(&self) -> Dir {
        let h = self.header();
        unsafe {
            Dir {
                idx: &h.rx,
                descs: self.base.add(RX_DESC_OFFSET) as *const Desc,
                data: self.base.add(DATA_OFFSET + self.data_size()),
                size: self.data_size(),
            }
        }
    }
}

fn align_up(n: usize) -> usize {
    (n + FRAME_ALIGN - 1) & !(FRAME_ALIGN - 1)
}

fn hdr_words(hdr: &[u8; HDR_SIZE]) -> [u32; 3] {
    core::array::from_fn(|i| u32::from_le_bytes(hdr[i * 4..i * 4 + 4].try_into().unwrap()))
}

/// The producer's side of one direction.  `starts` records, per
/// descriptor slot, where in the stream (an unwrapped byte count) its
/// space begins: the bytes the consumer has not freed are those from the
/// start of the oldest unfreed descriptor to `pos`.
pub struct Writer {
    ring: Producer,
    pos: u64,
    starts: [u64; DESCS],
}

impl Writer {
    /// For a direction no one has written yet.
    pub const fn new() -> Self {
        Writer { ring: Producer::new(DESCS), pos: 0, starts: [0; DESCS] }
    }

    /// Bytes and descriptors free, given the consumer's tail: none if the
    /// tail is broken.
    fn room(&self, d: &Dir) -> (usize, u32) {
        let idx = unsafe { &*d.idx };
        let free = self.ring.free(idx);
        let used = DESCS as u32 - free;
        if used == 0 {
            return (d.size, free);
        }
        // The oldest descriptor not freed: `used` behind our head.
        let oldest = (self.ring.slot() + DESCS - used as usize) % DESCS;
        let held = (self.pos - self.starts[oldest]) as usize;
        (d.size.saturating_sub(held), free)
    }

    /// Bytes free now, if at least `descs` descriptors are too (else 0).
    pub fn free_bytes(&self, d: &Dir, descs: u32) -> usize {
        let (bytes, free) = self.room(d);
        if free >= descs { bytes } else { 0 }
    }

    /// Whether a frame of `len` bytes fits now.
    pub fn fits(&self, d: &Dir, len: usize) -> bool {
        self.space(d, len).is_some()
    }

    /// Descriptors and bytes a frame of `len` takes at the current
    /// position: (padding bytes first, if any), or None if it does not fit.
    fn space(&self, d: &Dir, len: usize) -> Option<usize> {
        if len == 0 || len > MAX_FRAME {
            return None;
        }
        let (bytes, descs) = self.room(d);
        let off = (self.pos % d.size as u64) as usize;
        let need = align_up(len);
        let pad = if off + need > d.size { d.size - off } else { 0 };
        (pad + need <= bytes && descs >= 1 + (pad != 0) as u32).then_some(pad)
    }

    fn put(&mut self, d: &Dir, len: u32, hdr: [u32; 3]) {
        let idx = unsafe { &*d.idx };
        let slot = self.ring.slot();
        self.starts[slot] = self.pos;
        let desc = unsafe { &*d.descs.add(slot) };
        desc.len.store(len, Ordering::Relaxed);
        desc.flags.store(0, Ordering::Relaxed);
        for (w, v) in desc.hdr.iter().zip(hdr) {
            w.store(v, Ordering::Relaxed);
        }
        self.ring.push(idx);
    }

    /// Reserve room for a frame of up to `max` bytes, written through the
    /// returned slice and published with `commit` (the bytes it took):
    /// none if it does not fit.  Room is for the whole `max`, as a frame
    /// never wraps.
    pub fn reserve(&mut self, d: &Dir, max: usize) -> Option<&mut [u8]> {
        let pad = self.space(d, max)?;
        if pad != 0 {
            self.put(d, 0, [0; 3]);
            self.pos += pad as u64;
        }
        let off = (self.pos % d.size as u64) as usize;
        Some(unsafe { core::slice::from_raw_parts_mut(d.data.add(off), max) })
    }

    /// Publish the frame `reserve` gave room for, of `len` bytes (no more
    /// than reserved).
    pub fn commit(&mut self, d: &Dir, len: usize, hdr: &[u8; HDR_SIZE]) {
        debug_assert!(len > 0 && len <= MAX_FRAME);
        self.put(d, len as u32, hdr_words(hdr));
        self.pos += align_up(len) as u64;
    }

    /// Copy one frame in; false if it does not fit.
    pub fn write(&mut self, d: &Dir, frame: &[u8], hdr: &[u8; HDR_SIZE]) -> bool {
        let Some(buf) = self.reserve(d, frame.len()) else { return false };
        buf.copy_from_slice(frame);
        self.commit(d, frame.len(), hdr);
        true
    }

    /// Descriptors the consumer has not freed (all, if its tail is broken).
    pub fn pending(&self, d: &Dir) -> u32 {
        DESCS as u32 - self.ring.free(unsafe { &*d.idx })
    }
}

impl Default for Writer {
    fn default() -> Self {
        Self::new()
    }
}

/// What the consumer found next.
pub enum Next<'a> {
    /// A frame, in the peer's memory: it may change while it is read.
    Frame(&'a [u8], [u8; HDR_SIZE]),
    /// A descriptor the consumer refused (reserved flags): skipped and
    /// freed, nothing else is wrong.
    Dropped,
    Empty,
    /// The producer broke the protocol (a head beyond the ring, a length
    /// past the area's end, padding at offset 0): nothing more is read.
    Broken,
}

/// The consumer's side of one direction: its own cursor in the data area.
pub struct Reader {
    ring: Consumer,
    pos: u64,
    broken: bool,
    /// The length of the frame `next` returned, which `release` frees.
    cur: usize,
}

impl Reader {
    pub const fn new() -> Self {
        Reader { ring: Consumer::new(DESCS), pos: 0, broken: false, cur: 0 }
    }

    pub fn is_broken(&self) -> bool {
        self.broken
    }

    /// Whether descriptors wait (a broken ring counts as none).
    pub fn has_next(&self, d: &Dir) -> bool {
        !self.broken && self.ring.pending(unsafe { &*d.idx }).is_some_and(|n| n > 0)
    }

    /// The next frame.  Its bytes stay the consumer's until `release`,
    /// which the caller calls once it has copied them; padding and dropped
    /// descriptors are released here.
    pub fn next(&mut self, d: &Dir) -> Next<'_> {
        if self.broken {
            return Next::Broken;
        }
        let idx = unsafe { &*d.idx };
        loop {
            match self.ring.pending(idx) {
                None => {
                    self.broken = true;
                    return Next::Broken;
                }
                Some(0) => return Next::Empty,
                Some(_) => {}
            }
            let desc = unsafe { &*d.descs.add(self.ring.slot()) };
            let len = desc.len.load(Ordering::Relaxed) as usize;
            let flags = desc.flags.load(Ordering::Relaxed);
            let off = (self.pos % d.size as u64) as usize;
            if len == 0 {
                // Padding: the rest of the area.  At offset 0 it would
                // skip a whole area of frames.
                if off == 0 {
                    self.broken = true;
                    return Next::Broken;
                }
                self.pos += (d.size - off) as u64;
                self.ring.pop(idx);
                continue;
            }
            if len > MAX_FRAME || off + len > d.size {
                self.broken = true;
                return Next::Broken;
            }
            if flags != 0 {
                self.pos += align_up(len) as u64;
                self.ring.pop(idx);
                return Next::Dropped;
            }
            let mut hdr = [0u8; HDR_SIZE];
            for (i, w) in desc.hdr.iter().enumerate() {
                hdr[i * 4..i * 4 + 4].copy_from_slice(&w.load(Ordering::Relaxed).to_le_bytes());
            }
            self.cur = len;
            let frame = unsafe { core::slice::from_raw_parts(d.data.add(off) as *const u8, len) };
            return Next::Frame(frame, hdr);
        }
    }

    /// Free the frame `next` returned: its bytes are the producer's again.
    pub fn release(&mut self, d: &Dir) {
        let idx = unsafe { &*d.idx };
        // The length `next` checked, not the descriptor's now.
        self.pos += align_up(core::mem::take(&mut self.cur)) as u64;
        // Our reads of the frame come before the tail that frees it.
        fence(Ordering::Release);
        self.ring.pop(idx);
    }
}

impl Default for Reader {
    fn default() -> Self {
        Self::new()
    }
}

/// Set `flag` (a waiting word) and decide whether to sleep: false if
/// `still` (the condition to wait for) already holds after the fence, in
/// which case the flag is cleared again.
pub fn arm(flag: &AtomicU32, still: impl FnOnce() -> bool) -> bool {
    flag.store(1, Ordering::Relaxed);
    fence(Ordering::SeqCst);
    if still() {
        flag.store(0, Ordering::Relaxed);
        return false;
    }
    true
}

/// Whether the peer waits on `flag`: if so it is cleared, and the caller
/// signals the peer.
pub fn take_waiter(flag: &AtomicU32) -> bool {
    fence(Ordering::SeqCst);
    flag.load(Ordering::Relaxed) != 0 && flag.swap(0, Ordering::Relaxed) != 0
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::{vec, vec::Vec};

    struct Mem {
        buf: Vec<u64>,
        bits: u32,
    }

    impl Mem {
        fn new(bits: u32) -> Self {
            Mem { buf: vec![0; channel_size(bits) / 8], bits }
        }
        fn chan(&mut self) -> Channel {
            unsafe { Channel::new(self.buf.as_mut_ptr() as *mut u8, self.bits) }
        }
    }

    fn frame(n: usize, seed: u8) -> Vec<u8> {
        (0..n).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
    }

    fn read_all(r: &mut Reader, d: &Dir) -> Vec<(Vec<u8>, [u8; HDR_SIZE])> {
        let mut out = Vec::new();
        loop {
            match r.next(d) {
                Next::Frame(f, h) => {
                    let v = f.to_vec();
                    r.release(d);
                    out.push((v, h));
                }
                Next::Dropped => {}
                Next::Empty => return out,
                Next::Broken => panic!("broken"),
            }
        }
    }

    #[test]
    fn frames_in_order_with_wrap_and_padding() {
        let mut m = Mem::new(MIN_DATA_BITS);
        let ch = m.chan();
        let d = ch.tx();
        let (mut w, mut r) = (Writer::new(), Reader::new());
        let mut sent = Vec::new();
        let mut got = Vec::new();
        for i in 0..20_000usize {
            let len = [60, 1514, 9000, MAX_FRAME, 61, 4095][i % 6];
            let f = frame(len, i as u8);
            let mut hdr = [0u8; HDR_SIZE];
            hdr[0] = i as u8;
            if !w.write(&d, &f, &hdr) {
                got.extend(read_all(&mut r, &d));
                assert!(w.write(&d, &f, &hdr), "room after the reader drained");
            }
            sent.push((f, hdr));
        }
        got.extend(read_all(&mut r, &d));
        assert_eq!(got.len(), sent.len());
        assert!(got == sent);
    }

    #[test]
    fn writer_never_overwrites_unread_frames() {
        let mut m = Mem::new(MIN_DATA_BITS);
        let ch = m.chan();
        let d = ch.rx();
        let (mut w, mut r) = (Writer::new(), Reader::new());
        // Fill without reading, then check every frame is intact.
        let mut sent = Vec::new();
        let mut i = 0u8;
        while w.write(&d, &frame(7000, i), &[i; HDR_SIZE]) {
            sent.push((frame(7000, i), [i; HDR_SIZE]));
            i = i.wrapping_add(1);
        }
        assert!(sent.len() > 100);
        let got = read_all(&mut r, &d);
        assert!(got == sent);
        // Descriptor-bound: many tiny frames.
        let mut n = 0;
        while w.write(&d, &[1], &[0; HDR_SIZE]) {
            n += 1;
        }
        assert_eq!(n, DESCS);
    }

    #[test]
    fn hostile_producer_breaks_only_the_channel() {
        let mut m = Mem::new(MIN_DATA_BITS);
        let ch = m.chan();
        let d = ch.rx();
        let idx = unsafe { &*d.idx };
        let desc = |i: usize| unsafe { &*d.descs.add(i) };
        // A length past the area's end.
        desc(0).len.store((1 << MIN_DATA_BITS) as u32 + 1, Ordering::Relaxed);
        idx.head.store(1, Ordering::Release);
        let mut r = Reader::new();
        assert!(matches!(r.next(&d), Next::Broken));
        assert!(matches!(r.next(&d), Next::Broken));
        // Padding at offset 0.
        let mut r = Reader::new();
        desc(0).len.store(0, Ordering::Relaxed);
        assert!(matches!(r.next(&d), Next::Broken));
        // A head beyond the ring.
        let mut r = Reader::new();
        idx.head.store(DESCS as u32 + 1, Ordering::Release);
        assert!(matches!(r.next(&d), Next::Broken));
        // Reserved flags: dropped, the ring goes on.
        let mut r = Reader::new();
        desc(0).len.store(100, Ordering::Relaxed);
        desc(0).flags.store(1, Ordering::Relaxed);
        desc(1).len.store(100, Ordering::Relaxed);
        desc(1).flags.store(0, Ordering::Relaxed);
        idx.head.store(2, Ordering::Release);
        assert!(matches!(r.next(&d), Next::Dropped));
        assert!(matches!(r.next(&d), Next::Frame(f, _) if f.len() == 100));
        r.release(&d);
        assert!(matches!(r.next(&d), Next::Empty));
        // A length changed between next and release does not move the
        // cursor: the next frame is still found where the writer put it.
        let mut m = Mem::new(MIN_DATA_BITS);
        let ch = m.chan();
        let d = ch.rx();
        let (mut w, mut r) = (Writer::new(), Reader::new());
        assert!(w.write(&d, &frame(100, 1), &[0; HDR_SIZE]) && w.write(&d, &frame(200, 2), &[0; HDR_SIZE]));
        assert!(matches!(r.next(&d), Next::Frame(..)));
        unsafe { &*d.descs }.len.store(5000, Ordering::Relaxed);
        r.release(&d);
        assert!(matches!(r.next(&d), Next::Frame(f, _) if f == &frame(200, 2)[..]));
    }

    #[test]
    fn hostile_consumer_gives_no_room() {
        let mut m = Mem::new(MIN_DATA_BITS);
        let ch = m.chan();
        let d = ch.tx();
        let mut w = Writer::new();
        assert!(w.write(&d, &[0; 100], &[0; HDR_SIZE]));
        let idx = unsafe { &*d.idx };
        // A tail ahead of our head.
        idx.tail.store(5, Ordering::Release);
        assert!(!w.fits(&d, 1));
        assert_eq!(w.pending(&d), DESCS as u32);
        idx.tail.store(1, Ordering::Release);
        assert!(w.fits(&d, 1));
    }

    #[test]
    fn offer_is_clamped() {
        let mut o = Offer::plain([2, 0, 0, 0, 0, 1]);
        assert_eq!(o.checked().unwrap().tx_gso_mask, 0);
        o.tx_gso_mask = u32::MAX;
        o.tx_csum = 7;
        o.tx_gso_max = u32::MAX;
        o.tx_mss_min = 1;
        o.tx_mss_max = 9000;
        o.tx_hdr_max = 128;
        let c = o.checked().unwrap();
        assert_eq!((c.tx_gso_mask, c.tx_csum, c.tx_gso_max), (0x12, 1, MAX_FRAME as u32));
        // The plain-frame bound does not bound GSO frames.
        o.tx_frame_max = 1518;
        o.tx_gso_max = 64000;
        assert_eq!(o.checked().unwrap().tx_gso_max, 64000);
        let mut hdr = [0u8; HDR_SIZE];
        hdr[1] = 1;
        hdr[2..4].copy_from_slice(&54u16.to_le_bytes());
        hdr[4..6].copy_from_slice(&1448u16.to_le_bytes());
        assert!(c.takes_gso(60000, &hdr));
        hdr[1] = 3;
        assert!(!c.takes_gso(60000, &hdr), "UDP is not offered");
        o.abi = 2;
        assert!(o.checked().is_none());
        let mut o = Offer::plain([2, 0, 0, 0, 0, 1]);
        o.tx_frame_min = 100;
        assert!(o.checked().is_none(), "a minimum above 60 cannot send short frames");
    }
}

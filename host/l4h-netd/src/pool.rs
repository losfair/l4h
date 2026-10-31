//! Frames netd holds: for a guest whose RX ring is full, or for an uplink
//! NIC without a free TX buffer.  They live in one pool of fixed chunks,
//! sized here, each frame a chain of chunks; a backlog is a FIFO of such
//! frames.  Every backlog takes from the same pool, so its limits are
//! checks against it, and running out drops a frame instead of growing a
//! heap (DESIGN.md §10).  Free of seL4 dependencies, like offload.rs.

use core::ptr::addr_of_mut;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::offload::HDR_SIZE;

pub const CHUNK: usize = 2048;
/// Bytes held in all backlogs, guest ports' and NICs' together.
pub const BYTES: usize = 16 << 20;
pub const CHUNKS: usize = BYTES / CHUNK;
const NIL: u16 = u16::MAX;
const _: () = assert!(CHUNKS < NIL as usize);

/// A held frame's length, header and successor in its FIFO, kept with
/// its first chunk.
#[derive(Clone, Copy)]
struct Meta {
    len: u32,
    hdr: [u8; HDR_SIZE],
    next: u16,
}

pub struct Pool {
    data: [[u8; CHUNK]; CHUNKS],
    /// The next chunk of a frame, or of the free list.
    next: [u16; CHUNKS],
    meta: [Meta; CHUNKS],
    free: u16,
    nfree: usize,
}

/// Zero, so that it takes no room in the image (.bss); take() links it.
static mut POOL: Pool = Pool {
    data: [[0; CHUNK]; CHUNKS],
    next: [0; CHUNKS],
    meta: [Meta { len: 0, hdr: [0; HDR_SIZE], next: 0 }; CHUNKS],
    free: 0,
    nfree: 0,
};
static TAKEN: AtomicBool = AtomicBool::new(false);

/// Frames held for one port or NIC, oldest first.
#[derive(Clone, Copy)]
pub struct Fifo {
    head: u16,
    tail: u16,
    pub frames: usize,
    pub chunks: usize,
}

impl Fifo {
    pub const EMPTY: Fifo = Fifo { head: NIL, tail: NIL, frames: 0, chunks: 0 };

    pub fn is_empty(&self) -> bool {
        self.head == NIL
    }
}

/// A frame to copy out: in one piece, or held in the pool.
pub trait Frame {
    fn len(&self) -> usize;
    /// Copy the frame to `dst`, which is len() bytes long.
    fn copy_to(&self, dst: &mut [u8]);
}

impl Frame for [u8] {
    fn len(&self) -> usize {
        <[u8]>::len(self)
    }

    fn copy_to(&self, dst: &mut [u8]) {
        dst.copy_from_slice(self);
    }
}

/// The frame at the front of a FIFO.
pub struct Held<'a> {
    pool: &'a Pool,
    first: u16,
    pub hdr: [u8; HDR_SIZE],
}

impl Frame for Held<'_> {
    fn len(&self) -> usize {
        self.pool.meta[self.first as usize].len as usize
    }

    fn copy_to(&self, dst: &mut [u8]) {
        let mut c = self.first;
        for part in dst.chunks_mut(CHUNK) {
            part.copy_from_slice(&self.pool.data[c as usize][..part.len()]);
            c = self.pool.next[c as usize];
        }
    }
}

/// The pool, all chunks free.  There is one, taken once.
pub fn take() -> &'static mut Pool {
    assert!(!TAKEN.swap(true, Ordering::Relaxed), "netd: frame pool taken twice");
    let p = unsafe { &mut *addr_of_mut!(POOL) };
    for (i, n) in p.next.iter_mut().enumerate() {
        *n = if i + 1 < CHUNKS { (i + 1) as u16 } else { NIL };
    }
    p.free = 0;
    p.nfree = CHUNKS;
    p
}

impl Pool {
    /// Append a frame to `q` if it fits: in `q`'s limits (frames, chunks)
    /// and in the chunks free.
    pub fn push(&mut self, q: &mut Fifo, frame: &[u8], hdr: &[u8; HDR_SIZE], max_frames: usize, max_chunks: usize) -> bool {
        let need = frame.len().div_ceil(CHUNK).max(1);
        if q.frames >= max_frames || q.chunks + need > max_chunks || need > self.nfree {
            return false;
        }
        // The free list's first `need` chunks are already a chain.
        let first = self.free;
        let mut c = first;
        for (k, part) in frame.chunks(CHUNK).enumerate() {
            self.data[c as usize][..part.len()].copy_from_slice(part);
            if k + 1 < need {
                c = self.next[c as usize];
            }
        }
        self.free = self.next[c as usize];
        self.next[c as usize] = NIL;
        self.nfree -= need;
        self.meta[first as usize] = Meta { len: frame.len() as u32, hdr: *hdr, next: NIL };
        if q.tail == NIL {
            q.head = first;
        } else {
            self.meta[q.tail as usize].next = first;
        }
        q.tail = first;
        q.frames += 1;
        q.chunks += need;
        true
    }

    pub fn front(&self, q: &Fifo) -> Option<Held<'_>> {
        (q.head != NIL).then(|| Held { pool: self, first: q.head, hdr: self.meta[q.head as usize].hdr })
    }

    /// Drop the frame at the front of `q`, if any.
    pub fn pop(&mut self, q: &mut Fifo) {
        let first = q.head;
        if first == NIL {
            return;
        }
        let m = self.meta[first as usize];
        let need = (m.len as usize).div_ceil(CHUNK).max(1);
        let mut last = first;
        for _ in 1..need {
            last = self.next[last as usize];
        }
        self.next[last as usize] = self.free;
        self.free = first;
        self.nfree += need;
        q.head = m.next;
        if q.head == NIL {
            q.tail = NIL;
        }
        q.frames -= 1;
        q.chunks -= need;
    }

    /// Drop every frame of `q`.
    pub fn clear(&mut self, q: &mut Fifo) {
        while !q.is_empty() {
            self.pop(q);
        }
    }
}

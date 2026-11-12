//! Randomised test of the uplink channel (host/l4h-host/src/uplink.rs),
//! the one ABI between netd and the NIC drivers, against hostile peers:
//!
//! - an honest producer and consumer on two threads, with random frame
//!   sizes and random pauses, against a model: every frame arrives, in
//!   order, intact;
//! - a hostile producer that writes random descriptors and heads, and
//!   rewrites the data area while the consumer reads it: the consumer
//!   never returns a frame outside the data area, never panics, and stops
//!   for good once the producer breaks the protocol;
//! - a hostile consumer that writes random tails: the producer never
//!   writes outside the data area, never panics, and gives no room while
//!   the tail is broken.
//!
//! Debug build (overflow checks): usage fuzz-uplink [ITERATIONS].

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::thread;

use l4h_host::net::{HDR_SIZE, MAX_FRAME};
use l4h_host::uplink::{self, Channel, Dir, Next, Reader, Writer};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

/// A channel in a buffer with guard bytes around it.
struct Mem {
    buf: Vec<u64>,
    bits: u32,
}

const GUARD: usize = 1 << 16;

impl Mem {
    /// A fresh (zeroed) channel, as root gives one.
    fn new(bits: u32) -> Self {
        let mut buf = vec![0xa5a5_a5a5_a5a5_a5a5; (uplink::channel_size(bits) + 2 * GUARD) / 8];
        buf[GUARD / 8..(GUARD + uplink::channel_size(bits)) / 8].fill(0);
        Mem { buf, bits }
    }
    fn chan(&mut self) -> Channel {
        unsafe { Channel::new((self.buf.as_mut_ptr() as *mut u8).add(GUARD), self.bits) }
    }
    fn guards_intact(&self) -> bool {
        let words = GUARD / 8;
        let n = self.buf.len();
        self.buf[..words].iter().chain(&self.buf[n - words..]).all(|&w| w == 0xa5a5_a5a5_a5a5_a5a5)
    }
}

fn inside(d: &Dir, f: &[u8]) -> bool {
    let (lo, hi) = (d.data as usize, d.data as usize + d.size);
    f.as_ptr() as usize >= lo && f.as_ptr() as usize + f.len() <= hi
}

fn frame_of(seq: u64, len: usize) -> Vec<u8> {
    let mut f = vec![0u8; len];
    f[..8.min(len)].copy_from_slice(&seq.to_le_bytes()[..8.min(len)]);
    for (i, b) in f.iter_mut().enumerate().skip(8) {
        *b = (seq as u8).wrapping_add(i as u8);
    }
    f
}

fn hdr_of(seq: u64) -> [u8; HDR_SIZE] {
    let mut h = [0u8; HDR_SIZE];
    h[4..12].copy_from_slice(&seq.to_le_bytes());
    h
}

/// Honest peers on two threads: what the consumer reads is what the
/// producer wrote, in order.
fn honest(seed: u64, frames: u64) {
    let mut mem = Mem::new(uplink::MIN_DATA_BITS);
    let chan = mem.chan();
    let base = chan.base as usize;
    let done = Arc::new(AtomicBool::new(false));
    let producer = {
        let done = done.clone();
        thread::spawn(move || {
            let chan = unsafe { Channel::new(base as *mut u8, uplink::MIN_DATA_BITS) };
            let d = chan.tx();
            let mut w = Writer::new();
            let mut rng = Rng(seed | 1);
            let mut seq = 0;
            while seq < frames {
                let len = match rng.below(4) {
                    0 => 1 + rng.below(64) as usize,
                    1 => 60 + rng.below(1500) as usize,
                    2 => MAX_FRAME - rng.below(64) as usize,
                    _ => 1 + rng.below(MAX_FRAME as u64) as usize,
                };
                if w.write(&d, &frame_of(seq, len), &hdr_of(seq)) {
                    seq += 1;
                } else {
                    thread::yield_now();
                }
            }
            done.store(true, Ordering::Release);
        })
    };
    let d = chan.tx();
    let mut r = Reader::new();
    let mut want = 0;
    let mut rng = Rng(seed.rotate_left(17) | 1);
    while want < frames {
        match r.next(&d) {
            Next::Frame(f, h) => {
                assert!(inside(&d, f));
                let seq = u64::from_le_bytes(h[4..12].try_into().unwrap());
                assert_eq!(seq, want, "out of order");
                assert!(f == &frame_of(seq, f.len())[..], "frame {seq} damaged");
                r.release(&d);
                want += 1;
                if rng.below(64) == 0 {
                    thread::yield_now();
                }
            }
            Next::Empty => thread::yield_now(),
            Next::Dropped => panic!("dropped at frame {want}"),
            Next::Broken => { let i = unsafe { &*d.idx }; panic!("broken at frame {want}: head {} tail {}", i.head.load(Ordering::Relaxed), i.tail.load(Ordering::Relaxed)) }
        }
    }
    producer.join().unwrap();
    assert!(done.load(Ordering::Acquire));
    assert!(mem.guards_intact());
}

/// A producer that writes anything: the consumer's frames are inside the
/// area, and a broken ring stays broken.
fn hostile_producer(seed: u64, steps: u64) {
    let mut mem = Mem::new(uplink::MIN_DATA_BITS);
    let chan = mem.chan();
    let d = chan.rx();
    let idx = unsafe { &*d.idx };
    let base = chan.base as usize;
    let stop = Arc::new(AtomicBool::new(false));
    // A second thread scribbles over the data area and descriptors while
    // the consumer reads.
    let scribbler = {
        let stop = stop.clone();
        thread::spawn(move || {
            let mut rng = Rng(seed ^ 0x9e37_79b9_7f4a_7c15);
            let size = uplink::channel_size(uplink::MIN_DATA_BITS);
            while !stop.load(Ordering::Relaxed) {
                let off = rng.below((size - uplink::PAGE) as u64 / 4) as usize * 4 + uplink::PAGE;
                let w = unsafe { &*((base + off) as *const AtomicU32) };
                w.store(rng.next() as u32, Ordering::Relaxed);
            }
        })
    };
    let mut r = Reader::new();
    let mut rng = Rng(seed | 1);
    let mut broken = false;
    for _ in 0..steps {
        match rng.below(8) {
            0 => idx.head.store(rng.next() as u32, Ordering::Release),
            1 => idx.head.store(idx.tail.load(Ordering::Relaxed).wrapping_add(rng.below(4) as u32), Ordering::Release),
            _ => {}
        }
        match r.next(&d) {
            Next::Frame(f, _) => {
                assert!(!broken, "a frame after the ring broke");
                assert!(inside(&d, f) && !f.is_empty() && f.len() <= MAX_FRAME);
                // Read every byte, as netd's copy does.
                let _ = f.iter().fold(0u8, |a, &b| a ^ b);
                r.release(&d);
            }
            Next::Broken => broken = true,
            Next::Dropped | Next::Empty => assert!(!broken),
        }
        assert_eq!(broken, r.is_broken());
    }
    stop.store(true, Ordering::Relaxed);
    scribbler.join().unwrap();
    assert!(mem.guards_intact());
}

/// A consumer that writes any tail: the producer writes only inside the
/// area, and never into room a broken tail claims.
fn hostile_consumer(seed: u64, steps: u64) {
    let mut mem = Mem::new(uplink::MIN_DATA_BITS);
    let chan = mem.chan();
    let d = chan.tx();
    let idx = unsafe { &*d.idx };
    let mut w = Writer::new();
    let mut rng = Rng(seed | 1);
    let mut head = 0u32;
    for _ in 0..steps {
        match rng.below(4) {
            0 => idx.tail.store(rng.next() as u32, Ordering::Release),
            1 => idx.tail.store(head.wrapping_sub(rng.below(uplink::DESCS as u64 + 4) as u32), Ordering::Release),
            _ => {}
        }
        let tail = idx.tail.load(Ordering::Acquire);
        let used = head.wrapping_sub(tail);
        let len = 1 + rng.below(MAX_FRAME as u64) as usize;
        if let Some(buf) = w.reserve(&d, len) {
            assert!(used <= uplink::DESCS as u32, "room while the tail is broken");
            assert!(inside(&d, buf) && buf.len() == len);
            buf.fill(0x5a);
            w.commit(&d, len, &[0; HDR_SIZE]);
        }
        head = idx.head.load(Ordering::Relaxed);
    }
    assert!(mem.guards_intact());
}

fn main() {
    let n: u64 = std::env::args().nth(1).and_then(|a| a.parse().ok()).unwrap_or(200_000);
    let seed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64;
    println!("fuzz-uplink: seed {seed:#x}, {n} iterations");
    for k in 0..4 {
        honest(seed.wrapping_add(k), n / 4);
        hostile_producer(seed.wrapping_add(k), n);
        hostile_consumer(seed.wrapping_add(k), n);
    }
    println!("fuzz-uplink: ok");
}

// Run with tests/run-ringtest.sh: the message rings of partitions'
// channels (l4h_partition::MsgRing, DESIGN.md §11.4) on the host.
#[path = "../host/l4h-partition/src/lib.rs"]
#[allow(unused_attributes, dead_code)]
mod part;
use part::*;
use std::sync::atomic::{AtomicBool, Ordering::*};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// A ring of `size` bytes, as (writer, reader).
fn ring(size: u64) -> (MsgRing, MsgReader) {
    let mem: &'static mut [u64] = Box::leak(vec![0u64; size as usize / 8].into_boxed_slice());
    let va = mem.as_ptr() as usize;
    let (tx, _) = MsgRing::pair(va, size, 0, 1);
    let (_, rx) = MsgRing::pair(va, size, 1, 0);
    (tx, MsgReader::new(rx))
}

fn byte(seq: u64, i: usize) -> u8 {
    (seq.wrapping_mul(0x9e3779b97f4a7c15) >> 24) as u8 ^ (i as u8).wrapping_mul(31)
}

fn frame(seq: u64, n: usize) -> Vec<u8> {
    let mut f: Vec<u8> = (0..n).map(|i| byte(seq, i)).collect();
    f[..8].copy_from_slice(&seq.to_le_bytes());
    f[8..16].copy_from_slice(&(n as u64).to_le_bytes());
    f
}

fn intact(buf: &[u8]) -> bool {
    let seq = u64::from_le_bytes(buf[..8].try_into().unwrap());
    let n = u64::from_le_bytes(buf[8..16].try_into().unwrap()) as usize;
    n == buf.len() && (16..n).all(|i| buf[i] == byte(seq, i))
}

#[test]
fn a_message_the_writer_is_overwriting_is_lost_not_read() {
    let (tx, mut rx) = ring(64 << 10);
    let cap = tx.cap;
    let n = 1000;
    let room = (8 + n as u64).next_multiple_of(8);
    // Fill the ring until the next message no longer fits before its
    // end: the head is still less than a lap ahead of the reader.
    let mut seq = 1;
    while tx.head() + room < cap {
        tx.send(MSG_FRAME, &[&frame(seq, n)]);
        seq += 1;
    }
    let head = tx.head();
    assert!(head <= rx.tail + cap);
    // The writer's next message, half written and not yet published:
    // padding to the end of the ring, then the message's header (the
    // same length) and the start of its payload at the ring's start, over
    // the reader's first message.
    let start = if head % cap + room > cap { head + (cap - head % cap) } else { head };
    assert!(start + room > rx.tail + cap);
    let mut next = (8 + n as u32).to_le_bytes().to_vec();
    next.extend(MSG_FRAME.to_le_bytes());
    next.extend(&frame(seq, n)[..n / 2]);
    for (i, &b) in next.iter().enumerate() {
        let off = start + i as u64;
        unsafe { ((tx.va + MSG_RING_HEADER + (off % cap) as usize) as *mut u8).write_volatile(b) };
    }
    let mut buf = vec![0u8; n];
    let mut lost = 0;
    while let Some((ty, got)) = rx.recv(&mut buf, &mut lost) {
        assert_eq!(ty, MSG_FRAME);
        assert!(intact(&buf[..got]), "a message read while it was overwritten");
    }
    assert!(lost > 0, "nothing reported lost");
}

#[test]
fn messages_arrive_whole_and_wakeups_are_not_lost() {
    let (tx, mut rx) = ring(LINK_CHANNEL_SIZE);
    let stop = Arc::new(AtomicBool::new(false));
    let reader = {
        let stop = stop.clone();
        std::thread::spawn(move || {
            let mut buf = vec![0u8; LINK_FRAME_MAX];
            let (mut ok, mut lost, mut stuck, mut s) = (0u64, 0u64, 0u64, 1u64);
            while !stop.load(Relaxed) {
                match rx.recv(&mut buf, &mut lost) {
                    Some((_, n)) => {
                        assert!(intact(&buf[..n]), "a torn message");
                        ok += 1;
                        s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
                        if s >> 52 == 0 {
                            // Fall behind: the writer laps the reader.
                            std::thread::sleep(Duration::from_micros(500));
                        }
                    }
                    None if rx.arm() => {
                        let t = Instant::now();
                        std::thread::park_timeout(Duration::from_millis(200));
                        if t.elapsed() >= Duration::from_millis(200) && !rx.is_empty() && !stop.load(Relaxed) {
                            stuck += 1;
                        }
                    }
                    None => {}
                }
            }
            (ok, lost, stuck)
        })
    };
    let rt = reader.thread().clone();
    let start = Instant::now();
    let (mut seq, mut s) = (1u64, 7u64);
    while start.elapsed() < Duration::from_secs(3) {
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
        tx.send(MSG_FRAME, &[&frame(seq, 16 + (s >> 33) as usize % (LINK_FRAME_MAX - 16))]);
        seq += 1;
        if tx.take_wake() {
            rt.unpark();
        }
        if s >> 54 == 0 {
            // Go idle: the reader arms and sleeps.
            std::thread::sleep(Duration::from_micros(300));
        }
    }
    stop.store(true, Relaxed);
    rt.unpark();
    let (ok, lost, stuck) = reader.join().unwrap();
    println!("{} sent, {} read whole, {} bytes lost", seq - 1, ok, lost);
    assert!(ok > 0 && lost > 0, "the reader was never lapped");
    assert_eq!(stuck, 0, "lost wakeups");
}

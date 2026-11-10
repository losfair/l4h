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

#[test]
fn a_header_the_peer_writes_over_does_not_move_the_writer() {
    let (tx, mut rx) = ring(64 << 10);
    let mut buf = vec![0u8; 256];
    let mut lost = 0;
    tx.send(MSG_FRAME, &[&frame(1, 100)]);
    let head = tx.head();
    // The peer writes a count of its own, unaligned and far ahead: the
    // writer's next message goes after its own last one, and its count
    // replaces the peer's.
    unsafe { ((tx.va + MSG_RING_HEAD) as *mut u64).write_volatile(u64::MAX - 3) };
    tx.send(MSG_FRAME, &[&frame(2, 100)]);
    assert_eq!(tx.head(), head + (8 + 100u64).next_multiple_of(8));
    for seq in 1..=2u64 {
        let (ty, got) = rx.recv(&mut buf, &mut lost).expect("message");
        assert_eq!((ty, got), (MSG_FRAME, 100));
        assert!(intact(&buf[..got]) && buf[..8] == seq.to_le_bytes());
    }
    assert_eq!(lost, 0);
}

/// Write the peer's count of bytes written over the ring's header.
fn set_head(tx: &MsgRing, head: u64) {
    unsafe { ((tx.va + MSG_RING_HEAD) as *mut u64).write_volatile(head) };
}

#[test]
fn a_count_that_is_not_aligned_is_a_broken_writer() {
    let (tx, mut rx) = ring(64 << 10);
    let mut buf = vec![0u8; 256];
    let mut lost = 0;
    tx.send(MSG_FRAME, &[&frame(1, 100)]);
    let head = tx.head();
    // The peer's count is not a multiple of 8: what it covers is lost,
    // also the message before it, and the reader waits there.
    set_head(&tx, head + 5);
    assert_eq!(rx.recv(&mut buf, &mut lost), None);
    assert_eq!(lost, head + 5);
    assert!(rx.is_empty());
    assert_eq!(rx.recv(&mut buf, &mut lost), None);
    assert_eq!(lost, head + 5);
    // The writer's next count is aligned again (its own): the reader goes
    // on from it, without reading a header at its unaligned position.
    tx.send(MSG_FRAME, &[&frame(2, 100)]);
    assert_eq!(rx.recv(&mut buf, &mut lost), None);
    assert!(rx.is_empty() && rx.tail % 8 == 0);
    tx.send(MSG_FRAME, &[&frame(3, 100)]);
    let (ty, got) = rx.recv(&mut buf, &mut lost).expect("message");
    assert_eq!((ty, got), (MSG_FRAME, 100));
    assert!(intact(&buf[..got]) && buf[..8] == 3u64.to_le_bytes());
}

#[test]
fn a_reader_that_starts_at_an_unaligned_count_reads_no_header_there() {
    let mem: &'static mut [u64] = Box::leak(vec![0u64; (64usize << 10) / 8].into_boxed_slice());
    let va = mem.as_ptr() as usize;
    // The peer left an odd count before this side started.
    unsafe { ((va + MSG_RING_HEAD) as *mut u64).write_volatile(1001) };
    let (tx, _) = MsgRing::pair(va, 64 << 10, 0, 1);
    let (_, rxr) = MsgRing::pair(va, 64 << 10, 1, 0);
    let mut rx = MsgReader::new(rxr);
    assert_eq!(rx.tail, 1001);
    // What looks like a message at the reader's unaligned position.
    for (i, b) in 16u32.to_le_bytes().into_iter().chain(MSG_FRAME.to_le_bytes()).enumerate() {
        unsafe { ((va + MSG_RING_HEADER + 1001 + i) as *mut u8).write_volatile(b) };
    }
    set_head(&tx, 1001 + 24 + 7);
    let mut buf = vec![0u8; 256];
    let mut lost = 0;
    assert_eq!(rx.recv(&mut buf, &mut lost), None);
    assert!(lost > 0 && rx.tail % 8 == 0 && rx.is_empty());
}

#[test]
fn padding_after_padding_is_not_read_record_by_record() {
    let (tx, mut rx) = ring(64 << 10);
    // The peer fills its ring with padding records of 8 bytes and
    // publishes as many as a reader may be behind.
    let n = (tx.cap - 2 * MsgRing::max_room(tx.cap)) / 8;
    for i in 0..n {
        unsafe {
            ((tx.va + MSG_RING_HEADER + 8 * i as usize) as *mut u32).write_volatile(8);
            ((tx.va + MSG_RING_HEADER + 8 * i as usize + 4) as *mut u32).write_volatile(MSG_PAD);
        }
    }
    set_head(&tx, 8 * n);
    let mut buf = vec![0u8; 256];
    let mut lost = 0;
    // One call reads two of them and gives up on the rest.
    assert_eq!(rx.recv(&mut buf, &mut lost), None);
    assert_eq!(lost, 8 * n - 16);
    assert!(rx.is_empty());
}

#[test]
fn padding_at_the_end_of_the_ring_is_skipped() {
    let (tx, mut rx) = ring(64 << 10);
    let mut buf = vec![0u8; 2048];
    let mut lost = 0;
    // Three laps, read as they are written: every message arrives, also
    // those after the padding at the ring's end.
    let mut seq = 1;
    while tx.head() < 3 * tx.cap {
        tx.send(MSG_FRAME, &[&frame(seq, 1000 + seq as usize % 7)]);
        let (ty, got) = rx.recv(&mut buf, &mut lost).expect("message");
        assert_eq!(ty, MSG_FRAME);
        assert!(intact(&buf[..got]) && buf[..8] == seq.to_le_bytes());
        seq += 1;
    }
    assert_eq!(rx.recv(&mut buf, &mut lost), None);
    assert_eq!(lost, 0);
}

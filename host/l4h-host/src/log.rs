//! Bounded host diagnostics shared by root and every host component.
//!
//! The slots are `ring`'s. Readers skip unavailable records and report the
//! gap.

use core::fmt::{self, Write};
use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, Ordering::SeqCst};

use crate::ring::{self, Buf, Entry};

pub const CAPACITY: usize = 256;
pub const TEXT_SIZE: usize = 480;
const WORDS: usize = TEXT_SIZE / 8;
pub const VA: usize = 0x1002_0000;
pub const PAGES: usize = core::mem::size_of::<Ring>() / 4096;
pub const FRAME_RADIX: usize = PAGES.next_power_of_two().trailing_zeros() as usize;

/// Page-aligned so root can share these image frames without sharing any
/// other root data. Its page-rounded size includes the final padding.
#[repr(C, align(4096))]
pub struct Ring {
    start_ticks: AtomicU64,
    hz: AtomicU64,
    ring: ring::Ring<CAPACITY, WORDS>,
}

impl Ring {
    pub const fn new() -> Self {
        Self { start_ticks: AtomicU64::new(0), hz: AtomicU64::new(0), ring: ring::Ring::new() }
    }

    /// Root sets the common clock before starting any component.
    pub fn set_clock(&self, start_ticks: u64, hz: u64) {
        self.start_ticks.store(start_ticks, SeqCst);
        self.hz.store(hz.max(1), SeqCst);
    }

    pub fn write(&self, ticks: u64, source: u32, args: fmt::Arguments<'_>) {
        let us = ticks.saturating_sub(self.start_ticks.load(SeqCst)) as u128 * 1_000_000
            / self.hz.load(SeqCst).max(1) as u128;
        let mut text = Text::new();
        let _ = write!(text, "[{:>6}.{:06}] [{:#x}] {}", us / 1_000_000, us % 1_000_000, source, args);
        text.finish();
        let seq = self.ring.claim(1);
        self.ring.commit(seq, ticks, 0, text.len, &text.buf);
    }

    /// Read whole lines, without consuming them. `end == 0` snapshots the
    /// current head; subsequent reads can use the returned end to finish
    /// that snapshot even while new messages arrive. Cursor 0 starts at
    /// boot; lost counts overwritten, dropped and not-yet-committed records.
    pub fn read(&self, cursor: u64, end: u64, out: &mut [u8]) -> Option<Read> {
        // One snapshot of head: `oldest` must come from the same value, or
        // a writer flipping head between a huge and a small value could put
        // `next` far below `end` and spin the loop below (a reader bounds it
        // to the ring's own CAPACITY of records).
        let head = self.ring.head();
        let end = if end == 0 { head } else { end.min(head) };
        if cursor > end { return None; }
        let oldest = ring::Ring::<CAPACITY, WORDS>::oldest_at(head);
        let mut next = cursor.max(oldest).min(end);
        let mut lost = next - cursor;
        let mut len = 0;
        while next < end {
            next.checked_add(1)?.checked_mul(2)?;
            match self.ring.get(next) {
                Entry::Ready(r) => {
                    let text = r.text();
                    if text.len() > out.len() - len { break; }
                    out[len..len + text.len()].copy_from_slice(text);
                    len += text.len();
                }
                _ => lost += 1,
            }
            next += 1;
        }
        Some(Read { next, len, lost, end })
    }
}

pub struct Read {
    pub next: u64,
    pub len: usize,
    pub lost: u64,
    pub end: u64,
}

struct Text {
    buf: Buf<WORDS>,
    len: usize,
    truncated: bool,
}

impl Text {
    const SUFFIX: &str = " [truncated]\n";
    fn new() -> Self { Self { buf: Buf::new(), len: 0, truncated: false } }
    fn finish(&mut self) {
        let suffix = if self.truncated { Self::SUFFIX.as_bytes() } else { b"\n" };
        self.buf.bytes_mut()[self.len..self.len + suffix.len()].copy_from_slice(suffix);
        self.len += suffix.len();
    }
}

impl Write for Text {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if self.truncated { return Ok(()); }
        let mut n = s.len().min(TEXT_SIZE - Self::SUFFIX.len() - self.len);
        while !s.is_char_boundary(n) { n -= 1; }
        self.buf.bytes_mut()[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        self.truncated = n < s.len();
        Ok(())
    }
}

static RING: AtomicPtr<Ring> = AtomicPtr::new(core::ptr::null_mut());
static SOURCE: AtomicU32 = AtomicU32::new(0);

/// Install this process's mapping before starting its secondary thread.
pub fn init(ring: &'static Ring, source: u32) {
    SOURCE.store(source, SeqCst);
    RING.store(core::ptr::from_ref(ring).cast_mut(), SeqCst);
}

pub fn record(args: fmt::Arguments<'_>) {
    let p = RING.load(SeqCst);
    if !p.is_null() {
        // init only accepts a mapping that lives for the process's lifetime.
        unsafe { &*p }.write(crate::ticks::now(), SOURCE.load(SeqCst), args);
    }
}

const _: () = assert!(VA >= crate::KEEPER_IPCBUF_VA + 4096
    && VA + PAGES * 4096 < crate::KEEPER_STACK_TOP - crate::KEEPER_STACK_SIZE);

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::{boxed::Box, string::String, sync::Arc, thread, vec::Vec};

    fn ring() -> Box<Ring> {
        let ring = Box::new(Ring::new());
        ring.set_clock(100, 1_000_000);
        ring
    }

    fn read(ring: &Ring, cursor: u64, end: u64) -> (Read, String) {
        let mut out = [0; 1984];
        let r = ring.read(cursor, end, &mut out).unwrap();
        let text = String::from_utf8(out[..r.len].to_vec()).unwrap();
        (r, text)
    }

    #[test]
    fn timestamps_cursors_and_independent_readers() {
        let ring = ring();
        assert_eq!(read(&ring, 0, 0).0.next, 0);
        ring.write(1_250_100, 0x500, format_args!("guest 2 kernel fault"));
        let (r, text) = read(&ring, 0, 0);
        assert_eq!(text, "[     1.250000] [0x500] guest 2 kernel fault\n");
        assert_eq!((r.next, r.lost, r.end), (1, 0, 1));
        assert_eq!(read(&ring, 0, 0).1, text);
        assert_eq!(read(&ring, 1, 0).1, "");
        assert!(ring.read(2, 0, &mut [0; 1984]).is_none());
        ring.write(200, 2, format_args!("next"));
        assert_eq!(read(&ring, 1, 1).1, "");
        assert!(read(&ring, 1, 0).1.ends_with("next\n"));
    }

    #[test]
    fn wrapped_snapshot_reports_loss_and_finishes() {
        let ring = ring();
        for i in 0..CAPACITY + 17 { ring.write(100, 0, format_args!("record {i}")); }
        let (mut cursor, mut end, mut lost, mut lines) = (0, 0, 0, Vec::new());
        loop {
            let (r, text) = read(&ring, cursor, end);
            assert!(r.next > cursor);
            cursor = r.next;
            end = r.end;
            lost += r.lost;
            lines.extend(text.lines().map(String::from));
            // New logging must not extend the snapshot being read.
            ring.write(100, 0, format_args!("later"));
            if cursor == end { break; }
        }
        assert_eq!(lost, 17);
        assert_eq!(lines.len(), CAPACITY);
        assert!(lines[0].ends_with("record 17"));
        assert!(lines.last().unwrap().ends_with("record 272"));
    }

    #[test]
    fn long_utf8_records_are_marked_and_never_split() {
        let ring = ring();
        ring.write(100, 0, format_args!("{}", "é".repeat(TEXT_SIZE)));
        let (r, text) = read(&ring, 0, 0);
        assert!(text.ends_with(Text::SUFFIX));
        assert!(text.len() <= TEXT_SIZE);
        let mut small = [0; 16];
        let short = ring.read(0, 0, &mut small).unwrap();
        assert_eq!((short.next, short.len, short.lost), (0, 0, 0));
        ring.write(100, 0, format_args!("following"));
        assert!(read(&ring, r.next, 0).1.ends_with("following\n"));
    }

    #[test]
    fn abandoned_writer_does_not_block_other_slots_or_readers() {
        let ring = ring();
        // Simulate a fault after claiming sequence 0 but before commit.
        ring.ring.head.store(1, SeqCst);
        ring.ring.slots[0].state.store(1, SeqCst);
        for i in 1..=CAPACITY * 3 { ring.write(100, 0, format_args!("record {i}")); }
        let mut cursor = 0;
        let mut lost = 0;
        let mut count = 0;
        loop {
            let (r, text) = read(&ring, cursor, 0);
            lost += r.lost;
            count += text.lines().count();
            cursor = r.next;
            if cursor == r.end { break; }
        }
        // The next writer of that slot took it back.
        assert_eq!(count, CAPACITY);
        assert_eq!(lost + count as u64, (CAPACITY * 3 + 1) as u64);
    }

    #[test]
    fn concurrent_writes_and_reads_never_return_torn_records() {
        let ring = Arc::new(Ring::new());
        ring.set_clock(0, 1_000_000);
        let writers: Vec<_> = (0..4).map(|id| {
            let ring = Arc::clone(&ring);
            thread::spawn(move || {
                for i in 0..3000 {
                    // Different lengths and contents catch mismatched length,
                    // prefix and payload from different generations of a slot.
                    let body = std::format!("{id}:{i}:{}", "x".repeat(i % 180));
                    ring.write(0, id, format_args!("{}|{}", body, body));
                }
            })
        }).collect();
        let (mut cursor, mut lost, mut count) = (0, 0, 0);
        loop {
            let (r, text) = read(&ring, cursor, 0);
            for line in text.lines() {
                let (_, body) = line.split_once("] ").unwrap();
                let (source, body) = body.split_once("] ").unwrap();
                let (a, b) = body.split_once('|').unwrap();
                assert_eq!(a, b);
                assert_eq!(source, std::format!("[0x{}", &a[..1]));
                count += 1;
            }
            cursor = r.next;
            lost += r.lost;
            if writers.iter().all(|w| w.is_finished()) && cursor == ring.ring.head() { break; }
            thread::yield_now();
        }
        for writer in writers { writer.join().unwrap(); }
        assert_eq!(count + lost, 12000);
        assert!(count > 0);
    }
}

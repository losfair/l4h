//! Bounded host diagnostics shared by root and every host component.
//!
//! Writers format on their stack before claiming a slot. They never wait
//! for another writer: a preempted or faulted writer can strand one slot,
//! but cannot stop logging on the other slots. Readers skip unavailable
//! records and report the gap. No allocation, IPC or seL4 invocation occurs.

use core::fmt::{self, Write};
use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, Ordering::SeqCst};

pub const CAPACITY: usize = 256;
pub const TEXT_SIZE: usize = 480;
pub const VA: usize = 0x1002_0000;
pub const PAGES: usize = core::mem::size_of::<Ring>() / 4096;
pub const FRAME_RADIX: usize = PAGES.next_power_of_two().trailing_zeros() as usize;

#[repr(C, align(64))]
struct Slot {
    // 0: unused; odd: being written; 2 * sequence + 2: committed.
    state: AtomicU64,
    len: AtomicU64,
    text: [AtomicU64; TEXT_SIZE / 8],
}

impl Slot {
    const fn new() -> Self {
        Self { state: AtomicU64::new(0), len: AtomicU64::new(0), text: [const { AtomicU64::new(0) }; TEXT_SIZE / 8] }
    }
}

/// Page-aligned so root can share these image frames without sharing any
/// other root data. Its page-rounded size includes the final padding.
#[repr(C, align(4096))]
pub struct Ring {
    head: AtomicU64,
    start_ticks: AtomicU64,
    hz: AtomicU64,
    slots: [Slot; CAPACITY],
}

impl Ring {
    pub const fn new() -> Self {
        Self {
            head: AtomicU64::new(0), start_ticks: AtomicU64::new(0), hz: AtomicU64::new(0),
            slots: [const { Slot::new() }; CAPACITY],
        }
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
        let seq = self.head.fetch_add(1, SeqCst);
        // Sequence exhaustion is not expected within a host's lifetime.
        let Some(state) = seq.checked_add(1).and_then(|n| n.checked_mul(2)) else { return };
        let slot = &self.slots[seq as usize % CAPACITY];
        let old = slot.state.load(SeqCst);
        if old & 1 != 0 || old >= state
            || slot.state.compare_exchange(old, state - 1, SeqCst, SeqCst).is_err()
        {
            return;
        }
        // Atomic payload and sequential consistency make a reader's two
        // state checks exclude torn records even on AArch64. A slot is
        // never stolen from a writer that has not committed it yet.
        for (dst, src) in slot.text.iter().zip(text.bytes.chunks_exact(8)) {
            dst.store(u64::from_le_bytes(src.try_into().unwrap()), SeqCst);
        }
        slot.len.store(text.len as u64, SeqCst);
        slot.state.store(state, SeqCst);
    }

    /// Read whole lines, without consuming them. `end == 0` snapshots the
    /// current head; subsequent reads can use the returned end to finish
    /// that snapshot even while new messages arrive. Cursor 0 starts at
    /// boot; lost counts overwritten, dropped and not-yet-committed records.
    pub fn read(&self, cursor: u64, end: u64, out: &mut [u8]) -> Option<Read> {
        let head = self.head.load(SeqCst);
        let end = if end == 0 { head } else { end.min(head) };
        if cursor > end { return None; }
        let mut next = cursor.max(head.saturating_sub(CAPACITY as u64)).min(end);
        let mut lost = next - cursor;
        let mut len = 0;
        while next < end {
            let slot = &self.slots[next as usize % CAPACITY];
            let state = (next + 1).checked_mul(2)?;
            let mut bytes = [0; TEXT_SIZE];
            let available = slot.state.load(SeqCst) == state;
            let n = slot.len.load(SeqCst) as usize;
            let available = available && n <= TEXT_SIZE;
            if available {
                for (dst, src) in bytes.chunks_exact_mut(8).zip(&slot.text) {
                    dst.copy_from_slice(&src.load(SeqCst).to_le_bytes());
                }
            }
            if available && slot.state.load(SeqCst) == state {
                if n > out.len() - len { break; }
                out[len..len + n].copy_from_slice(&bytes[..n]);
                len += n;
            } else {
                lost += 1;
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
    bytes: [u8; TEXT_SIZE],
    len: usize,
    truncated: bool,
}

impl Text {
    const SUFFIX: &str = " [truncated]\n";
    fn new() -> Self { Self { bytes: [0; TEXT_SIZE], len: 0, truncated: false } }
    fn finish(&mut self) {
        let suffix = if self.truncated { Self::SUFFIX.as_bytes() } else { b"\n" };
        self.bytes[self.len..self.len + suffix.len()].copy_from_slice(suffix);
        self.len += suffix.len();
    }
}

impl Write for Text {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if self.truncated { return Ok(()); }
        let mut n = s.len().min(TEXT_SIZE - Self::SUFFIX.len() - self.len);
        while !s.is_char_boundary(n) { n -= 1; }
        self.bytes[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
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
        ring.head.store(1, SeqCst);
        ring.slots[0].state.store(1, SeqCst);
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
        assert_eq!(count, CAPACITY - 1);
        assert_eq!(lost + count as u64, (CAPACITY * 3 + 1) as u64);
        assert_eq!(ring.slots[0].state.load(SeqCst), 1);
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
            if writers.iter().all(|w| w.is_finished()) && cursor == ring.head.load(SeqCst) { break; }
            thread::yield_now();
        }
        for writer in writers { writer.join().unwrap(); }
        assert_eq!(count + lost, 12000);
        assert!(count > 0);
    }
}

//! The slots behind the host log (`log`) and the serial ring (`serial`):
//! a bounded multi-writer ring of records, overwritten when full.
//!
//! Writers format on their stack before claiming a slot. They never wait
//! for another writer: a preempted or faulted writer can lose its own
//! record, and holds its slot for at most a lap of the ring. Readers never
//! block writers. No allocation, IPC or seL4 invocation occurs.
//!
//! `Ring<N, W>` has N slots of W words of text. It lives in memory shared
//! between tasks, and for `serial` between partitions that do not trust
//! each other: a reader indexes with `seq % N`, and clamps what it reads.

use core::sync::atomic::{AtomicU64, Ordering::SeqCst};

#[repr(C, align(64))]
pub(crate) struct Slot<const W: usize> {
    // 0: unused; odd: being written; 2 * sequence + 2: committed.
    pub(crate) state: AtomicU64,
    // Text bytes in the low 16 bits; the rest is the user's (`Meta`).
    meta: AtomicU64,
    ticks: AtomicU64,
    // `checksum` of the committed record.
    sum: AtomicU64,
    text: [AtomicU64; W],
}

impl<const W: usize> Slot<W> {
    const fn new() -> Self {
        Self {
            state: AtomicU64::new(0), meta: AtomicU64::new(0), ticks: AtomicU64::new(0),
            sum: AtomicU64::new(0), text: [const { AtomicU64::new(0) }; W],
        }
    }
}

/// What `commit` stores in `sum`, over the words as the slot holds them. A
/// writer of an earlier lap can still make one store into a later record
/// (`commit`). Each step maps its word one-to-one, so changing any one word
/// changes the result, and the reader drops the record.
fn checksum(seq: u64, ticks: u64, meta: u64, text: &[u64]) -> u64 {
    let mut h = seq ^ 0x9e37_79b9_7f4a_7c15;
    for w in [ticks, meta].into_iter().chain(text.iter().copied()) {
        h = (h ^ w).wrapping_mul(0x0000_0100_0000_01b3).rotate_left(29);
    }
    h
}

#[repr(C)]
pub struct Ring<const N: usize, const W: usize> {
    pub(crate) head: AtomicU64,
    pub(crate) slots: [Slot<W>; N],
}

/// A committed record, copied out of its slot: nothing here changes under
/// the reader, whatever a writer does afterwards.
pub struct Record<const W: usize> {
    pub ticks: u64,
    /// `meta` as passed to `commit`.
    pub meta: u64,
    len: usize,
    text: [u64; W],
}

impl<const W: usize> Record<W> {
    pub fn text(&self) -> &[u8] {
        // Any bytes are valid u8s, and `get` clamped len to the words.
        unsafe { core::slice::from_raw_parts(self.text.as_ptr().cast(), self.len) }
    }

    pub fn buf(&self) -> Buf<W> {
        Buf(self.text)
    }
}

/// What a reader finds at a sequence number.
pub enum Entry<const W: usize> {
    Ready(Record<W>),
    /// Claimed, and not committed yet. A writer that stranded the slot
    /// looks the same, so the reader decides how long to wait.
    Pending,
    /// Overwritten, or holding what no writer of that sequence could
    /// have put there.
    Gone,
}

/// The bytes a writer fills before it claims a slot.
pub struct Buf<const W: usize>(pub [u64; W]);

impl<const W: usize> Buf<W> {
    pub const SIZE: usize = W * 8;

    pub const fn new() -> Self { Self([0; W]) }

    pub fn bytes_mut(&mut self) -> &mut [u8] {
        // The same memory as u8s, whose alignment u64 satisfies.
        unsafe { core::slice::from_raw_parts_mut(self.0.as_mut_ptr().cast(), Self::SIZE) }
    }
}

impl<const N: usize, const W: usize> Ring<N, W> {
    pub const fn new() -> Self {
        Self { head: AtomicU64::new(0), slots: [const { Slot::new() }; N] }
    }

    pub fn head(&self) -> u64 {
        self.head.load(SeqCst)
    }

    /// The oldest sequence a reader can still find, given `head`, which
    /// it read once: a writer can move head at any time, and a reader
    /// whose bounds come from two reads of it can be sent far outside the
    /// ring's N records.
    pub fn oldest_at(&self, head: u64) -> u64 {
        head.saturating_sub(N as u64)
    }

    /// Claim `n` consecutive sequences, so that a reader finds them next
    /// to each other. Each must then be committed.
    pub fn claim(&self, n: u64) -> u64 {
        self.head.fetch_add(n, SeqCst)
    }

    /// Publish sequence `seq`, or drop the record if a writer of the same
    /// or a later lap has the slot. A writer of an earlier lap loses it, as
    /// it would have if it had committed: its record is a lap old, and the
    /// writer may be dead. If it is only slow, it sees that the slot is no
    /// longer its own and stops; the worst it can do is one more store,
    /// into a later record, which its checksum then shows a reader to be
    /// torn.
    pub fn commit(&self, seq: u64, ticks: u64, meta: u64, len: usize, text: &Buf<W>) {
        // Sequence exhaustion is not expected within a host's lifetime.
        let Some(state) = seq.checked_add(1).and_then(|n| n.checked_mul(2)) else { return };
        let slot = &self.slots[(seq % N as u64) as usize];
        let (mine, old) = (state - 1, slot.state.load(SeqCst));
        if old >= mine || slot.state.compare_exchange(old, mine, SeqCst, SeqCst).is_err() {
            return;
        }
        let ours = || slot.state.load(SeqCst) == mine;
        // Atomic payload and sequential consistency make a reader's two
        // state checks exclude records torn by this lap's writers even on
        // AArch64; `sum` excludes those an earlier lap's writer tore.
        for (dst, src) in slot.text.iter().zip(&text.0) {
            if !ours() {
                return;
            }
            dst.store(*src, SeqCst);
        }
        if !ours() {
            return;
        }
        slot.ticks.store(ticks, SeqCst);
        if !ours() {
            return;
        }
        let meta = meta << 16 | len as u64;
        slot.meta.store(meta, SeqCst);
        if !ours() {
            return;
        }
        slot.sum.store(checksum(seq, ticks, meta, &text.0), SeqCst);
        let _ = slot.state.compare_exchange(mine, state, SeqCst, SeqCst);
    }

    /// Copy out the record of sequence `seq`, without consuming it.
    pub fn get(&self, seq: u64) -> Entry<W> {
        let Some(want) = seq.checked_add(1).and_then(|n| n.checked_mul(2)) else { return Entry::Gone };
        let slot = &self.slots[(seq % N as u64) as usize];
        let state = slot.state.load(SeqCst);
        if state != want {
            return if state > want { Entry::Gone } else { Entry::Pending };
        }
        let meta = slot.meta.load(SeqCst);
        let ticks = slot.ticks.load(SeqCst);
        let len = (meta & 0xffff) as usize;
        if len > W * 8 {
            return Entry::Gone;
        }
        let mut text = [0; W];
        for (dst, src) in text.iter_mut().zip(&slot.text) {
            *dst = src.load(SeqCst);
        }
        let sum = slot.sum.load(SeqCst);
        if slot.state.load(SeqCst) != want || sum != checksum(seq, ticks, meta, &text) {
            return Entry::Gone;
        }
        Entry::Ready(Record { ticks, meta: meta >> 16, len, text })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A writer of an earlier lap, preempted between its ownership check
    /// and its store, stores into the record committed after it.
    #[test]
    fn a_stale_writers_store_does_not_tear_a_later_record() {
        let ring = Ring::<4, 4>::new();
        let mut buf = Buf::<4>::new();
        buf.bytes_mut()[..10].copy_from_slice(b"0123456789");
        let stray: [fn(&Slot<4>); 4] = [
            |s| s.meta.store(3, SeqCst),
            |s| s.ticks.store(7, SeqCst),
            |s| s.text[1].store(u64::from_le_bytes(*b"stalestr"), SeqCst),
            |s| s.sum.store(0, SeqCst),
        ];
        for (seq, store) in (4u64..).zip(stray) {
            ring.commit(seq, 5, 1, 10, &buf);
            let Entry::Ready(r) = ring.get(seq) else { panic!("not committed") };
            assert_eq!(r.text(), b"0123456789");
            store(&ring.slots[(seq % 4) as usize]);
            assert!(matches!(ring.get(seq), Entry::Gone));
        }
    }
}

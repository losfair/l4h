//! The slots behind the host log (`log`) and the serial ring (`serial`):
//! a bounded multi-writer ring of records, overwritten when full.
//!
//! Writers format on their stack before claiming a slot. They never wait
//! for another writer: a preempted or faulted writer can strand one slot,
//! but cannot stop logging on the other slots. Readers never block writers.
//! No allocation, IPC or seL4 invocation occurs.
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
    text: [AtomicU64; W],
}

impl<const W: usize> Slot<W> {
    const fn new() -> Self {
        Self {
            state: AtomicU64::new(0), meta: AtomicU64::new(0), ticks: AtomicU64::new(0),
            text: [const { AtomicU64::new(0) }; W],
        }
    }
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

    /// The oldest sequence a reader can still find.
    pub fn oldest(&self) -> u64 {
        self.head().saturating_sub(N as u64)
    }

    /// Claim `n` consecutive sequences, so that a reader finds them next
    /// to each other. Each must then be committed.
    pub fn claim(&self, n: u64) -> u64 {
        self.head.fetch_add(n, SeqCst)
    }

    /// Publish sequence `seq`, or drop the record if the slot is not ours
    /// to take: a slot is never stolen from a writer that has not
    /// committed it yet.
    pub fn commit(&self, seq: u64, ticks: u64, meta: u64, len: usize, text: &Buf<W>) {
        // Sequence exhaustion is not expected within a host's lifetime.
        let Some(state) = seq.checked_add(1).and_then(|n| n.checked_mul(2)) else { return };
        let slot = &self.slots[(seq % N as u64) as usize];
        let old = slot.state.load(SeqCst);
        if old & 1 != 0 || old >= state
            || slot.state.compare_exchange(old, state - 1, SeqCst, SeqCst).is_err()
        {
            return;
        }
        // Atomic payload and sequential consistency make a reader's two
        // state checks exclude torn records even on AArch64.
        for (dst, src) in slot.text.iter().zip(&text.0) {
            dst.store(*src, SeqCst);
        }
        slot.ticks.store(ticks, SeqCst);
        slot.meta.store(meta << 16 | len as u64, SeqCst);
        slot.state.store(state, SeqCst);
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
        if slot.state.load(SeqCst) != want {
            return Entry::Gone;
        }
        Entry::Ready(Record { ticks, meta: meta >> 16, len, text })
    }
}

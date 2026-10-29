//! The host's free memory: power-of-two Untyped blocks of 2 MiB and more,
//! buddy style, kept in a table with an entry per 2 MiB unit of physical
//! address space (TABLE_VA, mapped and sized by l4h-root).
//!
//! A block of 2^(BLOCK_BITS + k) bytes ("order k") at unit i is described
//! by the entry of unit i, its head, and its Untyped is in a slot of its
//! own (`slot`), so nothing here allocates and every operation is O(1)
//! or O(ORDERS), save merging, which is O(free blocks) and done only when
//! no block is large enough.  The free blocks of each order are on lists
//! linked through their entries: those not reported to the hypervisor, in
//! the order they were freed, and those reported.
//!
//! A request takes the smallest block that fits and splits it in halves
//! as needed, so large aligned allocations never waste memory on
//! alignment.  The Untyped of every split block is kept (with the halves
//! as its children), and deleting both halves makes it whole again: guest
//! RAM comes back in 2 MiB blocks, and without merging the free memory
//! would end up in 2 MiB pieces.  Blocks merge only when a larger one is
//! needed: the next retype of a merged parent makes seL4 clear all the
//! memory its children used, which for a large parent costs far more than
//! the request that split it.
//!
//! Blocks that stay free are reported to the hypervisor, if it takes free
//! page reports (`balloon`), so that it can drop their memory.

use core::ops::Range;

use l4h_rt::host::memd::{BLOCK_BITS, ORDERS, SLOT_DYN_BASE, TABLE_VA, UNIT_BYTES};
use l4h_rt::{cap, host, sel4};
use sel4::{ObjectBlueprint, cap_type};

use crate::balloon::{self, Balloon};

pub type Slot = u64;

pub fn cnode() -> sel4::cap::CNode {
    cap::<cap_type::CNode>(host::SLOT_CNODE)
}

/// Slot `s` of memd's CNode, for CNode operations.
pub fn abs(s: Slot) -> sel4::AbsoluteCPtr {
    cnode().absolute_cptr(cap::<cap_type::Null>(s))
}

fn untyped(s: Slot) -> sel4::cap::Untyped {
    cap::<cap_type::Untyped>(s)
}

const NIL: u32 = u32::MAX;

/// What a unit is.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum State {
    /// Not the head of a block of ours (zeroed memory reads as this).
    None = 0,
    /// Head of a free block, not reported; free since `since`.
    Free,
    /// In the report in flight: not to be used until the device returns it.
    Reporting,
    /// Reported: the hypervisor may have dropped the memory.
    Reported,
    /// Given to l4h-root.
    Root,
    /// A copy given to l4h-vmmgr, the original kept here.
    Vmmgr,
    /// RAM of a guest, on its list.
    Guest,
}

/// An entry of the table.
#[repr(C)]
struct Unit {
    /// Links of the list the block is on.
    next: u32,
    prev: u32,
    /// Orders k for which we keep the Untyped of the split block of order
    /// k headed here.
    split: u32,
    state: State,
    order: u8,
    since: u64,
}

const _: () = assert!(core::mem::size_of::<Unit>() == UNIT_BYTES);

#[derive(Clone, Copy)]
pub struct List {
    head: u32,
    tail: u32,
    pub len: usize,
}

impl List {
    pub const EMPTY: List = List { head: NIL, tail: NIL, len: 0 };

    pub fn head(&self) -> u32 {
        self.head
    }

    /// The guest list from unit `head` on (NIL: empty), whose units are
    /// to be taken off with `pop_guest`: its tail and length are not kept.
    pub fn from_head(head: u32) -> List {
        List { head, tail: NIL, len: usize::MAX / 2 }
    }
}

pub struct Mem {
    table: &'static mut [Unit],
    /// First slot of each order's blocks.
    first: [Slot; ORDERS],
    free: [List; ORDERS],
    reported: [List; ORDERS],
    reporting: List,
    /// Merging below this order will find nothing until a block is freed.
    merged_below: usize,
    pub balloon: Option<Balloon>,
}

/// Size of a block of order k, in bytes.
pub const fn bytes(k: usize) -> usize {
    1 << (BLOCK_BITS + k)
}

impl Mem {
    /// The table of `units` entries at TABLE_VA, zeroed.
    pub fn new(units: usize) -> Self {
        let table = unsafe { core::slice::from_raw_parts_mut(TABLE_VA as *mut Unit, units) };
        let mut first = [0; ORDERS];
        let mut next = SLOT_DYN_BASE;
        for (k, f) in first.iter_mut().enumerate() {
            *f = next;
            next += (units as u64).div_ceil(1 << k);
        }
        Mem {
            table,
            first,
            free: [List::EMPTY; ORDERS],
            reported: [List::EMPTY; ORDERS],
            reporting: List::EMPTY,
            merged_below: 0,
            balloon: None,
        }
    }

    /// The slot of the block of order k at unit i.
    pub fn slot(&self, i: u32, k: usize) -> Slot {
        self.first[k] + (i >> k) as u64
    }

    pub fn state(&self, i: u32) -> State {
        self.table[i as usize].state
    }

    pub fn order(&self, i: u32) -> usize {
        self.table[i as usize].order as usize
    }

    /// Whether (paddr, bits) is a block of the table: aligned, at least a
    /// unit and inside it.
    pub fn block_at(&self, paddr: usize, bits: usize) -> Option<(u32, usize)> {
        let k = bits.checked_sub(BLOCK_BITS).filter(|&k| k < ORDERS)?;
        let i = paddr >> BLOCK_BITS;
        (paddr % bytes(k) == 0 && i + (1 << k) <= self.table.len()).then_some((i as u32, k))
    }

    // Lists.

    fn push_back(&mut self, l: &mut List, i: u32) {
        let u = &mut self.table[i as usize];
        u.next = NIL;
        u.prev = l.tail;
        match l.tail {
            NIL => l.head = i,
            t => self.table[t as usize].next = i,
        }
        l.tail = i;
        l.len += 1;
    }

    fn push_front(&mut self, l: &mut List, i: u32) {
        let u = &mut self.table[i as usize];
        u.prev = NIL;
        u.next = l.head;
        match l.head {
            NIL => l.tail = i,
            h => self.table[h as usize].prev = i,
        }
        l.head = i;
        l.len += 1;
    }

    fn unlink(&mut self, l: &mut List, i: u32) {
        let (next, prev) = (self.table[i as usize].next, self.table[i as usize].prev);
        match prev {
            NIL => l.head = next,
            p => self.table[p as usize].next = next,
        }
        match next {
            NIL => l.tail = prev,
            n => self.table[n as usize].prev = prev,
        }
        l.len -= 1;
    }

    /// The units on `l`, in order.
    pub fn iter(&self, l: List) -> impl Iterator<Item = u32> + '_ {
        let mut i = l.head;
        core::iter::from_fn(move || {
            let cur = i;
            (cur != NIL).then(|| {
                i = self.table[cur as usize].next;
                cur
            })
        })
    }

    /// Put the block taken at unit i on a guest's list `l`.
    pub fn add_guest(&mut self, l: &mut List, i: u32) {
        self.table[i as usize].state = State::Guest;
        self.push_back(l, i);
    }

    /// Take the first block off a guest's list `l`.
    pub fn pop_guest(&mut self, l: &mut List) -> Option<u32> {
        let i = l.head;
        (i != NIL).then(|| {
            self.unlink(l, i);
            i
        })
    }

    // Free blocks.

    /// Put the block of order k at unit i, an untouched Untyped in its
    /// slot, on the free lists.
    fn put(&mut self, i: u32, k: usize, state: State, since: u64, front: bool) {
        let u = &mut self.table[i as usize];
        u.state = state;
        u.order = k as u8;
        u.since = since;
        let mut l = if state == State::Reported { self.reported[k] } else { self.free[k] };
        if front {
            self.push_front(&mut l, i);
        } else {
            self.push_back(&mut l, i);
        }
        if state == State::Reported {
            self.reported[k] = l;
        } else {
            self.free[k] = l;
        }
    }

    /// Take the free block of order k at unit i off its list.
    fn unput(&mut self, i: u32, k: usize) {
        if self.state(i) == State::Reported {
            let mut l = self.reported[k];
            self.unlink(&mut l, i);
            self.reported[k] = l;
        } else {
            let mut l = self.free[k];
            self.unlink(&mut l, i);
            self.free[k] = l;
        }
    }

    /// Free the block of order k at unit i: its Untyped, without children,
    /// is in its slot.
    pub fn add(&mut self, i: u32, k: usize) {
        self.put(i, k, State::Free, host::ticks::now(), false);
        self.merged_below = 0;
    }

    pub fn free_bytes(&self) -> usize {
        (0..ORDERS).map(|k| (self.free[k].len + self.reported[k].len) * bytes(k)).sum::<usize>() + self.reporting_bytes()
    }

    /// Free memory that can be taken without waiting for a report.
    pub fn available_bytes(&self) -> usize {
        (0..ORDERS).map(|k| (self.free[k].len + self.reported[k].len) * bytes(k)).sum()
    }

    fn reporting_bytes(&self) -> usize {
        self.iter(self.reporting).map(|i| bytes(self.order(i))).sum()
    }

    /// Free memory reported to the hypervisor, in bytes.
    pub fn reported_bytes(&self) -> usize {
        (0..ORDERS).map(|k| self.reported[k].len * bytes(k)).sum()
    }

    /// Free blocks: (count, bytes of the largest).
    pub fn block_stats(&self) -> (usize, usize) {
        let mut n = self.reporting.len;
        let mut largest = self.iter(self.reporting).map(|i| bytes(self.order(i))).max().unwrap_or(0);
        for k in 0..ORDERS {
            let m = self.free[k].len + self.reported[k].len;
            n += m;
            if m != 0 {
                largest = largest.max(bytes(k));
            }
        }
        (n, largest)
    }

    /// Whether a block of order k or more can be taken now, without
    /// merging or waiting for a report.
    fn has_block(&self, k: usize) -> bool {
        (k..ORDERS).any(|j| self.free[j].len + self.reported[j].len != 0)
    }

    /// The last block on `list` whose first order-k block lies in `window`.
    /// Splitting never moves the selected block's lower half.
    fn last_in(&self, list: List, k: usize, window: &Range<usize>) -> Option<u32> {
        self.iter(list).filter(|&i| {
            let start = (i as usize) << BLOCK_BITS;
            start >= window.start && start.checked_add(bytes(k)).is_some_and(|end| end <= window.end)
        }).last()
    }

    fn find_in(&self, k: usize, window: &Range<usize>) -> Option<(u32, usize)> {
        for j in k..ORDERS {
            if let Some(i) = self.last_in(self.free[j], k, window)
                .or_else(|| self.last_in(self.reported[j], k, window))
            {
                return Some((i, j));
            }
        }
        None
    }

    /// Take unit i, splitting its order-j block down to order k.
    fn take_at(&mut self, k: usize, j: usize, i: u32, state: State) -> u32 {
        let (hint, since) = (self.state(i), self.table[i as usize].since);
        self.unput(i, j);
        for o in (k..j).rev() {
            // Split the block of order o + 1 at i: its halves go to the
            // slots of i and its buddy, which are consecutive.
            let buddy = i + (1 << o);
            untyped(self.slot(i, o + 1))
                .untyped_retype(&ObjectBlueprint::Untyped { size_bits: BLOCK_BITS + o }, &cnode().absolute_cptr_for_self(), self.slot(i, o) as usize, 2)
                .expect("memd: split block");
            debug_assert_eq!(self.slot(buddy, o), self.slot(i, o) + 1);
            // The parent is kept, to merge the halves again when both
            // are free.  The other half, freed as long ago as it, goes
            // first in line to be reported.
            self.table[i as usize].split |= 1 << (o + 1);
            self.put(buddy, o, hint, since, true);
        }
        let u = &mut self.table[i as usize];
        u.state = state;
        u.order = k as u8;
        i
    }

    /// An untouched Untyped of order k: its unit, whose state is now
    /// `state`; the Untyped is in `slot(i, k)`, the caller's until it
    /// gives it back with `add`.
    pub fn take(&mut self, k: usize, state: State) -> Option<u32> {
        if !self.has_block(k) {
            self.finish_report(true);
        }
        if !self.has_block(k) {
            self.merge_up_to(k);
        }
        // The smallest block that fits; of those, one not reported (its
        // memory is there), the most recently freed.
        let j = (k..ORDERS).find(|&j| self.free[j].len + self.reported[j].len != 0)?;
        let i = if self.free[j].len != 0 { self.free[j].tail } else { self.reported[j].tail };
        Some(self.take_at(k, j, i, state))
    }

    /// `take`, with the allocated order-k block entirely in `window`. Only
    /// constrained requests scan the free lists; ordinary allocations
    /// retain their O(ORDERS) behavior.
    pub fn take_in(&mut self, k: usize, state: State, window: Range<usize>) -> Option<u32> {
        if window == (0..usize::MAX) {
            return self.take(k, state);
        }
        let mut found = self.find_in(k, &window);
        if found.is_none() {
            self.finish_report(true);
            found = self.find_in(k, &window);
        }
        if found.is_none() {
            self.merge_up_to(k);
            found = self.find_in(k, &window);
        }
        let (i, j) = found?;
        Some(self.take_at(k, j, i, state))
    }

    /// Merge free buddies, smallest first, into blocks of up to order k,
    /// so that a request for order k can be met.
    fn merge_up_to(&mut self, k: usize) {
        if k <= self.merged_below {
            return;
        }
        for o in 0..k {
            for reported in [false, true] {
                let mut i = if reported { self.reported[o].head } else { self.free[o].head };
                while i != NIL {
                    let mut next = self.table[i as usize].next;
                    let buddy = i ^ (1 << o);
                    let parent = i & !(1 << o);
                    let mergeable = self.table[parent as usize].split & (1 << (o + 1)) != 0
                        && matches!(self.state(buddy), State::Free | State::Reported)
                        && self.order(buddy) == o;
                    if mergeable {
                        if next == buddy {
                            next = self.table[buddy as usize].next;
                        }
                        self.merge(parent, o);
                    }
                    i = next;
                }
            }
        }
        self.merged_below = k;
    }

    /// Merge the free halves of order o of the split block at `parent`.
    fn merge(&mut self, parent: u32, o: usize) {
        let buddy = parent + (1 << o);
        let reported = self.state(parent) == State::Reported && self.state(buddy) == State::Reported;
        for h in [parent, buddy] {
            self.unput(h, o);
            // Neither half has children: deleting both leaves the parent
            // without children, so its next retype starts afresh (and
            // clears what the halves used).
            abs(self.slot(h, o)).delete().expect("memd: delete merged half");
        }
        self.table[buddy as usize].state = State::None;
        self.table[parent as usize].split &= !(1 << (o + 1));
        let (state, since) = if reported { (State::Reported, 0) } else { (State::Free, host::ticks::now()) };
        self.put(parent, o + 1, state, since, false);
    }

    /// Report the blocks that have been free for `delay` ticks to the
    /// hypervisor, as many as one report holds, unless a report is in
    /// flight.  Called periodically.
    pub fn report_free(&mut self, now: u64, delay: u64) {
        self.finish_report(false);
        let Some(dev) = &self.balloon else { return };
        if dev.busy() {
            return;
        }
        let cap = dev.capacity();
        let mut ranges = [(0, 0); balloon::QUEUE_SIZE];
        let mut n = 0;
        for k in 0..ORDERS {
            let piece = bytes(k).min(1 << balloon::MAX_DESC_BITS);
            let per = bytes(k) / piece;
            if n + per > cap {
                // Neither this order's blocks nor any larger fit.
                break;
            }
            // Oldest first.
            let mut i = self.free[k].head;
            while i != NIL && n + per <= cap && now.saturating_sub(self.table[i as usize].since) >= delay {
                let next = self.table[i as usize].next;
                let paddr = (i as usize) << BLOCK_BITS;
                for p in 0..per {
                    ranges[n] = (paddr + p * piece, piece);
                    n += 1;
                }
                self.unput(i, k);
                self.table[i as usize].state = State::Reporting;
                let mut l = self.reporting;
                self.push_back(&mut l, i);
                self.reporting = l;
                i = next;
            }
        }
        if n != 0 {
            self.balloon.as_mut().unwrap().report(&ranges[..n]);
        }
    }

    /// Take back the blocks of the report in flight once the device is
    /// done with it; `wait` waits for that.
    fn finish_report(&mut self, wait: bool) {
        let Some(dev) = &mut self.balloon else { return };
        if !dev.busy() {
            return;
        }
        if !dev.done(wait) {
            if wait {
                l4h_rt::log!("memd: balloon: the device holds a free page report too long");
            }
            return;
        }
        let mut bytes_back = 0;
        while self.reporting.head != NIL {
            let i = self.reporting.head;
            let mut l = self.reporting;
            self.unlink(&mut l, i);
            self.reporting = l;
            let k = self.order(i);
            bytes_back += bytes(k);
            self.put(i, k, State::Reported, 0, false);
        }
        // Reporting blocks are not merged; they can be now.
        self.merged_below = 0;
        l4h_rt::info!(
            "memd: balloon: reported {} MiB, {} of {} MiB free reported",
            bytes_back >> 20, self.reported_bytes() >> 20, self.free_bytes() >> 20
        );
    }
}

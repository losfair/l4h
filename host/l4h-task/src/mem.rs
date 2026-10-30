//! Untyped memory and CSpace slot management for seL4 tasks. The caller
//! supplies its CNode and table storage; slots are reached at depth 64
//! in that CNode (one level, guarded).
//!
//! All kernel objects are carved out of Untyped capabilities.  We keep our
//! own copy of each Untyped's watermark so that we know the physical address
//! of every child we create (seL4 aligns each retyped object to its size,
//! starting at the current watermark).  I/O pools rely on this to obtain
//! physically contiguous chunks.

use core::ops::Range;

use l4h_host::fixed::ArrayVec;

use l4h_host::memd::BLOCK_BITS;
use sel4::{ObjectBlueprint, cap};

use crate::memd::MemdLink;

pub type Slot = usize;

/// Maximum objects retyped by one kernel invocation.
pub const RETYPE_FAN_OUT: usize = 16384;

/// Owner of the slots of global objects (`Slots::global`).
pub const GLOBAL: u8 = u8::MAX;

/// Caller-owned storage for a task's CSpace bitmap and ownership table.
/// Put this in static storage: the largest CSpaces do not fit on a stack.
pub struct SlotStorage<const WORDS: usize, const SLOTS: usize> {
    free: [u64; WORDS],
    owner: [u8; SLOTS],
}

impl<const WORDS: usize, const SLOTS: usize> SlotStorage<WORDS, SLOTS> {
    pub const fn new() -> Self {
        assert!(WORDS * 64 == SLOTS);
        Self { free: [0; WORDS], owner: [GLOBAL; SLOTS] }
    }
}

/// Allocator for slots in the caller's own CNode: a bitmap of the free
/// ones, so that ranges freed by destroyed guests (vNIC ports, disk DMA
/// buffers) can be allocated again as ranges.
///
/// Every slot allocated is recorded as its owner's: a guest's while the
/// allocator works for it (`track`), else global.  The slots holding a
/// guest's capabilities are cleaned up and reused when it is destroyed
/// (`free_owned`).
pub struct Slots {
    cnode: cap::CNode,
    free: &'static mut [u64],
    owners: &'static mut [u8],
    count: usize,
    /// No slot below this is free.
    low: usize,
    owner: u8,
}

impl Slots {
    pub fn new<const WORDS: usize, const SLOTS: usize>(
        cnode: cap::CNode,
        storage: &'static mut SlotStorage<WORDS, SLOTS>,
        range: Range<usize>,
    ) -> Self {
        assert!(range.start <= range.end && range.end <= SLOTS);
        assert_eq!(WORDS * 64, SLOTS);
        let SlotStorage { free, owner } = storage;
        free.fill(0);
        owner.fill(GLOBAL);
        for s in range.clone() {
            free[s / 64] |= 1 << (s % 64);
        }
        Self { cnode, free, owners: owner, count: range.len(), low: range.start, owner: GLOBAL }
    }

    pub fn cnode(&self) -> cap::CNode {
        self.cnode
    }

    fn is_free(&self, s: Slot) -> bool {
        self.free[s / 64] & (1 << (s % 64)) != 0
    }

    pub fn alloc(&mut self) -> Slot {
        self.alloc_range(1).start
    }

    /// Allocate `n` consecutive slots (the lowest range that fits).
    pub fn alloc_range(&mut self, n: usize) -> Range<Slot> {
        self.try_alloc_range(n).expect("task CNode full")
    }

    /// `alloc_range`, or None if no range of `n` slots is free.
    pub fn try_alloc_range(&mut self, n: usize) -> Option<Range<Slot>> {
        let start = self.find_range(n)?;
        for s in start..start + n {
            self.free[s / 64] &= !(1 << (s % 64));
            self.owners[s] = self.owner;
        }
        self.count -= n;
        if start == self.low {
            self.low = start + n;
        }
        Some(start..start + n)
    }

    /// The lowest free range of `n` slots.
    fn find_range(&self, n: usize) -> Option<Slot> {
        if n == 0 || n > self.count {
            return None;
        }
        let (mut start, mut len) = (self.low, 0);
        let mut s = self.low;
        while s < self.owners.len() {
            let w = self.free[s / 64];
            // Whole words at a time where they are all used or all free.
            if s % 64 == 0 && w == 0 {
                s += 64;
                (start, len) = (s, 0);
                continue;
            }
            if s % 64 == 0 && w == u64::MAX && len + 64 < n {
                (s, len) = (s + 64, len + 64);
                continue;
            }
            if w & (1 << (s % 64)) != 0 {
                len += 1;
                if len == n {
                    return Some(start);
                }
            } else {
                len = 0;
                start = s + 1;
            }
            s += 1;
        }
        None
    }

    pub fn free(&mut self, s: Slot) {
        assert!(!self.is_free(s), "slot {} freed twice", s);
        self.free[s / 64] |= 1 << (s % 64);
        self.owners[s] = GLOBAL;
        self.count += 1;
        self.low = self.low.min(s);
    }

    /// Slots that can still be allocated.
    pub fn available(&self) -> usize {
        self.count
    }

    /// The longest range `alloc_range` can return.
    pub fn largest_range(&self) -> usize {
        let (mut best, mut len) = (0, 0);
        for &w in self.free.iter() {
            if w == u64::MAX {
                len += 64;
                continue;
            }
            // Runs of free (set) bits, a run at a time.
            let mut w = w;
            let mut left = 64;
            while left > 0 {
                let ones = (w.trailing_ones() as usize).min(left);
                len += ones;
                if ones == left {
                    break;
                }
                best = best.max(len);
                let zeros = ((w >> ones).trailing_zeros() as usize).min(left - ones);
                len = 0;
                w = w.checked_shr((ones + zeros) as u32).unwrap_or(0);
                left -= ones + zeros;
            }
        }
        best.max(len)
    }

    /// Record allocations as guest `owner`'s, until `untrack`.
    pub fn track(&mut self, owner: usize) {
        assert!(self.owner == GLOBAL, "nested slot tracking");
        assert!(owner < GLOBAL as usize, "slot owner out of range");
        self.owner = owner as u8;
    }

    pub fn untrack(&mut self) {
        self.owner = GLOBAL;
    }

    /// Delete the capabilities in all slots of guest `owner`, and free them.
    pub fn free_owned(&mut self, owner: usize) {
        assert!(owner < GLOBAL as usize, "slot owner out of range");
        for s in 0..self.owners.len() {
            if self.owners[s] == owner as u8 && !self.is_free(s) {
                let _ = self.cnode.absolute_cptr(sel4::Cap::<sel4::cap_type::Null>::from_bits(s as u64)).delete();
                self.free(s);
            }
        }
    }

    /// Run `f` with tracking suspended (for objects that outlive a guest).
    pub fn global<R>(&mut self, f: impl FnOnce(&mut Self) -> R) -> R {
        let t = core::mem::replace(&mut self.owner, GLOBAL);
        let r = f(self);
        self.owner = t;
        r
    }
}

impl Alloc {
    /// `Slots::global` for code that needs the whole allocator.
    pub fn global<R>(&mut self, f: impl FnOnce(&mut Self) -> R) -> R {
        let t = core::mem::replace(&mut self.slots.owner, GLOBAL);
        let r = f(self);
        self.slots.owner = t;
        r
    }
}

/// One Untyped capability and our view of its watermark.
pub struct UtRegion {
    pub cap: cap::Untyped,
    pub paddr: usize,
    pub size_bits: usize,
    used: usize,
}

impl UtRegion {
    /// A region whose capability has no children.
    pub fn fresh(cap: cap::Untyped, paddr: usize, size_bits: usize) -> Self {
        UtRegion { cap, paddr, size_bits, used: 0 }
    }

    fn size(&self) -> usize {
        1 << self.size_bits
    }

    /// Offset at which `count` objects of 2^bits bytes would be placed.
    fn fit(&self, bits: usize, count: usize) -> Option<usize> {
        let align = 1usize << bits;
        let off = (self.used + align - 1) & !(align - 1);
        (bits <= self.size_bits && off + (count << bits) <= self.size()).then_some(off)
    }

    /// Retype `count` objects of `bp` into `dest`, physically contiguous
    /// and each aligned to its size.  Returns the physical address of the
    /// first one, or None if they do not fit.
    pub fn retype(&mut self, bp: &ObjectBlueprint, count: usize, dest: Dest) -> Option<usize> {
        let bits = bp.physical_size_bits();
        let off = self.fit(bits, count)?;
        // The kernel caps fan-out per call; split large requests.
        let mut done = 0;
        while done < count {
            let n = (count - done).min(RETYPE_FAN_OUT);
            self.cap
                .untyped_retype(bp, &dest.cnode, dest.offset + done, n)
                .unwrap_or_else(|e| panic!("retype {:?} x{} failed: {:?}", bp.ty(), n, e));
            done += n;
        }
        self.used = off + (count << bits);
        Some(self.paddr + off)
    }
}

pub fn cnode_dest(cnode: cap::CNode) -> sel4::AbsoluteCPtr {
    cnode.absolute_cptr_for_self()
}

/// Where a retype should place its result.
#[derive(Clone, Copy)]
pub struct Dest {
    /// CNode the objects are placed in (as seen from the caller's CSpace).
    pub cnode: sel4::AbsoluteCPtr,
    /// First slot index within that CNode.
    pub offset: usize,
}

impl Dest {
    pub fn new(cnode: cap::CNode, slot: Slot) -> Self {
        Dest { cnode: cnode_dest(cnode), offset: slot }
    }
}

/// A pool of at most N Untyped regions that objects are allocated from:
/// the global pool of the task's own objects, and per-guest arenas
/// of regions split off the free blocks, so that a guest can be torn down
/// by revoking a handful of capabilities.
pub struct UtPool<const N: usize> {
    pub regions: ArrayVec<UtRegion, N>,
}

impl<const N: usize> UtPool<N> {
    pub const fn empty() -> Self {
        Self { regions: ArrayVec::new() }
    }

    pub fn free_bytes(&self) -> usize {
        self.regions.iter().map(|r| r.size() - r.used).sum()
    }

    /// Add `r`, keeping the regions sorted by size (small objects come
    /// from small regions, so that big ones stay intact).  Gives it back
    /// if the pool is full.
    pub fn add(&mut self, r: UtRegion) -> Result<(), UtRegion> {
        let i = self.regions.iter().position(|x| x.size_bits > r.size_bits).unwrap_or(self.regions.len());
        self.regions.insert(i, r)
    }

    /// Retype `count` objects of `bp` into `dest`.  All objects come from a
    /// single region, so they are physically contiguous and each is aligned
    /// to its size.  Returns the physical address of the first one.
    pub fn retype(&mut self, bp: &ObjectBlueprint, count: usize, dest: Dest) -> Option<usize> {
        let bits = bp.physical_size_bits();
        // Take the region where alignment wastes least (an aligned
        // allocation skips the memory between the watermark and its start,
        // for good); among equals, the smallest region.
        let idx = self
            .regions
            .iter()
            .enumerate()
            .filter_map(|(i, r)| r.fit(bits, count).map(|off| (off - r.used, r.size_bits, i)))
            .min()
            .map(|(_, _, i)| i)?;
        self.regions[idx].retype(bp, count, dest)
    }
}

/// Global allocation state of a task.
///
/// Free memory is kept as untouched power-of-two Untyped *blocks*, buddy
/// style: a request takes the smallest block that fits and splits it in
/// halves as needed, so large aligned allocations never waste memory on
/// alignment.  The Untyped of every split block is kept (with the halves
/// as its children), and deleting both halves makes it whole.  Small
/// global objects come from `pool`, which is refilled with blocks.
///
/// At boot the blocks are the boot Untypeds.  Once l4h-memd runs, they all
/// go to it (`hand_over`), and the blocks here are a cache: a request that
/// they cannot meet takes a *grant* from memd (GRANT_BITS, or more for a
/// larger request), and grants that are whole and free again go back to
/// it (`trim`) beyond the LOCAL_KEEP bytes kept for the next requests.
/// Guest RAM does not come from here at all (memd.rs).
///
/// The tables are fixed (ALLOC_BLOCKS and so on): a request that would
/// overflow one fails as out of memory.
pub struct Alloc {
    pub slots: Slots,
    /// Small objects of the task itself.
    pub pool: UtPool<POOL_REGIONS>,
    blocks: &'static mut ArrayVec<UtRegion, ALLOC_BLOCKS>,
    /// Split blocks: (paddr, size bits, slot of their Untyped), sorted.
    parents: &'static mut ArrayVec<(usize, usize, Slot), ALLOC_BLOCKS>,
    pub memd: Option<MemdLink>,
    /// Grants from memd that we hold, whole or split: (paddr, size bits).
    grants: &'static mut ArrayVec<(usize, usize), ALLOC_GRANTS>,
}

/// Caller-owned allocator tables: about 240 KiB, so keep them in static
/// storage to avoid overflowing a task's stack.
pub struct AllocStorage {
    blocks: ArrayVec<UtRegion, ALLOC_BLOCKS>,
    parents: ArrayVec<(usize, usize, Slot), ALLOC_BLOCKS>,
    grants: ArrayVec<(usize, usize), ALLOC_GRANTS>,
}

impl AllocStorage {
    pub const fn new() -> Self {
        Self { blocks: ArrayVec::new(), parents: ArrayVec::new(), grants: ArrayVec::new() }
    }
}

const SMALL_POOL_BITS: usize = 24;
/// Regions of the global pool: SMALL_POOL_BITS each, refilled when it has
/// less than half of one free; a full region is dropped from it.
const POOL_REGIONS: usize = 8;
/// Free blocks, and split blocks, the allocator can keep track of: more
/// than the boot Untypeds (seL4 hands out at most 230), and room for the
/// pieces of hundreds of grants.
const ALLOC_BLOCKS: usize = 4096;
/// Grants held at once: 16 GiB of host objects in 16 MiB grants.
const ALLOC_GRANTS: usize = 1024;
/// Smallest grant memd is asked for.
const GRANT_BITS: usize = 24;
/// Free grants kept beyond what is in use.
const LOCAL_KEEP: usize = 32 << 20;

fn untyped_at(s: Slot) -> cap::Untyped {
    sel4::Cap::<sel4::cap_type::Untyped>::from_bits(s as u64)
}

impl Alloc {
    pub fn new(slots: Slots, storage: &'static mut AllocStorage, bootinfo: &sel4::BootInfo) -> Self {
        let AllocStorage { blocks, parents, grants } = storage;
        Self::with_tables(Alloc { slots, pool: UtPool::empty(), blocks, parents, memd: None, grants }, bootinfo)
    }

    /// An allocator with no memory until it is given a link to memd
    /// (vmmgr's: all it has are grants).
    pub fn empty(slots: Slots, storage: &'static mut AllocStorage) -> Self {
        let AllocStorage { blocks, parents, grants } = storage;
        Alloc { slots, pool: UtPool::empty(), blocks, parents, memd: None, grants }
    }

    /// A new allocator for `bootinfo`, with this one's slots and tables:
    /// storage is reused without allocating another set of tables.
    pub fn renew(self, bootinfo: &sel4::BootInfo) -> Self {
        let Alloc { slots, blocks, parents, grants, .. } = self;
        blocks.clear();
        parents.clear();
        grants.clear();
        Self::with_tables(Alloc { slots, pool: UtPool::empty(), blocks, parents, memd: None, grants }, bootinfo)
    }

    fn with_tables(mut a: Self, bootinfo: &sel4::BootInfo) -> Self {
        for (i, desc) in bootinfo.untyped_list().iter().enumerate() {
            if !desc.is_device() {
                a.blocks.must_push(UtRegion::fresh(bootinfo.untyped().index(i).cap(), desc.paddr(), desc.size_bits()));
            }
        }
        a.refill();
        a
    }

    /// Keep the small-object pool stocked, preserving message registers.
    pub fn refill(&mut self) {
        if self.pool.free_bytes() >= 1 << (SMALL_POOL_BITS - 1) {
            return;
        }
        // Root and vmmgr refill before dispatching received calls and
        // faults.  Both kernel invocations and calls to memd overwrite
        // the IPC buffer, so keep the incoming message across this work.
        let regs: [u64; sel4::NUM_MESSAGE_REGISTERS] = sel4::with_ipc_buffer(|b| b.msg_regs().try_into().unwrap());
        // Regions too full to be of use leave the pool; their objects
        // stay, as global objects do.
        self.pool.regions.retain(|r| r.size() - r.used >= 4096);
        if self.pool.regions.is_full() {
            let (i, _) = self.pool.regions.iter().enumerate().min_by_key(|(_, r)| r.size() - r.used).unwrap();
            self.pool.regions.remove(i);
        }
        let s = self.slots.global(|s| s.alloc());
        match self.split(SMALL_POOL_BITS, s) {
            Some(r) => {
                let _ = self.pool.add(r);
            }
            None => self.slots.global(|sl| sl.free(s)),
        }
        sel4::with_ipc_buffer_mut(|b| b.msg_regs_mut().copy_from_slice(&regs));
    }

    fn local_bytes(&self) -> usize {
        self.blocks.iter().map(|b| 1usize << b.size_bits).sum()
    }

    /// Free memory here, not in memd.
    pub fn local_free_bytes(&self) -> usize {
        self.local_bytes() + self.pool.free_bytes()
    }

    /// Free memory, here and in memd.
    pub fn free_bytes(&self) -> usize {
        self.local_bytes() + self.pool.free_bytes() + self.memd.map_or(0, |m| m.status().free_bytes as usize)
    }

    /// Free memory reported to the hypervisor, in bytes (memd).
    pub fn reported_bytes(&self) -> usize {
        self.memd.map_or(0, |m| m.status().reported_bytes as usize)
    }

    /// Largest block available, here or in memd.
    pub fn largest_block_bits(&self) -> Option<usize> {
        let memd = self.memd.map(|m| m.status().largest_block as usize).filter(|&b| b != 0).map(|b| b.trailing_zeros() as usize);
        self.blocks.iter().map(|b| b.size_bits).max().max(memd)
    }

    /// Whether a block of 2^bits bytes can be split off here.
    fn has_block(&self, bits: usize) -> bool {
        self.blocks.iter().any(|b| b.size_bits >= bits)
    }

    fn is_grant(&self, paddr: usize, bits: usize) -> bool {
        self.grants.contains(&(paddr, bits))
    }

    fn parent(&self, paddr: usize, bits: usize) -> Result<usize, usize> {
        self.parents.binary_search_by_key(&(paddr, bits), |&(p, b, _)| (p, b))
    }

    /// Take a grant from memd for a request of 2^bits bytes: GRANT_BITS,
    /// or exactly what is asked if memd has no larger block.
    fn grant(&mut self, bits: usize) -> bool {
        let Some(memd) = self.memd else { return false };
        if self.grants.is_full() || self.blocks.is_full() {
            return false;
        }
        for gbits in [bits.max(GRANT_BITS), bits.max(BLOCK_BITS)] {
            let s = self.slots.global(|s| s.alloc());
            if let Some(paddr) = memd.alloc(gbits, s) {
                self.blocks.must_push(UtRegion::fresh(untyped_at(s), paddr, gbits));
                self.grants.must_push((paddr, gbits));
                return true;
            }
            self.slots.global(|sl| sl.free(s));
        }
        false
    }

    /// An untouched Untyped of exactly 2^bits bytes, in local slot `slot`.
    pub fn split(&mut self, bits: usize, slot: Slot) -> Option<UtRegion> {
        if !self.has_block(bits) {
            self.merge_up_to(bits);
        }
        if !self.has_block(bits) && !self.grant(bits) {
            return None;
        }
        let (i, _) = self
            .blocks
            .iter()
            .enumerate()
            .filter(|(_, b)| b.size_bits >= bits)
            .min_by_key(|(_, b)| (b.size_bits, b.paddr))?;
        // Every level split keeps a parent and frees a half.
        let levels = self.blocks[i].size_bits - bits;
        if self.parents.len() + levels > ALLOC_BLOCKS || self.blocks.len() + levels > ALLOC_BLOCKS {
            return None;
        }
        let mut b = self.blocks.swap_remove(i);
        while b.size_bits > bits {
            let half = b.size_bits - 1;
            let s = self.slots.global(|s| s.alloc_range(2));
            b.cap
                .untyped_retype(&ObjectBlueprint::Untyped { size_bits: half }, &cnode_dest(self.slots.cnode()), s.start, 2)
                .expect("split block");
            // The parent is kept, to merge the halves again when both
            // are free.
            let at = self.parent(b.paddr, b.size_bits).unwrap_err();
            let _ = self.parents.insert(at, (b.paddr, b.size_bits, b.cap.bits() as Slot));
            self.blocks.must_push(UtRegion::fresh(untyped_at(s.start + 1), b.paddr + (1 << half), half));
            b = UtRegion::fresh(untyped_at(s.start), b.paddr, half);
        }
        let dst = self.slots.cnode().absolute_cptr(untyped_at(slot));
        dst.move_(&self.slots.cnode().absolute_cptr(b.cap)).expect("move block");
        self.slots.global(|s| s.free(b.cap.bits() as Slot));
        Some(UtRegion::fresh(untyped_at(slot), b.paddr, bits))
    }

    /// Allocate a single object into a fresh local slot.
    pub fn object(&mut self, bp: ObjectBlueprint) -> Slot {
        self.refill();
        let s = self.slots.alloc();
        self.pool
            .retype(&bp, 1, Dest::new(self.slots.cnode(), s))
            .unwrap_or_else(|| panic!("out of memory allocating {:?}", bp.ty()));
        s
    }

    pub fn object_cap<T: sel4::CapType>(&mut self, bp: ObjectBlueprint) -> sel4::Cap<T> {
        let s = self.object(bp);
        sel4::Cap::<T>::from_bits(s as u64)
    }

    /// Destroy every object of `arena` and return its memory as blocks.
    /// The Untyped capabilities move to fresh slots, leaving the owner's
    /// slots empty.
    pub fn reclaim(&mut self, arena: Arena) {
        self.reclaim_pinning(arena, |_| false);
    }

    /// `reclaim`, except that the Untypeds at a physical address for which
    /// `pin` is true never return to the free pool: a device that could not
    /// be stopped may still write to them.  Their objects are destroyed all
    /// the same.  Returns the bytes kept out of use.
    pub fn reclaim_pinning(&mut self, arena: Arena, pin: impl Fn(usize) -> bool) -> usize {
        self.reclaim_inner(arena, pin, false)
    }

    fn reclaim_inner(&mut self, arena: Arena, pin: impl Fn(usize) -> bool, free_slots: bool) -> usize {
        let mut pinned = 0;
        for &(slot, paddr, bits) in arena.owned.iter() {
            let cap = untyped_at(slot);
            self.slots.cnode().absolute_cptr(cap).revoke().expect("revoke arena untyped");
            if self.blocks.is_full() {
                self.merge_up_to(usize::MAX);
            }
            if pin(paddr) || self.blocks.is_full() {
                if !pin(paddr) {
                    log!("l4h-task: free block table full, {} KiB lost", (1usize << bits) >> 10);
                }
                pinned += 1 << bits;
                continue;
            }
            let s = self.slots.global(|s| s.alloc());
            self.slots.cnode().absolute_cptr(untyped_at(s)).move_(&self.slots.cnode().absolute_cptr(cap)).expect("move block");
            self.blocks.must_push(UtRegion::fresh(untyped_at(s), paddr, bits));
            if free_slots {
                self.slots.free(slot);
            }
        }
        self.trim();
        pinned
    }

    /// Merge free buddies, smallest first, into blocks of up to 2^bits
    /// bytes, so that a request for 2^bits can be met.  A grant is not
    /// merged with its buddy: it goes back to memd whole.
    fn merge_up_to(&mut self, bits: usize) {
        loop {
            let mut merged = false;
            let mut i = 0;
            while i < self.blocks.len() {
                let (paddr, b) = (self.blocks[i].paddr, self.blocks[i].size_bits);
                let parent = (paddr & !(1 << b), b + 1);
                let buddy = paddr ^ (1 << b);
                let p = self.parent(parent.0, parent.1).ok();
                let j = self.blocks.iter().position(|x| x.paddr == buddy && x.size_bits == b);
                let grant = self.is_grant(paddr, b) || self.is_grant(buddy, b);
                let (Some(p), Some(j), true, false) = (p, j, b < bits, grant) else {
                    i += 1;
                    continue;
                };
                // Neither half has children: deleting both leaves the
                // parent without children, so its next retype starts
                // afresh (and clears what the halves used).
                let (x, y) = (self.blocks.swap_remove(i.max(j)), self.blocks.swap_remove(i.min(j)));
                for half in [x.cap, y.cap] {
                    let s = half.bits() as Slot;
                    self.slots.cnode().absolute_cptr(half).delete().expect("delete merged half");
                    self.slots.global(|sl| sl.free(s));
                }
                let (_, _, pslot) = self.parents.remove(p);
                self.blocks.must_push(UtRegion::fresh(untyped_at(pslot), parent.0, parent.1));
                merged = true;
            }
            if !merged || self.has_block(bits) {
                return;
            }
        }
    }

    /// Units of memd's table: 2 MiB units up to the end of the last free
    /// block memd will get (`hand_over`).
    pub fn memd_units(&mut self) -> u64 {
        self.merge_up_to(usize::MAX);
        self.blocks.iter().filter(|b| b.size_bits >= BLOCK_BITS).map(|b| ((b.paddr + (1 << b.size_bits)) >> BLOCK_BITS) as u64).max().unwrap_or(0)
    }

    /// Give memd every free block of 2 MiB or more, once it runs: from
    /// then on, memory comes from it.  Smaller blocks (boot Untypeds next
    /// to reserved memory) stay here, for the task's own objects.
    /// The parents of blocks split here stay here, so memd cannot merge
    /// those blocks with their buddies; only the blocks root split at boot
    /// are concerned.
    pub fn hand_over(&mut self, memd: MemdLink) {
        self.merge_up_to(usize::MAX);
        self.give_back(memd, |_, b| b.size_bits >= BLOCK_BITS);
        self.memd = Some(memd);
    }

    /// Return whole free grants to memd, beyond LOCAL_KEEP bytes of free
    /// blocks.  Nothing is merged until there is a grant's worth more than
    /// that: the next retype of a merged block makes seL4 clear all that
    /// its halves used, and merging after every destroy made creating a
    /// guest a fifth slower.
    fn trim(&mut self) {
        let Some(memd) = self.memd else { return };
        if self.local_bytes() < LOCAL_KEEP + (1 << GRANT_BITS) {
            return;
        }
        self.merge_up_to(usize::MAX);
        // The largest first, while what stays is LOCAL_KEEP or more.
        let mut keep = self.local_bytes();
        let mut bits = usize::BITS as usize;
        while bits > BLOCK_BITS {
            bits -= 1;
            self.give_back(memd, |a, b| {
                let size = 1usize << b.size_bits;
                let back = b.size_bits == bits && a.is_grant(b.paddr, b.size_bits) && keep >= LOCAL_KEEP + size;
                if back {
                    keep -= size;
                }
                back
            });
        }
    }

    /// Move the free blocks for which `pick` is true (untouched) to memd,
    /// and free their slots.
    fn give_back(&mut self, memd: MemdLink, mut pick: impl FnMut(&Self, &UtRegion) -> bool) {
        loop {
            let mut batch: ArrayVec<(cap::Untyped, usize, usize), { l4h_host::memd::XCHG_SLOTS }> = ArrayVec::new();
            let mut i = 0;
            while i < self.blocks.len() && !batch.is_full() {
                if pick(self, &self.blocks[i]) {
                    let b = self.blocks.swap_remove(i);
                    if let Some(g) = self.grants.iter().position(|&g| g == (b.paddr, b.size_bits)) {
                        self.grants.swap_remove(g);
                    }
                    batch.must_push((b.cap, b.paddr, b.size_bits));
                } else {
                    i += 1;
                }
            }
            if batch.is_empty() {
                return;
            }
            memd.free(&batch);
            for &(cap, _, _) in batch.iter() {
                self.slots.global(|sl| sl.free(cap.bits() as Slot));
            }
        }
    }

    /// Undo a partly built arena: reclaim its memory and free its slots.
    fn release(&mut self, arena: Arena) {
        self.reclaim_inner(arena, |_| false, true);
    }

    /// Carve a per-guest arena of at least `bytes` out of the free blocks.
    pub fn arena(&mut self, bytes: usize) -> Option<Arena> {
        let mut arena = Arena::new();
        let mut remaining = bytes;
        while remaining > 0 {
            let Some(max_bits) = self.largest_block_bits() else {
                self.release(arena);
                return None;
            };
            // Binary decomposition: the largest power of two not above
            // what is left, and a rounded-up tail below 1 MiB.
            let want_bits = if remaining <= 1 << 20 {
                remaining.max(4096).next_power_of_two().trailing_zeros() as usize
            } else {
                (usize::BITS - 1 - remaining.leading_zeros()) as usize
            };
            let bits = want_bits.min(max_bits);
            if arena.pool.regions.is_full() {
                self.release(arena);
                return None;
            }
            let slot = self.slots.alloc();
            let Some(region) = self.split(bits, slot) else {
                self.slots.free(slot);
                self.release(arena);
                return None;
            };
            arena.owned.must_push((slot, region.paddr, bits));
            remaining = remaining.saturating_sub(1 << bits);
            let _ = arena.pool.add(region);
        }
        Some(arena)
    }
}

/// An arena grows by at least this much (2^bits bytes) when it runs out,
/// preferring an eighth of its size once that is more, so that its
/// regions stay few.  Smaller blocks can still serve it under fragmentation.
const ARENA_GROW_BITS: usize = 20;
/// Regions of an arena, and the Untypeds it owns besides (the I/O pool,
/// disk channels and netd ports: at most one per root-counted device).
const ARENA_REGIONS: usize = 96;
/// What alignment may leave unusable at the end of a region, for
/// Arena::reserve: the largest object allocated in quantity (a 16 KiB RAM
/// CNode) and the space before it.
pub const ARENA_TAIL: usize = 32 << 10;
const ARENA_OWNED: usize = ARENA_REGIONS + 1 + l4h_host::MAX_GUEST_DEVICES;

/// Untyped memory dedicated to one guest (or host component).
///
/// An arena starts with the memory its owner is expected to need and
/// grows from the free blocks, a block at a time, if that was too little:
/// host overhead is accounted as it is used, without a safety factor.
pub struct Arena {
    pub pool: UtPool<ARENA_REGIONS>,
    /// Untyped capabilities owned by the guest (slot, paddr, size bits):
    /// the arena's own regions and others (the I/O pool).  Revoking these
    /// destroys every object created from them.
    pub owned: ArrayVec<(Slot, usize, usize), ARENA_OWNED>,
}

impl Arena {
    pub const fn new() -> Self {
        Arena { pool: UtPool::empty(), owned: ArrayVec::new() }
    }

    /// Own the Untyped in `slot` besides the arena's regions (at most one
    /// per device and the I/O pool).
    pub fn own(&mut self, slot: Slot, paddr: usize, bits: usize) {
        self.owned.must_push((slot, paddr, bits));
    }

    /// Retype `count` objects of `bp` into `dest`, growing the arena if it
    /// has no room.  None if the host is out of memory.
    pub fn retype(&mut self, alloc: &mut Alloc, bp: &ObjectBlueprint, count: usize, dest: Dest) -> Option<usize> {
        if let Some(p) = self.pool.retype(bp, count, dest) {
            return Some(p);
        }
        let need = count << bp.physical_size_bits();
        let eighth = (self.bytes() / 8).max(1).ilog2() as usize;
        if !self.grow(alloc, need.next_power_of_two().trailing_zeros() as usize, eighth) {
            return None;
        }
        self.pool.retype(bp, count, dest)
    }

    /// Add a region of 2^bits bytes, preferably `preferred` bits, at
    /// least `minimum` (and ARENA_GROW_BITS): the preferred size may be
    /// unavailable even when a smaller block can satisfy the request, so
    /// take the largest block that fits.
    fn grow(&mut self, alloc: &mut Alloc, minimum: usize, preferred: usize) -> bool {
        if self.pool.regions.is_full() || self.owned.is_full() {
            return false;
        }
        let minimum = minimum.max(ARENA_GROW_BITS);
        let slot = alloc.slots.alloc();
        let Some(region) = (minimum..=preferred.max(minimum)).rev().find_map(|bits| alloc.split(bits, slot)) else {
            alloc.slots.free(slot);
            return false;
        };
        self.owned.must_push((slot, region.paddr, region.size_bits));
        let _ = self.pool.add(region);
        true
    }

    /// Grow until the arena has `bytes` free beyond what alignment may
    /// waste at the end of each region (ARENA_TAIL), so that objects of
    /// up to ARENA_TAIL bytes adding up to `bytes` (each counted with its
    /// alignment) cannot run out.  False if the host has too little
    /// memory, or it is too fragmented; what was added stays the arena's.
    /// Like `retype`, it prefers to grow by an eighth of the arena, so
    /// that many small reservations (VM_LOAD) do not fill its regions.
    pub fn reserve(&mut self, alloc: &mut Alloc, bytes: usize) -> bool {
        loop {
            let usable = self.pool.free_bytes().saturating_sub(self.pool.regions.len() * ARENA_TAIL);
            let Some(short) = bytes.checked_sub(usable).filter(|&n| n > 0) else {
                return true;
            };
            // Room for the tail of the new region too.
            let bits = (short + ARENA_TAIL).next_power_of_two().trailing_zeros() as usize;
            let eighth = (self.bytes() / 8).max(1).ilog2() as usize;
            if !self.grow(alloc, ARENA_GROW_BITS, bits.max(eighth)) {
                return false;
            }
        }
    }

    /// Bytes this arena holds (its own regions, not the I/O pool).
    pub fn bytes(&self) -> usize {
        self.pool.regions.iter().map(|r| r.size()).sum()
    }

    /// Allocate one object, or leave its slot free if it cannot fit.
    pub fn try_object(&mut self, alloc: &mut Alloc, bp: ObjectBlueprint) -> Option<Slot> {
        let s = alloc.slots.alloc();
        if self.retype(alloc, &bp, 1, Dest::new(alloc.slots.cnode(), s)).is_none() {
            alloc.slots.free(s);
            return None;
        }
        Some(s)
    }

    pub fn object(&mut self, alloc: &mut Alloc, bp: ObjectBlueprint) -> Slot {
        let ty = bp.ty();
        self.try_object(alloc, bp)
            .unwrap_or_else(|| panic!("out of host memory allocating {:?}", ty))
    }

    pub fn object_cap<T: sel4::CapType>(&mut self, alloc: &mut Alloc, bp: ObjectBlueprint) -> sel4::Cap<T> {
        let s = self.object(alloc, bp);
        sel4::Cap::<T>::from_bits(s as u64)
    }
}

/// Something objects can be allocated from: an arena (which grows from the
/// allocator), or the task's global pool.
pub struct ObjCtx<'a> {
    pub alloc: &'a mut Alloc,
    pub arena: Option<&'a mut Arena>,
}

impl<'a> ObjCtx<'a> {
    pub fn arena(alloc: &'a mut Alloc, arena: &'a mut Arena) -> Self {
        ObjCtx { alloc, arena: Some(arena) }
    }

    pub fn global(alloc: &'a mut Alloc) -> Self {
        ObjCtx { alloc, arena: None }
    }

    pub fn object(&mut self, bp: ObjectBlueprint) -> Slot {
        match &mut self.arena {
            Some(a) => a.object(self.alloc, bp),
            None => self.alloc.object(bp),
        }
    }


    pub fn cap<T: sel4::CapType>(&mut self, bp: ObjectBlueprint) -> sel4::Cap<T> {
        let s = self.object(bp);
        sel4::Cap::<T>::from_bits(s as u64)
    }
}

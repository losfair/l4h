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

/// One untyped capability supplied when the host starts.
pub struct Untyped {
    pub cap: cap::Untyped,
    pub paddr: usize,
    pub size_bits: usize,
    pub is_device: bool,
}

/// Maximum objects retyped by one kernel invocation.
pub const RETYPE_FAN_OUT: usize = sel4::sel4_cfg_usize!(RETYPE_FAN_OUT_LIMIT);

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

    /// Give the slots of owner `from` to owner `to`, which frees them in
    /// its time (objects a guest leaves behind that a driver still uses).
    pub fn reown(&mut self, from: usize, to: usize) {
        assert!(from < GLOBAL as usize && to < GLOBAL as usize, "slot owner out of range");
        for o in self.owners.iter_mut() {
            if *o == from as u8 {
                *o = to as u8;
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

    /// `retype` for an object type rust-sel4 has no blueprint for (FL4's
    /// AArch64 VCPU and Stage-2 VSpace on a kernel configured without
    /// hypervisor support): seL4 type number `obj_type`, of 2^size_bits
    /// bytes, fixed-size (no API size).  Same placement, fan-out and
    /// watermark as `retype`.
    pub fn retype_raw(&mut self, obj_type: u64, size_bits: usize, count: usize, dest: Dest) -> Option<usize> {
        let off = self.fit(size_bits, count)?;
        let mut done = 0;
        while done < count {
            let n = (count - done).min(RETYPE_FAN_OUT);
            retype_raw(self.cap, obj_type, &dest.cnode, dest.offset + done, n)
                .unwrap_or_else(|e| panic!("retype type {} x{} failed: {:?}", obj_type, n, e));
            done += n;
        }
        self.used = off + (count << size_bits);
        Some(self.paddr + off)
    }

    /// `retype` for frames that devices reach by DMA (`bp` is a 4 KiB or
    /// 2 MiB frame): shared with the hypervisor (`crate::retype_shared`)
    /// when `shared` (`Alloc::shared_dma`), ordinary frames otherwise.
    /// Shared frames take the same watermark as other objects.
    pub fn retype_dma(&mut self, shared: bool, bp: &ObjectBlueprint, count: usize, dest: Dest) -> Option<usize> {
        if !shared {
            return self.retype(bp, count, dest);
        }
        let bits = bp.physical_size_bits();
        assert!(bits == 12 || bits == 21, "unsupported shared DMA frame size 2^{}", bits);
        let off = self.fit(bits, count)?;
        // The kernel makes at most 256 4 KiB frames, or one 2 MiB frame,
        // per call.
        let limit = if bits == 12 { RETYPE_FAN_OUT.min(256) } else { 1 };
        let mut done = 0;
        while done < count {
            let n = (count - done).min(limit);
            crate::retype_shared(self.cap, bits, &dest.cnode, dest.offset + done, n)
                .unwrap_or_else(|e| panic!("shared retype 2^{} x{} failed: {:?}", bits, n, e));
            done += n;
        }
        self.used = off + (count << bits);
        Some(self.paddr + off)
    }
}

/// seL4_Untyped_Retype of `count` fixed-size objects of seL4 type
/// `obj_type`, which rust-sel4's ObjectBlueprint cannot name.
fn retype_raw(
    untyped: cap::Untyped,
    obj_type: u64,
    dst: &sel4::AbsoluteCPtr,
    dst_offset: usize,
    count: usize,
) -> sel4::Result<()> {
    let err = sel4::with_ipc_buffer_mut(|ipc| {
        ipc.inner_mut().seL4_Untyped_Retype(
            untyped.bits(),
            obj_type,
            0,
            dst.root().bits(),
            dst.path().bits(),
            dst.path().depth() as u64,
            dst_offset as u64,
            count as u64,
        )
    });
    sel4::Error::from_sys(err).map_or(Ok(()), Err)
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

    /// Whether an object of 2^bits bytes fits in a region.
    pub fn fits(&self, bits: usize) -> bool {
        self.regions.iter().any(|r| r.fit(bits, 1).is_some())
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

    /// `retype` of fixed-size objects of a raw seL4 type
    /// (`UtRegion::retype_raw`).
    pub fn retype_raw(&mut self, obj_type: u64, size_bits: usize, count: usize, dest: Dest) -> Option<usize> {
        let idx = self
            .regions
            .iter()
            .enumerate()
            .filter_map(|(i, r)| r.fit(size_bits, count).map(|off| (off - r.used, r.size_bits, i)))
            .min()
            .map(|(_, _, i)| i)?;
        self.regions[idx].retype_raw(obj_type, size_bits, count, dest)
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
    /// Devices reach only memory shared with the hypervisor (FL4 on a
    /// confidential VM, SEL4_BOOTINFO_HEADER_SHARED_DMA): DMA frames are
    /// made with `UtRegion::retype_dma`.  Set by the task at boot.
    pub shared_dma: bool,
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
/// less than half of one free; a full region is dropped from it.  Without
/// blocks that large (fragmented memory), smaller ones, down to 4 KiB.
const POOL_REGIONS: usize = 8;
/// Free bytes below which the pool takes any block it can get.
const POOL_LOW: usize = 1 << 20;
/// Free blocks, and split blocks, the allocator can keep track of: more
/// than the untypeds supplied at boot, and room for the
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
    pub fn new(slots: Slots, storage: &'static mut AllocStorage, untypeds: impl IntoIterator<Item = Untyped>) -> Self {
        let AllocStorage { blocks, parents, grants } = storage;
        Self::with_tables(Alloc { slots, pool: UtPool::empty(), blocks, parents, memd: None, shared_dma: false, grants }, untypeds)
    }

    /// An allocator with no memory until it is given a link to memd
    /// (vmmgr's: all it has are grants).
    pub fn empty(slots: Slots, storage: &'static mut AllocStorage) -> Self {
        let AllocStorage { blocks, parents, grants } = storage;
        Alloc { slots, pool: UtPool::empty(), blocks, parents, memd: None, shared_dma: false, grants }
    }

    /// A new allocator for `untypeds`, with this one's slots and tables:
    /// storage is reused without allocating another set of tables.
    pub fn renew(self, untypeds: impl IntoIterator<Item = Untyped>) -> Self {
        let Alloc { slots, blocks, parents, grants, .. } = self;
        blocks.clear();
        parents.clear();
        grants.clear();
        Self::with_tables(Alloc { slots, pool: UtPool::empty(), blocks, parents, memd: None, shared_dma: false, grants }, untypeds)
    }

    fn with_tables(mut a: Self, untypeds: impl IntoIterator<Item = Untyped>) -> Self {
        for desc in untypeds {
            if !desc.is_device {
                a.blocks.must_push(UtRegion::fresh(desc.cap, desc.paddr, desc.size_bits));
            }
        }
        a.refill();
        a
    }

    /// Keep the small-object pool stocked, preserving message registers:
    /// with a region of SMALL_POOL_BITS when it has less than half of one
    /// free, if there is a block that large, here or in memd.
    pub fn refill(&mut self) {
        self.stock(12, false);
    }

    /// `refill`, and make sure that the pool has room for an object of
    /// 2^bits bytes (`object`).  When there is no block of SMALL_POOL_BITS
    /// (or 2^bits, if larger), here or in memd, and the pool cannot serve
    /// the object or has less than POOL_LOW bytes left, it takes the
    /// largest smaller block there is, down to 2^bits: memory fragmented
    /// into 2 MiB blocks, which guests leave, must not make the next host
    /// object panic while there is plenty of it.  Above POOL_LOW the pool
    /// waits for a large block, without calling memd (its status says
    /// when it has one), so that it does not fill with small regions, nor
    /// drop regions that still have room (`add_pool_block`).
    pub fn refill_for(&mut self, bits: usize) {
        self.stock(bits, true);
    }

    fn stock(&mut self, bits: usize, fallback: bool) {
        let bits = bits.max(12);
        let fits = self.pool.fits(bits);
        if fits && self.pool.free_bytes() >= 1 << (SMALL_POOL_BITS - 1) {
            return;
        }
        // Root and vmmgr refill before dispatching received calls and
        // faults.  Both kernel invocations and calls to memd overwrite
        // the IPC buffer, so keep the incoming message across this work.
        l4h_ipc::preserving(|| {
            // Regions too full to be of use leave the pool; their objects
            // stay, as global objects do.
            self.pool.regions.retain(|r| r.size() - r.used >= 4096);
            let urgent = fallback && (!self.pool.fits(bits) || self.pool.free_bytes() < POOL_LOW);
            let want = SMALL_POOL_BITS.max(bits);
            // What memd may have: its status names the largest block it
            // has without merging (a lower bound); an unreadable status
            // tells nothing, so a grant is tried.
            let memd = self.memd.map(|m| m.status().map_or(usize::MAX, |s| match s.largest_block as usize {
                0 => 0,
                b => b.trailing_zeros() as usize,
            }));
            let local = self.blocks.iter().map(|b| b.size_bits).max().unwrap_or(0);
            let avail = local.max(memd.unwrap_or(0));
            // A block of the preferred size: when there is one, or one
            // merging could make (in memd, whose status does not count
            // those, only with the pool short).
            if (urgent || avail >= want || memd.is_none()) && self.add_pool_block(want, urgent) {
                return;
            }
            if !urgent {
                return;
            }
            // That split merged what local buddies it could: blocks that
            // may now be larger.
            let local = self.blocks.iter().map(|b| b.size_bits).max().unwrap_or(0);
            let avail = local.max(memd.unwrap_or(0));
            // Fragmented: the largest smaller block there is, if any is
            // large enough for the object.  memd has none below 2 MiB:
            // smaller ones are local blocks, which no call to it is made for.
            let mut b = avail.min(want - 1);
            while b >= bits {
                if b < BLOCK_BITS {
                    b = b.min(local);
                    if b < bits {
                        break;
                    }
                }
                if self.add_pool_block(b, true) {
                    return;
                }
                b -= 1;
            }
        })
    }

    /// Add a block of 2^bits bytes to the pool.  A full pool drops the
    /// region with the least room for it, whose room is lost (its objects
    /// stay): only when `urgent`, or when that room is at most a sixteenth
    /// of the new block.  False, with nothing dropped, if no block could
    /// be had.
    fn add_pool_block(&mut self, bits: usize, urgent: bool) -> bool {
        let drop = if self.pool.regions.is_full() {
            let (i, r) = self.pool.regions.iter().enumerate().min_by_key(|(_, r)| r.size() - r.used).unwrap();
            if !urgent && (r.size() - r.used) * 16 > 1 << bits {
                return false;
            }
            Some(i)
        } else {
            None
        };
        let s = self.slots.global(|s| s.alloc());
        let Some(r) = self.split(bits, s) else {
            self.slots.global(|sl| sl.free(s));
            return false;
        };
        if let Some(i) = drop {
            self.pool.regions.remove(i);
        }
        let _ = self.pool.add(r);
        true
    }

    fn local_bytes(&self) -> usize {
        self.blocks.iter().map(|b| 1usize << b.size_bits).sum()
    }

    /// Free memory here, not in memd.
    pub fn local_free_bytes(&self) -> usize {
        self.local_bytes() + self.pool.free_bytes()
    }

    /// Free memory, here and in memd.  A status page that could not be
    /// read whole (memd was writing it at every look) counts as no free
    /// memory in memd: a caller that checks what it can afford refuses,
    /// rather than go by a number that memd never wrote.
    pub fn free_bytes(&self) -> usize {
        self.local_bytes() + self.pool.free_bytes() + self.memd.and_then(|m| m.status()).map_or(0, |s| s.free_bytes as usize)
    }

    /// Free memory reported to the hypervisor, in bytes (memd).
    pub fn reported_bytes(&self) -> usize {
        self.memd.and_then(|m| m.status()).map_or(0, |s| s.reported_bytes as usize)
    }

    /// Largest block available, here or in memd.
    pub fn largest_block_bits(&self) -> Option<usize> {
        let memd = self.memd.and_then(|m| m.status()).map(|s| s.largest_block as usize).filter(|&b| b != 0).map(|b| b.trailing_zeros() as usize);
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

    /// Can the kernel create `bp`?  Types it refuses at runtime (VT-x objects
    /// on a CPU without VT-x) would panic in the ordinary paths.  Costs the
    /// page or so of the attempt for good, so this is for boot.
    pub fn can_retype(&mut self, bp: &ObjectBlueprint) -> bool {
        let ut = self.slots.alloc();
        let dest = self.slots.alloc();
        let Some(r) = self.split(bp.physical_size_bits(), ut) else {
            return false;
        };
        r.cap.untyped_retype(bp, &cnode_dest(self.slots.cnode()), dest, 1).is_ok()
    }

    /// `can_retype` for a raw seL4 object type of 2^size_bits bytes
    /// (`UtRegion::retype_raw`): FL4's AArch64 VCPU, which it refuses
    /// without EL2.
    pub fn can_retype_raw(&mut self, obj_type: u64, size_bits: usize) -> bool {
        let ut = self.slots.alloc();
        let dest = self.slots.alloc();
        let Some(r) = self.split(size_bits, ut) else {
            return false;
        };
        retype_raw(r.cap, obj_type, &cnode_dest(self.slots.cnode()), dest, 1).is_ok()
    }

    /// Allocate a single object into a fresh local slot.
    pub fn object(&mut self, bp: ObjectBlueprint) -> Slot {
        self.refill_for(bp.physical_size_bits());
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
    /// be stopped may still write to them.  They are not revoked either:
    /// they move, with their objects, to global slots for good (deleting
    /// shared DMA frames makes their memory private again, which a device
    /// still writing must not see), leaving the owner's slots empty.  The
    /// caller keeps capabilities to those objects held elsewhere that must
    /// not go (`Slots::free_owned` would delete them).  Returns the bytes
    /// kept out of use.
    pub fn reclaim_pinning(&mut self, arena: Arena, pin: impl Fn(usize) -> bool) -> usize {
        self.reclaim_inner(arena, pin, false)
    }

    fn reclaim_inner(&mut self, arena: Arena, pin: impl Fn(usize) -> bool, free_slots: bool) -> usize {
        let mut pinned = 0;
        for &(slot, paddr, bits) in arena.owned.iter() {
            let cap = untyped_at(slot);
            if pin(paddr) {
                let s = self.slots.global(|s| s.alloc());
                self.slots.cnode().absolute_cptr(untyped_at(s)).move_(&self.slots.cnode().absolute_cptr(cap)).expect("keep pinned untyped");
                if free_slots {
                    self.slots.free(slot);
                }
                pinned += 1 << bits;
                continue;
            }
            self.slots.cnode().absolute_cptr(cap).revoke().expect("revoke arena untyped");
            if self.blocks.is_full() {
                self.merge_up_to(usize::MAX);
            }
            if self.blocks.is_full() {
                log!("l4h-task: free block table full, {} KiB lost", (1usize << bits) >> 10);
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
            let taken = self.give_back(memd, |a, b| {
                let size = 1usize << b.size_bits;
                let back = b.size_bits == bits && a.is_grant(b.paddr, b.size_bits) && keep >= LOCAL_KEEP + size;
                if back {
                    keep -= size;
                }
                back
            });
            // A memd that takes none back (it has failed) is not asked for
            // every other size too: the grants stay here, in use.
            if !taken {
                return;
            }
        }
    }

    /// Move the free blocks for which `pick` is true (untouched) to memd,
    /// and free their slots.  False if memd did not take a batch (it has
    /// failed): the blocks of that batch it left us are free blocks here
    /// again, grants as they were, and no more are offered.
    fn give_back(&mut self, memd: MemdLink, mut pick: impl FnMut(&Self, &UtRegion) -> bool) -> bool {
        const _: () = assert!(l4h_host::memd::XCHG_SLOTS <= u64::BITS as usize);
        loop {
            let mut batch: ArrayVec<(cap::Untyped, usize, usize), { l4h_host::memd::XCHG_SLOTS }> = ArrayVec::new();
            // The blocks of the batch that are grants: bit n for block n.
            let mut grants = 0u64;
            let mut i = 0;
            while i < self.blocks.len() && !batch.is_full() {
                if pick(self, &self.blocks[i]) {
                    let b = self.blocks.swap_remove(i);
                    if let Some(g) = self.grants.iter().position(|&g| g == (b.paddr, b.size_bits)) {
                        self.grants.swap_remove(g);
                        grants |= 1 << batch.len();
                    }
                    batch.must_push((b.cap, b.paddr, b.size_bits));
                } else {
                    i += 1;
                }
            }
            if batch.is_empty() {
                return true;
            }
            let back = memd.free(&batch).err();
            for (n, &(cap, paddr, bits)) in batch.iter().enumerate() {
                if back.as_ref().is_some_and(|b| b[n]) {
                    // Their places in the tables were just left.
                    self.blocks.must_push(UtRegion::fresh(cap, paddr, bits));
                    if grants & (1 << n) != 0 {
                        self.grants.must_push((paddr, bits));
                    }
                } else {
                    self.slots.global(|sl| sl.free(cap.bits() as Slot));
                }
            }
            if back.is_some() {
                return false;
            }
        }
    }

    /// Undo a partly built arena, or one made outside any owner's slot
    /// tracking: reclaim its memory and free its slots.
    pub fn release(&mut self, arena: Arena) {
        self.reclaim_inner(arena, |_| false, true);
    }

    /// `release`, and free `objects`, the slots of objects made from the
    /// arena (`Arena::try_object`): revoking its Untypeds deleted them, but
    /// their slots stay allocated otherwise, a leak each time a caller
    /// gives up on an arena.
    pub fn release_objects(&mut self, arena: Arena, objects: &[Slot]) {
        self.release(arena);
        for &s in objects {
            self.slots.free(s);
        }
    }

    /// A DMA region of 2^bits bytes in an Untyped of its own, all of it
    /// frames of `bp` (shared ones if `shared`), and the CNode of those
    /// frames, made from an arena of its own: or None if memory is short
    /// or too fragmented, with nothing kept.  Not from the global pool,
    /// whose allocations panic.  The caller keeps the result's arena for
    /// as long as the region, or gives both back with `release_objects`
    /// (arena, [frames]).
    pub fn dma_frames(&mut self, bits: usize, shared: bool, bp: &ObjectBlueprint) -> Option<DmaFrames> {
        let pages = 1usize << bits.checked_sub(bp.physical_size_bits())?;
        let frames_bits = (pages.next_power_of_two().trailing_zeros() as usize).max(1);
        // The region first, the largest: the smallest free block that
        // holds it, before the CNode's arena splits one.
        let slot = self.slots.alloc();
        let Some(mut region) = self.split(bits, slot) else {
            self.slots.free(slot);
            return None;
        };
        let Some(mut arena) = self.arena(32 << frames_bits) else {
            let mut alone = Arena::new();
            alone.own(slot, region.paddr, bits);
            self.release(alone);
            return None;
        };
        // The arena's from here: revoked and given back with it.
        arena.own(slot, region.paddr, bits);
        let Some(frames) = arena.try_object(self, ObjectBlueprint::CNode { size_bits: frames_bits }) else {
            self.release(arena);
            return None;
        };
        let dest = Dest::new(sel4::Cap::from_bits(frames as u64), 0);
        if region.retype_dma(shared, bp, pages, dest).is_none() {
            self.release_objects(arena, &[frames]);
            return None;
        }
        Some(DmaFrames { paddr: region.paddr, frames, frames_bits, arena })
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
/// Regions of an arena, and the Untypeds it owns besides (`Arena::own`):
/// the I/O pool and its mapping CNode's, and netd ports, at most one per
/// device.
const ARENA_REGIONS: usize = 96;
/// What alignment may leave unusable at the end of a region, for
/// Arena::reserve: the largest object allocated in quantity (a 16 KiB RAM
/// CNode) and the space before it.
pub const ARENA_TAIL: usize = 32 << 10;
const ARENA_OWNED: usize = ARENA_REGIONS + 2 + l4h_host::MAX_GUEST_DEVICES;

/// A DMA region and the CNode of its frames (`Alloc::dma_frames`).
pub struct DmaFrames {
    pub paddr: usize,
    /// The CNode of its frames, in a slot of ours: radix `frames_bits`.
    pub frames: Slot,
    pub frames_bits: usize,
    /// The CNode's memory, and the region's Untyped.
    pub arena: Arena,
}

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
    /// per device, the I/O pool and the Untyped of its mapping CNode:
    /// ARENA_OWNED holds them with every region).
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

    /// `retype` of fixed-size objects of a raw seL4 type
    /// (`UtRegion::retype_raw`), growing the arena as `retype` does.
    pub fn retype_raw(
        &mut self,
        alloc: &mut Alloc,
        obj_type: u64,
        size_bits: usize,
        count: usize,
        dest: Dest,
    ) -> Option<usize> {
        if let Some(p) = self.pool.retype_raw(obj_type, size_bits, count, dest) {
            return Some(p);
        }
        let need = count << size_bits;
        let eighth = (self.bytes() / 8).max(1).ilog2() as usize;
        if !self.grow(alloc, need.next_power_of_two().trailing_zeros() as usize, eighth) {
            return None;
        }
        self.pool.retype_raw(obj_type, size_bits, count, dest)
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

    /// `object_cap` for a raw seL4 type of 2^size_bits bytes
    /// (`UtRegion::retype_raw`).
    pub fn object_cap_raw<T: sel4::CapType>(&mut self, alloc: &mut Alloc, obj_type: u64, size_bits: usize) -> sel4::Cap<T> {
        let s = alloc.slots.alloc();
        if self.retype_raw(alloc, obj_type, size_bits, 1, Dest::new(alloc.slots.cnode(), s)).is_none() {
            alloc.slots.free(s);
            panic!("out of host memory allocating object type {}", obj_type);
        }
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

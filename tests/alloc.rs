//! Run with tests/run-alloctest.sh.  Exercise the shared task allocator and
//! fixed containers on the host; only seL4 capability operations are stubs.
#![allow(dead_code)]

extern crate self as l4h_host;
extern crate self as sel4;
extern crate self as l4h_ipc;

#[macro_export]
macro_rules! sel4_cfg_usize {
    (RETYPE_FAN_OUT_LIMIT) => { 256 };
}

/// l4h_ipc::preserving, on the mock IPC buffer.
pub fn preserving<R>(f: impl FnOnce() -> R) -> R {
    let regs = with_ipc_buffer(|b| b.msg);
    let r = f();
    with_ipc_buffer_mut(|b| b.msg = regs);
    r
}

macro_rules! log { ($($arg:tt)*) => { println!($($arg)*) }; }

#[path = "../host/l4h-host/src/fixed.rs"]
pub mod fixed;
#[path = "../host/l4h-task/src/bootinfo.rs"]
mod bootinfo;
#[path = "../host/l4h-task/src/mem.rs"]
mod mem;

pub const MAX_GUEST_DEVICES: usize = 64;
pub const CNODE_SLOTS: usize = 1 << 19;
pub use init_thread::slot;
static SLOT_STORAGE: fixed::StaticCell<mem::SlotStorage<{ CNODE_SLOTS / 64 }, CNODE_SLOTS>> =
    fixed::StaticCell::new(mem::SlotStorage::new());
static ALLOC_STORAGE: fixed::StaticCell<mem::AllocStorage> = fixed::StaticCell::new(mem::AllocStorage::new());

pub const NUM_MESSAGE_REGISTERS: usize = 120;

pub struct IpcBuffer {
    msg: [u64; NUM_MESSAGE_REGISTERS],
}

impl IpcBuffer {
    pub fn msg_regs(&self) -> &[u64] { &self.msg }
    pub fn msg_regs_mut(&mut self) -> &mut [u64] { &mut self.msg }
}

thread_local! {
    static IPC_BUFFER: std::cell::RefCell<IpcBuffer> = const {
        std::cell::RefCell::new(IpcBuffer { msg: [0; NUM_MESSAGE_REGISTERS] })
    };
}

pub fn with_ipc_buffer<R>(f: impl FnOnce(&IpcBuffer) -> R) -> R {
    IPC_BUFFER.with_borrow(f)
}

pub fn with_ipc_buffer_mut<R>(f: impl FnOnce(&mut IpcBuffer) -> R) -> R {
    IPC_BUFFER.with_borrow_mut(f)
}

pub mod cap_type {
    #[derive(Clone, Copy)]
    pub struct Null;
    #[derive(Clone, Copy)]
    pub struct CNode;
    #[derive(Clone, Copy)]
    pub struct Untyped;
}

pub trait CapType: Copy {}
impl CapType for cap_type::Null {}
impl CapType for cap_type::CNode {}
impl CapType for cap_type::Untyped {}

#[derive(Clone, Copy)]
pub struct Cap<T>(u64, core::marker::PhantomData<T>);

impl<T> Cap<T> {
    pub fn from_bits(bits: u64) -> Self { Self(bits, core::marker::PhantomData) }
    pub fn bits(&self) -> u64 { self.0 }
    pub fn absolute_cptr<U>(&self, c: Cap<U>) -> AbsoluteCPtr { AbsoluteCPtr { cnode: self.0, path: c.0 } }
    pub fn absolute_cptr_for_self(&self) -> AbsoluteCPtr { AbsoluteCPtr { cnode: self.0, path: 0 } }
    pub fn untyped_retype(&self, _: &ObjectBlueprint, dest: &AbsoluteCPtr, offset: usize, count: usize) -> Result<(), ()> {
        assert!((1..=sel4_cfg_usize!(RETYPE_FAN_OUT_LIMIT)).contains(&count));
        RETYPES.with_borrow_mut(|v| v.push(dest.cnode));
        RETYPE_WINDOWS.with_borrow_mut(|v| v.push((offset, count)));
        // Kernel invocations marshal their arguments into the IPC buffer.
        with_ipc_buffer_mut(|b| b.msg_regs_mut()[..6].fill(0xdead_beef));
        Ok(())
    }
}

/// FL4's seL4_Untyped_RetypeShared (l4h_task::retype_shared), with its
/// limits: up to 256 4 KiB frames, or one 2 MiB frame, per call.
pub fn retype_shared(untyped: cap::Untyped, size_bits: usize, dst: &AbsoluteCPtr, dst_offset: usize, count: usize) -> Result<(), ()> {
    assert!((size_bits == 12 && (1..=256).contains(&count)) || (size_bits == 21 && count == 1), "2^{size_bits} x{count}");
    SHARED_RETYPES.with_borrow_mut(|v| v.push((untyped.bits(), size_bits, dst.cnode, dst_offset, count)));
    with_ipc_buffer_mut(|b| b.msg_regs_mut()[..6].fill(0xdead_beef));
    Ok(())
}

/// seL4_Untyped_Retype of a raw object type (l4h_task::retype_raw).
pub fn retype_raw(_untyped: cap::Untyped, _obj_type: u64, dst: &AbsoluteCPtr, dst_offset: usize, count: usize) -> Result<(), ()> {
    assert!((1..=sel4_cfg_usize!(RETYPE_FAN_OUT_LIMIT)).contains(&count));
    RETYPES.with_borrow_mut(|v| v.push(dst.cnode));
    RETYPE_WINDOWS.with_borrow_mut(|v| v.push((dst_offset, count)));
    with_ipc_buffer_mut(|b| b.msg_regs_mut()[..6].fill(0xdead_beef));
    Ok(())
}

pub mod cap {
    pub type Untyped = crate::Cap<crate::cap_type::Untyped>;
    pub type CNode = crate::Cap<crate::cap_type::CNode>;
}

/// A slot: the CNode it is in, and its index there (0 for the CNode itself).
#[derive(Clone, Copy)]
pub struct AbsoluteCPtr { cnode: u64, path: u64 }

thread_local! {
    static RETYPES: std::cell::RefCell<Vec<u64>> = const { std::cell::RefCell::new(Vec::new()) };
    static RETYPE_WINDOWS: std::cell::RefCell<Vec<(usize, usize)>> = const { std::cell::RefCell::new(Vec::new()) };
    static DELETES: std::cell::RefCell<Vec<u64>> = const { std::cell::RefCell::new(Vec::new()) };
    /// Slots deleted, revoked, and moved (to, from).
    static DELETED_SLOTS: std::cell::RefCell<Vec<u64>> = const { std::cell::RefCell::new(Vec::new()) };
    static REVOKES: std::cell::RefCell<Vec<u64>> = const { std::cell::RefCell::new(Vec::new()) };
    static MOVES: std::cell::RefCell<Vec<(u64, u64)>> = const { std::cell::RefCell::new(Vec::new()) };
    /// retype_shared calls: (untyped, size bits, destination CNode, offset, count).
    static SHARED_RETYPES: std::cell::RefCell<Vec<(u64, usize, u64, usize, usize)>> = const { std::cell::RefCell::new(Vec::new()) };
}

impl AbsoluteCPtr {
    pub fn delete(&self) -> Result<(), ()> {
        DELETES.with_borrow_mut(|v| v.push(self.cnode));
        DELETED_SLOTS.with_borrow_mut(|v| v.push(self.path));
        Ok(())
    }
    pub fn revoke(&self) -> Result<(), ()> { REVOKES.with_borrow_mut(|v| v.push(self.path)); Ok(()) }
    pub fn move_(&self, src: &Self) -> Result<(), ()> { MOVES.with_borrow_mut(|v| v.push((self.path, src.path))); Ok(()) }
}

pub mod init_thread {
    pub struct Slot<T> {
        index: usize,
        marker: core::marker::PhantomData<T>,
    }

    impl<T> Slot<T> {
        pub const fn from_index(index: usize) -> Self { Self { index, marker: core::marker::PhantomData } }
        pub fn cap(&self) -> crate::Cap<T> { crate::Cap::from_bits(self.index as u64) }
    }

    pub mod slot {
        pub const CNODE: super::Slot<crate::cap_type::CNode> = super::Slot::from_index(1);
    }
}

pub enum ObjectBlueprint {
    Untyped { size_bits: usize },
    CNode { size_bits: usize },
    Frame,
    LargePage,
}

impl ObjectBlueprint {
    pub fn physical_size_bits(&self) -> usize {
        match self {
            Self::Untyped { size_bits } => *size_bits,
            Self::CNode { size_bits } => size_bits + 5,
            Self::Frame => 12,
            Self::LargePage => 21,
        }
    }

    pub fn ty(&self) -> usize { self.physical_size_bits() }
}

pub struct Desc {
    paddr: usize,
    bits: usize,
}

impl Desc {
    fn paddr(&self) -> usize { self.paddr }
    fn size_bits(&self) -> usize { self.bits }
    fn is_device(&self) -> bool { false }
}

pub struct FrameObjectType;
pub struct BootGranule;

impl FrameObjectType {
    pub const GRANULE: BootGranule = BootGranule;
}

impl BootGranule {
    fn bytes(&self) -> usize { 4096 }
}

pub struct BootInfoPtr {
    bytes: &'static [u8],
    descriptors: Vec<Desc>,
}

struct UntypedSlots(usize);

impl UntypedSlots {
    fn range(&self) -> std::ops::Range<usize> { 32..32 + self.0 }
    fn index(&self, index: usize) -> init_thread::Slot<cap_type::Untyped> {
        init_thread::Slot::from_index(self.range().start + index)
    }
}

impl BootInfoPtr {
    fn ptr(&self) -> *const u8 { self.bytes.as_ptr() }
    fn footprint_size(&self) -> usize { self.bytes.len() }
    fn untyped_list(&self) -> &[Desc] { &self.descriptors }
    fn untyped(&self) -> UntypedSlots { UntypedSlots(self.descriptors.len()) }
}

pub fn cap_at<T: CapType>(slot: usize) -> Cap<T> { Cap::from_bits(slot as u64) }

fn bootinfo_fixture(extra: &[u8]) -> BootInfoPtr {
    let mut bytes = vec![0; 4096];
    bytes.extend_from_slice(extra);
    BootInfoPtr {
        bytes: bytes.leak(),
        descriptors: (0..230).map(|i| Desc { paddr: i << 12, bits: 12 }).collect(),
    }
}

#[test]
fn bootinfo_overflow_keeps_untyped_slots_contiguous() {
    let mut extra = Vec::new();
    // An unrelated chunk precedes the overflow descriptors.
    for word in [99u64, 16, 10, 48] {
        extra.extend_from_slice(&word.to_le_bytes());
    }
    for (paddr, bits, device) in [(0x200000u64, 21, false), (0xfec00000, 12, true)] {
        extra.extend_from_slice(&paddr.to_le_bytes());
        extra.extend_from_slice(&[bits, u8::from(device), 0, 0, 0, 0, 0, 0]);
    }
    let bootinfo = bootinfo_fixture(&extra);
    let untypeds: Vec<_> = bootinfo::untypeds(&bootinfo).collect();
    assert_eq!(untypeds.len(), 232);
    assert_eq!(untypeds[229].cap.bits(), 261);
    let overflow: Vec<_> = untypeds[230..].iter().map(|u| {
        (u.cap.bits(), u.paddr, u.size_bits, u.is_device)
    }).collect();
    assert_eq!(overflow, [(262, 0x200000, 21, false), (263, 0xfec00000, 12, true)]);
}

#[test]
fn bootinfo_ignores_missing_empty_and_truncated_overflow() {
    for (extra, chunk) in [
        (vec![], None),
        ([10u64, 16].into_iter().flat_map(u64::to_le_bytes).collect(), Some(&[][..])),
        ([10u64, 32, 0].into_iter().flat_map(u64::to_le_bytes).collect(), None),
    ] {
        let bootinfo = bootinfo_fixture(&extra);
        assert_eq!(bootinfo::extra_chunk(&bootinfo, 10), chunk);
        assert_eq!(bootinfo::untypeds(&bootinfo).count(), 230);
    }
}

struct BootMemory(Vec<Desc>);

impl IntoIterator for &BootMemory {
    type Item = mem::Untyped;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter().enumerate().map(|(i, desc)| mem::Untyped {
            cap: init_thread::Slot::<cap_type::Untyped>::from_index(32 + i).cap(),
            paddr: desc.paddr,
            size_bits: desc.bits,
            is_device: false,
        }).collect::<Vec<_>>().into_iter()
    }
}

pub mod memd {
    pub const BLOCK_BITS: usize = 21;
    pub const XCHG_SLOTS: usize = 32;

    /// How the memd of a test answers `free`.
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub enum Free {
        /// No test expects one.
        Unexpected,
        /// It takes the blocks.
        Takes,
        /// It has failed: the blocks are back in the caller's slots.
        Failed,
        /// It failed after taking them.
        FailedHolding,
    }

    thread_local! {
        pub static GRANTS: std::cell::RefCell<Vec<Option<usize>>> = const { std::cell::RefCell::new(Vec::new()) };
        /// memd's status page, if it can be read whole.
        pub static STATUS: std::cell::Cell<Option<Status>> = const { std::cell::Cell::new(None) };
        pub static FREE: std::cell::Cell<Free> = const { std::cell::Cell::new(Free::Unexpected) };
        /// The batches `free` was called with: (physical address, size bits).
        pub static FREED: std::cell::RefCell<Vec<Vec<(usize, usize)>>> = const { std::cell::RefCell::new(Vec::new()) };
        /// The largest block memd can grant (2^bits bytes): a larger
        /// request fails, and takes nothing from GRANTS.
        pub static MAX_BITS: std::cell::Cell<usize> = const { std::cell::Cell::new(usize::MAX) };
        /// Calls to `alloc`: (size bits asked for, whether granted).
        pub static ALLOCS: std::cell::RefCell<Vec<(usize, bool)>> = const { std::cell::RefCell::new(Vec::new()) };
    }

    #[derive(Clone, Copy)]
    pub struct MemdLink;
    #[derive(Clone, Copy)]
    pub struct Status {
        pub free_bytes: u64,
        pub reported_bytes: u64,
        pub largest_block: u64,
    }

    impl MemdLink {
        pub fn status(&self) -> Option<Status> { STATUS.get() }
        pub fn alloc(&self, bits: usize, _: usize) -> Option<usize> {
            let paddr = if bits > MAX_BITS.get() {
                None
            } else {
                GRANTS.with_borrow_mut(|g| g.pop().expect("unexpected memd allocation"))
            };
            ALLOCS.with_borrow_mut(|a| a.push((bits, paddr.is_some())));
            crate::with_ipc_buffer_mut(|b| {
                b.msg_regs_mut()[..2].copy_from_slice(&[if paddr.is_some() { 0 } else { u64::MAX }, paddr.unwrap_or(0) as u64]);
            });
            paddr
        }
        pub fn free(&self, blocks: &[(crate::cap::Untyped, usize, usize)]) -> Result<(), crate::fixed::ArrayVec<bool, XCHG_SLOTS>> {
            FREED.with_borrow_mut(|f| f.push(blocks.iter().map(|&(_, paddr, bits)| (paddr, bits)).collect()));
            match FREE.get() {
                Free::Unexpected => panic!("no memd in this test"),
                Free::Takes => Ok(()),
                back => Err(blocks.iter().map(|_| back == Free::Failed).collect()),
            }
        }
    }
}

#[test]
fn retype_respects_kernel_fanout_and_keeps_contiguous_placement() {
    RETYPE_WINDOWS.with_borrow_mut(|windows| windows.clear());
    let base = 64 << 20;
    let mut region = mem::UtRegion::fresh(cap::Untyped::from_bits(1), base, 24);
    let dest = mem::Dest::new(slot::CNODE.cap(), 1024);
    let count = 2 * sel4_cfg_usize!(RETYPE_FAN_OUT_LIMIT) + 1;
    assert_eq!(region.retype(&ObjectBlueprint::Frame, count, dest), Some(base));
    RETYPE_WINDOWS.with_borrow(|windows| {
        assert!(windows.len() > 1);
        let mut next = dest.offset;
        for &(offset, n) in windows {
            assert_eq!(offset, next);
            next += n;
        }
        assert_eq!(next, dest.offset + count);
    });
    let next = mem::Dest { offset: dest.offset + count, ..dest };
    assert_eq!(region.retype(&ObjectBlueprint::Frame, 1, next), Some(base + (count << 12)));
}

#[test]
fn arena_growth_on_fragmented_memory_and_reclaim() {
    // Disjoint 2 MiB blocks with occupied holes between them; no buddies
    // can merge.  Slots and allocator tables are taken only once.
    let boot = BootMemory((0..48).map(|i| Desc { paddr: (64 << 20) + i * (4 << 20), bits: 21 }).collect());
    let mut alloc = mem::Alloc::new(
        mem::Slots::new(slot::CNODE.cap(), SLOT_STORAGE.take(), 1024..CNODE_SLOTS), ALLOC_STORAGE.take(), &boot,
    );
    let mut arena = alloc.arena(32 << 20).unwrap();
    let block = ObjectBlueprint::Untyped { size_bits: 21 };
    for i in 0..16 {
        assert!(arena.retype(&mut alloc, &block, 1, mem::Dest::new(slot::CNODE.cap(), 512 + i)).is_some());
    }
    assert_eq!(alloc.free_bytes(), 64 << 20);

    // A 4 MiB request really cannot fit: do not fall back below its size
    // or consume any memory or slots on failure.
    let slots = alloc.slots.available();
    assert!(arena.retype(&mut alloc, &ObjectBlueprint::Untyped { size_bits: 22 }, 1, mem::Dest::new(slot::CNODE.cap(), 528)).is_none());
    assert_eq!(alloc.free_bytes(), 64 << 20);
    assert_eq!(alloc.slots.available(), slots);

    // A page does fit, despite the arena's preferred 4 MiB growth size.
    arena.object(&mut alloc, ObjectBlueprint::Frame);
    assert_eq!(arena.bytes(), 34 << 20);
    assert_eq!(alloc.free_bytes(), 62 << 20);
    alloc.reclaim(arena);
    assert_eq!(alloc.free_bytes(), 96 << 20);

    // Exhaustion still fails cleanly and gives back the attempted slot.
    let mut arena = alloc.arena(96 << 20).unwrap();
    for i in 0..48 {
        assert!(arena.retype(&mut alloc, &block, 1, mem::Dest::new(slot::CNODE.cap(), 512 + i)).is_some());
    }
    let slots = alloc.slots.available();
    assert!(arena.retype(&mut alloc, &ObjectBlueprint::Frame, 1, mem::Dest::new(slot::CNODE.cap(), 560)).is_none());
    assert_eq!(alloc.free_bytes(), 0);
    assert_eq!(alloc.slots.available(), slots);
    alloc.reclaim(arena);
    assert_eq!(alloc.free_bytes(), 96 << 20);

    // Reuse the slot and allocator tables for a larger
    // fragmented fixture.
    // VM_LOAD reserves one block's CNode and paging overhead before
    // making objects: a full arena must refuse despite free host RAM.
    let boot = BootMemory((0..256).map(|i| Desc { paddr: (64 << 20) + i * (4 << 20), bits: 21 }).collect());
    let mut alloc = alloc.renew(&boot);
    let mut arena = alloc.arena(4 << 20).unwrap();
    let load_bytes = (32 << 10) + 2 * 4096;
    let mut loads = 0;
    while arena.reserve(&mut alloc, load_bytes) {
        arena.object(&mut alloc, ObjectBlueprint::CNode { size_bits: 9 });
        arena.object(&mut alloc, ObjectBlueprint::Frame);
        loads += 1;
        assert!(loads < 13000, "arena table never filled");
    }
    assert!(loads > 0);
    assert!(alloc.free_bytes() > 32 << 20);
    let slots = alloc.slots.available();
    assert!(!arena.reserve(&mut alloc, load_bytes));
    assert_eq!(alloc.slots.available(), slots);
    alloc.reclaim(arena);
    assert_eq!(alloc.free_bytes(), 512 << 20);

    // Reproduce VM_START after loads have nearly filled the arena table:
    // the boot-block reservation still fits, but the VMM's does not.
    // A large I/O pool needs a 2 MiB mapping CNode as well, which total
    // free bytes alone cannot promise.  Keep its CNodes from creation.
    let boot = BootMemory((0..256).map(|i| Desc { paddr: (64 << 20) + i * (4 << 20), bits: 21 }).collect());
    let mut alloc = alloc.renew(&boot);
    let mut arena = alloc.arena(8 << 20).unwrap();
    for bits in [12, 16, 12] {
        assert!(arena.try_object(&mut alloc, ObjectBlueprint::CNode { size_bits: bits }).is_some());
    }
    let boot_bytes = 8 * (32 << 10) + 20 * 4096;
    loop {
        let usable = arena.pool.free_bytes().saturating_sub(arena.pool.regions.len() * (32 << 10));
        if arena.pool.regions.len() == 96 && usable < boot_bytes + (32 << 10) {
            break;
        }
        assert!(arena.reserve(&mut alloc, load_bytes));
        arena.object(&mut alloc, ObjectBlueprint::CNode { size_bits: 9 });
        arena.object(&mut alloc, ObjectBlueprint::Frame);
    }
    assert!(arena.reserve(&mut alloc, boot_bytes));
    let slots = alloc.slots.available();
    assert!(!arena.reserve(&mut alloc, boot_bytes + (2 << 20)));
    assert!(alloc.free_bytes() > 32 << 20);
    assert!(arena.try_object(&mut alloc, ObjectBlueprint::CNode { size_bits: 16 }).is_none());
    assert_eq!(alloc.slots.available(), slots);
    alloc.reclaim(arena);
    assert_eq!(alloc.free_bytes(), 512 << 20);

    // On whole memory, the same reservations grow the arena by an eighth
    // at a time, so its regions stay few: thousands of loads (several
    // GiB of guest RAM) fit, where 1 MiB regions filled the table.
    let boot = BootMemory(vec![Desc { paddr: 1 << 30, bits: 29 }]);
    let mut alloc = alloc.renew(&boot);
    let mut arena = alloc.arena(4 << 20).unwrap();
    for _ in 0..4000 {
        assert!(arena.reserve(&mut alloc, load_bytes));
        arena.object(&mut alloc, ObjectBlueprint::CNode { size_bits: 9 });
        arena.object(&mut alloc, ObjectBlueprint::Frame);
    }
    assert!(arena.pool.regions.len() < 48);
    alloc.reclaim(arena);
    assert_eq!(alloc.free_bytes(), 512 << 20);

    // Root and vmmgr refill after receiving a request or fault, before
    // reading its registers.  Keep a nonzero guest id and POWER_OFF in
    // the request, plus a full payload, across local splitting and memd
    // calls (including both failed grant attempts).
    let mut request: [u64; NUM_MESSAGE_REGISTERS] = core::array::from_fn(|i| 0x1234_0000 + i as u64);
    request[0] = 7;
    request[1] = 0;
    with_ipc_buffer_mut(|b| b.msg_regs_mut().copy_from_slice(&request));
    let boot = BootMemory(vec![Desc { paddr: 1 << 30, bits: 25 }]);
    let mut alloc = alloc.renew(&boot);
    with_ipc_buffer(|b| assert_eq!(b.msg_regs(), &request));
    assert_eq!(alloc.pool.free_bytes(), 16 << 20);

    for grant in [Some(1 << 30), None] {
        alloc = alloc.renew(&BootMemory(vec![]));
        alloc.memd = Some(memd::MemdLink);
        memd::GRANTS.with_borrow_mut(|g| *g = if grant.is_some() { vec![grant] } else { vec![None, None] });
        with_ipc_buffer_mut(|b| b.msg_regs_mut().copy_from_slice(&request));
        alloc.refill();
        with_ipc_buffer(|b| assert_eq!(b.msg_regs(), &request));
        assert_eq!(alloc.pool.free_bytes(), if grant.is_some() { 16 << 20 } else { 0 });
        memd::GRANTS.with_borrow(|g| assert!(g.is_empty()));
    }
}

#[test]
fn independent_allocators_use_their_own_cnodes_and_storage() {
    let mut root = mem::Alloc::new(
        mem::Slots::new(Cap::from_bits(1), Box::leak(Box::new(mem::SlotStorage::<2, 128>::new())), 64..128),
        Box::leak(Box::new(mem::AllocStorage::new())),
        &BootMemory(vec![Desc { paddr: 1 << 30, bits: 25 }]),
    );
    let mut manager = mem::Alloc::empty(
        mem::Slots::new(Cap::from_bits(11), Box::leak(Box::new(mem::SlotStorage::<4, 256>::new())), 128..256),
        Box::leak(Box::new(mem::AllocStorage::new())),
    );
    manager.memd = Some(memd::MemdLink);
    memd::GRANTS.with_borrow_mut(|g| *g = vec![Some(2 << 30)]);
    manager.refill();
    let (root_slots, manager_slots) = (root.slots.available(), manager.slots.available());
    root.slots.track(3);
    manager.slots.track(3);
    RETYPES.with_borrow_mut(Vec::clear);
    let r = root.object(ObjectBlueprint::Frame);
    let m = manager.object(ObjectBlueprint::Frame);
    assert!((64..128).contains(&r));
    assert!((128..256).contains(&m));
    RETYPES.with_borrow(|v| assert_eq!(v, &[1, 11]));

    root.slots.free_owned(3);
    assert_eq!(root.slots.available(), root_slots);
    assert_eq!(manager.slots.available(), manager_slots - 1);
    DELETES.with_borrow(|v| assert_eq!(v, &[1]));
    manager.slots.free_owned(3);
    assert_eq!(manager.slots.available(), manager_slots);
    DELETES.with_borrow(|v| assert_eq!(v, &[1, 11]));
}

/// A memd that has failed takes no grants back.  Its client goes on with
/// them: nothing is lost, nothing is offered twice in one trim, and the
/// blocks serve the next requests.
#[test]
fn grants_a_failed_memd_does_not_take_stay_in_use() {
    use memd::{FREE, FREED, Free, GRANTS, STATUS, Status};
    const MIB: usize = 1 << 20;
    let mut alloc = mem::Alloc::empty(
        mem::Slots::new(Cap::from_bits(21), Box::leak(Box::new(mem::SlotStorage::<16, 1024>::new())), 64..1024),
        Box::leak(Box::new(mem::AllocStorage::new())),
    );
    alloc.memd = Some(memd::MemdLink);
    // A status page that cannot be read whole counts as no memory in memd.
    assert_eq!(alloc.free_bytes(), 0);
    assert!(alloc.arena(MIB).is_none());
    STATUS.set(Some(Status { free_bytes: 100 << 20, reported_bytes: 0, largest_block: 32 << 20 }));
    assert_eq!(alloc.free_bytes(), 100 * MIB);

    // Three grants, of 32, 16 and 16 MiB, none a buddy of another.
    let (a, b, c) = (1 << 30, (1 << 30) + 64 * MIB, (1 << 30) + 128 * MIB);
    GRANTS.with_borrow_mut(|g| *g = vec![Some(c), Some(b), Some(a)]);
    let arenas = [32, 16, 16].map(|mib| alloc.arena(mib * MIB).unwrap());
    GRANTS.with_borrow(|g| assert!(g.is_empty()));
    assert_eq!(alloc.local_free_bytes(), 0);

    // memd has failed.  The first trim offers one size and stops.
    FREE.set(Free::Failed);
    let [x, y, z] = arenas;
    alloc.reclaim(x);
    FREED.with_borrow(|f| assert!(f.is_empty()));
    let slots = alloc.slots.available();
    alloc.reclaim(y);
    FREED.with_borrow(|f| assert_eq!(f.as_slice(), [vec![(b, 24)]]));
    assert_eq!(alloc.local_free_bytes(), 48 * MIB);
    // The block kept its (new) slot; none was freed for it.
    assert_eq!(alloc.slots.available(), slots - 1);
    alloc.reclaim(z);
    FREED.with_borrow(|f| assert_eq!(f.as_slice(), [vec![(b, 24)], vec![(a, 25)]]));
    assert_eq!(alloc.local_free_bytes(), 64 * MIB);

    // The blocks are used again (GRANTS is empty: memd is not asked), and
    // are still grants: a memd that takes them gets them whole.
    let x = alloc.arena(16 * MIB).unwrap();
    assert_eq!(alloc.local_free_bytes(), 48 * MIB);
    FREED.with_borrow_mut(Vec::clear);
    FREE.set(Free::Takes);
    let slots = alloc.slots.available();
    alloc.reclaim(x);
    FREED.with_borrow(|f| assert_eq!(f.as_slice(), [vec![(a, 25)]]));
    assert_eq!(alloc.local_free_bytes(), 32 * MIB);
    // One slot for the reclaimed region, one back from the grant returned.
    assert_eq!(alloc.slots.available(), slots);

    // A memd that failed holding a batch has it: the blocks are gone from
    // here, with their slots, and the trim stops as well.
    GRANTS.with_borrow_mut(|g| *g = vec![Some(a)]);
    let x = alloc.arena(32 * MIB).unwrap();
    FREED.with_borrow_mut(Vec::clear);
    FREE.set(Free::FailedHolding);
    let slots = alloc.slots.available();
    alloc.reclaim(x);
    FREED.with_borrow(|f| assert_eq!(f.as_slice(), [vec![(a, 25)]]));
    assert_eq!(alloc.local_free_bytes(), 32 * MIB);
    assert_eq!(alloc.slots.available(), slots);
    // What is left serves requests without memd (GRANTS is empty).
    let _rest = [alloc.arena(16 * MIB).unwrap(), alloc.arena(16 * MIB).unwrap()];
    assert_eq!(alloc.local_free_bytes(), 0);
}

/// DMA frames: ordinary ones without shared DMA; shared ones in the
/// kernel's batches (256 4 KiB frames, one 2 MiB frame), placed on the
/// region's watermark after its other objects, as `retype` places them.
#[test]
fn retype_dma_batches_4k_and_2m_and_shares_watermark() {
    RETYPE_WINDOWS.with_borrow_mut(Vec::clear);
    SHARED_RETYPES.with_borrow_mut(Vec::clear);
    let base = 64 << 20;
    let mut region = mem::UtRegion::fresh(cap::Untyped::from_bits(7), base, 24);
    let cnode = slot::CNODE.cap().bits();

    assert_eq!(region.retype_dma(false, &ObjectBlueprint::Frame, 3, mem::Dest::new(slot::CNODE.cap(), 1024)), Some(base));
    RETYPE_WINDOWS.with_borrow(|w| assert_eq!(w, &[(1024, 3)]));
    SHARED_RETYPES.with_borrow(|v| assert!(v.is_empty(), "no shared frames unless asked"));

    // A 16 KiB CNode after the three pages, then shared pages after it.
    let cn = ObjectBlueprint::CNode { size_bits: 9 };
    assert_eq!(region.retype(&cn, 1, mem::Dest::new(slot::CNODE.cap(), 2000)), Some(base + (16 << 10)));
    let count = 2 * 256 + 3;
    assert_eq!(region.retype_dma(true, &ObjectBlueprint::Frame, count, mem::Dest::new(slot::CNODE.cap(), 4096)), Some(base + (32 << 10)));
    SHARED_RETYPES.with_borrow(|v| {
        assert_eq!(v, &[(7, 12, cnode, 4096, 256), (7, 12, cnode, 4352, 256), (7, 12, cnode, 4608, 3)]);
    });
    RETYPE_WINDOWS.with_borrow(|w| assert_eq!(w.len(), 2, "shared frames are not retyped as ordinary ones"));

    // 2 MiB frames one per call, aligned past the 4 KiB ones.
    SHARED_RETYPES.with_borrow_mut(Vec::clear);
    let dest = mem::Dest::new(slot::CNODE.cap(), 8192);
    assert_eq!(region.retype_dma(true, &ObjectBlueprint::LargePage, 3, dest), Some(base + (4 << 20)));
    SHARED_RETYPES.with_borrow(|v| {
        assert_eq!(v, &[(7, 21, cnode, 8192, 1), (7, 21, cnode, 8193, 1), (7, 21, cnode, 8194, 1)]);
    });
    // The watermark is shared: the next object comes after them, and
    // what does not fit makes no kernel call.
    assert_eq!(region.retype(&ObjectBlueprint::Frame, 1, mem::Dest::new(slot::CNODE.cap(), 9000)), Some(base + (10 << 20)));
    assert!(region.retype_dma(true, &ObjectBlueprint::LargePage, 3, dest).is_none());
    SHARED_RETYPES.with_borrow(|v| assert_eq!(v.len(), 3));
}

/// A pinned Untyped (a deleted guest's I/O pool a device may still write,
/// and the CNode of its frames) is not revoked: it keeps its objects, in a
/// global slot that the guest's `free_owned` leaves alone, and stays out
/// of the free memory.  The rest of the arena is revoked and reused.
#[test]
fn reclaim_pinning_keeps_pinned_untyped_unrevoked() {
    let boot = BootMemory(vec![Desc { paddr: 1 << 30, bits: 26 }]);
    let mut alloc = mem::Alloc::new(
        mem::Slots::new(Cap::from_bits(31), Box::leak(Box::new(mem::SlotStorage::<16, 1024>::new())), 64..1024),
        Box::leak(Box::new(mem::AllocStorage::new())),
        &boot,
    );
    let free = alloc.free_bytes();
    alloc.slots.track(3);
    let mut arena = alloc.arena(1 << 20).unwrap();
    let pool_slot = alloc.slots.alloc();
    let mut pool = alloc.split(22, pool_slot).unwrap();
    arena.own(pool_slot, pool.paddr, 22);
    let cnode_slot = alloc.slots.alloc();
    let cnode_ut = alloc.split(15, cnode_slot).unwrap();
    arena.own(cnode_slot, cnode_ut.paddr, 15);
    let frames = mem::Dest { cnode: Cap::<cap_type::CNode>::from_bits(500).absolute_cptr_for_self(), offset: 0 };
    assert_eq!(pool.retype_dma(true, &ObjectBlueprint::Frame, 1024, frames), Some(pool.paddr));
    alloc.slots.untrack();
    let (pool_paddr, cnode_paddr, region_slot) = (pool.paddr, cnode_ut.paddr, arena.owned[0].0);
    assert_eq!(alloc.free_bytes(), free - (1 << 20) - (4 << 20) - (1 << 15));

    REVOKES.with_borrow_mut(Vec::clear);
    MOVES.with_borrow_mut(Vec::clear);
    DELETED_SLOTS.with_borrow_mut(Vec::clear);
    let kept = alloc.reclaim_pinning(arena, |p| p == pool_paddr || p == cnode_paddr);
    assert_eq!(kept, (4 << 20) + (1 << 15));
    REVOKES.with_borrow(|v| assert_eq!(v, &[region_slot as u64], "only the arena's own region is revoked"));
    let kept_at = |slot: usize| MOVES.with_borrow(|v| v.iter().find(|m| m.1 == slot as u64).map(|m| m.0)).unwrap();
    let (pool_kept, cnode_kept) = (kept_at(pool_slot), kept_at(cnode_slot));
    let slots = alloc.slots.available();
    alloc.slots.free_owned(3);
    DELETED_SLOTS.with_borrow(|v| {
        assert!(!v.contains(&pool_kept) && !v.contains(&cnode_kept), "the kept Untypeds are not the guest's");
        assert!(v.contains(&(pool_slot as u64)) && v.contains(&(cnode_slot as u64)), "their old slots are freed");
    });
    // The arena region's slot, emptied when its block moved, and the two.
    assert_eq!(alloc.slots.available(), slots + 3);
    assert_eq!(alloc.free_bytes(), free - kept);
}

/// CTL_DRIVER_LOAD and CTL_FIRMWARE_LOAD (nicd.rs) copy up to a megabyte
/// into frames of an arena, and give the arena up when the image is
/// refused or memory runs out half way.  Revoking its Untypeds deletes
/// the frames, but their slots in root's CNode must be freed too: dom0
/// could otherwise refuse image after image until root's CNode is full,
/// and root panics at its next allocation.
#[test]
fn a_given_up_load_frees_its_frames_slots() {
    const PAGES: usize = 256;
    let boot = BootMemory(vec![Desc { paddr: 1 << 30, bits: 26 }]);
    let mut alloc = mem::Alloc::new(
        mem::Slots::new(Cap::from_bits(41), Box::leak(Box::new(mem::SlotStorage::<64, 4096>::new())), 64..4096),
        Box::leak(Box::new(mem::AllocStorage::new())),
        &boot,
    );
    // The first round splits blocks, whose parents keep their slots for
    // the next: count from its end.
    let (mut slots, mut free) = (0, 0);
    // Far more refused images than the CNode has slots for 256 frames each.
    for round in 0..64 {
        let mut arena = alloc.arena(PAGES * 4096 + 4096).unwrap();
        let mut frames = Vec::new();
        for _ in 0..PAGES {
            frames.push(arena.try_object(&mut alloc, ObjectBlueprint::Frame).unwrap());
        }
        REVOKES.with_borrow_mut(Vec::clear);
        let owned: Vec<u64> = arena.owned.iter().map(|o| o.0 as u64).collect();
        alloc.release_objects(arena, &frames);
        REVOKES.with_borrow(|v| assert_eq!(v, &owned, "the frames go with the arena's Untypeds"));
        if round == 0 {
            (slots, free) = (alloc.slots.available(), alloc.free_bytes());
        }
        assert_eq!(alloc.slots.available(), slots, "round {round}: slots leaked");
        assert_eq!(alloc.free_bytes(), free, "round {round}: memory leaked");
    }
    // Out of memory half way: the frames made so far are freed too.
    let boot = BootMemory(vec![Desc { paddr: 1 << 30, bits: 20 }]);
    let mut alloc = alloc.renew(&boot);
    for round in 0..4 {
        let mut arena = alloc.arena(4096).unwrap();
        let mut frames = Vec::new();
        while let Some(s) = arena.try_object(&mut alloc, ObjectBlueprint::Frame) {
            frames.push(s);
            assert!(frames.len() <= PAGES);
        }
        assert!(!frames.is_empty());
        alloc.release_objects(arena, &frames);
        if round == 0 {
            slots = alloc.slots.available();
        }
        assert_eq!(alloc.slots.available(), slots, "round {round}: slots leaked");
    }
}

/// A NIC's DMA region (root's nicd.rs, alloc_dma): an Untyped of its own,
/// all frames, and the CNode of those frames from an arena of its own.
/// When either does not fit, nothing is kept and nothing panics: the
/// CNode came from the global pool, whose allocation panicked once the
/// region had taken the memory, and with it root.
#[test]
fn a_dma_region_that_does_not_fit_keeps_nothing() {
    let new = |boot: &BootMemory| mem::Alloc::new(
        mem::Slots::new(Cap::from_bits(51), Box::leak(Box::new(mem::SlotStorage::<64, 4096>::new())), 64..4096),
        Box::leak(Box::new(mem::AllocStorage::new())),
        boot,
    );
    // Only disjoint 2 MiB blocks: no 4 MiB region.
    let mut alloc = new(&BootMemory((0..16).map(|i| Desc { paddr: (64 << 20) + i * (4 << 20), bits: 21 }).collect()));
    let (slots, free) = (alloc.slots.available(), alloc.free_bytes());
    assert!(alloc.dma_frames(22, false, &ObjectBlueprint::Frame).is_none());
    assert_eq!((alloc.slots.available(), alloc.free_bytes()), (slots, free));
    // The region fits, the CNode of its frames does not: a 2 MiB block and
    // nothing else, again and again.
    let mut alloc = alloc.renew(&BootMemory(vec![Desc { paddr: 64 << 20, bits: 21 }]));
    let (slots, free) = (alloc.slots.available(), alloc.free_bytes());
    for round in 0..4 {
        assert!(alloc.dma_frames(21, false, &ObjectBlueprint::Frame).is_none(), "round {round}");
        assert_eq!((alloc.slots.available(), alloc.free_bytes()), (slots, free), "round {round}");
    }
    // A region smaller than its frames is no region.
    assert!(alloc.dma_frames(11, false, &ObjectBlueprint::Frame).is_none());
    // Room for it: a 4 MiB region, its 1024 frames in a CNode of 1024
    // slots, given back (by a caller that gives up) to what there was.
    let mut alloc = alloc.renew(&BootMemory(vec![Desc { paddr: 1 << 30, bits: 26 }]));
    // Counted from the end of the first round, which splits blocks whose
    // parents keep slots.
    let (mut slots, mut free) = (0, 0);
    for round in 0..8 {
        RETYPES.with_borrow_mut(Vec::clear);
        let d = alloc.dma_frames(22, false, &ObjectBlueprint::Frame).unwrap();
        assert_eq!((d.frames_bits, d.paddr % (4 << 20)), (10, 0));
        RETYPES.with_borrow(|v| assert!(v.contains(&(d.frames as u64)), "frames go to their CNode"));
        alloc.release_objects(d.arena, &[d.frames]);
        if round == 0 {
            (slots, free) = (alloc.slots.available(), alloc.free_bytes());
        }
        assert_eq!((alloc.slots.available(), alloc.free_bytes()), (slots, free), "round {round}");
    }
}

/// A guest's arena in root (vmmgr.rs, guest_new and nic_add) owns, besides
/// its regions, the I/O pool, the Untyped of the pool's mapping CNode and
/// a netd port per device (Arena::own).  With every region taken, there is
/// still room for all of them: one fewer, and the last port's own()
/// panicked root.
#[test]
fn a_full_arena_owns_its_pool_the_pool_cnode_and_every_port() {
    let new = |boot: &BootMemory| mem::Alloc::new(
        mem::Slots::new(Cap::from_bits(51), Box::leak(Box::new(mem::SlotStorage::<64, 4096>::new())), 1024..4096),
        Box::leak(Box::new(mem::AllocStorage::new())),
        boot,
    );
    // Disjoint 1 MiB blocks (their Untypeds in slots 32..288), more than
    // an arena has regions: it grows a block at a time until its regions
    // are all taken.
    let mut alloc = new(&BootMemory((0..256).map(|i| Desc { paddr: (64 << 20) + i * (2 << 20), bits: 20 }).collect()));
    let mut arena = alloc.arena(1 << 20).unwrap();
    assert!(!arena.reserve(&mut alloc, 512 << 20));
    assert!(arena.pool.regions.is_full());
    let regions = arena.owned.len();
    assert_eq!(regions, arena.pool.regions.len());
    for k in 0..2 + MAX_GUEST_DEVICES {
        let s = alloc.slots.alloc();
        arena.own(s, (1 << 32) + k * (4 << 20), 22);
    }
    assert_eq!(arena.owned.len(), regions + 2 + MAX_GUEST_DEVICES);
}

/// Memory fragmented into 2 MiB blocks (memd has no 16 MiB one, though it
/// has plenty of memory): the global pool takes them, rather than panic
/// once its first region is used up.  Without a large block, it takes
/// another only when it is short (under 1 MiB, or no room for the
/// object), calls memd for none in between, and never drops a region
/// that still has room for one of the same size.
#[test]
fn the_global_pool_refills_from_fragmented_memory() {
    use memd::{ALLOCS, GRANTS, MAX_BITS, STATUS, Status};
    const MIB: usize = 1 << 20;
    let mut alloc = mem::Alloc::empty(
        mem::Slots::new(Cap::from_bits(21), Box::leak(Box::new(mem::SlotStorage::<512, 32768>::new())), 64..32768),
        Box::leak(Box::new(mem::AllocStorage::new())),
    );
    alloc.memd = Some(memd::MemdLink);
    STATUS.set(Some(Status { free_bytes: 512 << 20, reported_bytes: 0, largest_block: 2 << 20 }));
    MAX_BITS.set(21);
    // 2 MiB blocks, none a buddy of another.
    let grants: Vec<_> = (0..32).map(|i| Some((1usize << 32) + i * 4 * MIB)).rev().collect();
    GRANTS.with_borrow_mut(|g| *g = grants);
    ALLOCS.with_borrow_mut(Vec::clear);

    // The first object takes a 2 MiB grant, after asking for 16 MiB.
    alloc.object(ObjectBlueprint::Frame);
    ALLOCS.with_borrow(|a| assert_eq!(a.as_slice(), [(24, false), (24, false), (24, false), (21, true)]));
    assert_eq!(alloc.pool.regions.len(), 1);
    assert_eq!(alloc.pool.free_bytes(), 2 * MIB - 4096);

    // With 1 MiB or more left, refills ask memd nothing.
    ALLOCS.with_borrow_mut(Vec::clear);
    while alloc.pool.free_bytes() >= MIB {
        alloc.object(ObjectBlueprint::Frame);
        alloc.refill();
    }
    ALLOCS.with_borrow(|a| assert!(a.is_empty(), "{a:?}"));
    assert_eq!(alloc.pool.regions.len(), 1);
    // Under 1 MiB, the next takes another 2 MiB block.
    alloc.object(ObjectBlueprint::Frame);
    ALLOCS.with_borrow(|a| assert_eq!(a.as_slice(), [(24, false), (24, false), (24, false), (21, true)]));
    assert_eq!(alloc.pool.regions.len(), 2);

    // A 2 MiB object fits the new region, untouched.  The next is larger
    // than any room the pool has: a block for it.
    ALLOCS.with_borrow_mut(Vec::clear);
    alloc.object(ObjectBlueprint::CNode { size_bits: 16 });
    ALLOCS.with_borrow(|a| assert!(a.is_empty(), "{a:?}"));
    alloc.object(ObjectBlueprint::CNode { size_bits: 16 });
    ALLOCS.with_borrow(|a| assert_eq!(a.last(), Some(&(21, true))));

    // 16 MiB more of small objects: the pool goes through 2 MiB blocks
    // one at a time, using each up before it takes the next, and wastes
    // none of them.
    let grants = GRANTS.with_borrow(Vec::len);
    for _ in 0..4096 {
        alloc.object(ObjectBlueprint::Frame);
        alloc.refill();
        assert!(alloc.pool.regions.len() <= 2);
    }
    let taken = grants - GRANTS.with_borrow(Vec::len);
    assert!(taken <= 9, "{taken} blocks for 16 MiB");
    ALLOCS.with_borrow(|a| assert!(a.iter().filter(|&&(_, ok)| ok).all(|&(bits, _)| bits == 21)));

    // memd with a 16 MiB block again: the pool takes it as before, with
    // less than 8 MiB.
    MAX_BITS.set(usize::MAX);
    STATUS.set(Some(Status { free_bytes: 512 << 20, reported_bytes: 0, largest_block: 16 << 20 }));
    GRANTS.with_borrow_mut(|g| g.push(Some(1 << 33)));
    ALLOCS.with_borrow_mut(Vec::clear);
    alloc.refill();
    ALLOCS.with_borrow(|a| assert_eq!(a.as_slice(), [(24, true)]));
    assert!(alloc.pool.free_bytes() >= 16 * MIB);
    STATUS.set(None);
}

/// A pool short of room for an object takes the block that merging
/// local buddies makes: the merge the preferred size's split does first
/// (two free 2 MiB halves of a 4 MiB block) counts in the smaller blocks
/// it falls back to, or a 4 MiB object would find none.
#[test]
fn the_pool_falls_back_to_a_block_merged_for_the_preferred_size() {
    const MIB: usize = 1 << 20;
    let boot = BootMemory(vec![Desc { paddr: 64 * MIB, bits: 22 }]);
    let mut alloc = mem::Alloc::new(
        mem::Slots::new(Cap::from_bits(21), Box::leak(Box::new(mem::SlotStorage::<512, 32768>::new())), 64..32768),
        Box::leak(Box::new(mem::AllocStorage::new())),
        &boot,
    );
    assert_eq!(alloc.pool.regions.len(), 0);
    // Split into two 2 MiB halves, both free again: no block is 4 MiB.
    let arena = alloc.arena(2 * MIB).unwrap();
    alloc.reclaim(arena);
    assert_eq!(alloc.largest_block_bits(), Some(21));
    // A 4 MiB object: the split for the pool's 16 MiB merges the halves.
    alloc.object(ObjectBlueprint::CNode { size_bits: 17 });
    assert_eq!(alloc.pool.regions.len(), 1);
    assert_eq!(alloc.local_free_bytes(), 0);
}

//! Run with tests/run-alloctest.sh.  Exercise the shared task allocator and
//! fixed containers on the host; only seL4 capability operations are stubs.
#![allow(dead_code)]

extern crate self as l4h_host;
extern crate self as sel4;
extern crate self as l4h_ipc;

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
    pub fn absolute_cptr<U>(&self, _: U) -> AbsoluteCPtr { AbsoluteCPtr { cnode: self.0 } }
    pub fn absolute_cptr_for_self(&self) -> AbsoluteCPtr { AbsoluteCPtr { cnode: self.0 } }
    pub fn untyped_retype(&self, _: &ObjectBlueprint, dest: &AbsoluteCPtr, _: usize, _: usize) -> Result<(), ()> {
        RETYPES.with_borrow_mut(|v| v.push(dest.cnode));
        // Kernel invocations marshal their arguments into the IPC buffer.
        with_ipc_buffer_mut(|b| b.msg_regs_mut()[..6].fill(0xdead_beef));
        Ok(())
    }
}

pub mod cap {
    pub type Untyped = crate::Cap<crate::cap_type::Untyped>;
    pub type CNode = crate::Cap<crate::cap_type::CNode>;
}

#[derive(Clone, Copy)]
pub struct AbsoluteCPtr { cnode: u64 }

thread_local! {
    static RETYPES: std::cell::RefCell<Vec<u64>> = const { std::cell::RefCell::new(Vec::new()) };
    static DELETES: std::cell::RefCell<Vec<u64>> = const { std::cell::RefCell::new(Vec::new()) };
}

impl AbsoluteCPtr {
    pub fn delete(&self) -> Result<(), ()> { DELETES.with_borrow_mut(|v| v.push(self.cnode)); Ok(()) }
    pub fn revoke(&self) -> Result<(), ()> { Ok(()) }
    pub fn move_(&self, _: &Self) -> Result<(), ()> { Ok(()) }
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
}

impl ObjectBlueprint {
    pub fn physical_size_bits(&self) -> usize {
        match self {
            Self::Untyped { size_bits } => *size_bits,
            Self::CNode { size_bits } => size_bits + 5,
            Self::Frame => 12,
        }
    }

    pub fn ty(&self) -> usize { self.physical_size_bits() }
}

pub struct Desc {
    paddr: usize,
    bits: usize,
}

impl Desc {
    pub fn is_device(&self) -> bool { false }
    pub fn paddr(&self) -> usize { self.paddr }
    pub fn size_bits(&self) -> usize { self.bits }
}

pub struct BootInfo(Vec<Desc>);
pub struct UntypedSlots;

impl BootInfo {
    pub fn untyped_list(&self) -> &[Desc] { &self.0 }
    pub fn untyped(&self) -> UntypedSlots { UntypedSlots }
}

impl UntypedSlots {
    pub fn index(&self, i: usize) -> init_thread::Slot<cap_type::Untyped> { init_thread::Slot::from_index(32 + i) }
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
        pub fn alloc(&self, _: usize, _: usize) -> Option<usize> {
            let paddr = GRANTS.with_borrow_mut(|g| g.pop().expect("unexpected memd allocation"));
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
fn arena_growth_on_fragmented_memory_and_reclaim() {
    // Disjoint 2 MiB blocks with occupied holes between them; no buddies
    // can merge.  Slots and allocator tables are taken only once.
    let boot = BootInfo((0..48).map(|i| Desc { paddr: (64 << 20) + i * (4 << 20), bits: 21 }).collect());
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
    let boot = BootInfo((0..256).map(|i| Desc { paddr: (64 << 20) + i * (4 << 20), bits: 21 }).collect());
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
    let boot = BootInfo((0..256).map(|i| Desc { paddr: (64 << 20) + i * (4 << 20), bits: 21 }).collect());
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
    let boot = BootInfo(vec![Desc { paddr: 1 << 30, bits: 29 }]);
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
    let boot = BootInfo(vec![Desc { paddr: 1 << 30, bits: 25 }]);
    let mut alloc = alloc.renew(&boot);
    with_ipc_buffer(|b| assert_eq!(b.msg_regs(), &request));
    assert_eq!(alloc.pool.free_bytes(), 16 << 20);

    for grant in [Some(1 << 30), None] {
        alloc = alloc.renew(&BootInfo(vec![]));
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
        &BootInfo(vec![Desc { paddr: 1 << 30, bits: 25 }]),
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

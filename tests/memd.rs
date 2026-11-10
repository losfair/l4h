//! Exercise memd's real grant handlers and buddy allocator on the host.
//! Capability operations model Untyped ranges; no seL4 kernel is involved.
#![allow(dead_code)]

extern crate self as l4h_rt;
extern crate self as sel4;

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

#[path = "../host/l4h-memd/src/bucket.rs"]
mod bucket;
#[path = "../host/l4h-memd/src/exchange.rs"]
mod exchange;
#[path = "../host/l4h-memd/src/mem.rs"]
mod mem;
#[path = "../host/l4h-host/src/fixed.rs"]
pub mod fixed;
#[path = "../host/l4h-host/src/errno.rs"]
pub mod errno;

use host::memd::{BLOCK_BITS, TABLE_VA, XCHG_SLOTS};
use mem::{Mem, State, abs};

use errno::{EINVAL, ENOMEM};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Client { Root, Vmmgr }

struct Memd { mem: Mem }

#[derive(Clone, Debug, PartialEq, Eq)]
struct Kernel {
    caps: BTreeMap<u64, (usize, usize)>,
    mrs: [u64; 1 + 2 * XCHG_SLOTS],
    calls: usize,
    /// A slot another thread of the client fills again as soon as it is
    /// emptied.
    refill: Option<u64>,
}

thread_local! {
    static KERNEL: RefCell<Kernel> = RefCell::new(Kernel {
        caps: BTreeMap::new(), mrs: [0; 1 + 2 * XCHG_SLOTS], calls: 0, refill: None,
    });
}

fn kernel<T>(f: impl FnOnce(&mut Kernel) -> T) -> T {
    KERNEL.with(|k| f(&mut k.borrow_mut()))
}

fn invoke<T>(f: impl FnOnce(&mut Kernel) -> T) -> T {
    kernel(|k| {
        k.calls += 1;
        // Real invocations can overwrite the message registers. A batch
        // must read all its input before making its first invocation.
        k.mrs.fill(u64::MAX);
        f(k)
    })
}

fn xchg(c: Client, i: usize) -> AbsoluteCPtr {
    AbsoluteCPtr(if c == Client::Root { 160 } else { 1000 } + i as u64)
}

/// memd's two views of a block's exchange slot (alloc's and free's).
fn granted(c: Client, i: usize) -> AbsoluteCPtr {
    xchg(c, i)
}

fn returned(c: Client, i: usize) -> AbsoluteCPtr {
    xchg(c, i)
}

#[macro_export]
macro_rules! info { ($($a:tt)*) => { println!($($a)*); }; }
#[macro_export]
macro_rules! log { ($($a:tt)*) => { println!($($a)*); }; }

pub mod cap_type {
    #[derive(Clone, Copy)] pub struct Null;
    #[derive(Clone, Copy)] pub struct CNode;
    #[derive(Clone, Copy)] pub struct Untyped;
}

#[derive(Clone, Copy)]
pub struct Cap<T>(u64, std::marker::PhantomData<T>);
pub fn cap<T>(s: u64) -> Cap<T> { Cap(s, std::marker::PhantomData) }
pub mod cap {
    pub type CNode = super::Cap<super::cap_type::CNode>;
    pub type Untyped = super::Cap<super::cap_type::Untyped>;
}

pub struct CapRights;
impl CapRights { pub fn all() -> Self { Self } }
pub enum ObjectBlueprint { Untyped { size_bits: usize } }

impl<T> Cap<T> {
    pub fn absolute_cptr<U>(&self, c: Cap<U>) -> AbsoluteCPtr { AbsoluteCPtr(c.0) }
    pub fn absolute_cptr_for_self(&self) -> AbsoluteCPtr { AbsoluteCPtr(self.0) }
    pub fn untyped_retype(&self, b: &ObjectBlueprint, _: &AbsoluteCPtr, to: usize, n: usize) -> Result<(), ()> {
        let ObjectBlueprint::Untyped { size_bits } = *b;
        invoke(|k| {
            let (base, size) = *k.caps.get(&self.0).ok_or(())?;
            assert!((1 << size_bits) * n <= size);
            for j in 0..n {
                assert!(k.caps.insert((to + j) as u64, (base + (j << size_bits), 1 << size_bits)).is_none());
            }
            Ok(())
        })
    }
}

#[derive(Clone, Copy)]
pub struct AbsoluteCPtr(u64);

impl AbsoluteCPtr {
    pub fn delete(&self) -> Result<(), ()> {
        invoke(|k| {
            k.caps.remove(&self.0);
            if k.refill == Some(self.0) {
                k.caps.insert(self.0, (0, 0));
            }
        });
        Ok(())
    }
    // Like seL4, a full destination fails and leaves the source as it was.
    pub fn move_(&self, from: &Self) -> Result<(), ()> {
        invoke(|k| {
            if k.caps.contains_key(&self.0) {
                return Err(());
            }
            let cap = k.caps.remove(&from.0).ok_or(())?;
            k.caps.insert(self.0, cap);
            Ok(())
        })
    }
    pub fn copy(&self, from: &Self, _: CapRights) -> Result<(), ()> {
        invoke(|k| {
            if k.caps.contains_key(&self.0) {
                return Err(());
            }
            let cap = *k.caps.get(&from.0).ok_or(())?;
            k.caps.insert(self.0, cap);
            Ok(())
        })
    }
    pub fn revoke(&self) -> Result<(), ()> {
        invoke(|k| {
            let (base, size) = *k.caps.get(&self.0).ok_or(())?;
            k.caps.retain(|&s, &mut (p, n)| s == self.0 || p < base || p + n > base + size);
            Ok(())
        })
    }
}

pub mod host {
    pub use crate::{errno, fixed};
    pub const SLOT_CNODE: u64 = 1;
    pub mod ticks { pub fn now() -> u64 { 1000 } }
    pub mod memd {
        pub const BLOCK_BITS: usize = 21;
        pub const ORDERS: usize = 27;
        pub const SLOT_DYN_BASE: u64 = 256;
        pub const TABLE_VA: usize = 0x5100_0000_0000;
        pub const UNIT_BYTES: usize = 24;
        pub const XCHG_SLOTS: usize = 32;
        pub const HP_SHARE: u64 = 125;
        pub const HP_BURST_US: u64 = 16_000;
        pub const HP_CALL_US: u64 = 1_000;
    }
}

mod balloon {
    pub const QUEUE_SIZE: usize = 32;
    pub const MAX_DESC_BITS: usize = 31;
    pub struct Balloon;
    impl Balloon {
        pub fn busy(&self) -> bool { false }
        pub fn capacity(&self) -> usize { QUEUE_SIZE }
        pub fn done(&mut self, _: bool) -> bool { true }
        pub fn report(&mut self, _: &[(usize, usize)]) { unreachable!() }
    }
}

// memd uses a fixed mapping for its table. Serialize fixtures, reserve
// the address without replacing existing mappings, and release it after
// each test. Only one page is needed for these 32 units.
static TABLE_LOCK: Mutex<()> = Mutex::new(());
unsafe extern "C" {
    fn mmap(addr: *mut u8, len: usize, prot: i32, flags: i32, fd: i32, off: i64) -> *mut u8;
    fn munmap(addr: *mut u8, len: usize) -> i32;
}

struct Fixture {
    d: Memd,
    next_slot: u64,
    _table: MutexGuard<'static, ()>,
}

impl Fixture {
    fn new() -> Self {
        let guard = TABLE_LOCK.lock().unwrap();
        // PROT_READ | PROT_WRITE; MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE.
        let p = unsafe { mmap(TABLE_VA as *mut u8, 4096, 3, 0x100022, -1, 0) };
        assert_eq!(p as usize, TABLE_VA);
        kernel(|k| { k.caps.clear(); k.calls = 0; k.mrs.fill(0); k.refill = None; });
        let mut f = Self { d: Memd { mem: Mem::new(32) }, next_slot: 10_000, _table: guard };
        // Boot handover from root: the table has no state or order for
        // this 8 MiB block yet. Root must still be allowed to return it.
        kernel(|k| { k.caps.insert(xchg(Client::Root, 0).0, (8 << BLOCK_BITS, 4 << BLOCK_BITS)); });
        assert_eq!(f.d.free(Client::Root, &batch(&[(8, BLOCK_BITS + 2)])), 0);
        assert_eq!(f.d.mem.free_bytes(), 8 << 20);
        f
    }

    fn grant(&mut self, c: Client, order: usize) -> (u32, u64) {
        let paddrs = self.d.alloc(c, BLOCK_BITS + order, 1).unwrap();
        let i = (paddrs[0] >> BLOCK_BITS) as u32;
        let slot = self.next_slot;
        self.next_slot += 1;
        abs(slot).move_(&xchg(c, 0)).unwrap();
        (i, slot)
    }

    fn reject(&mut self, c: Client, blocks: &[(u32, usize)]) {
        let before = kernel(|k| k.clone());
        let free = self.d.mem.free_bytes();
        assert_eq!(self.d.free(c, &batch(blocks)), EINVAL);
        assert_eq!(kernel(|k| k.clone()), before, "invalid batch made a capability invocation");
        assert_eq!(self.d.mem.free_bytes(), free);
    }
}

/// A `free` call's blocks: (physical address, size bits) of (unit, bits).
fn batch(blocks: &[(u32, usize)]) -> Vec<(usize, usize)> {
    blocks.iter().map(|&(i, bits)| ((i as usize) << BLOCK_BITS, bits)).collect()
}

impl Drop for Fixture {
    fn drop(&mut self) {
        assert_eq!(unsafe { munmap(TABLE_VA as *mut u8, 4096) }, 0);
    }
}

#[test]
fn forged_parent_cannot_revoke_a_neighboring_root_grant() {
    let mut f = Fixture::new();
    let (mgr, mgr_cap) = f.grant(Client::Vmmgr, 0);
    let (root, root_cap) = f.grant(Client::Root, 0);
    assert_eq!((mgr, root), (8, 9));
    for order in [1, 2] {
        f.reject(Client::Vmmgr, &[(mgr, BLOCK_BITS + order)]);
    }
    f.reject(Client::Vmmgr, &[(root, BLOCK_BITS)]);
    assert!(f.d.mem.state(mgr) == State::Vmmgr);
    assert!(f.d.mem.state(root) == State::Root);

    assert_eq!(f.d.free(Client::Vmmgr, &batch(&[(mgr, BLOCK_BITS)])), 0);
    assert!(!kernel(|k| k.caps.contains_key(&mgr_cap)));
    assert!(kernel(|k| k.caps.contains_key(&root_cap)));
    assert_eq!(f.d.mem.free_bytes(), 6 << 20);
    assert_eq!(f.grant(Client::Vmmgr, 0).0, mgr);
}

#[test]
fn partial_and_malformed_returns_are_rejected() {
    let mut f = Fixture::new();
    let (mgr, _) = f.grant(Client::Vmmgr, 1);
    for (i, bits) in [(mgr, BLOCK_BITS), (mgr + 1, BLOCK_BITS), (mgr, BLOCK_BITS - 1), (mgr, usize::MAX), (32, BLOCK_BITS)] {
        f.reject(Client::Vmmgr, &[(i, bits)]);
    }
    let before = kernel(|k| k.clone());
    assert_eq!(f.d.free(Client::Vmmgr, &batch(&[(mgr, BLOCK_BITS + 1); XCHG_SLOTS + 1])), EINVAL);
    assert_eq!(f.d.free(Client::Vmmgr, &[]), 0);
    assert_eq!(kernel(|k| k.clone()), before);
    assert_eq!(f.d.free(Client::Vmmgr, &batch(&[(mgr, BLOCK_BITS + 1)])), 0);
    assert_eq!(f.d.mem.free_bytes(), 8 << 20);
}

#[test]
fn duplicate_and_invalid_batches_are_atomic() {
    let mut f = Fixture::new();
    let (a, a_cap) = f.grant(Client::Vmmgr, 0);
    let (b, b_cap) = f.grant(Client::Vmmgr, 0);
    f.reject(Client::Vmmgr, &[(a, BLOCK_BITS), (a, BLOCK_BITS)]);
    f.reject(Client::Vmmgr, &[(b, BLOCK_BITS), (a, BLOCK_BITS + 1)]);
    assert!(f.d.mem.state(a) == State::Vmmgr && f.d.mem.state(b) == State::Vmmgr);
    assert_eq!(f.d.free(Client::Vmmgr, &batch(&[(a, BLOCK_BITS), (b, BLOCK_BITS)])), 0);
    assert!(!kernel(|k| k.caps.contains_key(&a_cap) || k.caps.contains_key(&b_cap)));
    assert_eq!(f.d.mem.free_bytes(), 8 << 20);
    f.reject(Client::Vmmgr, &[(a, BLOCK_BITS)]);
    // All of the returned memory must still merge into one usable block.
    assert_eq!(f.grant(Client::Vmmgr, 2).0, 8);
    assert_eq!(f.d.mem.free_bytes(), 0);
    assert_eq!(f.d.alloc(Client::Vmmgr, BLOCK_BITS, 1).err(), Some(ENOMEM));
}

#[test]
fn root_can_return_a_grant_after_boot_handover() {
    let mut f = Fixture::new();
    let (root, slot) = f.grant(Client::Root, 1);
    xchg(Client::Root, 0).move_(&abs(slot)).unwrap();
    assert_eq!(f.d.free(Client::Root, &batch(&[(root, BLOCK_BITS + 1)])), 0);
    assert_eq!(f.d.mem.free_bytes(), 8 << 20);
    assert_eq!(f.grant(Client::Root, 2).0, 8);
}

#[test]
fn a_slot_root_left_full_fails_alloc_and_keeps_the_blocks() {
    let mut f = Fixture::new();
    kernel(|k| { k.caps.insert(xchg(Client::Root, 1).0, (0, 0)); });
    assert_eq!(f.d.alloc(Client::Root, BLOCK_BITS, 2).err(), Some(EINVAL));
    // The first grant came back; the slot root left full is as it was.
    assert!(!kernel(|k| k.caps.contains_key(&xchg(Client::Root, 0).0)));
    assert_eq!(kernel(|k| k.caps.get(&xchg(Client::Root, 1).0).copied()), Some((0, 0)));
    assert_eq!(f.d.mem.free_bytes(), 8 << 20);
    assert_eq!(f.grant(Client::Root, 2).0, 8);
}

#[test]
fn a_slot_vmmgr_fills_again_fails_alloc_and_keeps_the_blocks() {
    let mut f = Fixture::new();
    kernel(|k| k.refill = Some(xchg(Client::Vmmgr, 2).0));
    assert_eq!(f.d.alloc(Client::Vmmgr, BLOCK_BITS, 3).err(), Some(EINVAL));
    // The copies given are revoked, and every block is free.
    for n in 0..2 {
        assert!(!kernel(|k| k.caps.contains_key(&xchg(Client::Vmmgr, n).0)));
    }
    assert_eq!(f.d.mem.free_bytes(), 8 << 20);
    kernel(|k| k.refill = None);
    assert_eq!(f.grant(Client::Vmmgr, 2).0, 8);
}

#[test]
fn hotplug_bucket_bounds_calls_and_time() {
    use bucket::Bucket;
    let mut b = Bucket::full(0);
    // A burst of 16 quick calls, then 8 a second.
    for _ in 0..16 {
        assert!(b.admit(0).is_some());
        b.charge(10);
    }
    assert_eq!(b.admit(0), None);
    assert_eq!(b.admit(124_999), None);
    assert_eq!(b.admit(125_000), Some(1_000));
    b.charge(0);
    let mut n = 0;
    for t in (125_000..=1_125_000).step_by(1_000) {
        if b.admit(t).is_some() {
            b.charge(1);
            n += 1;
        }
    }
    assert_eq!(n, 8);
    // A call that took 100 ms is paid for by 12.5 s without calls.
    let mut b = Bucket::full(0);
    assert_eq!(b.admit(0), Some(16_000));
    b.charge(100_000);
    let paid = 125 * (100_000 - 16_000 + 1_000);
    assert_eq!(b.admit(paid - 1), None);
    assert_eq!(b.admit(paid), Some(1_000));
    // Polling often loses no refill, and time far apart or going back
    // neither wraps nor overfills.
    let mut b = Bucket::full(0);
    b.charge(16_000);
    for t in 0..125_000 {
        assert_eq!(b.admit(t), None);
    }
    assert_eq!(b.admit(125_000), Some(1_000));
    assert_eq!(b.admit(u64::MAX), Some(16_000));
    assert_eq!(b.admit(0), Some(16_000));
    b.charge(u64::MAX);
    assert_eq!(b.admit(u64::MAX), None);
}

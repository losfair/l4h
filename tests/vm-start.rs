//! The production CTL_VM_START handler with a guest that records its boot.
// All of the host's errnos, which this handler returns only some of.
#[allow(dead_code)]
#[path = "../host/l4h-host/src/errno.rs"]
mod errno;
use errno::{EBUSY, EINVAL, EIO, ENOENT, ENOMEM, Errno};
use l4h_abi as abi;

const MAX_GUESTS: usize = 2;

#[derive(PartialEq, Eq)]
enum State { Created, Stopped }
struct Kernel { end: usize }
struct Wins { a: () }

/// Host memory its boot blocks, its l4h-vmm and the VMM's mappings of its
/// backends take.
const BOOT: usize = 64 << 10;
const VMM: usize = 2 << 20;
const MAPS: usize = 32 << 10;

struct Guest {
    state: State,
    vmm: Option<()>,
    root_pending: bool,
    /// What its arena has reserved, and what the host can still give it.
    reserved: usize,
    host: usize,
    boots: usize,
    /// An HVM guest, and the (kernel, initrd, flags) it was booted with.
    hvm: Option<Option<((u64, u64), (u64, u64), u64)>>,
}
impl Guest {
    fn boot_cost(&self, _: usize, _: (usize, usize)) -> Option<(usize, usize)> { Some((BOOT, 0)) }
    fn start_bytes(&self) -> usize { VMM + MAPS }
    /// As Arena::reserve: grow until `bytes` are free, or fail.
    fn reserve(&mut self, _: &mut (), bytes: usize) -> bool {
        let short = bytes.saturating_sub(self.reserved);
        if short > self.host { return false; }
        self.host -= short;
        self.reserved += short;
        true
    }
}

mod hvm {
    /// As the production one: an HVM guest is booted once, with the
    /// kernel dom0 loaded; flags it does not know are refused.  Its boot
    /// blocks are its own RAM: no host memory.
    pub fn boot(g: &mut super::Guest, _: &mut (), kernel: (u64, u64), initrd: (u64, u64), flags: u64, _: &[u8])
        -> Result<(), super::Errno> {
        let h = g.hvm.as_mut().expect("an HVM guest");
        if flags != 0 || kernel.1 == 0 { return Err(super::EINVAL); }
        if h.is_some() { return Err(super::EBUSY); }
        *h = Some((kernel, initrd, flags));
        g.boots += 1;
        Ok(())
    }
}

mod guest {
    /// As the production one: a guest's boot info is written once, and its
    /// boot blocks come out of the arena.
    pub fn boot(g: &mut super::Guest, _: &mut (), _: &mut (), _: &(), _: &super::Kernel, _: (usize, usize), _: &[u8]) -> bool {
        g.boots += 1;
        g.reserved -= super::BOOT;
        g.boots == 1
    }
}

struct Vmmgr { guests: [Option<Guest>; MAX_GUESTS], kernel: Option<Kernel>, alloc: (), wins: Wins, info: (), started: usize, fail_start: bool }
impl Vmmgr {
    fn with_guest<R>(&mut self, id: usize, f: impl FnOnce(&mut Self, &mut Guest) -> R) -> Option<R> {
        let mut g = self.guests[id].take()?;
        let r = f(self, &mut g);
        self.guests[id] = Some(g);
        Some(r)
    }
    fn guest(&self, id: usize) -> Option<&Guest> { self.guests.get(id)?.as_ref() }
    fn can_afford(&self, _: usize, _: usize, _: usize) -> bool { true }
    /// As the production one, nothing here is refused: what the VMM takes
    /// was reserved.
    fn spawn_vmm(&mut self, g: &mut Guest) -> Result<(), Errno> {
        if self.fail_start { g.state = State::Stopped; return Err(EIO); }
        g.reserved = g.reserved.checked_sub(VMM + MAPS).expect("the VMM's memory was reserved");
        g.vmm = Some(());
        self.started += 1;
        Ok(())
    }
}

fn guest(root_pending: bool, host: usize) -> Guest {
    Guest { state: State::Created, vmm: None, root_pending, reserved: 0, host, boots: 0, hvm: None }
}
fn vmmgr(g: Guest) -> Vmmgr {
    Vmmgr { guests: [None, Some(g)], kernel: Some(Kernel { end: 0 }), alloc: (), wins: Wins { a: () }, info: (), started: 0, fail_start: false }
}
fn start() -> abi::CtlReq {
    abi::CtlReq { op: abi::CTL_VM_START, args: [1, 0, 0, 0, 0, 0], ..unsafe { core::mem::zeroed() } }
}

fn cstr(data: &[u8]) -> &[u8] { data }

include!(env!("L4H_VM_START_TEST_SRC"));

#[test]
fn start_refused_for_a_pending_disk_can_be_retried() {
    let mut h = vmmgr(guest(true, BOOT + VMM + MAPS));
    assert_eq!(execute(&mut h, 0, &start()), Err(EBUSY));
    assert_eq!(h.guests[1].as_ref().unwrap().boots, 0, "a refused start must not prepare the guest");
    h.guests[1].as_mut().unwrap().root_pending = false;
    assert_eq!(execute(&mut h, 0, &start()), Ok(()));
    assert_eq!((h.guests[1].as_ref().unwrap().boots, h.started), (1, 1));
}

/// The host has memory for the boot blocks and the VMM, not for the VMM's
/// mappings of the backends: the start is refused before the guest is
/// booted, which is done once, and can be made again.
#[test]
fn start_without_memory_for_the_vmm_is_refused_before_boot() {
    let mut h = vmmgr(guest(false, BOOT + VMM));
    assert_eq!(execute(&mut h, 0, &start()), Err(ENOMEM));
    assert_eq!((h.guests[1].as_ref().unwrap().boots, h.started), (0, 0), "a refused start must not prepare the guest");
    h.guests[1].as_mut().unwrap().host += MAPS;
    assert_eq!(execute(&mut h, 0, &start()), Ok(()));
    assert_eq!((h.guests[1].as_ref().unwrap().boots, h.started), (1, 1));
}

/// A guest that has its VMM is in the wrong state, as for the attach
/// paths, and is not booted again.
#[test]
fn start_of_a_started_guest_is_busy() {
    let mut h = vmmgr(guest(false, BOOT + VMM + MAPS));
    assert_eq!(execute(&mut h, 0, &start()), Ok(()));
    assert_eq!(execute(&mut h, 0, &start()), Err(EBUSY));
    assert_eq!((h.guests[1].as_ref().unwrap().boots, h.started), (1, 1));
    // dom0 does not start itself, nor a VM there is none of.
    assert_eq!(execute(&mut h, 1, &start()), Err(EINVAL));
    let none = abi::CtlReq { args: [0, 0, 0, 0, 0, 0], ..start() };
    assert_eq!(execute(&mut h, 1, &none), Err(ENOENT));
}

#[test]
fn scheduling_failure_is_reported_by_the_public_start_handler() {
    let mut h = vmmgr(guest(false, BOOT + VMM + MAPS));
    h.fail_start = true;
    assert_eq!(execute(&mut h, 0, &start()), Err(EIO));
    assert!(matches!(h.guests[1].as_ref().unwrap().state, State::Stopped));
    assert_eq!(h.started, 0);
}

/// An HVM guest boots the kernel dom0 loaded (args 3-5), once, and only
/// with memory for its l4h-hvm reserved first.
#[test]
fn an_hvm_guest_starts_with_its_kernel() {
    let mut g = guest(false, VMM);
    g.hvm = Some(None);
    let mut h = vmmgr(g);
    let req = abi::CtlReq { args: [1, 0x400_0000, 6, 0x300_0000, 0x80_0000, 0], ..start() };
    assert_eq!(execute(&mut h, 0, &req), Err(ENOMEM));
    assert_eq!((h.guests[1].as_ref().unwrap().boots, h.started), (0, 0), "a refused start must not boot it");
    h.guests[1].as_mut().unwrap().host += MAPS;
    let bad = abi::CtlReq { args: [1, 0x400_0000, 6, 0x300_0000, 0x80_0000, 1], ..start() };
    assert_eq!(execute(&mut h, 0, &bad), Err(EINVAL), "unknown boot flags");
    assert_eq!(execute(&mut h, 0, &req), Ok(()));
    let g = h.guests[1].as_ref().unwrap();
    assert_eq!(g.hvm, Some(Some(((0x300_0000, 0x80_0000), (0x400_0000, 6), 0))));
    assert_eq!((g.boots, h.started), (1, 1));
    assert_eq!(execute(&mut h, 0, &req), Err(EBUSY));
}

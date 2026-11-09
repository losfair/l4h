//! vmmgr's calls to l4h-root (l4h_host::vmmgr): what guests get of the
//! hardware and of the memory devices reach.  Root answers with
//! capabilities in our exchange slots, which we move to slots of our own.
//! A request that waits for a driver root answers later (Later::Token):
//! vmmgr goes on, and takes the answer when root says it has it
//! (main.rs, root_done).  And trustd's flags, which vmmgr acts on for the
//! console.

use l4h_host::errno::Errno;
use sel4::{cap, cap_type};

use l4h_abi as abi;
use l4h_host as host;
use l4h_host::fixed::ArrayVec;
use l4h_host::trust;
use l4h_host::root::{Vals, call::Client};
/// What root's calls pass in our exchange area.
mod caps {
    pub use l4h_host::root::call::XCHG;
    pub use l4h_host::root::call::caps::*;
}
use l4h_host::vmmgr as proto;
use l4h_ipc::Endpoint;
use l4h_host::wiring;

use crate::component::abs_of;
use crate::guest::Guest;
use crate::mem::{Alloc, Arena};
use crate::vmm::Backend;
use crate::ctl;

/// Root's endpoint, whose calls l4h_host::root::call declares.
fn root() -> Endpoint<l4h_host::root::call::Proto> {
    Endpoint::of(&wiring::VMMGR_ROOT, wiring::p::Vmmgr, 0)
}

/// Root's errno as ours: a failed root is EIO.
use l4h_host::wire::eio_if_failed as errno;

/// An answer root gives now, or later: the token of its `result`.
pub use l4h_host::root::Later;

/// The answer of pending request `token`, now that root has it: as the
/// request would have answered.
fn result(token: usize) -> Result<Vals, Errno> {
    errno(root().result(token))
}

/// Take root's answer of a pending request whose answer vmmgr does not
/// want any more (its guest is gone): the token is free again.
pub fn discard(token: usize) {
    let _ = result(token);
}

/// Slot `i` of our exchange area with root (root::call::XCHG).
fn xchg(i: usize) -> sel4::AbsoluteCPtr {
    assert!(i < caps::XCHG);
    abs_of(sel4::Cap::<cap_type::Null>::from_bits(proto::SLOT_XCHG + i as u64))
}

/// Move the `i`th of the capabilities `c` that root passed with its reply,
/// which are T's kind, from our exchange area to a slot of ours.
fn take<T: l4h_ipc::Kind>(alloc: &mut Alloc, c: l4h_host::wire::Caps, i: usize) -> sel4::Cap<T> {
    let s = alloc.slots.alloc();
    let to = sel4::Cap::<T>::from_bits(s as u64);
    abs_of(to).move_(&xchg(c.passed_out(i, T::KIND))).expect("vmmgr: take from exchange");
    to
}

/// What root made for a new guest.
pub struct NewGuest {
    pub instance: u64,
    /// The CNode of its I/O pool's frames.
    pub pool_frames: cap::CNode,
    /// Its l4h-vmm's notification, which root's backends signal.
    pub vmm_ntfn: cap::Notification,
    /// Its attestation device: page and kick capability (badged).
    pub attest: Option<(cap::Granule, cap::Notification)>,
}

/// Guest `id` is being created, with an I/O pool of `pool` bytes at
/// `pool_gpa`.
pub fn guest_new(alloc: &mut Alloc, id: usize, pool: usize, pool_gpa: usize, dom0: bool) -> Result<NewGuest, Errno> {
    let new = errno(root().guest_new(id, pool, pool_gpa, dom0))?;
    let (instance, attest) = (new.instance, new.attest);
    use caps::guest_new::{ATTEST_KICK, ATTEST_PAGE, POOL_FRAMES, VMM_NTFN};
    let pool_frames = take(alloc, POOL_FRAMES, 0);
    let vmm_ntfn = take(alloc, VMM_NTFN, 0);
    let attest = attest.then(|| (take(alloc, ATTEST_PAGE, 0), take(alloc, ATTEST_KICK, 0)));
    Ok(NewGuest { instance, pool_frames, vmm_ntfn, attest })
}

/// Guest `id` is gone from here: root drains its disks and takes back what
/// it gave.
pub fn guest_del(id: usize) {
    if let Ok(kept @ 1..) = root().guest_del(id) {
        info!("l4h-vmmgr: guest {}: {} MiB of I/O pool kept out of use", id, kept >> 20);
    }
}

/// A window of host disk `disk`, or (n, offset) extents in dom0's control
/// data area, for guest `id`'s device `d`: its channel.  `flags`:
/// abi::BLK_*.
#[allow(clippy::too_many_arguments)]
pub fn disk_attach(alloc: &mut Alloc, id: usize, d: usize, disk: usize, flags: u64, lba_start: u64, lba_count: u64,
    (n, offset): (u64, u64)) -> Result<Later<Backend>, Errno> {
    let r = errno(root().disk_attach(id, d, disk, flags, lba_start, lba_count, n as usize, offset))?;
    Ok(r.map(|()| disk_backend(alloc)))
}

/// The channel of disk attachment `token` (disk_attach), now that root
/// has it.
pub fn disk_attach_result(alloc: &mut Alloc, token: usize) -> Result<Backend, Errno> {
    result(token)?;
    Ok(disk_backend(alloc))
}

fn disk_backend(alloc: &mut Alloc) -> Backend {
    let mut chan = ArrayVec::new();
    for i in 0..host::blk::CHANNEL_PAGES {
        chan.must_push(take(alloc, caps::disk_attach::CHANNEL, i));
    }
    let kick = take(alloc, caps::disk_attach::KICK, 0);
    Backend::Blk { chan, kick }
}

/// A port of netd's `switch` for guest `id`'s device `d`.  The VMM's
/// mappings of it are kept in a CNode of `arena`.
#[allow(clippy::too_many_arguments)]
pub fn nic_add(alloc: &mut Alloc, arena: &mut Arena, id: usize, d: usize, switch: u32, mac: u64, lock: bool, isolated: bool) -> Result<Backend, Errno> {
    let keep = arena.try_object(alloc, sel4::ObjectBlueprint::CNode { size_bits: proto::PORT_RADIX }).ok_or(ctl::ENOMEM)?;
    let mac = errno(root().nic_add(id, d, switch, mac, lock, isolated))?.to_be_bytes();
    let chan = take(alloc, caps::nic_add::PORT_FRAMES, 0);
    let kick = take(alloc, caps::nic_add::KICK, 0);
    Ok(Backend::Net { chan, kick, mac: mac[2..8].try_into().unwrap(), keep: sel4::Cap::from_bits(keep as u64) })
}

/// USB controller `ctrl` for guest `id`'s device `d`: the CNode of its
/// queue area's frames, usbd's kick, and the guest's USB number.
pub fn usb_attach(alloc: &mut Alloc, id: usize, d: usize, ctrl: usize) -> Result<(cap::CNode, cap::Notification, usize), Errno> {
    let n = errno(root().usb_attach(id, d, ctrl))? as usize;
    Ok((take(alloc, caps::usb_attach::QUEUE_FRAMES, 0), take(alloc, caps::usb_attach::KICK, 0), n))
}

/// Guest `g` starts: its reports describe it from now on.
pub fn trust_register(g: &Guest) {
    let Some(launch) = g.launch else { return };
    let w = |i: usize| u64::from_le_bytes(launch[8 * i..8 * i + 8].try_into().unwrap());
    let _ = root().trust_register(g.id, g.owned_ram() as u64, g.vcpus.len() as u32, [w(0), w(1), w(2), w(3)]);
}

/// A control op root serves (`host_op`): its vals, and its data in the
/// result page.
pub fn host_op(op: u32, args: &[u64; 6]) -> Result<Later<[u64; 6]>, Errno> {
    Ok(errno(root().host_op(op, *args))?.map(|v| core::array::from_fn(|i| v.at(i))))
}

/// The vals of host op `token` (host_op), now that root has them.  Its
/// data is none.
pub fn host_op_result(token: usize) -> Result<[u64; 6], Errno> {
    let v = result(token)?;
    Ok(core::array::from_fn(|i| v.at(i)))
}

/// The data of the last host op.
pub fn result_data() -> &'static [u8; abi::CTL_DATA_MAX] {
    unsafe { &*(proto::RESULT_VA as *const [u8; abi::CTL_DATA_MAX]) }
}

/// trustd's flags, and the capability to act on them for the console.
pub struct Flags {
    ep: Endpoint<l4h_host::trust::call::Proto>,
}

impl Flags {
    pub fn new(cfg: &proto::VmmgrConfig) -> Option<Self> {
        (cfg.trust != 0).then(|| Flags { ep: Endpoint::of(&wiring::VMMGR_FLAGS, wiring::p::Vmmgr, 0) })
    }

    pub fn flags(&self, g: &Guest) -> trust::Flags {
        unsafe { &*(proto::FLAGS_VA as *const trust::FlagsEntry).add(g.id) }.read().for_instance(g.instance)
    }

    /// Seal check on every op, ACT only for its first taint. `effect`
    /// is false for an empty read/write: it checks seals without tainting.
    pub fn act(&self, g: &Guest, caller: usize, bits: u64, effect: bool) -> Result<(), Errno> {
        if g.id == caller { return Ok(()); }
        self.flags(g).act(bits, effect, || {
            use l4h_host::trust::call::Client;
            errno(self.ep.act(g.id, g.instance, [bits, 0, 0, 0], 0)).map(|_| ())
        })
    }
}

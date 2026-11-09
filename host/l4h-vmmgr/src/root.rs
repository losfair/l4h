//! vmmgr's calls to l4h-root (l4h_host::vmmgr): what guests get of the
//! hardware and of the memory devices reach.  Root answers with
//! capabilities in our exchange slots, which we move to slots of our own.
//! A request that waits for a driver root answers later (Later::Token):
//! vmmgr goes on, and takes the answer when root says it has it
//! (main.rs, root_done).  And trustd's flags, which vmmgr acts on for the
//! console.

use sel4::{cap, cap_type};

use l4h_abi as abi;
use l4h_host as host;
use l4h_host::fixed::ArrayVec;
use l4h_host::trust;
use l4h_host::vmmgr::{self as proto, VMMGR_DISK_ATTACH, VMMGR_GUEST_DEL, VMMGR_GUEST_NEW, VMMGR_HOST_OP, VMMGR_NIC_ADD, VMMGR_PENDING,
    VMMGR_RESULT, VMMGR_TRUST_REGISTER, VMMGR_USB_ATTACH};

use crate::component::abs_of;
use crate::guest::Guest;
use crate::mem::{Alloc, Arena};
use crate::vmm::Backend;
use crate::{ctl, mr, set_mr};

fn ep() -> cap::Endpoint {
    sel4::Cap::from_bits(host::SLOT_ROOT_EP)
}

/// Call root with `args`: Ok, or the errno it answered.
fn call(label: u64, args: &[u64]) -> Result<(), i64> {
    match call_later(label, args)? {
        Later::Now(()) => Ok(()),
        // Only the requests that say so are answered later.
        Later::Token(_) => Err(ctl::EIO),
    }
}

/// An answer root gives now, or later: the token of VMMGR_PENDING.
pub enum Later<T> {
    Now(T),
    Token(usize),
}

impl Later<()> {
    /// What an answer now is (read from the reply).
    fn map<U>(self, f: impl FnOnce() -> U) -> Later<U> {
        match self {
            Later::Now(()) => Later::Now(f()),
            Later::Token(t) => Later::Token(t),
        }
    }
}

/// Call root with `args`: Ok now or later, or the errno it answered.
fn call_later(label: u64, args: &[u64]) -> Result<Later<()>, i64> {
    for (i, &a) in args.iter().enumerate() {
        set_mr(i, a);
    }
    ep().call(sel4::MessageInfo::new(label, 0, 0, args.len()));
    match mr(0) {
        0 => Ok(Later::Now(())),
        VMMGR_PENDING if (mr(1) as usize) < proto::MAX_PENDING => Ok(Later::Token(mr(1) as usize)),
        e => Err(e as i64),
    }
}

/// The answer of pending request `token`, now that root has it: as the
/// request would have answered.
fn result(token: usize) -> Result<(), i64> {
    call(VMMGR_RESULT, &[token as u64])
}

/// Take root's answer of a pending request whose answer vmmgr does not
/// want any more (its guest is gone): the token is free again.
pub fn discard(token: usize) {
    let _ = result(token);
}

fn xchg(i: usize) -> sel4::AbsoluteCPtr {
    abs_of(sel4::Cap::<cap_type::Null>::from_bits(proto::SLOT_XCHG + i as u64))
}

/// Move what root put in exchange slot `i` to a slot of ours.
fn take<T: sel4::CapType>(alloc: &mut Alloc, i: usize) -> sel4::Cap<T> {
    let s = alloc.slots.alloc();
    let to = sel4::Cap::<T>::from_bits(s as u64);
    abs_of(to).move_(&xchg(i)).expect("vmmgr: take from exchange");
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
pub fn guest_new(alloc: &mut Alloc, id: usize, pool: usize, pool_gpa: usize, dom0: bool) -> Result<NewGuest, i64> {
    call(VMMGR_GUEST_NEW, &[id as u64, pool as u64, pool_gpa as u64, dom0 as u64])?;
    let (instance, attest) = (mr(1), mr(2) != 0);
    let pool_frames = take(alloc, 0);
    let vmm_ntfn = take(alloc, 3);
    let attest = attest.then(|| (take(alloc, 1), take(alloc, 2)));
    Ok(NewGuest { instance, pool_frames, vmm_ntfn, attest })
}

/// Guest `id` is gone from here: root drains its disks and takes back what
/// it gave.
pub fn guest_del(id: usize) {
    if call(VMMGR_GUEST_DEL, &[id as u64]).is_ok() && mr(1) != 0 {
        info!("l4h-vmmgr: guest {}: {} MiB of I/O pool kept out of use", id, mr(1) >> 20);
    }
}

/// A window of host disk `disk`, or (n, offset) extents in dom0's control
/// data area, for guest `id`'s device `d`: its channel.  `flags`:
/// abi::BLK_*.
#[allow(clippy::too_many_arguments)]
pub fn disk_attach(alloc: &mut Alloc, id: usize, d: usize, disk: usize, flags: u64, lba_start: u64, lba_count: u64,
    (n, offset): (u64, u64)) -> Result<Later<Backend>, i64> {
    match call_later(VMMGR_DISK_ATTACH, &[id as u64, d as u64, disk as u64, flags, lba_start, lba_count, n, offset])? {
        Later::Now(()) => Ok(Later::Now(disk_backend(alloc))),
        Later::Token(t) => Ok(Later::Token(t)),
    }
}

/// The channel of disk attachment `token` (disk_attach), now that root
/// has it.
pub fn disk_attach_result(alloc: &mut Alloc, token: usize) -> Result<Backend, i64> {
    result(token)?;
    Ok(disk_backend(alloc))
}

fn disk_backend(alloc: &mut Alloc) -> Backend {
    let mut chan = ArrayVec::new();
    for i in 0..host::blk::CHANNEL_PAGES {
        chan.must_push(take(alloc, i));
    }
    let kick = take(alloc, host::blk::CHANNEL_PAGES);
    Backend::Blk { chan, kick }
}

/// A port of netd's `switch` for guest `id`'s device `d`.  The VMM's
/// mappings of it are kept in a CNode of `arena`.
#[allow(clippy::too_many_arguments)]
pub fn nic_add(alloc: &mut Alloc, arena: &mut Arena, id: usize, d: usize, switch: u32, mac: u64, lock: bool, isolated: bool) -> Result<Backend, i64> {
    let keep = arena.try_object(alloc, sel4::ObjectBlueprint::CNode { size_bits: proto::PORT_RADIX }).ok_or(ctl::ENOMEM)?;
    call(VMMGR_NIC_ADD, &[id as u64, d as u64, switch as u64, mac, lock as u64, isolated as u64])?;
    let mac = mr(1).to_be_bytes();
    let chan = take(alloc, 0);
    let kick = take(alloc, 1);
    Ok(Backend::Net { chan, kick, mac: mac[2..8].try_into().unwrap(), keep: sel4::Cap::from_bits(keep as u64) })
}

/// USB controller `ctrl` for guest `id`'s device `d`: the CNode of its
/// queue area's frames, usbd's kick, and the guest's USB number.
pub fn usb_attach(alloc: &mut Alloc, id: usize, d: usize, ctrl: usize) -> Result<(cap::CNode, cap::Notification, usize), i64> {
    call(VMMGR_USB_ATTACH, &[id as u64, d as u64, ctrl as u64])?;
    let n = mr(1) as usize;
    Ok((take(alloc, 0), take(alloc, 1), n))
}

/// Guest `g` starts: its reports describe it from now on.
pub fn trust_register(g: &Guest) {
    let Some(launch) = g.launch else { return };
    let w = |i: usize| u64::from_le_bytes(launch[8 * i..8 * i + 8].try_into().unwrap());
    let flags = if g.dom0 { trust::RECORD_DOM0 } else { 0 } as u64;
    let _ = call(VMMGR_TRUST_REGISTER, &[g.id as u64, g.owned_ram() as u64, g.vcpus.len() as u64, flags, w(0), w(1), w(2), w(3)]);
}

/// A control op root serves (VMMGR_HOST_OP): its vals, and its data in
/// the result page.
pub fn host_op(op: u32, args: &[u64; 6]) -> Result<Later<[u64; 6]>, i64> {
    let mut a = [0; 7];
    a[0] = op as u64;
    a[1..].copy_from_slice(args);
    Ok(call_later(VMMGR_HOST_OP, &a)?.map(|| core::array::from_fn(|i| mr(1 + i))))
}

/// The vals of host op `token` (host_op), now that root has them.  Its
/// data is none.
pub fn host_op_result(token: usize) -> Result<[u64; 6], i64> {
    result(token)?;
    Ok(core::array::from_fn(|i| mr(1 + i)))
}

/// The data of the last host op.
pub fn result_data() -> &'static [u8; abi::CTL_DATA_MAX] {
    unsafe { &*(proto::RESULT_VA as *const [u8; abi::CTL_DATA_MAX]) }
}

/// trustd's flags, and the capability to act on them for the console.
pub struct Flags {
    ep: cap::Endpoint,
}

impl Flags {
    pub fn new(cfg: &proto::VmmgrConfig) -> Option<Self> {
        (cfg.trust != 0).then(|| Flags { ep: sel4::Cap::from_bits(proto::SLOT_FLAGS_EP) })
    }

    pub fn flags(&self, g: &Guest) -> trust::Flags {
        unsafe { &*(proto::FLAGS_VA as *const trust::FlagsEntry).add(g.id) }.read().for_instance(g.instance)
    }

    /// Seal check on every op, ACT only for its first taint. `effect`
    /// is false for an empty read/write: it checks seals without tainting.
    pub fn act(&self, g: &Guest, caller: usize, bits: u64, effect: bool) -> Result<(), i64> {
        if g.id == caller { return Ok(()); }
        self.flags(g).act(bits, effect, || {
            sel4::with_ipc_buffer_mut(|b| b.msg_regs_mut()[..8].copy_from_slice(
                &[trust::FLAGS_ACT, g.id as u64, g.instance, bits, 0, 0, 0, 0]));
            let reply = self.ep.call(sel4::MessageInfo::new(0, 0, 0, 8));
            if reply.length() != 10 { return Err(ctl::EIO); }
            let status = mr(0) as i64;
            if status == 0 { Ok(()) } else { Err(-status) }
        })
    }
}

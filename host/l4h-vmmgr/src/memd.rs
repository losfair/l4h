//! vmmgr's calls to l4h-memd (DESIGN.md §8.4): grants for its own objects,
//! and guests' RAM.  Capabilities cross in the exchange area the two
//! share; memd keeps the originals of what it grants us.  Memory a guest
//! plugs while it runs (DESIGN.md §8.5) is between its l4h-vmm and memd:
//! vmmgr only sets the target.

use sel4::{CapRights, cap, cap_type};

use l4h_host::memd::{self, Status, XCHG_RADIX, call::Client, call::caps};
use l4h_host::vmmgr as proto;
use l4h_task::memd::MemdLink;

use crate::component::abs_of;
use crate::mem::{Alloc, Slot};

/// memd's endpoint, mailbox, and status mapping, installed by root.
pub fn link() -> MemdLink {
    // Root maps the read-only status record for this task's lifetime.
    unsafe {
        MemdLink::new(
            sel4::Cap::from_bits(proto::SLOT_MEMD_EP), crate::slot::CNODE.cap(),
            sel4::Cap::from_bits(proto::SLOT_MEMD_XCHG), XCHG_RADIX, 0, proto::MEMD_STATUS_VA,
        )
    }
}

fn link_of(alloc: &Alloc) -> MemdLink {
    alloc.memd.expect("memd link")
}

/// Take the RAM of guest `g`: `blocks` 2 MiB blocks.  `block_cn` is its
/// block CNode, of radix `radix`, into which memd gives the guest its
/// blocks at boot; `hp_cn` its hotplug CNode, for `hp_count` hotplug
/// blocks.
pub fn guest_create(alloc: &Alloc, g: usize, blocks: usize, block_cn: cap::CNode, radix: usize, hp_cn: cap::CNode, hp_count: usize) -> bool {
    let m = link_of(alloc);
    let (bcn, hcn) = (m.area(caps::guest_create::BLOCK_CNODE.first), m.area(caps::guest_create::HP_CNODE.first));
    bcn.copy(&abs_of(block_cn), CapRights::all()).expect("memd: give block CNode");
    hcn.copy(&abs_of(hp_cn), CapRights::all()).expect("memd: give hotplug CNode");
    let ok = m.guest_create(g, blocks, radix, hp_count).is_ok();
    // What memd did not take.
    let _ = (bcn.delete(), hcn.delete());
    ok
}

/// Set the hotplug target of guest `g`, in hotplug blocks.
pub fn set_target(alloc: &Alloc, g: usize, target: usize) -> bool {
    link_of(alloc).set_target(g, target).is_ok()
}

/// Hotplug target and plugged hotplug blocks of guest `g`.
pub fn hotplug(g: usize) -> memd::GuestHp {
    let st = proto::MEMD_STATUS_VA as *const Status;
    unsafe { core::ptr::addr_of!((*st).hp[g]).read_volatile() }
}

/// Give guest `g`'s l4h-vmm its capability to memd, in `dst`: root made it
/// (badged for the guest), since ours cannot be minted again.
pub fn give_vmm_ep(g: usize, dst: &sel4::AbsoluteCPtr) {
    let ep = sel4::Cap::<cap_type::Endpoint>::from_bits(proto::SLOT_VMM_MEMD_EP + g as u64);
    dst.copy(&abs_of(ep), CapRights::all()).expect("memd: VMM endpoint");
}

/// A copy of block `b` of guest `g`, into our slot `slot`: its physical
/// address.
pub fn guest_copy(alloc: &Alloc, g: usize, b: usize, slot: Slot) -> usize {
    let m = link_of(alloc);
    let paddr = m.guest_copy(g, b).expect("memd: copy of a guest block") as usize;
    abs_of(sel4::Cap::<cap_type::Null>::from_bits(slot as u64)).move_(&m.area(caps::guest_copy::BLOCK.first)).expect("memd: take block copy");
    paddr
}

/// Give guest `g` its blocks from `first` on, block b at index b + `skip`
/// of its block CNode (past its shared blocks, guest.rs).
pub fn guest_give(alloc: &Alloc, g: usize, first: usize, skip: usize) -> bool {
    link_of(alloc).guest_give(g, first, skip).is_ok()
}

/// Revoke and free all the RAM of guest `g`.
pub fn guest_destroy(alloc: &Alloc, g: usize) {
    if let Some(m) = alloc.memd {
        let _ = m.guest_destroy(g);
    }
}

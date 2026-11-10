//! vmmgr's calls to l4h-memd (DESIGN.md §8.4): grants for its own objects,
//! and guests' RAM.  Capabilities cross in the exchange area the two
//! share; memd keeps the originals of what it grants us.  Memory a guest
//! plugs while it runs (DESIGN.md §8.5) is between its l4h-vmm and memd:
//! vmmgr only sets the target.

use sel4::cap_type;

use l4h_host::memd::{self, Status, XCHG_RADIX, call::Client, call::caps};
use l4h_host::vmmgr as proto;
use l4h_task::memd::MemdLink;

use crate::component::abs_of;
use crate::mem::{Alloc, Slot};

/// memd's endpoint, exchange area, and status mapping, installed by root.
pub fn link() -> MemdLink {
    // Root maps the read-only status record for this task's lifetime.
    unsafe {
        MemdLink::new(
            l4h_ipc::Endpoint::of(&l4h_host::wiring::VMMGR_MEMD, l4h_host::wiring::p::Vmmgr, 0), crate::slot::CNODE.cap(),
            sel4::Cap::from_bits(proto::SLOT_MEMD_XCHG), XCHG_RADIX, 0, proto::MEMD_STATUS_VA,
        )
    }
}

fn link_of(alloc: &Alloc) -> MemdLink {
    alloc.memd.expect("memd link")
}

/// Take the RAM of guest `g`: `blocks` 2 MiB blocks.  memd makes its
/// block CNode, of radix `radix`, into which memd gives the guest its
/// blocks at boot, and its hotplug CNode, for `hp_count` hotplug blocks:
/// they go to our slots `cnodes`.  False if memd cannot, or did not give
/// them (it has the guest all the same: guest_destroy).
pub fn guest_create(alloc: &Alloc, g: usize, blocks: usize, radix: usize, hp_count: usize, cnodes: [Slot; 2]) -> bool {
    let m = link_of(alloc);
    if m.guest_create(g, blocks, radix, hp_count).is_err() {
        return false;
    }
    use caps::guest_create::{BLOCK_CNODE, HP_CNODE};
    const GIVEN: [usize; 2] = [BLOCK_CNODE.passed_out(0, l4h_host::wire::Cap::CNode), HP_CNODE.passed_out(0, l4h_host::wire::Cap::CNode)];
    GIVEN.into_iter().zip(cnodes).all(|(c, s)| abs_of(sel4::Cap::<cap_type::Null>::from_bits(s as u64)).move_(&m.area(c)).is_ok())
}

/// Set the hotplug target of guest `g`, in hotplug blocks.
pub fn set_target(alloc: &Alloc, g: usize, target: usize) -> bool {
    link_of(alloc).set_target(g, target).is_ok()
}

/// Hotplug target and plugged hotplug blocks of guest `g`.
pub fn hotplug(g: usize) -> memd::GuestHp {
    // A page memd was writing at every look reads as nothing plugged.
    unsafe { Status::read_at(proto::MEMD_STATUS_VA) }.map_or_else(memd::GuestHp::default, |st| st.hp[g])
}

/// Give guest `g`'s l4h-vmm, `vmm`, its capability to memd: root made it
/// (badged for the guest, wiring::VMMGR_VMM_MEMD), since ours cannot be
/// minted again, and we pass it on (VMM_MEMD).
pub fn give_vmm_ep(g: usize, vmm: &crate::component::Component) {
    let ep = sel4::Cap::<cap_type::Endpoint>::from_bits(l4h_host::wiring::VMMGR_VMM_MEMD.slot(g));
    vmm.pass_edge(&l4h_host::wiring::VMM_MEMD, 0, ep);
}

/// A copy of block `b` of guest `g`, into our slot `slot`: its physical
/// address.  None if memd has failed.
pub fn guest_copy(alloc: &Alloc, g: usize, b: usize, slot: Slot) -> Option<usize> {
    let m = link_of(alloc);
    let paddr = m.guest_copy(g, b).ok()? as usize;
    abs_of(sel4::Cap::<cap_type::Null>::from_bits(slot as u64)).move_(&m.area(caps::guest_copy::BLOCK.passed_out(0, l4h_host::wire::Cap::Untyped))).ok()?;
    Some(paddr)
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

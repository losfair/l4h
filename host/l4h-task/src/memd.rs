//! The allocator's memory-service client. Root and vmmgr supply their own
//! endpoint, exchange CNode, slot range and mapped status page.

use l4h_host::fixed::ArrayVec;
use l4h_host::memd::{self, Status, call::Client};
use l4h_host::wire::Call;
use l4h_host::wiring::{o, p};
use sel4::{cap, cap_type};

use crate::cap_at;
use crate::mem::Slot;

#[derive(Clone, Copy)]
pub struct MemdLink {
    ep: l4h_ipc::Endpoint<memd::call::Proto>,
    local_cnode: cap::CNode,
    exchange: cap::CNode,
    exchange_bits: usize,
    exchange_base: u64,
    status_va: usize,
}

impl MemdLink {
    /// Connect an allocator to its memory service and exchange slots.
    ///
    /// # Safety
    /// `status_va` must remain mapped to memd's aligned, readable `Status`
    /// record for the lifetime of this link and all its copies.
    pub unsafe fn new(
        ep: l4h_ipc::Endpoint<memd::call::Proto>,
        local_cnode: cap::CNode,
        exchange: cap::CNode,
        exchange_bits: usize,
        exchange_base: u64,
        status_va: usize,
    ) -> Self {
        Self { ep, local_cnode, exchange, exchange_bits, exchange_base, status_va }
    }

    /// memd's endpoint, to mint from (wiring::VMMGR_MEMD).
    pub fn obj(&self) -> crate::edge::Obj<p::Memd, o::Endpoint> {
        crate::edge::Obj::claim(p::Memd, o::Endpoint, self.local_cnode.absolute_cptr(self.ep.cap()))
    }

    pub fn slot(&self, i: u64) -> sel4::AbsoluteCPtr {
        self.exchange.absolute_cptr_from_bits_with_depth(i, self.exchange_bits)
    }

    /// Slot `i` of our exchange area with memd (memd::call::XCHG; each
    /// call's capabilities are memd::call::caps).
    pub fn area(&self, i: usize) -> sel4::AbsoluteCPtr {
        assert!(i < memd::XCHG_AREA);
        self.slot(self.exchange_base + i as u64)
    }

    /// memd's status page as it last wrote it, whole: None if it was
    /// writing it at every look (memd::STATUS_TRIES), which a caller takes
    /// as no free memory in memd.
    pub fn status(&self) -> Option<Status> {
        unsafe { Status::read_at(self.status_va) }
    }

    /// An untouched Untyped of 2^bits bytes in local `slot`: its physical
    /// address, or None when the service cannot supply it.
    pub fn alloc(&self, bits: usize, slot: Slot) -> Option<usize> {
        let out = self.area(memd::call::caps::alloc::BLOCKS.passed_out(0, l4h_host::wire::Cap::Untyped));
        // Nothing is ours to keep there between calls: what a call that
        // failed left (memd stopped after passing a grant out) must not
        // fail this one, as a full slot of root's would.
        let _ = out.delete();
        let paddr = *Client::alloc(self, bits, 1).ok()?.0.first()? as usize;
        self.local_cnode.absolute_cptr(cap_at::<cap_type::Null>(slot)).move_(&out).ok()?;
        Some(paddr)
    }

    /// Return untouched grants: (capability, physical address, size bits).
    /// Ok if memd took them: their local slots are then empty.  If it did
    /// not (it has failed), nothing is left in the exchange area and the
    /// call says, for each block, whether it is back in its local slot,
    /// the caller's to use as before; one that is not is gone (memd
    /// stopped after taking it), and its local slot is empty.
    pub fn free(&self, blocks: &[(cap::Untyped, usize, usize)]) -> Result<(), ArrayVec<bool, { memd::XCHG_SLOTS }>> {
        assert!(blocks.len() <= memd::XCHG_SLOTS);
        let area = |i: usize, ut: &cap::Untyped| self.area(memd::call::caps::free::BLOCKS.passed_in(i, l4h_ipc::kind_of(ut)));
        let mut given = ArrayVec::new();
        let mut passed = 0;
        for (i, &(ut, paddr, bits)) in blocks.iter().enumerate() {
            // As memd and root do with a slot they write: whatever an
            // earlier call left there is emptied first, so a full slot
            // cannot fail this one.
            let to = area(i, &ut);
            let _ = to.delete();
            if to.move_(&self.local_cnode.absolute_cptr(ut)).is_err() {
                break;
            }
            given.must_push((paddr, bits));
            passed += 1;
        }
        if passed == blocks.len() && Client::free(self, given).is_ok() {
            return Ok(());
        }
        // memd did not take them (or not all could be passed): each goes
        // back to its slot, which is empty since it was moved out of it.
        let mut back = ArrayVec::new();
        for (i, &(ut, _, _)) in blocks.iter().enumerate() {
            // A block that was not passed is in its slot still.
            back.must_push(i >= passed || self.local_cnode.absolute_cptr(ut).move_(&area(i, &ut)).is_ok());
        }
        log!("l4h-task: memd did not take back {} blocks; {} kept", blocks.len(), back.iter().filter(|&&b| b).count());
        Err(back)
    }
}

/// memd's calls (l4h_host::memd::call) go over its endpoint.
impl Call for MemdLink {
    type Proto = memd::call::Proto;

    fn ipc(&self, label: u64, args: &[u64], reply: &mut [u64]) -> usize {
        self.ep.ipc(label, args, reply)
    }
}

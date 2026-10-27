//! The allocator's memory-service client. Root and vmmgr supply their own
//! endpoint, exchange CNode, slot range and mapped status page.

use l4h_host::memd::{self, Status};
use sel4::{cap, cap_type};

use crate::cap_at;
use crate::mem::Slot;

#[derive(Clone, Copy)]
pub struct MemdLink {
    ep: cap::Endpoint,
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
        ep: cap::Endpoint,
        local_cnode: cap::CNode,
        exchange: cap::CNode,
        exchange_bits: usize,
        exchange_base: u64,
        status_va: usize,
    ) -> Self {
        Self { ep, local_cnode, exchange, exchange_bits, exchange_base, status_va }
    }

    pub fn endpoint(&self) -> cap::Endpoint {
        self.ep
    }

    pub fn slot(&self, i: u64) -> sel4::AbsoluteCPtr {
        self.exchange.absolute_cptr_from_bits_with_depth(i, self.exchange_bits)
    }

    pub fn xchg(&self, i: usize) -> sel4::AbsoluteCPtr {
        assert!(i < memd::XCHG_SLOTS);
        self.slot(self.exchange_base + i as u64)
    }

    pub fn call(&self, label: u64, args: &[u64]) -> u64 {
        sel4::with_ipc_buffer_mut(|b| b.msg_regs_mut()[..args.len()].copy_from_slice(args));
        self.ep.call(sel4::MessageInfo::new(label, 0, 0, args.len()));
        sel4::with_ipc_buffer(|b| b.msg_regs()[0])
    }

    pub fn status(&self) -> Status {
        unsafe { (self.status_va as *const Status).read_volatile() }
    }

    /// An untouched Untyped of 2^bits bytes in local `slot`: its physical
    /// address, or None when the service cannot supply it.
    pub fn alloc(&self, bits: usize, slot: Slot) -> Option<usize> {
        if self.call(memd::MEMD_ALLOC, &[bits as u64, 1]) != 0 {
            return None;
        }
        let paddr = sel4::with_ipc_buffer(|b| b.msg_regs()[1]) as usize;
        self.local_cnode.absolute_cptr(cap_at::<cap_type::Null>(slot))
            .move_(&self.xchg(0)).expect("memd: take grant");
        Some(paddr)
    }

    /// Return untouched grants: (capability, physical address, size bits).
    /// Their local slots are left empty.
    pub fn free(&self, blocks: &[(cap::Untyped, usize, usize)]) {
        assert!(blocks.len() <= memd::XCHG_SLOTS);
        let mut args = [0; 1 + 2 * memd::XCHG_SLOTS];
        args[0] = blocks.len() as u64;
        for (i, &(ut, paddr, bits)) in blocks.iter().enumerate() {
            self.xchg(i).move_(&self.local_cnode.absolute_cptr(ut)).expect("memd: return block");
            (args[1 + 2 * i], args[2 + 2 * i]) = (paddr as u64, bits as u64);
        }
        assert_eq!(self.call(memd::MEMD_FREE, &args[..1 + 2 * blocks.len()]), 0, "memd: free");
    }
}

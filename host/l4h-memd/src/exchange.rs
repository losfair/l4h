//! Memory grants to root and vmmgr through their exchange slots.

use l4h_rt::host::memd::{self, BLOCK_BITS, XCHG_SLOTS};
use l4h_rt::sel4::CapRights;

use crate::mem::{State, abs};
use crate::{Client, EINVAL, ENOMEM, Memd, mr, set_mr, xchg};

impl Memd {
    /// MEMD_ALLOC, each block in the physical `window`. Root gets the
    /// blocks, vmmgr gets copies.
    pub(super) fn alloc_in(&mut self, c: Client, bits: usize, count: usize, window: core::ops::Range<usize>) -> u64 {
        let k = match bits.checked_sub(BLOCK_BITS) {
            Some(k) if k < memd::ORDERS && count <= XCHG_SLOTS => k,
            _ => return EINVAL,
        };
        let mut got = [0u32; XCHG_SLOTS];
        for n in 0..count {
            match self.mem.take_in(k, if c == Client::Root { State::Root } else { State::Vmmgr }, window.clone()) {
                Some(i) => got[n] = i,
                None => {
                    for &i in &got[..n] {
                        self.mem.add(i, k);
                    }
                    return ENOMEM;
                }
            }
        }
        for (n, &i) in got[..count].iter().enumerate() {
            let from = abs(self.mem.slot(i, k));
            match c {
                Client::Root => xchg(c, n).move_(&from).expect("memd: move to exchange"),
                Client::Vmmgr => {
                    // Whatever vmmgr left in its mailbox must not make us fail.
                    let _ = xchg(c, n).delete();
                    xchg(c, n).copy(&from, CapRights::all()).expect("memd: copy to mailbox")
                }
            }
        }
        // Invocations use the message registers: the reply's go last.
        for (n, &i) in got[..count].iter().enumerate() {
            set_mr(1 + n, (i as u64) << BLOCK_BITS);
        }
        0
    }

    /// MEMD_FREE: blocks from the exchange slots.  Of vmmgr's, we keep the
    /// originals: revoking one deletes its copy wherever vmmgr put it, and
    /// all that was made of it.
    pub(super) fn free(&mut self, c: Client, count: usize) -> u64 {
        if count > XCHG_SLOTS {
            return EINVAL;
        }
        // Check them all first, reading the message registers before any
        // invocation uses them.
        let mut blocks = [(0u32, 0usize); XCHG_SLOTS];
        for n in 0..count {
            let Some((i, k)) = self.mem.block_at(mr(1 + 2 * n) as usize, mr(2 + 2 * n) as usize) else {
                return EINVAL;
            };
            let ours = match c {
                Client::Root => matches!(self.mem.state(i), State::None | State::Root),
                // Larger orders can name a retained parent Untyped with
                // other clients' grants below it. Only revoke the grant
                // we actually made, never a caller-selected ancestor.
                Client::Vmmgr => self.mem.state(i) == State::Vmmgr && self.mem.order(i) == k,
            };
            // A repeated head would enter the free list twice. Reject the
            // whole batch before moving or revoking any capabilities.
            if !ours || blocks[..n].iter().any(|&(head, _)| head == i) {
                return EINVAL;
            }
            blocks[n] = (i, k);
        }
        for (n, &(i, k)) in blocks[..count].iter().enumerate() {
            match c {
                Client::Root => abs(self.mem.slot(i, k)).move_(&xchg(c, n)).expect("memd: move from exchange"),
                Client::Vmmgr => {
                    let _ = xchg(c, n).delete();
                    abs(self.mem.slot(i, k)).revoke().expect("memd: revoke vmmgr block");
                }
            }
            self.mem.add(i, k);
        }
        0
    }
}

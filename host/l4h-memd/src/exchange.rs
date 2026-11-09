//! Memory grants to root and vmmgr through their exchange slots.

use l4h_rt::host::memd::{self, BLOCK_BITS, XCHG_SLOTS};
use l4h_rt::sel4::CapRights;

use crate::mem::{State, abs};
use crate::{Client, EINVAL, ENOMEM, Memd, xchg};
use l4h_rt::host::fixed::ArrayVec;

impl Memd {
    /// `alloc`: `count` blocks of 2^bits bytes into the exchange slots,
    /// and their physical addresses.  Root gets them, vmmgr copies.
    pub(super) fn alloc(&mut self, c: Client, bits: usize, count: usize) -> Result<ArrayVec<u64, XCHG_SLOTS>, u64> {
        let k = match bits.checked_sub(BLOCK_BITS) {
            Some(k) if k < memd::ORDERS && count <= XCHG_SLOTS => k,
            _ => return Err(EINVAL),
        };
        let mut got = [0u32; XCHG_SLOTS];
        for n in 0..count {
            match self.mem.take(k, if c == Client::Root { State::Root } else { State::Vmmgr }) {
                Some(i) => got[n] = i,
                None => {
                    for &i in &got[..n] {
                        self.mem.add(i, k);
                    }
                    return Err(ENOMEM);
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
        Ok(got[..count].iter().map(|&i| (i as u64) << BLOCK_BITS).collect())
    }

    /// `free`: the (physical address, size bits) of blocks in the exchange
    /// slots.  Of vmmgr's, we keep the originals: revoking one deletes its
    /// copy wherever vmmgr put it, and all that was made of it.
    pub(super) fn free(&mut self, c: Client, given: &[(usize, usize)]) -> u64 {
        let count = given.len();
        if count > XCHG_SLOTS {
            return EINVAL;
        }
        // Check them all first.
        let mut blocks = [(0u32, 0usize); XCHG_SLOTS];
        for (n, &(paddr, bits)) in given.iter().enumerate() {
            let Some((i, k)) = self.mem.block_at(paddr, bits) else {
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

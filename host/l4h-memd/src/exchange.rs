//! Memory grants to root and vmmgr through their exchange slots.

use l4h_rt::host::errno::Errno;
use l4h_rt::host::memd::{self, BLOCK_BITS, XCHG_SLOTS};
use l4h_rt::sel4::CapRights;

use crate::mem::{State, abs};
use crate::{Client, Memd, granted, returned};
use l4h_rt::host::errno::{EINVAL, ENOMEM};
use l4h_rt::host::fixed::ArrayVec;

impl Memd {
    /// `alloc`: `count` blocks of 2^bits bytes into the exchange slots,
    /// and their physical addresses.  Root gets them, vmmgr copies.
    pub(super) fn alloc(&mut self, c: Client, bits: usize, count: usize) -> Result<ArrayVec<u64, XCHG_SLOTS>, Errno> {
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
            // Whatever vmmgr left in its mailbox must not make us fail, nor
            // a slot it fills again before we do (from another thread):
            // that fails the call.
            let given = match c {
                Client::Root => granted(c, n).move_(&from).is_ok(),
                Client::Vmmgr => {
                    let _ = granted(c, n).delete();
                    granted(c, n).copy(&from, CapRights::all()).is_ok()
                }
            };
            if !given {
                self.ungrant(c, k, &got[..count], n);
                return Err(EINVAL);
            }
        }
        Ok(got[..count].iter().map(|&i| (i as u64) << BLOCK_BITS).collect())
    }

    /// Take back the blocks of order k at `got` of a failed `alloc`, the
    /// first `given` of which are in the caller's slots.  A root grant
    /// that root took already stays root's, to `free`.
    fn ungrant(&mut self, c: Client, k: usize, got: &[u32], given: usize) {
        for (n, &i) in got.iter().enumerate() {
            let slot = abs(self.mem.slot(i, k));
            let back = n >= given
                || match c {
                    Client::Root => slot.move_(&granted(c, n)).is_ok(),
                    // Deletes the copy, wherever vmmgr put it.
                    Client::Vmmgr => slot.revoke().is_ok(),
                };
            if back {
                self.mem.add(i, k);
            }
        }
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
                Client::Root => abs(self.mem.slot(i, k)).move_(&returned(c, n)).expect("memd: move from exchange"),
                Client::Vmmgr => {
                    let _ = returned(c, n).delete();
                    abs(self.mem.slot(i, k)).revoke().expect("memd: revoke vmmgr block");
                }
            }
            self.mem.add(i, k);
        }
        0
    }
}

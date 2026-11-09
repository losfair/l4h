//! A serve loop's reply object (l4h_ipc::run), made from an Untyped of
//! its own so that one left bound to an unanswered caller (a faulted or
//! stopped thread) is replaced without using more memory: revoking the
//! Untyped deletes it, which leaves that caller inactive for good.

use sel4::{ObjectBlueprint, cap};

use crate::mem::{Alloc, cnode_dest};

pub struct ReplySlot {
    cnode: cap::CNode,
    ut: cap::Untyped,
    reply: cap::Reply,
}

impl ReplySlot {
    /// One in `reply`, an empty slot of the caller's CNode.
    pub fn new(alloc: &mut Alloc, reply: cap::Reply) -> Self {
        let ut_slot = alloc.slots.alloc();
        let ut = alloc.split(12, ut_slot).expect("reply object memory").cap;
        let r = ReplySlot { cnode: alloc.slots.cnode(), ut, reply };
        r.make();
        r
    }

    fn make(&self) {
        self.ut
            .untyped_retype(&ObjectBlueprint::Reply, &cnode_dest(self.cnode), self.reply.bits() as usize, 1)
            .expect("reply object");
    }
}

impl l4h_ipc::ReplyObject for ReplySlot {
    fn cap(&self) -> cap::Reply {
        self.reply
    }

    fn unanswered(&mut self) {
        self.cnode.absolute_cptr(self.ut).revoke().expect("revoke reply object");
        self.make();
    }
}

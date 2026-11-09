//! Root's requests to blkd and netd (host::mailbox).  Each handles guests'
//! rings and device memory, so its code may be an attacker's, and root
//! never waits for it: it posts a request and goes back to its loop, and
//! finishes what the request was for when the driver has answered
//! (blkd.rs, netd.rs: `poll`, from the serve loop on MAILBOX_BADGE).  A
//! request a driver never answers stays pending, and so does whatever
//! waits for it.  memd, which handles no one's data, is called (memd.rs).

use core::sync::atomic::{AtomicU64, Ordering};

use sel4::{CapRights, VmAttributes, cap, cap_type};

use l4h_host::mailbox::{self as mb, ANSWER, ARGS, MAILBOX_PAGES, MAILBOX_VA, PUBLISHED_OFFSET, RING};

use crate::component::{Component, abs_of};
use crate::layout;
use crate::mem::{Alloc, Arena, ObjCtx};
use crate::vspace::{FRAME_BP, map_frame};

const PAGE: usize = 4096;

/// Badge bit of a driver's answers on root's notification.
pub const MAILBOX_BADGE: u64 = 1 << 43;

/// Mailboxes in layout::MAILBOXES: netd's, then each disk controller's.
pub const NETD_MAILBOX: usize = 0;
pub const fn blkd_mailbox(ctrl: usize) -> usize {
    1 + ctrl
}

/// Root's notification, bound to its TCB (main.rs).
static NTFN: AtomicU64 = AtomicU64::new(0);

pub fn init(ntfn: cap::Notification) {
    NTFN.store(ntfn.bits(), Ordering::Relaxed);
}

pub struct Mailbox {
    page: *const mb::Mailbox,
    published: usize,
    /// The driver's notification, badged BADGE_CALL.
    kick: cap::Notification,
    /// Requests posted and answered, as root counts them: the driver
    /// can write over the page's.
    posted: u64,
    answered: u64,
}

impl Mailbox {
    /// Give `comp` its mailbox, number `index` in layout::MAILBOXES, from
    /// `arena`, keeping the mapping capabilities in `keep()`.
    pub fn new(comp: &Component, index: usize, alloc: &mut Alloc, arena: &mut Arena,
        mut keep: impl FnMut() -> sel4::AbsoluteCPtr) -> Self {
        let base = layout::MAILBOXES.base + index * MAILBOX_PAGES * PAGE;
        assert!(base + MAILBOX_PAGES * PAGE <= layout::MAILBOXES.end(), "mailbox {}", index);
        for p in 0..MAILBOX_PAGES {
            let f = arena.object_cap::<cap_type::Granule>(alloc, FRAME_BP);
            comp.map_copy(alloc, arena, &abs_of(f), MAILBOX_VA + p * PAGE, CapRights::read_write(), VmAttributes::DEFAULT, keep());
            map_frame(&mut ObjCtx::global(alloc), sel4::init_thread::slot::VSPACE.cap(), f, base + p * PAGE,
                CapRights::read_write(), VmAttributes::DEFAULT);
        }
        let ntfn = cap::Notification::from_bits(NTFN.load(Ordering::Relaxed));
        comp.give_badged(mb::SLOT_MAILBOX_DONE, ntfn, CapRights::write_only(), MAILBOX_BADGE);
        let slot = alloc.slots.alloc();
        let kick = sel4::init_thread::Slot::<cap_type::Notification>::from_index(slot).cap();
        abs_of(kick).mint(&abs_of(comp.ntfn), CapRights::write_only(), mb::BADGE_CALL).expect("mailbox kick");
        Mailbox { page: base as *const mb::Mailbox, published: base + PUBLISHED_OFFSET, kick, posted: 0, answered: 0 }
    }

    fn page(&self) -> &mb::Mailbox {
        unsafe { &*self.page }
    }

    /// Whether a request can be posted now.
    pub fn room(&self) -> bool {
        self.posted - self.answered < RING as u64
    }


    /// Post a request: its number, or None if the ring is full (a driver
    /// that does not answer).
    pub fn post(&mut self, label: u64, args: &[u64]) -> Option<u64> {
        if !self.room() {
            return None;
        }
        let k = self.posted;
        let e = &self.page().entries[k as usize % RING];
        e.label.store(label, Ordering::Relaxed);
        for (i, a) in e.args.iter().enumerate() {
            a.store(args.get(i).copied().unwrap_or(0), Ordering::Relaxed);
        }
        const { assert!(ARGS >= 6) };
        self.posted = k + 1;
        self.page().posted.store(k + 1, Ordering::Release);
        self.kick.signal();
        Some(k)
    }

    /// The oldest answer not taken yet, if the driver has given it: the
    /// request's number and the answer's words.  A count the driver gives
    /// out of order is ignored, which leaves everything pending.
    pub fn answer(&mut self) -> Option<(u64, [u64; ANSWER])> {
        let done = self.page().done.load(Ordering::Acquire);
        if done <= self.answered || done > self.posted {
            return None;
        }
        let k = self.answered;
        let e = &self.page().entries[k as usize % RING];
        let words = core::array::from_fn(|i| e.answer[i].load(Ordering::Relaxed));
        self.answered = k + 1;
        Some((k, words))
    }

    /// Give up on the oldest request not answered (the driver is stopped):
    /// its number.
    pub fn abandon(&mut self) -> Option<u64> {
        (self.answered < self.posted).then(|| {
            self.answered += 1;
            self.answered - 1
        })
    }

    /// The driver says it has failed (l4h_rt::abort_trap).
    pub fn failed(&self) -> bool {
        self.page().failed.load(Ordering::Acquire) != 0
    }

    /// What the driver publishes (blk::Published, net::Published).
    pub fn published<T>(&self) -> &T {
        const { assert!(core::mem::size_of::<T>() <= PAGE) };
        unsafe { &*(self.published as *const T) }
    }
}

//! Root's requests to blkd, netd and usbd (host::mailbox).  Each handles
//! guests' rings and device memory, so its code may be an attacker's, and
//! root never waits for it: it posts a request and goes back to its loop,
//! and finishes what the request was for when the driver has answered
//! (blkd.rs, netd.rs, usb.rs: `poll`, from the serve loop on
//! badges::root::MAILBOX).  A request a driver never answers stays pending, and so
//! does whatever waits for it.  A driver that faults (it has no keeper) is
//! failed by root (`fault`), which gives up on what it has not answered.  memd, which handles no one's data, is
//! called (memd.rs).

use core::sync::atomic::{AtomicU64, Ordering};

use l4h_host::wire::{Message, Protocol};

use sel4::{CapRights, VmAttributes, cap, cap_type};

use l4h_host::wiring::{E, Rights, o, p};
use l4h_host::mailbox::{self as mb, MAILBOX_PAGES, MAILBOX_VA, PUBLISHED_OFFSET};

use crate::component::{Component, abs_of};
use crate::layout;
use crate::mem::{Alloc, Arena, ObjCtx};
use crate::vspace::{FRAME_BP, map_frame};

const PAGE: usize = 4096;

/// Mailboxes in layout::MAILBOXES: netd's, then each disk controller's,
/// then each xHCI controller's, then each NIC's nicd's (one at a time),
/// then vmmgr's.
pub const NETD_MAILBOX: usize = 0;
pub const fn blkd_mailbox(ctrl: usize) -> usize {
    1 + ctrl
}
pub const fn usbd_mailbox(ctrl: usize) -> usize {
    1 + crate::pci::MAX_DISK_CTRLS + ctrl
}
pub const fn nicd_mailbox(nic: usize) -> usize {
    usbd_mailbox(l4h_host::usb::MAX_USB_CTRLS) + nic
}
pub const VMMGR_MAILBOX: usize = nicd_mailbox(l4h_host::nicd::MAX_UPLINKS);
pub const MAILBOXES: usize = VMMGR_MAILBOX + 1;

/// Root's notification, bound to its TCB (main.rs).
static NTFN: AtomicU64 = AtomicU64::new(0);

pub fn init(ntfn: cap::Notification) {
    NTFN.store(ntfn.bits(), Ordering::Relaxed);
}

pub struct Mailbox<P> {
    client: mb::Client<'static, P>,
    published: usize,
    /// The driver's notification, badged badges::driver::CALL.
    kick: cap::Notification,
}

impl<P: Protocol> Mailbox<P> {
    /// Give `comp` its mailbox, number `index` in layout::MAILBOXES, from
    /// `arena`, keeping the mapping capabilities in `keep()`.  Root posts
    /// on edge `call`, and `comp` answers on `done`.
    pub fn new<T: p::IsParty>(comp: &Component, index: usize, call: &E<p::Root, T, o::Notification, P>,
        done: &E<T, p::Root, o::Notification>, alloc: &mut Alloc, arena: &mut Arena,
        mut keep: impl FnMut() -> sel4::AbsoluteCPtr) -> Self {
        assert!(matches!(call.rights, Rights::Post), "a mailbox is made from a post edge");
        let base = layout::MAILBOXES.base + index * MAILBOX_PAGES * PAGE;
        assert!(base + MAILBOX_PAGES * PAGE <= layout::MAILBOXES.end(), "mailbox {}", index);
        for p in 0..MAILBOX_PAGES {
            let f = arena.object_cap::<cap_type::Granule>(alloc, FRAME_BP);
            comp.map_copy(alloc, arena, &abs_of(f), MAILBOX_VA + p * PAGE, CapRights::read_write(), VmAttributes::DEFAULT, keep());
            map_frame(&mut ObjCtx::global(alloc), sel4::init_thread::slot::VSPACE.cap(), f, base + p * PAGE,
                CapRights::read_write(), VmAttributes::DEFAULT);
        }
        let ntfn = cap::Notification::from_bits(NTFN.load(Ordering::Relaxed));
        comp.give_edge(done, 0, 0, &crate::component::root_ntfn(ntfn));
        let slot = alloc.slots.alloc();
        let kick = sel4::init_thread::Slot::<cap_type::Notification>::from_index(slot).cap();
        crate::component::mint_edge(&abs_of(kick), call, 0, &comp.obj()).expect("mailbox kick");
        let page = unsafe { &*(base as *const mb::Mailbox) };
        Mailbox { client: mb::Client::new(page), published: base + PUBLISHED_OFFSET, kick }
    }

    pub fn room(&self) -> bool {
        self.client.room()
    }

    pub fn idle(&self) -> bool {
        self.client.idle()
    }

    /// Post a request of this mailbox's protocol and signal its peer.
    pub fn send<M: Message<Proto = P>>(&mut self, req: &M) -> Option<u64> {
        let k = self.client.send(req)?;
        self.kick.signal();
        Some(k)
    }

    /// Signal the peer without posting (a nicd's configuration request
    /// is answered: l4h-root's nicd.rs).
    pub fn kick(&self) {
        self.kick.signal();
    }

    pub fn answer(&mut self) -> Option<(u64, mb::Reply)> {
        self.client.answer()
    }

    /// Give up on the oldest request, once the peer is stopped.
    pub fn abandon(&mut self) -> Option<u64> {
        self.client.abandon()
    }

    /// What the driver publishes (blk::Published, net::Published).
    pub fn published<T>(&self) -> &T {
        const { assert!(core::mem::size_of::<T>() <= PAGE) };
        unsafe { &*(self.published as *const T) }
    }
}

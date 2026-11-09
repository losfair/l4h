//! A driver's side of root's requests (host::mailbox).

use core::sync::atomic::Ordering;

use crate::host::mailbox::{ANSWER, ARGS, MAILBOX_VA, Mailbox, PUBLISHED_OFFSET, RING, SLOT_MAILBOX_DONE};
use crate::{cap, sel4};

fn page() -> &'static Mailbox {
    unsafe { &*(MAILBOX_VA as *const Mailbox) }
}

/// The page the driver publishes for root (blk::Published, net::Published).
pub fn published<T>() -> &'static T {
    const { assert!(core::mem::size_of::<T>() <= 4096) };
    unsafe { &*((MAILBOX_VA + PUBLISHED_OFFSET) as *const T) }
}

/// Root's next request, if one is waiting: its label, with its arguments
/// in message registers 0.., as a call would have them.  Answer it before
/// asking for the next.
pub fn request() -> Option<u64> {
    let m = page();
    let k = m.done.load(Ordering::Relaxed);
    if m.posted.load(Ordering::Acquire) == k {
        return None;
    }
    let e = &m.entries[k as usize % RING];
    sel4::with_ipc_buffer_mut(|b| {
        for (r, a) in b.msg_regs_mut()[..ARGS].iter_mut().zip(&e.args) {
            *r = a.load(Ordering::Relaxed);
        }
    });
    Some(e.label.load(Ordering::Relaxed))
}

/// Answer the request `request` returned with message registers 0..n.
/// Root learns of it at the next `signal`.
pub fn answer(n: usize) {
    let words = sel4::with_ipc_buffer(|b| {
        let mut w = [0; ANSWER];
        w[..n].copy_from_slice(&b.msg_regs()[..n]);
        w
    });
    publish(&words);
}

/// Tell root that requests were answered.
pub fn signal() {
    cap::<sel4::cap_type::Notification>(SLOT_MAILBOX_DONE).signal();
}

fn publish(words: &[u64; ANSWER]) {
    let m = page();
    let k = m.done.load(Ordering::Relaxed);
    for (a, &w) in m.entries[k as usize % RING].answer.iter().zip(words) {
        a.store(w, Ordering::Relaxed);
    }
    m.done.store(k + 1, Ordering::Release);
}

/// The driver has failed: answer every request, now and later, with
/// u64::MAX.
pub(crate) fn fail() {
    let m = page();
    m.failed.store(1, Ordering::Release);
    let mut words = [0; ANSWER];
    words[0] = u64::MAX;
    while m.posted.load(Ordering::Acquire) != m.done.load(Ordering::Relaxed) {
        publish(&words);
    }
    signal();
}

//! A driver's side of root's requests (host::mailbox).

use core::sync::atomic::{AtomicU64, Ordering};

use crate::host::mailbox::{ANSWER, ARGS, MAILBOX_VA, Mailbox, PUBLISHED_OFFSET, RING, SLOT_MAILBOX_DONE};
use crate::{cap, sel4};

fn page() -> &'static Mailbox {
    unsafe { &*(MAILBOX_VA as *const Mailbox) }
}

/// Requests answered, as the driver counts them.  It only publishes the
/// page's `done`, as root keeps its own counts (l4h-root's mailbox.rs).
static DONE: AtomicU64 = AtomicU64::new(0);

/// The page the driver publishes for root (blk::Published, net::Published).
pub fn published<T>() -> &'static T {
    const { assert!(core::mem::size_of::<T>() <= 4096) };
    unsafe { &*((MAILBOX_VA + PUBLISHED_OFFSET) as *const T) }
}

/// Answer every request root has waiting, in order: `f(label, args,
/// answer)` fills the answer and returns its length, or None to answer
/// wire::FAILED (the driver could not carry the request out).  Arguments
/// and answer never pass through the message registers, so `f`'s
/// invocations cannot overwrite them.  Returns whether it answered any;
/// then `signal` root.
pub fn serve(mut f: impl FnMut(u64, &[u64], &mut [u64; ANSWER]) -> Option<usize>) -> bool {
    let m = page();
    let mut answered = false;
    loop {
        let k = DONE.load(Ordering::Relaxed);
        if m.posted.load(Ordering::Acquire) == k {
            return answered;
        }
        let e = &m.entries[k as usize % RING];
        let mut args = [0; ARGS];
        let mut words = [0; ANSWER];
        match e.arguments(&mut args) {
            Some((label, n)) => match f(label, &args[..n], &mut words) {
                Some(n) if n <= ANSWER => e.write_reply(&words[..n]),
                _ => e.write_reply(&[crate::host::wire::FAILED]),
            },
            None => e.write_reply(&[crate::host::wire::EINVAL]),
        }
        publish(k);
        answered = true;
    }
}

/// Tell root that requests were answered.
pub fn signal() {
    cap::<sel4::cap_type::Notification>(SLOT_MAILBOX_DONE).signal();
}

/// Signal a client through a slot root fills and empties (blkd's, netd's
/// and usbd's notifications of their clients).  Root may empty the slot
/// before the driver has taken the request that says so, and Signal on an
/// empty slot would fault the driver; NBSend ignores it.
#[allow(clippy::disallowed_methods)]
pub fn notify(client: sel4::cap::Notification) {
    client.nb_send(sel4::MessageInfo::new(0, 0, 0, 0));
}

fn publish(k: u64) {
    let m = page();
    DONE.store(k + 1, Ordering::Relaxed);
    m.done.store(k + 1, Ordering::Release);
}

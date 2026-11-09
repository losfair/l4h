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

/// Answer every request root has waiting, in order: `f(label, args,
/// answer)` fills the answer and returns its length, or None to answer as
/// a failed driver would (FAILED).  Arguments and answer never pass
/// through the message registers, so `f`'s invocations cannot overwrite
/// them.  Returns whether it answered any; then `signal` root.
pub fn serve(mut f: impl FnMut(u64, &[u64; ARGS], &mut [u64; ANSWER]) -> Option<usize>) -> bool {
    let m = page();
    let mut answered = false;
    loop {
        let k = m.done.load(Ordering::Relaxed);
        if m.posted.load(Ordering::Acquire) == k {
            return answered;
        }
        let e = &m.entries[k as usize % RING];
        let label = e.label.load(Ordering::Relaxed);
        let args: [u64; ARGS] = core::array::from_fn(|i| e.args[i].load(Ordering::Relaxed));
        let mut words = [0; ANSWER];
        if f(label, &args, &mut words).is_none() {
            words = [0; ANSWER];
            words[0] = crate::host::wire::FAILED;
        }
        publish(&words);
        answered = true;
    }
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

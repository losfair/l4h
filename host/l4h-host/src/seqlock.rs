//! A sequence count over data that one party writes and others read in
//! memory they share: odd while it is written, changed by every write.  A
//! reader takes its copy between two loads of the count, and has nothing
//! if a write was under way or came meanwhile.  The readers never write,
//! so a page mapped read-only for them is enough; how often one looks
//! again, and what it does without a copy, is its own to say.
//!
//! The one place the host's sequence counts are read and written
//! (trust::FlagsEntry, memd::Status, vmmgr::GuestStatus, trustd's relay
//! slots as root writes them).

use core::sync::atomic::{AtomicU32, Ordering, fence};

/// One look: what `copy` gave, if no write was under way when it began
/// and none started before it ended.
pub fn look<T>(seq: &AtomicU32, copy: impl FnOnce() -> T) -> Option<T> {
    let before = seq.load(Ordering::Acquire);
    if before & 1 != 0 {
        return None;
    }
    let value = copy();
    fence(Ordering::Acquire);
    (seq.load(Ordering::Relaxed) == before).then_some(value)
}

/// `look`, up to `tries` times.
pub fn read<T>(seq: &AtomicU32, tries: usize, mut copy: impl FnMut() -> T) -> Option<T> {
    for _ in 0..tries {
        if let Some(value) = look(seq, &mut copy) {
            return Some(value);
        }
        core::hint::spin_loop();
    }
    None
}

/// The one writer's write: the count is odd while `store` runs, which is
/// given that odd count, and even and new after.  A count found odd (the
/// last write never ended, or a peer that maps the page changed it) is
/// taken as it is, so that the count ends even all the same.
pub fn write(seq: &AtomicU32, store: impl FnOnce(u32)) {
    let odd = seq.load(Ordering::Relaxed) | 1;
    seq.store(odd, Ordering::Relaxed);
    fence(Ordering::Release);
    store(odd);
    seq.store(odd.wrapping_add(1), Ordering::Release);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_look_gives_what_was_written_whole_or_nothing() {
        let seq = AtomicU32::new(0);
        let data = AtomicU32::new(7);
        assert_eq!(look(&seq, || data.load(Ordering::Relaxed)), Some(7));
        write(&seq, |odd| {
            assert_eq!(odd, 1);
            // A reader that comes during the write has nothing, however
            // often it looks.
            assert_eq!(look(&seq, || data.load(Ordering::Relaxed)), None);
            assert_eq!(read(&seq, 8, || data.load(Ordering::Relaxed)), None);
            data.store(9, Ordering::Relaxed);
        });
        assert_eq!((seq.load(Ordering::Relaxed), read(&seq, 1, || data.load(Ordering::Relaxed))), (2, Some(9)));
        // A write that comes during a look takes its copy away.
        assert_eq!(look(&seq, || write(&seq, |_| ())), None);
        // A count left odd ends even after the next write.
        seq.store(5, Ordering::Relaxed);
        write(&seq, |odd| assert_eq!(odd, 5));
        assert_eq!(seq.load(Ordering::Relaxed), 6);
    }
}

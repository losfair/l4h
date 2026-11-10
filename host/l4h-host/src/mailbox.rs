//! Root's requests to the drivers (blkd, netd, usbd), and its notices to
//! vmmgr, which root never waits on either.  A driver handles guests'
//! rings and device memory, so root must assume its code can be an
//! attacker's, and an attacker's driver could leave a request unanswered
//! for good.  Root never waits for one: it posts requests in a ring in a
//! page the two share, signals the driver's notification with badges::driver::CALL
//! and goes back to its loop.  The driver answers them in order, counts
//! them in `done` and signals SLOT_MAILBOX_DONE; root finishes what it was
//! doing then (l4h-root's mailbox.rs), matching each answer to its request
//! by the request's number.  A request a driver never answers stays
//! pending, and so does whatever waits for it, nothing else.  A driver has
//! no keeper: its faults go to root (badges::root::FAULT), which
//! quarantines it and gives up on what it has not answered, as
//! wire::FAILED.  An answer can also say that a request failed (an errno,
//! or wire::FAILED from l4h_rt::mailbox::serve), and for some requests root
//! then quarantines the controller as it would for a fault.  That gives a
//! driver nothing it lacks: it could fault, or never answer, instead.  A
//! quarantine suspends the driver and turns its device off, and keeps what
//! either may still reach out of use.
//!
//! The third page is the driver's to publish what root reads without
//! asking: blkd's disks (blk::Published), netd's counters (net::Published),
//! usbd's (usb::Published).

use core::marker::PhantomData;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::wire::{Message, Protocol};

/// The pages, in the driver from MAILBOX_VA: the ring, then the published
/// page.
pub const MAILBOX_VA: usize = 0x1020_0000;
pub const MAILBOX_PAGES: usize = 3;
pub const PUBLISHED_OFFSET: usize = 2 * 4096;
const _: () = assert!(MAILBOX_VA >= crate::serial::VA + crate::serial::PAGES * 4096
    && MAILBOX_VA + MAILBOX_PAGES * 4096 < crate::KEEPER_STACK_TOP - crate::KEEPER_STACK_SIZE);


/// The driver's capability to signal root that it answered.
pub const SLOT_MAILBOX_DONE: u64 = 11;
const _: () = assert!(crate::SLOT_KEEPER_REPLY < SLOT_MAILBOX_DONE && SLOT_MAILBOX_DONE < crate::SLOT_FIRST_FREE);

/// Words of a request's arguments and of its answer.
pub const ARGS: usize = 6;
pub const ANSWER: usize = 5;
/// Requests in the ring.
pub const RING: usize = 64;

#[repr(C)]
pub struct Entry {
    pub label: AtomicU64,
    pub args_len: AtomicU64,
    pub args: [AtomicU64; ARGS],
    pub answer_len: AtomicU64,
    pub answer: [AtomicU64; ANSWER],
}

impl Entry {
    /// Take exactly the published argument words, or refuse a length
    /// outside the entry. Padding is never part of a protocol message.
    pub fn arguments(&self, out: &mut [u64; ARGS]) -> Option<(u64, usize)> {
        let n = self.args_len.load(Ordering::Relaxed);
        if n > ARGS as u64 {
            return None;
        }
        let n = n as usize;
        for (to, from) in out[..n].iter_mut().zip(&self.args) {
            *to = from.load(Ordering::Relaxed);
        }
        Some((self.label.load(Ordering::Relaxed), n))
    }

    /// Write a reply before publishing the count that covers it.
    pub fn write_reply(&self, words: &[u64]) {
        assert!(words.len() <= ANSWER);
        for (to, &word) in self.answer.iter().zip(words) {
            to.store(word, Ordering::Relaxed);
        }
        self.answer_len.store(words.len() as u64, Ordering::Relaxed);
    }
}

#[repr(C)]
pub struct Mailbox {
    /// Requests root has posted: request k is in entries[k % RING].  Root
    /// writes an entry, then raises `posted`.
    pub posted: AtomicU64,
    /// Requests the driver has answered, in order.  It writes the answer,
    /// then raises `done`.
    pub done: AtomicU64,
    pub entries: [Entry; RING],
}
const _: () = assert!(core::mem::size_of::<Mailbox>() <= PUBLISHED_OFFSET);

/// One reply's words and their actual length. A peer's oversized length
/// is FAILED; a short message stays short for wire::reply to reject.
#[derive(Clone, Copy, Debug)]
pub struct Reply {
    words: [u64; ANSWER],
    len: usize,
}

impl Reply {
    pub const FAILED: Self = {
        let mut words = [0; ANSWER];
        words[0] = crate::wire::FAILED;
        Self { words, len: 1 }
    };

    fn read(e: &Entry) -> Self {
        let n = e.answer_len.load(Ordering::Relaxed);
        if n > ANSWER as u64 {
            return Self::FAILED;
        }
        let mut reply = Self { words: [0; ANSWER], len: n as usize };
        for (to, from) in reply.words[..reply.len].iter_mut().zip(&e.answer) {
            *to = from.load(Ordering::Relaxed);
        }
        reply
    }
}

impl core::ops::Deref for Reply {
    type Target = [u64];
    fn deref(&self) -> &[u64] {
        &self.words[..self.len]
    }
}

/// The poster's side of a mailbox of protocol P. Root's transport adds
/// the notification; the protocol and the private counts live here, so
/// a request of another protocol cannot be posted through this client.
pub struct Client<'a, P> {
    page: &'a Mailbox,
    posted: u64,
    answered: u64,
    protocol: PhantomData<P>,
}

impl<'a, P: Protocol> Client<'a, P> {
    /// A fresh, zeroed mailbox whose peer has not run yet.
    pub fn new(page: &'a Mailbox) -> Self {
        const { assert!(P::MAX_WORDS <= ARGS && P::MAX_REPLY_WORDS <= ANSWER, "protocol longer than a mailbox entry") };
        Self { page, posted: 0, answered: 0, protocol: PhantomData }
    }

    pub fn room(&self) -> bool {
        self.posted - self.answered < RING as u64
    }

    pub fn idle(&self) -> bool {
        self.answered == self.posted
    }

    /// Post a request of P, before signalling the peer: its number, or
    /// None if all entries are still in use. Shared counts are the
    /// peer's to overwrite, so only our private counts govern reuse.
    pub fn send<M: Message<Proto = P>>(&mut self, req: &M) -> Option<u64> {
        if !self.room() {
            return None;
        }
        let mut args = [0; ARGS];
        let n = req.encode(&mut args);
        assert!(n <= ARGS);
        let k = self.posted;
        let e = &self.page.entries[k as usize % RING];
        e.label.store(req.label(), Ordering::Relaxed);
        for (to, &word) in e.args.iter().zip(&args[..n]) {
            to.store(word, Ordering::Relaxed);
        }
        e.args_len.store(n as u64, Ordering::Relaxed);
        self.posted = k + 1;
        self.page.posted.store(self.posted, Ordering::Release);
        Some(k)
    }

    /// The oldest reply, if the peer has published it. A shared count
    /// outside the requests we actually posted leaves them pending.
    pub fn answer(&mut self) -> Option<(u64, Reply)> {
        let done = self.page.done.load(Ordering::Acquire);
        if done <= self.answered || done > self.posted {
            return None;
        }
        let k = self.answered;
        let reply = Reply::read(&self.page.entries[k as usize % RING]);
        self.answered = k + 1;
        Some((k, reply))
    }

    /// Give up on the oldest request, once the peer is stopped.
    pub fn abandon(&mut self) -> Option<u64> {
        (self.answered < self.posted).then(|| {
            self.answered += 1;
            self.answered - 1
        })
    }
}


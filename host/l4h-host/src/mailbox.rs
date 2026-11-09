//! Root's requests to the drivers (blkd, netd, usbd).  A driver handles guests'
//! rings and device memory, so root must assume its code can be an
//! attacker's, and an attacker's driver could leave a request unanswered
//! for good.  Root never waits for one: it posts requests in a ring in a
//! page the two share, signals the driver's notification with badges::driver::CALL
//! and goes back to its loop.  The driver answers them in order, counts
//! them in `done` and signals SLOT_MAILBOX_DONE; root finishes what it was
//! doing then (l4h-root's mailbox.rs).  A request a driver never answers
//! stays pending, and so does whatever waits for it, nothing else.  A
//! driver has no keeper: its faults go to root (badges::root::FAULT),
//! which quarantines it and gives up on what it has not answered, as
//! wire::FAILED.  Nothing a driver writes says that it failed.
//!
//! The second page is the driver's to publish what root reads without
//! asking: blkd's disks (blk::Published), netd's counters (net::Published),
//! usbd's (usb::Published).

use core::sync::atomic::AtomicU64;

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
    pub args: [AtomicU64; ARGS],
    pub answer: [AtomicU64; ANSWER],
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


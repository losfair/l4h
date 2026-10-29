//! Completion badges used during host handoff. They live above component
//! IDs, whose low 16 bits identify the caller.

/// trustd's measurement completion on root's bound notification.
pub const MEASURE_DONE_BADGE: u64 = 1 << 42;
/// netd completed its host-handoff reset successfully.
pub const NETD_RESET_OK: u64 = 1 << 43;
/// netd failed to reset at least one uplink.
pub const NETD_RESET_ERROR: u64 = 1 << 44;

use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{fence, Ordering};

/// One outstanding request on a page root shares with a server: root posts
/// a body, the server answers it with a status. Each side writes only its
/// own sequence, after its payload. A completion left by an earlier request
/// has an older sequence, so it never answers the current one.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Mailbox<T: Copy> {
    request_seq: u32,
    response_seq: u32,
    status: u64,
    body: T,
}

impl<T: Copy> Mailbox<T> {
    /// Root: publish a request and return its sequence.
    ///
    /// # Safety
    /// `this` points to a mapped mailbox that only this caller posts to.
    pub unsafe fn post(this: *mut Self, body: T) -> u32 {
        unsafe {
            let seq = addr_of!((*this).request_seq).read_volatile().wrapping_add(1);
            addr_of_mut!((*this).body).write_volatile(body);
            addr_of_mut!((*this).status).write_volatile(0);
            fence(Ordering::Release);
            addr_of_mut!((*this).request_seq).write_volatile(seq);
            seq
        }
    }

    /// Root: the status of request `seq`, once the server answered it.
    ///
    /// # Safety
    /// `this` points to a mapped mailbox.
    pub unsafe fn answer(this: *const Self, seq: u32) -> Option<u64> {
        unsafe {
            if addr_of!((*this).response_seq).read_volatile() != seq {
                return None;
            }
            fence(Ordering::Acquire);
            Some(addr_of!((*this).status).read_volatile())
        }
    }

    /// Server: the unanswered request, if any.
    ///
    /// # Safety
    /// `this` points to a mapped mailbox that only this caller answers.
    pub unsafe fn pending(this: *const Self) -> Option<(u32, T)> {
        unsafe {
            let seq = addr_of!((*this).request_seq).read_volatile();
            if seq == addr_of!((*this).response_seq).read_volatile() {
                return None;
            }
            fence(Ordering::Acquire);
            Some((seq, addr_of!((*this).body).read_volatile()))
        }
    }

    /// Server: answer request `seq`.
    ///
    /// # Safety
    /// As for `pending`.
    pub unsafe fn complete(this: *mut Self, seq: u32, status: u64) {
        unsafe {
            addr_of_mut!((*this).status).write_volatile(status);
            fence(Ordering::Release);
            addr_of_mut!((*this).response_seq).write_volatile(seq);
        }
    }
}

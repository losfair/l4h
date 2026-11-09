//! The errnos of the host: their one definition.  A protocol's reply
//! carries one in its first word (crate::wire); the guest ABI's statuses
//! are their negatives (`negative`).

/// An errno: positive, as protocols carry it.
pub type Errno = u64;

pub const EPERM: Errno = 1;
pub const ENOENT: Errno = 2;
pub const ESRCH: Errno = 3;
pub const EIO: Errno = 5;
pub const EAGAIN: Errno = 11;
pub const ENOMEM: Errno = 12;
pub const EBUSY: Errno = 16;
pub const EEXIST: Errno = 17;
pub const ENODEV: Errno = 19;
pub const EINVAL: Errno = 22;
pub const ENOSPC: Errno = 28;
pub const ENOSYS: Errno = 38;
pub const ETIMEDOUT: Errno = 110;

/// A handler's 0 or errno as a result.
pub const fn check(e: Errno) -> Result<(), Errno> {
    if e == 0 { Ok(()) } else { Err(e) }
}

/// The guest ABI's status of an errno: its negative.
pub const fn negative(e: Errno) -> i64 {
    -(e as i64)
}

/// The errno of a guest ABI status (`negative`'s inverse; EIO for one that
/// is not negative).
pub const fn of_status(status: i64) -> Errno {
    if status < 0 { status.unsigned_abs() } else { EIO }
}

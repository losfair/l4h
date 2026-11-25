//! What l4h-hvm's threads share, and how (DESIGN.md §5.11).  Only vCPU
//! threads, all of one priority, take the locks here, for a few
//! instructions; the I/O thread, at a higher priority, never does: were
//! it to spin on a lock held by a vCPU thread it preempted on the same
//! core, neither would run.  It hands what needs a lock to vCPU 0 instead
//! (vm.rs).

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

pub struct SpinLock<T> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Sync for SpinLock<T> {}

impl<T> SpinLock<T> {
    pub const fn new(v: T) -> Self {
        SpinLock { locked: AtomicBool::new(false), data: UnsafeCell::new(v) }
    }

    pub fn lock(&self) -> Guard<'_, T> {
        let mut spins = 0u32;
        while self.locked.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            spins = spins.wrapping_add(1);
            // The holder may be off its core (preempted, or out of budget):
            // let a thread of our priority there run.
            if spins.is_multiple_of(1024) {
                crate::yield_now();
            } else {
                core::hint::spin_loop();
            }
        }
        Guard { lock: self }
    }
}

pub struct Guard<'a, T> {
    lock: &'a SpinLock<T>,
}

impl<T> Deref for Guard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> DerefMut for Guard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T> Drop for Guard<'_, T> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
    }
}

/// A value set once, by the I/O thread before it starts any vCPU thread,
/// and shared from then on.
pub struct Global<T>(UnsafeCell<MaybeUninit<T>>, AtomicBool);

unsafe impl<T: Sync> Sync for Global<T> {}

impl<T> Global<T> {
    pub const fn new() -> Self {
        Global(UnsafeCell::new(MaybeUninit::uninit()), AtomicBool::new(false))
    }

    /// Set it (once; before any other thread looks).
    pub fn set(&'static self, v: T) -> &'static T {
        assert!(!self.1.swap(true, Ordering::AcqRel), "set twice");
        unsafe { (*self.0.get()).write(v) }
    }

    /// Whether it has been set.
    #[cfg_attr(target_arch = "aarch64", allow(dead_code))] // x86-64's vCPU loop
    pub fn is_set(&'static self) -> bool {
        self.1.load(Ordering::Acquire)
    }

    pub fn get(&'static self) -> &'static T {
        debug_assert!(self.1.load(Ordering::Acquire));
        unsafe { (*self.0.get()).assume_init_ref() }
    }
}

/// State one thread owns, in a static (too large for its stack): the I/O
/// thread's devices.
pub struct Owned<T>(UnsafeCell<T>);

unsafe impl<T> Sync for Owned<T> {}

impl<T> Owned<T> {
    pub const fn new(v: T) -> Self {
        Owned(UnsafeCell::new(v))
    }

    /// # Safety
    /// Only its owner calls this, and holds one reference at a time.
    #[allow(clippy::mut_from_ref)]
    pub unsafe fn get(&self) -> &mut T {
        unsafe { &mut *self.0.get() }
    }
}

// ---- A vCPU thread's idle time, which vmmgr reads (its steal estimate).

use core::sync::atomic::{AtomicU64, fence};

/// idle_seq, idle_since and idle_ticks of an event page.
unsafe fn idle_fields<'a>(page: *mut l4h_abi::EventPage) -> (&'a AtomicU64, &'a AtomicU64, &'a AtomicU64) {
    unsafe {
        (&*(core::ptr::addr_of_mut!((*page).idle_seq) as *const AtomicU64),
            &*(core::ptr::addr_of_mut!((*page).idle_since) as *const AtomicU64),
            &*(core::ptr::addr_of_mut!((*page).idle_ticks) as *const AtomicU64))
    }
}

/// Change idle_since and idle_ticks under idle_seq (odd meanwhile), so
/// that vmmgr reads both from one moment (l4h-vmmgr's sched::idle_ticks).
fn idle_write(seq: &AtomicU64, f: impl FnOnce()) {
    seq.store(seq.load(Ordering::Relaxed).wrapping_add(1), Ordering::Relaxed);
    fence(Ordering::Release);
    f();
    seq.store(seq.load(Ordering::Relaxed).wrapping_add(1), Ordering::Release);
}

/// A block of the vCPU starts at `now` (EventPage::idle_since; never 0).
///
/// # Safety
/// `page` is the vCPU's event page, whose idle fields only its thread
/// writes.
pub unsafe fn idle_begin(page: *mut l4h_abi::EventPage, now: u64) {
    let (seq, since, _) = unsafe { idle_fields(page) };
    idle_write(seq, || since.store(now.max(1), Ordering::Relaxed));
}

/// The block ended after `blocked` ticks: counted in idle_ticks, and
/// idle_since cleared, together.
///
/// # Safety
/// As idle_begin.
pub unsafe fn idle_end(page: *mut l4h_abi::EventPage, blocked: u64) {
    let (seq, since, idle) = unsafe { idle_fields(page) };
    idle_write(seq, || {
        idle.store(idle.load(Ordering::Relaxed).wrapping_add(blocked), Ordering::Relaxed);
        since.store(0, Ordering::Relaxed);
    });
}

/// `f`, during which the vCPU is blocked (a call to the I/O thread): idle
/// as a wait is, timed by `now`.
///
/// # Safety
/// As idle_begin.
pub unsafe fn idle_during<T>(page: *mut l4h_abi::EventPage, now: impl Fn() -> u64, f: impl FnOnce() -> T) -> T {
    let before = now();
    unsafe { idle_begin(page, before) };
    let r = f();
    unsafe { idle_end(page, now().wrapping_sub(before)) };
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What vmmgr reads of a block (l4h-vmmgr's sched::idle_ticks):
    /// idle_since set while it lasts, never 0, idle_ticks updated as it
    /// is cleared, and idle_seq even between the changes.
    #[test]
    fn idle_since_brackets_a_block() {
        let mut page: std::boxed::Box<core::mem::MaybeUninit<l4h_abi::EventPage>> = std::boxed::Box::new_zeroed();
        let p = page.as_mut_ptr();
        let read = |p: *mut l4h_abi::EventPage| unsafe {
            (core::ptr::addr_of!((*p).idle_since).read(), core::ptr::addr_of!((*p).idle_ticks).read(),
                core::ptr::addr_of!((*p).idle_seq).read())
        };
        unsafe { idle_begin(p, 0) };
        assert_eq!(read(p), (1, 0, 2), "a block at counter 0 still reads as one");
        unsafe { idle_end(p, 500) };
        assert_eq!(read(p), (0, 500, 4));
        unsafe { idle_begin(p, 7_000) };
        assert_eq!(read(p), (7_000, 500, 6), "in progress: not yet in idle_ticks");
        unsafe { idle_end(p, 250) };
        assert_eq!(read(p), (0, 750, 8), "the count even between changes");
        // A call to the I/O thread is a block too, in progress while it lasts.
        let t = core::cell::Cell::new(10_000u64);
        let got = unsafe {
            idle_during(p, || t.get(), || {
                assert_eq!(read(p), (10_000, 750, 10), "in progress during the call");
                t.set(10_300);
                7
            })
        };
        assert_eq!((got, read(p)), (7, (0, 1_050, 12)));
    }
}

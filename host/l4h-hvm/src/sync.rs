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

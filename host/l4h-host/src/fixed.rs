//! Fixed-capacity containers for host components, which do not allocate
//! (DESIGN.md §10): their storage is inline, sized by a constant, and a
//! push beyond it fails instead of growing.

use core::mem::MaybeUninit;
use core::ops::{Deref, DerefMut};

/// A vector of at most N elements, stored inline.
pub struct ArrayVec<T, const N: usize> {
    len: usize,
    buf: [MaybeUninit<T>; N],
}

impl<T, const N: usize> ArrayVec<T, N> {
    pub const fn new() -> Self {
        ArrayVec { len: 0, buf: [const { MaybeUninit::uninit() }; N] }
    }

    pub const fn capacity(&self) -> usize {
        N
    }

    pub fn is_full(&self) -> bool {
        self.len == N
    }

    /// Append `v`, or give it back if full.
    pub fn push(&mut self, v: T) -> Result<(), T> {
        if self.len == N {
            return Err(v);
        }
        self.buf[self.len].write(v);
        self.len += 1;
        Ok(())
    }

    /// Append `v` where the caller has already checked that it fits (a
    /// bound checked on input); panics if not.
    pub fn must_push(&mut self, v: T) {
        assert!(self.len < N, "ArrayVec of {} full", N);
        self.buf[self.len].write(v);
        self.len += 1;
    }

    pub fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        self.len -= 1;
        Some(unsafe { self.buf[self.len].assume_init_read() })
    }

    /// Remove element `i`, replacing it with the last.
    pub fn swap_remove(&mut self, i: usize) -> T {
        assert!(i < self.len, "swap_remove index {} out of {}", i, self.len);
        let last = self.len - 1;
        self.buf.swap(i, last);
        self.len = last;
        unsafe { self.buf[last].assume_init_read() }
    }

    /// Remove element `i`, shifting the rest down.
    pub fn remove(&mut self, i: usize) -> T {
        assert!(i < self.len, "remove index {} out of {}", i, self.len);
        let p = self.buf.as_mut_ptr();
        let v = unsafe { self.buf[i].assume_init_read() };
        unsafe { core::ptr::copy(p.add(i + 1), p.add(i), self.len - i - 1) };
        self.len -= 1;
        v
    }

    /// Insert `v` at `i`, shifting the rest up, or give it back if full.
    pub fn insert(&mut self, i: usize, v: T) -> Result<(), T> {
        assert!(i <= self.len, "insert index {} out of {}", i, self.len);
        if self.len == N {
            return Err(v);
        }
        let p = self.buf.as_mut_ptr();
        unsafe { core::ptr::copy(p.add(i), p.add(i + 1), self.len - i) };
        self.buf[i].write(v);
        self.len += 1;
        Ok(())
    }

    /// Keep only the elements for which `f` is true, in order.
    pub fn retain(&mut self, mut f: impl FnMut(&T) -> bool) {
        // During compaction the initialized elements are a kept prefix
        // and an unprocessed tail.  Restore one contiguous slice even if
        // the predicate or an element's destructor panics.
        struct Backshift<'a, T, const N: usize> {
            vec: &'a mut ArrayVec<T, N>,
            len: usize,
            processed: usize,
            kept: usize,
        }

        impl<T, const N: usize> Drop for Backshift<'_, T, N> {
            fn drop(&mut self) {
                let tail = self.len - self.processed;
                if self.processed != self.kept {
                    let p = self.vec.buf.as_mut_ptr();
                    unsafe { core::ptr::copy(p.add(self.processed), p.add(self.kept), tail) };
                }
                self.vec.len = self.kept + tail;
            }
        }

        let len = core::mem::replace(&mut self.len, 0);
        let mut g = Backshift { vec: self, len, processed: 0, kept: 0 };
        while g.processed < len {
            let p = g.vec.buf.as_mut_ptr();
            if f(unsafe { &*p.add(g.processed).cast::<T>() }) {
                if g.processed != g.kept {
                    unsafe { core::ptr::copy_nonoverlapping(p.add(g.processed), p.add(g.kept), 1) };
                }
                g.kept += 1;
                g.processed += 1;
            } else {
                let i = g.processed;
                // Exclude it from the tail before Drop can panic.
                g.processed += 1;
                unsafe { core::ptr::drop_in_place(p.add(i).cast::<T>()) };
            }
        }
    }

    pub fn clear(&mut self) {
        while self.pop().is_some() {}
    }

    pub fn as_slice(&self) -> &[T] {
        unsafe { core::slice::from_raw_parts(self.buf.as_ptr() as *const T, self.len) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [T] {
        unsafe { core::slice::from_raw_parts_mut(self.buf.as_mut_ptr() as *mut T, self.len) }
    }
}

impl<T: Copy, const N: usize> ArrayVec<T, N> {
    /// Append all of `s`, or nothing if it does not fit.
    pub fn extend_from_slice(&mut self, s: &[T]) -> Result<(), ()> {
        if s.len() > N - self.len {
            return Err(());
        }
        for &v in s {
            self.buf[self.len].write(v);
            self.len += 1;
        }
        Ok(())
    }
}

/// Collects at most N elements; panics on more (for iterators a caller's
/// check keeps within capacity, like `must_push`).
impl<T, const N: usize> FromIterator<T> for ArrayVec<T, N> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let mut v = Self::new();
        for x in iter {
            v.must_push(x);
        }
        v
    }
}

impl<T, const N: usize> Default for ArrayVec<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const N: usize> Drop for ArrayVec<T, N> {
    fn drop(&mut self) {
        self.clear();
    }
}

impl<T: Clone, const N: usize> Clone for ArrayVec<T, N> {
    fn clone(&self) -> Self {
        let mut v = Self::new();
        for x in self.iter() {
            let _ = v.push(x.clone());
        }
        v
    }
}

impl<T: core::fmt::Debug, const N: usize> core::fmt::Debug for ArrayVec<T, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        self.as_slice().fmt(f)
    }
}

impl<T, const N: usize> Deref for ArrayVec<T, N> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        self.as_slice()
    }
}

impl<T, const N: usize> DerefMut for ArrayVec<T, N> {
    fn deref_mut(&mut self) -> &mut [T] {
        self.as_mut_slice()
    }
}

impl<'a, T, const N: usize> IntoIterator for &'a ArrayVec<T, N> {
    type Item = &'a T;
    type IntoIter = core::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a, T, const N: usize> IntoIterator for &'a mut ArrayVec<T, N> {
    type Item = &'a mut T;
    type IntoIter = core::slice::IterMut<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}

/// A string of at most N bytes, stored inline.
#[derive(Clone, Copy)]
pub struct ArrayString<const N: usize> {
    len: usize,
    buf: [u8; N],
}

impl<const N: usize> ArrayString<N> {
    pub const fn new() -> Self {
        ArrayString { len: 0, buf: [0; N] }
    }

    /// `s`, cut at a character boundary to fit.
    pub fn from_str_truncate(s: &str) -> Self {
        let mut a = Self::new();
        let _ = a.push_str_truncate(s);
        a
    }

    /// Append as much of `s` as fits, cut at a character boundary;
    /// whether all of it did.
    pub fn push_str_truncate(&mut self, s: &str) -> bool {
        let mut n = s.len().min(N - self.len);
        while !s.is_char_boundary(n) {
            n -= 1;
        }
        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        n == s.len()
    }

    pub fn clear(&mut self) {
        self.len = 0;
    }

    pub fn as_str(&self) -> &str {
        // Only whole characters are ever appended.
        unsafe { core::str::from_utf8_unchecked(&self.buf[..self.len]) }
    }
}

impl<const N: usize> Default for ArrayString<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Deref for ArrayString<N> {
    type Target = str;

    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl<const N: usize> core::fmt::Write for ArrayString<N> {
    /// Fails (keeping what fits) when full.
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        if self.push_str_truncate(s) { Ok(()) } else { Err(core::fmt::Error) }
    }
}

impl<const N: usize> core::fmt::Display for ArrayString<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl<const N: usize> core::fmt::Debug for ArrayString<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        core::fmt::Debug::fmt(self.as_str(), f)
    }
}

/// A static that is handed out once, as `&'static mut`: for state too
/// large for a stack, in a single-threaded component.
pub struct StaticCell<T> {
    taken: core::sync::atomic::AtomicBool,
    value: core::cell::UnsafeCell<T>,
}

// Only one `&mut` is ever handed out (`take`). It may be handed to a
// different thread, which requires T: Send.
unsafe impl<T: Send> Sync for StaticCell<T> {}

impl<T> StaticCell<T> {
    pub const fn new(value: T) -> Self {
        StaticCell { taken: core::sync::atomic::AtomicBool::new(false), value: core::cell::UnsafeCell::new(value) }
    }

    /// The value; panics if it was taken before.
    pub fn take(&'static self) -> &'static mut T {
        assert!(!self.taken.swap(true, core::sync::atomic::Ordering::AcqRel), "static taken twice");
        unsafe { &mut *self.value.get() }
    }
}

/// A static buffer lent out for the length of a call (`with`): scratch
/// space too large for a stack, such as a structure built before it is
/// copied out, in a single-threaded component.
pub struct Scratch<T> {
    busy: core::sync::atomic::AtomicBool,
    value: core::cell::UnsafeCell<T>,
}

// Only one `&mut` is lent at a time (`with`). Successive calls may run on
// different threads, which requires T: Send.
unsafe impl<T: Send> Sync for Scratch<T> {}

impl<T> Scratch<T> {
    pub const fn new(value: T) -> Self {
        Scratch { busy: core::sync::atomic::AtomicBool::new(false), value: core::cell::UnsafeCell::new(value) }
    }

    /// Run `f` on the buffer, as left by the last call; panics if called
    /// from inside `f`.
    pub fn with<R>(&'static self, f: impl FnOnce(&mut T) -> R) -> R {
        assert!(!self.busy.swap(true, core::sync::atomic::Ordering::AcqRel), "scratch in use");
        let r = f(unsafe { &mut *self.value.get() });
        self.busy.store(false, core::sync::atomic::Ordering::Release);
        r
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::cell::Cell;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use super::*;

    #[test]
    fn storage_cells_require_send_for_sync() {
        fn assert_sync<T: Sync>() {}
        // Cell is Send but not Sync: exclusive access is sufficient.
        assert_sync::<StaticCell<Cell<usize>>>();
        assert_sync::<Scratch<Cell<usize>>>();

        // If either type becomes Sync for a non-Send value, inference
        // becomes ambiguous between the two implementations and this
        // test no longer compiles.
        trait AmbiguousIfSync<A> {
            fn check() {}
        }
        struct IsSync;
        impl<T: ?Sized> AmbiguousIfSync<()> for T {}
        impl<T: ?Sized + Sync> AmbiguousIfSync<IsSync> for T {}
        let _ = <StaticCell<std::rc::Rc<Cell<usize>>> as AmbiguousIfSync<_>>::check;
        let _ = <Scratch<std::rc::Rc<Cell<usize>>> as AmbiguousIfSync<_>>::check;
    }

    struct Tracked<'a> {
        id: usize,
        drops: &'a [Cell<usize>],
        panic_on_drop: bool,
    }

    impl Drop for Tracked<'_> {
        fn drop(&mut self) {
            let n = self.drops[self.id].get();
            self.drops[self.id].set(n + 1);
            if self.panic_on_drop && n == 0 {
                panic!("element destructor");
            }
        }
    }

    #[test]
    fn retain_predicate_panic_preserves_remaining_elements() {
        // Panic at every position, then also finish normally.
        for panic_at in 0..=6 {
            let drops = [const { Cell::new(0) }; 6];
            let mut v = ArrayVec::<_, 6>::new();
            for id in 0..6 {
                v.must_push(Tracked { id, drops: &drops, panic_on_drop: false });
            }
            let result = catch_unwind(AssertUnwindSafe(|| {
                v.retain(|x| {
                    assert_ne!(x.id, panic_at, "predicate");
                    x.id % 2 == 1
                });
            }));
            assert_eq!(result.is_err(), panic_at < 6);
            let expected = (0..6).filter(|&i| i >= panic_at || i % 2 == 1);
            assert!(v.iter().map(|x| x.id).eq(expected));
            for (id, count) in drops.iter().enumerate() {
                assert_eq!(count.get(), usize::from(id < panic_at && id % 2 == 0));
            }
            drop(v);
            assert!(drops.iter().all(|n| n.get() == 1));
        }
    }

    #[test]
    fn retain_destructor_panic_does_not_drop_rejected_element_again() {
        let drops = [const { Cell::new(0) }; 6];
        let mut v = ArrayVec::<_, 6>::new();
        for id in 0..6 {
            v.must_push(Tracked { id, drops: &drops, panic_on_drop: id == 3 });
        }
        let result = catch_unwind(AssertUnwindSafe(|| v.retain(|x| x.id % 2 == 0)));
        assert!(result.is_err());
        assert!(v.iter().map(|x| x.id).eq([0, 2, 4, 5]));
        drop(v);
        assert!(drops.iter().all(|n| n.get() == 1));
    }

    #[test]
    fn array_vec() {
        let mut v: ArrayVec<u32, 3> = ArrayVec::new();
        assert!(v.push(1).is_ok() && v.push(2).is_ok() && v.push(3).is_ok());
        assert_eq!(v.push(4), Err(4));
        assert_eq!(v.remove(0), 1);
        assert_eq!(&v[..], &[2, 3]);
        assert!(v.insert(0, 9).is_ok());
        assert_eq!(&v[..], &[9, 2, 3]);
        v.retain(|&x| x != 2);
        assert_eq!(&v[..], &[9, 3]);
        assert_eq!(v.swap_remove(0), 9);
        assert_eq!(&v[..], &[3]);
        assert_eq!(v.extend_from_slice(&[1, 2, 3]), Err(()));
        assert_eq!(v.extend_from_slice(&[1, 2]), Ok(()));
        assert_eq!(&v[..], &[3, 1, 2]);
    }

    #[test]
    fn array_string() {
        use core::fmt::Write;
        let mut s: ArrayString<4> = ArrayString::new();
        assert!(write!(s, "ab").is_ok());
        assert!(write!(s, "cé").is_err());
        assert_eq!(s.as_str(), "abc");
    }
}

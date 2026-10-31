//! CPU access to validated, snapshotted scatter/gather requests. Raw
//! pointers, never Rust slices into memory a guest can concurrently write.
use crate::{Seg, crypt::{self, Xts}};

pub struct Data<'a> { pub segs: &'a [Seg], pub pool_pa: u64, pub pool_va: usize }
impl Data<'_> {
    fn ptr(&self, i: usize, off: usize) -> *mut u8 {
        (self.pool_va + (self.segs[i].pa - self.pool_pa) as usize + off) as *mut u8
    }

    /// The validated segments address mapped pool memory. `dst` is a
    /// disjoint bounce run large enough for the entire request.
    pub unsafe fn copy_to(&self, mut dst: *mut u8) {
        for (i, s) in self.segs.iter().enumerate() {
            unsafe { core::ptr::copy_nonoverlapping(self.ptr(i, 0), dst, s.len as usize); dst = dst.add(s.len as usize); }
        }
    }

    /// Encrypt to a bounce run, or decrypt in place (dst=None). AES is
    /// available and the total length is a multiple of 4096. Segments may
    /// split a unit at ANY byte; the wire format does not align them.
    pub unsafe fn crypt(&self, keys: &Xts, mut unit: u64, dst: Option<*mut u8>) {
        let (mut seg, mut off, mut output) = (0, 0, 0);
        let mut scratch = [0u8; crypt::UNIT];
        while seg < self.segs.len() {
            let src = self.ptr(seg, off);
            if self.segs[seg].len as usize - off >= crypt::UNIT {
                unsafe {
                    match dst {
                        Some(dst) => keys.encrypt(src, dst.add(output), unit),
                        None => keys.decrypt(src, src, unit),
                    }
                }
                off += crypt::UNIT;
                if off == self.segs[seg].len as usize { seg += 1; off = 0; }
            } else {
                let (start_seg, start_off) = (seg, off);
                let mut n = 0;
                while n < crypt::UNIT {
                    let len = (crypt::UNIT - n).min(self.segs[seg].len as usize - off);
                    unsafe { core::ptr::copy_nonoverlapping(self.ptr(seg, off), scratch.as_mut_ptr().add(n), len); }
                    n += len; off += len;
                    if off == self.segs[seg].len as usize { seg += 1; off = 0; }
                }
                unsafe {
                    match dst {
                        Some(dst) => keys.encrypt(scratch.as_ptr(), dst.add(output), unit),
                        None => {
                            keys.decrypt(scratch.as_ptr(), scratch.as_mut_ptr(), unit);
                            let (mut s, mut o, mut n) = (start_seg, start_off, 0);
                            while n < crypt::UNIT {
                                let len = (crypt::UNIT - n).min(self.segs[s].len as usize - o);
                                core::ptr::copy_nonoverlapping(scratch.as_ptr().add(n), self.ptr(s, o), len);
                                n += len; s += 1; o = 0;
                            }
                        }
                    }
                }
            }
            output += crypt::UNIT;
            unit = unit.wrapping_add(1);
        }
        crate::wipe::bytes(&mut scratch);
    }
}

//! AES-256-XTS with 4096-byte units and window-relative, little-endian
//! unit numbers. Hardware AES only; callers check root's FEATURE_AES.
//! No key-dependent table lookups, and no vector values in the x86 ABI.

#[cfg(target_arch = "x86_64")]
#[path = "crypt/x86.rs"]
mod backend;
#[cfg(target_arch = "aarch64")]
#[path = "crypt/arm.rs"]
mod backend;

pub const UNIT: usize = 4096;
pub const BACKEND: &str = if cfg!(target_arch = "x86_64") { "aes-ni" } else { "armv8-ce" };

#[repr(C, align(16))]
pub struct Xts {
    enc: [[u8; 16]; 15],
    dec: [[u8; 16]; 15],
    tweak: [[u8; 16]; 15],
}

impl Xts {
    pub const fn empty() -> Self { Self { enc: [[0; 16]; 15], dec: [[0; 16]; 15], tweak: [[0; 16]; 15] } }

    /// CPU must implement AES. Initialize in its final location so expanded
    /// keys need not be moved through temporary stack records.
    pub unsafe fn init(&mut self, key: &[u8; 64]) {
        unsafe {
            backend::expand(key.as_ptr(), self.enc.as_mut_ptr().cast(), self.dec.as_mut_ptr().cast());
            backend::expand(key.as_ptr().add(32), self.tweak.as_mut_ptr().cast(), core::ptr::null_mut());
        }
    }

    /// Constant-time comparison for overlapping read-only attachments.
    pub fn same_key(&self, other: &Self) -> bool {
        let mut diff = 0u8;
        for (a, b) in self.enc.iter().flatten().zip(other.enc.iter().flatten()) { diff |= a ^ b; }
        for (a, b) in self.tweak.iter().flatten().zip(other.tweak.iter().flatten()) { diff |= a ^ b; }
        diff == 0
    }

    /// src and dst address 4096 bytes, either disjoint or identical. CPU
    /// must implement AES. Raw pointers allow the guest to race its pool;
    /// no Rust reference to guest-owned data is formed.
    pub unsafe fn encrypt(&self, src: *const u8, dst: *mut u8, unit: u64) {
        unsafe { backend::encrypt(self.enc.as_ptr().cast(), self.tweak.as_ptr().cast(), src, dst, unit); }
    }

    /// The same bounds and feature requirements as encrypt.
    pub unsafe fn decrypt(&self, src: *const u8, dst: *mut u8, unit: u64) {
        unsafe { backend::decrypt(self.dec.as_ptr().cast(), self.tweak.as_ptr().cast(), src, dst, unit); }
    }

    pub fn clear(&mut self) {
        for keys in [&mut self.enc, &mut self.dec, &mut self.tweak] {
            for byte in keys.iter_mut().flatten() { unsafe { core::ptr::write_volatile(byte, 0); } }
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl Drop for Xts { fn drop(&mut self) { self.clear(); } }

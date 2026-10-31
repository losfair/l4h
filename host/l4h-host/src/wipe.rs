//! Erase explicit secret buffers with volatile stores and a compiler barrier.
//! This does not erase compiler-generated copies or register/stack spills.

/// Erase a private byte buffer.
pub fn bytes(data: &mut [u8]) {
    unsafe { raw(data.as_mut_ptr(), data.len()); }
}

/// Erase a private word buffer, including IPC message registers.
pub fn words(data: &mut [u64]) {
    unsafe { raw(data.as_mut_ptr().cast(), core::mem::size_of_val(data)); }
}

/// Erase shared memory without creating a Rust reference to it.
///
/// # Safety
/// `data` must address `len` writable bytes for the duration of the call.
pub unsafe fn raw(data: *mut u8, len: usize) {
    let prefix = data.align_offset(core::mem::align_of::<u64>()).min(len);
    let end = prefix + (len - prefix) / 8 * 8;
    unsafe {
        for i in 0..prefix { data.add(i).write_volatile(0); }
        for i in (prefix..end).step_by(8) { data.add(i).cast::<u64>().write_volatile(0); }
        for i in end..len { data.add(i).write_volatile(0); }
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    #[test]
    fn unaligned_wipes_preserve_adjacent_bytes() {
        // Exercise every alignment, partial word, and zero-length range.
        for start in 0..16 {
            for len in 0..48 {
                let mut buf = [0x5a; 64];
                super::bytes(&mut buf[start..start + len]);
                assert!(buf[..start].iter().all(|&b| b == 0x5a));
                assert!(buf[start..start + len].iter().all(|&b| b == 0));
                assert!(buf[start + len..].iter().all(|&b| b == 0x5a));
            }
        }
    }
}

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
    for i in 0..len { unsafe { data.add(i).write_volatile(0); } }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

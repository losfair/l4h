//! Hardware backends cross-checked against OpenSSL's EVP XTS implementation.
//! `openssl enc` does not support XTS; the EVP API does.
#![allow(dead_code)]
#[path = "../host/l4h-host/src/wipe.rs"]
mod wipe;
#[path = "../host/l4h-host/src/blk.rs"]
mod blk;
#[path = "../host/l4h-blkd/src/crypt.rs"]
mod crypt;

#[cfg(target_arch = "x86_64")]
#[link(name = "crypto")]
unsafe extern "C" {
    fn EVP_CIPHER_CTX_new() -> *mut core::ffi::c_void;
    fn EVP_CIPHER_CTX_free(ctx: *mut core::ffi::c_void);
    fn EVP_aes_256_xts() -> *const core::ffi::c_void;
    fn EVP_EncryptInit_ex(ctx: *mut core::ffi::c_void, cipher: *const core::ffi::c_void, engine: *mut core::ffi::c_void,
        key: *const u8, iv: *const u8) -> i32;
    fn EVP_EncryptUpdate(ctx: *mut core::ffi::c_void, out: *mut u8, len: *mut i32, src: *const u8, size: i32) -> i32;
    fn EVP_EncryptFinal_ex(ctx: *mut core::ffi::c_void, out: *mut u8, len: *mut i32) -> i32;
}
fn available() -> bool {
    #[cfg(target_arch = "x86_64")]
    let yes = std::is_x86_feature_detected!("aes");
    #[cfg(target_arch = "aarch64")]
    let yes = std::arch::is_aarch64_feature_detected!("aes");
    if !yes { eprintln!("SKIP: CPU has no hardware AES"); }
    yes
}
#[cfg(target_arch = "x86_64")]
fn openssl(key: &[u8; 64], index: u64, data: &[u8]) -> Vec<u8> {
    let mut out = vec![0; data.len() + 16];
    unsafe {
        let ctx = EVP_CIPHER_CTX_new();
        assert!(!ctx.is_null());
        assert_eq!(EVP_EncryptInit_ex(ctx, EVP_aes_256_xts(), core::ptr::null_mut(), key.as_ptr(), (index as u128).to_le_bytes().as_ptr()), 1);
        let mut len = 0;
        assert_eq!(EVP_EncryptUpdate(ctx, out.as_mut_ptr(), &mut len, data.as_ptr(), data.len() as i32), 1);
        assert_eq!(len as usize, data.len());
        assert_eq!(EVP_EncryptFinal_ex(ctx, out.as_mut_ptr().add(len as usize), &mut len), 1);
        assert_eq!(len, 0);
        EVP_CIPHER_CTX_free(ctx);
    }
    out.truncate(data.len()); out
}
#[cfg(target_arch = "x86_64")]
fn check(key: &[u8; 64], index: u64, data: &[u8; 4096]) {
    let mut k = crypt::Xts::empty();
    let mut out = [0; 4096];
    unsafe { k.init(key); k.encrypt(data.as_ptr(), out.as_mut_ptr(), index); }
    assert_eq!(out.as_slice(), openssl(key, index, data), "unit {index}");
    unsafe { k.decrypt(out.as_ptr(), out.as_mut_ptr(), index); }
    assert_eq!(&out, data);
    unsafe { k.encrypt(out.as_ptr(), out.as_mut_ptr(), index); }
    assert_eq!(out.as_slice(), openssl(key, index, data));
    unsafe { k.decrypt(out.as_ptr(), out.as_mut_ptr(), index); }
    assert_eq!(&out, data);
}
#[cfg(target_arch = "x86_64")]
#[test]
fn random_units_match_openssl_and_round_trip() {
    if !available() { return; }
    let mut state = 0x590afcf34u64;
    let mut random = || { state ^= state << 13; state ^= state >> 7; state ^= state << 17; state as u8 };
    for index in [0, 1, 8, 255, 256, 65535, 1 << 32, 0x1234_5678_abcd_ef01, u64::MAX] {
        for _ in 0..8 {
            let key = core::array::from_fn(|_| random());
            let data = core::array::from_fn(|_| random());
            check(&key, index, &data);
        }
    }
}
#[test]
fn clear_erases_all_720_bytes() {
    if !available() { return; }
    let mut k = crypt::Xts::empty();
    unsafe { k.init(&core::array::from_fn(|i| i as u8)); }
    assert_eq!(core::mem::size_of_val(&k), 720);
    k.clear();
    let bytes = unsafe { core::slice::from_raw_parts((&k as *const crypt::Xts).cast::<u8>(), 720) };
    assert!(bytes.iter().all(|&b| b == 0));
}

#[path = "blk-crypt-vectors.rs"]
mod vectors;
fn unhex(s: &str) -> Vec<u8> { (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2], 16).unwrap()).collect() }
#[test]
fn ieee_1619_aes256_vectors() {
    if !available() { return; }
    for &(key, index, plain, cipher) in vectors::VECTORS {
        let mut keys = crypt::Xts::empty();
        let mut input = [0; 4096];
        let mut output = [0; 4096];
        let plain = unhex(plain);
        input[..plain.len()].copy_from_slice(&plain);
        // Whole-block XTS prefixes are independent of the data-unit length.
        unsafe { keys.init(&unhex(key).try_into().unwrap()); keys.encrypt(input.as_ptr(), output.as_mut_ptr(), index); }
        assert_eq!(&output[..plain.len()], unhex(cipher), "unit {index}");
        unsafe { keys.decrypt(output.as_ptr(), output.as_mut_ptr(), index); }
        assert_eq!(output, input);
    }
}

#[derive(Clone, Copy)]
pub struct Seg { pub pa: u64, pub len: u32 }
#[path = "../host/l4h-blkd/src/data.rs"]
mod data;
#[path = "../host/l4h-blkd/src/bounce.rs"]
mod bounce;

#[test]
fn scatter_units_and_guest_write_races() {
    if !available() { return; }
    let mut keys = crypt::Xts::empty();
    unsafe { keys.init(&core::array::from_fn(|i| i as u8)); }
    let plain: Vec<u8> = (0..3 * 4096).map(|i| (i * 7 + i / 29) as u8).collect();
    for lengths in [vec![4096, 8192], vec![1, 4094, 2, 8191], vec![512, 8192, 3584], vec![4097, 8191]] {
        let mut pool = vec![0xcc; 16 * 4096];
        let mut segs = Vec::new();
        let mut n = 0;
        for (i, len) in lengths.into_iter().enumerate() {
            let start = i * 12288 + 13; // Deliberately unaligned, with gaps.
            pool[start..start + len].copy_from_slice(&plain[n..n + len]);
            segs.push(Seg { pa: start as u64, len: len as u32 });
            n += len;
        }
        let before = pool.clone();
        let scatter = data::Data { segs: &segs, pool_pa: 0, pool_va: pool.as_mut_ptr() as usize };
        let mut ciphertext = vec![0; plain.len()];
        unsafe { scatter.crypt(&keys, 91, Some(ciphertext.as_mut_ptr())); }
        assert_eq!(pool, before, "encrypt must not change the guest buffer");
        for i in 0..3 {
            let mut expected = [0; 4096];
            unsafe { keys.encrypt(plain.as_ptr().add(i * 4096), expected.as_mut_ptr(), 91 + i as u64); }
            assert_eq!(&ciphertext[i * 4096..(i+1)*4096], expected);
        }
        let mut snapshot = vec![0; plain.len()];
        unsafe { scatter.copy_to(snapshot.as_mut_ptr()); }
        pool.fill(0xff); // Guest rewrites after submit, before device DMA.
        assert_eq!(snapshot, plain);
        // Simulate read DMA to the original scattered segments.
        let mut n = 0;
        for s in &segs {
            pool[s.pa as usize..s.pa as usize + s.len as usize].copy_from_slice(&ciphertext[n..n + s.len as usize]);
            n += s.len as usize;
        }
        unsafe { scatter.crypt(&keys, 91, None); scatter.copy_to(snapshot.as_mut_ptr()); }
        assert_eq!(snapshot, plain);
    }
}

#[test]
fn bounce_exhaustion_fragmentation_and_completion_reuse() {
    let mut b = bounce::Bounce::new();
    assert!(b.alloc(0).is_none());
    assert!(b.alloc(bounce::SIZE + 1).is_none());
    let large = b.alloc(14 * 256 * 1024).unwrap();
    let small = b.alloc(512 * 1024).unwrap();
    assert!(b.alloc(512).is_none());
    b.free(large);
    assert_eq!(b.alloc(14 * 256 * 1024), Some(large));
    b.free(large); b.free(small);
    let runs: Vec<_> = (0..4).map(|_| b.alloc(1 << 20).unwrap()).collect();
    b.free(runs[0]); b.free(runs[2]);
    assert!(b.alloc(2 << 20).is_none()); // Free space must be contiguous.
    b.free(runs[1]);
    assert_eq!(b.alloc(3 << 20).unwrap().offset(), 0);
    b.free(runs[3]);
}

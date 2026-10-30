//! ARMv8 Crypto Extensions. The host target enables NEON; AES is checked
//! by root before any of these target-feature functions may run.
use core::arch::aarch64::*;

// Keep the scrub inside a non-inlined leaf. Its epilogue restores only
// the caller's preserved values, never this function's intermediate data.
// All caller-saved GP/SIMD registers and the high halves of v8-v15 are
// cleared. Clobbers tell LLVM to preserve the AAPCS64 callee-saved halves.
macro_rules! clear_registers {
    ($($v:tt),*; $($x:tt),*) => {
        core::arch::asm!(
            $(concat!("movi ", $v, ".16b, #0"),)*
            $(concat!("mov ", $x, ", xzr"),)*
            $(out($v) _,)* $(out($x) _,)*
            options(nostack, preserves_flags));
    };
}
#[inline(always)]
unsafe fn scrub_registers() {
    unsafe { clear_registers!("v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7",
        "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15",
        "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23",
        "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31";
        "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
        "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17"); }
}

#[inline(never)]
#[target_feature(enable = "aes")]
pub unsafe extern "C" fn expand(key: *const u8, enc: *mut u8, dec: *mut u8) {
    unsafe {
        core::ptr::copy_nonoverlapping(key, enc, 32);
        let mut rc = 1u32;
        let mut word = [0u32; 1];
        let mut v = [vdupq_n_u8(0); 1];
        for i in 8..60 {
            word[0] = enc.add(4 * (i - 1)).cast::<u32>().read_unaligned();
            if i % 8 == 0 { word[0] = word[0].rotate_right(8); }
            if i % 8 == 0 || i % 8 == 4 {
                // Identical columns make ShiftRows a no-op: AESE with a
                // zero round key computes SubWord without a lookup table.
                v[0] = vaeseq_u8(vreinterpretq_u8_u32(vdupq_n_u32(word[0])), vdupq_n_u8(0));
                word[0] = vgetq_lane_u32::<0>(vreinterpretq_u32_u8(v[0]));
            }
            if i % 8 == 0 { word[0] ^= rc; rc <<= 1; }
            word[0] ^= enc.add(4 * (i - 8)).cast::<u32>().read_unaligned();
            enc.add(4 * i).cast::<u32>().write_unaligned(word[0]);
        }
        if !dec.is_null() {
            vst1q_u8(dec, vld1q_u8(enc.add(224)));
            for i in 1..14 { vst1q_u8(dec.add(i * 16), vaesimcq_u8(vld1q_u8(enc.add((14 - i) * 16)))); }
            vst1q_u8(dec.add(224), vld1q_u8(enc));
        }
        core::ptr::write_volatile(&mut word[0], 0);
        core::ptr::write_volatile(&mut v[0], vdupq_n_u8(0));
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        scrub_registers();
    }
}

#[inline(never)]
#[target_feature(enable = "aes")]
unsafe fn unit<const DECRYPT: bool>(keys: *const u8, tweak: *const u8, src: *const u8, dst: *mut u8, index: u64) {
    unsafe {
        let mut t = vreinterpretq_u8_u64(vsetq_lane_u64::<1>(0, vdupq_n_u64(index)));
        for r in 0..13 { t = vaesmcq_u8(vaeseq_u8(t, vld1q_u8(tweak.add(r * 16)))); }
        t = veorq_u8(vaeseq_u8(t, vld1q_u8(tweak.add(208))), vld1q_u8(tweak.add(224)));
        let mut ts = [vdupq_n_u8(0); 8];
        let mut blocks = [vdupq_n_u8(0); 8];
        let mut round = [vdupq_n_u8(0); 2];
        for batch in 0..32 {
            for i in 0..8 {
                ts[i] = t;
                // Multiply the little-endian tweak by alpha entirely in
                // NEON, without untracked to_le_bytes() stack temporaries.
                let x = vreinterpretq_u64_u8(t);
                let carry = vshrq_n_u64::<63>(x);
                let carry = vextq_u64::<1>(carry, carry);
                let mask = vsetq_lane_u64::<1>(1, vdupq_n_u64(0x87));
                t = vreinterpretq_u8_u64(veorq_u64(vshlq_n_u64::<1>(x),
                    vandq_u64(vsubq_u64(vdupq_n_u64(0), carry), mask)));
                blocks[i] = veorq_u8(vld1q_u8(src.add(batch * 128 + i * 16)), ts[i]);
            }
            for r in 0..13 {
                round[0] = vld1q_u8(keys.add(r * 16));
                for b in &mut blocks {
                    *b = if DECRYPT { vaesimcq_u8(vaesdq_u8(*b, round[0])) } else { vaesmcq_u8(vaeseq_u8(*b, round[0])) };
                }
            }
            round[0] = vld1q_u8(keys.add(208));
            round[1] = vld1q_u8(keys.add(224));
            for i in 0..8 {
                let b = if DECRYPT { vaesdq_u8(blocks[i], round[0]) } else { vaeseq_u8(blocks[i], round[0]) };
                vst1q_u8(dst.add(batch * 128 + i * 16), veorq_u8(veorq_u8(b, round[1]), ts[i]));
            }
        }
        // These clears cover named scratch, not compiler-generated spills.
        for v in ts.iter_mut().chain(&mut blocks).chain(&mut round).chain(core::iter::once(&mut t)) {
            core::ptr::write_volatile(v, vdupq_n_u8(0));
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        scrub_registers();
    }
}

#[target_feature(enable = "aes")]
pub unsafe extern "C" fn encrypt(keys: *const u8, tweak: *const u8, src: *const u8, dst: *mut u8, index: u64) {
    unsafe { unit::<false>(keys, tweak, src, dst, index); }
}
#[target_feature(enable = "aes")]
pub unsafe extern "C" fn decrypt(keys: *const u8, tweak: *const u8, src: *const u8, dst: *mut u8, index: u64) {
    unsafe { unit::<true>(keys, tweak, src, dst, index); }
}

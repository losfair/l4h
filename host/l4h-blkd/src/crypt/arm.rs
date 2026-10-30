//! ARMv8 Crypto Extensions. The host target enables NEON; AES is checked
//! by root before any of these target-feature functions may run.
use core::arch::aarch64::*;

#[target_feature(enable = "aes")]
pub unsafe fn expand(key: *const u8, enc: *mut u8, dec: *mut u8) {
    unsafe {
        core::ptr::copy_nonoverlapping(key, enc, 32);
        let mut rc = 1u32;
        for i in 8..60 {
            let mut word = enc.add(4 * (i - 1)).cast::<u32>().read_unaligned();
            if i % 8 == 0 { word = word.rotate_right(8); }
            if i % 8 == 0 || i % 8 == 4 {
                // Identical columns make ShiftRows a no-op: AESE with a
                // zero round key computes SubWord without a lookup table.
                let v = vaeseq_u8(vreinterpretq_u8_u32(vdupq_n_u32(word)), vdupq_n_u8(0));
                word = vgetq_lane_u32::<0>(vreinterpretq_u32_u8(v));
            }
            if i % 8 == 0 { word ^= rc; rc <<= 1; }
            word ^= enc.add(4 * (i - 8)).cast::<u32>().read_unaligned();
            enc.add(4 * i).cast::<u32>().write_unaligned(word);
        }
        if !dec.is_null() {
            vst1q_u8(dec, vld1q_u8(enc.add(224)));
            for i in 1..14 { vst1q_u8(dec.add(i * 16), vaesimcq_u8(vld1q_u8(enc.add((14 - i) * 16)))); }
            vst1q_u8(dec.add(224), vld1q_u8(enc));
        }
    }
}

#[target_feature(enable = "aes")]
unsafe fn unit<const DECRYPT: bool>(keys: *const u8, tweak: *const u8, src: *const u8, dst: *mut u8, index: u64) {
    unsafe {
        let mut t = vld1q_u8((index as u128).to_le_bytes().as_ptr());
        for r in 0..13 { t = vaesmcq_u8(vaeseq_u8(t, vld1q_u8(tweak.add(r * 16)))); }
        t = veorq_u8(vaeseq_u8(t, vld1q_u8(tweak.add(208))), vld1q_u8(tweak.add(224)));
        let mut tb = [0u8; 16];
        vst1q_u8(tb.as_mut_ptr(), t);
        let mut value = u128::from_le_bytes(tb);
        for batch in 0..32 {
            let mut ts = [vdupq_n_u8(0); 8];
            let mut blocks = [vdupq_n_u8(0); 8];
            for i in 0..8 {
                ts[i] = vld1q_u8(value.to_le_bytes().as_ptr());
                value = (value << 1) ^ (0x87 & 0u128.wrapping_sub(value >> 127));
                blocks[i] = veorq_u8(vld1q_u8(src.add(batch * 128 + i * 16)), ts[i]);
            }
            for r in 0..13 {
                let k = vld1q_u8(keys.add(r * 16));
                for b in &mut blocks {
                    *b = if DECRYPT { vaesimcq_u8(vaesdq_u8(*b, k)) } else { vaesmcq_u8(vaeseq_u8(*b, k)) };
                }
            }
            let k13 = vld1q_u8(keys.add(208));
            let k14 = vld1q_u8(keys.add(224));
            for i in 0..8 {
                let b = if DECRYPT { vaesdq_u8(blocks[i], k13) } else { vaeseq_u8(blocks[i], k13) };
                vst1q_u8(dst.add(batch * 128 + i * 16), veorq_u8(veorq_u8(b, k14), ts[i]));
            }
        }
    }
}

#[target_feature(enable = "aes")]
pub unsafe fn encrypt(keys: *const u8, tweak: *const u8, src: *const u8, dst: *mut u8, index: u64) {
    unsafe { unit::<false>(keys, tweak, src, dst, index); }
}
#[target_feature(enable = "aes")]
pub unsafe fn decrypt(keys: *const u8, tweak: *const u8, src: *const u8, dst: *mut u8, index: u64) {
    unsafe { unit::<true>(keys, tweak, src, dst, index); }
}

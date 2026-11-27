//! trustd's key material, free of seL4 dependencies so that
//! tests/trustd-key compiles it unchanged: another partition's key
//! (trust::RELAY_KEY), which the primary quotes and extends into PCR 15,
//! and the seed of the host key it makes from the TPM's randomness.

use core::sync::atomic::{Ordering, compiler_fence};
use sha2::{Digest, Sha256};

/// Whether `point` is a key a verifier could use: a point the TPM quote
/// then binds for good (PCR 15 only moves forward), so never one that is
/// not on the curve.
pub fn partition_key_ok(point: &[u8; 65]) -> bool {
    point[0] == 4 && p256::PublicKey::from_sec1_bytes(point).is_ok()
}

/// Domain of the host key's seed, mixed from the TPM's and the CPU's
/// randomness.
pub const KEY_SEED_DOMAIN: &[u8] = b"l4h-trustd-rng-v1";

/// The host key's seed: `SHA-256("l4h-trustd-rng-v1" ‖ tpm ‖ cpu)`, so
/// that it is unpredictable while either source is (a TPM whose
/// TPM2_GetRandom answers are known, or bus traffic read or replaced on
/// its way from a discrete TPM, no longer gives the key away); `tpm`
/// alone when the CPU has neither RDSEED nor RDRAND.
pub fn mix_key_seed(tpm: &[u8; 32], cpu: Option<&[u8; 32]>) -> [u8; 32] {
    match cpu {
        Some(cpu) => Sha256::new().chain_update(KEY_SEED_DOMAIN).chain_update(tpm).chain_update(cpu).finalize().into(),
        None => *tpm,
    }
}

/// Overwrite `b` with zeroes as stores the compiler may not drop for
/// being dead.
pub fn wipe(b: &mut [u8; 32]) {
    for x in b.iter_mut() {
        // SAFETY: `x` is a valid, aligned &mut u8.
        unsafe { core::ptr::write_volatile(x, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

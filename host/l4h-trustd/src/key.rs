//! Another partition's key (trust::RELAY_KEY), which the primary quotes
//! and extends into PCR 15: an uncompressed SEC1 P-256 point on the
//! curve, not the identity.  Free of seL4 dependencies so that
//! tests/trustd-key compiles it unchanged.

/// Whether `point` is a key a verifier could use: a point the TPM quote
/// then binds for good (PCR 15 only moves forward), so never one that is
/// not on the curve.
pub fn partition_key_ok(point: &[u8; 65]) -> bool {
    point[0] == 4 && p256::PublicKey::from_sec1_bytes(point).is_ok()
}

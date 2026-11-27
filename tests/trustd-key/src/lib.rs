//! trustd's check of another partition's key and the seed of its own
//! (host/l4h-trustd/src/key.rs), compiled unchanged.  Run with tests/run-trusttest.sh.
#[path = "../../../host/l4h-trustd/src/key.rs"]
pub mod key;

#[cfg(test)]
mod tests {
    use super::key::{KEY_SEED_DOMAIN, mix_key_seed, partition_key_ok, wipe};
    use p256::ecdsa::SigningKey;

    fn point(scalar: u8) -> [u8; 65] {
        let k = SigningKey::from_bytes(&[scalar; 32].into()).unwrap();
        k.verifying_key().to_encoded_point(false).as_bytes().try_into().unwrap()
    }

    #[test]
    fn a_point_on_the_curve_is_a_key() {
        for s in [1, 7, 0x42] {
            assert!(partition_key_ok(&point(s)), "{s}");
        }
    }

    #[test]
    fn a_point_off_the_curve_is_not() {
        // y moved by one: no longer on the curve.
        let mut p = point(7);
        p[64] ^= 1;
        assert!(!partition_key_ok(&p));
        // All zeroes (the identity has no uncompressed encoding), and x
        // past the field's prime.
        let mut z = [0u8; 65];
        z[0] = 4;
        assert!(!partition_key_ok(&z));
        let mut big = point(7);
        big[1..33].fill(0xff);
        assert!(!partition_key_ok(&big));
        // A compressed or hybrid prefix on 65 bytes.
        for prefix in [2, 3, 6, 7] {
            let mut q = point(7);
            q[0] = prefix;
            assert!(!partition_key_ok(&q), "{prefix}");
        }
    }

    fn hex(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, o) in out.iter_mut().enumerate() {
            *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn seed_is_the_domain_separated_hash() {
        assert_eq!(KEY_SEED_DOMAIN, b"l4h-trustd-rng-v1");
        // SHA-256("l4h-trustd-rng-v1" || tpm || cpu), from Python's hashlib.
        assert_eq!(
            mix_key_seed(&[0x11; 32], Some(&[0x22; 32])),
            hex("5f73302f051f36f0d41b53dcd8ecd59d78c7c611e8983e4046aab21c53a75701")
        );
        let tpm: [u8; 32] = core::array::from_fn(|i| i as u8);
        let cpu: [u8; 32] = core::array::from_fn(|i| 32 + i as u8);
        assert_eq!(
            mix_key_seed(&tpm, Some(&cpu)),
            hex("70ab9821f366c36ba8a942994ff84ada4628ec4c42958ac07ba613f58a776a63")
        );
    }

    #[test]
    fn cpu_entropy_changes_the_seed() {
        let tpm = [0x11; 32];
        assert_ne!(mix_key_seed(&tpm, Some(&[0x22; 32])), tpm);
        // Even CPU bytes equal to the TPM's, or all zero, are mixed in.
        assert_ne!(mix_key_seed(&tpm, Some(&tpm)), tpm);
        assert_ne!(mix_key_seed(&tpm, Some(&[0; 32])), tpm);
    }

    #[test]
    fn either_source_alone_changes_the_seed() {
        let (t, c) = ([0x11; 32], [0x22; 32]);
        let base = mix_key_seed(&t, Some(&c));
        for i in 0..32 {
            for bit in [0x01, 0x80] {
                let mut t2 = t;
                t2[i] ^= bit;
                assert_ne!(mix_key_seed(&t2, Some(&c)), base, "tpm byte {i}");
                let mut c2 = c;
                c2[i] ^= bit;
                assert_ne!(mix_key_seed(&t, Some(&c2)), base, "cpu byte {i}");
            }
        }
        // The order matters: TPM and CPU bytes swapped differ.
        assert_ne!(mix_key_seed(&c, Some(&t)), base);
    }

    #[test]
    fn without_cpu_entropy_the_seed_is_the_tpms() {
        for t in [[0u8; 32], [0x11; 32], core::array::from_fn(|i| i as u8)] {
            assert_eq!(mix_key_seed(&t, None), t);
        }
    }

    #[test]
    fn wipe_zeroes() {
        let mut b = [0xa5u8; 32];
        wipe(&mut b);
        assert_eq!(b, [0; 32]);
    }
}

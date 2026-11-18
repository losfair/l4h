//! trustd's check of another partition's key (host/l4h-trustd/src/key.rs),
//! compiled unchanged.  Run with tests/run-trusttest.sh.
#[path = "../../../host/l4h-trustd/src/key.rs"]
mod key;

#[cfg(test)]
mod tests {
    use super::key::partition_key_ok;
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
}

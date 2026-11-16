#[path = "../host/l4h-vmmgr/src/compat.rs"]
mod compat;

fn images(guest_abi: u64, guest_version: u64, required: u64, needed: u64,
          host_version: u64, available: u64, features: u64) -> (Vec<u8>, Vec<u8>) {
    let mut guest = b"L4HGABI1".to_vec();
    for word in [guest_abi, guest_version, required, needed] {
        guest.extend_from_slice(&word.to_le_bytes());
    }
    let mut host = b"L4HPVDR1".to_vec();
    for word in [host_version, available, features] {
        host.extend_from_slice(&word.to_le_bytes());
    }
    host.resize(4096, 0);
    (guest, host)
}

#[test]
fn independent_versions_with_append_only_provider_slots() {
    let (guest, host) = images(10, 1, 600, 0, 1, 608, 1);
    assert_eq!(compat::check(&guest, &host, 10), Ok(()));
    let (guest, host) = images(10, 1, 608, 0, 1, 600, 1);
    assert_eq!(compat::check(&guest, &host, 10), Err("guest requires a newer provider table"));
}

#[test]
fn versions_and_required_features_fail_before_guest_boot() {
    for (abi, version, features, error) in [
        (11, 1, 0, "guest ABI version does not match host"),
        (10, 2, 0, "guest provider ABI version does not match host"),
        (10, 1, 2, "host lacks required guest provider features"),
    ] {
        let (guest, host) = images(abi, version, 600, features, 1, 600, 1);
        assert_eq!(compat::check(&guest, &host, 10), Err(error));
    }
    let (guest, host) = images(10, 1, 600, 0, 1, 600, 0);
    assert!(compat::check(&guest, &host, 10).is_ok());
}

#[test]
fn malformed_metadata_never_panics_or_boots() {
    let (guest, host) = images(10, 1, 600, 0, 1, 600, 1);
    for size in 0..40 {
        assert!(compat::check(&guest[..size], &host, 10).is_err());
    }
    for size in 0..32 {
        assert!(compat::check(&guest, &host[..size], 10).is_err());
    }
    for required in [0, 31, 33, u64::MAX] {
        let (guest, host) = images(10, 1, required, 0, 1, 600, 1);
        assert!(compat::check(&guest, &host, 10).is_err());
    }
}

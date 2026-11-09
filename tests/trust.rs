// SPDX-License-Identifier: GPL-2.0-only
//! The flags service's permission, instance and ordering contract.
use l4h_host::trust::*;
use std::sync::Arc;

fn bits(ns: &[usize]) -> [u64; 4] {
    let mut b = [0; 4];
    for &n in ns { b[n / 64] |= 1 << (n % 64); }
    b
}
fn update(e: &mut FlagsEntry, from: Sender, op: u64, instance: u64, ns: &[usize], flags: u64) -> Result<Flags, l4h_host::errno::Errno> {
    // Exclusive reference serializes writers as the endpoint does.
    unsafe { e.update(from, op, instance, bits(ns), flags) }
}

#[test]
fn ranges_and_badges_cannot_be_bypassed() {
    let mut e = FlagsEntry::new();
    for n in 0..256 {
        let b = bits(&[n]);
        let before = e.read();
        let guest = unsafe { e.update(Sender::Trustd, FLAGS_ACT, 1, b, 0) };
        assert_eq!(guest.is_ok(), n >= 64);
        if n < 64 { assert_eq!(e.read(), before); }
        let seal = update(&mut e, Sender::Trustd, FLAGS_SEAL, 1, &[n], 0);
        assert_eq!(seal.is_ok(), n < 2 || n >= 128);
    }
    // An unknown caller never reaches update: the endpoint refuses it.
    assert_eq!(Sender::of_badge(99), None);
    for (badge, op, ns, flags) in [
        (Sender::Root, FLAGS_SEAL, vec![0], 0),
        (Sender::Root, FLAGS_ACT, vec![0], 1),
        (Sender::Root, FLAGS_ACT, vec![128], 0),
        (Sender::Trustd, FLAGS_ACT, vec![64, 140], 1),
        (Sender::Trustd, FLAGS_ACT, vec![140], 2),
        (Sender::Trustd, FLAGS_SEAL, vec![140], 1),
        (Sender::Trustd, 99, vec![], 0),
    ] {
        let before = e.read();
        assert_eq!(update(&mut e, badge, op, 99, &ns, flags), Err(22));
        assert_eq!(e.read(), before, "invalid call replaced a live instance");
    }
}

#[test]
fn all_or_nothing_and_at_most_once() {
    let mut e = FlagsEntry::new();
    update(&mut e, Sender::Trustd, FLAGS_SEAL, 1, &[130], 0).unwrap();
    let before = e.read();
    assert_eq!(update(&mut e, Sender::Trustd, FLAGS_ACT, 1, &[131, 130], 0), Err(1));
    assert_eq!(e.read(), before);
    let f = update(&mut e, Sender::Trustd, FLAGS_ACT, 1, &[140, 255], 1).unwrap();
    assert_eq!(f.taint, bits(&[140, 255]));
    assert_eq!(f.seal, bits(&[130, 140, 255]));
    assert_eq!(update(&mut e, Sender::Trustd, FLAGS_ACT, 1, &[140], 1), Err(1));
    assert_eq!(update(&mut e, Sender::Trustd, FLAGS_ACT, 1, &[255], 0), Err(1));
    assert_eq!(e.read(), f);
    assert_eq!(f.bytes().taint[31], 0x80);
}

#[test]
fn instances_are_monotonic_and_reset_only_on_replacement() {
    let mut e = FlagsEntry::new();
    update(&mut e, Sender::Root, FLAGS_ACT, 8, &[0], 0).unwrap();
    update(&mut e, Sender::Trustd, FLAGS_SEAL, 8, &[0], 0).unwrap();
    let before = e.read();
    assert_eq!(update(&mut e, Sender::Trustd, FLAGS_ACT, 7, &[], 0), Err(3));
    assert_eq!(update(&mut e, Sender::Root, FLAGS_ACT, 0, &[1], 0), Err(22));
    assert_eq!(e.read(), before);
    assert_eq!(before.for_instance(9).taint, [0; 4]);
    let next = update(&mut e, Sender::Trustd, FLAGS_ACT, 9, &[], 0).unwrap();
    assert_eq!(next, Flags { instance: 9, ..Flags::default() });
    assert_eq!(update(&mut e, Sender::Root, FLAGS_ACT, 8, &[1], 0), Err(3));
}

#[test]
fn cached_host_actions_check_the_seal_first() {
    let mut e = FlagsEntry::new();
    assert_eq!(e.read().acted(1), Ok(false));
    update(&mut e, Sender::Root, FLAGS_ACT, 1, &[0], 0).unwrap();
    assert_eq!(e.read().acted(1), Ok(true));
    let f = update(&mut e, Sender::Trustd, FLAGS_SEAL, 1, &[0, 1], 0).unwrap();
    assert_eq!(f.acted(1), Err(1));
    assert_eq!(f.acted(2), Err(1));
    // An in-flight action checked before the seal already has its taint
    // in the answer. A clean seal cannot have passed an action.
    assert_eq!(f.taint[0] & f.seal[0], 1);
}

#[test]
fn readers_never_mix_instances_or_see_a_seal_before_its_taint() {
    let e = Arc::new(FlagsEntry::new());
    let w = e.clone();
    let writer = std::thread::spawn(move || {
        for instance in 1..100_000 {
            let b = [0, 0, instance, !instance];
            // This thread is the sole writer.
            unsafe { w.update(Sender::Trustd, FLAGS_ACT, instance, b, 1) }.unwrap();
        }
    });
    while !writer.is_finished() {
        let f = e.read();
        assert_eq!(f.taint, f.seal);
        if f.instance != 0 { assert_eq!(f.taint, [0, 0, f.instance, !f.instance]); }
    }
    writer.join().unwrap();
}

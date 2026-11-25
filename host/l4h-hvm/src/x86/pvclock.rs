//! kvmclock (DESIGN.md §5.11): KVM's paravirtual clock, the one way an
//! unmodified Linux on AMD learns its TSC's rate without calibrating it
//! against the PIT or the ACPI PM timer, which nested exits are too slow
//! for (tsc.c gives up on reads slower than about 13 µs).  CPUID's KVM
//! leaves offer only the clock (cpuid.rs); a vCPU's time info is written
//! once, when the guest names it, as the TSC is invariant.  Free of seL4.

/// MSR_KVM_WALL_CLOCK_NEW and MSR_KVM_SYSTEM_TIME_NEW.
pub const MSR_WALL_CLOCK: u32 = 0x4b56_4d00;
pub const MSR_SYSTEM_TIME: u32 = 0x4b56_4d01;
/// MSR_KVM_PV_EOI_EN: bit 0 on, the rest a 4-byte aligned address of the
/// guest's PV EOI word (Vcpu::pv_eoi_*).
pub const MSR_PV_EOI: u32 = 0x4b56_4d04;
/// MSR_KVM_STEAL_TIME: bit 0 on, bits 5:1 reserved (#GP), the rest the
/// 64-byte aligned address of the vCPU's struct kvm_steal_time.
pub const MSR_STEAL_TIME: u32 = 0x4b56_4d03;
pub const STEAL_TIME_ENABLE: u64 = 1;
pub const STEAL_TIME_RESERVED: u64 = 0x3e;
/// CPUID 0x40000001 EAX: KVM_FEATURE_CLOCKSOURCE2, KVM_FEATURE_STEAL_TIME,
/// KVM_FEATURE_PV_EOI and KVM_FEATURE_CLOCKSOURCE_STABLE_BIT.
pub const FEATURES: u32 = (1 << 3) | (1 << 5) | (1 << 6) | (1 << 24);
/// The size of struct kvm_steal_time.
pub const STEAL_TIME_SIZE: usize = 64;
/// pvclock_vcpu_time_info.flags: PVCLOCK_TSC_STABLE_BIT.
pub const TSC_STABLE: u8 = 1;
/// The size of pvclock_vcpu_time_info and of pvclock_wall_clock.
pub const TIME_INFO_SIZE: usize = 32;
pub const WALL_CLOCK_SIZE: usize = 12;

/// The (multiplier, shift) that turn TSC ticks at `tsc_hz` into
/// nanoseconds, as KVM's kvm_get_time_scale(NSEC_PER_SEC, tsc_hz) finds
/// them: ns = ((ticks << shift, or >> -shift) * mul) >> 32.
pub fn time_scale(tsc_hz: u64) -> (u32, i8) {
    let mut scaled: u64 = 1_000_000_000;
    let mut tps64 = tsc_hz.max(1);
    let mut shift: i32 = 0;
    while tps64 > scaled * 2 || tps64 & 0xffff_ffff_0000_0000 != 0 {
        tps64 >>= 1;
        shift -= 1;
    }
    let mut tps32 = tps64 as u32;
    while tps32 as u64 <= scaled || scaled & 0xffff_ffff_0000_0000 != 0 {
        if scaled & 0xffff_ffff_0000_0000 != 0 || tps32 & 0x8000_0000 != 0 {
            scaled >>= 1;
        } else {
            tps32 <<= 1;
        }
        shift += 1;
    }
    (((scaled << 32) / tps32 as u64) as u32, shift as i8)
}

/// Linux's pvclock_scale_delta(): `delta` ticks in nanoseconds.
pub fn scale(delta: u64, mul: u32, shift: i8) -> u64 {
    let d = if shift < 0 { delta >> -shift } else { delta << shift };
    ((d as u128 * mul as u128) >> 32) as u64
}

/// Linux's pvclock_tsc_khz(): the rate the guest takes from the scale.
pub fn tsc_khz(mul: u32, shift: i8) -> u64 {
    let khz = (1_000_000u64 << 32) / mul.max(1) as u64;
    if shift < 0 { khz << -shift } else { khz >> shift }
}

/// pvclock_vcpu_time_info: `version`, then the guest's TSC at kvmclock
/// time `system_time`, the scale and the flags.
pub fn time_info(version: u32, tsc_timestamp: u64, system_time: u64, mul: u32, shift: i8, flags: u8) -> [u8; TIME_INFO_SIZE] {
    let mut b = [0; TIME_INFO_SIZE];
    b[0..4].copy_from_slice(&version.to_le_bytes());
    b[8..16].copy_from_slice(&tsc_timestamp.to_le_bytes());
    b[16..24].copy_from_slice(&system_time.to_le_bytes());
    b[24..28].copy_from_slice(&mul.to_le_bytes());
    b[28] = shift as u8;
    b[29] = flags;
    b
}

/// pvclock_wall_clock: `version`, and the wall time at kvmclock time 0.
pub fn wall_clock(version: u32, sec: u32, nsec: u32) -> [u8; WALL_CLOCK_SIZE] {
    let mut b = [0; WALL_CLOCK_SIZE];
    b[0..4].copy_from_slice(&version.to_le_bytes());
    b[4..8].copy_from_slice(&sec.to_le_bytes());
    b[8..12].copy_from_slice(&nsec.to_le_bytes());
    b
}

/// Write a pvclock structure as KVM does, for its even version `v`
/// (`b[0..4]`): `v - 1` first, then the rest, then `v`.  Linux's
/// pvclock_read_begin() takes `version & ~1` and pvclock_read_retry()
/// compares it with the version after: a reader that began before or
/// during the write sees `v - 2` or `v - 1` there and retries.  The caller
/// checks the whole structure is RAM first, so that nothing is left half
/// written, and stores `version` as one aligned 32-bit word.
pub fn publish(b: &[u8], mut version: impl FnMut(u32), mut body: impl FnMut(&[u8])) {
    let v = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    debug_assert!(v & 1 == 0);
    version(v.wrapping_sub(1));
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    body(&b[4..]);
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    version(v);
}

/// struct kvm_steal_time: `steal` (ns the vCPU was runnable and not
/// running, cumulative since the guest named it), then `version` at 8, as
/// pvclock's even when stable, `flags` 0 and `preempted` 0 (the
/// preempted hint is not offered: KVM_FEATURE_PV_TLB_FLUSH and the like
/// are not in FEATURES).
pub fn steal_time(version: u32, steal: u64) -> [u8; STEAL_TIME_SIZE] {
    let mut b = [0; STEAL_TIME_SIZE];
    b[0..8].copy_from_slice(&steal.to_le_bytes());
    b[8..12].copy_from_slice(&version.to_le_bytes());
    b
}

/// Write a kvm_steal_time `b`, for its even version `v` (`b[8..12]`), as
/// KVM's record_steal_time does: `v - 1` first, then the rest, then `v`.
/// Linux's kvm_steal_clock() retries while the version is odd or changed,
/// so it never takes a `steal` from the middle of a write.  `write(off,
/// bytes)` stores at that offset of the structure; the version is one
/// aligned 32-bit store.
pub fn publish_steal(b: &[u8; STEAL_TIME_SIZE], mut write: impl FnMut(usize, &[u8])) {
    let v = u32::from_le_bytes([b[8], b[9], b[10], b[11]]);
    debug_assert!(v & 1 == 0);
    write(8, &v.wrapping_sub(1).to_le_bytes());
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    write(0, &b[0..8]);
    write(12, &b[12..]);
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    write(8, &b[8..12]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scale_matches_kvm_and_gives_the_rate_back() {
        for hz in [1_000_000_000u64, 1_900_000_000, 2_700_000_000, 3_793_000_000, 5_000_000_000, 25_000_000, 100_000_000_000] {
            let (mul, shift) = time_scale(hz);
            assert!(mul >= 1 << 31, "{hz}: normalized");
            // A second, and an hour, of ticks, within a part in 10^8.
            for secs in [1u64, 3600] {
                let ns = scale(hz * secs, mul, shift) as i128;
                let want = (secs * 1_000_000_000) as i128;
                assert!((ns - want).abs() <= want / 100_000_000 + 1, "{hz} Hz, {secs} s: {ns}");
            }
            let khz = tsc_khz(mul, shift) as i64;
            assert!((khz - (hz / 1000) as i64).abs() <= 1, "{hz} Hz: {khz} kHz");
        }
        // A 3.793 GHz TSC: shift -1, mul = 10^9 * 2^32 / (3.793e9 / 2).
        assert_eq!(time_scale(3_793_000_000), (0x86fc_49b3, -1));
    }

    #[test]
    fn layouts_and_the_version_protocol() {
        let t = time_info(4, 0x1122_3344_5566_7788, 0x99, 0xaabb_ccdd, -1, TSC_STABLE);
        assert_eq!(&t[0..4], &4u32.to_le_bytes());
        assert_eq!(&t[8..16], &0x1122_3344_5566_7788u64.to_le_bytes());
        assert_eq!(&t[16..24], &0x99u64.to_le_bytes());
        assert_eq!(&t[24..28], &0xaabb_ccddu32.to_le_bytes());
        assert_eq!((t[28], t[29]), (0xff, 1));
        let w = wall_clock(2, 1_700_000_000, 5);
        assert_eq!(w, [2, 0, 0, 0, 0, 0xf1, 0x53, 0x65, 5, 0, 0, 0]);
        // v - 1, the body, v: a reader that began with v - 2 (or v - 1)
        // finds `begin & !1 != end` and retries.
        let mem = core::cell::RefCell::new([0u8; 32]);
        let log = core::cell::RefCell::new(std::vec::Vec::new());
        publish(&t, |v| {
            mem.borrow_mut()[0..4].copy_from_slice(&v.to_le_bytes());
            log.borrow_mut().push(std::format!("v{v}"));
        }, |b| {
            mem.borrow_mut()[4..4 + b.len()].copy_from_slice(b);
            log.borrow_mut().push(std::format!("body{}", b.len()));
        });
        assert_eq!(*log.borrow(), ["v3", "body28", "v4"]);
        assert_eq!(*mem.borrow(), t);
        for begin in [2u32, 3] {
            assert_ne!(begin & !1, 4, "a reader from before retries");
        }
        // kvm_steal_time: steal at 0, the version at 8, v - 1 first.
        let st = steal_time(6, 0x0102_0304_0506_0708);
        assert_eq!(&st[0..8], &0x0102_0304_0506_0708u64.to_le_bytes());
        assert_eq!(&st[8..12], &6u32.to_le_bytes());
        assert!(st[12..].iter().all(|&b| b == 0), "flags and preempted clear");
        let mem = core::cell::RefCell::new([0xffu8; STEAL_TIME_SIZE]);
        let order = core::cell::RefCell::new(std::vec::Vec::new());
        publish_steal(&st, |off, b| {
            mem.borrow_mut()[off..off + b.len()].copy_from_slice(b);
            order.borrow_mut().push((off, b.len(), u32::from_le_bytes(mem.borrow()[8..12].try_into().unwrap())));
        });
        assert_eq!(*order.borrow(), [(8, 4, 5), (0, 8, 5), (12, 52, 5), (8, 4, 6)], "odd while the body changes");
        assert_eq!(*mem.borrow(), st);
        // Across the wrap: 0 - 1 is odd, and its & !1 is not 0.
        assert_eq!(0u32.wrapping_sub(1) & 1, 1);
        assert_ne!(0u32.wrapping_sub(1) & !1, 0);
    }
}

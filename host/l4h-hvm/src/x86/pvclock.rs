//! kvmclock (DESIGN.md §5.11): KVM's paravirtual clock, the one way an
//! unmodified Linux on AMD learns its TSC's rate without calibrating it
//! against the PIT or the ACPI PM timer, which nested exits are too slow
//! for (tsc.c gives up on reads slower than about 13 µs).  CPUID's KVM
//! leaves offer only the clock (cpuid.rs); a vCPU's time info is written
//! once, when the guest names it, as the TSC is invariant.  Free of seL4.

/// MSR_KVM_WALL_CLOCK_NEW and MSR_KVM_SYSTEM_TIME_NEW.
pub const MSR_WALL_CLOCK: u32 = 0x4b56_4d00;
pub const MSR_SYSTEM_TIME: u32 = 0x4b56_4d01;
/// CPUID 0x40000001 EAX: KVM_FEATURE_CLOCKSOURCE2 and
/// KVM_FEATURE_CLOCKSOURCE_STABLE_BIT.
pub const FEATURES: u32 = (1 << 3) | (1 << 24);
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

/// Write a pvclock structure as KVM does: an odd version first, then the
/// rest, then the even version (`b[0..4]`), so that a guest reading it
/// meanwhile retries.  `write(offset, bytes)` stores into guest RAM; false
/// (not RAM) leaves it.
pub fn publish(b: &[u8], mut write: impl FnMut(usize, &[u8]) -> bool) -> bool {
    let version = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    if !write(0, &(version | 1).to_le_bytes()) {
        return false;
    }
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    let ok = write(4, &b[4..]);
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    ok && write(0, &b[0..4])
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
        let mut mem = [0u8; 32];
        let mut versions = std::vec::Vec::new();
        assert!(publish(&t, |o, b| {
            mem[o..o + b.len()].copy_from_slice(b);
            versions.push(u32::from_le_bytes([mem[0], mem[1], mem[2], mem[3]]));
            true
        }));
        assert_eq!(versions, [5, 5, 4]);
        assert_eq!(mem, t);
        assert!(!publish(&t, |_, _| false));
    }
}

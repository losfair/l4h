//! Read KVM's virtual TSC rate once, before native CPUID or PIT calibration.
//! CPUID 0x15 can describe the physical CPU instead (GCE C3: 1.9 vs 2.7 GHz).

use crate::io::{cpuid, wrmsr};
use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{compiler_fence, Ordering};

#[repr(C, align(32))]
struct ClockInfo {
    version: u32,
    pad: u32,
    tsc_timestamp: u64,
    system_time: u64,
    mul: u32,
    shift: i8,
    flags: u8,
    reserved: [u8; 2],
}

static mut CLOCK: ClockInfo = ClockInfo {
    version: 0, pad: 0, tsc_timestamp: 0, system_time: 0,
    mul: 0, shift: 0, flags: 0, reserved: [0; 2],
};

fn clock_msr() -> Option<u32> {
    if cpuid(1, 0)[2] & (1 << 31) == 0 {
        return None;
    }
    let r = cpuid(0x4000_0000, 0);
    if r[1..] != [0x4b4d_564b, 0x564b_4d56, 0x4d]
        || (r[0] != 0 && r[0] < 0x4000_0001)
    {
        return None;
    }
    let features = cpuid(0x4000_0001, 0)[0];
    if features & (1 << 3) != 0 {
        Some(0x4b56_4d01)
    } else if features & 1 != 0 {
        Some(0x12)
    } else {
        None
    }
}

fn scale_mhz(mul: u32, shift: i8) -> u32 {
    if mul == 0 || !(-31..=31).contains(&shift) {
        return 0;
    }
    let mut khz = (1_000_000u128 << 32) / mul as u128;
    if shift < 0 { khz <<= -shift; } else { khz >>= shift; }
    ((khz + 500) / 1000).try_into().unwrap_or(0)
}

/// MHz, the unit seL4 accepts on its command line and passes in bootinfo.
/// The shim is identity-mapped. Registration lasts only for this call,
/// so the hypervisor cannot overwrite shim memory after it is reclaimed.
pub fn tsc_mhz() -> u32 {
    let Some(msr) = clock_msr() else { return 0 };
    let clock = addr_of_mut!(CLOCK);
    compiler_fence(Ordering::SeqCst);
    wrmsr(msr, clock as u64 | 1);
    let mut mhz = 0;
    for _ in 0..10000 {
        // x86 orders the loads; volatile reads and compiler fences keep
        // the version checks on either side of this scale snapshot.
        let version = unsafe { addr_of!((*clock).version).read_volatile() };
        compiler_fence(Ordering::SeqCst);
        let mul = unsafe { addr_of!((*clock).mul).read_volatile() };
        let shift = unsafe { addr_of!((*clock).shift).read_volatile() };
        compiler_fence(Ordering::SeqCst);
        if version != 0 && version & 1 == 0
            && version == unsafe { addr_of!((*clock).version).read_volatile() }
        {
            mhz = scale_mhz(mul, shift);
            break;
        }
    }
    wrmsr(msr, 0);
    compiler_fence(Ordering::SeqCst);
    mhz
}

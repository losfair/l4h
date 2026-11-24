//! PSCI 1.0 and the SMCCC's discovery calls (DESIGN.md §5.11): what a guest
//! asks with HVC (or SMC) of its firmware.  The power state of each vCPU is
//! atomic, for other vCPUs to look at and start it.  Free of seL4.

use core::sync::atomic::{AtomicU8, AtomicU64, Ordering::SeqCst};

use l4h_rt::host::hvm::arm;

pub const SUCCESS: i64 = 0;
pub const NOT_SUPPORTED: i64 = -1;
pub const INVALID_PARAMS: i64 = -2;
pub const ALREADY_ON: i64 = -4;
pub const ON_PENDING: i64 = -5;

const VERSION: u32 = 0x8400_0000;
const CPU_SUSPEND: u32 = 0x0000_0001;
const CPU_OFF: u32 = 0x8400_0002;
const CPU_ON: u32 = 0x0000_0003;
const AFFINITY_INFO: u32 = 0x0000_0004;
const MIGRATE_INFO_TYPE: u32 = 0x8400_0006;
const SYSTEM_OFF: u32 = 0x8400_0008;
const SYSTEM_RESET: u32 = 0x8400_0009;
const FEATURES: u32 = 0x8400_000a;
const SMCCC_VERSION: u32 = 0x8000_0000;
const SMCCC_ARCH_FEATURES: u32 = 0x8000_0001;

/// PSCI's 32-bit and 64-bit calling conventions of a function.
const CONV_32: u32 = 0x8400_0000;
const CONV_64: u32 = 0xc400_0000;

/// CPU_SUSPEND's power_state, original format: its StateType (power down),
/// and the bits it reserves.
const POWER_STATE_DOWN: u32 = 1 << 16;
const POWER_STATE_RESERVED: u32 = 0xfc00_0000 | 0x00fe_0000;

/// PSCI 1.0.
const PSCI_1_0: u64 = 1 << 16;
/// SMCCC 1.1.
const SMCCC_1_1: u64 = 0x1_0001;
/// No Trusted OS to migrate.
const MIGRATE_NONE: u64 = 2;

/// AFFINITY_INFO's answers, and a vCPU's states.
pub const AFF_ON: u8 = 0;
pub const AFF_OFF: u8 = 1;
pub const AFF_ON_PENDING: u8 = 2;

/// A vCPU's power state, and where CPU_ON starts it.
pub struct Power {
    state: AtomicU8,
    entry: AtomicU64,
    context: AtomicU64,
}

impl Power {
    pub fn new(on: bool) -> Self {
        Power {
            state: AtomicU8::new(if on { AFF_ON } else { AFF_OFF }),
            entry: AtomicU64::new(0),
            context: AtomicU64::new(0),
        }
    }

    pub fn state(&self) -> u8 {
        self.state.load(SeqCst)
    }

    /// CPU_ON: the vCPU is to start at `entry`.
    fn request(&self, entry: u64, context: u64) -> i64 {
        // Claimed first: only the winner writes where it starts, and the
        // vCPU reads that after it sees ON_PENDING.
        match self.state.compare_exchange(AFF_OFF, AFF_ON_PENDING + 1, SeqCst, SeqCst) {
            Ok(_) => {
                self.entry.store(entry, SeqCst);
                self.context.store(context, SeqCst);
                self.state.store(AFF_ON_PENDING, SeqCst);
                SUCCESS
            }
            Err(AFF_ON) => ALREADY_ON,
            Err(_) => ON_PENDING,
        }
    }

    /// The vCPU's thread: where a pending CPU_ON starts it, if one is.
    pub fn take_start(&self) -> Option<(u64, u64)> {
        if self.state.load(SeqCst) != AFF_ON_PENDING {
            return None;
        }
        let start = (self.entry.load(SeqCst), self.context.load(SeqCst));
        self.state.store(AFF_ON, SeqCst);
        Some(start)
    }

    /// The vCPU's thread: it powers itself off.
    pub fn set_off(&self) {
        self.state.store(AFF_OFF, SeqCst);
    }
}

/// What a call makes of the machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Back to the guest, with x0.
    Ret(i64),
    /// The caller is off (CPU_OFF).
    Off,
    /// As WFI, then back with success (CPU_SUSPEND).
    Standby,
    SystemOff,
    SystemReset,
    /// vCPU `.0` is to wake: back with success.
    Started(usize),
}

fn known(fid: u32) -> bool {
    matches!(fid, VERSION | CPU_OFF | MIGRATE_INFO_TYPE | SYSTEM_OFF | SYSTEM_RESET | FEATURES | SMCCC_VERSION)
        || [CPU_SUSPEND, CPU_ON, AFFINITY_INFO].iter().any(|&f| fid == CONV_32 | f || fid == CONV_64 | f)
}

/// The call `fid` by a vCPU, with its arguments x1-x3.
pub fn call(fid: u32, x: [u64; 3], power: &[Power]) -> Outcome {
    // The 32-bit convention's arguments are 32 bits wide.
    let a = if fid & 0x4000_0000 == 0 { x.map(|v| v & 0xffff_ffff) } else { x };
    match fid {
        VERSION => Outcome::Ret(PSCI_1_0 as i64),
        MIGRATE_INFO_TYPE => Outcome::Ret(MIGRATE_NONE as i64),
        CPU_OFF => Outcome::Off,
        SYSTEM_OFF => Outcome::SystemOff,
        // Ends the guest as a reboot: what follows is l4h-vmmgr's to decide
        // (DESIGN.md §5.11).
        SYSTEM_RESET => Outcome::SystemReset,
        FEATURES => {
            // No feature flags: CPU_SUSPEND's original format, no OS-initiated mode.
            Outcome::Ret(if known(a[0] as u32) { SUCCESS } else { NOT_SUPPORTED })
        }
        SMCCC_VERSION => Outcome::Ret(SMCCC_1_1 as i64),
        // No workarounds to offer: FL4 has its own.
        SMCCC_ARCH_FEATURES => Outcome::Ret(if a[0] as u32 == SMCCC_VERSION { SUCCESS } else { NOT_SUPPORTED }),
        // Standby is WFI; there is no power-down state to lose context in.
        f if f == CONV_32 | CPU_SUSPEND || f == CONV_64 | CPU_SUSPEND => {
            if a[0] as u32 & (POWER_STATE_DOWN | POWER_STATE_RESERVED) != 0 {
                Outcome::Ret(INVALID_PARAMS)
            } else {
                Outcome::Standby
            }
        }
        f if f == CONV_32 | CPU_ON || f == CONV_64 | CPU_ON => {
            let Some(v) = arm::vcpu_of_aff(a[0], power.len()) else { return Outcome::Ret(INVALID_PARAMS) };
            match power[v].request(a[1], a[2]) {
                SUCCESS => Outcome::Started(v),
                e => Outcome::Ret(e),
            }
        }
        f if f == CONV_32 | AFFINITY_INFO || f == CONV_64 | AFFINITY_INFO => {
            if a[1] != 0 {
                return Outcome::Ret(INVALID_PARAMS);
            }
            match arm::vcpu_of_aff(a[0], power.len()) {
                Some(v) => Outcome::Ret(power[v].state().min(AFF_ON_PENDING) as i64),
                None => Outcome::Ret(INVALID_PARAMS),
            }
        }
        _ => Outcome::Ret(NOT_SUPPORTED),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Not offered: its reset types are not implemented.
    const SYSTEM_RESET2: u32 = 0x0000_0012;

    fn cpus(n: usize) -> Vec<Power> {
        (0..n).map(|v| Power::new(v == 0)).collect()
    }

    #[test]
    fn discovery() {
        let p = cpus(1);
        assert_eq!(call(VERSION, [0; 3], &p), Outcome::Ret(1 << 16));
        assert_eq!(call(MIGRATE_INFO_TYPE, [0; 3], &p), Outcome::Ret(2));
        assert_eq!(call(SMCCC_VERSION, [0; 3], &p), Outcome::Ret(0x1_0001));
        assert_eq!(call(FEATURES, [SMCCC_VERSION as u64, 0, 0], &p), Outcome::Ret(SUCCESS));
        assert_eq!(call(FEATURES, [(CONV_64 | CPU_ON) as u64, 0, 0], &p), Outcome::Ret(SUCCESS));
        assert_eq!(call(FEATURES, [(CONV_64 | SYSTEM_RESET2) as u64, 0, 0], &p), Outcome::Ret(NOT_SUPPORTED));
        assert_eq!(call(FEATURES, [(CONV_32 | SYSTEM_RESET2) as u64, 0, 0], &p), Outcome::Ret(NOT_SUPPORTED));
        assert_eq!(call(FEATURES, [0x8400_0005, 0, 0], &p), Outcome::Ret(NOT_SUPPORTED), "MIGRATE");
        assert_eq!(call(SMCCC_ARCH_FEATURES, [SMCCC_VERSION as u64, 0, 0], &p), Outcome::Ret(SUCCESS));
        assert_eq!(call(SMCCC_ARCH_FEATURES, [0x8000_7fff, 0, 0], &p), Outcome::Ret(NOT_SUPPORTED), "a workaround");
        assert_eq!(call(0x8400_00ff, [0; 3], &p), Outcome::Ret(NOT_SUPPORTED));
    }

    #[test]
    fn cpu_on_off_and_affinity() {
        let p = cpus(2);
        let on = CONV_64 | CPU_ON;
        let aff = CONV_64 | AFFINITY_INFO;
        assert_eq!(call(aff, [1, 0, 0], &p), Outcome::Ret(AFF_OFF as i64));
        assert_eq!(call(on, [5, 0x4100_0000, 7], &p), Outcome::Ret(INVALID_PARAMS), "no such vCPU");
        assert_eq!(call(on, [0, 0x4100_0000, 7], &p), Outcome::Ret(ALREADY_ON));
        assert_eq!(call(on, [1, 0x4100_0000, 7], &p), Outcome::Started(1));
        assert_eq!(call(aff, [1, 0, 0], &p), Outcome::Ret(AFF_ON_PENDING as i64));
        assert_eq!(call(on, [1, 0x4200_0000, 8], &p), Outcome::Ret(ON_PENDING));
        assert_eq!(p[1].take_start(), Some((0x4100_0000, 7)), "the first CPU_ON's");
        assert_eq!(p[1].take_start(), None);
        assert_eq!(call(aff, [1, 0, 0], &p), Outcome::Ret(AFF_ON as i64));
        assert_eq!(call(CPU_OFF, [0; 3], &p), Outcome::Off);
        p[1].set_off();
        assert_eq!(call(aff, [1, 0, 0], &p), Outcome::Ret(AFF_OFF as i64));
        // Only its own level.
        assert_eq!(call(aff, [1, 1, 0], &p), Outcome::Ret(INVALID_PARAMS));
    }

    #[test]
    fn the_32_bit_convention_is_32_bits() {
        let p = cpus(2);
        let on = CONV_32 | CPU_ON;
        assert_eq!(call(on, [0xffff_ffff_0000_0001, 0xffff_ffff_4100_0000, 0xdead_0000_0000_0009], &p), Outcome::Started(1));
        assert_eq!(p[1].take_start(), Some((0x4100_0000, 9)));
    }

    #[test]
    fn system_calls() {
        let p = cpus(1);
        assert_eq!(call(SYSTEM_OFF, [0; 3], &p), Outcome::SystemOff);
        assert_eq!(call(SYSTEM_RESET, [0; 3], &p), Outcome::SystemReset);
        assert_eq!(call(CONV_64 | SYSTEM_RESET2, [0; 3], &p), Outcome::Ret(NOT_SUPPORTED));
        assert_eq!(call(CONV_32 | SYSTEM_RESET2, [0; 3], &p), Outcome::Ret(NOT_SUPPORTED));
    }

    #[test]
    fn cpu_suspend_is_standby_only() {
        let p = cpus(1);
        for fid in [CONV_32 | CPU_SUSPEND, CONV_64 | CPU_SUSPEND] {
            assert_eq!(call(fid, [0; 3], &p), Outcome::Standby);
            assert_eq!(call(fid, [0xffff, 0, 0], &p), Outcome::Standby, "a state ID");
            assert_eq!(call(fid, [1 << 24, 0, 0], &p), Outcome::Standby, "a power level");
            assert_eq!(call(fid, [1 << 16, 0, 0], &p), Outcome::Ret(INVALID_PARAMS), "power down");
            for bit in (17..=23).chain(26..=31) {
                assert_eq!(call(fid, [1 << bit, 0, 0], &p), Outcome::Ret(INVALID_PARAMS), "reserved bit {bit}");
            }
        }
    }
}

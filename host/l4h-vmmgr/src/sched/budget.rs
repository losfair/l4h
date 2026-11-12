//! CPU caps and VMM priority policy, independent of seL4. Boosted,
//! uncapped contexts remain work conserving; vCPU 0 pays for its capped VMM.

/// Stay above seL4's minimum budget, derived from the kernel WCET.
pub const MIN_US: u64 = 200;
pub const VMM_SHARE_INIT: u32 = 250;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    pub period: u64,
    pub kernel: u64,
    pub user: u64,
    pub vmm_period: u64,
    pub vmm: u64,
}

/// `vmm` is its share of vCPU 0's cap, in permille.
/// `min_period` is the architecture's capped floor.
pub fn plan(timeslice: u64, min_period: u64, cap: u32, kernel_share: u32, vmm: Option<u32>) -> Plan {
    let cap = cap.min(100);
    // K/U share a core, so 100% needs no split without a VMM. The VMM
    // may stay behind when vCPU 0 migrates: its time must still be paid.
    if cap == 0 || (cap == 100 && vmm.is_none()) {
        let vmm_period = vmm.map_or(0, |_| timeslice);
        return Plan { period: timeslice, kernel: timeslice, user: timeslice,
            vmm_period, vmm: vmm_period };
    }
    let parts = if vmm.is_some() { 3 } else { 2 };
    let period = timeslice.max(min_period).max((parts * MIN_US * 100).div_ceil(cap as u64));
    let total = period * cap as u64 / 100;
    let vmm_budget = match vmm {
        Some(share) => (total * share.min(1000) as u64 / 1000)
            .clamp(MIN_US, total - 2 * MIN_US),
        _ => 0,
    };
    let guest = total - vmm_budget;
    let kernel = (guest * kernel_share.min(1000) as u64 / 1000).clamp(MIN_US, guest - MIN_US);
    Plan { period, kernel, user: guest - kernel, vmm_period: period, vmm: vmm_budget }
}

/// Boost recovery requires uninterrupted quiescence. Repeated offenders
/// wait 1, 2, 4, 8, then 16 seconds, so quiet/spin cycles cannot regain a
/// full-priority context every other 100 ms sample.
#[derive(Clone, Copy, Debug, Default)]
pub struct BoostGuard {
    demotions: u8,
    quiet_us: u64,
}

impl BoostGuard {
    /// Select the largest consumer, independent of how many idle VMMs
    /// share its core. A lone VMM using otherwise idle CPU is not pressure.
    pub fn boost(&mut self, was: bool, used: u64, core_vmm: u64, largest: u64,
        contended: bool, elapsed: u64, old: Plan) -> bool {
        if elapsed == 0 { return was; }
        if was {
            self.quiet_us = 0;
            let crowded = core_vmm as u128 * 5 >= elapsed as u128 * 4;
            if contended && crowded && used > 0 && used == largest {
                self.demotions = self.demotions.saturating_add(1);
                return false;
            }
            return true;
        }
        if used as u128 * old.vmm_period as u128 * 2 < old.vmm as u128 * elapsed as u128 {
            self.quiet_us = self.quiet_us.saturating_add(elapsed);
        } else {
            self.quiet_us = 0;
        }
        let wait = 1_000_000u64 << self.demotions.saturating_sub(1).min(4);
        self.quiet_us >= wait
    }
}

/// Only VMMs whose boost was withdrawn share this half-core limit.
/// It leaves time for guest users while priority above guest kernels lets
/// the VMM service a guest kernel that spins waiting for a device reply.
/// Other VMMs, including idle ones, do not divide this allowance.
pub fn background(mut p: Plan, peers: usize) -> Plan {
    assert!(peers > 0 && peers <= 64);
    let divisor = 2 * peers as u64;
    let period = p.vmm_period.max(MIN_US * divisor);
    p.vmm = (p.vmm as u128 * period as u128 / p.vmm_period as u128)
        .min((period / divisor) as u128) as u64;
    p.vmm_period = period;
    p
}

/// Adapt only once a context saturated. Consumption ratios survive
/// throttling; unused budget on a blocked peer is not evidence of demand.
pub fn adapt(old: Plan, kernel_share: u32, vmm_share: u32, used: [u64; 3], elapsed: u64) -> Option<(u32, u32)> {
    let [k, u, v] = used;
    let total = k + u + v;
    if elapsed == 0 || total == 0 || total > elapsed {
        return None;
    }
    if k * old.period / elapsed * 10 < old.kernel * 9
        && u * old.period / elapsed * 10 < old.user * 9
        && (old.vmm == 0 || v * old.vmm_period / elapsed * 10 < old.vmm * 9) {
        return None;
    }
    let kernel = if k + u == 0 { kernel_share } else { (k * 1000 / (k + u)) as u32 };
    let vmm = if old.vmm == 0 { vmm_share } else { (v * 1000 / total) as u32 };
    Some((kernel, vmm))
}

/// Avoid refills and kernel calls for changes below one sixteenth of the
/// cap. A period change always takes effect.
pub fn changed(old: Plan, new: Plan) -> bool {
    if old.period != new.period || old.vmm_period != new.vmm_period { return true; }
    let total = old.kernel + old.user + old.vmm;
    [old.kernel.abs_diff(new.kernel), old.user.abs_diff(new.user), old.vmm.abs_diff(new.vmm)]
        .iter().any(|d| d * 16 >= total)
}

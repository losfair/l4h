//! CPU caps and VMM priority policy, independent of seL4. Uncapped
//! contexts remain work conserving; vCPU 0 pays for a capped guest's VMM.

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

/// Elevated priority is for short I/O turns. If VMMs dominate a core,
/// drop them to the guest-user band; unused CPU remains available there.
/// Include relative use so higher-priority host work cannot hide a VMM
/// monopolizing the time left to guests. Ignore less than one quantum
/// for that comparison, since timer work alone can dominate an idle core.
/// Restore the boost only after quiescence, preventing busy/quiet priority
/// oscillation while a VMM still has sustained work.
pub fn boost(was: bool, used: u64, core_vmm: u64, core_guest: u64, elapsed: u64, quantum: u64) -> bool {
    if elapsed == 0 { return was; }
    let vmm = core_vmm as u128;
    let crowded = vmm * 5 >= elapsed as u128 * 4
        || (core_vmm >= quantum && vmm >= core_guest as u128 * 4);
    if crowded { return false; }
    was || used as u128 * 100 <= elapsed as u128 * 2
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

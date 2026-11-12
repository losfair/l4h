//! Scheduling limits independent of seL4. The VMMs on one core share at
//! most a quarter of it; a capped guest also pays for its VMM from vCPU 0.

/// Stay above seL4's minimum budget, derived from the kernel WCET.
pub const MIN_US: u64 = 200;
pub const VMM_SHARE_INIT: u32 = 250;
const VMM_CORE_DIVISOR: u64 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    pub period: u64,
    pub kernel: u64,
    pub user: u64,
    pub vmm_period: u64,
    pub vmm: u64,
}

/// `vmm` is its share of vCPU 0's cap (permille) and the number of VMMs
/// sharing its host core. `min_period` is the architecture's capped floor.
pub fn plan(timeslice: u64, min_period: u64, cap: u32, kernel_share: u32, vmm: Option<(u32, usize)>) -> Plan {
    let cap = cap.min(100);
    let fair = vmm.map(|(_, peers)| {
        assert!(peers > 0 && peers <= 64);
        VMM_CORE_DIVISOR * peers as u64
    });
    // K/U share a core, so 100% needs no split without a VMM. The VMM
    // may stay behind when vCPU 0 migrates: its time must still be paid.
    if cap == 0 || (cap == 100 && vmm.is_none()) {
        let vmm_period = fair.map_or(0, |d| timeslice.max(MIN_US * d));
        return Plan { period: timeslice, kernel: timeslice, user: timeslice,
            vmm_period, vmm: fair.map_or(0, |d| vmm_period / d) };
    }
    let parts = if vmm.is_some() { 3 } else { 2 };
    let period = timeslice.max(min_period).max((parts * MIN_US * 100).div_ceil(cap as u64))
        .max(fair.map_or(0, |d| MIN_US * d));
    let total = period * cap as u64 / 100;
    let vmm_budget = match (vmm, fair) {
        (Some((share, _)), Some(d)) => (total * share.min(1000) as u64 / 1000)
            .clamp(MIN_US, (period / d).min(total - 2 * MIN_US)),
        _ => 0,
    };
    let guest = total - vmm_budget;
    let kernel = (guest * kernel_share.min(1000) as u64 / 1000).clamp(MIN_US, guest - MIN_US);
    Plan { period, kernel, user: guest - kernel, vmm_period: period, vmm: vmm_budget }
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
/// cap. A period change (new peers, cap or placement) always takes effect.
pub fn changed(old: Plan, new: Plan) -> bool {
    if old.period != new.period || old.vmm_period != new.vmm_period { return true; }
    let total = old.kernel + old.user + old.vmm;
    [old.kernel.abs_diff(new.kernel), old.user.abs_diff(new.user), old.vmm.abs_diff(new.vmm)]
        .iter().any(|d| d * 16 >= total)
}

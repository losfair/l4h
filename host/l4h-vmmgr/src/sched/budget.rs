//! CPU caps and VMM priority policy, independent of seL4. Boosted,
//! uncapped contexts remain work conserving; vCPU 0 pays for its capped VMM.

/// Stay above seL4's minimum budget, derived from the kernel WCET.
pub const MIN_US: u64 = 200;
pub const VMM_SHARE_INIT: u32 = 250;

/// Each round-robin budget expiry takes FL4's serial gate for a timer
/// interrupt. On 64 busy vCPUs (GCE n4a-standard-64), raising the guest
/// timeslice from 5 ms to 20 ms cut those interrupts from 57k/s to 22k/s
/// and raised total guest getpid throughput from 24M/s to 37M/s.
const GUEST_TIMESLICE_US: u64 = 20_000;

pub fn guest_timeslice(host_timeslice: u64) -> u64 {
    host_timeslice.max(GUEST_TIMESLICE_US)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    pub period: u64,
    pub kernel: u64,
    pub user: u64,
    /// SC_U's period: `period`, but where limit_kernel lengthened SC_K's
    /// alone (an uncapped SC_U keeps its round-robin timeslice).
    pub user_period: u64,
    pub vmm_period: u64,
    pub vmm: u64,
}

/// `vmm` is its share of vCPU 0's cap, in permille.
/// `min_period` is the architecture's capped floor.
/// `single_sc`: the vCPU runs on SC_K alone (an HVM guest's, which runs
/// guest kernel and user code alike there): no SC_U to reserve for, and
/// the guest's whole part is `kernel`.
pub fn plan(host_timeslice: u64, min_period: u64, cap: u32, kernel_share: u32, vmm: Option<u32>, single_sc: bool) -> Plan {
    let cap = cap.min(100);
    // K/U share a core, so 100% needs no split without a VMM. The VMM
    // may stay behind when vCPU 0 migrates: its time must still be paid.
    if cap == 0 || (cap == 100 && vmm.is_none()) {
        let period = guest_timeslice(host_timeslice);
        // The VMM takes turns with other host threads at its priority.
        let vmm_period = vmm.map_or(0, |_| host_timeslice);
        // A single-SC vCPU has no user part (Plan::user, below).
        return Plan { period, kernel: period, user: if single_sc { 0 } else { period }, user_period: period,
            vmm_period, vmm: vmm_period };
    }
    let guest_parts: u64 = if single_sc { 1 } else { 2 };
    let parts = guest_parts + u64::from(vmm.is_some());
    let period = host_timeslice.max(min_period).max((parts * MIN_US * 100).div_ceil(cap as u64));
    let total = period * cap as u64 / 100;
    let vmm_budget = match vmm {
        Some(share) => (total * share.min(1000) as u64 / 1000)
            .clamp(MIN_US, total - guest_parts * MIN_US),
        _ => 0,
    };
    let guest = total - vmm_budget;
    if single_sc {
        return Plan { period, kernel: guest, user: 0, user_period: period, vmm_period: period, vmm: vmm_budget };
    }
    let kernel = (guest * kernel_share.min(1000) as u64 / 1000).clamp(MIN_US, guest - MIN_US);
    Plan { period, kernel, user: guest - kernel, user_period: period, vmm_period: period, vmm: vmm_budget }
}

/// A PV vCPU that shares its CPU with an HVM guest's vCPU: SC_K, at
/// PRIO_KERNEL, above the HVM vCPU's PRIO_USER, gets at most 1/`divisor`
/// of the period (0: no limit), so that the guest kernels there
/// (syscalls, interrupts, kernel threads, idle polling, or a hostile
/// kernel spinning), which share a half or a quarter of the CPU between
/// them (sched::kernel_divisors), cannot keep the HVM vCPU off it.  An
/// uncapped vCPU's SC_U keeps its full round-robin budget; a capped one's
/// takes what SC_K gives up, so the cap is unchanged.  A period too short
/// for MIN_US per part grows (as background's for the VMM): SC_K's budget
/// with it, and a capped SC_U's, whose period follows; an uncapped SC_U
/// keeps its round-robin timeslice, not to run longer turns than the
/// HVM vCPU beside it at the same priority.  (DESIGN.md §7.1.)
pub fn limit_kernel(mut p: Plan, divisor: u64) -> Plan {
    if divisor == 0 {
        return p;
    }
    let rr = p.user == p.user_period;
    let period = p.period.max(MIN_US * divisor);
    if period != p.period {
        let scale = |x: u64| (x as u128 * period as u128 / p.period as u128) as u64;
        if !rr {
            p.user = scale(p.user);
            p.user_period = period;
        }
        p.kernel = scale(p.kernel);
        p.period = period;
    }
    let most = period / divisor;
    if p.kernel > most {
        let cut = p.kernel - most;
        p.kernel = most;
        if !rr {
            p.user = (p.user + cut).min(p.user_period);
        }
    }
    p
}

/// Boost recovery requires uninterrupted quiescence. Repeated offenders
/// wait 1, 2, 4, 8, then 16 seconds, so quiet/spin cycles cannot regain a
/// full-priority context every other 100 ms sample. A minute spent boosted
/// without another demotion clears that history; it is not a lifetime penalty.
#[derive(Clone, Copy, Debug, Default)]
pub struct BoostGuard {
    demotions: u8,
    quiet_us: u64,
    boosted_us: u64,
}

impl BoostGuard {
    /// Select the largest consumer (`largest`; beside an HVM vCPU, of the
    /// boosted VMMs on the core, sched::balance), independent of how many
    /// idle VMMs share its core. A lone VMM using otherwise idle CPU is
    /// not pressure.  The core is crowded when its VMMs use 80% of it.
    pub fn boost(&mut self, was: bool, used: u64, core_vmm: u64, largest: u64,
        contended: bool, elapsed: u64, old: Plan) -> bool {
        self.boost_when(was, used, core_vmm, largest, contended, elapsed, old, Crowded::Vmms)
    }

    /// `boost`, crowding judged as `crowded` says.
    #[allow(clippy::too_many_arguments)]
    pub fn boost_when(&mut self, was: bool, used: u64, core_vmm: u64, largest: u64,
        contended: bool, elapsed: u64, old: Plan, crowded: Crowded) -> bool {
        if elapsed == 0 { return was; }
        if was {
            self.quiet_us = 0;
            let crowded = crowded.at(core_vmm, elapsed);
            if contended && crowded && used > 0 && used == largest {
                self.demotions = self.demotions.saturating_add(1);
                self.boosted_us = 0;
                return false;
            }
            self.boosted_us = self.boosted_us.saturating_add(elapsed);
            if self.boosted_us >= 60_000_000 { self.demotions = 0; }
            return true;
        }
        self.boosted_us = 0;
        if used as u128 * old.vmm_period as u128 * 2 < old.vmm as u128 * elapsed as u128 {
            self.quiet_us = self.quiet_us.saturating_add(elapsed);
        } else {
            self.quiet_us = 0;
        }
        let wait = 1_000_000u64 << self.demotions.saturating_sub(1).min(4);
        self.quiet_us >= wait
    }
}

/// When a core is crowded enough for its largest boosted VMM to lose its
/// boost (BoostGuard::boost_when), by the use `crowd` of it over `elapsed`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Crowded {
    /// VMMs using 80% of it.
    Vmms,
    /// Beside an HVM vCPU: VMMs and PV kernels (sched::balance's crowd)
    /// using more than three quarters of it, so that PRIO_USER, which has
    /// the HVM vCPU, keeps a quarter once the VMM is demoted.
    BesideHvm,
}

impl Crowded {
    pub fn at(self, crowd: u64, elapsed: u64) -> bool {
        match self {
            Crowded::Vmms => crowd as u128 * 5 >= elapsed as u128 * 4,
            Crowded::BesideHvm => crowd as u128 * 4 > elapsed as u128 * 3,
        }
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
    // A single-SC vCPU (an HVM guest's) has no user part: SC_K's use is
    // measured against the guest's whole budget, and its split is kept.
    if k * old.period / elapsed * 10 < old.kernel * 9
        && (old.user == 0 || u * old.user_period / elapsed * 10 < old.user * 9)
        && (old.vmm == 0 || v * old.vmm_period / elapsed * 10 < old.vmm * 9) {
        return None;
    }
    let kernel = if old.user == 0 || k + u == 0 { kernel_share } else { (k * 1000 / (k + u)) as u32 };
    let vmm = if old.vmm == 0 { vmm_share } else { (v * 1000 / total) as u32 };
    Some((kernel, vmm))
}

/// Avoid refills and kernel calls for changes below one sixteenth of the
/// cap. A period change always takes effect.
pub fn changed(old: Plan, new: Plan) -> bool {
    if old.period != new.period || old.user_period != new.user_period || old.vmm_period != new.vmm_period { return true; }
    let total = old.kernel + old.user + old.vmm;
    [old.kernel.abs_diff(new.kernel), old.user.abs_diff(new.user), old.vmm.abs_diff(new.vmm)]
        .iter().any(|d| d * 16 >= total)
}

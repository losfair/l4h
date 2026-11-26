//! Placement and migration decisions independent of seL4, for host-side
//! testing (tests/sched.rs, tests/dst-sched.rs).
//!
//! A guest sees each of its *virtual cores* (vCores: the vCPUs placed on
//! one physical core) as one SMT core (abi::BootInfo::vcpu_core). Moves
//! keep that true: a vCPU only changes logical CPU within its physical
//! core, and a vCore only moves to another physical core as a whole,
//! trading places with the guest's vCore there, if any.

use super::topology::{MAX_CPUS, Topology};

/// Guests a sample may name (`Sample::guest` is below it); sched.rs checks
/// it against the host's limit.
pub const MAX_GUESTS: usize = 64;
// A guest's CPUs and its vCPUs are bitmasks of a u128 each, the guests
// one of a u64.
const _: () = assert!(MAX_CPUS <= 128 && MAX_GUESTS <= 64);

const ACTIVE_PCT: u64 = 2;
const LIGHT_PCT: u64 = 50;
/// A CPU whose vCPUs and VMMs used this much of a period had no time to
/// spare: what a vCPU waited there, it waited for the others (Census::busy).
const FULL_PCT: u64 = 90;
/// A CPU's VMMs (an HVM guest's monitor, or PV VMMs) using this much of it
/// count as one busy vCPU there that cannot move: its vCPUs are crowded
/// as by another busy vCPU, and others are not brought to it.
const VMM_BUSY_PCT: u64 = 25;

/// Whether VMMs using `used` of a CPU over `elapsed_us` keep it busy.
fn vmm_busy(used: u64, elapsed_us: u64) -> bool {
    used * 100 >= elapsed_us * VMM_BUSY_PCT
}

pub struct Sample {
    pub guest: usize,
    /// Below 64.
    pub vcpu: usize,
    pub vcore: usize,
    pub cpu: usize,
    pub used: u64,
    /// `used` plus what it waited for its CPU over the period (its steal
    /// time: neither running nor idle), at most the period; `used` for a
    /// capped vCPU, which waits for its own budget.
    pub wanted: u64,
    pub movable: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Move one vCPU between SMT siblings of one physical core.
    IntraCore { guest: usize, vcpu: usize, src: usize, dst: usize },
    /// Move the guest's vCore on physical core `ps` to `pd`, and its vCore
    /// on `pd`, if any, to `ps` (swap_moves).
    VcoreSwap { guest: usize, ps: usize, pd: usize },
}

/// CPUs for a new guest's vCPUs, with their vCores (numbered 0.. in
/// order of first use), into `out`. `load` weighs what each CPU already
/// carries. Spread over physical cores before SMT siblings, preferring the
/// least loaded ones; `stagger` rotates ties so that guests of equal size
/// do not all start on the same cores.
pub fn place(topology: &Topology, load: &[usize; MAX_CPUS], stagger: usize, out: &mut [(usize, usize)]) {
    let cpus = topology.physical().len();
    let mut cpu_load = *load;
    let mut threads = [0usize; MAX_CPUS];
    let mut core_load = [0usize; MAX_CPUS];
    for c in 0..cpus {
        threads[topology.core(c)] += 1;
        core_load[topology.core(c)] += load[c];
    }
    let cores = topology.physical_cores();
    if cores == 0 {
        return;
    }
    let mut depth = [0usize; MAX_CPUS];
    let mut own = [0usize; MAX_CPUS];
    let mut vcore = [usize::MAX; MAX_CPUS];
    let mut vcores = 0;
    for slot in out.iter_mut() {
        let mut best = None;
        // Physical cores in CPU order: `i` is the core's index among them.
        for (i, p) in (0..cpus).filter(|&c| topology.core(c) == c).enumerate() {
            let w = threads[p];
            let tier = if depth[p] < w { depth[p] } else { 1000 + depth[p] };
            let key = (tier, core_load[p] * 100 / w, core_load[p], (i + cores - stagger % cores) % cores);
            if best.is_none_or(|(k, _)| key < k) {
                best = Some((key, p));
            }
        }
        let Some((_, p)) = best else { return };
        let cpu = (0..cpus).filter(|&c| topology.core(c) == p).min_by_key(|&c| (own[c], cpu_load[c])).unwrap();
        if vcore[p] == usize::MAX {
            vcore[p] = vcores;
            vcores += 1;
        }
        depth[p] += 1;
        own[cpu] += 1;
        cpu_load[cpu] += 1;
        core_load[p] += 1;
        *slot = (cpu, vcore[p]);
    }
}

/// Reduce contention between physical cores first, then between their
/// logical CPUs, without breaking up a vCore. Each step strictly reduces
/// the sum of squared busy counts per physical core, else per logical CPU,
/// so equal loads do not trade vCPUs every cooldown.  `vmm_load` is what
/// VMMs used of each CPU over the period (their vCPUs' samples do not
/// say): it is load there, and a busy unit that stays (vmm_busy).
pub fn choose(topology: &Topology, sample: &[Sample], elapsed_us: u64, vmm_load: &[u64; MAX_CPUS]) -> Option<Action> {
    if elapsed_us == 0 {
        return None;
    }
    let cpus = topology.physical().len();
    let mut threads = [0usize; MAX_CPUS];
    for c in 0..cpus {
        threads[topology.core(c)] += 1;
    }
    let census = Census::new(sample, elapsed_us, vmm_load);
    let (load, is_busy) = (census.load, |s: &Sample| census.busy(s));
    let light = |c: usize| load[c] * 100 < elapsed_us * LIGHT_PCT;
    let mut busy = [0i64; MAX_CPUS];
    let mut physical_busy = [0i64; MAX_CPUS];
    let mut physical_load = [0u64; MAX_CPUS];
    for c in 0..cpus {
        let p = topology.core(c);
        physical_load[p] += vmm_load[c];
        if vmm_busy(vmm_load[c], elapsed_us) {
            busy[c] += 1;
            physical_busy[p] += 1;
        }
    }
    let mut guest_cpu = [0u128; MAX_GUESTS];
    let mut guests = 0u64;
    for s in sample {
        let p = topology.core(s.cpu);
        physical_load[p] += s.used;
        guest_cpu[s.guest] |= 1 << s.cpu;
        guests |= 1 << s.guest;
        if is_busy(s) {
            busy[s.cpu] += 1;
            physical_busy[p] += 1;
        }
    }

    // (physical gain, logical gain, no swap, fewer vCPUs moved, not onto
    // the guest's own CPU, idler physical core, idler CPU, moved load)
    type Score = (i64, i64, bool, usize, bool, u64, u64, u64);
    let mut best: Option<(Score, Action)> = None;
    let mut consider = |score: Score, action| {
        if best.as_ref().is_none_or(|(old, _)| score > *old) {
            best = Some((score, action));
        }
    };

    for g in (0..MAX_GUESTS).filter(|&g| guests & 1 << g != 0) {
        // The guest's vCores, by physical core, and its busy vCPUs by CPU.
        let mut size = [0usize; MAX_CPUS];
        let mut vcore = [0usize; MAX_CPUS];
        let mut g_busy = [0i64; MAX_CPUS];
        let mut g_load = [0u64; MAX_CPUS];
        let mut movable = [true; MAX_CPUS];
        let mut cpu_busy = [0i64; MAX_CPUS];
        for s in sample.iter().filter(|s| s.guest == g) {
            let p = topology.core(s.cpu);
            if size[p] == 0 {
                vcore[p] = s.vcore;
            }
            // A split vCore stays where it is.
            movable[p] &= s.movable && vcore[p] == s.vcore;
            size[p] += 1;
            g_load[p] += s.used;
            if is_busy(s) {
                g_busy[p] += 1;
                cpu_busy[s.cpu] += 1;
            }
        }
        // Logical sum-of-squares gain of the swap, the moved busy vCPUs
        // taking the least busy CPUs; whether a crowded source CPU sees a
        // lightly loaded destination.
        let logical = |ps: usize, pd: usize| {
            let mut b = busy;
            let mut old = 0;
            let mut lightly = false;
            for c in (0..cpus).filter(|&c| on_either(topology, c, ps, pd)) {
                old += busy[c] * busy[c];
                if topology.core(c) == ps && cpu_busy[c] > 0 && busy[c] >= 2 {
                    lightly |= (0..cpus).any(|d| topology.core(d) == pd && light(d));
                }
                b[c] -= cpu_busy[c];
            }
            for (from, to) in [(ps, pd), (pd, ps)] {
                for _ in 0..g_busy[from] {
                    let c = (0..cpus).filter(|&c| topology.core(c) == to).min_by_key(|&c| b[c]).unwrap();
                    b[c] += 1;
                }
            }
            let new: i64 = (0..cpus).filter(|&c| on_either(topology, c, ps, pd)).map(|c| b[c] * b[c]).sum();
            (old - new, lightly)
        };
        for ps in (0..cpus).filter(|&p| topology.core(p) == p && g_busy[p] > 0 && movable[p]) {
            for pd in (0..cpus).filter(|&p| topology.core(p) == p && p != ps) {
                if size[pd] > 0 && !movable[pd] {
                    continue;
                }
                // Hybrid CPUs: a vCore wider than a narrower core would
                // stack SMT siblings on one thread.
                if (size[ps] > threads[pd] && threads[pd] < threads[ps])
                    || (size[pd] > threads[ps] && threads[ps] < threads[pd]) {
                    continue;
                }
                let delta = g_busy[ps] - g_busy[pd];
                if delta <= 0 {
                    continue;
                }
                let physical_gain = delta * (physical_busy[ps] - physical_busy[pd] - delta);
                if physical_gain < 0 {
                    continue;
                }
                let (logical_gain, lightly) = logical(ps, pd);
                if physical_gain == 0 && !(logical_gain > 0 || (logical_gain == 0 && lightly)) {
                    continue;
                }
                let min_dst = (0..cpus).filter(|&c| topology.core(c) == pd).map(|c| load[c]).min().unwrap_or(0);
                consider(
                    (physical_gain, logical_gain, size[pd] == 0, usize::MAX - (size[ps] + size[pd]), true,
                        u64::MAX - physical_load[pd], u64::MAX - min_dst, g_load[ps]),
                    Action::VcoreSwap { guest: g, ps, pd },
                );
            }
        }
    }

    for s in sample.iter().filter(|s| s.movable && is_busy(s)) {
        let src = s.cpu;
        let ps = topology.core(src);
        for dst in (0..cpus).filter(|&c| c != src && topology.core(c) == ps) {
            let logical_gain = busy[src] - busy[dst] - 1;
            if logical_gain < 0 || (logical_gain == 0 && !(busy[src] >= 2 && light(dst))) {
                continue;
            }
            consider(
                (0, 2 * logical_gain, true, usize::MAX - 1, guest_cpu[s.guest] & 1 << dst == 0,
                    u64::MAX - physical_load[ps], u64::MAX - load[dst], s.used),
                Action::IntraCore { guest: s.guest, vcpu: s.vcpu, src, dst },
            );
        }
    }
    best.map(|(_, action)| action)
}

/// The moves of `Action::VcoreSwap`, as `(vcpu, dst)`: the guest's vCPUs
/// on `ps`, busiest first, each to the CPU of `pd` with the fewest busy
/// vCPUs (as `choose` assumed), then the least load; then those on `pd`
/// to `ps` likewise.
pub fn swap_moves(topology: &Topology, sample: &[Sample], elapsed_us: u64, vmm_load: &[u64; MAX_CPUS], guest: usize,
    ps: usize, pd: usize, mut each: impl FnMut(usize, usize)) {
    let cpus = topology.physical().len();
    let census = Census::new(sample, elapsed_us, vmm_load);
    let mut cpu_load = [0u64; MAX_CPUS];
    let mut busy = [0u64; MAX_CPUS];
    for c in 0..cpus {
        cpu_load[c] += vmm_load[c];
        busy[c] += u64::from(vmm_busy(vmm_load[c], elapsed_us));
    }
    for s in sample.iter().filter(|s| s.guest != guest || !on_either(topology, s.cpu, ps, pd)) {
        cpu_load[s.cpu] += s.used;
        busy[s.cpu] += u64::from(census.busy(s));
    }
    for (from, to) in [(ps, pd), (pd, ps)] {
        let mut moved = 0u128;
        loop {
            let mut next: Option<&Sample> = None;
            for s in sample.iter().filter(|s| s.guest == guest && topology.core(s.cpu) == from && moved & 1 << s.vcpu == 0) {
                if next.is_none_or(|n| s.used > n.used) {
                    next = Some(s);
                }
            }
            let Some(s) = next else { break };
            moved |= 1 << s.vcpu;
            let dst = (0..cpus).filter(|&c| topology.core(c) == to).min_by_key(|&c| (busy[c], cpu_load[c])).unwrap();
            cpu_load[dst] += s.used + 1;
            busy[dst] += u64::from(census.busy(s));
            each(s.vcpu, dst);
        }
    }
}

/// The capacity other guests leave a vCPU (abi::EventPage::host_cap),
/// smoothed from `old`, given their use of its CPU (`same`, VMMs
/// included) and of its SMT siblings (`sibling`) over `elapsed_us`: half
/// a CPU's worth for its own CPU, about a third for a busy sibling.
pub fn capacity(old: u32, same: u64, sibling: u64, elapsed_us: u64) -> u32 {
    if elapsed_us == 0 {
        return old;
    }
    let (same, sibling) = (same.min(elapsed_us), sibling.min(elapsed_us));
    let raw = 1024u32.saturating_sub((512 * same / elapsed_us) as u32 + (350 * sibling / elapsed_us) as u32)
        .clamp(128, 1024);
    (old + raw) / 2
}

/// Each CPU's load (its VMMs' included), active vCPUs and VMM use over a
/// period.
struct Census {
    load: [u64; MAX_CPUS],
    active: [u64; MAX_CPUS],
    vmm: [u64; MAX_CPUS],
    elapsed_us: u64,
}

impl Census {
    fn new(sample: &[Sample], elapsed_us: u64, vmm_load: &[u64; MAX_CPUS]) -> Self {
        let mut c = Census { load: *vmm_load, active: [0; MAX_CPUS], vmm: *vmm_load, elapsed_us };
        for s in sample {
            c.load[s.cpu] += s.used;
            if s.used * 100 >= elapsed_us * ACTIVE_PCT {
                c.active[s.cpu] += 1;
            }
        }
        c
    }

    /// Half a fair share still recognizes a starved vCPU on a crowded CPU:
    /// a share of what the CPU's VMMs left (a monitor that takes 76% of it
    /// leaves a vCPU using the other 24% busy).  The share is of what the
    /// vCPU wanted, not only of what it got: seL4 does not divide a CPU
    /// evenly between threads of one priority that are preempted and
    /// resumed at different rates (of two PV guests spinning in user mode
    /// on one CPU, one got 84% and the other 16%, for as long as they
    /// shared it), and the one left with less than half its share is the
    /// one that most needs another CPU.
    ///
    /// The wait counts only on a CPU that was in use for the whole period
    /// (FULL_PCT): nothing kept a vCPU off a CPU that had time to spare,
    /// and the steal estimate there is the tail of its wake-ups (a dom0
    /// that ran a command beside an idle guest's vCPU was busy by it, and
    /// was moved from CPU to CPU).
    fn busy(&self, s: &Sample) -> bool {
        let left = self.elapsed_us.saturating_sub(self.vmm[s.cpu]);
        let full = self.load[s.cpu] * 100 >= self.elapsed_us * FULL_PCT;
        let wanted = if full { s.wanted.clamp(s.used, self.elapsed_us.max(s.used)) } else { s.used };
        s.used * 100 >= self.elapsed_us * ACTIVE_PCT && wanted * self.active[s.cpu] * 2 >= left
    }
}

fn on_either(topology: &Topology, cpu: usize, p: usize, q: usize) -> bool {
    topology.core(cpu) == p || topology.core(cpu) == q
}

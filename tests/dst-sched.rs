//! Closed-loop deterministic simulation (DST) of l4h vCPU scheduling, run
//! by tests/run-schedtest.sh. It drives the production placement,
//! balancer and capacity hint (host/l4h-vmmgr/src/sched/policy.rs), CPU
//! budgets (budget.rs) and topology (l4h-task topology.rs) with seeded
//! workloads, seL4 MCS refills, SMT throughput sharing, a hostile VMM and
//! balancer clock jitter, then checks safety invariants (caps, vCores
//! whole, contexts on their vCPU's CPU) and throughput, fairness and
//! starvation bounds. A guest model aware of the topology and capacity
//! hint stands for Linux with arch/l4h's SMT topology; a flat one for an
//! older guest kernel. A host that never balances is the reference.

use std::collections::VecDeque;

#[path = "../host/l4h-task/src/topology.rs"]
mod topology;
#[path = "../host/l4h-vmmgr/src/sched/policy.rs"]
mod policy;
#[path = "../host/l4h-vmmgr/src/sched/budget.rs"]
mod budget;

use topology::{MAX_CPUS, Topology};

const MAX_GUESTS: usize = 64;
const MAX_VCPUS: usize = 64;
const TIMESLICE_US: u64 = 5_000;
const BALANCE_US: u64 = 100_000;
const GUEST_BALANCE_US: u64 = 4_000;
const COOLDOWN: u32 = 10;
const MAX_REFILLS: usize = 16; // GUEST_EXTRA_REFILLS (14) + 2

const PRIO_VMM: u8 = 3;
const PRIO_VMM_FAIR: u8 = 2;
const PRIO_KERNEL: u8 = 1;
const PRIO_USER: u8 = 0;

// ---- Deterministic PRNG (SplitMix64) ----

#[derive(Clone)]
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_add(0x9e37_79b9_7f4a_7c15))
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        if lo >= hi { return lo; }
        lo + (self.next_u64() % (hi - lo))
    }
    fn usize_range(&mut self, lo: usize, hi: usize) -> usize {
        self.range(lo as u64, hi as u64) as usize
    }
    fn chance(&mut self, pct: u64) -> bool {
        (self.next_u64() % 100) < pct
    }
}

// ---- Strategies ----

/// What the guest kernel knows: nothing (an older guest), its vCores, or
/// its vCores and the host's capacity hint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GuestModel {
    Flat,
    Smt,
    Cap,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Strategy {
    /// The production balancer; else vCPUs stay where placed.
    balance: bool,
    guest: GuestModel,
}

impl Strategy {
    fn name(self) -> String {
        format!("{}/{:?}", if self.balance { "balance" } else { "static" }, self.guest)
    }
    fn guest_smt_aware(self) -> bool {
        self.guest != GuestModel::Flat
    }
    fn guest_cap_aware(self) -> bool {
        self.guest == GuestModel::Cap
    }
}

// ---- seL4 MCS SchedContext Model ----

#[derive(Clone, Debug)]
struct SchedCtx {
    cpu: usize,
    budget: u64,
    period: u64,
    refills: VecDeque<(u64, u64)>,
    consumed: u64,
    total_consumed: u64,
    config_calls: u64,
}

impl SchedCtx {
    fn new(cpu: usize, budget: u64, period: u64, now: u64) -> Self {
        let mut refills = VecDeque::with_capacity(MAX_REFILLS);
        refills.push_back((now, budget));
        Self { cpu, budget, period, refills, consumed: 0, total_consumed: 0, config_calls: 0 }
    }

    fn configure(&mut self, cpu: usize, budget: u64, period: u64, now: u64, runnable: bool) {
        assert!(budget >= budget::MIN_US && budget <= period, "invalid SC budget={budget} period={period}");
        self.config_calls += 1;
        let same_shape = self.budget == budget && self.period == period;
        self.cpu = cpu;
        self.budget = budget;
        self.period = period;
        if !runnable {
            self.refills.clear();
            self.refills.push_back((now, budget));
        } else if !same_shape {
            self.compact(now);
            let mut sum = 0u64;
            for r in &mut self.refills {
                let allow = budget.saturating_sub(sum);
                r.1 = r.1.min(allow);
                sum += r.1;
            }
            self.refills.retain(|r| r.1 > 0);
            if self.refills.is_empty() {
                self.refills.push_back((now + period, budget));
            }
        }
    }

    fn compact(&mut self, now: u64) {
        while self.refills.len() >= 2 && self.refills[0].0 <= now && self.refills[1].0 <= now {
            let a = self.refills.pop_front().unwrap();
            let b = self.refills.front_mut().unwrap();
            b.1 = (a.1 + b.1).min(self.budget);
            b.0 = now;
        }
        if let Some(front) = self.refills.front_mut() {
            if front.0 < now {
                front.0 = now;
            }
        }
    }

    fn available(&mut self, now: u64) -> u64 {
        self.compact(now);
        match self.refills.front() {
            Some(&(t, amt)) if t <= now => amt,
            _ => 0,
        }
    }

    fn next_ready(&mut self, now: u64) -> Option<u64> {
        self.compact(now);
        match self.refills.front() {
            Some(&(t, _)) if t > now => Some(t),
            _ => None,
        }
    }

    fn charge(&mut self, now: u64, dt: u64) {
        if dt == 0 { return; }
        self.compact(now);
        self.consumed += dt;
        self.total_consumed += dt;
        if self.budget == self.period {
            return;
        }
        let Some(front) = self.refills.front_mut() else { return };
        let used = dt.min(front.1);
        let ready_t = front.0;
        front.1 -= used;
        let repl_t = ready_t + self.period;
        if front.1 == 0 {
            self.refills.pop_front();
        }
        if self.refills.len() >= MAX_REFILLS {
            if let Some(back) = self.refills.back_mut() {
                back.1 += used;
                back.0 = back.0.max(repl_t);
            }
        } else {
            self.refills.push_back((repl_t, used));
        }
    }

    fn take_consumed(&mut self) -> u64 {
        let c = self.consumed;
        self.consumed = 0;
        c
    }
}

// ---- Guest Tasks & Workload Profiles ----

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TaskMode {
    User,
    Kernel,
}

#[derive(Clone, Debug)]
enum TaskPattern {
    SteadyHog,
    Bursty { run_min: u64, run_max: u64, sleep_min: u64, sleep_max: u64, random_wake_cpu: bool },
    Interactive { run_us: u64, sleep_min: u64, sleep_max: u64 },
    PhaseSwitch { phase_us: u64, io_vmm_ratio: u64 },
}

#[derive(Clone, Debug)]
struct Task {
    pattern: TaskPattern,
    pinned_vcpu: Option<usize>,
    last_vcpu: usize,
    sleeping_until: Option<u64>,
    on_vcpu: Option<usize>,
    enqueued_at: u64,
    first_scheduled: bool,
    rem_burst: u64,
    mode: TaskMode,
    effective_work: u128,
    wakeup_latencies: Vec<u64>,
}

#[derive(Clone, Copy, Debug)]
enum VmmPattern {
    None,
    HonestIo { burst_us: u64, period_us: u64 },
    HostileQuietSpin { quiet_us: u64, spin_us: u64 },
}

#[derive(Clone, Debug)]
struct VcpuState {
    sc_k: SchedCtx,
    sc_u: SchedCtx,
    core: usize,
    vcore: usize,
    cooldown: u32,
    k_share: u32,
    idle_us: u64,
    wall_us: u64,
    run_us: u64,
    steal_ns: u64,
    started_accounting: bool,
    /// SC_K's divisor beside an HVM vCPU (sched::kernel_divisors); 0: none.
    kernel_divisor: u16,
    /// Host-published available capacity hint (0..=1024, like Linux hw_pressure / arch_scale_cpu_capacity)
    host_cap: u32,
}

#[derive(Clone, Debug)]
struct GuestState {
    id: usize,
    active: bool,
    cpu_cap_pct: u32,
    vcpus: Vec<VcpuState>,
    tasks: Vec<Task>,
    has_vmm: bool,
    vmm_sc: Option<SchedCtx>,
    vmm_pattern: VmmPattern,
    vmm_limits: Option<(usize, budget::Plan)>,
    vmm_share: u32,
    vmm_boosted: bool,
    vmm_limited: bool,
    vmm_guard: budget::BoostGuard,
    vmm_runnable_until: u64,
    vmm_next_wake: u64,
    /// Queue for work charged to SC_K (PV kernel or the entire HVM vCPU).
    sc_k_prio: usize,
    /// An HVM guest (Sim::make_hvm): its vCPUs run on SC_K alone, at
    /// PRIO_USER, and PV vCPUs beside them have SC_K limited.
    hvm: bool,
    fairness_group: u8,
    effective_work: u128,
    window_work: u128,
    window_consumed_total: u64,
    window_vmm_work: u128,
    cap_window_consumed: u64,
    cap_window_elapsed: u64,
    tlb_flushes: u64,
    next_guest_balance: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ThreadId {
    Vmm(usize),
    VcpuKernel(usize, usize),
    VcpuUser(usize, usize),
}

// ---- Simulation Engine ----

struct Sim {
    strategy: Strategy,
    topology: Topology,
    cpus: usize,
    phys_cores: Vec<usize>,
    guests: Vec<Option<GuestState>>,
    guest_stagger_cursor: usize,
    rng: Rng,
    now: u64,
    warmup_us: u64,
    last_balance: u64,
    next_balance: u64,
    balance_jitter: bool,
    // Global stats (post-warmup)
    total_effective_work: u128,
    total_busy_thread_us: u128,
    wasted_smt_us: u128,
    migrations: u64,
    vcore_swaps: u64,
    intra_core_moves: u64,
    tlb_flushes: u64,
    balance_ticks_recorded: u64,
    topo_drift_ticks: u64,
    // Per logical CPU scheduler state
    cpu_running: Vec<Option<(ThreadId, u64)>>,
    cpu_rr: Vec<[VecDeque<ThreadId>; 4]>,
}

impl Sim {
    fn new(strategy: Strategy, topology: Topology, seed: u64, warmup_us: u64) -> Self {
        let cpus = topology.physical().len();
        let mut phys_cores = Vec::new();
        for c in 0..cpus {
            let p = topology.core(c);
            if p == c {
                phys_cores.push(p);
            }
        }
        Self {
            strategy,
            topology,
            cpus,
            phys_cores,
            guests: (0..MAX_GUESTS).map(|_| None).collect(),
            guest_stagger_cursor: 0,
            rng: Rng::new(seed),
            now: 0,
            warmup_us,
            last_balance: 0,
            next_balance: BALANCE_US,
            balance_jitter: false,
            total_effective_work: 0,
            total_busy_thread_us: 0,
            wasted_smt_us: 0,
            migrations: 0,
            vcore_swaps: 0,
            intra_core_moves: 0,
            tlb_flushes: 0,
            balance_ticks_recorded: 0,
            topo_drift_ticks: 0,
            cpu_running: vec![None; cpus],
            cpu_rr: (0..cpus).map(|_| Default::default()).collect(),
        }
    }

    /// sched::place: vCPUs weigh one, VMMs two.
    fn place(&mut self, nr_vcpus: usize) -> Vec<(usize, usize)> {
        let mut load = [0usize; MAX_CPUS];
        for g in self.guests.iter().flatten().filter(|g| g.active) {
            for vc in &g.vcpus {
                load[vc.core] += 1;
            }
            if let Some((core, _)) = g.vmm_limits {
                load[core] += 2;
            }
        }
        let mut out = vec![(0, 0); nr_vcpus];
        policy::place(&self.topology, &load, self.guest_stagger_cursor, &mut out);
        self.guest_stagger_cursor += 1;
        out
    }

    fn spawn_guest(
        &mut self,
        id: usize,
        nr_vcpus: usize,
        cpu_cap_pct: u32,
        vmm_pattern: VmmPattern,
        tasks: Vec<Task>,
        fairness_group: u8,
    ) {
        let placements = self.place(nr_vcpus);

        let has_vmm = !matches!(vmm_pattern, VmmPattern::None);
        let p0 = budget::plan(TIMESLICE_US, 0, cpu_cap_pct, 500, has_vmm.then_some(budget::VMM_SHARE_INIT), false);
        let p_other = budget::plan(TIMESLICE_US, 0, cpu_cap_pct, 500, None, false);

        let mut vcpus = Vec::with_capacity(nr_vcpus);
        for (v, &(cpu, vcore)) in placements.iter().enumerate() {
            let pl = if v == 0 { p0 } else { p_other };
            vcpus.push(VcpuState {
                sc_k: SchedCtx::new(cpu, pl.kernel, pl.period, self.now),
                sc_u: SchedCtx::new(cpu, pl.user, pl.period, self.now),
                core: cpu,
                vcore,
                cooldown: 0,
                k_share: 500,
                idle_us: 0,
                wall_us: 0,
                run_us: 0,
                steal_ns: 0,
                started_accounting: false,
                kernel_divisor: 0,
                host_cap: 1024,
            });
        }

        let vmm_sc = if has_vmm {
            Some(SchedCtx::new(vcpus[0].core, p0.vmm, p0.vmm_period, self.now))
        } else {
            None
        };
        let vmm_limits = if has_vmm { Some((vcpus[0].core, p0)) } else { None };
        let vmm_next_wake = match vmm_pattern {
            VmmPattern::HostileQuietSpin { quiet_us, .. } => self.now + quiet_us,
            VmmPattern::HonestIo { period_us, .. } => self.now + self.rng.range(0, period_us.max(1)),
            VmmPattern::None => u64::MAX,
        };

        let g = GuestState {
            id,
            active: true,
            cpu_cap_pct,
            vcpus,
            tasks,
            has_vmm,
            vmm_sc,
            vmm_pattern,
            vmm_limits,
            vmm_share: budget::VMM_SHARE_INIT,
            vmm_boosted: true,
            vmm_limited: false,
            vmm_guard: budget::BoostGuard::default(),
            vmm_runnable_until: 0,
            vmm_next_wake,
            sc_k_prio: PRIO_KERNEL as usize,
            hvm: false,
            fairness_group,
            effective_work: 0,
            window_work: 0,
            window_consumed_total: 0,
            window_vmm_work: 0,
            cap_window_consumed: 0,
            cap_window_elapsed: 0,
            tlb_flushes: 0,
            next_guest_balance: self.now + GUEST_BALANCE_US,
        };
        self.guests[id] = Some(g);
        self.protect_vmms();
    }

    /// Guest `id` as an HVM guest: one thread per vCPU, on SC_K at
    /// PRIO_USER (hvm::PRIO_VCPU) for guest kernel and user code alike.
    fn make_hvm(&mut self, id: usize) {
        let g = self.guests[id].as_mut().unwrap();
        g.hvm = true;
        g.sc_k_prio = (l4h_host::hvm::PRIO_VCPU - l4h_abi::PRIO_USER) as usize;
        for t in &mut g.tasks { t.mode = TaskMode::Kernel; }
        self.protect_vmms();
    }

    fn destroy_guest(&mut self, id: usize) {
        self.guests[id] = None;
        for c in 0..self.cpus {
            if let Some((t, _)) = self.cpu_running[c] {
                if thread_guest(t) == id {
                    self.cpu_running[c] = None;
                }
            }
            for q in &mut self.cpu_rr[c] {
                q.retain(|t| thread_guest(*t) != id);
            }
        }
        self.protect_vmms();
    }

    fn replace_tasks(&mut self, id: usize, tasks: Vec<Task>) {
        if let Some(g) = self.guests[id].as_mut() {
            g.tasks = tasks;
        }
    }

    /// The CPUs HVM vCPUs run on (sched::hvm_cpus).
    fn hvm_cpus(&self) -> u64 {
        let mut cpus = 0u64;
        for g in self.guests.iter().flatten().filter(|g| g.active && g.hvm) {
            for v in &g.vcpus { cpus |= 1u64 << v.core; }
        }
        cpus
    }

    /// sched::kernel_divisors: per CPU with an HVM vCPU, the PV kernels
    /// there share half of it, a quarter where a VMM runs.  `moves`
    /// (guest, vCPU, CPU) are counted at their destinations too.
    fn kernel_divisors(&self, moves: &[(usize, usize, usize)]) -> [u16; MAX_CPUS] {
        let hvm = self.hvm_cpus();
        let mut pv = [0u16; MAX_CPUS];
        let mut vmm = [false; MAX_CPUS];
        for g in self.guests.iter().flatten().filter(|g| g.active) {
            if !g.hvm {
                for v in &g.vcpus { pv[v.core] += 1; }
            }
            if g.has_vmm { vmm[g.vmm_limits.unwrap().0] = true; }
        }
        for &(gid, v, dst) in moves {
            let g = self.guests[gid].as_ref().unwrap();
            if !g.hvm && g.vcpus[v].core != dst { pv[dst] += 1; }
        }
        let mut div = [0u16; MAX_CPUS];
        for c in 0..MAX_CPUS {
            if hvm & (1u64 << c) != 0 && pv[c] != 0 {
                div[c] = pv[c] * if vmm[c] { 4 } else { 2 };
            }
        }
        div
    }

    /// sched::limit_kernels: PV vCPUs whose contexts change are
    /// reconfigured; vCPU 0 with a VMM is left to the VMM's plan below.
    fn limit_kernels(&mut self) {
        let div = self.kernel_divisors(&[]);
        let now = self.now;
        for g in self.guests.iter_mut().flatten().filter(|g| g.active && !g.hvm) {
            for v in 0..g.vcpus.len() {
                let want = div[g.vcpus[v].core];
                if want == g.vcpus[v].kernel_divisor { continue; }
                let before = vcpu_plan(g, v, g.vcpus[v].k_share, None);
                g.vcpus[v].kernel_divisor = want;
                if v == 0 && g.has_vmm { continue; }
                let p = vcpu_plan(g, v, g.vcpus[v].k_share, None);
                if (p.period, p.kernel, p.user, p.user_period)
                    == (before.period, before.kernel, before.user, before.user_period) { continue; }
                let core = g.vcpus[v].core;
                g.vcpus[v].sc_k.configure(core, p.kernel, p.period, now, true);
                g.vcpus[v].sc_u.configure(core, sc_u_budget(g.hvm, p), p.user_period, now, true);
            }
        }
    }

    fn protect_vmms(&mut self) {
        let mut occupied = [0u64; MAX_CPUS];
        for g in self.guests.iter().flatten().filter(|g| g.active) {
            for v in &g.vcpus {
                occupied[v.core] |= 1u64 << g.id;
            }
        }
        let mut backgrounds = [0usize; MAX_CPUS];
        for g in self.guests.iter_mut().flatten().filter(|g| g.active && g.has_vmm) {
            let core = g.vmm_limits.unwrap().0;
            g.vmm_limited = !g.vmm_boosted && (occupied[core] & !(1u64 << g.id)) != 0;
            if g.vmm_limited {
                backgrounds[core] += 1;
            }
        }
        self.limit_kernels();
        for g in self.guests.iter_mut().flatten().filter(|g| g.active && g.has_vmm) {
            let (core, old) = g.vmm_limits.unwrap();
            let mut p = vcpu_plan(g, 0, g.vcpus[0].k_share, Some(g.vmm_share));
            if g.vmm_limited {
                p = budget::background(p, backgrounds[core]);
            }
            if p != old {
                let v0_core = g.vcpus[0].core;
                if (p.period, p.kernel, p.user, p.user_period) != (old.period, old.kernel, old.user, old.user_period) {
                    g.vcpus[0].sc_k.configure(v0_core, p.kernel, p.period, self.now, true);
                    g.vcpus[0].sc_u.configure(v0_core, sc_u_budget(g.hvm, p), p.user_period, self.now, true);
                }
                if (p.vmm_period, p.vmm) != (old.vmm_period, old.vmm) {
                    let vmm_runnable = self.now < g.vmm_runnable_until;
                    g.vmm_sc.as_mut().unwrap().configure(core, p.vmm, p.vmm_period, self.now, vmm_runnable);
                }
                g.vmm_limits = Some((core, p));
            }
        }
    }

    fn guest_pick_vcpu(g: &GuestState, smt_aware: bool, cap_aware: bool, last: usize, pinned: Option<usize>) -> usize {
        if let Some(v) = pinned {
            return v % g.vcpus.len();
        }
        let n = g.vcpus.len();
        let mut vcpu_nr = [0usize; MAX_VCPUS];
        let mut vcore_nr = [0usize; MAX_CPUS];
        for t in &g.tasks {
            if let Some(v) = t.on_vcpu {
                vcpu_nr[v] += 1;
                vcore_nr[g.vcpus[v].vcore] += 1;
            }
        }
        let last = last % n;

        if cap_aware {
            // Capacity-aware + SMT-aware selection (mirrors Linux select_idle_core + hw_pressure):
            // Rule 1: An idle vCPU (vcpu_nr == 0) ALWAYS beats a busy vCPU (never queue behind
            //         our own running task when another vCPU is idle!).
            // Rule 2: Among idle vCPUs, maximize marginal effective capacity:
            //         idle vCore -> host_cap[v]; idle sibling on busy vCore -> host_cap[v] * 650 / 1000.
            // Rule 3: Break ties by affinity to `last` to avoid cross-guest thundering herd.
            let mut best_v = last;
            let mut best_key = (0u8, 0u32, 0u32);
            for off in 0..n {
                let v = (last + off) % n;
                let hc = g.vcpus[v].host_cap;
                let idle_tier = if vcpu_nr[v] == 0 { 1u8 } else { 0u8 };
                let marginal = if vcore_nr[g.vcpus[v].vcore] == 0 {
                    hc
                } else if vcpu_nr[v] == 0 {
                    hc * 650 / 1000
                } else {
                    hc / (vcpu_nr[v] as u32 + 1)
                };
                // Bucket marginal capacity to 64-unit steps (~6%) so `last` affinity wins near-ties
                let bucket = marginal / 64;
                let key = (idle_tier, bucket, if v == last { 1 } else { 0 });
                if key > best_key {
                    best_key = key;
                    best_v = v;
                }
            }
            return best_v;
        }

        if smt_aware {
            if vcore_nr[g.vcpus[last].vcore] == 0 {
                return last;
            }
            for off in 1..n {
                let v = (last + off) % n;
                if vcore_nr[g.vcpus[v].vcore] == 0 {
                    return v;
                }
            }
        }
        if vcpu_nr[last] == 0 {
            return last;
        }
        for off in 1..n {
            let v = (last + off) % n;
            if vcpu_nr[v] == 0 {
                return v;
            }
        }
        let mut best_v = last;
        let mut best_key = (usize::MAX, usize::MAX);
        for off in 0..n {
            let v = (last + off) % n;
            let key = if smt_aware {
                (vcore_nr[g.vcpus[v].vcore], vcpu_nr[v])
            } else {
                (vcpu_nr[v], 0)
            };
            if key < best_key {
                best_key = key;
                best_v = v;
            }
        }
        best_v
    }

    fn guest_periodic_balance(&mut self, gid: usize) {
        let smt_aware = self.strategy.guest_smt_aware();
        let cap_aware = self.strategy.guest_cap_aware();
        let Some(g) = self.guests[gid].as_mut() else { return };
        if !g.active || g.vcpus.len() < 2 { return; }
        let n = g.vcpus.len();
        let mut vcpu_nr = [0usize; MAX_VCPUS];
        let mut vcore_nr = [0usize; MAX_CPUS];
        for t in &g.tasks {
            if let Some(v) = t.on_vcpu {
                vcpu_nr[v] += 1;
                vcore_nr[g.vcpus[v].vcore] += 1;
            }
        }

        if cap_aware {
            // Pull a non-pinned task off a lower-marginal-capacity vCPU onto a strictly better idle vCPU
            let mut best_dst = None;
            let mut best_dst_cap = 0u32;
            for v in 0..n {
                if vcpu_nr[v] > 0 { continue; }
                let m = if vcore_nr[g.vcpus[v].vcore] == 0 {
                    g.vcpus[v].host_cap
                } else {
                    g.vcpus[v].host_cap * 650 / 1000
                };
                if m > best_dst_cap {
                    best_dst_cap = m;
                    best_dst = Some(v);
                }
            }
            if let Some(dst) = best_dst {
                for ti in 0..g.tasks.len() {
                    if g.tasks[ti].pinned_vcpu.is_some() { continue; }
                    if let Some(v) = g.tasks[ti].on_vcpu {
                        let cur = if vcpu_nr[v] >= 2 {
                            g.vcpus[v].host_cap / vcpu_nr[v] as u32
                        } else if vcore_nr[g.vcpus[v].vcore] >= 2 {
                            g.vcpus[v].host_cap * 650 / 1000
                        } else {
                            g.vcpus[v].host_cap
                        };
                        if best_dst_cap >= cur + 150 {
                            g.tasks[ti].on_vcpu = Some(dst);
                            g.tasks[ti].last_vcpu = dst;
                            return;
                        }
                    }
                }
            }
            return;
        }

        if smt_aware {
            if let Some(idle_v) = (0..n).find(|&v| vcore_nr[g.vcpus[v].vcore] == 0) {
                for ti in 0..g.tasks.len() {
                    if g.tasks[ti].pinned_vcpu.is_some() { continue; }
                    if let Some(v) = g.tasks[ti].on_vcpu {
                        let vc = g.vcpus[v].vcore;
                        if vcore_nr[vc] >= 2 {
                            g.tasks[ti].on_vcpu = Some(idle_v);
                            g.tasks[ti].last_vcpu = idle_v;
                            return;
                        }
                    }
                }
            }
        }
        if let Some(idle_v) = (0..n).find(|&v| vcpu_nr[v] == 0) {
            for ti in 0..g.tasks.len() {
                if g.tasks[ti].pinned_vcpu.is_some() { continue; }
                if let Some(v) = g.tasks[ti].on_vcpu {
                    if vcpu_nr[v] >= 2 {
                        g.tasks[ti].on_vcpu = Some(idle_v);
                        g.tasks[ti].last_vcpu = idle_v;
                        return;
                    }
                }
            }
        }
    }

    fn wake_tasks_and_vmms(&mut self) {
        let now = self.now;
        let smt_aware = self.strategy.guest_smt_aware();
        for gid in 0..MAX_GUESTS {
            if self.guests[gid].as_ref().is_none_or(|g| !g.active) {
                continue;
            }
            {
                let g = self.guests[gid].as_mut().unwrap();
                if g.has_vmm && now >= g.vmm_next_wake {
                    match g.vmm_pattern {
                        VmmPattern::HonestIo { burst_us, period_us } => {
                            g.vmm_runnable_until = now + burst_us;
                            g.vmm_next_wake = now + period_us;
                        }
                        VmmPattern::HostileQuietSpin { quiet_us, spin_us } => {
                            g.vmm_runnable_until = now + spin_us;
                            g.vmm_next_wake = now + spin_us + quiet_us;
                        }
                        VmmPattern::None => {}
                    }
                }
            }
            let (ntasks, nvcpus) = {
                let g = self.guests[gid].as_ref().unwrap();
                (g.tasks.len(), g.vcpus.len())
            };
            for ti in 0..ntasks {
                let should_wake = self.guests[gid].as_ref().unwrap().tasks[ti]
                    .sleeping_until
                    .is_some_and(|t| t <= now);
                if !should_wake {
                    continue;
                }
                let (pattern, last, pinned) = {
                    let t = &self.guests[gid].as_ref().unwrap().tasks[ti];
                    (t.pattern.clone(), t.last_vcpu, t.pinned_vcpu)
                };
                let (burst, wake_hint) = match pattern {
                    TaskPattern::SteadyHog => (u64::MAX / 2, last),
                    TaskPattern::Bursty { run_min, run_max, random_wake_cpu, .. } => {
                        let b = self.rng.range(run_min, run_max);
                        let h = if random_wake_cpu { self.rng.usize_range(0, nvcpus) } else { last };
                        (b, h)
                    }
                    TaskPattern::Interactive { run_us, .. } => (run_us, last),
                    TaskPattern::PhaseSwitch { phase_us, .. } => (phase_us, last),
                };
                let cap_aware = self.strategy.guest_cap_aware();
                let target_v = Self::guest_pick_vcpu(self.guests[gid].as_ref().unwrap(), smt_aware, cap_aware, wake_hint, pinned);
                let g = self.guests[gid].as_mut().unwrap();
                let t = &mut g.tasks[ti];
                t.sleeping_until = None;
                t.on_vcpu = Some(target_v);
                t.last_vcpu = target_v;
                t.enqueued_at = now;
                t.first_scheduled = false;
                t.rem_burst = burst;
                t.mode = match pattern {
                    TaskPattern::PhaseSwitch { .. } => {
                        if self.rng.chance(50) { TaskMode::Kernel } else { TaskMode::User }
                    }
                    _ => TaskMode::User,
                };
            }
            if self.guests[gid].as_ref().unwrap().next_guest_balance <= now {
                self.guests[gid].as_mut().unwrap().next_guest_balance = now + GUEST_BALANCE_US;
                self.guest_periodic_balance(gid);
            }
        }
    }

    fn thread_runnable(&mut self, tid: ThreadId) -> bool {
        let now = self.now;
        match tid {
            ThreadId::Vmm(gid) => {
                let Some(g) = self.guests[gid].as_mut() else { return false };
                g.active && g.has_vmm && now < g.vmm_runnable_until && g.vmm_sc.as_mut().unwrap().available(now) > 0
            }
            ThreadId::VcpuKernel(gid, v) => {
                let Some(g) = self.guests[gid].as_mut() else { return false };
                if !g.active || v >= g.vcpus.len() { return false; }
                let has_k = g.tasks.iter().any(|t| t.on_vcpu == Some(v) && t.mode == TaskMode::Kernel);
                has_k && g.vcpus[v].sc_k.available(now) > 0
            }
            ThreadId::VcpuUser(gid, v) => {
                let Some(g) = self.guests[gid].as_mut() else { return false };
                if !g.active || v >= g.vcpus.len() { return false; }
                let has_u = g.tasks.iter().any(|t| t.on_vcpu == Some(v) && t.mode == TaskMode::User);
                has_u && g.vcpus[v].sc_u.available(now) > 0
            }
        }
    }

    fn thread_cpu_and_prio(&self, tid: ThreadId) -> Option<(usize, usize)> {
        match tid {
            ThreadId::Vmm(gid) => {
                let g = self.guests[gid].as_ref()?;
                let core = g.vmm_limits?.0;
                let prio = if g.vmm_boosted { PRIO_VMM } else { PRIO_VMM_FAIR } as usize;
                Some((core, prio))
            }
            ThreadId::VcpuKernel(gid, v) => {
                let g = self.guests[gid].as_ref()?;
                Some((g.vcpus.get(v)?.core, g.sc_k_prio))
            }
            ThreadId::VcpuUser(gid, v) => {
                let g = self.guests[gid].as_ref()?;
                Some((g.vcpus.get(v)?.core, PRIO_USER as usize))
            }
        }
    }

    fn sync_ready_queues(&mut self) {
        let now = self.now;
        let mut want_present: Vec<(usize, usize, ThreadId)> = Vec::new();
        for gid in 0..MAX_GUESTS {
            let Some(g) = self.guests[gid].as_mut() else { continue };
            if !g.active { continue; }
            if g.has_vmm && now < g.vmm_runnable_until && g.vmm_sc.as_mut().unwrap().available(now) > 0 {
                let core = g.vmm_limits.unwrap().0;
                let prio = if g.vmm_boosted { PRIO_VMM } else { PRIO_VMM_FAIR } as usize;
                want_present.push((core, prio, ThreadId::Vmm(gid)));
            }
            for v in 0..g.vcpus.len() {
                let has_k = g.tasks.iter().any(|t| t.on_vcpu == Some(v) && t.mode == TaskMode::Kernel);
                let has_u = g.tasks.iter().any(|t| t.on_vcpu == Some(v) && t.mode == TaskMode::User);
                let core = g.vcpus[v].core;
                if has_k && g.vcpus[v].sc_k.available(now) > 0 {
                    want_present.push((core, g.sc_k_prio, ThreadId::VcpuKernel(gid, v)));
                } else if has_u && g.vcpus[v].sc_u.available(now) > 0 {
                    want_present.push((core, PRIO_USER as usize, ThreadId::VcpuUser(gid, v)));
                }
            }
        }

        for c in 0..self.cpus {
            if let Some((t, _)) = self.cpu_running[c] {
                let ok = self.thread_cpu_and_prio(t).is_some_and(|(tc, _)| tc == c) && self.thread_runnable(t);
                if !ok {
                    self.cpu_running[c] = None;
                }
            }
            for p in 0..4 {
                let mut keep = VecDeque::new();
                while let Some(t) = self.cpu_rr[c][p].pop_front() {
                    let ok = self.thread_cpu_and_prio(t).is_some_and(|(tc, tp)| tc == c && tp == p)
                        && self.thread_runnable(t);
                    if ok && !keep.contains(&t) {
                        keep.push_back(t);
                    }
                }
                self.cpu_rr[c][p] = keep;
            }
        }

        for (c, p, t) in want_present {
            let is_running = self.cpu_running[c].is_some_and(|(rt, _)| rt == t);
            if !is_running && !self.cpu_rr[c][p].contains(&t) {
                self.cpu_rr[c][p].push_back(t);
            }
        }

        for c in 0..self.cpus {
            let mut cur_prio = None;
            if let Some((rt, ts_end)) = self.cpu_running[c] {
                if let Some((_, rp)) = self.thread_cpu_and_prio(rt) {
                    if now >= ts_end {
                        self.cpu_running[c] = None;
                        self.cpu_rr[c][rp].push_back(rt);
                    } else {
                        cur_prio = Some((rt, rp));
                    }
                }
            }
            let highest_q = (0..4).rev().find(|&p| !self.cpu_rr[c][p].is_empty());
            match (cur_prio, highest_q) {
                (Some((rt, rp)), Some(hp)) if hp > rp => {
                    self.cpu_rr[c][rp].push_front(rt);
                    let next = self.cpu_rr[c][hp].pop_front().unwrap();
                    self.cpu_running[c] = Some((next, now + TIMESLICE_US));
                }
                (None, Some(hp)) => {
                    let next = self.cpu_rr[c][hp].pop_front().unwrap();
                    self.cpu_running[c] = Some((next, now + TIMESLICE_US));
                }
                _ => {}
            }
        }
    }

    fn next_event_time(&mut self, limit: u64) -> u64 {
        let now = self.now;
        let mut next = limit.min(self.next_balance);
        for c in 0..self.cpus {
            if let Some((t, ts_end)) = self.cpu_running[c] {
                next = next.min(ts_end);
                match t {
                    ThreadId::Vmm(gid) => {
                        let g = self.guests[gid].as_mut().unwrap();
                        let avail = g.vmm_sc.as_mut().unwrap().available(now);
                        next = next.min(now + avail).min(g.vmm_runnable_until);
                    }
                    ThreadId::VcpuKernel(gid, v) => {
                        let g = self.guests[gid].as_mut().unwrap();
                        let avail = g.vcpus[v].sc_k.available(now);
                        next = next.min(now + avail);
                        for task in &g.tasks {
                            if task.on_vcpu == Some(v) && task.mode == TaskMode::Kernel {
                                next = next.min(now.saturating_add(task.rem_burst));
                            }
                        }
                    }
                    ThreadId::VcpuUser(gid, v) => {
                        let g = self.guests[gid].as_mut().unwrap();
                        let avail = g.vcpus[v].sc_u.available(now);
                        next = next.min(now + avail);
                        for task in &g.tasks {
                            if task.on_vcpu == Some(v) && task.mode == TaskMode::User {
                                next = next.min(now.saturating_add(task.rem_burst));
                            }
                        }
                    }
                }
            }
        }
        for g in self.guests.iter_mut().flatten().filter(|g| g.active) {
            next = next.min(g.next_guest_balance);
            if g.has_vmm {
                next = next.min(g.vmm_next_wake);
                if let Some(rt) = g.vmm_sc.as_mut().unwrap().next_ready(now) {
                    next = next.min(rt);
                }
            }
            for v in &mut g.vcpus {
                if let Some(rt) = v.sc_k.next_ready(now) { next = next.min(rt); }
                if let Some(rt) = v.sc_u.next_ready(now) { next = next.min(rt); }
            }
            for t in &g.tasks {
                if let Some(wt) = t.sleeping_until {
                    next = next.min(wt);
                }
            }
        }
        next.max(now + 1)
    }

    fn advance(&mut self, dt: u64) {
        let now = self.now;
        let record = now >= self.warmup_us;

        let mut active_phys = [0u64; MAX_CPUS];
        for c in 0..self.cpus {
            if self.cpu_running[c].is_some() {
                active_phys[self.topology.core(c)] += 1;
            }
        }
        let idle_phys_exists = self.phys_cores.iter().any(|&p| active_phys[p] == 0);
        if record {
            for &p in &self.phys_cores {
                let a = active_phys[p];
                self.total_busy_thread_us += (a * dt) as u128;
                if a >= 2 && idle_phys_exists {
                    self.wasted_smt_us += ((a - 1) * dt) as u128;
                }
            }
        }

        for g in self.guests.iter_mut().flatten().filter(|g| g.active) {
            for v in 0..g.vcpus.len() {
                if g.vcpus[v].started_accounting {
                    let has_task = g.tasks.iter().any(|t| t.on_vcpu == Some(v));
                    if !has_task {
                        g.vcpus[v].idle_us += dt;
                    }
                }
            }
        }

        let running = self.cpu_running.clone();
        for c in 0..self.cpus {
            let Some((tid, _)) = running[c] else { continue };
            let p = self.topology.core(c);
            let a = active_phys[p];
            let eff_rate: u64 = match a {
                0 | 1 => 1000,
                2 => 650,
                n => 1300 / n,
            };
            let work = (dt as u128) * (eff_rate as u128);

            match tid {
                ThreadId::Vmm(gid) => {
                    let g = self.guests[gid].as_mut().unwrap();
                    g.vmm_sc.as_mut().unwrap().charge(now, dt);
                    if record {
                        g.window_vmm_work += work;
                        g.window_consumed_total += dt;
                    }
                    g.cap_window_consumed += dt;
                }
                ThreadId::VcpuKernel(gid, v) | ThreadId::VcpuUser(gid, v) => {
                    let is_k = matches!(tid, ThreadId::VcpuKernel(_, _));
                    let g = self.guests[gid].as_mut().unwrap();
                    g.vcpus[v].started_accounting = true;
                    if is_k {
                        g.vcpus[v].sc_k.charge(now, dt);
                    } else {
                        g.vcpus[v].sc_u.charge(now, dt);
                    }
                    g.effective_work += work;
                    if record {
                        g.window_work += work;
                        g.window_consumed_total += dt;
                        self.total_effective_work += work;
                    }
                    g.cap_window_consumed += dt;

                    let target_mode = if is_k { TaskMode::Kernel } else { TaskMode::User };
                    let mut finished_task: Option<(usize, TaskPattern)> = None;
                    for (ti, t) in g.tasks.iter_mut().enumerate() {
                        if t.on_vcpu == Some(v) && t.mode == target_mode {
                            if !t.first_scheduled {
                                t.first_scheduled = true;
                                if record {
                                    t.wakeup_latencies.push(now.saturating_sub(t.enqueued_at));
                                }
                            }
                            t.effective_work += work;
                            let prog = ((dt * eff_rate) / 1000).max(1);
                            t.rem_burst = t.rem_burst.saturating_sub(prog);
                            if t.rem_burst == 0 {
                                finished_task = Some((ti, t.pattern.clone()));
                            }
                            break;
                        }
                    }
                    if let Some((ti, pat)) = finished_task {
                        let sleep_dt = match pat {
                            TaskPattern::SteadyHog => 0,
                            TaskPattern::Bursty { sleep_min, sleep_max, .. } => self.rng.range(sleep_min, sleep_max),
                            TaskPattern::Interactive { sleep_min, sleep_max, .. } => self.rng.range(sleep_min, sleep_max),
                            TaskPattern::PhaseSwitch { .. } => 0,
                        };
                        let g = self.guests[gid].as_mut().unwrap();
                        let t = &mut g.tasks[ti];
                        if sleep_dt > 0 {
                            t.on_vcpu = None;
                            t.sleeping_until = Some(now + dt + sleep_dt);
                        } else {
                            match pat {
                                TaskPattern::PhaseSwitch { phase_us, io_vmm_ratio } => {
                                    t.rem_burst = phase_us;
                                    t.mode = if t.mode == TaskMode::User { TaskMode::Kernel } else { TaskMode::User };
                                    if t.mode == TaskMode::Kernel && g.has_vmm && io_vmm_ratio > 0 {
                                        g.vmm_runnable_until = (now + dt + phase_us * io_vmm_ratio / 100).max(g.vmm_runnable_until);
                                    }
                                }
                                _ => {
                                    t.rem_burst = u64::MAX / 2;
                                }
                            }
                        }
                    }
                }
            }
        }

        self.now += dt;
    }

    fn has_topology_drift(&self) -> bool {
        if !self.strategy.guest_smt_aware() {
            return false;
        }
        for g in self.guests.iter().flatten().filter(|g| g.active) {
            let mut vcore_to_phys = [None::<usize>; MAX_CPUS];
            let mut phys_to_vcore = [None::<usize>; MAX_CPUS];
            for vc in &g.vcpus {
                let p = self.topology.core(vc.core);
                if let Some(prev) = vcore_to_phys[vc.vcore] {
                    if prev != p { return true; }
                } else {
                    vcore_to_phys[vc.vcore] = Some(p);
                }
                if let Some(prev) = phys_to_vcore[p] {
                    if prev != vc.vcore { return true; }
                } else {
                    phys_to_vcore[p] = Some(vc.vcore);
                }
            }
        }
        false
    }

    fn execute_balance(&mut self, elapsed_us: u64) {
        if elapsed_us == 0 { return; }
        let record = self.now >= self.warmup_us;

        if record {
            self.balance_ticks_recorded += 1;
            if self.has_topology_drift() {
                self.topo_drift_ticks += 1;
            }
        }

        let mut backgrounds = [0usize; MAX_CPUS];
        for g in self.guests.iter().flatten().filter(|g| g.active && g.has_vmm && g.vmm_limited) {
            backgrounds[g.vmm_limits.unwrap().0] += 1;
        }
        let mut vmm_used = [0u64; MAX_GUESTS];
        let mut vmm_before = [None; MAX_GUESTS];
        let mut core_vmm = [0u64; MAX_CPUS];
        let mut largest = [0u64; MAX_CPUS];
        let mut core_pvk = [0u64; MAX_CPUS];
        let mut largest_boosted = [0u64; MAX_CPUS];

        let mut samples: Vec<policy::Sample> = Vec::new();

        for g in self.guests.iter_mut().flatten().filter(|g| g.active) {
            let cv = g.vmm_sc.as_mut().map_or(0, |sc| sc.take_consumed());
            vmm_used[g.id] = cv;
            vmm_before[g.id] = g.vmm_limits.map(|(_, p)| p);
            if g.has_vmm {
                let core = g.vmm_limits.unwrap().0;
                core_vmm[core] += cv;
                largest[core] = largest[core].max(cv);
                if g.vmm_boosted {
                    largest_boosted[core] = largest_boosted[core].max(cv);
                }
            }

            g.cap_window_elapsed += elapsed_us;
            if g.cpu_cap_pct > 0 && g.cap_window_elapsed >= 1_000_000 {
                let cap_limit_per_vcpu = (g.cap_window_elapsed * g.cpu_cap_pct as u64 / 100) * g.vcpus.len() as u64;
                let period_slack = g.vcpus.iter().map(|v| v.sc_k.period * 2).sum::<u64>() + 40_000;
                assert!(
                    g.cap_window_consumed <= cap_limit_per_vcpu + period_slack,
                    "CAP VIOLATION guest {} ({}% cap): consumed={}us limit={}us+slack={}us",
                    g.id, g.cpu_cap_pct, g.cap_window_consumed, cap_limit_per_vcpu, period_slack
                );
                g.cap_window_consumed = 0;
                g.cap_window_elapsed = 0;
            }

            for v in 0..g.vcpus.len() {
                let has_vmm = v == 0 && g.has_vmm;
                let old = if has_vmm {
                    g.vmm_limits.unwrap().1
                } else {
                    vcpu_plan(g, v, g.vcpus[v].k_share, None)
                };
                let ck = g.vcpus[v].sc_k.take_consumed();
                let cu = g.vcpus[v].sc_u.take_consumed();
                let c = ck + cu;
                if !g.hvm {
                    core_pvk[g.vcpus[v].core] += ck;
                }

                if g.cpu_cap_pct > 0 {
                    if let Some((ks, vs)) = budget::adapt(
                        old,
                        g.vcpus[v].k_share,
                        g.vmm_share,
                        [ck, cu, if has_vmm { cv } else { 0 }],
                        elapsed_us,
                    ) {
                        let mut next = vcpu_plan(g, v, ks, has_vmm.then_some(vs));
                        if has_vmm && g.vmm_limited {
                            next = budget::background(next, backgrounds[g.vmm_limits.unwrap().0]);
                        }
                        if budget::changed(old, next) {
                            let core = g.vcpus[v].core;
                            g.vcpus[v].sc_k.configure(core, next.kernel, next.period, self.now, true);
                            g.vcpus[v].sc_u.configure(core, sc_u_budget(g.hvm, next), next.user_period, self.now, true);
                            if has_vmm {
                                let vc = g.vmm_limits.unwrap().0;
                                g.vmm_sc.as_mut().unwrap().configure(vc, next.vmm, next.vmm_period, self.now, true);
                                g.vmm_limits = Some((vc, next));
                                g.vmm_share = vs;
                            }
                            g.vcpus[v].k_share = ks;
                        }
                    }
                }

                let vc = &mut g.vcpus[v];
                vc.cooldown = vc.cooldown.saturating_sub(1);
                if vc.wall_us != 0 || c != 0 {
                    vc.wall_us += elapsed_us;
                    vc.run_us += c;
                    let steal_us = vc.wall_us.saturating_sub(vc.run_us).saturating_sub(vc.idle_us);
                    let ns = steal_us * 1000;
                    if ns > vc.steal_ns {
                        vc.steal_ns = ns;
                    }
                }

                samples.push(policy::Sample {
                    guest: g.id,
                    vcpu: v,
                    vcore: vc.vcore,
                    cpu: vc.core,
                    used: c,
                    movable: vc.cooldown == 0,
                });
            }
        }

        // Production BoostGuard
        let hvm = self.hvm_cpus();
        let mut occupied = [0u64; MAX_CPUS];
        let mut guarded_vmms = [0usize; MAX_CPUS];
        for g in self.guests.iter().flatten().filter(|g| g.active) {
            for v in &g.vcpus {
                occupied[v.core] |= 1u64 << g.id;
            }
            if g.has_vmm && !g.vmm_boosted {
                guarded_vmms[g.vmm_limits.unwrap().0] += 1;
            }
        }
        for g in self.guests.iter_mut().flatten().filter(|g| g.active && g.has_vmm) {
            let core = g.vmm_limits.unwrap().0;
            let contended = (occupied[core] & !(1u64 << g.id)) != 0
                || core == 0
                || core_vmm[core].saturating_sub(vmm_used[g.id]) >= TIMESLICE_US
                || guarded_vmms[core] > usize::from(!g.vmm_boosted);
            let beside_hvm = hvm & (1u64 << core) != 0;
            let crowd = core_vmm[core] + if beside_hvm { core_pvk[core] } else { 0 };
            let largest = if beside_hvm { largest_boosted[core] } else { largest[core] };
            let old = vmm_before[g.id].unwrap();
            let boosted = if beside_hvm {
                g.vmm_guard.boost_when(g.vmm_boosted, vmm_used[g.id], crowd, largest, contended, elapsed_us, old,
                    budget::Crowded::BesideHvm)
            } else {
                g.vmm_guard.boost(g.vmm_boosted, vmm_used[g.id], crowd, largest, contended, elapsed_us, old)
            };
            g.vmm_boosted = boosted;
        }
        self.protect_vmms();

        if self.strategy.balance && self.cpus >= 2 {
            match policy::choose(&self.topology, &samples, elapsed_us, &core_vmm) {
                Some(policy::Action::IntraCore { guest, vcpu, src, dst }) => {
                    assert_eq!(self.topology.core(src), self.topology.core(dst));
                    self.apply_single_move(guest, vcpu, dst, record);
                    if record {
                        self.migrations += 1;
                        self.intra_core_moves += 1;
                    }
                }
                Some(policy::Action::VcoreSwap { guest, ps, pd }) => {
                    self.apply_vcore_swap(guest, ps, pd, &samples, elapsed_us, &core_vmm, record);
                    if record {
                        self.migrations += 1;
                        self.vcore_swaps += 1;
                    }
                }
                None => {}
            }
        }
        self.assert_vcore_invariant();
        self.publish_host_capacities(&samples, &core_vmm, &vmm_used, elapsed_us);
        self.protect_vmms();
    }

    fn apply_single_move(&mut self, gid: usize, v: usize, dst: usize, record: bool) {
        if !self.guests[gid].as_ref().is_some_and(|g| g.active) { return; }
        let div = self.kernel_divisors(&[(gid, v, dst)]);
        let g = self.guests[gid].as_mut().unwrap();
        g.vcpus[v].kernel_divisor = if g.hvm { 0 } else { div[dst] };
        let p = if v == 0 && g.has_vmm {
            g.vmm_limits.unwrap().1
        } else {
            vcpu_plan(g, v, g.vcpus[v].k_share, None)
        };
        g.vcpus[v].sc_k.configure(dst, p.kernel, p.period, self.now, true);
        g.vcpus[v].sc_u.configure(dst, sc_u_budget(g.hvm, p), p.user_period, self.now, true);
        g.vcpus[v].core = dst;
        g.vcpus[v].cooldown = COOLDOWN;
        if record {
            g.tlb_flushes += 1;
            self.tlb_flushes += 1;
        }
    }

    /// sched::migrate of a VcoreSwap: the production moves.
    fn apply_vcore_swap(&mut self, gid: usize, ps: usize, pd: usize, samples: &[policy::Sample], elapsed_us: u64,
        vmm_load: &[u64; MAX_CPUS], record: bool) {
        let mut moves = Vec::new();
        policy::swap_moves(&self.topology, samples, elapsed_us, vmm_load, gid, ps, pd, |v, dst| moves.push((v, dst)));
        let all: Vec<_> = moves.iter().map(|&(v, dst)| (gid, v, dst)).collect();
        if !self.guests[gid].as_ref().is_some_and(|g| g.active) { return; }
        let div = self.kernel_divisors(&all);
        let Some(g) = self.guests[gid].as_mut() else { return };
        if !g.active { return; }
        let mut moved = vec![false; g.vcpus.len()];
        for (v, dst) in moves {
            assert!(!moved[v], "vCPU {v} moved twice");
            moved[v] = true;
            let from = self.topology.core(g.vcpus[v].core);
            let to = self.topology.core(dst);
            assert!((from, to) == (ps, pd) || (from, to) == (pd, ps), "move {from} -> {to} outside {ps} <-> {pd}");
            g.vcpus[v].kernel_divisor = if g.hvm { 0 } else { div[dst] };
            let p = if v == 0 && g.has_vmm {
                g.vmm_limits.unwrap().1
            } else {
                vcpu_plan(g, v, g.vcpus[v].k_share, None)
            };
            g.vcpus[v].sc_k.configure(dst, p.kernel, p.period, self.now, true);
            g.vcpus[v].sc_u.configure(dst, sc_u_budget(g.hvm, p), p.user_period, self.now, true);
            g.vcpus[v].core = dst;
            g.vcpus[v].cooldown = COOLDOWN;
        }
        // Every vCPU of the two vCores moved.
        for (v, vc) in g.vcpus.iter().enumerate() {
            let p = self.topology.core(vc.core);
            assert!(moved[v] || (p != ps && p != pd), "guest {gid} vCPU {v} left behind on {p}");
        }
        if record {
            g.tlb_flushes += 1;
            self.tlb_flushes += 1;
        }
    }

    fn assert_vcore_invariant(&self) {
        for g in self.guests.iter().flatten().filter(|g| g.active) {
            let mut vcore_to_phys = [None::<usize>; MAX_CPUS];
            let mut phys_to_vcore = [None::<usize>; MAX_CPUS];
            for (v, vc) in g.vcpus.iter().enumerate() {
                let p = self.topology.core(vc.core);
                assert_eq!(vc.sc_k.cpu, vc.core, "sc_k desync");
                assert_eq!(vc.sc_u.cpu, vc.core, "sc_u desync");
                if let Some(prev_p) = vcore_to_phys[vc.vcore] {
                    assert_eq!(prev_p, p, "TOPOLOGY BROKEN: guest {} vcpu {} vcore {} split across P{} and P{}", g.id, v, vc.vcore, prev_p, p);
                } else {
                    vcore_to_phys[vc.vcore] = Some(p);
                }
                if let Some(prev_vc) = phys_to_vcore[p] {
                    assert_eq!(prev_vc, vc.vcore, "TOPOLOGY BROKEN: guest {} P{} holds both vcore {} and vcore {}", g.id, p, prev_vc, vc.vcore);
                } else {
                    phys_to_vcore[p] = Some(vc.vcore);
                }
            }
        }
    }

    /// Publish per-vCPU available capacity hints (0..=1024, like Linux hw_pressure) reflecting
    /// external neighbor pressure on the same logical CPU and sibling SMT threads.
    fn publish_host_capacities(
        &mut self,
        samples: &[policy::Sample],
        core_vmm: &[u64; MAX_CPUS],
        vmm_used: &[u64; MAX_GUESTS],
        elapsed_us: u64,
    ) {
        if elapsed_us == 0 {
            return;
        }
        let mut total_cpu = [0u64; MAX_CPUS];
        let mut guest_cpu = [[0u64; MAX_CPUS]; MAX_GUESTS];
        for c in 0..self.cpus {
            total_cpu[c] += core_vmm[c];
        }
        for g in self.guests.iter().flatten().filter(|g| g.active && g.has_vmm) {
            let vc = g.vmm_limits.unwrap().0;
            guest_cpu[g.id][vc] += vmm_used[g.id];
        }
        for s in samples {
            total_cpu[s.cpu] += s.used;
            guest_cpu[s.guest][s.cpu] += s.used;
        }
        let mut total_phys = [0u64; MAX_CPUS];
        let mut guest_phys = [[0u64; MAX_CPUS]; MAX_GUESTS];
        for c in 0..self.cpus {
            let p = self.topology.core(c);
            total_phys[p] += total_cpu[c];
            for g in 0..MAX_GUESTS {
                guest_phys[g][p] += guest_cpu[g][c];
            }
        }
        for g in self.guests.iter_mut().flatten().filter(|g| g.active) {
            for vc in &mut g.vcpus {
                let c = vc.core;
                let p = self.topology.core(c);
                // sched::publish_capacity.
                let same = total_cpu[c].saturating_sub(guest_cpu[g.id][c]);
                let sibling = total_phys[p].saturating_sub(guest_phys[g.id][p]).saturating_sub(same);
                vc.host_cap = policy::capacity(vc.host_cap, same, sibling, elapsed_us);
                assert!((128..=1024).contains(&vc.host_cap), "host_cap {}", vc.host_cap);
            }
        }
    }

    fn run_until(&mut self, end_us: u64) {
        while self.now < end_us {
            self.wake_tasks_and_vmms();
            self.sync_ready_queues();
            let next = self.next_event_time(end_us);
            let dt = next - self.now;
            self.advance(dt);
            if self.now >= self.next_balance {
                let elapsed = self.now - self.last_balance;
                self.last_balance = self.now;
                self.execute_balance(elapsed);
                let jitter = if self.balance_jitter && self.rng.chance(15) {
                    self.rng.range(0, 120_000)
                } else {
                    0
                };
                self.next_balance = self.now + BALANCE_US + jitter;
            }
        }
    }

    fn report(&self) -> RunMetrics {
        let mut class1_works: Vec<f64> = Vec::new();
        let mut all_lats: Vec<u64> = Vec::new();
        for g in self.guests.iter().flatten().filter(|g| g.active) {
            if g.fairness_group == 1 {
                class1_works.push(g.window_work as f64);
            }
            for t in &g.tasks {
                all_lats.extend_from_slice(&t.wakeup_latencies);
            }
        }
        let jain = if class1_works.len() >= 2 {
            let sum: f64 = class1_works.iter().sum();
            let sum_sq: f64 = class1_works.iter().map(|x| x * x).sum();
            if sum_sq > 0.0 {
                (sum * sum) / (class1_works.len() as f64 * sum_sq)
            } else {
                1.0
            }
        } else {
            1.0
        };
        let min_max_ratio = if class1_works.len() >= 2 {
            let mn = class1_works.iter().cloned().fold(f64::INFINITY, f64::min);
            let mx = class1_works.iter().cloned().fold(0.0f64, f64::max);
            if mx > 0.0 { mn / mx } else { 1.0 }
        } else {
            1.0
        };
        all_lats.sort_unstable();
        let p99_lat = if all_lats.is_empty() {
            0
        } else {
            all_lats[(all_lats.len() * 99) / 100]
        };
        let smt_waste_pct = if self.total_busy_thread_us > 0 {
            (self.wasted_smt_us as f64) * 100.0 / (self.total_busy_thread_us as f64)
        } else {
            0.0
        };
        let topo_drift_pct = if self.balance_ticks_recorded > 0 {
            (self.topo_drift_ticks as f64) * 100.0 / (self.balance_ticks_recorded as f64)
        } else {
            0.0
        };
        let min_hog_share = self.guests.iter().flatten().filter(|g| g.active)
            .flat_map(|g| g.tasks.iter())
            .filter(|t| matches!(t.pattern, TaskPattern::SteadyHog))
            .map(|t| t.effective_work as f64 / (self.now as f64 * 1000.0))
            .fold(1.0, f64::min);
        RunMetrics {
            min_hog_share,
            eff_work_ms: (self.total_effective_work as f64) / 1_000_000.0,
            smt_waste_pct,
            topo_drift_pct,
            jain,
            min_max_ratio,
            migrations: self.migrations,
            tlb_flushes: self.tlb_flushes,
            p99_lat_us: p99_lat,
        }
    }
}

/// SC_U's budget in `p`: an HVM vCPU has none (its plan's user part is 0),
/// and its idle model SC_U keeps the whole period.
fn sc_u_budget(hvm: bool, p: budget::Plan) -> u64 {
    if hvm { p.user_period } else { p.user }
}

/// sched::plan_with: the vCPU's plan, its VMM's background limit applied
/// by the caller, and SC_K's limit beside an HVM vCPU (budget::limit_kernel).
fn vcpu_plan(g: &GuestState, v: usize, k_share: u32, vmm: Option<u32>) -> budget::Plan {
    let p = budget::plan(TIMESLICE_US, 0, g.cpu_cap_pct, k_share, vmm, g.hvm);
    budget::limit_kernel(p, u64::from(g.vcpus[v].kernel_divisor))
}

fn thread_guest(t: ThreadId) -> usize {
    match t {
        ThreadId::Vmm(g) | ThreadId::VcpuKernel(g, _) | ThreadId::VcpuUser(g, _) => g,
    }
}

#[derive(Clone, Debug, Default)]
struct RunMetrics {
    eff_work_ms: f64,
    smt_waste_pct: f64,
    topo_drift_pct: f64,
    jain: f64,
    min_max_ratio: f64,
    migrations: u64,
    tlb_flushes: u64,
    p99_lat_us: u64,
    /// The smallest share of one thread a steady hog got (starvation).
    min_hog_share: f64,
}

fn make_task(pattern: TaskPattern, last_vcpu: usize, pinned_vcpu: Option<usize>, start_sleep: u64) -> Task {
    Task {
        pattern,
        pinned_vcpu,
        last_vcpu,
        sleeping_until: Some(start_sleep),
        on_vcpu: None,
        enqueued_at: 0,
        first_scheduled: false,
        rem_burst: 0,
        mode: TaskMode::User,
        effective_work: 0,
        wakeup_latencies: Vec::new(),
    }
}

#[test]
fn hvm_vcpu_shares_a_core_with_a_waking_pv_user() {
    let mut sim = Sim::new(STATIC, Topology::from_ids(&[0]), 0, 0);
    let peer_wake = TIMESLICE_US / 2;
    for (id, wake) in [(0, 0), (1, peer_wake)] {
        let task = make_task(TaskPattern::SteadyHog, 0, None, wake);
        sim.spawn_guest(id, 1, 0, VmmPattern::None, vec![task], 1);
    }
    sim.wake_tasks_and_vmms();
    // A single runnable HVM thread uses SC_K even for guest userspace.
    sim.make_hvm(0);

    sim.run_until(3 * TIMESLICE_US);
    let pv = &sim.guests[1].as_ref().unwrap().tasks[0];
    assert!(pv.first_scheduled, "PV user never ran after waking");
    assert!(pv.wakeup_latencies[0] <= TIMESLICE_US, "PV user waited {} us", pv.wakeup_latencies[0]);
    let hvm_cpu = &sim.guests[0].as_ref().unwrap().vcpus[0];
    assert!(hvm_cpu.sc_k.total_consumed > TIMESLICE_US, "HVM did not resume");
}

/// An HVM guest and `pv` PV guests whose kernels never stop (syscalls,
/// interrupts, kernel threads, or a hostile kernel spinning), all hogs,
/// all on CPU 0 of `cpus`: guest 0 is the HVM one.
fn hvm_beside_busy_pv_kernels(strategy: Strategy, cpus: usize, pv: usize) -> Sim {
    let ids: Vec<u32> = (0..cpus as u32).collect();
    let mut sim = Sim::new(strategy, Topology::from_ids(&ids), 0, 0);
    for id in 0..=pv {
        sim.spawn_guest(id, 1, 0, VmmPattern::None, vec![make_task(TaskPattern::SteadyHog, 0, None, 0)], 1);
        if sim.guests[id].as_ref().unwrap().vcpus[0].core != 0 {
            sim.apply_single_move(id, 0, 0, false);
        }
    }
    sim.wake_tasks_and_vmms();
    for id in 1..=pv {
        sim.guests[id].as_mut().unwrap().tasks[0].mode = TaskMode::Kernel;
    }
    sim.make_hvm(0);
    sim
}

/// A PV kernel at PRIO_KERNEL, above the HVM vCPU's PRIO_USER, would keep
/// it off a shared CPU for good with a full round-robin SC_K: beside an
/// HVM vCPU, the PV kernels there share half the CPU
/// (budget::limit_kernel), and the limit goes when the HVM guest does.
#[test]
fn a_busy_pv_kernel_leaves_a_shared_hvm_vcpu_its_part() {
    let mut sim = hvm_beside_busy_pv_kernels(STATIC, 1, 1);
    let pv = &sim.guests[1].as_ref().unwrap().vcpus[0];
    assert_eq!(pv.kernel_divisor, 2);
    let period = pv.sc_k.period;
    assert_eq!(pv.sc_k.budget, period / 2);
    assert_eq!((pv.sc_u.budget, pv.sc_u.period), (period, period), "SC_U keeps its full round-robin budget");
    let run = 2_000_000;
    sim.run_until(run);
    let hvm = sim.guests[0].as_ref().unwrap().vcpus[0].sc_k.total_consumed;
    let pv = sim.guests[1].as_ref().unwrap().vcpus[0].sc_k.total_consumed;
    assert!(hvm * 100 >= run * 40, "HVM vCPU got {hvm} us of {run}");
    assert!(pv * 100 >= run * 40, "PV kernel got {pv} us of {run}");
    // The HVM guest gone, the PV kernel's SC_K is whole again.
    sim.destroy_guest(0);
    let pv = &sim.guests[1].as_ref().unwrap().vcpus[0];
    assert_eq!(pv.kernel_divisor, 0);
    assert_eq!(pv.sc_k.budget, pv.sc_k.period);
}

/// Two busy PV kernels beside one HVM vCPU share the half between them:
/// each alone at half would leave the HVM vCPU nothing.
#[test]
fn busy_pv_kernels_share_half_a_cpu_beside_an_hvm_vcpu() {
    let mut sim = hvm_beside_busy_pv_kernels(STATIC, 1, 2);
    for id in 1..=2 {
        let pv = &sim.guests[id].as_ref().unwrap().vcpus[0];
        assert_eq!((pv.kernel_divisor, pv.sc_k.budget), (4, pv.sc_k.period / 4));
    }
    let run = 2_000_000;
    sim.run_until(run / 2);
    let half = sim.guests[0].as_ref().unwrap().vcpus[0].sc_k.total_consumed;
    sim.run_until(run);
    let hvm = sim.guests[0].as_ref().unwrap().vcpus[0].sc_k.total_consumed;
    assert!(hvm * 100 >= run * 40, "HVM vCPU got {hvm} us of {run}");
    assert!((hvm - half) * 100 >= run / 2 * 40, "and keeps progressing: {} us of the last {}", hvm - half, run / 2);
    for id in 1..=2 {
        let pv = sim.guests[id].as_ref().unwrap().vcpus[0].sc_k.total_consumed;
        assert!(pv * 100 >= run * 20, "PV kernel {id} got {pv} us of {run}");
    }
}

/// A PV guest whose VMM is busy with I/O (boosted, at PRIO_VMM) and whose
/// kernel never stops, beside an HVM vCPU on one CPU: with a VMM there,
/// the PV kernel gets a quarter, and a VMM that with it takes more than
/// three quarters of the CPU is demoted to its background half, so
/// PRIO_USER (here the HVM vCPU alone) keeps a quarter in the steady state
/// whatever the VMM's load (at exactly half, the VMM keeps its boost and
/// the quarter is what is left).
#[test]
fn a_busy_vmm_and_pv_kernel_leave_a_shared_hvm_vcpu_a_quarter() {
    for (burst, demoted) in [(2_500, None), (2_600, Some(true)), (2_700, Some(true)), (2_740, Some(true)),
        (2_750, Some(true)), (3_500, Some(true)), (5_000, Some(true))] {
        let mut sim = Sim::new(STATIC, Topology::from_ids(&[0]), 0, 0);
        sim.spawn_guest(0, 1, 0, VmmPattern::None, vec![make_task(TaskPattern::SteadyHog, 0, None, 0)], 1);
        sim.spawn_guest(1, 1, 0, VmmPattern::HonestIo { burst_us: burst, period_us: 5_000 },
            vec![make_task(TaskPattern::SteadyHog, 0, None, 0)], 1);
        sim.wake_tasks_and_vmms();
        sim.guests[1].as_mut().unwrap().tasks[0].mode = TaskMode::Kernel;
        sim.make_hvm(0);
        assert_eq!(sim.guests[1].as_ref().unwrap().vcpus[0].kernel_divisor, 4, "a VMM there: a quarter");
        let run = 4_000_000;
        sim.run_until(run / 2);
        let half = sim.guests[0].as_ref().unwrap().vcpus[0].sc_k.total_consumed;
        sim.run_until(run);
        let g = sim.guests[1].as_ref().unwrap();
        if let Some(demoted) = demoted {
            assert_eq!(!g.vmm_boosted, demoted, "VMM busy {burst} of 5000 us");
        }
        let hvm = sim.guests[0].as_ref().unwrap().vcpus[0].sc_k.total_consumed - half;
        assert!(hvm * 100 >= run / 2 * 24, "VMM busy {burst} of 5000 us: HVM vCPU got {hvm} us of the last {}", run / 2);
    }
}

/// Two VMMs beside an HVM vCPU, the busier demoted first and still using
/// its background part: the other, boosted, is then the largest boosted
/// one and is demoted in turn when they crowd the CPU, so the HVM vCPU
/// keeps its part (a demoted VMM using more must not shield it).
#[test]
fn a_demoted_vmm_does_not_shield_a_boosted_one_beside_an_hvm_vcpu() {
    let mut sim = Sim::new(STATIC, Topology::from_ids(&[0]), 0, 0);
    sim.spawn_guest(0, 1, 0, VmmPattern::None, vec![make_task(TaskPattern::SteadyHog, 0, None, 0)], 1);
    sim.spawn_guest(1, 1, 0, VmmPattern::HonestIo { burst_us: 5_000, period_us: 5_000 }, vec![], 1);
    sim.spawn_guest(2, 1, 0, VmmPattern::HonestIo { burst_us: 1_750, period_us: 5_000 },
        vec![make_task(TaskPattern::SteadyHog, 0, None, 0)], 1);
    sim.wake_tasks_and_vmms();
    sim.guests[2].as_mut().unwrap().tasks[0].mode = TaskMode::Kernel;
    sim.make_hvm(0);
    let run = 4_000_000;
    sim.run_until(run / 2);
    let half = sim.guests[0].as_ref().unwrap().vcpus[0].sc_k.total_consumed;
    sim.run_until(run);
    assert!(!sim.guests[1].as_ref().unwrap().vmm_boosted, "the spinning VMM demoted");
    assert!(!sim.guests[2].as_ref().unwrap().vmm_boosted, "and the 35% one after it");
    let hvm = sim.guests[0].as_ref().unwrap().vcpus[0].sc_k.total_consumed - half;
    assert!(hvm * 100 >= run / 2 * 24, "HVM vCPU got {hvm} us of the last {}", run / 2);
}

/// The limited PV kernel leaves the HVM vCPU enough to count as busy: with
/// a free CPU, the balancer spreads them, and each gets a whole CPU.
#[test]
fn a_busy_pv_kernel_and_an_hvm_vcpu_are_spread_by_the_balancer() {
    let mut sim = hvm_beside_busy_pv_kernels(Strategy { balance: true, guest: GuestModel::Cap }, 2, 1);
    // Past the placement's cooldown (COOLDOWN balancer periods).
    sim.run_until(2_000_000);
    let (hvm, pv) = (sim.guests[0].as_ref().unwrap(), sim.guests[1].as_ref().unwrap());
    assert_ne!(hvm.vcpus[0].core, pv.vcpus[0].core, "not spread");
    assert_eq!(pv.vcpus[0].kernel_divisor, 0);
    let before = hvm.vcpus[0].sc_k.total_consumed;
    sim.run_until(3_000_000);
    let got = sim.guests[0].as_ref().unwrap().vcpus[0].sc_k.total_consumed - before;
    assert!(got * 100 >= 1_000_000 * 95, "HVM vCPU alone got {got} us of 1 s");
}

// ---- Scenarios ----

fn run_scenario(name: &str, strat: Strategy, seed: u64) -> RunMetrics {
    let mut rng = Rng::new(seed ^ 0x55aa_1234_9876_fedc);
    let dur = 10_000_000; // 10s simulated
    let warmup = 1_500_000;

    match name {
        // 1. Single 8-vCPU guest on 4P/8T with 8 bursty tasks (~3.5 avg concurrent, rotating across all 8 vCPUs)
        "1_single_8v_8bursty" => {
            let topo = Topology::from_ids(&[0, 0, 1, 1, 2, 2, 3, 3]);
            let mut sim = Sim::new(strat, topo, seed, warmup);
            let mut tasks = Vec::new();
            for i in 0..8 {
                tasks.push(make_task(
                    TaskPattern::Bursty {
                        run_min: 15_000, run_max: 45_000,
                        sleep_min: 25_000, sleep_max: 65_000,
                        random_wake_cpu: false,
                    },
                    i,
                    None,
                    rng.range(0, 60_000),
                ));
            }
            sim.spawn_guest(0, 8, 0, VmmPattern::None, tasks, 1);
            sim.run_until(dur);
            sim.report()
        }

        // 2. Single 8-vCPU guest on 4P/8T with 4 fork/exec-like short tasks (random wake CPU hint)
        "2_single_8v_fork_churn" => {
            let topo = Topology::from_ids(&[0, 0, 1, 1, 2, 2, 3, 3]);
            let mut sim = Sim::new(strat, topo, seed, warmup);
            let mut tasks = Vec::new();
            for i in 0..4 {
                tasks.push(make_task(
                    TaskPattern::Bursty {
                        run_min: 10_000, run_max: 35_000,
                        sleep_min: 2_000, sleep_max: 8_000,
                        random_wake_cpu: true,
                    },
                    i,
                    None,
                    rng.range(0, 20_000),
                ));
            }
            sim.spawn_guest(0, 8, 0, VmmPattern::None, tasks, 1);
            sim.run_until(dur);
            sim.report()
        }

        // 3. Two 8-vCPU guests on 4P/8T (16 vCPUs > 8 HT), each 2 steady hogs
        "3_two_8v_overcommit" => {
            let topo = Topology::from_ids(&[0, 0, 1, 1, 2, 2, 3, 3]);
            let mut sim = Sim::new(strat, topo, seed, warmup);
            for gid in 0..2 {
                let mut tasks = Vec::new();
                for i in 0..2 {
                    tasks.push(make_task(TaskPattern::SteadyHog, i, None, rng.range(0, 10_000)));
                }
                sim.spawn_guest(gid, 8, 0, VmmPattern::None, tasks, 1);
            }
            sim.run_until(dur);
            sim.report()
        }

        // 4. Phase-drift stress test:
        //    Phase 1 (0..3s): Guest 0 & Guest 1 (both 8v) run 2 hogs each -> forces Host migrations.
        //    Phase 2 (3..10s): Guest 1 goes quiet; Guest 0 runs 8 bursty tasks (~3.5 concurrent).
        //    Exposes whether smt_free's scrambled topology hurts Guest 0 in Phase 2!
        "4_two_8v_phase_drift" => {
            let topo = Topology::from_ids(&[0, 0, 1, 1, 2, 2, 3, 3]);
            let mut sim = Sim::new(strat, topo, seed, 3_500_000); // measure Phase 2!
            // Intentionally start BOTH guests with 3 hogs on v0,v1,v2 so Host MUST migrate during Phase 1
            for gid in 0..2 {
                let mut tasks = Vec::new();
                for i in 0..3 {
                    tasks.push(make_task(TaskPattern::SteadyHog, i, None, rng.range(0, 5_000)));
                }
                sim.spawn_guest(gid, 8, 0, VmmPattern::None, tasks, 1);
            }
            sim.run_until(3_000_000);
            // Phase 2: Guest 1 goes idle, Guest 0 shifts to 8 bursty tasks
            sim.replace_tasks(1, Vec::new());
            let mut g0_tasks = Vec::new();
            for i in 0..8 {
                g0_tasks.push(make_task(
                    TaskPattern::Bursty {
                        run_min: 15_000, run_max: 45_000,
                        sleep_min: 20_000, sleep_max: 60_000,
                        random_wake_cpu: false,
                    },
                    i,
                    None,
                    3_000_000 + rng.range(0, 40_000),
                ));
            }
            sim.replace_tasks(0, g0_tasks);
            sim.run_until(dur);
            sim.report()
        }

        // 5. THREE 8-vCPU guests on 4P/8T (24 vCPUs > 8 HT), 1 hog + 2 bursty each
        "5_three_8v_heavy" => {
            let topo = Topology::from_ids(&[0, 0, 1, 1, 2, 2, 3, 3]);
            let mut sim = Sim::new(strat, topo, seed, warmup);
            for gid in 0..3 {
                let mut tasks = Vec::new();
                tasks.push(make_task(TaskPattern::SteadyHog, 0, None, rng.range(0, 10_000)));
                for k in 1..3 {
                    tasks.push(make_task(
                        TaskPattern::Bursty {
                            run_min: 20_000, run_max: 100_000,
                            sleep_min: 20_000, sleep_max: 80_000,
                            random_wake_cpu: true,
                        },
                        k,
                        None,
                        rng.range(0, 30_000),
                    ));
                }
                sim.spawn_guest(gid, 8, 0, VmmPattern::None, tasks, 1);
            }
            sim.run_until(dur);
            sim.report()
        }

        // 6. Asymmetric mix: 1x 6-vCPU guest (6 bursty) + 2x 2-vCPU guests (steady hogs) on 4P/8T
        "6_asym_6v_plus_smalls" => {
            let topo = Topology::from_ids(&[0, 0, 1, 1, 2, 2, 3, 3]);
            let mut sim = Sim::new(strat, topo, seed, warmup);
            let mut t0 = Vec::new();
            for i in 0..6 {
                t0.push(make_task(
                    TaskPattern::Bursty {
                        run_min: 15_000, run_max: 45_000,
                        sleep_min: 35_000, sleep_max: 90_000,
                        random_wake_cpu: false,
                    },
                    i,
                    None,
                    rng.range(0, 40_000),
                ));
            }
            sim.spawn_guest(0, 6, 0, VmmPattern::None, t0, 0);
            for gid in 1..3 {
                let tasks = vec![make_task(TaskPattern::SteadyHog, 0, None, rng.range(0, 10_000))];
                sim.spawn_guest(gid, 2, 0, VmmPattern::None, tasks, 1);
            }
            sim.run_until(dur);
            sim.report()
        }

        // 7. Single guest over HT: 16 vCPUs on 4P/8T running 8 bursty tasks
        "7_single_16v_over_ht" => {
            let topo = Topology::from_ids(&[0, 0, 1, 1, 2, 2, 3, 3]);
            let mut sim = Sim::new(strat, topo, seed, warmup);
            let mut tasks = Vec::new();
            for i in 0..8 {
                tasks.push(make_task(
                    TaskPattern::Bursty {
                        run_min: 15_000, run_max: 45_000,
                        sleep_min: 25_000, sleep_max: 65_000,
                        random_wake_cpu: true,
                    },
                    i,
                    None,
                    rng.range(0, 40_000),
                ));
            }
            sim.spawn_guest(0, 16, 0, VmmPattern::None, tasks, 1);
            sim.run_until(dur);
            sim.report()
        }

        // 8. Hybrid CPU (2 P-cores x 2T + 4 E-cores x 1T, unordered APIC IDs)
        "8_hybrid_topo" => {
            let topo = Topology::from_ids(&[10, 20, 30, 40, 10, 20, 50, 60]);
            let mut sim = Sim::new(strat, topo, seed, warmup);
            let mut t0 = Vec::new();
            for i in 0..8 {
                t0.push(make_task(
                    TaskPattern::Bursty {
                        run_min: 15_000, run_max: 45_000,
                        sleep_min: 25_000, sleep_max: 65_000,
                        random_wake_cpu: true,
                    },
                    i,
                    None,
                    rng.range(0, 40_000),
                ));
            }
            sim.spawn_guest(0, 8, 0, VmmPattern::None, t0, 0);
            for gid in 1..4 {
                let tasks = vec![make_task(TaskPattern::SteadyHog, 0, None, rng.range(0, 10_000))];
                sim.spawn_guest(gid, 2, 0, VmmPattern::None, tasks, 1);
            }
            sim.run_until(dur);
            sim.report()
        }

        // 9. Capped guests + hostile quiet-spin VMM + interactive tasks + balance clock jitter
        "9_caps_vmm_attack" => {
            let topo = Topology::from_ids(&[0, 0, 1, 1, 2, 2, 3, 3]);
            let mut sim = Sim::new(strat, topo, seed, warmup);
            sim.balance_jitter = true;
            sim.spawn_guest(
                0,
                2,
                50,
                VmmPattern::HonestIo { burst_us: 3_000, period_us: 25_000 },
                vec![make_task(TaskPattern::PhaseSwitch { phase_us: 80_000, io_vmm_ratio: 30 }, 0, None, 0)],
                2,
            );
            sim.spawn_guest(
                1,
                2,
                0,
                VmmPattern::HostileQuietSpin { quiet_us: 1_100_000, spin_us: 400_000 },
                vec![make_task(TaskPattern::SteadyHog, 0, None, 0)],
                0,
            );
            sim.spawn_guest(2, 8, 0, VmmPattern::None, vec![
                make_task(TaskPattern::SteadyHog, 0, None, 0),
                make_task(TaskPattern::Interactive { run_us: 2_000, sleep_min: 15_000, sleep_max: 40_000 }, 1, None, 5_000),
            ], 1);
            sim.spawn_guest(3, 8, 0, VmmPattern::None, vec![
                make_task(TaskPattern::SteadyHog, 0, None, 0),
                make_task(TaskPattern::Interactive { run_us: 2_000, sleep_min: 15_000, sleep_max: 40_000 }, 1, None, 7_000),
            ], 1);
            sim.run_until(dur);
            sim.report()
        }

        // 10. Randomized chaos across random topologies, dynamic lifecycle, mixed caps & sizes
        "10_random_chaos" => {
            let pcores = rng.usize_range(2, 7);
            let mut ids = Vec::new();
            for p in 0..pcores {
                let threads = if rng.chance(75) { 2 } else { 1 };
                for _ in 0..threads {
                    ids.push((p as u32 + 1) * 7);
                }
            }
            for i in (1..ids.len()).rev() {
                let j = rng.usize_range(0, i + 1);
                ids.swap(i, j);
            }
            let topo = Topology::from_ids(&ids);
            let lcpus = ids.len();
            let mut sim = Sim::new(strat, topo, seed, warmup);
            sim.balance_jitter = true;
            let ng = rng.usize_range(3, 8);
            for gid in 0..ng {
                let nv = match rng.usize_range(0, 3) {
                    0 => rng.usize_range(1, pcores.max(2)),
                    1 => lcpus,
                    _ => rng.usize_range(pcores + 1, (lcpus + 2).min(16)).max(1),
                };
                let cap = if rng.chance(25) { [25, 50, 75][rng.usize_range(0, 3)] } else { 0 };
                let nt = rng.usize_range(1, (pcores / 2 + 3).min(nv + 1).max(2));
                let mut tasks = Vec::new();
                for ti in 0..nt {
                    let pat = match rng.usize_range(0, 3) {
                        0 => TaskPattern::SteadyHog,
                        1 => TaskPattern::Bursty {
                            run_min: 10_000, run_max: 80_000,
                            sleep_min: 15_000, sleep_max: 60_000,
                            random_wake_cpu: rng.chance(50),
                        },
                        _ => TaskPattern::Interactive { run_us: 3_000, sleep_min: 15_000, sleep_max: 50_000 },
                    };
                    tasks.push(make_task(pat, ti % nv, None, rng.range(0, 50_000)));
                }
                let fgrp = if cap == 0 { 1 } else { 2 };
                sim.spawn_guest(gid, nv, cap, VmmPattern::None, tasks, fgrp);
            }
            sim.run_until(dur / 2);
            if ng >= 4 {
                sim.destroy_guest(ng - 1);
                let tasks = vec![
                    make_task(TaskPattern::SteadyHog, 0, None, 0),
                    make_task(TaskPattern::Bursty {
                        run_min: 20_000, run_max: 60_000,
                        sleep_min: 15_000, sleep_max: 45_000,
                        random_wake_cpu: true,
                    }, 1, None, 5_000),
                ];
                sim.spawn_guest(ng - 1, lcpus, 0, VmmPattern::None, tasks, 1);
            }
            sim.run_until(dur);
            sim.report()
        }

        _ => panic!("unknown scenario {name}"),
    }
}

const SCENARIOS: [&str; 10] = [
    "1_single_8v_8bursty",
    "2_single_8v_fork_churn",
    "3_two_8v_overcommit",
    "4_two_8v_phase_drift",
    "5_three_8v_heavy",
    "6_asym_6v_plus_smalls",
    "7_single_16v_over_ht",
    "8_hybrid_topo",
    "9_caps_vmm_attack",
    "10_random_chaos",
];

const STATIC: Strategy = Strategy { balance: false, guest: GuestModel::Cap };
const STRATEGIES: [Strategy; 4] = [
    STATIC,
    Strategy { balance: true, guest: GuestModel::Flat },
    Strategy { balance: true, guest: GuestModel::Smt },
    Strategy { balance: true, guest: GuestModel::Cap },
];

/// Mean metrics over `seeds` runs (the worst for starvation and latency).
fn measure(scenario: &str, strategy: Strategy, seeds: u64) -> RunMetrics {
    let mut m = RunMetrics { min_hog_share: 1.0, ..Default::default() };
    for i in 0..seeds {
        let r = run_scenario(scenario, strategy, 0x2026_1122 + i * 1009 + 17);
        m.eff_work_ms += r.eff_work_ms / seeds as f64;
        m.smt_waste_pct += r.smt_waste_pct / seeds as f64;
        m.topo_drift_pct += r.topo_drift_pct / seeds as f64;
        m.jain += r.jain / seeds as f64;
        m.min_max_ratio += r.min_max_ratio / seeds as f64;
        m.migrations += r.migrations;
        m.tlb_flushes += r.tlb_flushes;
        m.p99_lat_us = m.p99_lat_us.max(r.p99_lat_us);
        m.min_hog_share = m.min_hog_share.min(r.min_hog_share);
    }
    println!(
        "{scenario:<24} {:<16} work {:>8.1} waste {:>5.2}% drift {:>4.1}% jain {:.4} min/max {:.3} migr {:>5} p99 {:>6} us hog {:.3}",
        strategy.name(), m.eff_work_ms, m.smt_waste_pct, m.topo_drift_pct, m.jain, m.min_max_ratio, m.migrations,
        m.p99_lat_us, m.min_hog_share
    );
    m
}

/// What the production guest (topology and capacity aware) must get.
struct Bounds {
    /// Effective work, relative to the static host.
    work: f64,
    /// Fairness among the scenario's peer guests (Jain's index).
    jain: f64,
    /// Every steady hog's share of one thread (also 80% of it on the
    /// other guest models): no starvation.
    hog: f64,
    /// Time SMT siblings shared a core while another core idled.
    waste_pct: f64,
}

const P99_US: u64 = 25_000;

fn seeds() -> u64 {
    std::env::var("DST_SEEDS").ok().and_then(|s| s.parse().ok()).unwrap_or(3)
}

fn check(scenario: &str, b: Bounds) {
    let seeds = seeds();
    let base = measure(scenario, STATIC, seeds);
    for st in &STRATEGIES[1..] {
        let m = measure(scenario, *st, seeds);
        assert_eq!(m.topo_drift_pct, 0.0, "{scenario} {}: a vCore left its physical core", st.name());
        let hog = if st.guest == GuestModel::Cap { b.hog } else { b.hog * 0.8 };
        assert!(m.min_hog_share >= hog, "{scenario} {}: a hog starved: {:.3}", st.name(), m.min_hog_share);
        assert!(m.p99_lat_us <= P99_US, "{scenario} {}: p99 wakeup {} us", st.name(), m.p99_lat_us);
        if st.guest != GuestModel::Cap {
            continue;
        }
        assert!(m.eff_work_ms >= base.eff_work_ms * b.work,
            "{scenario}: work {:.1} vs static {:.1}", m.eff_work_ms, base.eff_work_ms);
        assert!(m.jain >= b.jain, "{scenario}: Jain {:.4}", m.jain);
        assert!(m.smt_waste_pct <= b.waste_pct, "{scenario}: SMT waste {:.2}%", m.smt_waste_pct);
    }
}

macro_rules! scenarios {
    ($($test:ident: $name:literal, $work:literal, $jain:literal, $hog:literal, $waste:literal;)*) => {
        $(#[test]
        fn $test() {
            check($name, Bounds { work: $work, jain: $jain, hog: $hog, waste_pct: $waste });
        })*
        const _: [(); SCENARIOS.len()] = [$({ let _ = $name; }),*];
    };
}

// Balancing never costs more than a few percent against static placement,
// and recovers stacked guests (3, 9) by a quarter or more.
scenarios! {
    single_8v_bursty: "1_single_8v_8bursty", 0.97, 0.99, 0.0, 4.0;
    single_8v_fork_churn: "2_single_8v_fork_churn", 0.97, 0.99, 0.0, 3.0;
    two_8v_overcommit: "3_two_8v_overcommit", 1.25, 0.99, 0.9, 3.0;
    two_8v_phase_drift: "4_two_8v_phase_drift", 0.97, 0.4, 0.0, 4.0;
    three_8v_heavy: "5_three_8v_heavy", 0.95, 0.99, 0.5, 6.0;
    asymmetric_6v_and_hogs: "6_asym_6v_plus_smalls", 0.95, 0.99, 0.7, 4.0;
    single_16v_over_ht: "7_single_16v_over_ht", 0.97, 0.99, 0.0, 3.0;
    hybrid_topology: "8_hybrid_topo", 0.95, 0.99, 0.6, 5.0;
    caps_hostile_vmm_clock_jitter: "9_caps_vmm_attack", 1.25, 0.99, 0.7, 2.0;
    random_chaos: "10_random_chaos", 0.95, 0.7, 0.03, 6.0;
}

/// Every scenario and strategy, for comparing changes: DST_SEEDS=50
/// tests/run-schedtest.sh --ignored --nocapture.
#[test]
#[ignore]
fn survey() {
    for sc in SCENARIOS {
        for st in STRATEGIES {
            measure(sc, st, seeds());
        }
    }
}

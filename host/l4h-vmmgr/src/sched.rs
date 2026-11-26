//! Host CPU scheduling (DESIGN.md §7): per-guest CPU caps and a balancer
//! that spreads busy vCPUs across physical cores before SMT siblings,
//! keeping each guest's virtual cores whole (policy.rs).
//!
//! seL4 does not balance; every vCPU's two scheduling contexts (SC_K, SC_U)
//! live on one core until `SchedControl_Configure` on another core's
//! SchedControl moves them.

use l4h_host::fixed::{ArrayVec, Scratch};
use l4h_host::{GUEST_EXTRA_REFILLS, errno::{EIO, EINVAL, ENOENT, Errno}};

use crate::guest::{Guest, State, Vcpu};
use crate::{HostInfo, Vmmgr};

#[path = "sched/budget.rs"]
pub mod budget;
#[path = "sched/policy.rs"]
mod policy;
use crate::topology;

/// Balancer period.
pub const BALANCE_MS: u64 = 100;
/// A vCPU that moved stays put for this many periods.
const COOLDOWN: u32 = 10;

pub fn consumed(sc: sel4::cap::SchedContext) -> u64 {
    let r = sel4::with_ipc_buffer_mut(|ipc| ipc.inner_mut().seL4_SchedContext_Consumed(sc.bits()));
    if r.error != 0 {
        l4h_rt::log!("l4h-vmmgr: SchedContext_Consumed({:#x}) failed: {}", sc.bits(), r.error);
        return 0;
    }
    r.consumed
}

pub const K_SHARE_INIT: u32 = 500;

fn min_period() -> u64 {
    if cfg!(target_arch = "aarch64") { 40_000 } else { 0 }
}

/// The round-robin timeslice of an uncapped vCPU's contexts.
pub fn guest_timeslice(info: &HostInfo) -> u64 {
    budget::guest_timeslice(info.timeslice_us)
}

fn plan(info: &HostInfo, g: &Guest, v: usize, has_vmm: bool, backgrounds: usize) -> budget::Plan {
    plan_with(info, g, v, has_vmm, backgrounds, g.vcpus[v].k_share, g.vmm_share)
}

/// `plan` with the split `k_share` (and `vmm_share` for vCPU 0's VMM):
/// the VMM's background limit if it is guarded, and SC_K's limit if the
/// vCPU shares its CPU with an HVM guest's (Vcpu::kernel_divisor,
/// budget::limit_kernel).
fn plan_with(info: &HostInfo, g: &Guest, v: usize, has_vmm: bool, backgrounds: usize, k_share: u32, vmm_share: u32)
    -> budget::Plan {
    let vcpu = &g.vcpus[v];
    let p = budget::plan(info.timeslice_us, min_period(), g.cpu_cap_pct, k_share, has_vmm.then_some(vmm_share),
        vcpu.sc_u.is_none());
    let p = if has_vmm && g.vmm_limited { budget::background(p, backgrounds) } else { p };
    budget::limit_kernel(p, u64::from(vcpu.kernel_divisor))
}

fn pair(info: &HostInfo, gid: usize, v: usize, vcpu: &Vcpu, core: usize, p: budget::Plan) -> bool {
    let sc = info.sched_control(core);
    let r = match vcpu.sc_u {
        Some(sc_u) => sc.sched_control_configure_flags(vcpu.sc_k, p.kernel, p.period, GUEST_EXTRA_REFILLS, 0, 0)
            .and_then(|_| sc.sched_control_configure_flags(sc_u, p.user, p.user_period, GUEST_EXTRA_REFILLS, 0, 0)),
        // An HVM guest's vCPU runs kernel and user alike on SC_K: the
        // guest's whole part of the plan, which is the full period
        // without a cap.
        None => sc.sched_control_configure_flags(vcpu.sc_k, p.kernel.saturating_add(p.user).min(p.period), p.period,
            GUEST_EXTRA_REFILLS, 0, 0),
    };
    if let Err(e) = r {
        l4h_rt::log!("l4h-vmmgr: configure guest {} vCPU {} on core {}: {:?}", gid, v, core, e);
    }
    r.is_ok()
}

fn active(g: &Guest) -> bool {
    g.vmm.is_some() && g.state != State::Stopped
}

fn counts(h: &Vmmgr) -> [usize; topology::MAX_CPUS] {
    let mut n = [0; topology::MAX_CPUS];
    for g in h.guests.iter().flatten().filter(|g| active(g) && g.vmm_limited) {
        n[g.vmm_limits.expect("VMM limits").0] += 1;
    }
    n
}

fn configure_vmm(info: &HostInfo, g: &mut Guest, p: budget::Plan) -> bool {
    let (core, old) = g.vmm_limits.expect("VMM limits");
    if p == old { return true; }
    if (p.period, p.kernel, p.user, p.user_period) != (old.period, old.kernel, old.user, old.user_period)
        && !pair(info, g.id, 0, &g.vcpus[0], g.vcpus[0].core, p) {
        g.stop();
        return false;
    }
    if !configure_vmm_sc(info, g, core, old, p) {
        return false;
    }
    g.vmm_limits = Some((core, p));
    true
}

/// The VMM's own context, if `p` changes it from `old`.
fn configure_vmm_sc(info: &HostInfo, g: &mut Guest, core: usize, old: budget::Plan, p: budget::Plan) -> bool {
    if (p.vmm_period, p.vmm) != (old.vmm_period, old.vmm) {
        let r = info.sched_control(core).sched_control_configure_flags(
            g.vmm.as_ref().expect("VMM").sc, p.vmm, p.vmm_period, GUEST_EXTRA_REFILLS, 0, 0);
        if let Err(e) = r {
            l4h_rt::log!("l4h-vmmgr: configure guest {} VMM on core {}: {:?}", g.id, core, e);
            g.stop();
            return false;
        }
    }
    true
}

/// The CPUs where an HVM guest's vCPUs run, or are about to (`arrival`).
fn hvm_cpus(h: &Vmmgr, arrival: Option<Arrival>) -> u128 {
    let mut cpus = 0u128;
    for g in h.guests.iter().flatten().filter(|g| g.hvm.is_some() && g.state == State::Running) {
        for v in &g.vcpus { cpus |= 1u128 << v.core; }
    }
    if let Some(a) = arrival.filter(|a| h.guest(a.guest).is_some_and(|g| g.hvm.is_some() && g.state != State::Stopped)) {
        cpus |= a.cores;
    }
    cpus
}

/// Per CPU, the divisor of PV vCPUs' SC_K there (Vcpu::kernel_divisor; 0:
/// none).  An HVM vCPU runs at PRIO_USER, below every PV kernel's SC_K at
/// PRIO_KERNEL: on a CPU with one, the PV kernels there together get at
/// most half of it, or a quarter where a VMM runs (above both: boosted, it
/// is demoted to at most half once VMMs and these kernels crowd the CPU,
/// BoostGuard via balance; guarded, it has at most half), so that
/// PRIO_USER, the HVM vCPU and PV users there, keeps at least a quarter.
/// Running PV vCPUs are counted where they are; an arrival's too: a
/// starting guest's where they will run, a migration's moves where they
/// go as well, so neither side is unlimited for a moment.
fn kernel_divisors(h: &Vmmgr, arrival: Option<Arrival>) -> [u16; topology::MAX_CPUS] {
    let hvm = hvm_cpus(h, arrival);
    let mut pv = [0u16; topology::MAX_CPUS];
    let mut vmm = [false; topology::MAX_CPUS];
    for g in h.guests.iter().flatten() {
        if active(g) { vmm[g.vmm_limits.expect("VMM limits").0] = true; }
        if g.state != State::Running { continue; }
        for v in g.vcpus.iter().filter(|v| v.sc_u.is_some()) { pv[v.core] += 1; }
    }
    if let Some(c) = arrival.and_then(|a| a.vmm) {
        vmm[c] = true;
    }
    if let Some(a) = arrival {
        match h.guest(a.guest) {
            // Starting (not merely its VMM arriving).
            Some(g) if g.state == State::Created && a.vmm.is_none() => {
                for v in g.vcpus.iter().filter(|v| v.sc_u.is_some()) { pv[v.core] += 1; }
            }
            Some(g) if g.state == State::Running => {
                for &(v, dst) in a.moves {
                    if g.vcpus[v].sc_u.is_some() && g.vcpus[v].core != dst { pv[dst] += 1; }
                }
            }
            _ => {}
        }
    }
    let mut div = [0u16; topology::MAX_CPUS];
    for c in 0..topology::MAX_CPUS {
        if hvm & (1u128 << c) != 0 && pv[c] != 0 {
            div[c] = pv[c] * if vmm[c] { 4 } else { 2 };
        }
    }
    div
}

/// What vCPU `v` of `g` divides its SC_K by on CPU `cpu` (an HVM vCPU, the
/// one protected, by nothing).
fn kernel_divisor_on(g: &Guest, v: usize, cpu: usize, div: &[u16; topology::MAX_CPUS]) -> u16 {
    if g.vcpus[v].sc_u.is_some() { div[cpu] } else { 0 }
}

/// Bring every running PV vCPU's SC_K limit, and a starting guest's
/// (`arrival`), in line with where HVM vCPUs are: only vCPUs whose
/// contexts change are reconfigured.  vCPU 0 of a guest with a VMM is
/// left to configure_vmm (its plan includes the limit; for one whose VMM
/// is not yet there, the start's).  Whether none failed (a failure stops
/// that guest).
fn limit_kernels(h: &mut Vmmgr, div: &[u16; topology::MAX_CPUS], arrival: Option<Arrival>) -> bool {
    let mut ok = true;
    let starting = arrival.filter(|a| a.vmm.is_none()).map(|a| a.guest);
    for g in h.guests.iter_mut().flatten()
        .filter(|g| g.state == State::Running || (g.state == State::Created && starting == Some(g.id))) {
        for v in 0..g.vcpus.len() {
            let want = kernel_divisor_on(g, v, g.vcpus[v].core, div);
            if want == g.vcpus[v].kernel_divisor { continue; }
            let before = plan(&h.info, g, v, false, 0);
            g.vcpus[v].kernel_divisor = want;
            if v == 0 && g.vmm_limits.is_some() { continue; }
            let after = plan(&h.info, g, v, false, 0);
            // A low cap already within the limit: its refills are kept.
            if (before.period, before.kernel, before.user, before.user_period)
                == (after.period, after.kernel, after.user, after.user_period) { continue; }
            if !pair(&h.info, g.id, v, &g.vcpus[v], g.vcpus[v].core, after) {
                g.stop();
                ok = false;
                break;
            }
        }
    }
    ok
}

/// Guest `gid`'s VMM is about to start on CPU `core` (before its guest
/// starts, and before the guest is back in vmmgr's table): PV kernels
/// beside an HVM vCPU there have their limit for a CPU with a VMM first
/// (kernel_divisors).  The guest's own vCPUs are not counted: they do
/// not run before its start.
pub fn vmm_arriving(h: &mut Vmmgr, gid: usize, core: usize) {
    protect(h, Some(Arrival { guest: gid, cores: 0, moves: &[], vmm: Some(core) }));
}

/// After a guest stopped or went: the survivors' limits follow at once,
/// not at the next balancer period (an HVM guest's PV neighbours have
/// their SC_K whole again, PV kernels left beside an HVM vCPU share its
/// CPU among fewer).
pub fn reconcile(h: &mut Vmmgr) {
    protect(h, None);
}

/// Whether an HVM guest's monitor should not busy-poll its network queues
/// (abi::EVENT_IO_NO_POLL, in vCPU 0's event page): when its guest is
/// capped, its boost was withdrawn (guarded or not), or another guest has vCPUs on the
/// monitor's core, whose CPU the polling would take at PRIO_VMM.
fn publish_io_flags(h: &Vmmgr, arrival: Option<Arrival>) {
    let occupied = occupied(h, arrival);
    for g in h.guests.iter().flatten().filter(|g| g.hvm.is_some() && active(g)) {
        let core = g.vmm_limits.expect("VMM limits").0;
        let no_poll = g.cpu_cap_pct > 0 || !g.vmm_boosted || occupied[core] & !(1u64 << g.id) != 0;
        let flags = if no_poll { l4h_abi::EVENT_IO_NO_POLL } else { 0 };
        let page = g.event_page(0);
        unsafe {
            let p = core::ptr::addr_of_mut!((*page).io_flags);
            if p.read_volatile() != flags {
                p.write_volatile(flags);
            }
        }
    }
}

/// Trusted placement controls contention and an existing guard.
/// A blocked or budget-depleted guest can wake before the next sample.
/// Keep guest identities so a VMM never reserves CPU against its own guest.
/// `moves`: the guest's vCPUs that move, and where (a migration's);
/// `vmm`: the CPU where its VMM is about to start (vmm_arriving).
#[derive(Clone, Copy)]
struct Arrival<'a> { guest: usize, cores: u128, moves: &'a [(usize, usize)], vmm: Option<usize> }

fn occupied(h: &Vmmgr, arrival: Option<Arrival>) -> [u64; topology::MAX_CPUS] {
    let mut cores = [0; topology::MAX_CPUS];
    for g in h.guests.iter().flatten().filter(|g| g.state == State::Running) {
        for v in &g.vcpus { cores[v.core] |= 1u64 << g.id; }
    }
    if let Some(a) = arrival.filter(|a| h.guest(a.guest).is_some_and(|g| g.state != State::Stopped)) {
        for (i, core) in cores.iter_mut().enumerate() {
            if a.cores & (1u128 << i) != 0 { *core |= 1u64 << a.guest; }
        }
    }
    cores
}

/// Reconcile all limits together so guarded VMMs sharing a core with other
/// guests divide the half-core pool. Stable placement/boost keeps the
/// installed SCs unchanged, regardless of blocking and refill phase.
fn protect(h: &mut Vmmgr, arrival: Option<Arrival>) {
    loop {
        let occupied = occupied(h, arrival);
        for g in h.guests.iter_mut().flatten().filter(|g| active(g)) {
            g.vmm_limited = !g.vmm_boosted
                && occupied[g.vmm_limits.expect("VMM limits").0] & !(1u64 << g.id) != 0;
        }
        // Limit PV kernels beside HVM vCPUs before those run (an arrival
        // included), and lift the limit where none is left.
        let div = kernel_divisors(h, arrival);
        if !limit_kernels(h, &div, arrival) { continue; }
        let backgrounds = counts(h);
        let mut failed = false;
        for g in h.guests.iter_mut().flatten().filter(|g| active(g)) {
            let core = g.vmm_limits.expect("VMM limits").0;
            let p = plan(&h.info, g, 0, true, backgrounds[core]);
            failed |= !configure_vmm(&h.info, g, p);
        }
        if !failed { break; }
        // Each failed pass stops at least one active guest: bounded by
        // MAX_GUESTS. Recompute both occupancy and pool membership so a
        // failed arrival reserves no CPU from the surviving VMMs.
    }
    publish_io_flags(h, arrival);
}

/// Install protection before any of this guest's vCPUs can run. A VMM
/// already demoted on an otherwise empty core must not stall the new guest
/// until the next 100 ms sample.
pub fn start(h: &mut Vmmgr, gid: usize) -> Result<(), Errno> {
    let g = h.guest(gid).ok_or(l4h_host::wire::NO_REPLY)?;
    if g.state != State::Created { return Err(EINVAL); }
    let cores = g.vcpus.iter().fold(0, |cores, v| cores | (1u128 << v.core));
    protect(h, Some(Arrival { guest: gid, cores, moves: &[], vmm: None }));
    let g = h.guests[gid].as_mut().unwrap();
    // The READY caller is this guest's VMM. If protection stopped it,
    // discard the reply just as guest_power does for a stopped caller.
    if g.state == State::Stopped { return Err(l4h_host::wire::NO_REPLY); }
    g.start();
    Ok(())
}

/// The core an HVM guest's monitor (l4h-hvm, whose I/O thread does its
/// devices' work) runs on: the least loaded core none of the guest's vCPUs
/// is on, preferring cores that are neither an SMT sibling of theirs nor
/// core 0, so that device work runs beside the vCPUs, as Linux's vhost
/// workers do, rather than taking turns with them; vCPU 0's if they are on
/// every core.  Its budget is the guest's VMM share all
/// the same (`plan`), and a core it shares with another guest limits it as
/// any VMM sharing a core (`protect`).
fn hvm_monitor_core(h: &Vmmgr, g: &Guest) -> usize {
    let mut load = [0usize; topology::MAX_CPUS];
    for o in h.guests.iter().flatten().filter(|o| o.state != State::Stopped && o.id != g.id) {
        // A vCPU runs guest code whenever it is not halted; a VMM or
        // monitor runs for its guest's I/O.  Sharing with a vCPU costs more
        // here, the reverse of `place`'s weights: there a vCPU avoids the
        // cores of VMMs, which wake to serve it; here the monitor is the
        // one placed, and busy vCPUs are what would delay it.
        for v in &o.vcpus { load[v.core] += 2; }
        if let Some((core, _)) = o.vmm_limits { load[core] += 1; }
    }
    let own = g.vcpus.iter().fold(0u128, |m, v| m | (1 << v.core));
    let topo = &h.info.topology;
    // An SMT sibling of the guest's own vCPUs shares their core as a vCPU
    // would; core 0 has the system's services (logd, netd, vmmgr), and
    // vmm_guard counts a VMM there as contended (protect).
    let weight = |c: usize| {
        load[c]
            + 2 * g.vcpus.iter().filter(|v| v.core != c && topo.same_core(v.core, c)).count()
            + usize::from(c == 0)
    };
    (0..h.info.cores.min(topology::MAX_CPUS))
        .filter(|&c| own & (1 << c) == 0)
        .min_by_key(|&c| weight(c))
        .unwrap_or(g.vcpus[0].core)
}

/// Charge the VMM to vCPU 0 before it starts. Boosted VMMs have independent
/// budgets; other guests reserve CPU only after protection is active.
pub fn prepare_vmm(h: &mut Vmmgr, g: &mut Guest) -> Option<budget::Plan> {
    let vcore = g.vcpus[0].core;
    let core = if g.hvm.is_some() { hvm_monitor_core(h, g) } else { vcore };
    let p = plan(&h.info, g, 0, true, 0);
    if !pair(&h.info, g.id, 0, &g.vcpus[0], vcore, p) {
        g.stop();
        return None;
    }
    g.vmm_limits = Some((core, p));
    Some(p)
}

/// CPUs and vCores for a new guest's `n` vCPUs (policy::place). Every
/// vCPU of the guests not stopped weighs one, each VMM two.
pub fn place(h: &Vmmgr, n: usize, stagger: usize) -> ArrayVec<(usize, usize), { l4h_abi::MAX_VCPUS }> {
    let mut load = [0; topology::MAX_CPUS];
    for g in h.guests.iter().flatten().filter(|g| g.state != State::Stopped) {
        for v in &g.vcpus { load[v.core] += 1; }
        if let Some((core, _)) = g.vmm_limits { load[core] += 2; }
    }
    let mut out = [(0, 0); l4h_abi::MAX_VCPUS];
    let out = &mut out[..n.min(l4h_abi::MAX_VCPUS)];
    policy::place(&h.info.topology, &load, stagger, out);
    out.iter().copied().collect()
}

/// The CPUs of some vCPUs, printed as a list.
pub struct Cores<'a>(pub &'a [Vcpu]);

impl core::fmt::Debug for Cores<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_list().entries(self.0.iter().map(|v| v.core)).finish()
    }
}

/// Apply a new CPU cap to every vCPU of guest `gid`.
pub fn set_cap(h: &mut Vmmgr, gid: usize, cap_pct: u32) -> Result<(), Errno> {
    let n = counts(h);
    let Some(Some(g)) = h.guests.get_mut(gid) else { return Err(ENOENT) };
    if g.state == State::Stopped { return Err(EINVAL); }
    g.cpu_cap_pct = cap_pct.min(100);
    let has_vmm = active(g);
    if has_vmm {
        let core = g.vmm_limits.expect("VMM limits").0;
        let p = plan(&h.info, g, 0, true, n[core]);
        if !configure_vmm(&h.info, g, p) {
            protect(h, None);
            return Err(EIO);
        }
    }
    for v in usize::from(has_vmm)..g.vcpus.len() {
        if !pair(&h.info, gid, v, &g.vcpus[v], g.vcpus[v].core, plan(&h.info, g, v, false, 0)) {
            g.stop();
            protect(h, None);
            return Err(EIO);
        }
    }
    publish_io_flags(h, None);
    Ok(())
}

const _: () = assert!(crate::MAX_GUESTS <= policy::MAX_GUESTS);
const _: () = assert!(crate::MAX_GUESTS <= u64::BITS as usize);
// policy::swap_moves keeps a guest's moved vCPUs in a u128.
const _: () = assert!(l4h_abi::MAX_VCPUS <= u128::BITS as usize);
const _: () = assert!(sel4::sel4_cfg_usize!(MAX_NUM_NODES) <= topology::MAX_CPUS);

/// The balancer's samples, one per vCPU: too large for root's stack
/// (160 KiB), so in .bss.  `balance` is its only user, and the flag makes
/// a second, nested use fail instead of aliasing it.
static SAMPLES: Scratch<ArrayVec<policy::Sample, { crate::MAX_GUESTS * l4h_abi::MAX_VCPUS }>> = Scratch::new(ArrayVec::new());

/// A vCPU's idle time (counter ticks) at `now`, from its event page: what
/// its blocks added to idle_ticks, and a block in progress (idle_since),
/// which would otherwise count as steal until it ends, and steal is
/// published monotonically.  Whoever runs the vCPU changes both under
/// idle_seq, odd meanwhile: equal even counts around the reads say they
/// are from one moment.  None if the vCPU kept changing them (its steal is
/// then left for this sample, never raised from a torn read).  A vCPU that
/// does not keep idle_seq or idle_since (an older guest) reads as before.
pub fn idle_ticks(page: *mut crate::guest::EventPage, now: u64) -> Option<u64> {
    use core::sync::atomic::{AtomicU64, Ordering, fence};
    let (seq, since, idle) = unsafe {
        (&*(core::ptr::addr_of!((*page).idle_seq) as *const AtomicU64),
            &*(core::ptr::addr_of!((*page).idle_since) as *const AtomicU64),
            &*(core::ptr::addr_of!((*page).idle_ticks) as *const AtomicU64))
    };
    for _ in 0..4 {
        let s1 = seq.load(Ordering::Acquire);
        if s1 & 1 != 0 { continue; }
        let ticks = idle.load(Ordering::Relaxed);
        let s = since.load(Ordering::Relaxed);
        fence(Ordering::Acquire);
        if seq.load(Ordering::Relaxed) == s1 {
            return Some(if s == 0 { ticks } else { ticks.wrapping_add(now.saturating_sub(s)) });
        }
    }
    None
}

/// One balancer step: sample consumption over the `elapsed_us` since the
/// last step (ending at counter value `now`), move at most one vCPU or
/// vCore, then tell each vCPU what capacity other guests leave it.
///
/// A vCPU is *busy* if it wanted at least half of its fair share of its
/// logical CPU (among the vCPUs active there): what it used and what it
/// waited for the CPU, its steal time. Balance their number per
/// physical core first, then per logical CPU. SMT siblings share execution
/// resources even when each has only one busy vCPU.
pub fn balance(h: &mut Vmmgr, elapsed_us: u64, now: u64) {
    let cores = h.info.cores;
    if elapsed_us == 0 {
        return;
    }
    let tsc_mhz = (h.info.tsc_hz / 1_000_000).max(1);
    let backgrounds = counts(h);
    let mut vmm_used = [0; crate::MAX_GUESTS];
    let mut vmm_before = [None; crate::MAX_GUESTS];
    let mut core_vmm = [0u64; topology::MAX_CPUS];
    let mut largest = [0u64; topology::MAX_CPUS];
    let mut largest_boosted = [0u64; topology::MAX_CPUS];
    // PV kernels' use of each CPU (SC_K), which crowds a VMM beside an HVM
    // vCPU as other VMMs do (BoostGuard below).
    let mut core_pvk = [0u64; topology::MAX_CPUS];
    let migration = SAMPLES.with(|sample| {
        sample.clear();
        for g in h.guests.iter_mut().flatten() {
            let cv = g.vmm.as_ref().map_or(0, |vmm| consumed(vmm.sc));
            vmm_used[g.id] = cv;
            vmm_before[g.id] = g.vmm_limits.map(|(_, p)| p);
            if active(g) {
                let core = g.vmm_limits.expect("VMM limits").0;
                core_vmm[core] += cv;
                largest[core] = largest[core].max(cv);
                if g.vmm_boosted {
                    largest_boosted[core] = largest_boosted[core].max(cv);
                }
            }
            g.vmm_usage = if active(g) { (cv * 1000 / elapsed_us) as u32 } else { 0 };
            for v in 0..g.vcpus.len() {
                let page = g.event_page(v);
                let has_vmm = v == 0 && active(g);
                let old = if has_vmm { g.vmm_limits.expect("VMM limits").1 } else { plan(&h.info, g, v, false, 0) };
                let (ck, cu) = (consumed(g.vcpus[v].sc_k), g.vcpus[v].sc_u.map_or(0, consumed));
                let c = ck + cu;
                if g.state != State::Running {
                    continue;
                }
                if g.vcpus[v].sc_u.is_some() {
                    core_pvk[g.vcpus[v].core] += ck;
                }
                // A capped vCPU whose budget split changed.
                if g.cpu_cap_pct > 0 {
                    if let Some((ks, vs)) = budget::adapt(old, g.vcpus[v].k_share, g.vmm_share,
                        [ck, cu, if has_vmm { cv } else { 0 }], elapsed_us) {
                        let bg = if has_vmm { backgrounds[g.vmm_limits.expect("VMM limits").0] } else { 0 };
                        let next = plan_with(&h.info, g, v, has_vmm, bg, ks, vs);
                        if budget::changed(old, next) {
                            let ok = if has_vmm {
                                configure_vmm(&h.info, g, next)
                            } else {
                                pair(&h.info, g.id, v, &g.vcpus[v], g.vcpus[v].core, next)
                            };
                            if !ok {
                                if g.state != State::Stopped { g.stop(); }
                                break;
                            }
                            g.vcpus[v].k_share = ks;
                            if has_vmm { g.vmm_share = vs; }
                        }
                    }
                }
                let vcpu = &mut g.vcpus[v];
                vcpu.cooldown = vcpu.cooldown.saturating_sub(1);
                vcpu.usage = (c * 1000 / elapsed_us) as u32;
                // Steal: time the vCPU existed minus what it ran minus what it
                // spent idle (reported by the guest).
                let mut waited = 0;
                if vcpu.wall_ticks != 0 || c != 0 {
                    vcpu.wall_ticks += elapsed_us * tsc_mhz;
                    vcpu.run_ticks += c * tsc_mhz;
                    if let Some(idle) = idle_ticks(page, now) {
                        let steal = vcpu.wall_ticks.saturating_sub(vcpu.run_ticks).saturating_sub(idle);
                        // steal * 1000 overflows after weeks of steal: u128.
                        let ns = u64::try_from(steal as u128 * 1000 / tsc_mhz as u128).unwrap_or(u64::MAX);
                        if ns > vcpu.steal_ns {
                            waited = (ns - vcpu.steal_ns) / 1000;
                            vcpu.steal_ns = ns;
                            unsafe { core::ptr::addr_of_mut!((*page).steal_ns).write_volatile(ns) };
                        }
                    }
                }
                // Guests are below MAX_GUESTS and have at most MAX_VCPUS
                // vCPUs, so the samples fit.
                // What it waited for a CPU counts as demand (policy.rs,
                // Census::busy), unless it waited for its own cap's budget.
                let wanted = if g.cpu_cap_pct > 0 { c } else { c.saturating_add(waited).min(elapsed_us.max(c)) };
                let _ = sample.push(policy::Sample { guest: g.id, vcpu: v, vcore: vcpu.vcore, cpu: vcpu.core, used: c,
                    wanted, movable: vcpu.cooldown == 0 });
            }
        }
        let action = if cores < 2 { None } else { policy::choose(&h.info.topology, sample, elapsed_us, &core_vmm) }?;
        let mut moves = ArrayVec::<(usize, usize), { l4h_abi::MAX_VCPUS }>::new();
        match action {
            policy::Action::IntraCore { vcpu, dst, .. } => moves.must_push((vcpu, dst)),
            policy::Action::VcoreSwap { guest, ps, pd } =>
                policy::swap_moves(&h.info.topology, sample, elapsed_us, &core_vmm, guest, ps, pd, |v, dst| { let _ = moves.push((v, dst)); }),
        }
        Some((action, moves))
    });
    let occupied = occupied(h, None);
    let hvm = hvm_cpus(h, None);
    let mut guarded_vmms = [0usize; topology::MAX_CPUS];
    for g in h.guests.iter().flatten().filter(|g| active(g) && !g.vmm_boosted) {
        guarded_vmms[g.vmm_limits.expect("VMM limits").0] += 1;
    }
    for g in h.guests.iter_mut().flatten().filter(|g| active(g)) {
        let core = g.vmm_limits.expect("VMM limits").0;
        // Zero consumption cannot distinguish a blocked guest from a
        // starved one. Protect other guests by trusted placement. Boosted
        // VMMs already round-robin at equal priority; meaningful peer use
        // or an existing lower-priority VMM establishes VMM contention.
        // Snapshot the latter before changing priorities so guest order
        // cannot affect the decisions. logd shares core 0.
        let contended = occupied[core] & !(1u64 << g.id) != 0 || core == 0
            || core_vmm[core].saturating_sub(vmm_used[g.id]) >= h.info.timeslice_us
            || guarded_vmms[core] > usize::from(!g.vmm_boosted);
        // Beside an HVM vCPU, the PV kernels' use (at most a quarter of
        // the CPU there, kernel_divisors) counts towards crowding too, the
        // CPU is crowded above three quarters (elsewhere at 80%), and the
        // largest of the VMMs still boosted is the one demoted (one
        // demoted already, using its background half, does not shield
        // it): VMMs that with the kernels take more than three quarters
        // of the CPU are demoted in turn, by the next sample, so that in
        // the steady state PRIO_USER, which has the HVM vCPU, keeps at
        // least a quarter.  Elsewhere a demoted spinner keeps shielding an
        // I/O neighbour that uses less (DESIGN.md §7.1).
        let old = vmm_before[g.id].expect("VMM limits");
        let boosted = if hvm & (1u128 << core) != 0 {
            g.vmm_guard.boost_when(g.vmm_boosted, vmm_used[g.id], core_vmm[core] + core_pvk[core], largest_boosted[core],
                contended, elapsed_us, old, budget::Crowded::BesideHvm)
        } else {
            g.vmm_guard.boost(g.vmm_boosted, vmm_used[g.id], core_vmm[core], largest[core], contended, elapsed_us, old)
        };
        if boosted == g.vmm_boosted { continue; }
        let tcb = g.vmm.as_ref().expect("VMM").tcb;
        let r = if boosted {
            tcb.tcb_set_priority(crate::slot::TCB.cap(), l4h_host::PRIO_VMM)
        } else {
            // Lower authority first: every copy of its own TCB refers to
            // this MCP, so the VMM cannot undo the priority reduction.  An
            // HVM guest's l4h-hvm keeps the lower MCP it has (hvm::MCP,
            // below the debug syscalls'): never raised.
            let mcp = if g.hvm.is_some() { l4h_host::hvm::MCP } else { l4h_host::PRIO_VMM_FAIR };
            tcb.tcb_set_mc_priority(crate::slot::TCB.cap(), mcp)
                .and_then(|_| tcb.tcb_set_priority(crate::slot::TCB.cap(), l4h_host::PRIO_VMM_FAIR))
        };
        if let Err(e) = r {
            l4h_rt::log!("l4h-vmmgr: guest {} VMM priority: {:?}; stopping guest", g.id, e);
            g.stop();
            continue;
        }
        g.vmm_boosted = boosted;
        info!("l4h-vmmgr: guest {} VMM priority {} on core {} (used {} us, VMMs {} us)",
            g.id, if boosted { l4h_host::PRIO_VMM } else { l4h_host::PRIO_VMM_FAIR }, core, vmm_used[g.id], core_vmm[core]);
    }
    protect(h, None);
    if let Some((action, moves)) = migration {
        migrate(h, action, &moves);
    }
    publish_capacity(h, elapsed_us, &vmm_used);
}

/// Apply the balancer's choice: `moves` are its `(vCPU, CPU)` pairs.
fn migrate(h: &mut Vmmgr, action: policy::Action, moves: &[(usize, usize)]) {
    let gid = match action {
        policy::Action::IntraCore { guest, .. } | policy::Action::VcoreSwap { guest, .. } => guest,
    };
    // The destinations alone: the sources are the vCPUs' own still.
    let cores = moves.iter().fold(0u128, |m, &(_, dst)| m | 1u128 << dst);
    if !h.guest(gid).is_some_and(|g| g.state == State::Running) { return; }
    // Keep source protection until the move commits, and protect the
    // destinations before their first runnable guest arrives.
    let arrival = Arrival { guest: gid, cores, moves, vmm: None };
    protect(h, Some(arrival));
    let Some(g) = h.guest(gid) else { return };
    if g.state != State::Running { return; }
    // The SC_K limits protection installed, the movers counted at their
    // destinations: a PV vCPU moved beside an HVM vCPU arrives limited,
    // never unlimited for a moment.
    let div = kernel_divisors(h, Some(arrival));
    let backgrounds = counts(h);
    for &(v, dst) in moves {
        let info = &h.info;
        let g = h.guests[gid].as_mut().unwrap();
        g.vcpus[v].kernel_divisor = kernel_divisor_on(g, v, dst, &div);
        let vmm = (v == 0 && active(g)).then(|| g.vmm_limits.expect("VMM limits"));
        let limits = match vmm {
            Some((core, _)) => plan(info, g, 0, true, backgrounds[core]),
            None => plan(info, g, v, false, 0),
        };
        // configure_vmm_sc stops the guest itself if it fails.
        let ok = pair(info, gid, v, &g.vcpus[v], dst, limits)
            && vmm.is_none_or(|(core, old)| configure_vmm_sc(info, g, core, old, limits));
        if !ok {
            if g.state != State::Stopped { g.stop(); }
            protect(h, None);
            return;
        }
        if let Some((core, _)) = vmm {
            g.vmm_limits = Some((core, limits));
        }
        let src = g.vcpus[v].core;
        info!(
            "l4h-vmmgr: balancer: guest {} vCPU {}: core {} -> {} (physical {} -> {})",
            gid, v, src, dst, h.info.topology.core(src), h.info.topology.core(dst)
        );
        let vcpu = &mut g.vcpus[v];
        vcpu.core = dst;
        vcpu.cooldown = COOLDOWN;
    }
    // The vCPUs have left their sources: unmaps in the guest's VSpaces need
    // not interrupt those cores any longer, unless another vCPU is there.
    h.guests[gid].as_mut().unwrap().flush_tlb_bitmaps();
    protect(h, None);
}

/// Publish to each vCPU of a running guest the capacity other guests left
/// it over the last period (policy::capacity, abi::EventPage::host_cap);
/// the guest takes the rest as lost capacity of that CPU.
fn publish_capacity(h: &mut Vmmgr, elapsed_us: u64, vmm_used: &[u64; crate::MAX_GUESTS]) {
    let topology = &h.info.topology;
    let mut total_cpu = [0u64; topology::MAX_CPUS];
    let mut total_phys = [0u64; topology::MAX_CPUS];
    SAMPLES.with(|sample| {
        for s in sample.iter() { total_cpu[s.cpu] += s.used; }
    });
    for g in h.guests.iter().flatten().filter(|g| active(g)) {
        total_cpu[g.vmm_limits.expect("VMM limits").0] += vmm_used[g.id];
    }
    for (c, &t) in total_cpu.iter().enumerate().take(h.info.cores) { total_phys[topology.core(c)] += t; }
    for g in h.guests.iter_mut().flatten().filter(|g| g.state == State::Running) {
        let mut own_cpu = [0u64; topology::MAX_CPUS];
        let mut own_phys = [0u64; topology::MAX_CPUS];
        SAMPLES.with(|sample| {
            for s in sample.iter().filter(|s| s.guest == g.id) { own_cpu[s.cpu] += s.used; }
        });
        if active(g) { own_cpu[g.vmm_limits.expect("VMM limits").0] += vmm_used[g.id]; }
        for (c, &t) in own_cpu.iter().enumerate().take(h.info.cores) { own_phys[topology.core(c)] += t; }
        for v in 0..g.vcpus.len() {
            let (c, p) = (g.vcpus[v].core, topology.core(g.vcpus[v].core));
            let same = total_cpu[c].saturating_sub(own_cpu[c]);
            let sibling = total_phys[p].saturating_sub(own_phys[p]).saturating_sub(same);
            let cap = policy::capacity(g.vcpus[v].host_cap, same, sibling, elapsed_us);
            if cap != g.vcpus[v].host_cap {
                g.vcpus[v].host_cap = cap;
                let page = g.event_page(v);
                unsafe { core::ptr::addr_of_mut!((*page).host_cap).write_volatile(cap as u64) };
            }
        }
    }
}

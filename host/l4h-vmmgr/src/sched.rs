//! Host CPU scheduling (DESIGN.md §7): per-guest CPU caps and a balancer
//! that spreads busy vCPUs across physical cores before SMT siblings.
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

pub fn consumed(sc: sel4::cap::SchedContext) -> (u64, bool) {
    let r = sel4::with_ipc_buffer_mut(|ipc| ipc.inner_mut().seL4_SchedContext_Consumed(sc.bits()));
    if r.error != 0 {
        l4h_rt::log!("l4h-vmmgr: SchedContext_Consumed({:#x}) failed: {}", sc.bits(), r.error);
        // Unknown readiness must not be mistaken for spare capacity.
        return (0, true);
    }
    (r.consumed, r.runnable != 0)
}

pub const K_SHARE_INIT: u32 = 500;

fn min_period() -> u64 {
    if cfg!(target_arch = "aarch64") { 40_000 } else { 0 }
}

fn plan(info: &HostInfo, g: &Guest, v: usize, has_vmm: bool, backgrounds: usize) -> budget::Plan {
    let p = budget::plan(info.timeslice_us, min_period(), g.cpu_cap_pct, g.vcpus[v].k_share,
        has_vmm.then_some(g.vmm_share));
    if has_vmm && g.vmm_limited { budget::background(p, backgrounds) } else { p }
}

fn pair(info: &HostInfo, gid: usize, v: usize, vcpu: &Vcpu, core: usize, p: budget::Plan) -> bool {
    let sc = info.sched_control(core);
    let r = sc.sched_control_configure_flags(vcpu.sc_k, p.kernel, p.period, GUEST_EXTRA_REFILLS, 0, 0)
        .and_then(|_| sc.sched_control_configure_flags(vcpu.sc_u, p.user, p.period, GUEST_EXTRA_REFILLS, 0, 0));
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
    if (p.period, p.kernel, p.user) != (old.period, old.kernel, old.user)
        && !pair(info, g.id, 0, &g.vcpus[0], g.vcpus[0].core, p) {
        g.stop();
        return false;
    }
    if (p.vmm_period, p.vmm) != (old.vmm_period, old.vmm) {
        let r = info.sched_control(core).sched_control_configure_flags(
            g.vmm.as_ref().expect("VMM").sc, p.vmm, p.vmm_period, GUEST_EXTRA_REFILLS, 0, 0);
        if let Err(e) = r {
            l4h_rt::log!("l4h-vmmgr: configure guest {} VMM on core {}: {:?}", g.id, core, e);
            g.stop();
            return false;
        }
    }
    g.vmm_limits = Some((core, p));
    true
}

/// Charge the VMM to vCPU 0 before it starts. Other VMMs' budgets are
/// independent: idle guests must not reserve CPU time from busy ones.
pub fn prepare_vmm(h: &mut Vmmgr, g: &mut Guest) -> Option<budget::Plan> {
    let core = g.vcpus[0].core;
    let p = plan(&h.info, g, 0, true, 0);
    if !pair(&h.info, g.id, 0, &g.vcpus[0], core, p) {
        g.stop();
        return None;
    }
    g.vmm_limits = Some((core, p));
    Some(p)
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
        if !configure_vmm(&h.info, g, p) { return Err(EIO); }
    }
    for v in usize::from(has_vmm)..g.vcpus.len() {
        if !pair(&h.info, gid, v, &g.vcpus[v], g.vcpus[v].core, plan(&h.info, g, v, false, 0)) {
            g.stop();
            return Err(EIO);
        }
    }
    Ok(())
}

const _: () = assert!(crate::MAX_GUESTS <= policy::MAX_GUESTS);
const _: () = assert!(sel4::sel4_cfg_usize!(MAX_NUM_NODES) <= topology::MAX_CPUS);

/// The balancer's samples, one per vCPU: too large for root's stack
/// (160 KiB), so in .bss.  `balance` is its only user, and the flag makes
/// a second, nested use fail instead of aliasing it.
static SAMPLES: Scratch<ArrayVec<policy::Sample, { crate::MAX_GUESTS * l4h_abi::MAX_VCPUS }>> = Scratch::new(ArrayVec::new());

/// One balancer step: sample consumption over the `elapsed_us` since the
/// last step, move at most one vCPU.
///
/// A vCPU is *busy* if it used at least half of its fair share of its
/// logical CPU (among the vCPUs active there). Balance their number per
/// physical core first, then per logical CPU. SMT siblings share execution
/// resources even when each has only one busy vCPU.
pub fn balance(h: &mut Vmmgr, elapsed_us: u64) {
    let cores = h.info.cores;
    if elapsed_us == 0 {
        return;
    }
    let tsc_mhz = (h.info.tsc_hz / 1_000_000).max(1);
    let backgrounds = counts(h);
    let mut vmm_used = [0; crate::MAX_GUESTS];
    let mut vmm_ready = [false; crate::MAX_GUESTS];
    let mut vmm_before = [None; crate::MAX_GUESTS];
    let mut core_vmm = [0u64; topology::MAX_CPUS];
    let mut largest = [0u64; topology::MAX_CPUS];
    let mut ready_vmms = [0usize; topology::MAX_CPUS];
    let mut guest_ready = [false; topology::MAX_CPUS];
    let migration = SAMPLES.with(|sample| {
        sample.clear();
        for g in h.guests.iter_mut().flatten() {
            let (cv, ready) = g.vmm.as_ref().map_or((0, false), |vmm| consumed(vmm.sc));
            vmm_used[g.id] = cv;
            vmm_ready[g.id] = ready;
            vmm_before[g.id] = g.vmm_limits.map(|(_, p)| p);
            if active(g) {
                let core = g.vmm_limits.expect("VMM limits").0;
                core_vmm[core] += cv;
                largest[core] = largest[core].max(cv);
                ready_vmms[core] += usize::from(ready);
            }
            g.vmm_usage = if active(g) { (cv * 1000 / elapsed_us) as u32 } else { 0 };
            for v in 0..g.vcpus.len() {
                let page = g.event_page(v);
                let has_vmm = v == 0 && active(g);
                let old = if has_vmm { g.vmm_limits.expect("VMM limits").1 } else { plan(&h.info, g, v, false, 0) };
                let ((ck, kr), (cu, ur)) = (consumed(g.vcpus[v].sc_k), consumed(g.vcpus[v].sc_u));
                let c = ck + cu;
                if g.state != State::Running {
                    continue;
                }
                // Query kernel-owned runnable state, not guest idle
                // counters or a consumption ratio. Idle/migrated vCPUs
                // must not reserve CPU from I/O on this core.
                guest_ready[g.vcpus[v].core] |= kr || ur;
                // A capped vCPU whose budget split changed.
                if g.cpu_cap_pct > 0 {
                    if let Some((ks, vs)) = budget::adapt(old, g.vcpus[v].k_share, g.vmm_share,
                        [ck, cu, if has_vmm { cv } else { 0 }], elapsed_us) {
                        let mut next = budget::plan(h.info.timeslice_us, min_period(), g.cpu_cap_pct, ks, has_vmm.then_some(vs));
                        if has_vmm && g.vmm_limited {
                            next = budget::background(next, backgrounds[g.vmm_limits.expect("VMM limits").0]);
                        }
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
                if vcpu.wall_ticks != 0 || c != 0 {
                    vcpu.wall_ticks += elapsed_us * tsc_mhz;
                    vcpu.run_ticks += c * tsc_mhz;
                    let idle = unsafe { core::ptr::addr_of!((*page).idle_ticks).read_volatile() };
                    let steal = vcpu.wall_ticks.saturating_sub(vcpu.run_ticks).saturating_sub(idle);
                    // steal * 1000 overflows after weeks of steal: u128.
                    let ns = u64::try_from(steal as u128 * 1000 / tsc_mhz as u128).unwrap_or(u64::MAX);
                    if ns > vcpu.steal_ns {
                        vcpu.steal_ns = ns;
                        unsafe { core::ptr::addr_of_mut!((*page).steal_ns).write_volatile(ns) };
                    }
                }
                // Guests are below MAX_GUESTS and have at most MAX_VCPUS
                // vCPUs, so the samples fit.
                let _ = sample.push(policy::Sample { guest: g.id, vcpu: v, cpu: vcpu.core, used: c, movable: vcpu.cooldown == 0 });
            }
        }
        if cores < 2 { None } else { policy::choose(&h.info.topology, sample, elapsed_us) }
    });
    for g in h.guests.iter_mut().flatten().filter(|g| active(g)) {
        let core = g.vmm_limits.expect("VMM limits").0;
        // logd is on core 0. A competing VMM may be runnable without
        // having consumed CPU yet, or may have blocked after its work.
        let contended = guest_ready[core] || core == 0 || core_vmm[core] > vmm_used[g.id]
            || ready_vmms[core] > usize::from(vmm_ready[g.id]);
        let boosted = g.vmm_guard.boost(g.vmm_boosted, vmm_used[g.id], core_vmm[core], largest[core], contended, elapsed_us,
            vmm_before[g.id].expect("VMM limits"));
        if boosted == g.vmm_boosted { continue; }
        let tcb = g.vmm.as_ref().expect("VMM").tcb;
        let r = if boosted {
            tcb.tcb_set_priority(crate::slot::TCB.cap(), l4h_host::PRIO_VMM)
        } else {
            // Lower authority first: every copy of its own TCB refers to
            // this MCP, so the VMM cannot undo the priority reduction.
            tcb.tcb_set_mc_priority(crate::slot::TCB.cap(), l4h_host::PRIO_VMM_FAIR)
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
    for g in h.guests.iter_mut().flatten().filter(|g| active(g)) {
        let core = g.vmm_limits.expect("VMM limits").0;
        g.vmm_limited = !g.vmm_boosted && guest_ready[core];
    }
    let backgrounds = counts(h);
    for g in h.guests.iter_mut().flatten().filter(|g| active(g)) {
        let core = g.vmm_limits.expect("VMM limits").0;
        let p = plan(&h.info, g, 0, true, backgrounds[core]);
        configure_vmm(&h.info, g, p);
    }
    let Some(policy::Migration { guest: gid, vcpu: v, src, dst }) = migration else { return };
    let Some(g) = h.guest(gid) else { return };
    if g.state != State::Running { return; }
    let limits = if v == 0 && active(g) { g.vmm_limits.expect("VMM limits").1 } else { plan(&h.info, g, v, false, 0) };
    if pair(&h.info, gid, v, &g.vcpus[v], dst, limits) {
        info!(
            "l4h-vmmgr: balancer: guest {} vCPU {}: core {} -> {} (physical {} -> {})",
            gid, v, src, dst, h.info.topology.core(src), h.info.topology.core(dst)
        );
        let g = h.guests[gid].as_mut().unwrap();
        let vcpu = &mut g.vcpus[v];
        vcpu.core = dst;
        vcpu.cooldown = COOLDOWN;
        // The vCPU has left `src`: unmaps in the guest's VSpaces need not
        // interrupt that core any longer, unless another of its vCPUs is
        // there.
        g.flush_tlb_bitmaps();
    } else {
        h.guests[gid].as_mut().unwrap().stop();
    }
}

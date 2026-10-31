//! Host CPU scheduling (DESIGN.md §7): per-guest CPU caps and a balancer
//! that spreads busy vCPUs across physical cores before SMT siblings.
//!
//! seL4 does not balance; every vCPU's two scheduling contexts (SC_K, SC_U)
//! live on one core until `SchedControl_Configure` on another core's
//! SchedControl moves them.

use l4h_host::fixed::{ArrayVec, Scratch};

use crate::guest::{State, Vcpu};
use crate::{HostInfo, Vmmgr};

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

/// seL4's minimum budget is a few times the kernel WCET; stay well above.
const MIN_BUDGET_US: u64 = 200;
/// Size of a vCPU's scheduling contexts: room for seL4's minimum of 2
/// refills plus EXTRA_REFILLS, 16 in all.  With few
/// refills, a budget used in many short pieces, as a vCPU that is
/// preempted and blocks often uses it, is merged into later refills and
/// lost to the vCPU.
pub const SC_BITS: usize = 9;
const EXTRA_REFILLS: u64 = 14;
/// SC_K's initial part of a capped vCPU's budget (permille).
pub const K_SHARE_INIT: u32 = 500;

/// Scheduling parameters of a vCPU, in µs: (period, SC_K budget, SC_U
/// budget).  Uncapped (`cap_pct` 0 or 100), both SCs may use the whole
/// period.  Under a cap the two SCs share one budget, `cap_pct` of the
/// period, so that the vCPU as a whole never exceeds its cap; SC_K gets
/// `k_share` permille of it.  Each SC needs at least MIN_BUDGET_US, so a
/// small cap stretches the period instead (1% runs 400 µs every 40 ms).
/// ARM virtual platforms use at least 40 ms under caps to amortize GIC
/// timer delivery latency.
pub fn budgets(timeslice_us: u64, cap_pct: u32, k_share: u32) -> (u64, u64, u64) {
    if cap_pct == 0 || cap_pct >= 100 {
        return (timeslice_us, timeslice_us, timeslice_us);
    }
    let cap = cap_pct as u64;
    // ARM virtual platforms deliver the GIC timer through a userspace
    // interrupt controller. Short periods lose useful runtime to that
    // delivery latency; retain a useful quota even after splitting it.
    let min_period = if cfg!(target_arch = "aarch64") { 40_000 } else { 0 };
    let period = timeslice_us.max(min_period).max((2 * MIN_BUDGET_US * 100).div_ceil(cap));
    let total = period * cap / 100;
    let k = (total * k_share as u64 / 1000).clamp(MIN_BUDGET_US, total - MIN_BUDGET_US);
    (period, k, total - k)
}

/// A capped vCPU used `ck` and `cu` µs of SC_K and SC_U over `elapsed_us`:
/// the new SC_K share, if its budget should move.
///
/// Once either SC used (nearly) all of its budget, the budget is split in
/// proportion to what each used.  The other SC's use is not a measure of
/// its demand: a vCPU alternates between its kernel and user threads
/// (each syscall or fault runs the one, then the other), so when one SC
/// runs out the other stalls too.  Giving the saturated SC "what the other
/// used plus headroom" therefore starved the other one, which saturated in
/// the next period: the split flipped every period, and a syscall-heavy
/// guest capped at 50% used about 10% of a core.  The ratio of the two
/// uses survives that throttling, so it is what the split follows.
fn adapt_share(timeslice_us: u64, cap_pct: u32, k_share: u32, ck: u64, cu: u64, elapsed_us: u64) -> Option<u32> {
    // More than the elapsed time: consumption from an earlier period
    // reported late (vmmgr ran late), not a measure of this one.
    if cap_pct == 0 || cap_pct >= 100 || ck + cu > elapsed_us || ck + cu == 0 {
        return None;
    }
    let (period, bk, bu) = budgets(timeslice_us, cap_pct, k_share);
    let total = bk + bu;
    // Use per period.
    let (uk, uu) = (ck * period / elapsed_us, cu * period / elapsed_us);
    if uk * 10 < bk * 9 && uu * 10 < bu * 9 {
        return None;
    }
    let new_k = (total * ck / (ck + cu)).clamp(MIN_BUDGET_US, total - MIN_BUDGET_US);
    // Reconfigure only for a real change.
    if new_k.abs_diff(bk) * 16 < total {
        return None;
    }
    Some((new_k * 1000).div_ceil(total) as u32)
}

/// (Re)configure vCPU `v` of guest `gid` on `core` with cap `cap_pct`.
pub fn configure(info: &HostInfo, gid: usize, v: usize, vcpu: &Vcpu, cap_pct: u32, core: usize) -> bool {
    let (period, budget_k, budget_u) = budgets(info.timeslice_us, cap_pct, vcpu.k_share);
    let sc = info.sched_control(core);
    let r = sc
        .sched_control_configure_flags(vcpu.sc_k, budget_k, period, EXTRA_REFILLS, 0, 0)
        .and_then(|_| sc.sched_control_configure_flags(vcpu.sc_u, budget_u, period, EXTRA_REFILLS, 0, 0));
    if let Err(e) = r {
        l4h_rt::log!("l4h-vmmgr: configure guest {} vCPU {} on core {}: {:?}", gid, v, core, e);
    }
    r.is_ok()
}

/// The CPUs of some vCPUs, printed as a list.
pub struct Cores<'a>(pub &'a [Vcpu]);

impl core::fmt::Debug for Cores<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_list().entries(self.0.iter().map(|v| v.core)).finish()
    }
}

/// Apply a new CPU cap to every vCPU of guest `gid`.
pub fn set_cap(h: &mut Vmmgr, gid: usize, cap_pct: u32) -> bool {
    let Some(Some(g)) = h.guests.get_mut(gid) else { return false };
    g.cpu_cap_pct = cap_pct.min(100);
    g.vcpus.iter().enumerate().all(|(v, vcpu)| configure(&h.info, gid, v, vcpu, g.cpu_cap_pct, vcpu.core))
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
    let timeslice_us = h.info.timeslice_us;
    let migration = SAMPLES.with(|sample| {
        sample.clear();
        for g in h.guests.iter_mut().flatten() {
            for v in 0..g.vcpus.len() {
                let page = g.event_page(v);
                let vcpu = &mut g.vcpus[v];
                let (ck, cu) = (consumed(vcpu.sc_k), consumed(vcpu.sc_u));
                let c = ck + cu;
                if g.state != State::Running {
                    continue;
                }
                // A capped vCPU whose budget split changed.
                if let Some(share) = adapt_share(timeslice_us, g.cpu_cap_pct, vcpu.k_share, ck, cu, elapsed_us) {
                    vcpu.k_share = share;
                    configure(&h.info, g.id, v, vcpu, g.cpu_cap_pct, vcpu.core);
                }
                vcpu.cooldown = vcpu.cooldown.saturating_sub(1);
                vcpu.usage = (c * 1000 / elapsed_us) as u32;
                // Steal: time the vCPU existed minus what it ran minus what it
                // spent idle (reported by the guest).
                if vcpu.wall_ticks != 0 || c != 0 {
                    vcpu.wall_ticks += elapsed_us * tsc_mhz;
                    vcpu.run_ticks += c * tsc_mhz;
                    let idle = unsafe { core::ptr::addr_of!((*page).idle_ticks).read_volatile() };
                    let steal = vcpu.wall_ticks.saturating_sub(vcpu.run_ticks).saturating_sub(idle);
                    let ns = steal * 1000 / tsc_mhz;
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
    let Some(policy::Migration { guest: gid, vcpu: v, src, dst }) = migration else { return };
    let Some(g) = h.guest(gid) else { return };
    if configure(&h.info, gid, v, &g.vcpus[v], g.cpu_cap_pct, dst) {
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
    }
}

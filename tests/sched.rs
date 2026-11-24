// Run with tests/run-schedtest.sh; no seL4 toolchain or QEMU needed.
extern crate alloc;

#[path = "../host/l4h-vmmgr/src/sched/policy.rs"]
mod policy;
#[path = "../host/l4h-task/src/topology.rs"]
mod topology;
#[path = "../host/l4h-vmmgr/src/sched/budget.rs"]
mod budget;

use policy::{Action, Sample, choose, swap_moves};
use topology::Topology;

const PERIOD: u64 = 100_000;

#[test]
fn vmm_and_guest_share_caps_without_reserving_uncapped_cpu_time() {
    for has_vmm in [false, true] {
        for cap in 0..=100 {
            for (host_slice, minimum, guest_slice) in [
                (5_000, 0, 20_000),
                (5_000, 40_000, 20_000),
                (25_000, 0, 25_000),
            ] {
                for k in [0, 1, 250, 500, 750, 999, 1000] {
                    for v in [0, 1, 250, 500, 750, 999, 1000] {
                        let p = budget::plan(host_slice, minimum, cap, k, has_vmm.then_some(v));
                        assert!(p.kernel >= budget::MIN_US && p.user >= budget::MIN_US);
                        assert!(if has_vmm { p.vmm >= budget::MIN_US } else { p.vmm == 0 });
                        if cap > 0 && (cap < 100 || has_vmm) {
                            if has_vmm { assert_eq!(p.period, p.vmm_period); }
                            if cap == 100 { assert_eq!(p.period, host_slice.max(minimum)); }
                            assert_eq!(p.kernel + p.user + p.vmm, p.period * cap as u64 / 100);
                        } else {
                            assert_eq!((p.period, p.kernel, p.user), (guest_slice, guest_slice, guest_slice));
                            let vmm_slice = if has_vmm { host_slice } else { 0 };
                            assert_eq!((p.vmm, p.vmm_period), (vmm_slice, vmm_slice));
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn capped_vmm_and_kernel_shares_follow_their_measured_demand() {
    let share = budget::VMM_SHARE_INIT;
    let old = budget::plan(5000, 0, 50, 500, Some(share));
    let (k, v) = budget::adapt(old, 500, share, [18_000, 18_000, 0], PERIOD).unwrap();
    let cpu = budget::plan(5000, 0, 50, k, Some(v));
    assert!(budget::changed(old, cpu));
    assert_eq!(cpu.vmm, budget::MIN_US);
    let (k, v) = budget::adapt(old, 500, share, [100, 100, 12_500], PERIOD).unwrap();
    let io = budget::plan(5000, 0, 50, k, Some(v));
    assert!(budget::changed(old, io));
    assert_eq!(io.vmm, io.period / 2 - 2 * budget::MIN_US);
    assert_eq!(io.kernel + io.user + io.vmm, io.period / 2);
    assert_eq!(budget::adapt(old, 500, share, [10, 10, 10], PERIOD), None);
    assert_eq!(budget::adapt(old, 500, share, [PERIOD, PERIOD, 0], PERIOD), None);
    assert!(!budget::changed(old, old));
}

#[test]
fn only_the_largest_contending_vmm_loses_its_boost() {
    let p = budget::plan(5000, 0, 0, 500, Some(250));
    let decide = |used, total, largest, contended, elapsed| {
        budget::BoostGuard::default().boost(true, used, total, largest, contended, elapsed, p)
    };
    assert!(decide(20_000, 20_000, 20_000, true, PERIOD));
    assert!(!decide(45_000, 90_000, 45_000, true, PERIOD));
    assert!(decide(90_000, 90_000, 90_000, false, PERIOD));
    assert!(decide(40_000, 100_000, 60_000, true, PERIOD));
    assert!(!decide(60_000, 100_000, 60_000, true, PERIOD));
    assert!(decide(0, 0, 0, true, 0));
    // Many spinning VMMs cannot evade the trigger by splitting the load.
    assert!(!decide(1000, 64_000, 1000, true, 80_000));
}

#[test]
fn recovery_requires_continuous_quiet_and_ignores_neighbour_pressure() {
    let p = budget::plan(5000, 0, 0, 500, Some(250));
    let mut guard = budget::BoostGuard::default();
    assert!(!guard.boost(true, 90_000, 90_000, 90_000, true, PERIOD, p));
    let p = budget::background(p, 1);
    for _ in 0..5 { assert!(!guard.boost(false, 0, 100_000, 100_000, true, PERIOD, p)); }
    // Saturation resets the quiet streak rather than accumulating idle gaps.
    assert!(!guard.boost(false, 50_000, 100_000, 50_000, true, PERIOD, p));
    for _ in 0..9 { assert!(!guard.boost(false, 0, 100_000, 100_000, true, PERIOD, p)); }
    assert!(guard.boost(false, 0, 100_000, 100_000, true, PERIOD, p));
}

#[test]
fn quiet_spin_cycles_back_off_instead_of_stalling_guests_every_other_sample() {
    let p = budget::plan(5000, 0, 0, 500, Some(250));
    let mut guard = budget::BoostGuard::default();
    let mut boosted = true;
    let mut bursts = 0;
    for _ in 0..10_000 {
        let used = if boosted { bursts += 1; PERIOD } else { 0 };
        let old = if boosted { p } else { budget::background(p, 1) };
        boosted = guard.boost(boosted, used, PERIOD, PERIOD, true, PERIOD, old);
    }
    assert!(bursts > 1 && bursts < 100, "repeated full-priority bursts must occupy under 1% of this long run: {bursts}");
}

#[test]
fn old_demotion_history_expires_after_a_minute_without_another_demotion() {
    let p = budget::plan(5000, 0, 0, 500, Some(250));
    let mut guard = budget::BoostGuard::default();
    for wait in [1, 2, 4, 8, 16, 16] {
        assert!(!guard.boost(true, PERIOD, PERIOD, PERIOD, true, PERIOD, p));
        for _ in 1..wait*10 { assert!(!guard.boost(false, 0, 0, 0, false, PERIOD, p)); }
        assert!(guard.boost(false, 0, 0, 0, false, PERIOD, p));
    }
    for _ in 0..600 { assert!(guard.boost(true, 0, 0, 0, false, PERIOD, p)); }
    assert!(!guard.boost(true, PERIOD, PERIOD, PERIOD, true, PERIOD, p));
    for _ in 0..9 { assert!(!guard.boost(false, 0, 0, 0, false, PERIOD, p)); }
    assert!(guard.boost(false, 0, 0, 0, false, PERIOD, p), "an old guest should recover like a new one");
}

#[test]
fn another_demotion_restarts_the_history_expiry_window() {
    let p = budget::plan(5000, 0, 0, 500, Some(250));
    let mut guard = budget::BoostGuard::default();
    assert!(!guard.boost(true, PERIOD, PERIOD, PERIOD, true, PERIOD, p));
    assert!(guard.boost(false, 0, 0, 0, false, 1_000_000, p));
    assert!(guard.boost(true, 0, 0, 0, false, 59_900_000, p));
    assert!(!guard.boost(true, PERIOD, PERIOD, PERIOD, true, PERIOD, p));
    // The short quiet intervals never reach a boosted minute, even over
    // a long-lived guest. They cannot reset the anti-cycling history.
    for _ in 0..19 { assert!(!guard.boost(false, 0, 0, 0, false, PERIOD, p)); }
    assert!(guard.boost(false, 0, 0, 0, false, PERIOD, p));
    assert!(guard.boost(true, 0, 0, 0, false, 59_900_000, p));
    assert!(!guard.boost(true, PERIOD, PERIOD, PERIOD, true, PERIOD, p));
    for _ in 0..39 { assert!(!guard.boost(false, 0, 0, 0, false, PERIOD, p)); }
    assert!(guard.boost(false, 0, 0, 0, false, PERIOD, p));
}

#[test]
fn background_vmms_share_half_a_core_without_exceeding_guest_caps() {
    for peers in 1..=64 {
        for cap in 0..=100 {
            for minimum in [0, 40_000] {
                let p = budget::plan(5000, minimum, cap, 500, Some(250));
                let q = budget::background(p, peers);
                assert!(q.vmm >= budget::MIN_US);
                assert!(q.vmm * 2 * peers as u64 <= q.vmm_period);
                assert!(q.vmm as u128 * p.vmm_period as u128 <= p.vmm as u128 * q.vmm_period as u128);
                assert_eq!((q.kernel, q.user, q.period), (p.kernel, p.user, p.period));
            }
        }
    }
}

#[test]
fn vcpus_without_a_vmm_keep_the_existing_two_context_budget() {
    for cap in 1..100 {
        let p = budget::plan(5000, 0, cap, 500, None);
        assert_eq!(p.kernel + p.user, p.period * cap as u64 / 100);
        assert_eq!(p.vmm, 0);
    }
    let p = budget::plan(5000, 0, 1, 500, None);
    assert_eq!((p.period, p.kernel, p.user), (40_000, 200, 200));
}

fn vcpu(guest: usize, vcpu: usize, cpu: usize, used: u64) -> Sample {
    Sample { guest, vcpu, vcore: 0, cpu, used, movable: true }
}

/// Number each guest's vCores by physical core, as placement would.
fn vcores(t: &Topology, mut s: Vec<Sample>) -> Vec<Sample> {
    for v in &mut s {
        v.vcore = t.core(v.cpu);
    }
    s
}

/// Apply `a` as sched.rs does; the `(src, dst)` CPUs of the moved vCPUs.
fn apply(t: &Topology, s: &mut [Sample], a: Action) -> Vec<(usize, usize)> {
    let mut moves = Vec::new();
    match a {
        Action::IntraCore { guest, vcpu, dst, .. } => moves.push((guest, vcpu, dst)),
        Action::VcoreSwap { guest, ps, pd } => swap_moves(t, s, PERIOD, guest, ps, pd, |v, dst| moves.push((guest, v, dst))),
    }
    let mut cpus = Vec::new();
    for (g, v, dst) in moves {
        let x = s.iter_mut().find(|x| x.guest == g && x.vcpu == v).unwrap();
        cpus.push((x.cpu, dst));
        x.cpu = dst;
    }
    cpus
}

fn step(t: &Topology, s: &[Sample]) -> Option<(usize, usize)> {
    let a = choose(t, s, PERIOD)?;
    let mut copy: Vec<_> = s.iter().map(|x| Sample { ..*x }).collect();
    let moved = apply(t, &mut copy, a);
    assert_eq!(moved.len(), 1, "{a:?}");
    Some(moved[0])
}

/// Each guest's vCores map one-to-one onto physical cores.
fn assert_vcores_whole(t: &Topology, s: &[Sample]) {
    let mut seen = std::collections::BTreeMap::new();
    let mut back = std::collections::BTreeMap::new();
    for v in s {
        assert_eq!(*seen.entry((v.guest, v.vcore)).or_insert(t.core(v.cpu)), t.core(v.cpu), "vCore split");
        assert_eq!(*back.entry((v.guest, t.core(v.cpu))).or_insert(v.vcore), v.vcore, "vCores share a core");
    }
}

#[test]
fn busy_smt_siblings_use_an_idle_physical_core() {
    let t = Topology::from_ids(&[0, 0, 1, 1]);
    let s = [vcpu(0, 0, 0, PERIOD), vcpu(1, 0, 1, PERIOD)];
    let (src, dst) = step(&t, &s).unwrap();
    assert!([0, 1].contains(&src));
    assert!([2, 3].contains(&dst));
}

#[test]
fn one_busy_vcpu_per_physical_core_stays_put() {
    let t = Topology::from_ids(&[0, 0, 1, 1]);
    let s = [vcpu(0, 0, 0, PERIOD), vcpu(1, 0, 2, PERIOD)];
    assert_eq!(choose(&t, &s, PERIOD), None);
}

#[test]
fn all_threads_busy_and_balanced_stay_put() {
    let t = Topology::from_ids(&[0, 0, 1, 1]);
    let s: Vec<_> = (0..4).map(|cpu| vcpu(cpu, 0, cpu, PERIOD)).collect();
    assert_eq!(choose(&t, &s, PERIOD), None);
}

#[test]
fn balance_within_a_physical_core_when_no_spare_core() {
    let t = Topology::from_ids(&[0, 0, 1, 1]);
    let s = [vcpu(0, 0, 0, PERIOD / 2), vcpu(1, 0, 0, PERIOD / 2), vcpu(2, 0, 2, PERIOD), vcpu(3, 0, 3, PERIOD)];
    assert!(matches!(choose(&t, &s, PERIOD), Some(Action::IntraCore { src: 0, dst: 1, .. })));
}

#[test]
fn do_not_fill_a_sibling_when_another_physical_core_is_empty() {
    let t = Topology::from_ids(&[0, 0, 1, 1]);
    let s = [vcpu(0, 0, 0, PERIOD / 2), vcpu(1, 0, 0, PERIOD / 2)];
    assert!([2, 3].contains(&step(&t, &s).unwrap().1));
}

#[test]
fn cooldown_vcpus_are_counted_but_not_moved() {
    let t = Topology::from_ids(&[0, 0, 1, 1]);
    let mut s = [vcpu(0, 0, 0, PERIOD), vcpu(1, 0, 1, PERIOD)];
    s[0].movable = false;
    assert_eq!(choose(&t, &s, PERIOD), Some(Action::VcoreSwap { guest: 1, ps: 0, pd: 2 }));
    s[1].movable = false;
    assert_eq!(choose(&t, &s, PERIOD), None);
}

#[test]
fn equivalent_destinations_prefer_moving_a_vcore_to_swapping_it() {
    let t = Topology::from_ids(&[0, 0, 1, 1, 2, 2]);
    // Only guest 0 may move; trading places with its idle vCore on core 1
    // would gain as much as taking the empty core 2.
    let mut s = vcores(&t, vec![vcpu(0, 0, 0, PERIOD), vcpu(1, 0, 1, PERIOD), vcpu(0, 1, 2, 0)]);
    s[1].movable = false;
    assert_eq!(choose(&t, &s, PERIOD), Some(Action::VcoreSwap { guest: 0, ps: 0, pd: 4 }));
    assert_eq!(step(&t, &s), Some((0, 4)));
}

#[test]
fn lightly_loaded_targets_and_flat_topology_keep_working() {
    let t = Topology::flat(2);
    let s = [vcpu(0, 0, 0, PERIOD / 2), vcpu(1, 0, 0, PERIOD / 2), vcpu(2, 0, 1, PERIOD / 4)];
    assert_eq!(step(&t, &s), Some((0, 1)));
    let mut full = s;
    full[2].used = PERIOD;
    assert_eq!(choose(&t, &full, PERIOD), None);
}

#[test]
fn starved_busy_vcpus_count_and_low_caps_do_not_trigger_migration() {
    let t = Topology::flat(2);
    let s: Vec<_> = (0..10).map(|g| vcpu(g, 0, 0, PERIOD / 10)).collect();
    assert_eq!(step(&t, &s), Some((0, 1)));
    let capped = [vcpu(0, 0, 0, PERIOD / 10), vcpu(1, 0, 0, PERIOD / 10)];
    assert_eq!(choose(&t, &capped, PERIOD), None);
    assert_eq!(choose(&t, &s, 0), None);
    assert_eq!(choose(&Topology::flat(1), &[vcpu(0, 0, 0, PERIOD)], PERIOD), None);
    assert_eq!(choose(&t, &[], PERIOD), None);
}

#[test]
fn use_an_available_source_when_the_busiest_cannot_move() {
    let t = Topology::flat(3);
    let mut s: Vec<_> = (0..3).map(|g| vcpu(g, 0, 0, PERIOD / 3)).collect();
    for v in &mut s {
        v.movable = false;
    }
    s.extend([vcpu(3, 0, 1, PERIOD / 2), vcpu(4, 0, 1, PERIOD / 2)]);
    assert_eq!(step(&t, &s), Some((1, 2)));
}

#[test]
fn a_busy_vcore_trades_places_with_the_guests_idle_one_as_a_whole() {
    // Guest 0: a busy vCore of two vCPUs on core 0, beside another guest's
    // busy vCPU, and an idle vCore on core 2. Core 4 runs two busy vCPUs
    // of guest 2, so core 2 is the only gain.
    let t = Topology::from_ids(&[0, 0, 1, 1, 2, 2]);
    let s = vec![vcpu(0, 0, 0, PERIOD / 2), vcpu(0, 1, 1, PERIOD / 2), vcpu(1, 0, 0, PERIOD / 2),
        vcpu(0, 2, 2, 0), vcpu(0, 3, 3, 0), vcpu(2, 0, 4, PERIOD), vcpu(2, 1, 5, PERIOD)];
    let mut s = vcores(&t, s);
    s[2].movable = false;
    assert_eq!(choose(&t, &s, PERIOD), Some(Action::VcoreSwap { guest: 0, ps: 0, pd: 2 }));
    let moved = apply(&t, &mut s, Action::VcoreSwap { guest: 0, ps: 0, pd: 2 });
    // All four vCPUs move; the busy ones each alone on a CPU of core 2,
    // the idle ones beside guest 1's vCPU, which keeps its CPU.
    assert_eq!(moved.len(), 4);
    assert_vcores_whole(&t, &s);
    let mut busy: Vec<_> = s.iter().filter(|v| v.guest == 0 && v.used > 0).map(|v| v.cpu).collect();
    busy.sort();
    assert_eq!(busy, [2, 3]);
    assert!(s.iter().filter(|v| v.guest == 0 && v.used == 0).all(|v| t.core(v.cpu) == 0));
}

#[test]
fn a_split_or_cooling_vcore_does_not_move() {
    let t = Topology::from_ids(&[0, 0, 1, 1]);
    let mut s = vcores(&t, vec![vcpu(0, 0, 0, PERIOD), vcpu(0, 1, 1, PERIOD), vcpu(1, 0, 0, PERIOD)]);
    s[2].movable = false;
    assert_eq!(choose(&t, &s, PERIOD), Some(Action::VcoreSwap { guest: 0, ps: 0, pd: 2 }));
    s[1].movable = false;
    assert!(!matches!(choose(&t, &s, PERIOD), Some(Action::VcoreSwap { .. })));
    s[1].movable = true;
    s[1].vcore = 7;
    assert!(!matches!(choose(&t, &s, PERIOD), Some(Action::VcoreSwap { .. })));
}

#[test]
fn hybrid_cores_do_not_take_a_wider_vcore() {
    // Core 0 has two threads, cores 2 and 3 one each.
    let t = Topology::from_ids(&[7, 7, 8, 9]);
    let mut s = vcores(&t, vec![vcpu(0, 0, 0, PERIOD), vcpu(0, 1, 1, PERIOD), vcpu(1, 0, 0, PERIOD), vcpu(1, 1, 1, PERIOD)]);
    s[2].movable = false;
    s[3].movable = false;
    assert_eq!(choose(&t, &s, PERIOD), None);
    // One vCPU wide, it fits.
    s.remove(1);
    assert!(matches!(choose(&t, &s, PERIOD), Some(Action::VcoreSwap { guest: 0, ps: 0, pd: 2 | 3 })));
    // A narrow core's vCore may not trade places with a wide one either.
    let mut s = vcores(&t, vec![vcpu(0, 0, 0, PERIOD), vcpu(0, 1, 1, 0), vcpu(0, 2, 2, 0), vcpu(1, 0, 0, PERIOD),
        vcpu(1, 1, 1, PERIOD), vcpu(2, 0, 3, PERIOD)]);
    for v in &mut s[3..] {
        v.movable = false;
    }
    assert!(!matches!(choose(&t, &s, PERIOD), Some(Action::VcoreSwap { guest: 0, pd: 2, .. })));
}

#[test]
fn siblings_balance_within_a_core_without_leaving_it() {
    let t = Topology::from_ids(&[0, 0, 1, 1]);
    let s = vcores(&t, vec![vcpu(0, 0, 0, PERIOD / 2), vcpu(0, 1, 0, PERIOD / 2), vcpu(0, 2, 2, PERIOD), vcpu(0, 3, 3, PERIOD)]);
    assert!(matches!(choose(&t, &s, PERIOD), Some(Action::IntraCore { guest: 0, src: 0, dst: 1, .. })));
}

#[test]
fn equal_vcores_do_not_ping_pong() {
    // Two 4-vCPU guests with two busy vCPUs each on 4 cores of 2 threads.
    let t = Topology::from_ids(&[0, 0, 1, 1, 2, 2, 3, 3]);
    let mut s = Vec::new();
    let mut load = [0usize; topology::MAX_CPUS];
    for g in 0..2 {
        let mut out = [(0, 0); 4];
        policy::place(&t, &load, g, &mut out);
        for (v, &(cpu, vcore)) in out.iter().enumerate() {
            load[cpu] += 1;
            s.push(Sample { guest: g, vcpu: v, vcore, cpu, used: 0, movable: true });
        }
    }
    let mut moves = 0;
    for _ in 0..100 {
        let mut active = [0u64; topology::MAX_CPUS];
        for v in s.iter().filter(|v| v.vcpu < 2) {
            active[v.cpu] += 1;
        }
        for v in &mut s {
            v.used = if v.vcpu < 2 { PERIOD / active[v.cpu] } else { 0 };
        }
        let Some(a) = choose(&t, &s, PERIOD) else { break };
        apply(&t, &mut s, a);
        assert_vcores_whole(&t, &s);
        moves += 1;
    }
    assert!(moves < 10, "{moves} moves");
    let mut busy = [0; topology::MAX_CPUS];
    for v in s.iter().filter(|v| v.vcpu < 2) {
        busy[t.core(v.cpu)] += 1;
    }
    assert_eq!((0..8).filter(|&c| t.core(c) == c).map(|c| busy[c]).collect::<Vec<_>>(), [1, 1, 1, 1]);
}

#[test]
fn placement_spreads_and_numbers_vcores_by_physical_core() {
    // run-smttest.sh: dom0's vCPU and VMM on CPU 0.
    let t = Topology::from_ids(&[0, 0, 1, 1]);
    let mut load = [0usize; topology::MAX_CPUS];
    load[0] = 3;
    for stagger in 0..4 {
        let mut out = [(0, 0); 4];
        policy::place(&t, &load, stagger, &mut out);
        assert_eq!(out, [(2, 0), (1, 1), (3, 0), (0, 1)]);
    }
    // Guests of equal size on an idle host start on different cores.
    let t = Topology::from_ids(&[0, 0, 1, 1, 2, 2, 3, 3]);
    let mut load = [0usize; topology::MAX_CPUS];
    let mut first = Vec::new();
    for g in 0..4 {
        let mut out = [(0, 0); 1];
        policy::place(&t, &load, g, &mut out);
        load[out[0].0] += 1;
        first.push(t.core(out[0].0));
    }
    first.sort();
    assert_eq!(first, [0, 2, 4, 6]);
    // More vCPUs than threads: every CPU of the guest's cores, then again.
    let mut out = [(0, 0); 10];
    policy::place(&t, &[0; topology::MAX_CPUS], 0, &mut out);
    let mut per_cpu = [0; 8];
    for &(cpu, vcore) in &out {
        per_cpu[cpu] += 1;
        assert_eq!(vcore, out.iter().position(|o| t.core(o.0) == t.core(cpu)).map(|i| out[i].1).unwrap());
    }
    assert!(per_cpu.iter().all(|&n| (1..=2).contains(&n)));
}

#[test]
fn capacity_hint_weighs_own_cpu_over_siblings_and_stays_in_range() {
    assert_eq!(policy::capacity(1024, 0, 0, PERIOD), 1024);
    // Half the CPU taken: 1024 - 256, averaged with the old value.
    assert_eq!(policy::capacity(768, PERIOD / 2, 0, PERIOD), 768);
    assert_eq!(policy::capacity(674, 0, PERIOD, PERIOD), 674);
    // Saturated neighbours, however long the period ran: 1024 - 512 - 350.
    let mut cap = 1024;
    for _ in 0..20 {
        cap = policy::capacity(cap, 3 * PERIOD, 3 * PERIOD, PERIOD);
        assert!((128..=1024).contains(&cap));
    }
    assert_eq!(cap, 162);
    assert_eq!(policy::capacity(500, PERIOD, PERIOD, 0), 500);
}

#[test]
fn repeated_steps_converge_on_smt_and_flat_hosts() {
    for ids in [&[0, 0, 1, 1, 2, 2][..], &[4, 9, 4, 12, 9][..], &[0, 1, 2, 3][..]] {
        let t = Topology::from_ids(ids);
        for count in 1..=24 {
            let mut s: Vec<_> = (0..count).map(|g| vcpu(g, 0, 0, 0)).collect();
            for step in 0..200 {
                let mut counts = vec![0; ids.len()];
                for v in &s {
                    counts[v.cpu] += 1;
                }
                for v in &mut s {
                    v.used = PERIOD / counts[v.cpu];
                }
                let Some(a) = choose(&t, &s, PERIOD) else { break };
                assert!(step < 199, "balancer did not settle: {ids:?}, {count}");
                apply(&t, &mut s, a);
            }
            let mut physical = vec![0usize; ids.len()];
            for v in &s {
                physical[t.core(v.cpu)] += 1;
            }
            let counts: Vec<_> = (0..ids.len()).filter(|&c| t.core(c) == c).map(|c| physical[c]).collect();
            assert!(counts.iter().max().unwrap() - counts.iter().min().unwrap() <= 1);
        }
    }
}

#[test]
fn physical_cores_counts_distinct_cores() {
    // CTL_HOST_INFO reports this as the host's physical cores.
    for (ids, want) in [
        (&[0, 0, 1, 1][..], 2),
        (&[0, 0, 1, 1, 2, 2][..], 3),
        (&[4, 9, 4, 12, 9][..], 3),
        (&[42, 7, 42, 99, 7, 42][..], 3),
        (&[0, 1, 2, 3][..], 4),
        (&[5][..], 1),
    ] {
        let t = Topology::from_ids(ids);
        assert_eq!(t.physical_cores(), want, "{ids:?}");
        let (cpus, physical, order) = t.raw();
        assert_eq!(Topology::from_raw(cpus, physical, order).physical_cores(), want, "{ids:?}");
    }
    for cpus in [0, 1, 4, topology::MAX_CPUS] {
        assert_eq!(Topology::flat(cpus).physical_cores(), cpus);
    }
}

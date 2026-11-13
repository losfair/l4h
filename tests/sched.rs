// Run with tests/run-schedtest.sh; no seL4 toolchain or QEMU needed.
extern crate alloc;

#[path = "../host/l4h-vmmgr/src/sched/policy.rs"]
mod policy;
#[path = "../host/l4h-task/src/topology.rs"]
mod topology;
#[path = "../host/l4h-vmmgr/src/sched/budget.rs"]
mod budget;

use policy::{Migration, Sample, choose};
use topology::Topology;

const PERIOD: u64 = 100_000;

#[test]
fn vmm_and_guest_share_caps_without_reserving_uncapped_cpu_time() {
    for has_vmm in [false, true] {
        for cap in 0..=100 {
            for minimum in [0, 40_000] {
                for k in [0, 1, 250, 500, 750, 999, 1000] {
                    for v in [0, 1, 250, 500, 750, 999, 1000] {
                        let p = budget::plan(5000, minimum, cap, k, has_vmm.then_some(v));
                        assert!(p.kernel >= budget::MIN_US && p.user >= budget::MIN_US);
                        assert!(if has_vmm { p.vmm >= budget::MIN_US } else { p.vmm == 0 });
                        if cap > 0 && (cap < 100 || has_vmm) {
                            if has_vmm { assert_eq!(p.period, p.vmm_period); }
                            assert_eq!(p.kernel + p.user + p.vmm, p.period * cap as u64 / 100);
                        } else {
                            assert_eq!((p.period, p.kernel, p.user), (5000, 5000, 5000));
                            assert_eq!(p.vmm, if has_vmm { 5000 } else { 0 });
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
    Sample { guest, vcpu, cpu, used, movable: true }
}

#[test]
fn busy_smt_siblings_use_an_idle_physical_core() {
    let t = Topology::from_ids(&[0, 0, 1, 1]);
    let s = [vcpu(0, 0, 0, PERIOD), vcpu(1, 0, 1, PERIOD)];
    let m = choose(&t, &s, PERIOD).unwrap();
    assert!([0, 1].contains(&m.src));
    assert!([2, 3].contains(&m.dst));
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
    let m = choose(&t, &s, PERIOD).unwrap();
    assert_eq!((m.src, m.dst), (0, 1));
}

#[test]
fn do_not_fill_a_sibling_when_another_physical_core_is_empty() {
    let t = Topology::from_ids(&[0, 0, 1, 1]);
    let s = [vcpu(0, 0, 0, PERIOD / 2), vcpu(1, 0, 0, PERIOD / 2)];
    let m = choose(&t, &s, PERIOD).unwrap();
    assert!([2, 3].contains(&m.dst));
}

#[test]
fn cooldown_vcpus_are_counted_but_not_moved() {
    let t = Topology::from_ids(&[0, 0, 1, 1]);
    let mut s = [vcpu(0, 0, 0, PERIOD), vcpu(1, 0, 1, PERIOD)];
    s[0].movable = false;
    assert_eq!(choose(&t, &s, PERIOD).unwrap().guest, 1);
    s[1].movable = false;
    assert_eq!(choose(&t, &s, PERIOD), None);
}

#[test]
fn equivalent_destinations_prefer_no_other_vcpu_of_the_guest() {
    let t = Topology::from_ids(&[0, 0, 1, 1, 2, 2]);
    let s = [vcpu(0, 0, 0, PERIOD), vcpu(1, 0, 1, PERIOD), vcpu(0, 1, 2, 0)];
    // Only guest 0 may move; its idle vCPU on core 1 still counts for placement.
    let mut s = s;
    s[1].movable = false;
    assert!([4, 5].contains(&choose(&t, &s, PERIOD).unwrap().dst));
}

#[test]
fn lightly_loaded_targets_and_flat_topology_keep_working() {
    let t = Topology::flat(2);
    let s = [vcpu(0, 0, 0, PERIOD / 2), vcpu(1, 0, 0, PERIOD / 2), vcpu(2, 0, 1, PERIOD / 4)];
    assert_eq!(choose(&t, &s, PERIOD).map(|m| (m.src, m.dst)), Some((0, 1)));
    let mut full = s;
    full[2].used = PERIOD;
    assert_eq!(choose(&t, &full, PERIOD), None);
}

#[test]
fn starved_busy_vcpus_count_and_low_caps_do_not_trigger_migration() {
    let t = Topology::flat(2);
    let s: Vec<_> = (0..10).map(|g| vcpu(g, 0, 0, PERIOD / 10)).collect();
    assert_eq!(choose(&t, &s, PERIOD).map(|m| (m.src, m.dst)), Some((0, 1)));
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
    assert_eq!(choose(&t, &s, PERIOD).map(|m| (m.src, m.dst)), Some((1, 2)));
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
                let Some(Migration { guest, dst, .. }) = choose(&t, &s, PERIOD) else { break };
                assert!(step < 199, "balancer did not settle: {ids:?}, {count}");
                s[guest].cpu = dst;
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

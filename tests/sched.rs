// Run with tests/run-schedtest.sh; no seL4 toolchain or QEMU needed.
extern crate alloc;

#[path = "../host/l4h-vmmgr/src/sched/policy.rs"]
mod policy;
#[path = "../host/l4h-task/src/topology.rs"]
mod topology;

use policy::{Migration, Sample, choose};
use topology::Topology;

const PERIOD: u64 = 100_000;

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

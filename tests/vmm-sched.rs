//! Production scheduling, with only kernel configuration and consumption
//! modeled. Exercise quota changes through the actual lifecycle helpers.
#![allow(dead_code)]
extern crate self as l4h_rt;
extern crate self as sel4;
pub use kernel::{cap, with_ipc_buffer_mut};
use std::cell::RefCell;
use std::collections::BTreeMap;

#[macro_export] macro_rules! log { ($($a:tt)*) => {{ let _ = format_args!($($a)*); }}; }
#[macro_export] macro_rules! info { ($($a:tt)*) => {{ let _ = format_args!($($a)*); }}; }
#[macro_export] macro_rules! sel4_cfg_usize { ($($a:tt)*) => { 64 }; }
mod kernel {
    pub mod cap {
        #[derive(Clone, Copy)] pub struct SchedContext(pub u64);
        impl SchedContext { pub fn bits(self) -> u64 { self.0 } }
        #[derive(Clone, Copy)] pub struct Tcb(pub u64);
        impl Tcb {
            pub fn tcb_set_mc_priority(&self, authority: Self, priority: u64) -> Result<(), ()> {
                assert_eq!(authority.0, 0);
                crate::MODEL.with_borrow_mut(|m| {
                    m.priorities.get_mut(&self.0).unwrap().0 = priority;
                    m.priority_calls.push((self.0, "mcp", priority));
                });
                Ok(())
            }
            pub fn tcb_set_priority(&self, authority: Self, priority: u64) -> Result<(), ()> {
                assert_eq!(authority.0, 0);
                crate::MODEL.with_borrow_mut(|m| {
                    if m.fail_priority == Some(self.0) { return Err(()); }
                    m.priorities.get_mut(&self.0).unwrap().1 = priority;
                    m.priority_calls.push((self.0, "priority", priority));
                    Ok(())
                })
            }
            pub fn tcb_suspend(&self) { crate::MODEL.with_borrow_mut(|m| m.suspended.push(self.0)); }
        }
        pub struct SchedControl(pub usize);
        impl SchedControl {
            pub fn sched_control_configure_flags(&self, sc: SchedContext, budget: u64, period: u64,
                refills: u64, _: u64, _: u64) -> Result<(), ()> {
                assert!(budget > 0 && budget <= period);
                crate::MODEL.with_borrow_mut(|m| {
                    m.calls.push(sc.0);
                    m.operations.push(('c', sc.0));
                    if m.fail_config == Some(sc.0) { return Err(()); }
                    m.limits.insert(sc.0, (self.0, budget, period, refills));
                    Ok(())
                })
            }
        }
    }
    pub struct Buffer;
    pub struct Consumed { pub error: u64, pub consumed: u64, pub runnable: u64 }
    impl Buffer {
        pub fn inner_mut(&mut self) -> &mut Self { self }
        #[allow(non_snake_case)]
        pub fn seL4_SchedContext_Consumed(&mut self, sc: u64) -> Consumed {
            crate::MODEL.with_borrow_mut(|m| Consumed { error: 0,
                consumed: m.used.remove(&sc).unwrap_or(0), runnable: u64::from(m.ready.get(&sc).copied().unwrap_or(true)) })
        }
    }
    pub fn with_ipc_buffer_mut<T>(f: impl FnOnce(&mut Buffer) -> T) -> T { f(&mut Buffer) }
}
#[path = "../host/l4h-task/src/topology.rs"] mod topology;
#[path = "../host/l4h-vmmgr/src/sched.rs"] mod sched;
const MAX_GUESTS: usize = 64;
struct Model {
    limits: BTreeMap<u64, (usize, u64, u64, u64)>,
    used: BTreeMap<u64, u64>,
    ready: BTreeMap<u64, bool>,
    calls: Vec<u64>,
    priorities: BTreeMap<u64, (u64, u64)>,
    priority_calls: Vec<(u64, &'static str, u64)>,
    fail_priority: Option<u64>,
    fail_config: Option<u64>,
    suspended: Vec<u64>,
    operations: Vec<(char, u64)>,
}
thread_local! { static MODEL: RefCell<Model> = RefCell::new(Model { limits: BTreeMap::new(), used: BTreeMap::new(), ready: BTreeMap::new(), calls: Vec::new(),
    priorities: BTreeMap::new(), priority_calls: Vec::new(), fail_priority: None, fail_config: None, suspended: Vec::new(), operations: Vec::new() }); }
mod slot {
    pub struct Slot;
    pub const TCB: Slot = Slot;
    impl Slot { pub fn cap(&self) -> crate::cap::Tcb { crate::cap::Tcb(0) } }
}
struct HostInfo { timeslice_us: u64, tsc_hz: u64, cores: usize, topology: topology::Topology }
impl HostInfo { fn sched_control(&self, core: usize) -> sel4::cap::SchedControl { sel4::cap::SchedControl(core) } }
mod guest {
    use super::*;
    #[derive(Clone, Copy, PartialEq, Eq, Debug)] pub enum State { Created, Running, Stopped }
    pub struct Vcpu {
        pub sc_k: sel4::cap::SchedContext, pub sc_u: sel4::cap::SchedContext,
        pub core: usize, pub cooldown: u32, pub usage: u32, pub k_share: u32,
        pub wall_ticks: u64, pub run_ticks: u64, pub steal_ns: u64,
    }
    pub struct Component { pub sc: sel4::cap::SchedContext, pub tcb: sel4::cap::Tcb }
    pub struct Event { pub idle_ticks: u64, pub steal_ns: u64 }
    pub struct Guest {
        pub id: usize, pub vmm: Option<Component>, pub state: State, pub cpu_cap_pct: u32,
        pub vcpus: Vec<Vcpu>, pub vmm_limits: Option<(usize, sched::budget::Plan)>,
        pub vmm_share: u32, pub vmm_usage: u32, pub vmm_boosted: bool,
        pub vmm_guard: sched::budget::BoostGuard, pub vmm_limited: bool, pub events: Vec<Box<Event>>,
    }
    impl Guest {
        pub fn event_page(&self, v: usize) -> *mut Event { (&*self.events[v]) as *const Event as *mut Event }
        pub fn flush_tlb_bitmaps(&self) {}
        pub fn start(&mut self) {
            MODEL.with_borrow_mut(|m| m.operations.push(('s', self.id as u64)));
            self.state = State::Running;
        }
        pub fn stop(&mut self) {
            if let Some(vmm) = &self.vmm { vmm.tcb.tcb_suspend(); }
            MODEL.with_borrow_mut(|m| m.operations.push(('x', self.id as u64)));
            self.state = State::Stopped;
        }
    }
}
use guest::{Component, Event, Guest, State, Vcpu};
struct Vmmgr { info: HostInfo, guests: Vec<Option<Guest>> }
impl Vmmgr { fn guest(&self, id: usize) -> Option<&Guest> { self.guests.get(id)?.as_ref() } }
fn manager() -> Vmmgr {
    MODEL.with_borrow_mut(|m| { m.limits.clear(); m.used.clear(); m.ready.clear(); m.calls.clear(); m.priorities.clear();
        m.priority_calls.clear(); m.fail_priority = None; m.fail_config = None; m.suspended.clear(); m.operations.clear(); });
    Vmmgr { info: HostInfo { timeslice_us: 5000, tsc_hz: 1_000_000, cores: 1, topology: topology::Topology::flat(1) },
        guests: (0..MAX_GUESTS).map(|_| None).collect() }
}
fn create(id: usize, core: usize, cap: u32, vcpus: usize) -> Guest {
    Guest { id, vmm: None, state: State::Created, cpu_cap_pct: cap,
        vcpus: (0..vcpus).map(|v| Vcpu { sc_k: sel4::cap::SchedContext((id * 10 + v * 2 + 1) as u64),
            sc_u: sel4::cap::SchedContext((id * 10 + v * 2 + 2) as u64), core, cooldown: 0,
            usage: 0, k_share: 500, wall_ticks: 0, run_ticks: 0, steal_ns: 0 }).collect(),
        vmm_limits: None, vmm_share: sched::budget::VMM_SHARE_INIT, vmm_usage: 0, vmm_boosted: true,
        vmm_guard: Default::default(), vmm_limited: false,
        events: (0..vcpus).map(|_| Box::new(Event { idle_ticks: 0, steal_ns: 0 })).collect() }
}
fn build(h: &mut Vmmgr, id: usize, core: usize, cap: u32, vcpus: usize) {
    let mut g = create(id, core, cap, vcpus);
    let p = sched::prepare_vmm(h, &mut g).unwrap();
    let sc = sel4::cap::SchedContext((id * 10 + 9) as u64);
    // These are exactly the limits passed to component::create, before Resume.
    h.info.sched_control(core).sched_control_configure_flags(sc, p.vmm, p.vmm_period, l4h_host::GUEST_EXTRA_REFILLS, 0, 0).unwrap();
    MODEL.with_borrow_mut(|m| { m.priorities.insert(sc.0, (l4h_host::PRIO_VMM, l4h_host::PRIO_VMM)); });
    g.vmm = Some(Component { sc, tcb: sel4::cap::Tcb(sc.0) });
    h.guests[id] = Some(g);
}
fn spawn(h: &mut Vmmgr, id: usize, core: usize, cap: u32, vcpus: usize) {
    build(h, id, core, cap, vcpus);
    sched::start(h, id).unwrap();
}
fn assert_limits(h: &Vmmgr) {
    for g in h.guests.iter().flatten().filter(|g| g.state != State::Stopped) {
        let (core, p) = g.vmm_limits.unwrap();
        MODEL.with_borrow(|m| {
            assert_eq!(m.limits[&g.vcpus[0].sc_k.0], (g.vcpus[0].core, p.kernel, p.period, 14));
            assert_eq!(m.limits[&g.vcpus[0].sc_u.0], (g.vcpus[0].core, p.user, p.period, 14));
            assert_eq!(m.limits[&g.vmm.as_ref().unwrap().sc.0], (core, p.vmm, p.vmm_period, 14));
        });
        if g.cpu_cap_pct > 0 {
            assert!((p.kernel + p.user) as u128 * p.vmm_period as u128 + p.vmm as u128 * p.period as u128
                <= (p.period * g.cpu_cap_pct as u64 / 100) as u128 * p.vmm_period as u128);
        } else if !g.vmm_limited {
            assert_eq!((p.vmm, p.vmm_period), (5000, 5000));
        }
    }
}

#[test]
fn spawn_stop_and_destroy_do_not_reserve_a_share_from_other_vmms() {
    let mut h = manager();
    h.info.cores = 2;
    h.info.topology = topology::Topology::flat(2);
    spawn(&mut h, 0, 0, 0, 1);
    spawn(&mut h, 1, 1, 0, 1);
    let separate = h.guest(1).unwrap().vmm_limits;
    let original = h.guest(0).unwrap().vmm_limits;
    for id in 2..64 {
        spawn(&mut h, id, 0, 0, 1);
        assert_limits(&h);
        assert_eq!(h.guest(0).unwrap().vmm_limits, original);
    }
    assert_eq!(h.guest(1).unwrap().vmm_limits, separate);
    h.guests[2].as_mut().unwrap().state = State::Stopped;
    assert_limits(&h);
    h.guests[3] = None;
    assert_limits(&h);
    let calls = MODEL.with_borrow(|m| m.calls.len());
    sched::balance(&mut h, 100_000);
    assert_eq!(MODEL.with_borrow(|m| m.calls.len()), calls, "unchanged quotas must not reset refills");
}

#[test]
fn changing_caps_reconfigures_the_vmm_and_both_guest_contexts() {
    let mut h = manager();
    spawn(&mut h, 0, 0, 0, 2);
    for cap in [50, 1, 99, 100, 0] {
        assert_eq!(sched::set_cap(&mut h, 0, cap), Ok(()));
        assert_limits(&h);
        MODEL.with_borrow(|m| {
            let (_, k, period, _) = m.limits[&3];
            let (_, u, _, _) = m.limits[&4];
            if cap > 0 && cap < 100 { assert_eq!(k + u, period * cap as u64 / 100); }
        });
    }
}

#[test]
fn periodic_accounting_includes_vmm_time_and_adapts_its_budget() {
    let mut h = manager();
    spawn(&mut h, 0, 0, 50, 1);
    let old = h.guest(0).unwrap().vmm_limits.unwrap().1;
    MODEL.with_borrow_mut(|m| m.used.extend([(1, 9000), (2, 9000), (9, 12_000)]));
    sched::balance(&mut h, 100_000);
    let g = h.guest(0).unwrap();
    assert_eq!(g.vmm_usage, 120);
    assert_eq!(g.vcpus[0].usage, 180);
    assert!(g.vmm_limits.unwrap().1.vmm > old.vmm);
    assert_limits(&h);
}

#[test]
fn migration_keeps_the_vmm_charged_at_a_100_percent_cap() {
    let mut h = manager();
    h.info.cores = 2;
    h.info.topology = topology::Topology::flat(2);
    spawn(&mut h, 0, 0, 100, 1);
    spawn(&mut h, 1, 0, 0, 1);
    h.guests[1].as_mut().unwrap().vcpus[0].cooldown = 10;
    MODEL.with_borrow_mut(|m| m.used.extend([(1, 10_000), (2, 20_000), (11, 10_000), (12, 20_000)]));
    sched::balance(&mut h, 100_000);
    let g = h.guest(0).unwrap();
    assert_eq!(g.vcpus[0].core, 1);
    assert_eq!(g.vmm_limits.unwrap().0, 0, "the VMM remains on its start core");
    assert_limits(&h);
    // Stopping its peer must not restore a full guest budget in addition
    // to the VMM's old one on a different core.
    h.guests[1].as_mut().unwrap().state = State::Stopped;
    assert_limits(&h);
}

#[test]
fn a_guest_split_change_does_not_refill_an_unchanged_vmm_budget() {
    let mut h = manager();
    spawn(&mut h, 0, 0, 50, 1);
    // Give the idle VMM its minimum, then shift K/U demand while the
    // VMM's share remains there. Its SC must retain its existing refills.
    MODEL.with_borrow_mut(|m| m.used.extend([(1, 18_000), (2, 18_000)]));
    sched::balance(&mut h, 100_000);
    assert_eq!(h.guest(0).unwrap().vmm_limits.unwrap().1.vmm, sched::budget::MIN_US);
    MODEL.with_borrow_mut(|m| { m.calls.clear(); m.used.extend([(1, 40_000), (2, 100)]); });
    sched::balance(&mut h, 100_000);
    MODEL.with_borrow(|m| {
        assert!(m.calls.contains(&1) && m.calls.contains(&2));
        assert!(!m.calls.contains(&9));
    });
    assert_limits(&h);
}

#[test]
fn dominating_vmms_share_a_background_allowance_and_cannot_restore_their_authority() {
    let mut h = manager();
    spawn(&mut h, 0, 0, 0, 1);
    spawn(&mut h, 1, 0, 0, 1);
    let calls = MODEL.with_borrow(|m| m.calls.len());
    MODEL.with_borrow_mut(|m| m.used.extend([(9, 45_000), (19, 45_000), (1, 10_000)]));
    sched::balance(&mut h, 100_000);
    assert!(!h.guest(0).unwrap().vmm_boosted && !h.guest(1).unwrap().vmm_boosted);
    MODEL.with_borrow(|m| {
        assert_eq!(m.priority_calls, vec![(9, "mcp", 101), (9, "priority", 101), (19, "mcp", 101), (19, "priority", 101)]);
        assert_eq!(&m.calls[calls..], &[9, 19], "only VMM limits change on demotion");
        assert_eq!(m.limits[&9].1 * 4, m.limits[&9].2);
    });
    // A continuously busy VMM must not oscillate back to high priority.
    MODEL.with_borrow_mut(|m| m.used.extend([(9, 25_000), (19, 25_000), (1, 50_000)]));
    sched::balance(&mut h, 100_000);
    assert!(!h.guest(0).unwrap().vmm_boosted);
    // After quiescence only the parent restores priority, keeping MCP low.
    for _ in 0..10 {
        MODEL.with_borrow_mut(|m| m.used.extend([(9, 1000), (1, 50_000)]));
        sched::balance(&mut h, 100_000);
    }
    assert!(h.guest(0).unwrap().vmm_boosted);
    MODEL.with_borrow(|m| assert_eq!(m.priorities[&9], (101, l4h_host::PRIO_VMM)));
    assert_limits(&h);
}

#[test]
fn a_vmm_spinning_before_guest_start_is_also_demoted() {
    let mut h = manager();
    spawn(&mut h, 0, 0, 0, 1);
    h.guests[0].as_mut().unwrap().state = State::Created;
    MODEL.with_borrow_mut(|m| { m.used.insert(9, 100_000); });
    sched::balance(&mut h, 100_000);
    assert!(!h.guest(0).unwrap().vmm_boosted);
    assert_eq!(h.guest(0).unwrap().vmm_usage, 1000, "pre-READY CPU must be visible to management");
}

#[test]
fn a_failed_priority_reduction_stops_the_guest() {
    let mut h = manager();
    spawn(&mut h, 0, 0, 0, 1);
    spawn(&mut h, 1, 0, 0, 1);
    MODEL.with_borrow_mut(|m| { m.used.extend([(9, 50_000), (19, 50_000)]); m.fail_priority = Some(9); });
    sched::balance(&mut h, 100_000);
    assert_eq!(h.guest(0).unwrap().state, State::Stopped);
    MODEL.with_borrow(|m| assert_eq!(m.suspended, vec![9]));
    assert!(!h.guest(1).unwrap().vmm_boosted, "later guests must still be protected this pass");
}

#[test]
fn a_failed_priority_update_does_not_skip_a_chosen_migration() {
    let mut h = manager();
    h.info.cores = 2;
    h.info.topology = topology::Topology::flat(2);
    for id in 0..4 { spawn(&mut h, id, 0, 0, 1); }
    for id in [0, 1, 3] { h.guests[id].as_mut().unwrap().vcpus[0].cooldown = 10; }
    MODEL.with_borrow_mut(|m| {
        m.used.extend([(9, 40_000), (19, 40_000), (21, 25_000), (31, 25_000)]);
        m.fail_priority = Some(9);
    });
    sched::balance(&mut h, 100_000);
    assert_eq!(h.guest(0).unwrap().state, State::Stopped);
    assert_eq!(h.guest(2).unwrap().vcpus[0].core, 1);
}

#[test]
fn one_spinner_does_not_remove_its_quiet_neighbours_boost() {
    let mut h = manager();
    spawn(&mut h, 0, 0, 0, 1);
    spawn(&mut h, 1, 0, 0, 1);
    MODEL.with_borrow_mut(|m| m.used.extend([(9, 99_000), (19, 1000)]));
    sched::balance(&mut h, 100_000);
    assert!(!h.guest(0).unwrap().vmm_boosted);
    assert!(h.guest(1).unwrap().vmm_boosted);
    // Even a previously demoted neighbour recovers under pressure.
    h.guests[1].as_mut().unwrap().vmm_boosted = false;
    for _ in 0..10 {
        MODEL.with_borrow_mut(|m| m.used.extend([(9, 99_000), (19, 0)]));
        sched::balance(&mut h, 100_000);
    }
    assert!(h.guest(1).unwrap().vmm_boosted);
}

#[test]
fn steady_io_after_vcpu_migration_keeps_its_boost() {
    let mut h = manager();
    h.info.cores = 2;
    h.info.topology = topology::Topology::flat(2);
    spawn(&mut h, 0, 0, 0, 1);
    h.guests[0].as_mut().unwrap().vcpus[0].core = 1;
    MODEL.with_borrow_mut(|m| m.used.extend([(9, 10_000), (1, 80_000)]));
    sched::balance(&mut h, 100_000);
    assert!(h.guest(0).unwrap().vmm_boosted);
    assert!(MODEL.with_borrow(|m| m.priority_calls.is_empty()));
}

#[test]
fn a_lone_heavy_io_vmm_on_an_idle_core_keeps_its_full_budget() {
    let mut h = manager();
    h.info.cores = 2;
    h.info.topology = topology::Topology::flat(2);
    spawn(&mut h, 0, 1, 0, 1);
    let before = MODEL.with_borrow(|m| m.calls.len());
    MODEL.with_borrow_mut(|m| {
        m.ready.extend([(1, false), (2, false)]);
        m.used.insert(9, 90_000);
    });
    sched::balance(&mut h, 100_000);
    let g = h.guest(0).unwrap();
    assert!(g.vmm_boosted && !g.vmm_limited);
    assert_eq!(MODEL.with_borrow(|m| m.calls.len()), before);
    assert_limits(&h);
}

#[test]
fn its_own_runnable_vcpus_do_not_demote_a_heavy_io_vmm() {
    for (id, idle_peer) in [(0, false), (0, true), (MAX_GUESTS - 1, false), (MAX_GUESTS - 1, true)] {
        let mut h = manager();
        h.info.cores = 2;
        h.info.topology = topology::Topology::flat(2);
        spawn(&mut h, id, 1, 0, 2);
        if idle_peer {
            spawn(&mut h, 32, 1, 0, 1);
            MODEL.with_borrow_mut(|m| m.ready.extend([(321, false), (322, false), (329, false)]));
        }
        let before = MODEL.with_borrow(|m| m.calls.len());
        for _ in 0..100 {
            // Both scheduling bands of both vCPUs are runnable. They
            // belong to this VMM, not a guest needing isolation from it.
            MODEL.with_borrow_mut(|m| {
                m.used.insert((id * 10 + 9) as u64, 90_000);
                if idle_peer { m.used.insert(329, 50); }
            });
            sched::balance(&mut h, 100_000);
            let g = h.guest(id).unwrap();
            assert!(g.vmm_boosted && !g.vmm_limited);
        }
        assert_eq!(MODEL.with_borrow(|m| m.calls.len()), before);
        assert_limits(&h);
    }
}

#[test]
fn blocking_and_refill_snapshots_cannot_remove_an_existing_limit() {
    let mut h = manager();
    h.info.cores = 2;
    h.info.topology = topology::Topology::flat(2);
    spawn(&mut h, 0, 1, 0, 1);
    spawn(&mut h, MAX_GUESTS - 1, 1, 0, 1);
    MODEL.with_borrow_mut(|m| m.ready.insert(639, false));
    // A guest cannot hide runnable demand by forging its idle counter.
    h.guests[0].as_mut().unwrap().events[0].idle_ticks = u64::MAX;
    MODEL.with_borrow_mut(|m| m.used.insert(9, 90_000));
    sched::balance(&mut h, 100_000);
    assert!(h.guest(0).unwrap().vmm_limited);
    let before = MODEL.with_borrow(|m| m.calls.len());
    for tick in 0..1000 {
        // Both blocked (including a capped SC waiting for refill), either
        // scheduling band ready, and both ready must all retain protection.
        MODEL.with_borrow_mut(|m| {
            m.ready.extend([(1, tick % 4 >= 2), (2, tick % 2 != 0)]);
            m.ready.extend([(631, tick % 4 >= 2), (632, tick % 2 != 0)]);
            m.used.insert(9, 50_000);
        });
        sched::balance(&mut h, 100_000);
        let g = h.guest(0).unwrap();
        assert!(g.vmm_limited && !g.vmm_boosted);
    }
    assert_eq!(MODEL.with_borrow(|m| m.calls.len()), before, "blocking must not reconfigure/refill SCs");
    assert_limits(&h);
}

#[test]
fn stopping_the_other_guest_releases_the_limit_with_own_vcpus_still_present() {
    let mut h = manager();
    h.info.cores = 2;
    h.info.topology = topology::Topology::flat(2);
    spawn(&mut h, 0, 1, 0, 1);
    spawn(&mut h, 1, 1, 0, 1);
    MODEL.with_borrow_mut(|m| m.used.insert(9, 90_000));
    sched::balance(&mut h, 100_000);
    assert!(h.guest(0).unwrap().vmm_limited);
    h.guests[1].as_mut().unwrap().stop();
    MODEL.with_borrow_mut(|m| { m.calls.clear(); m.used.insert(9, 50_000); });
    sched::balance(&mut h, 100_000);
    let g = h.guest(0).unwrap();
    assert!(!g.vmm_boosted && !g.vmm_limited);
    assert_eq!(g.vcpus[0].core, g.vmm_limits.unwrap().0);
    MODEL.with_borrow(|m| assert_eq!(m.calls, vec![9]));
    assert_limits(&h);
}

fn guard_on_empty_core(h: &mut Vmmgr) {
    h.info.cores = 2;
    h.info.topology = topology::Topology::flat(2);
    spawn(h, 0, 1, 0, 1);
    spawn(h, 1, 1, 0, 1);
    MODEL.with_borrow_mut(|m| m.used.insert(9, 90_000));
    sched::balance(h, 100_000);
    assert!(h.guest(0).unwrap().vmm_limited);
    // A real balancing step moves vCPU 0 away; stop and destroy its peer
    // afterwards so no guest threads remain assigned to the VMM's core.
    h.guests[1].as_mut().unwrap().vcpus[0].cooldown = 10;
    MODEL.with_borrow_mut(|m| m.used.extend([(9, 50_000), (1, 25_000), (11, 25_000)]));
    sched::balance(h, 100_000);
    h.guests[1].as_mut().unwrap().stop();
    h.guests[1] = None;
    MODEL.with_borrow_mut(|m| m.used.insert(9, 50_000));
    sched::balance(h, 100_000);
    let g = h.guest(0).unwrap();
    assert_eq!(g.vcpus[0].core, 0);
    assert!(!g.vmm_boosted && !g.vmm_limited);
    assert_eq!((g.vmm_limits.unwrap().1.vmm, g.vmm_limits.unwrap().1.vmm_period), (5000, 5000));
    assert_limits(h);
}

#[test]
fn an_empty_core_reclaims_capacity_but_new_guests_are_protected_before_start() {
    let mut h = manager();
    guard_on_empty_core(&mut h);
    build(&mut h, 1, 1, 0, 1);
    MODEL.with_borrow_mut(|m| m.operations.clear());
    sched::start(&mut h, 1).unwrap();
    assert!(h.guest(0).unwrap().vmm_limited);
    assert!(!h.guest(0).unwrap().vmm_boosted, "placement must not clear backoff");
    MODEL.with_borrow(|m| assert_eq!(m.operations, vec![('c', 9), ('s', 1)]));
    assert_limits(&h);
}

#[test]
fn migrating_onto_a_guarded_core_installs_its_limit_before_the_move() {
    let mut h = manager();
    guard_on_empty_core(&mut h);
    spawn(&mut h, 1, 0, 0, 1);
    h.guests[0].as_mut().unwrap().vcpus[0].cooldown = 10;
    MODEL.with_borrow_mut(|m| {
        m.operations.clear();
        m.used.extend([(9, 90_000), (1, 50_000), (11, 50_000)]);
    });
    sched::balance(&mut h, 100_000);
    assert_eq!(h.guest(1).unwrap().vcpus[0].core, 1);
    assert!(h.guest(0).unwrap().vmm_limited);
    MODEL.with_borrow(|m| assert_eq!(m.operations, vec![('c', 9), ('c', 11), ('c', 12)]));
    assert_limits(&h);
}

#[test]
fn migrating_its_own_vcpu_back_does_not_limit_a_guarded_vmm() {
    let mut h = manager();
    guard_on_empty_core(&mut h);
    spawn(&mut h, 1, 0, 0, 1);
    h.guests[0].as_mut().unwrap().vcpus[0].cooldown = 0;
    h.guests[1].as_mut().unwrap().vcpus[0].cooldown = 10;
    MODEL.with_borrow_mut(|m| {
        m.calls.clear();
        m.used.extend([(9, 90_000), (1, 50_000), (11, 50_000)]);
    });
    sched::balance(&mut h, 100_000);
    let g = h.guest(0).unwrap();
    assert_eq!(g.vcpus[0].core, g.vmm_limits.unwrap().0);
    assert!(!g.vmm_boosted && !g.vmm_limited);
    MODEL.with_borrow(|m| assert_eq!(m.calls, vec![1, 2]));
    assert_limits(&h);
}

#[test]
fn the_last_guest_stopping_releases_capacity_after_it_is_stopped() {
    let mut h = manager();
    guard_on_empty_core(&mut h);
    spawn(&mut h, 1, 1, 0, 1);
    MODEL.with_borrow_mut(|m| {
        m.operations.clear();
        m.used.insert(9, 50_000);
    });
    h.guests[1].as_mut().unwrap().stop();
    sched::balance(&mut h, 100_000);
    assert!(!h.guest(0).unwrap().vmm_limited && !h.guest(0).unwrap().vmm_boosted);
    MODEL.with_borrow(|m| assert_eq!(m.operations, vec![('x', 1), ('c', 9)]));
    assert_limits(&h);
}

#[test]
fn failed_protection_stops_the_affected_vmm_before_a_new_guest_runs() {
    let mut h = manager();
    guard_on_empty_core(&mut h);
    build(&mut h, 1, 1, 0, 1);
    MODEL.with_borrow_mut(|m| m.fail_config = Some(9));
    assert_eq!(sched::start(&mut h, 1), Ok(()));
    assert_eq!(h.guest(0).unwrap().state, State::Stopped);
    assert_eq!(h.guest(1).unwrap().state, State::Running);
}

#[test]
fn starting_its_own_guest_only_limits_guarded_neighbours() {
    let mut h = manager();
    build(&mut h, 0, 0, 0, 1);
    build(&mut h, 1, 0, 0, 1);
    MODEL.with_borrow_mut(|m| m.used.extend([(9, 45_000), (19, 45_000)]));
    sched::balance(&mut h, 100_000);
    assert!(!h.guest(0).unwrap().vmm_boosted && !h.guest(0).unwrap().vmm_limited);
    MODEL.with_borrow_mut(|m| { m.operations.clear(); m.fail_config = Some(19); });
    assert_eq!(sched::start(&mut h, 0), Ok(()));
    assert_eq!(h.guest(0).unwrap().state, State::Running);
    assert!(!h.guest(0).unwrap().vmm_limited);
    assert_eq!(h.guest(1).unwrap().state, State::Stopped);
    assert_eq!(h.guest(0).unwrap().vmm_limits.unwrap().1.vmm, 5000,
        "a failed neighbour must not reserve CPU from the starting guest");
    MODEL.with_borrow(|m| assert_eq!(m.operations, vec![('c', 19), ('x', 1), ('s', 0)]));
    assert_limits(&h);
}

#[test]
fn a_failed_budget_release_during_ready_never_replies_to_a_stopped_caller() {
    let mut h = manager();
    h.info.cores = 2;
    h.info.topology = topology::Topology::flat(2);
    build(&mut h, 0, 1, 0, 1);
    spawn(&mut h, 1, 1, 0, 1);
    MODEL.with_borrow_mut(|m| m.used.insert(9, 90_000));
    sched::balance(&mut h, 100_000);
    assert!(h.guest(0).unwrap().vmm_limited);
    h.guests[1].as_mut().unwrap().stop();
    MODEL.with_borrow_mut(|m| { m.operations.clear(); m.fail_config = Some(9); });
    assert_eq!(sched::start(&mut h, 0), Err(l4h_host::wire::NO_REPLY));
    assert_eq!(h.guest(0).unwrap().state, State::Stopped);
    MODEL.with_borrow(|m| assert_eq!(m.operations, vec![('c', 9), ('x', 0)]));
}

#[test]
fn a_failed_migration_removes_its_destination_reservation() {
    let mut h = manager();
    guard_on_empty_core(&mut h);
    spawn(&mut h, 1, 0, 0, 1);
    h.guests[0].as_mut().unwrap().vcpus[0].cooldown = 10;
    MODEL.with_borrow_mut(|m| {
        m.operations.clear();
        m.fail_config = Some(11);
        m.used.extend([(9, 90_000), (1, 50_000), (11, 50_000)]);
    });
    sched::balance(&mut h, 100_000);
    assert_eq!(h.guest(1).unwrap().state, State::Stopped);
    assert!(!h.guest(0).unwrap().vmm_limited && !h.guest(0).unwrap().vmm_boosted);
    MODEL.with_borrow(|m| assert_eq!(m.operations, vec![('c', 9), ('c', 11), ('x', 1), ('c', 9)]));
    assert_limits(&h);
}

#[test]
fn timer_bookkeeping_is_not_pressure_but_a_quantum_or_waiting_vmm_is() {
    for (other_used, other_ready, guarded) in [(50, false, false), (4999, false, false), (5000, false, true), (0, true, true)] {
        let mut h = manager();
        h.info.cores = 2;
        h.info.topology = topology::Topology::flat(2);
        for id in 0..4 { spawn(&mut h, id, 1, 0, 1); }
        MODEL.with_borrow_mut(|m| {
            for id in 0..4 { m.ready.extend([(id*10+1, false), (id*10+2, false), (id*10+9, false)]); }
            m.ready.insert(19, other_ready);
        });
        for _ in 0..20 {
            let own_used = if h.guest(0).unwrap().vmm_limited { 50_000 } else { 90_000 };
            MODEL.with_borrow_mut(|m| m.used.extend([(9, own_used), (19, other_used)]));
            sched::balance(&mut h, 100_000);
            assert_eq!(!h.guest(0).unwrap().vmm_boosted, guarded);
            assert!(h.guests[1..4].iter().flatten().all(|g| g.vmm_boosted));
        }
        assert_limits(&h);
    }
}

#[test]
fn many_idle_timers_still_do_not_remove_a_heavy_io_vmms_boost() {
    let mut h = manager();
    h.info.cores = 2;
    h.info.topology = topology::Topology::flat(2);
    for id in 0..64 { spawn(&mut h, id, 1, 0, 1); }
    let before = MODEL.with_borrow(|m| m.calls.len());
    MODEL.with_borrow_mut(|m| {
        for id in 0..64 {
            m.ready.extend([(id*10+1, false), (id*10+2, false), (id*10+9, false)]);
            m.used.insert(id*10+9, if id == 0 { 90_000 } else { 50 });
        }
    });
    sched::balance(&mut h, 100_000);
    assert!(h.guests.iter().flatten().all(|g| g.vmm_boosted && !g.vmm_limited));
    assert_eq!(MODEL.with_borrow(|m| m.calls.len()), before);
    assert_limits(&h);
}

#[test]
fn duplicate_or_stale_ready_never_restarts_a_guest_or_refills_contexts() {
    let mut h = manager();
    spawn(&mut h, 0, 0, 0, 1);
    MODEL.with_borrow_mut(|m| m.operations.clear());
    assert_eq!(sched::start(&mut h, 0), Err(l4h_host::errno::EINVAL));
    assert_eq!(sched::start(&mut h, 63), Err(l4h_host::wire::NO_REPLY));
    assert!(MODEL.with_borrow(|m| m.operations.is_empty()));
    h.guests[0].as_mut().unwrap().stop();
    MODEL.with_borrow_mut(|m| m.operations.clear());
    assert_eq!(sched::start(&mut h, 0), Err(l4h_host::errno::EINVAL));
    assert!(MODEL.with_borrow(|m| m.operations.is_empty()));
}

#[test]
fn idle_peers_do_not_turn_a_40_percent_io_neighbour_into_an_offender() {
    let mut h = manager();
    h.info.cores = 2;
    h.info.topology = topology::Topology::flat(2);
    for id in 0..8 { spawn(&mut h, id, 1, 0, 1); }
    for (a, b) in [(60_000, 40_000), (50_000, 40_000)] {
        MODEL.with_borrow_mut(|m| m.used.extend([(9, a), (19, b)]));
        sched::balance(&mut h, 100_000);
        assert!(!h.guest(0).unwrap().vmm_boosted);
        assert!(h.guest(1).unwrap().vmm_boosted);
        assert!(!h.guest(1).unwrap().vmm_limited);
        assert!(h.guests[2..8].iter().flatten().all(|g| g.vmm_boosted));
    }
    assert_limits(&h);
}

#[test]
fn logd_remains_above_throttled_vmms_and_below_short_io_turns() {
    assert!(l4h_abi::PRIO_KERNEL < l4h_host::PRIO_VMM_FAIR);
    assert!(l4h_host::PRIO_VMM_FAIR < l4h_host::PRIO_LOGD);
    assert!(l4h_host::PRIO_LOGD < l4h_host::PRIO_VMM);
    assert!(l4h_host::PRIO_VMM < l4h_host::PRIO_SERVICE);
}

#[test]
fn partial_scheduling_failures_stop_only_the_affected_guest_without_committing_shares() {
    for failed in [1, 2, 9] {
        let mut h = manager();
        spawn(&mut h, 0, 0, 50, 1);
        spawn(&mut h, 1, 0, 0, 1);
        let g = h.guest(0).unwrap();
        let before = (g.vcpus[0].k_share, g.vmm_share, g.vmm_limits);
        MODEL.with_borrow_mut(|m| { m.fail_config = Some(failed); m.used.extend([(1, 100), (2, 100), (9, 12_500)]); });
        sched::balance(&mut h, 100_000);
        let g = h.guest(0).unwrap();
        assert_eq!(g.state, State::Stopped);
        assert_eq!((g.vcpus[0].k_share, g.vmm_share, g.vmm_limits), before);
        assert_eq!(h.guest(1).unwrap().state, State::Running);
    }
}

#[test]
fn a_failed_cap_change_reports_io_error_and_stops_the_guest() {
    let mut h = manager();
    spawn(&mut h, 0, 0, 50, 1);
    MODEL.with_borrow_mut(|m| m.fail_config = Some(9));
    assert_eq!(sched::set_cap(&mut h, 0, 25), Err(l4h_host::errno::EIO));
    assert_eq!(h.guest(0).unwrap().state, State::Stopped);
    assert_eq!(sched::set_cap(&mut h, 63, 25), Err(l4h_host::errno::ENOENT));
}

#[test]
fn a_failed_start_budget_stops_the_new_guest_instead_of_panicking() {
    for failed in [11, 12] {
        let mut h = manager();
        spawn(&mut h, 0, 0, 0, 1);
        let mut g = create(1, 0, 50, 1);
        MODEL.with_borrow_mut(|m| m.fail_config = Some(failed));
        assert!(sched::prepare_vmm(&mut h, &mut g).is_none());
        assert_eq!(g.state, State::Stopped);
        assert!(g.vmm_limits.is_none());
        assert_eq!(h.guest(0).unwrap().state, State::Running);
    }
}

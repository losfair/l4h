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
                    if m.fail_priority { return Err(()); }
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
                    m.limits.insert(sc.0, (self.0, budget, period, refills));
                });
                Ok(())
            }
        }
    }
    pub struct Buffer;
    pub struct Consumed { pub error: u64, pub consumed: u64 }
    impl Buffer {
        pub fn inner_mut(&mut self) -> &mut Self { self }
        #[allow(non_snake_case)]
        pub fn seL4_SchedContext_Consumed(&mut self, sc: u64) -> Consumed {
            Consumed { error: 0, consumed: crate::MODEL.with_borrow_mut(|m| m.used.remove(&sc).unwrap_or(0)) }
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
    calls: Vec<u64>,
    priorities: BTreeMap<u64, (u64, u64)>,
    priority_calls: Vec<(u64, &'static str, u64)>,
    fail_priority: bool,
    suspended: Vec<u64>,
}
thread_local! { static MODEL: RefCell<Model> = RefCell::new(Model { limits: BTreeMap::new(), used: BTreeMap::new(), calls: Vec::new(),
    priorities: BTreeMap::new(), priority_calls: Vec::new(), fail_priority: false, suspended: Vec::new() }); }
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
        pub vmm_share: u32, pub vmm_usage: u32, pub vmm_boosted: bool, pub events: Vec<Box<Event>>,
    }
    impl Guest {
        pub fn event_page(&self, v: usize) -> *mut Event { (&*self.events[v]) as *const Event as *mut Event }
        pub fn flush_tlb_bitmaps(&self) {}
        pub fn stop(&mut self) {
            if let Some(vmm) = &self.vmm { vmm.tcb.tcb_suspend(); }
            self.state = State::Stopped;
        }
    }
}
use guest::{Component, Event, Guest, State, Vcpu};
struct Vmmgr { info: HostInfo, guests: Vec<Option<Guest>> }
impl Vmmgr { fn guest(&self, id: usize) -> Option<&Guest> { self.guests.get(id)?.as_ref() } }
fn manager() -> Vmmgr {
    MODEL.with_borrow_mut(|m| { m.limits.clear(); m.used.clear(); m.calls.clear(); m.priorities.clear();
        m.priority_calls.clear(); m.fail_priority = false; m.suspended.clear(); });
    Vmmgr { info: HostInfo { timeslice_us: 5000, tsc_hz: 1_000_000, cores: 1, topology: topology::Topology::flat(1) },
        guests: (0..MAX_GUESTS).map(|_| None).collect() }
}
fn create(id: usize, core: usize, cap: u32, vcpus: usize) -> Guest {
    Guest { id, vmm: None, state: State::Created, cpu_cap_pct: cap,
        vcpus: (0..vcpus).map(|v| Vcpu { sc_k: sel4::cap::SchedContext((id * 10 + v * 2 + 1) as u64),
            sc_u: sel4::cap::SchedContext((id * 10 + v * 2 + 2) as u64), core, cooldown: 0,
            usage: 0, k_share: 500, wall_ticks: 0, run_ticks: 0, steal_ns: 0 }).collect(),
        vmm_limits: None, vmm_share: sched::budget::VMM_SHARE_INIT, vmm_usage: 0, vmm_boosted: true,
        events: (0..vcpus).map(|_| Box::new(Event { idle_ticks: 0, steal_ns: 0 })).collect() }
}
fn spawn(h: &mut Vmmgr, id: usize, core: usize, cap: u32, vcpus: usize) {
    let mut g = create(id, core, cap, vcpus);
    let p = sched::prepare_vmm(h, &mut g);
    let sc = sel4::cap::SchedContext((id * 10 + 9) as u64);
    // These are exactly the limits passed to component::create, before Resume.
    h.info.sched_control(core).sched_control_configure_flags(sc, p.vmm, p.vmm_period, l4h_host::VMM_EXTRA_REFILLS, 0, 0).unwrap();
    MODEL.with_borrow_mut(|m| { m.priorities.insert(sc.0, (l4h_host::PRIO_VMM, l4h_host::PRIO_VMM)); });
    g.vmm = Some(Component { sc, tcb: sel4::cap::Tcb(sc.0) });
    g.state = State::Running;
    h.guests[id] = Some(g);
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
            assert_eq!(p.kernel + p.user + p.vmm, p.period * g.cpu_cap_pct as u64 / 100);
        } else {
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
        assert!(sched::set_cap(&mut h, 0, cap));
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
fn dominating_vmms_lose_authority_before_their_priority_and_keep_their_budgets() {
    let mut h = manager();
    spawn(&mut h, 0, 0, 0, 1);
    spawn(&mut h, 1, 0, 0, 1);
    let calls = MODEL.with_borrow(|m| m.calls.len());
    MODEL.with_borrow_mut(|m| m.used.extend([(9, 45_000), (19, 45_000), (1, 10_000)]));
    sched::balance(&mut h, 100_000);
    assert!(!h.guest(0).unwrap().vmm_boosted && !h.guest(1).unwrap().vmm_boosted);
    MODEL.with_borrow(|m| {
        assert_eq!(m.priority_calls, vec![(9, "mcp", 99), (9, "priority", 99), (19, "mcp", 99), (19, "priority", 99)]);
        assert_eq!(m.calls.len(), calls, "demotion must not refill an SC");
    });
    // A continuously busy VMM must not oscillate back to high priority.
    MODEL.with_borrow_mut(|m| m.used.extend([(9, 50_000), (1, 50_000)]));
    sched::balance(&mut h, 100_000);
    assert!(!h.guest(0).unwrap().vmm_boosted);
    // After quiescence only the parent restores priority, keeping MCP low.
    MODEL.with_borrow_mut(|m| m.used.extend([(9, 1000), (1, 50_000)]));
    sched::balance(&mut h, 100_000);
    assert!(h.guest(0).unwrap().vmm_boosted);
    MODEL.with_borrow(|m| assert_eq!(m.priorities[&9], (99, l4h_host::PRIO_VMM)));
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
}

#[test]
fn a_failed_priority_reduction_stops_the_guest() {
    let mut h = manager();
    spawn(&mut h, 0, 0, 0, 1);
    MODEL.with_borrow_mut(|m| { m.used.insert(9, 100_000); m.fail_priority = true; });
    sched::balance(&mut h, 100_000);
    assert_eq!(h.guest(0).unwrap().state, State::Stopped);
    MODEL.with_borrow(|m| assert_eq!(m.suspended, vec![9]));
}

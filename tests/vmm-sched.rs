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
    pub struct Consumed { pub error: u64, pub consumed: u64 }
    impl Buffer {
        pub fn inner_mut(&mut self) -> &mut Self { self }
        #[allow(non_snake_case)]
        pub fn seL4_SchedContext_Consumed(&mut self, sc: u64) -> Consumed {
            crate::MODEL.with_borrow_mut(|m| Consumed { error: 0,
                consumed: m.used.remove(&sc).unwrap_or(0) })
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
    fail_priority: Option<u64>,
    fail_config: Option<u64>,
    suspended: Vec<u64>,
    operations: Vec<(char, u64)>,
}
thread_local! { static MODEL: RefCell<Model> = RefCell::new(Model { limits: BTreeMap::new(), used: BTreeMap::new(), calls: Vec::new(),
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
        pub sc_k: sel4::cap::SchedContext, pub sc_u: Option<sel4::cap::SchedContext>,
        pub core: usize, pub vcore: usize, pub host_cap: u32, pub cooldown: u32, pub usage: u32, pub k_share: u32,
        pub kernel_divisor: u16, pub wall_ticks: u64, pub run_ticks: u64, pub steal_ns: u64,
    }
    pub struct Component { pub sc: sel4::cap::SchedContext, pub tcb: sel4::cap::Tcb }
    pub struct Event { pub idle_ticks: u64, pub steal_ns: u64, pub host_cap: u64, pub idle_since: u64, pub io_flags: u64, pub idle_seq: u64 }
    pub type EventPage = Event;
    pub struct Guest {
        pub id: usize, pub vmm: Option<Component>, pub state: State, pub cpu_cap_pct: u32,
        pub vcpus: Vec<Vcpu>, pub vmm_limits: Option<(usize, sched::budget::Plan)>,
        pub vmm_share: u32, pub vmm_usage: u32, pub vmm_boosted: bool,
        pub vmm_guard: sched::budget::BoostGuard, pub vmm_limited: bool, pub events: Vec<Box<Event>>,
        /// An HVM guest (its monitor's MCP is l4h_host::hvm::MCP).
        pub hvm: Option<()>,
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
    MODEL.with_borrow_mut(|m| { m.limits.clear(); m.used.clear(); m.calls.clear(); m.priorities.clear();
        m.priority_calls.clear(); m.fail_priority = None; m.fail_config = None; m.suspended.clear(); m.operations.clear(); });
    Vmmgr { info: HostInfo { timeslice_us: 5000, tsc_hz: 1_000_000, cores: 1, topology: topology::Topology::flat(1) },
        guests: (0..MAX_GUESTS).map(|_| None).collect() }
}
fn create(id: usize, core: usize, cap: u32, vcpus: usize) -> Guest {
    Guest { id, vmm: None, state: State::Created, cpu_cap_pct: cap,
        vcpus: (0..vcpus).map(|v| Vcpu { sc_k: sel4::cap::SchedContext((id * 10 + v * 2 + 1) as u64),
            sc_u: Some(sel4::cap::SchedContext((id * 10 + v * 2 + 2) as u64)), core, vcore: v, host_cap: 1024, cooldown: 0,
            usage: 0, k_share: 500, kernel_divisor: 0, wall_ticks: 0, run_ticks: 0, steal_ns: 0 }).collect(),
        vmm_limits: None, vmm_share: sched::budget::VMM_SHARE_INIT, vmm_usage: 0, vmm_boosted: true,
        vmm_guard: Default::default(), vmm_limited: false,
        events: (0..vcpus).map(|_| Box::new(Event { idle_ticks: 0, steal_ns: 0, host_cap: 1024, idle_since: 0, io_flags: 0, idle_seq: 0 })).collect(), hvm: None }
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
// Set up a completed vCPU move while its VMM stays on its original core.
fn place_vcpu(h: &mut Vmmgr, id: usize, core: usize) {
    let v = &mut h.guests[id].as_mut().unwrap().vcpus[0];
    v.core = core;
    MODEL.with_borrow_mut(|m| {
        m.limits.get_mut(&v.sc_k.0).unwrap().0 = core;
        m.limits.get_mut(&v.sc_u.unwrap().0).unwrap().0 = core;
    });
}
fn assert_limits(h: &Vmmgr) {
    for g in h.guests.iter().flatten().filter(|g| g.state != State::Stopped) {
        let (core, p) = g.vmm_limits.unwrap();
        MODEL.with_borrow(|m| {
            match g.vcpus[0].sc_u {
                Some(sc_u) => {
                    assert_eq!(m.limits[&g.vcpus[0].sc_k.0], (g.vcpus[0].core, p.kernel, p.period, 14));
                    assert_eq!(m.limits[&sc_u.0], (g.vcpus[0].core, p.user, p.period, 14));
                }
                // An HVM guest's vCPU: one context with the guest's whole part.
                None => assert_eq!(m.limits[&g.vcpus[0].sc_k.0],
                    (g.vcpus[0].core, (p.kernel + p.user).min(p.period), p.period, 14)),
            }
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
    sched::balance(&mut h, 100_000, 0);
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
fn an_hvm_guests_vcpus_run_on_one_context_with_the_guests_whole_budget() {
    let mut h = manager();
    let mut g = create(0, 0, 0, 2);
    for v in &mut g.vcpus {
        v.sc_u = None;
    }
    let p = sched::prepare_vmm(&mut h, &mut g).unwrap();
    let sc = sel4::cap::SchedContext(9);
    h.info.sched_control(0).sched_control_configure_flags(sc, p.vmm, p.vmm_period, l4h_host::GUEST_EXTRA_REFILLS, 0, 0).unwrap();
    MODEL.with_borrow_mut(|m| { m.priorities.insert(sc.0, (l4h_host::PRIO_VMM, l4h_host::PRIO_VMM)); });
    g.vmm = Some(Component { sc, tcb: sel4::cap::Tcb(sc.0) });
    h.guests[0] = Some(g);
    sched::start(&mut h, 0).unwrap();
    assert_limits(&h);
    MODEL.with_borrow(|m| assert!(!m.limits.contains_key(&2), "no user context configured"));
    for cap in [50, 1, 100, 0] {
        assert_eq!(sched::set_cap(&mut h, 0, cap), Ok(()));
        assert_limits(&h);
        MODEL.with_borrow(|m| {
            let (_, k, period, _) = m.limits[&1];
            if cap > 0 && cap < 100 { assert!(k <= period * cap as u64 / 100); }
        });
    }
    sched::balance(&mut h, 100_000, 0);
    assert_limits(&h);
}

#[test]
fn periodic_accounting_includes_vmm_time_and_adapts_its_budget() {
    let mut h = manager();
    spawn(&mut h, 0, 0, 50, 1);
    let old = h.guest(0).unwrap().vmm_limits.unwrap().1;
    MODEL.with_borrow_mut(|m| m.used.extend([(1, 9000), (2, 9000), (9, 12_000)]));
    sched::balance(&mut h, 100_000, 0);
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
    sched::balance(&mut h, 100_000, 0);
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
    sched::balance(&mut h, 100_000, 0);
    assert_eq!(h.guest(0).unwrap().vmm_limits.unwrap().1.vmm, sched::budget::MIN_US);
    MODEL.with_borrow_mut(|m| { m.calls.clear(); m.used.extend([(1, 40_000), (2, 100)]); });
    sched::balance(&mut h, 100_000, 0);
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
    sched::balance(&mut h, 100_000, 0);
    assert!(!h.guest(0).unwrap().vmm_boosted && !h.guest(1).unwrap().vmm_boosted);
    MODEL.with_borrow(|m| {
        assert_eq!(m.priority_calls, vec![(9, "mcp", 101), (9, "priority", 101), (19, "mcp", 101), (19, "priority", 101)]);
        assert_eq!(&m.calls[calls..], &[9, 19], "only VMM limits change on demotion");
        assert_eq!(m.limits[&9].1 * 4, m.limits[&9].2);
    });
    // A continuously busy VMM must not oscillate back to high priority.
    MODEL.with_borrow_mut(|m| m.used.extend([(9, 25_000), (19, 25_000), (1, 50_000)]));
    sched::balance(&mut h, 100_000, 0);
    assert!(!h.guest(0).unwrap().vmm_boosted);
    // After quiescence only the parent restores priority, keeping MCP low.
    for _ in 0..10 {
        MODEL.with_borrow_mut(|m| m.used.extend([(9, 1000), (1, 50_000)]));
        sched::balance(&mut h, 100_000, 0);
    }
    assert!(h.guest(0).unwrap().vmm_boosted);
    MODEL.with_borrow(|m| assert_eq!(m.priorities[&9], (101, l4h_host::PRIO_VMM)));
    assert_limits(&h);
}

/// An HVM guest's monitor (l4h-hvm) is demoted as a VMM is, but its MCP
/// never rises above hvm::MCP (below the debug syscalls' threshold): only
/// its priority changes.
#[test]
fn a_demoted_hvm_monitor_keeps_its_low_mcp() {
    let mut h = manager();
    build(&mut h, 0, 0, 0, 1);
    {
        let g = h.guests[0].as_mut().unwrap();
        g.hvm = Some(());
        for v in &mut g.vcpus { v.sc_u = None; }
    }
    MODEL.with_borrow_mut(|m| { m.priorities.insert(9, (l4h_host::hvm::MCP, l4h_host::PRIO_VMM)); });
    sched::start(&mut h, 0).unwrap();
    spawn(&mut h, 1, 0, 0, 1);
    MODEL.with_borrow_mut(|m| { m.priority_calls.clear(); m.used.extend([(9, 45_000), (19, 45_000), (1, 10_000)]); });
    sched::balance(&mut h, 100_000, 0);
    assert!(!h.guest(0).unwrap().vmm_boosted);
    MODEL.with_borrow(|m| {
        assert!(m.priority_calls.contains(&(9, "mcp", l4h_host::hvm::MCP)), "{:?}", m.priority_calls);
        assert!(!m.priority_calls.iter().any(|&(t, what, p)| t == 9 && what == "mcp" && p > l4h_host::hvm::MCP));
        assert!(m.priorities[&9].0 <= l4h_host::hvm::MCP && l4h_host::hvm::MCP < 101);
    });
    for _ in 0..10 {
        MODEL.with_borrow_mut(|m| m.used.extend([(9, 1000), (1, 50_000)]));
        sched::balance(&mut h, 100_000, 0);
    }
    MODEL.with_borrow(|m| assert_eq!(m.priorities[&9].0, l4h_host::hvm::MCP, "the MCP stays low"));
}

#[test]
fn a_vmm_spinning_before_guest_start_is_also_demoted() {
    let mut h = manager();
    spawn(&mut h, 0, 0, 0, 1);
    h.guests[0].as_mut().unwrap().state = State::Created;
    MODEL.with_borrow_mut(|m| { m.used.insert(9, 100_000); });
    sched::balance(&mut h, 100_000, 0);
    assert!(!h.guest(0).unwrap().vmm_boosted);
    assert_eq!(h.guest(0).unwrap().vmm_usage, 1000, "pre-READY CPU must be visible to management");
}

#[test]
fn a_failed_priority_reduction_stops_the_guest() {
    let mut h = manager();
    spawn(&mut h, 0, 0, 0, 1);
    spawn(&mut h, 1, 0, 0, 1);
    MODEL.with_borrow_mut(|m| { m.used.extend([(9, 50_000), (19, 50_000)]); m.fail_priority = Some(9); });
    sched::balance(&mut h, 100_000, 0);
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
    sched::balance(&mut h, 100_000, 0);
    assert_eq!(h.guest(0).unwrap().state, State::Stopped);
    assert_eq!(h.guest(2).unwrap().vcpus[0].core, 1);
}

#[test]
fn one_spinner_does_not_remove_its_quiet_neighbours_boost() {
    let mut h = manager();
    spawn(&mut h, 0, 0, 0, 1);
    spawn(&mut h, 1, 0, 0, 1);
    MODEL.with_borrow_mut(|m| m.used.extend([(9, 99_000), (19, 1000)]));
    sched::balance(&mut h, 100_000, 0);
    assert!(!h.guest(0).unwrap().vmm_boosted);
    assert!(h.guest(1).unwrap().vmm_boosted);
    // Even a previously demoted neighbour recovers under pressure.
    h.guests[1].as_mut().unwrap().vmm_boosted = false;
    for _ in 0..10 {
        MODEL.with_borrow_mut(|m| m.used.extend([(9, 99_000), (19, 0)]));
        sched::balance(&mut h, 100_000, 0);
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
    sched::balance(&mut h, 100_000, 0);
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
    MODEL.with_borrow_mut(|m| m.used.insert(9, 90_000));
    sched::balance(&mut h, 100_000, 0);
    let g = h.guest(0).unwrap();
    assert!(g.vmm_boosted && !g.vmm_limited);
    assert_eq!(MODEL.with_borrow(|m| m.calls.len()), before);
    assert_limits(&h);
}

#[test]
fn its_own_vcpus_do_not_demote_a_heavy_io_vmm() {
    for id in [0, MAX_GUESTS - 1] {
        let mut h = manager();
        h.info.cores = 2;
        h.info.topology = topology::Topology::flat(2);
        spawn(&mut h, id, 1, 0, 2);
        let before = MODEL.with_borrow(|m| m.calls.len());
        for _ in 0..100 {
            // Its two vCPUs belong to this VMM's trust domain. Their
            // placement and activity must not reserve CPU against it.
            MODEL.with_borrow_mut(|m| {
                m.used.insert((id * 10 + 9) as u64, 90_000);
                for sc in 1..=4 { m.used.insert((id * 10 + sc) as u64, 500); }
            });
            sched::balance(&mut h, 100_000, 0);
            let g = h.guest(id).unwrap();
            assert!(g.vmm_boosted && !g.vmm_limited);
        }
        assert_eq!(MODEL.with_borrow(|m| m.calls.len()), before);
        assert_limits(&h);
    }
}

#[test]
fn other_guests_with_zero_consumption_are_protected_without_refilling_contexts() {
    let mut h = manager();
    h.info.cores = 2;
    h.info.topology = topology::Topology::flat(2);
    spawn(&mut h, 0, 1, 0, 1);
    spawn(&mut h, MAX_GUESTS - 1, 1, 0, 1);
    // A guest cannot hide runnable demand by forging its idle counter.
    h.guests[0].as_mut().unwrap().events[0].idle_ticks = u64::MAX;
    MODEL.with_borrow_mut(|m| m.used.insert(9, 90_000));
    sched::balance(&mut h, 100_000, 0);
    assert!(h.guest(0).unwrap().vmm_limited);
    let before = MODEL.with_borrow(|m| m.calls.len());
    for tick in 0..1000 {
        // Zero consumption may mean blocked, awaiting refill or starved.
        // Even small changes in either guest's use must retain protection.
        MODEL.with_borrow_mut(|m| {
            m.used.extend([(1, tick % 2 * 500), (632, tick % 4 * 250)]);
            m.used.insert(9, 50_000);
        });
        sched::balance(&mut h, 100_000, 0);
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
    sched::balance(&mut h, 100_000, 0);
    assert!(h.guest(0).unwrap().vmm_limited);
    h.guests[1].as_mut().unwrap().stop();
    MODEL.with_borrow_mut(|m| { m.calls.clear(); m.used.insert(9, 50_000); });
    sched::balance(&mut h, 100_000, 0);
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
    sched::balance(h, 100_000, 0);
    assert!(h.guest(0).unwrap().vmm_limited);
    // A real balancing step moves vCPU 0 away; stop and destroy its peer
    // afterwards so no guest threads remain assigned to the VMM's core.
    h.guests[1].as_mut().unwrap().vcpus[0].cooldown = 10;
    MODEL.with_borrow_mut(|m| m.used.extend([(9, 50_000), (1, 25_000), (11, 25_000)]));
    sched::balance(h, 100_000, 0);
    h.guests[1].as_mut().unwrap().stop();
    h.guests[1] = None;
    MODEL.with_borrow_mut(|m| m.used.insert(9, 50_000));
    sched::balance(h, 100_000, 0);
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
        // The guarded VMM below VMM_BUSY_PCT of its core: the core
        // still counts as free for a busy vCPU (policy::vmm_busy).
        m.used.extend([(9, 20_000), (1, 50_000), (11, 50_000)]);
    });
    sched::balance(&mut h, 100_000, 0);
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
        // The guarded VMM below VMM_BUSY_PCT of its core: the core
        // still counts as free for a busy vCPU (policy::vmm_busy).
        m.used.extend([(9, 20_000), (1, 50_000), (11, 50_000)]);
    });
    sched::balance(&mut h, 100_000, 0);
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
    sched::balance(&mut h, 100_000, 0);
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
    sched::balance(&mut h, 100_000, 0);
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
    sched::balance(&mut h, 100_000, 0);
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
        // The guarded VMM below VMM_BUSY_PCT of its core: the core
        // still counts as free for a busy vCPU (policy::vmm_busy).
        m.used.extend([(9, 20_000), (1, 50_000), (11, 50_000)]);
    });
    sched::balance(&mut h, 100_000, 0);
    assert_eq!(h.guest(1).unwrap().state, State::Stopped);
    assert!(!h.guest(0).unwrap().vmm_limited && !h.guest(0).unwrap().vmm_boosted);
    MODEL.with_borrow(|m| assert_eq!(m.operations, vec![('c', 9), ('c', 11), ('x', 1), ('c', 9)]));
    assert_limits(&h);
}

#[test]
fn peer_vmm_consumption_requires_a_quantum_when_no_other_guests_are_assigned() {
    for (other_used, guarded) in [(50, false), (4999, false), (5000, true)] {
        let mut h = manager();
        h.info.cores = 2;
        h.info.topology = topology::Topology::flat(2);
        for id in 0..4 { spawn(&mut h, id, 1, 0, 1); }
        for id in 1..4 { place_vcpu(&mut h, id, 0); }
        for _ in 0..20 {
            let own_used = if h.guest(0).unwrap().vmm_limited { 50_000 } else { 90_000 };
            MODEL.with_borrow_mut(|m| m.used.extend([(9, own_used), (19, other_used)]));
            sched::balance(&mut h, 100_000, 0);
            assert_eq!(!h.guest(0).unwrap().vmm_boosted, guarded);
            assert!(h.guests[1..4].iter().flatten().all(|g| g.vmm_boosted));
        }
        assert_limits(&h);
    }
}

#[test]
fn a_guarded_peer_with_zero_cpu_use_cannot_be_starved_by_a_boosted_vmm() {
    for (offender, peer, quiet) in [(0, 1, 0), (1, 0, 0), (0, 1, 9), (1, 0, 9)] {
        let mut h = manager();
        h.info.cores = 2;
        h.info.topology = topology::Topology::flat(2);
        spawn(&mut h, offender, 1, 0, 1);
        spawn(&mut h, peer, 1, 0, 1);
        let peer_sc = (peer * 10 + 9) as u64;
        let offender_sc = (offender * 10 + 9) as u64;
        MODEL.with_borrow_mut(|m| m.used.insert(peer_sc, 90_000));
        sched::balance(&mut h, 100_000, 0);
        assert!(!h.guest(peer).unwrap().vmm_boosted);
        assert!(h.guest(offender).unwrap().vmm_boosted);
        // Both vCPUs leave the VMMs' core, so guest placement no longer
        // establishes contention. The guarded VMM still needs service.
        for id in [offender, peer] { place_vcpu(&mut h, id, 0); }
        for _ in 0..quiet { sched::balance(&mut h, 100_000, 0); }
        // At nine quiet samples the peer will recover this turn. Taking
        // the contention snapshot first must give the same result in
        // either guest order, including at that recovery boundary.
        MODEL.with_borrow_mut(|m| m.used.insert(offender_sc, 90_000));
        sched::balance(&mut h, 100_000, 0);
        assert!(!h.guest(offender).unwrap().vmm_boosted);
        assert_eq!(h.guest(peer).unwrap().vmm_boosted, quiet == 9);
        assert!(h.guests.iter().flatten().all(|g| !g.vmm_limited));
        assert_limits(&h);
    }
}

#[test]
fn many_idle_vmm_timers_without_other_guest_vcpus_do_not_remove_a_heavy_io_vmms_boost() {
    let mut h = manager();
    h.info.cores = 2;
    h.info.topology = topology::Topology::flat(2);
    for id in 0..64 { spawn(&mut h, id, 1, 0, 1); }
    for id in 1..64 { place_vcpu(&mut h, id, 0); }
    let before = MODEL.with_borrow(|m| m.calls.len());
    MODEL.with_borrow_mut(|m| {
        for id in 0..64 {
            m.used.insert(id*10+9, if id == 0 { 90_000 } else { 50 });
        }
    });
    sched::balance(&mut h, 100_000, 0);
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
        sched::balance(&mut h, 100_000, 0);
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
        sched::balance(&mut h, 100_000, 0);
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

// Two cores of two threads: CPUs 0/1 and 2/3.
fn smt_manager() -> Vmmgr {
    let mut h = manager();
    h.info.cores = 4;
    h.info.topology = topology::Topology::from_ids(&[0, 0, 1, 1]);
    h
}

#[test]
fn placement_weighs_guests_and_vmms_and_numbers_vcores() {
    let mut h = smt_manager();
    spawn(&mut h, 0, 0, 0, 1);
    let cores = sched::place(&h, 4, 0);
    assert_eq!(cores.as_slice(), [(2, 0), (1, 1), (3, 0), (0, 1)]);
    h.guests[0].as_mut().unwrap().stop();
    assert_eq!(sched::place(&h, 2, 1).as_slice(), [(2, 0), (0, 1)]);
}

/// Guest 0: vCPUs 0 and 1 (one vCore) busy on CPUs 0 and 1, beside guest
/// 1's busy vCPU, which cannot move; its idle vCore (vCPUs 2, 3) on 2/3.
fn busy_vcore(h: &mut Vmmgr) {
    build(h, 0, 0, 0, 4);
    {
        let g = h.guests[0].as_mut().unwrap();
        for (v, core) in [0, 1, 2, 3].into_iter().enumerate() {
            g.vcpus[v].core = core;
            g.vcpus[v].vcore = core / 2;
        }
    }
    for v in 1..4 {
        let g = h.guest(0).unwrap();
        let p = sched::budget::plan(5000, 0, 0, 500, None, false);
        h.info.sched_control(v).sched_control_configure_flags(g.vcpus[v].sc_k, p.kernel, p.period, 14, 0, 0).unwrap();
        h.info.sched_control(v).sched_control_configure_flags(g.vcpus[v].sc_u.unwrap(), p.user, p.period, 14, 0, 0).unwrap();
    }
    sched::start(h, 0).unwrap();
    spawn(h, 1, 0, 0, 1);
    h.guests[1].as_mut().unwrap().vcpus[0].cooldown = 10;
    MODEL.with_borrow_mut(|m| {
        m.operations.clear();
        m.used.extend([(1, 25_000), (2, 25_000), (3, 25_000), (4, 25_000), (11, 25_000), (12, 25_000)]);
    });
}

#[test]
fn a_vcore_swap_protects_both_cores_and_moves_the_whole_vcore() {
    let mut h = smt_manager();
    busy_vcore(&mut h);
    sched::balance(&mut h, 100_000, 0);
    let g = h.guest(0).unwrap();
    let cores: Vec<_> = g.vcpus.iter().map(|v| v.core).collect();
    // The busy vCore takes core 1, one vCPU per thread; the idle one core 0.
    let mut busy = cores[..2].to_vec();
    busy.sort();
    assert_eq!(busy, [2, 3]);
    assert!(cores[2..].iter().all(|&c| c < 2), "{cores:?}");
    assert!(g.vcpus.iter().all(|v| v.cooldown == 10));
    assert_eq!(g.state, State::Running);
    MODEL.with_borrow(|m| {
        for v in &g.vcpus {
            assert_eq!(m.limits[&v.sc_k.0].0, v.core);
            assert_eq!(m.limits[&v.sc_u.unwrap().0].0, v.core);
        }
        // Each vCPU moved once, both contexts, busiest first; no guest stopped.
        assert_eq!(m.operations, [1, 2, 3, 4, 5, 6, 7, 8].map(|sc| ('c', sc)));
    });
    assert_limits(&h);
}

#[test]
fn a_failed_vcore_swap_stops_the_guest() {
    let mut h = smt_manager();
    busy_vcore(&mut h);
    MODEL.with_borrow_mut(|m| m.fail_config = Some(3));
    sched::balance(&mut h, 100_000, 0);
    assert_eq!(h.guest(0).unwrap().state, State::Stopped);
    assert_eq!(h.guest(1).unwrap().state, State::Running);
    MODEL.with_borrow(|m| assert!(m.operations.contains(&('x', 0))));
}

#[test]
fn host_capacity_reflects_other_guests_on_the_cpu_and_its_siblings() {
    let mut h = smt_manager();
    spawn(&mut h, 0, 0, 0, 1);
    spawn(&mut h, 1, 0, 0, 1);
    spawn(&mut h, 2, 1, 0, 1);
    for id in 0..3 { h.guests[id].as_mut().unwrap().vcpus[0].cooldown = 10; }
    let cap = |h: &Vmmgr, id: usize| (h.guest(id).unwrap().vcpus[0].host_cap, h.guest(id).unwrap().events[0].host_cap);
    // Idle neighbours leave the full capacity, and nothing is rewritten.
    sched::balance(&mut h, 100_000, 0);
    assert_eq!(cap(&h, 0), (1024, 1024));
    // Guest 1 takes half of CPU 0 and guest 2 all of its sibling CPU 1.
    MODEL.with_borrow_mut(|m| m.used.extend([(1, 50_000), (11, 25_000), (12, 25_000), (21, 50_000), (22, 50_000)]));
    sched::balance(&mut h, 100_000, 0);
    // raw = 1024 - 512 * 0.5 - 350 * 1.0 = 418, halfway from 1024.
    assert_eq!(cap(&h, 0), (721, 721));
    // Guest 2 sees guest 0 and guest 1 on its sibling only: 1024 - 350.
    assert_eq!(cap(&h, 2).0, (1024 + 674) / 2);
    // Its own VMM is not another guest.
    MODEL.with_borrow_mut(|m| m.used.extend([(29, 100_000)]));
    let before = cap(&h, 2).0;
    sched::balance(&mut h, 100_000, 0);
    assert!(cap(&h, 2).0 > before);
    // A late report above the period on its own CPU is not a sibling's:
    // 1024 - 512, without a sibling penalty.
    h.guests[1].as_mut().unwrap().vcpus[0].cooldown = 10;
    MODEL.with_borrow_mut(|m| m.used.extend([(11, 60_000), (12, 60_000)]));
    h.guests[0].as_mut().unwrap().vcpus[0].host_cap = 1024;
    sched::balance(&mut h, 100_000, 0);
    assert_eq!(cap(&h, 0), ((1024 + 512) / 2, 768));
    // A stopped guest's page is left alone.
    h.guests[0].as_mut().unwrap().stop();
    MODEL.with_borrow_mut(|m| m.used.extend([(11, 100_000), (12, 100_000)]));
    let before = cap(&h, 0);
    sched::balance(&mut h, 100_000, 0);
    assert_eq!(cap(&h, 0), before);
}

/// An HVM guest `id` with `vcpus` vCPUs on `core`, started (its monitor
/// where sched::prepare_vmm puts it).
fn spawn_hvm(h: &mut Vmmgr, id: usize, core: usize, cap: u32, vcpus: usize) {
    let mut g = create(id, core, cap, vcpus);
    g.hvm = Some(());
    for v in &mut g.vcpus { v.sc_u = None; }
    let p = sched::prepare_vmm(h, &mut g).unwrap();
    let sc = sel4::cap::SchedContext((id * 10 + 9) as u64);
    let vmm_core = g.vmm_limits.unwrap().0;
    h.info.sched_control(vmm_core).sched_control_configure_flags(sc, p.vmm, p.vmm_period, l4h_host::GUEST_EXTRA_REFILLS, 0, 0).unwrap();
    MODEL.with_borrow_mut(|m| { m.priorities.insert(sc.0, (l4h_host::hvm::MCP, l4h_host::PRIO_VMM)); });
    g.vmm = Some(Component { sc, tcb: sel4::cap::Tcb(sc.0) });
    h.guests[id] = Some(g);
    sched::start(h, id).unwrap();
}

/// (budget, period) of scheduling context `sc` as last configured.
fn limit(sc: u64) -> (u64, u64) {
    MODEL.with_borrow(|m| { let (_, b, p, _) = m.limits[&sc]; (b, p) })
}

/// A PV guest `id` with two vCPUs, vCPU 0 (and its VMM) on CPU 0 and
/// vCPU 1 on CPU 1, built (Created) or started.
fn build_split(h: &mut Vmmgr, id: usize, start: bool) {
    build(h, id, 0, 0, 2);
    let g = h.guests[id].as_mut().unwrap();
    g.vcpus[1].core = 1;
    let p = sched::budget::plan(5000, 0, 0, 500, None, false);
    h.info.sched_control(1).sched_control_configure_flags(g.vcpus[1].sc_k, p.kernel, p.period, 14, 0, 0).unwrap();
    h.info.sched_control(1).sched_control_configure_flags(g.vcpus[1].sc_u.unwrap(), p.user, p.period, 14, 0, 0).unwrap();
    if start { sched::start(h, id).unwrap(); }
}

fn two_cpus() -> Vmmgr {
    let mut h = manager();
    h.info.cores = 2;
    h.info.topology = topology::Topology::flat(2);
    h
}

/// A PV vCPU's SC_K runs at PRIO_KERNEL, above an HVM vCPU: on a CPU with
/// one, the PV kernels there share a quarter of it when a VMM runs there
/// too (here guest 0's, beside its vCPU 0), limited before the HVM vCPU
/// runs, their SC_U left whole; the limit goes as soon as the HVM guest
/// does; and a steady state reconfigures nothing.
#[test]
fn pv_kernels_share_a_quarter_beside_an_hvm_vcpu_and_a_vmm() {
    let mut h = two_cpus();
    spawn(&mut h, 0, 0, 0, 2);
    let (full, period) = limit(1);
    assert_eq!(full, period);
    MODEL.with_borrow_mut(|m| m.operations.clear());
    spawn_hvm(&mut h, 1, 0, 0, 1);
    let g = h.guest(0).unwrap();
    assert!(g.vcpus.iter().all(|v| v.kernel_divisor == 8), "two PV kernels and a VMM: a quarter");
    for (k, u) in [(1, 2), (3, 4)] {
        assert_eq!((limit(k), limit(u)), ((period / 8, period), (period, period)));
    }
    assert_eq!(limit(11), (period, period), "the HVM vCPU is not limited");
    MODEL.with_borrow(|m| {
        let start = m.operations.iter().position(|&o| o == ('s', 1)).unwrap();
        assert!(m.operations[..start].contains(&('c', 1)) && m.operations[..start].contains(&('c', 3)),
            "limited before the HVM vCPU runs: {:?}", m.operations);
    });
    assert_limits(&h);
    // Steady: no context reconfigured (refills kept).
    MODEL.with_borrow_mut(|m| m.calls.clear());
    sched::balance(&mut h, 100_000, 0);
    sched::balance(&mut h, 100_000, 0);
    MODEL.with_borrow(|m| assert!(!m.calls.iter().any(|&c| c <= 4), "{:?}", m.calls));
    // The HVM guest goes (destroyed: no longer in the table): whole again
    // at once, before any balancer step.
    h.guests[1].as_mut().unwrap().stop();
    h.guests[1] = None;
    sched::reconcile(&mut h);
    let g = h.guest(0).unwrap();
    assert!(g.vcpus.iter().all(|v| v.kernel_divisor == 0));
    for sc in 1..=4 { assert_eq!(limit(sc), (period, period)); }
    assert_limits(&h);
}

/// Beside an HVM vCPU, PV kernels on a CPU without a VMM share half of
/// it; a guest only created (not started) is not counted until it starts,
/// and a guest that stops leaves the survivors' share whole again at once.
#[test]
fn pv_kernels_share_half_a_cpu_without_a_vmm() {
    let mut h = two_cpus();
    build_split(&mut h, 0, true);
    spawn_hvm(&mut h, 1, 1, 0, 1);
    assert_ne!(h.guest(1).unwrap().vmm_limits.unwrap().0, 1, "the monitor away from its vCPU");
    let (_, period) = limit(3);
    let g = h.guest(0).unwrap();
    assert_eq!((g.vcpus[0].kernel_divisor, g.vcpus[1].kernel_divisor), (0, 2), "CPU 0 has no HVM vCPU");
    assert_eq!((limit(3), limit(4)), ((period / 2, period), (period, period)));
    // A second PV guest's vCPU 1 on CPU 1, created only: not counted.
    build_split(&mut h, 2, false);
    sched::balance(&mut h, 100_000, 0);
    assert_eq!(h.guest(0).unwrap().vcpus[1].kernel_divisor, 2, "a created guest does not run");
    assert_eq!(limit(3), (period / 2, period));
    // Started: both share the half, limited before it runs.
    MODEL.with_borrow_mut(|m| m.operations.clear());
    sched::start(&mut h, 2).unwrap();
    assert_eq!((h.guest(0).unwrap().vcpus[1].kernel_divisor, h.guest(2).unwrap().vcpus[1].kernel_divisor), (4, 4));
    assert_eq!((limit(3), limit(23)), ((period / 4, period), (period / 4, period)));
    MODEL.with_borrow(|m| {
        let start = m.operations.iter().position(|&o| o == ('s', 2)).unwrap();
        assert!(m.operations[..start].contains(&('c', 23)), "limited before it runs: {:?}", m.operations);
    });
    // Guest 2 stops: guest 0's vCPU 1 has the half to itself again at once.
    h.guests[2].as_mut().unwrap().stop();
    sched::reconcile(&mut h);
    assert_eq!(h.guest(0).unwrap().vcpus[1].kernel_divisor, 2);
    assert_eq!(limit(3), (period / 2, period));
    assert_limits(&h);
}

/// A guarded VMM beside them counts as a VMM there: a quarter.
#[test]
fn a_pv_kernel_beside_an_hvm_vcpu_and_a_guarded_vmm_gets_a_quarter() {
    let mut h = manager();
    guard_on_empty_core(&mut h);
    // Guest 0: its vCPU on CPU 0, its VMM guarded on CPU 1.
    assert_eq!(h.guest(0).unwrap().vmm_limits.unwrap().0, 1);
    spawn_hvm(&mut h, 1, 1, 0, 1);
    assert!(h.guest(0).unwrap().vmm_limited, "another guest's vCPU on the VMM's CPU");
    build_split(&mut h, 2, true);
    let v = &h.guest(2).unwrap().vcpus[1];
    assert_eq!(v.kernel_divisor, 4);
    let (_, period) = limit(23);
    assert_eq!((limit(23), limit(24)), ((period / 4, period), (period, period)));
    assert_eq!(h.guest(0).unwrap().vcpus[0].kernel_divisor, 0, "on CPU 0: no HVM vCPU there");
    assert_limits(&h);
}

/// A boosted VMM (at PRIO_VMM, above everything here) and a busy PV kernel
/// beside an HVM vCPU: the kernel gets a quarter, and the VMM, which with
/// it crowds the CPU, is demoted to its background half, so PRIO_USER
/// keeps a quarter; without the HVM vCPU, the same VMM keeps its boost.
#[test]
fn a_vmm_crowding_an_hvm_vcpus_cpu_with_pv_kernels_is_demoted() {
    for with_hvm in [true, false] {
        let mut h = two_cpus();
        spawn(&mut h, 0, 0, 0, 1);
        if with_hvm {
            spawn_hvm(&mut h, 1, 0, 0, 1);
            assert_eq!(h.guest(0).unwrap().vcpus[0].kernel_divisor, 4);
        }
        // The VMM uses 60%, the PV kernel 25% (its limit); the vCPU stays
        // (the balancer would rightly move it to the free CPU).
        h.guests[0].as_mut().unwrap().vcpus[0].cooldown = 10;
        MODEL.with_borrow_mut(|m| m.used.extend([(9, 60_000), (1, 25_000)]));
        sched::balance(&mut h, 100_000, 0);
        let g = h.guest(0).unwrap();
        assert_eq!(g.vmm_boosted, !with_hvm, "with an HVM vCPU there: {with_hvm}");
        if with_hvm {
            let (_, p) = g.vmm_limits.unwrap();
            assert!(g.vmm_limited && p.vmm * 2 <= p.vmm_period, "its background half: {p:?}");
            assert!(p.kernel * 4 <= p.period, "{p:?}");
        }
        assert_limits(&h);
    }
}

/// A capped PV vCPU beside an HVM vCPU: SC_K at most its part, the rest
/// of the cap to SC_U, the cap itself unchanged; one whose cap already
/// keeps SC_K within the limit is not reconfigured.
#[test]
fn a_capped_pv_kernel_beside_an_hvm_vcpu_keeps_its_cap() {
    let mut h = two_cpus();
    spawn(&mut h, 0, 0, 80, 2);
    h.guests[0].as_mut().unwrap().vcpus[1].k_share = 900;
    assert_eq!(sched::set_cap(&mut h, 0, 80), Ok(()));
    let ((k0, p), (u0, _)) = (limit(3), limit(4));
    assert!(k0 > p / 8);
    spawn_hvm(&mut h, 1, 0, 0, 1);
    let ((k, _), (u, _)) = (limit(3), limit(4));
    assert_eq!((k, k + u), (p / 8, k0 + u0));
    assert_limits(&h);

    let mut h = two_cpus();
    spawn(&mut h, 0, 0, 10, 2);
    assert_eq!(sched::set_cap(&mut h, 0, 10), Ok(()));
    let before = (limit(3), limit(4));
    assert!(before.0.0 <= before.0.1 / 8, "a 10% cap keeps SC_K within an eighth");
    MODEL.with_borrow_mut(|m| m.calls.clear());
    spawn_hvm(&mut h, 1, 0, 0, 1);
    assert_eq!(h.guest(0).unwrap().vcpus[1].kernel_divisor, 8);
    MODEL.with_borrow(|m| assert!(!m.calls.iter().any(|&c| c == 3 || c == 4), "refills kept: {:?}", m.calls));
    assert_eq!((limit(3), limit(4)), before);
    assert_limits(&h);
}

/// A PV vCPU the balancer moves onto an HVM vCPU's CPU arrives there
/// limited (its contexts configured once, for the destination), counted
/// with the PV vCPUs already there.
#[test]
fn a_pv_vcpu_moved_beside_an_hvm_vcpu_arrives_limited() {
    let mut h = manager();
    h.info.cores = 2;
    h.info.topology = topology::Topology::flat(2);
    // An idle HVM vCPU on CPU 1; two busy PV vCPUs on CPU 0.
    spawn_hvm(&mut h, 1, 1, 0, 1);
    spawn(&mut h, 0, 0, 0, 1);
    spawn(&mut h, 2, 0, 0, 1);
    h.guests[0].as_mut().unwrap().vcpus[0].cooldown = 10;
    let (_, period) = limit(21);
    assert_eq!(h.guest(2).unwrap().vcpus[0].kernel_divisor, 0);
    MODEL.with_borrow_mut(|m| { m.calls.clear(); m.used.extend([(1, 50_000), (21, 50_000)]); });
    sched::balance(&mut h, 100_000, 0);
    let v = &h.guest(2).unwrap().vcpus[0];
    assert_eq!((v.core, v.kernel_divisor), (1, 2));
    MODEL.with_borrow(|m| {
        assert_eq!(m.limits[&21], (1, period / 2, period, 14));
        assert_eq!(m.limits[&22], (1, period, period, 14));
        assert_eq!(m.calls.iter().filter(|&&c| c == 21).count(), 1, "{:?}", m.calls);
    });
    assert_limits(&h);
}

/// vmmgr tells an HVM guest's monitor not to busy-poll (io_flags) while
/// its guest is capped, its boost is withdrawn, or other guests' vCPUs
/// share the monitor's core.
#[test]
fn an_hvm_monitor_busy_polls_only_alone_boosted_and_uncapped() {
    let mut h = manager();
    h.info.cores = 2;
    h.info.topology = topology::Topology::flat(2);
    spawn_hvm(&mut h, 0, 0, 0, 1);
    let monitor = h.guest(0).unwrap().vmm_limits.unwrap().0;
    assert_ne!(monitor, 0, "away from its own vCPU");
    let flags = |h: &Vmmgr| h.guest(0).unwrap().events[0].io_flags;
    assert_eq!(flags(&h), 0);
    spawn(&mut h, 1, monitor, 0, 1);
    assert_eq!(flags(&h), l4h_abi::EVENT_IO_NO_POLL, "another guest's vCPU on its core");
    h.guests[1].as_mut().unwrap().stop();
    sched::balance(&mut h, 100_000, 0);
    assert_eq!(flags(&h), 0);
    assert_eq!(sched::set_cap(&mut h, 0, 50), Ok(()));
    assert_eq!(flags(&h), l4h_abi::EVENT_IO_NO_POLL, "capped");
    assert_eq!(sched::set_cap(&mut h, 0, 0), Ok(()));
    assert_eq!(flags(&h), 0);
    // Demoted, alone on its core (so not limited): still no busy polling
    // while its boost is withdrawn.
    h.guests[0].as_mut().unwrap().vmm_boosted = false;
    sched::balance(&mut h, 100_000, 0);
    let g = h.guest(0).unwrap();
    assert!(!g.vmm_boosted && !g.vmm_limited);
    assert_eq!(flags(&h), l4h_abi::EVENT_IO_NO_POLL, "boost withdrawn");
}

/// A vCPU blocked across a sample (EventPage::idle_since set) is idle
/// then, not stolen from: steal_ns, published monotonically, stays 0.  A
/// sample that finds the idle fields changing (idle_seq odd) leaves steal
/// alone.
#[test]
fn a_block_in_progress_is_idle_not_steal() {
    let mut h = manager();
    spawn(&mut h, 0, 0, 0, 1);
    fn ev(h: &mut Vmmgr) -> &mut Event { &mut h.guests[0].as_mut().unwrap().events[0] }
    // 10 ms run, 90 ms blocked.
    MODEL.with_borrow_mut(|m| { m.used.insert(1, 10_000); });
    (ev(&mut h).idle_ticks, ev(&mut h).idle_seq) = (90_000, 2);
    sched::balance(&mut h, 100_000, 100_000);
    // Blocked since 100 ms, still blocked at the next sample.
    (ev(&mut h).idle_since, ev(&mut h).idle_seq) = (100_000, 4);
    sched::balance(&mut h, 100_000, 200_000);
    assert_eq!(h.guest(0).unwrap().vcpus[0].steal_ns, 0);
    // It wakes at 250 ms and runs on; the 300 ms sample finds the idle
    // fields changing (odd): idle_since already clear, idle_ticks not yet
    // updated, which read as they are would make 150 ms steal.  Steal is
    // left as it was.
    (ev(&mut h).idle_since, ev(&mut h).idle_seq) = (0, 5);
    MODEL.with_borrow_mut(|m| { m.used.insert(1, 50_000); });
    sched::balance(&mut h, 100_000, 300_000);
    assert_eq!(h.guest(0).unwrap().vcpus[0].steal_ns, 0, "a sample mid-change leaves steal");
    // The next one reads them settled: 400 ms, of which it ran 160 and
    // was idle 240.
    (ev(&mut h).idle_ticks, ev(&mut h).idle_since, ev(&mut h).idle_seq) = (90_000 + 150_000, 0, 6);
    MODEL.with_borrow_mut(|m| { m.used.insert(1, 100_000); });
    sched::balance(&mut h, 100_000, 400_000);
    assert_eq!(h.guest(0).unwrap().vcpus[0].steal_ns, 0);
    // idle_ticks itself.
    let mut page = Event { idle_ticks: 7, steal_ns: 0, host_cap: 0, idle_since: 0, io_flags: 0, idle_seq: 0 };
    assert_eq!(sched::idle_ticks(&mut page, 1_000), Some(7), "an older guest: as before");
    page.idle_since = 400;
    assert_eq!(sched::idle_ticks(&mut page, 1_000), Some(7 + 600));
    assert_eq!(sched::idle_ticks(&mut page, 100), Some(7), "a counter behind idle_since adds nothing");
    page.idle_seq = 9;
    assert_eq!(sched::idle_ticks(&mut page, 1_000), None);
}

/// A VMM about to start on a CPU with an HVM vCPU and a PV kernel but no
/// VMM yet (sched::vmm_arriving, before component::start): the PV kernel
/// has its limit for a CPU with a VMM first; the arriving guest's own
/// vCPUs, which do not run before its start, are not counted.
#[test]
fn a_vmm_arriving_beside_an_hvm_vcpu_tightens_its_pv_neighbours_first() {
    for in_table in [false, true] {
        let mut h = two_cpus();
        build_split(&mut h, 0, true);
        spawn_hvm(&mut h, 1, 1, 0, 1);
        let (_, period) = limit(3);
        assert_eq!(h.guest(0).unwrap().vcpus[1].kernel_divisor, 2, "no VMM on CPU 1 yet");
        // Guest 2, created on CPU 1: its VMM starts there.  vmmgr has it
        // out of its table meanwhile (with_guest); either way it is not
        // counted.
        let mut g = create(2, 1, 0, 1);
        let _ = sched::prepare_vmm(&mut h, &mut g).unwrap();
        assert_eq!(g.vmm_limits.unwrap().0, 1);
        if in_table { h.guests[2] = Some(g); }
        MODEL.with_borrow_mut(|m| m.operations.clear());
        sched::vmm_arriving(&mut h, 2, 1);
        assert_eq!(h.guest(0).unwrap().vcpus[1].kernel_divisor, 4, "a quarter for one PV kernel, not an eighth");
        assert_eq!(limit(3), (period / 4, period));
        MODEL.with_borrow(|m| assert!(m.operations.contains(&('c', 3)), "{:?}", m.operations));
        if in_table {
            assert_eq!(h.guest(2).unwrap().vcpus[0].kernel_divisor, 0, "not starting yet");
        }
    }
}

// SPDX-License-Identifier: GPL-2.0-only
//! Production IPC transport over a deterministic seL4 model. A bound
//! notification wins over endpoint senders exactly as receiveIPC does.
#![allow(dead_code, unused_attributes)]
extern crate self as sel4;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::marker::PhantomData;
use l4h_host as host;

pub const NUM_MESSAGE_REGISTERS: usize = 120;
pub trait CapType {}
pub mod cap_type {
    macro_rules! types { ($($t:ident),*) => {$(pub struct $t; impl super::CapType for $t {})*}; }
    types!(Endpoint, Reply, Untyped, CNode, Granule, Notification, Tcb);
}
pub struct Cap<T: CapType>(u64, PhantomData<T>);
impl<T: CapType> Clone for Cap<T> { fn clone(&self) -> Self { *self } }
impl<T: CapType> Copy for Cap<T> {}
impl<T: CapType> Cap<T> {
    pub const fn from_bits(v: u64) -> Self { Self(v, PhantomData) }
    pub fn bits(self) -> u64 { self.0 }
}
#[derive(Debug, Clone, Copy)]
pub enum Error { IllegalOperation, InvalidCapability }
pub mod cap {
    pub type Endpoint = super::Cap<super::cap_type::Endpoint>;
    pub type Reply = super::Cap<super::cap_type::Reply>;
    pub type Tcb = super::Cap<super::cap_type::Tcb>;
    pub type Notification = super::Cap<super::cap_type::Notification>;
}
#[derive(Clone, Copy)]
pub struct MessageInfo { label: u64, len: usize }
impl MessageInfo {
    pub fn new(label: u64, _: u64, _: u64, len: usize) -> Self { Self { label, len } }
    pub fn label(&self) -> u64 { self.label }
    pub fn length(&self) -> usize { self.len }
}
pub struct Buffer([u64; NUM_MESSAGE_REGISTERS]);
impl Buffer {
    pub fn msg_regs(&self) -> &[u64] { &self.0 }
    pub fn msg_regs_mut(&mut self) -> &mut [u64] { &mut self.0 }
}
thread_local! {
    static BUFFER: RefCell<Buffer> = const { RefCell::new(Buffer([0; NUM_MESSAGE_REGISTERS])) };
    static MODEL: RefCell<Model> = RefCell::new(Model::new());
}
pub fn with_ipc_buffer<R>(f: impl FnOnce(&Buffer) -> R) -> R { BUFFER.with(|b| f(&b.borrow())) }
pub fn with_ipc_buffer_mut<R>(f: impl FnOnce(&mut Buffer) -> R) -> R { BUFFER.with(|b| f(&mut b.borrow_mut())) }
fn clobber() { with_ipc_buffer_mut(|b| b.0.fill(0xbad)); }

#[derive(Clone, Copy)]
enum Input { Call(u64), Fault, Unanswered, Unbadged }
struct Model {
    bound: bool, notification: bool, flood: bool,
    bound_tcb: u64, notification_badge: u64,
    unbind_error: Option<Error>, bind_error: Option<Error>,
    inputs: VecDeque<Input>, held: Option<Input>, replies: Vec<Vec<u64>>,
    signals: usize, polls: usize, rebinds: usize, unanswered: usize,
    calls: Vec<u64>, faults: usize, idle: usize,
    expiry_on_unbind: bool, rearm_expiry: bool, deadline: u64,
    reply_words: Vec<u64>,
}
impl Model {
    fn new() -> Self {
        Self {
            bound: true, notification: false, flood: false, inputs: VecDeque::new(), held: None,
            bound_tcb: host::SLOT_TCB, notification_badge: host::badges::root::CHANNEL,
            unbind_error: None, bind_error: None,
            replies: Vec::new(), signals: 0, polls: 0, rebinds: 0, unanswered: 0,
            calls: Vec::new(), faults: 0, idle: 0,
            expiry_on_unbind: false, rearm_expiry: false, deadline: 100, reply_words: vec![0],
        }
    }
}
struct End;
fn finish() -> ! { std::panic::panic_any(End) }
fn receive(blocking: bool) -> (MessageInfo, u64) {
    let input = MODEL.with(|m| {
        let mut m = m.borrow_mut();
        if !blocking { m.polls += 1; }
        if m.bound && m.notification {
            m.notification = false;
            return None;
        }
        // Receiving on an already-bound reply lets go of its old caller.
        m.held = m.inputs.pop_front();
        if m.held.is_none() && blocking { finish(); }
        Some(m.held)
    });
    match input {
        None => (MessageInfo::new(0, 0, 0, 0), MODEL.with(|m| m.borrow().notification_badge)),
        Some(None) => (MessageInfo::new(0, 0, 0, 0), 0),
        Some(Some(input)) => {
            let (label, badge, word) = match input {
                Input::Call(w) => (0x101, host::root::Sender::Vmmgr.badge(), w),
                Input::Fault => (9, host::badges::parent::FAULT | 1, 0xfeed),
                Input::Unanswered => (0x101, host::root::Sender::Vmmgr.badge(), 0xffff),
                Input::Unbadged => (1, 0, 21),
            };
            with_ipc_buffer_mut(|b| b.0[0] = word);
            (MessageInfo::new(label, 0, 0, 1), badge)
        }
    }
}
fn answer(info: MessageInfo) {
    let words = with_ipc_buffer(|b| b.0[..info.length()].to_vec());
    MODEL.with(|m| {
        let mut m = m.borrow_mut();
        assert!(matches!(m.held.take(), Some(Input::Call(_) | Input::Unbadged)), "fault/unanswered call was replied to");
        m.replies.push(words);
    });
}
impl Cap<cap_type::Endpoint> {
    pub fn call(self, _: MessageInfo) -> MessageInfo {
        let words = MODEL.with(|m| m.borrow().reply_words.clone());
        with_ipc_buffer_mut(|b| b.0[..words.len()].copy_from_slice(&words));
        MessageInfo::new(0, 0, 0, words.len())
    }
    pub fn recv(self, _: cap::Reply) -> (MessageInfo, u64) { receive(true) }
    pub fn nb_recv(self, _: cap::Reply) -> (MessageInfo, u64) { receive(false) }
    pub fn reply_recv(self, info: MessageInfo, reply: cap::Reply) -> (MessageInfo, u64) { answer(info); self.recv(reply) }
}
impl Cap<cap_type::Reply> { pub fn send(self, info: MessageInfo) { answer(info); } }
impl Cap<cap_type::Tcb> {
    pub fn tcb_unbind_notification(self) -> Result<(), Error> {
        let result = MODEL.with(|m| {
            let mut m = m.borrow_mut();
            if let Some(e) = m.unbind_error.take() { return Err(e); }
            if !m.bound || m.bound_tcb != self.0 { return Err(Error::IllegalOperation); }
            m.bound = false;
            // A kernel timer can expire here without delivering a signal.
            if m.expiry_on_unbind { m.rearm_expiry = true; m.expiry_on_unbind = false; }
            Ok(())
        });
        clobber();
        result
    }
    pub fn tcb_bind_notification(self, _: cap::Notification) -> Result<(), Error> {
        let result = MODEL.with(|m| {
            let mut m = m.borrow_mut();
            if let Some(e) = m.bind_error.take() { return Err(e); }
            if m.bound { return Err(Error::IllegalOperation); }
            m.bound = true;
            m.bound_tcb = self.0;
            m.rebinds += 1;
            Ok(())
        });
        clobber();
        result
    }
}

#[path = "../host/l4h-ipc/src/lib.rs"]
mod ipc;
pub fn cap<T: CapType>(slot: u64) -> Cap<T> { Cap::from_bits(slot) }
#[path = "../host/l4h-rt/src/failure.rs"]
mod failure;

struct Reply;
impl ipc::ReplyObject for Reply {
    fn cap(&self) -> cap::Reply { cap::Reply::from_bits(2) }
    fn unanswered(&mut self) {
        assert!(!ipc::holds_call() || MODEL.with(|m| matches!(m.borrow().held, Some(Input::Fault))));
        MODEL.with(|m| { let mut m = m.borrow_mut(); m.unanswered += 1; m.held = None; });
        clobber();
    }
}
struct Receiver;
impl ipc::Server for Receiver {
    const SIGNALS: u64 = host::badges::root::SIGNALS;
    const FAULT: u64 = host::badges::root::FAULT;
    type Sender = host::root::Sender;
    fn notification(&self) -> Option<ipc::Bound> {
        Some(ipc::Bound::new(cap::Tcb::from_bits(host::SLOT_TCB), cap::Notification::from_bits(4)))
    }
    fn rebound(&mut self) {
        MODEL.with(|m| {
            let mut m = m.borrow_mut();
            assert!(m.bound);
            assert_eq!(m.deadline, 100, "rebind must not postpone the deadline");
            if m.rearm_expiry { m.notification = true; m.rearm_expiry = false; }
        });
        clobber();
    }
    fn received(&mut self) { clobber(); }
    fn signal(&mut self, badge: u64) {
        assert!(!ipc::holds_call());
        MODEL.with(|m| {
            let mut m = m.borrow_mut();
            if badge == 0 { m.idle += 1; } else { m.signals += 1; }
            assert!(m.signals < 20, "notifications starved queued calls");
            if m.inputs.is_empty() && m.held.is_none() && !m.replies.is_empty() { finish(); }
            m.notification |= m.flood;
        });
    }
    fn fault(&mut self, _: u64, _: &MessageInfo) {
        assert!(!ipc::holds_call());
        assert_eq!(with_ipc_buffer(|b| b.0[0]), 0xfeed);
        MODEL.with(|m| m.borrow_mut().faults += 1);
    }
    fn call(&mut self, from: Self::Sender, _: u64, info: &MessageInfo) -> Option<MessageInfo> {
        assert!(ipc::holds_call());
        let word = with_ipc_buffer(|b| {
            assert!(host::root::call::Request::decode(info.label(), &b.0[..info.length()], from).is_ok());
            b.0[0]
        });
        MODEL.with(|m| m.borrow_mut().calls.push(word));
        if word == 0xffff { None } else { Some(ipc::reply(&[0, word])) }
    }
    fn next(&mut self) -> ipc::Next { clobber(); ipc::Next::Wait }
}
fn run(s: &mut impl ipc::Server) {
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let end = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| ipc::run(cap::Endpoint::from_bits(1), Reply, s)));
    std::panic::set_hook(hook);
    assert!(end.unwrap_err().is::<End>());
}

#[test]
fn continuous_signals_allow_calls_and_keep_words_across_rebinding_and_handlers() {
    MODEL.with(|m| *m.borrow_mut() = Model { notification: true, flood: true, inputs: [Input::Call(42), Input::Call(43)].into(), ..Model::new() });
    run(&mut Receiver);
    MODEL.with(|m| {
        let m = m.borrow();
        assert_eq!(m.calls, [42, 43]);
        assert_eq!(m.replies, [vec![0, 42], vec![0, 43]]);
        assert_eq!(m.rebinds, 2);
        assert_eq!(m.idle, 0);
    });
}

#[test]
fn faults_and_calls_left_unanswered_are_not_replied_to_during_signal_load() {
    MODEL.with(|m| *m.borrow_mut() = Model { notification: true, flood: true, inputs: [Input::Fault, Input::Unanswered, Input::Call(7)].into(), ..Model::new() });
    run(&mut Receiver);
    MODEL.with(|m| {
        let m = m.borrow();
        assert_eq!((m.faults, m.unanswered), (1, 2));
        assert_eq!(m.replies, [vec![0, 7]]);
    });
}

#[test]
fn empty_unbound_poll_keeps_signals_and_a_timer_expiring_while_unbound() {
    MODEL.with(|m| *m.borrow_mut() = Model { notification: true, expiry_on_unbind: true, ..Model::new() });
    run(&mut Receiver);
    MODEL.with(|m| {
        let m = m.borrow();
        assert_eq!(m.signals, 2);
        assert_eq!(m.rebinds, 2);
        assert_eq!(m.idle, 0, "an empty fairness poll is not an idle server turn");
        assert!(m.bound);
    });
}

struct Memd;
impl ipc::Server for Memd {
    const SIGNALS: u64 = host::badges::memd::SIGNALS;
    type Sender = host::memd::Sender;
    fn call(&mut self, from: Self::Sender, _: u64, _: &MessageInfo) -> Option<MessageInfo> {
        assert_eq!(from, host::memd::Sender::Root);
        Some(ipc::reply(&[0]))
    }
}
#[test]
fn a_server_with_only_its_own_timer_still_receives_unbadged_root_calls() {
    MODEL.with(|m| *m.borrow_mut() = Model { inputs: [Input::Unbadged].into(), ..Model::new() });
    run(&mut Memd);
    MODEL.with(|m| assert_eq!(m.borrow().replies, [vec![0]]));
}

#[test]
fn endpoint_preserves_oversized_length_for_the_client_to_reject() {
    use host::trust::call::{Client, Request};
    let endpoint = ipc::Endpoint::of(&host::wiring::TRUSTD_FLAGS, host::wiring::p::Trustd, 0);
    for n in [0, 1, Request::MAX_REPLY_WORDS + 1, NUM_MESSAGE_REGISTERS] {
        MODEL.with(|m| m.borrow_mut().reply_words = vec![0; n]);
        assert_eq!(endpoint.sync(), if n == 1 { Ok(()) } else { Err(host::wire::FAILED) }, "length {n}");
    }
}

#[test]
fn client_rejects_a_length_beyond_its_buffer_even_from_another_transport() {
    struct Oversized;
    impl host::wire::Call for Oversized {
        type Proto = host::trust::call::Proto;
        fn ipc(&self, _: u64, _: &[u64], reply: &mut [u64]) -> usize { reply.fill(0); reply.len() + 1 }
    }
    use host::trust::call::Client;
    assert_eq!(Oversized.sync(), Err(host::wire::FAILED));
}

static FAILURE_HANDLER: failure::FailureHandler = failure::FailureHandler {
    notification_badges: host::badges::vmmgr::SIGNALS,
    notified: failed_signal,
};
fn failed_signal(badge: u64) {
    MODEL.with(|m| {
        let mut m = m.borrow_mut();
        if badge != 0 {
            assert!(!ipc::holds_call());
            m.signals += 1;
            assert!(m.signals < 20, "notifications starved failed-server callers");
        }
        if m.inputs.is_empty() && m.held.is_none() && !m.replies.is_empty() { finish(); }
        m.notification |= m.flood;
    });
    clobber();
}
fn failed_model(mut model: Model) {
    // An empty production poll clears held-call state left by another test.
    MODEL.with(|m| *m.borrow_mut() = Model::new());
    assert!(ipc::Bound::new(cap(host::SLOT_TCB), cap(host::SLOT_NTFN))
        .poll_endpoint(cap(host::SLOT_SERVICE_EP), cap(host::SLOT_REPLY), host::badges::parent::FAULT, || {}).is_none());
    model.notification_badge = host::badges::vmmgr::CTL_KICK;
    MODEL.with(|m| *m.borrow_mut() = model);
    failure::set_failure_handler(&FAILURE_HANDLER);
}
fn run_failed(tcb: u64) {
    let end = std::panic::catch_unwind(|| failure::answer_failed(tcb));
    assert!(end.unwrap_err().is::<End>());
}

#[test]
fn failed_server_transfers_pending_signals_from_bound_unbound_or_keeper_state() {
    for (bound, owner, tcb) in [
        (true, host::SLOT_TCB, host::SLOT_KEEPER),
        (false, host::SLOT_TCB, host::SLOT_KEEPER),
        (true, host::SLOT_KEEPER, host::SLOT_KEEPER),
        (false, host::SLOT_TCB, host::SLOT_TCB),
    ] {
        failed_model(Model { bound, bound_tcb: owner, notification: true, ..Model::new() });
        run_failed(tcb);
        MODEL.with(|m| {
            let m = m.borrow();
            assert!(m.bound);
            assert_eq!(m.bound_tcb, tcb);
            assert_eq!(m.signals, 1, "handoff must preserve the pending kick");
        });
    }
}

#[test]
fn failed_server_answers_calls_and_leaves_faults_stopped_under_continuous_kicks() {
    failed_model(Model {
        notification: true, flood: true,
        inputs: [Input::Fault, Input::Call(42), Input::Call(43)].into(), ..Model::new()
    });
    run_failed(host::SLOT_KEEPER);
    MODEL.with(|m| {
        let m = m.borrow();
        assert_eq!(m.replies, [vec![host::wire::FAILED], vec![host::wire::FAILED]]);
        assert!(m.inputs.is_empty());
        assert_eq!(m.polls, 3);
        assert_eq!(m.bound_tcb, host::SLOT_KEEPER);
    });
}

#[test]
fn failure_after_a_fairness_poll_answers_the_call_already_received() {
    failed_model(Model {
        notification: true, inputs: [Input::Call(42)].into(),
        bind_error: Some(Error::InvalidCapability), ..Model::new()
    });
    MODEL.with(|m| m.borrow_mut().notification_badge = host::badges::root::CHANNEL);
    // Fail in the real live loop after NBRecv, before the notification binds.
    assert!(std::panic::catch_unwind(|| ipc::run(cap(1), Reply, &mut Receiver)).is_err());
    assert!(ipc::holds_call());
    MODEL.with(|m| assert!(!m.borrow().bound));
    run_failed(host::SLOT_KEEPER);
    MODEL.with(|m| {
        let m = m.borrow();
        assert_eq!(m.replies, [vec![host::wire::FAILED]]);
        assert_eq!(m.bound_tcb, host::SLOT_KEEPER);
    });
}

#[test]
fn notification_handoff_does_not_ignore_unrelated_kernel_errors() {
    failed_model(Model { unbind_error: Some(Error::InvalidCapability), ..Model::new() });
    let result = std::panic::catch_unwind(|| failure::answer_failed(host::SLOT_KEEPER));
    let error = result.unwrap_err();
    let message = error.downcast_ref::<String>().map(String::as_str)
        .or_else(|| error.downcast_ref::<&str>().copied()).unwrap();
    assert!(message.contains("failure unbind: InvalidCapability"));
    MODEL.with(|m| {
        let m = m.borrow();
        assert!(m.bound);
        assert_eq!(m.bound_tcb, host::SLOT_TCB);
        assert_eq!(m.rebinds, 0);
    });
}

// SPDX-License-Identifier: GPL-2.0-only
//! Run the production failure loop and control completions with mocked
//! seL4 IPC. Both panic and keeper entry must finish consumed kicks, keep
//! serving new requests, and leave fault IPC unanswered.
extern crate self as l4h_rt;
pub use l4h_host as host;
/// failure.rs answers through l4h_rt::ipc.
pub use sel4::ipc_mock as ipc;

use l4h_abi as abi;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::marker::PhantomData;
use std::sync::Mutex;

#[path = "../host/l4h-rt/src/failure.rs"]
mod failure;
/// A second copy, whose handler is never set: memd's.
#[path = "../host/l4h-rt/src/failure.rs"]
#[allow(dead_code)]
mod failure_plain;
pub use failure::FailureHandler;
#[path = "../host/l4h-vmmgr/src/ctl_failure.rs"]
mod ctl_failure;

const MAX_GUESTS: usize = 2;


const EVENT: usize = 71;
const DONE_CAP: u64 = 300;
static LOCK: Mutex<()> = Mutex::new(());

enum Input { Call, Fault, Notify(u64), Request(u32), End }
#[derive(Debug)]
struct End;
#[derive(Default)]
struct Model {
    current_tcb: u64,
    bound_tcb: u64,
    bindings: Vec<u64>,
    incoming: VecDeque<Input>,
    caller: Option<bool>, // true: a fault, which must remain unanswered
    replies: Vec<[u64; 8]>,
    wakes: Vec<(u32, u32, i64)>,
    page: usize,
    events: usize,
    ipc: sel4::IpcBuffer,
}
thread_local! { static MODEL: RefCell<Model> = RefCell::new(Model::default()); }

pub fn cap<T>(bits: u64) -> sel4::Cap<T> { sel4::Cap(bits, PhantomData) }
pub mod sel4 {
    use super::*;
    pub mod cap_type {
        #[derive(Clone, Copy)] pub struct Tcb;
        #[derive(Clone, Copy)] pub struct Endpoint;
        #[derive(Clone, Copy)] pub struct Reply;
        #[derive(Clone, Copy)] pub struct Notification;
    }
    #[derive(Clone, Copy)]
    pub struct Cap<T>(pub u64, pub PhantomData<T>);
    pub struct MessageInfo(usize);
    impl MessageInfo {
        pub fn new(label: u64, caps: usize, extra: usize, len: usize) -> Self {
            assert_eq!((label, caps, extra), (0, 0, 0));
            Self(len)
        }
    }
    #[derive(Default)]
    pub struct IpcBuffer([u64; 8]);
    impl IpcBuffer { pub fn msg_regs_mut(&mut self) -> &mut [u64] { &mut self.0 } }
    pub fn with_ipc_buffer_mut<R>(f: impl FnOnce(&mut IpcBuffer) -> R) -> R {
        MODEL.with(|m| f(&mut m.borrow_mut().ipc))
    }
    /// l4h_ipc::reply, on the mock IPC buffer.
    pub mod ipc_mock {
        pub fn reply(words: &[u64]) -> super::MessageInfo {
            super::with_ipc_buffer_mut(|b| b.msg_regs_mut()[..words.len()].copy_from_slice(words));
            super::MessageInfo::new(0, 0, 0, words.len())
        }
    }
    impl Cap<cap_type::Tcb> {
        pub fn tcb_unbind_notification(self) -> Result<(), ()> {
            MODEL.with(|m| {
                let mut m = m.borrow_mut();
                assert_eq!(m.bound_tcb, self.0);
                m.bound_tcb = 0;
                m.bindings.push(0);
            });
            Ok(())
        }
        pub fn tcb_bind_notification(self, ntfn: Cap<cap_type::Notification>) -> Result<(), ()> {
            assert_eq!(ntfn.0, host::SLOT_NTFN);
            MODEL.with(|m| {
                let mut m = m.borrow_mut();
                assert_eq!(m.bound_tcb, 0);
                m.bound_tcb = self.0;
                m.bindings.push(self.0);
            });
            Ok(())
        }
    }
    impl Cap<cap_type::Notification> {
        pub fn signal(self) {
            assert_eq!(self.0, DONE_CAP);
            MODEL.with(|m| unsafe {
                let mut m = m.borrow_mut();
                let events = &*(m.events as *const abi::EventPage);
                assert_ne!(events.pending[EVENT / 64] & (1 << (EVENT % 64)), 0);
                let sync = &*((m.page + abi::CTL_SYNC_OFF) as *const abi::CtlSync);
                let resp = &*((m.page + abi::CTL_RESP_OFF) as *const abi::CtlResp);
                assert_eq!(sync.seq, sync.done, "completion must precede the wakeup");
                if resp.status == -5 {
                    assert!(resp.vals.iter().all(|&v| v == 0));
                    assert!(resp.data.iter().all(|&v| v == 0));
                }
                m.wakes.push((sync.seq, sync.done, resp.status));
            });
        }
    }
    impl Cap<cap_type::Endpoint> {
        pub fn reply_recv(self, info: MessageInfo, reply: Cap<cap_type::Reply>) -> (MessageInfo, u64) {
            assert_eq!(info.0, 1, "a failed component answers wire::FAILED alone");
            MODEL.with(|m| {
                let mut m = m.borrow_mut();
                if let Some(fault) = m.caller.take() {
                    assert!(!fault, "a notification must not cause a reply to a fault");
                    let regs = m.ipc.0;
                    m.replies.push(regs);
                }
            });
            self.recv(reply)
        }
        pub fn recv(self, reply: Cap<cap_type::Reply>) -> (MessageInfo, u64) {
            assert_eq!((self.0, reply.0), (host::SLOT_SERVICE_EP, host::SLOT_REPLY));
            MODEL.with(|m| {
                let mut m = m.borrow_mut();
                let badge = match m.incoming.pop_front().expect("scripted input") {
                    Input::Call => { m.caller = Some(false); 0x500 }
                    Input::Fault => { m.caller = Some(true); host::badges::parent::FAULT | 1 }
                    Input::Notify(badge) => {
                        assert_eq!(m.bound_tcb, m.current_tcb);
                        badge
                    }
                    Input::Request(seq) => {
                        assert_eq!(m.bound_tcb, m.current_tcb);
                        unsafe { (*((m.page + abi::CTL_SYNC_OFF) as *mut abi::CtlSync)).seq = seq };
                        host::badges::vmmgr::CTL_KICK
                    }
                    Input::End => std::panic::panic_any(End),
                };
                (MessageInfo(0), badge)
            })
        }
    }
}

struct Fixture {
    page: Box<[u64; 512]>,
    events: Box<abi::EventPage>,
}
impl Fixture {
    fn new(seq: u32, done: u32) -> Self {
        let mut f = Self { page: Box::new([0; 512]), events: Box::new(unsafe { core::mem::zeroed() }) };
        let page = f.page.as_mut_ptr().cast::<u8>();
        unsafe {
            page.add(abi::CTL_SYNC_OFF).cast::<abi::CtlSync>().write(abi::CtlSync { seq, done });
            page.add(abi::CTL_RESP_OFF).cast::<abi::CtlResp>().write(abi::CtlResp {
                status: 0, vals: [123; 6], data: [0xa5; abi::CTL_DATA_MAX],
            });
            ctl_failure::register(0, page, &mut *f.events, EVENT as u32, DONE_CAP);
        }
        MODEL.with(|m| *m.borrow_mut() = Model { page: page as usize, events: &mut *f.events as *mut _ as usize, ..Model::default() });
        f
    }
}
impl Drop for Fixture { fn drop(&mut self) { ctl_failure::remove(0); } }

#[test]
fn panic_and_keeper_finish_outstanding_and_future_requests_without_replying_to_faults() {
    let _lock = LOCK.lock().unwrap();
    failure::set_failure_handler(&ctl_failure::HANDLER);
    for tcb in [host::SLOT_TCB, host::SLOT_KEEPER] {
        let _f = Fixture::new(7, 6); // kick already consumed, or caller killed
        MODEL.with(|m| {
            let mut m = m.borrow_mut();
            m.current_tcb = tcb;
            m.bound_tcb = host::SLOT_TCB;
            m.caller = Some(false); // preserve synchronous failure replies
            m.incoming = [Input::Call, Input::Fault, Input::Notify(host::badges::vmmgr::TIMER),
                Input::Notify(host::badges::vmmgr::MAILBOX), Input::Request(8),
                Input::Request(9), Input::Call, Input::End].into();
        });
        let end = std::panic::catch_unwind(|| failure::answer_failed(tcb)).unwrap_err();
        assert!(end.is::<End>());
        MODEL.with(|m| {
            let m = m.borrow();
            assert_eq!(m.wakes, [(7, 7, -5), (8, 8, -5), (9, 9, -5)]);
            assert_eq!(m.replies, [[u64::MAX, 0, 0, 0, 0, 0, 0, 0]; 3]);
            assert_eq!(m.bindings, if tcb == host::SLOT_KEEPER { vec![0, tcb] } else { vec![] });
        });
    }
}

#[test]
fn keeper_without_handler_answers_calls_and_leaves_faults() {
    let _lock = LOCK.lock().unwrap();
    for tcb in [host::SLOT_TCB, host::SLOT_KEEPER] {
        MODEL.with(|m| {
            *m.borrow_mut() = Model {
                current_tcb: tcb,
                bound_tcb: host::SLOT_TCB,
                incoming: [Input::Call, Input::Fault, Input::Call, Input::End].into(),
                ..Model::default()
            };
        });
        let end = std::panic::catch_unwind(|| failure_plain::answer_failed(tcb)).unwrap_err();
        assert!(end.is::<End>());
        MODEL.with(|m| {
            let m = m.borrow();
            // The notification stays with the main thread: nothing on it is
            // the keeper's.
            assert_eq!(m.replies, [[u64::MAX, 0, 0, 0, 0, 0, 0, 0]; 2]);
            assert!(m.bindings.is_empty());
        });
    }
}

#[test]
fn completed_request_is_woken_and_removed_guest_is_not_touched() {
    let _lock = LOCK.lock().unwrap();
    let mut f = Fixture::new(u32::MAX, u32::MAX);
    // Failure after publishing done and the event bit, before Signal.
    f.events.pending[EVENT / 64] = 1 << (EVENT % 64);
    (ctl_failure::HANDLER.notified)(0);
    MODEL.with(|m| assert_eq!(m.borrow().wakes, [(u32::MAX, u32::MAX, 0)]));
    // The next request wraps the sequence; it still receives EIO.
    unsafe { (*((f.page.as_mut_ptr() as *mut u8).add(abi::CTL_SYNC_OFF).cast::<abi::CtlSync>())).seq = 0 };
    (ctl_failure::HANDLER.notified)(host::badges::vmmgr::CTL_KICK);
    MODEL.with(|m| assert_eq!(m.borrow().wakes.last(), Some(&(0, 0, -5))));
    drop(f);
    (ctl_failure::HANDLER.notified)(host::badges::vmmgr::CTL_KICK);
    MODEL.with(|m| assert_eq!(m.borrow().wakes.len(), 2));
    let _replacement = Fixture::new(1, 0);
    (ctl_failure::HANDLER.notified)(host::badges::vmmgr::CTL_KICK);
    MODEL.with(|m| assert_eq!(m.borrow().wakes, [(1, 1, -5)]));
}

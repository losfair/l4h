//! Failure replies for synchronous callers and optional shared-page devices.

use core::sync::atomic::{AtomicPtr, Ordering};

use crate::{cap, host, sel4};

/// A component's asynchronous failure service. It runs after the main
/// thread has stopped, on either that thread (panic) or its keeper (fault).
/// It must not borrow the main thread's mutable state or allocate resources.
pub struct FailureHandler {
    /// All badges on the component's bound notification, including those
    /// the failure service ignores. They must never be treated as calls.
    pub notification_badges: u64,
    /// Called once with zero to finish requests whose kick was already
    /// consumed, then for each notification received after failure.
    pub notified: fn(u64),
}

static HANDLER: AtomicPtr<FailureHandler> = AtomicPtr::new(core::ptr::null_mut());

/// Install before starting any clients of the asynchronous devices.
pub fn set_failure_handler(handler: &'static FailureHandler) {
    HANDLER.store(core::ptr::from_ref(handler).cast_mut(), Ordering::Release);
}

/// Answer the callers of a failed component: u64::MAX and zeros to every
/// call, the one the main thread's reply object holds (if any) first, and
/// to every request in its mailbox (host::mailbox), if it has one.
/// Faults sent to it (vmmgr's guests' and VMMs') stay unanswered.
pub(crate) fn answer_failed(tcb: u64, mailbox: bool) -> ! {
    let handler = unsafe { HANDLER.load(Ordering::Acquire).as_ref() };
    if (handler.is_some() || mailbox) && tcb != host::SLOT_TCB {
        // The faulted main thread still owns the notification, which
        // carries the handler's signals and root's BADGE_CALL. Pending
        // signals survive the transfer to the keeper.
        cap::<sel4::cap_type::Tcb>(host::SLOT_TCB).tcb_unbind_notification().expect("failure unbind");
        cap::<sel4::cap_type::Tcb>(tcb)
            .tcb_bind_notification(cap(host::SLOT_NTFN)).expect("failure bind");
    }
    if let Some(handler) = handler {
        (handler.notified)(0);
    }
    if mailbox {
        crate::mailbox::fail();
    }
    let ep = cap::<sel4::cap_type::Endpoint>(host::SLOT_SERVICE_EP);
    let reply = cap::<sel4::cap_type::Reply>(host::SLOT_REPLY);
    let mut answer = true;
    loop {
        let (_, badge) = if answer {
            sel4::with_ipc_buffer_mut(|b| {
                let m = b.msg_regs_mut();
                m[0] = u64::MAX;
                m[1..8].fill(0);
            });
            ep.reply_recv(sel4::MessageInfo::new(0, 0, 0, 8), reply)
        } else {
            ep.recv(reply)
        };
        if mailbox && badge & host::mailbox::BADGE_CALL != 0 {
            crate::mailbox::fail();
            answer = false;
        } else if let Some(handler) = handler.filter(|h| badge & h.notification_badges != 0) {
            (handler.notified)(badge);
            answer = false;
        } else {
            answer = badge & host::BADGE_FAULT == 0;
        }
    }
}

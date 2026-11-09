//! seL4 IPC for the protocols l4h-host declares (l4h_host::wire): the one
//! way a host component calls an endpoint, and the one way it serves one.
//! Both copy a call's words between the message registers and arrays
//! once, at the edge: arguments leave the registers before a handler runs
//! and its reply goes there after it returns, so no invocation a handler
//! makes can overwrite either.  The drivers' mailboxes, which carry the
//! same protocols without IPC, are l4h_rt::mailbox (the driver's end) and
//! l4h-root's mailbox.rs (root's).  See DESIGN.md §10, "Wiring
//! declarations".

#![no_std]

use l4h_host::wire::{Call, EINVAL, MAX_MRS};

/// An endpoint capability, as a protocol's client calls it.
#[derive(Clone, Copy)]
pub struct Endpoint(pub sel4::cap::Endpoint);

impl Call for Endpoint {
    fn ipc(&self, label: u64, args: &[u64], reply: &mut [u64]) -> usize {
        sel4::with_ipc_buffer_mut(|b| b.msg_regs_mut()[..args.len()].copy_from_slice(args));
        let info = self.0.call(sel4::MessageInfo::new(label, 0, 0, args.len()));
        let n = info.length().min(reply.len());
        sel4::with_ipc_buffer(|b| reply[..n].copy_from_slice(&b.msg_regs()[..n]));
        n
    }
}

const _: () = assert!(MAX_MRS == sel4::NUM_MESSAGE_REGISTERS);

/// Serve the call `info` describes: `f(label, args, reply)` writes the
/// reply's words (a protocol's `serve`) and returns their count, or None
/// to leave the caller unanswered.  The arguments are taken out of the
/// message registers first, so do it before any invocation; the reply's
/// MessageInfo, its words in the message registers.
pub fn serve(info: &sel4::MessageInfo, f: impl FnOnce(u64, &[u64], &mut [u64]) -> Option<usize>) -> Option<sel4::MessageInfo> {
    let mut args = [0; MAX_MRS];
    let len = info.length().min(MAX_MRS);
    sel4::with_ipc_buffer(|b| args[..len].copy_from_slice(&b.msg_regs()[..len]));
    let mut out = [0; MAX_MRS];
    let n = f(info.label(), &args[..len], &mut out)?;
    Some(reply(&out[..n]))
}

/// Run `f`, whose invocations overwrite the message registers, without
/// losing a message received but not yet served there (a call, or a
/// fault, which seL4 delivers in the registers too).
pub fn preserving<R>(f: impl FnOnce() -> R) -> R {
    let regs: [u64; MAX_MRS] = sel4::with_ipc_buffer(|b| b.msg_regs()[..MAX_MRS].try_into().unwrap());
    let r = f();
    sel4::with_ipc_buffer_mut(|b| b.msg_regs_mut()[..MAX_MRS].copy_from_slice(&regs));
    r
}

/// The reply to a caller the server does not know: EINVAL.
pub fn refuse() -> sel4::MessageInfo {
    reply(&[EINVAL])
}

/// Put a reply's words in the message registers: its MessageInfo.
pub fn reply(words: &[u64]) -> sel4::MessageInfo {
    sel4::with_ipc_buffer_mut(|b| b.msg_regs_mut()[..words.len()].copy_from_slice(words));
    sel4::MessageInfo::new(0, 0, 0, words.len())
}

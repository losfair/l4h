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

use l4h_host::wire::{Badged, Call, EINVAL, MAX_MRS};

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

/// What a server does after a message (Server::next).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Next {
    /// Wait for the next message.
    Wait,
    /// Take the next message if one is queued; if none is, an idle turn
    /// (`signal(0)`): a server that polls has no sender badged 0.
    Poll,
    /// Another turn on `signal(badge)` at once, receiving nothing.
    Again(u64),
}

/// A server's thread: what arrives on its endpoint, and its bound
/// notification's signals.  `run` receives, tells the kinds apart by the
/// badge and answers, the same way for every server.
pub trait Server {
    /// The bound notification's bits (its badge space's SIGNALS): a
    /// message with any of them is a signal.
    const SIGNALS: u64;
    /// Its badge space's FAULT bit, for a server faults go to.
    const FAULT: u64 = 0;
    /// Who may call it (wire::Badged; Infallible for an endpoint nobody
    /// calls).
    type Sender: Badged;

    /// After each receive, before the message is looked at, which it
    /// keeps.
    fn received(&mut self) {}
    /// A signal: `badge` is some of SIGNALS (0 for an idle turn).
    fn signal(&mut self, badge: u64) {
        let _ = badge;
    }
    /// A fault, which is never answered: the thread stays stopped.
    fn fault(&mut self, badge: u64, info: &sel4::MessageInfo) {
        let _ = (badge, info);
    }
    /// A call from `from`: its reply (`serve`), or None to leave the
    /// caller blocked for good.
    fn call(&mut self, from: Self::Sender, badge: u64, info: &sel4::MessageInfo) -> Option<sel4::MessageInfo>;
    /// A call from a badge no sender is, which is refused (EINVAL).
    fn unknown(&mut self, badge: u64, info: &sel4::MessageInfo) {
        let _ = (badge, info);
    }
    /// After each message, before its reply (which it keeps): what next.
    fn next(&mut self) -> Next {
        Next::Wait
    }
}

/// A server's reply object.
pub trait ReplyObject {
    fn cap(&self) -> sel4::cap::Reply;
    /// It is still bound to a caller left unanswered (a fault, or a
    /// call answered None).  A plain reply capability does nothing: the
    /// next receive cancels that caller's IPC, which leaves it inactive.
    fn unanswered(&mut self) {}
}

impl ReplyObject for sel4::cap::Reply {
    fn cap(&self) -> sel4::cap::Reply {
        *self
    }
}

/// Serve `ep` with `s`, for good.
pub fn run<S: Server>(ep: sel4::cap::Endpoint, mut reply: impl ReplyObject, s: &mut S) -> ! {
    let (mut info, mut badge) = ep.recv(reply.cap());
    let mut received = true;
    let mut polled = false;
    loop {
        if received {
            preserving(|| s.received());
        }
        let mut answer = None;
        if !received || (polled && badge == 0) || badge & S::SIGNALS != 0 {
            s.signal(badge);
        } else if badge & S::FAULT != 0 {
            s.fault(badge, &info);
            reply.unanswered();
        } else {
            answer = match S::Sender::of_badge(badge) {
                Some(from) => s.call(from, badge, &info),
                None => {
                    preserving(|| s.unknown(badge, &info));
                    Some(refuse())
                }
            };
            if answer.is_none() {
                reply.unanswered();
            }
        }
        let next = if answer.is_some() { preserving(|| s.next()) } else { s.next() };
        (received, polled) = (!matches!(next, Next::Again(_)), next == Next::Poll);
        (info, badge) = match (next, answer) {
            (Next::Wait, Some(a)) => ep.reply_recv(a, reply.cap()),
            (Next::Wait, None) => ep.recv(reply.cap()),
            (next, a) => {
                if let Some(a) = a {
                    reply.cap().send(a);
                }
                match next {
                    Next::Again(b) => (sel4::MessageInfo::new(0, 0, 0, 0), b),
                    _ => ep.nb_recv(reply.cap()),
                }
            }
        };
    }
}

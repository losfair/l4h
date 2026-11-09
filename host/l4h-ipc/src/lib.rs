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
// The one crate that calls, serves and receives on endpoints: host/clippy.toml
// refuses those seL4 calls everywhere else.
#![allow(clippy::disallowed_methods)]

use core::marker::PhantomData;
use core::mem::MaybeUninit;

use l4h_host::wire::{Badged, Call, Cap, EINVAL, MAX_MRS, Protocol};
use l4h_host::wiring::{At, E, p};

/// An endpoint that serves protocol P, as P's client calls it: made from
/// a call edge whose protocol is P (wiring::E), so that no other
/// protocol's calls can be made on it.
pub struct Endpoint<P>(sel4::cap::Endpoint, PhantomData<P>);

impl<P> Clone for Endpoint<P> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<P> Copy for Endpoint<P> {}

impl<P: Protocol> Endpoint<P> {
    /// The one `e` gives its holder, `_me`, in the edge's slot n.
    pub const fn of<H: p::IsParty, T, O>(e: &E<H, T, O, P>, _me: H, n: usize) -> Self {
        Endpoint(sel4::cap::Endpoint::from_bits(e.0.slot(n)), PhantomData)
    }

    /// The one `e` gives its holder in a slot of the holder's choosing
    /// (At::Chosen), `ep`.
    pub fn chosen<H: p::IsParty, T, O>(e: &E<H, T, O, P>, _me: H, ep: sel4::cap::Endpoint) -> Self {
        assert!(matches!(e.at, At::Chosen), "{} is in a slot of its own", e.name);
        Endpoint(ep, PhantomData)
    }

    pub fn cap(&self) -> sel4::cap::Endpoint {
        self.0
    }
}

impl<P: Protocol> Call for Endpoint<P> {
    type Proto = P;

    fn ipc(&self, label: u64, args: &[u64], reply: &mut [u64]) -> usize {
        sel4::with_ipc_buffer_mut(|b| b.msg_regs_mut()[..args.len()].copy_from_slice(args));
        let info = self.0.call(sel4::MessageInfo::new(label, 0, 0, args.len()));
        let n = info.length().min(reply.len());
        sel4::with_ipc_buffer(|b| reply[..n].copy_from_slice(&b.msg_regs()[..n]));
        n
    }
}

const _: () = assert!(MAX_MRS == sel4::NUM_MESSAGE_REGISTERS);

/// Run `f` on a copy of the first `n` message registers.  Only those are
/// read: a message is a few words, the buffer 120.
fn with_words<R>(n: usize, f: impl FnOnce(&[u64]) -> R) -> R {
    let n = n.min(MAX_MRS);
    let mut words = [const { MaybeUninit::<u64>::uninit() }; MAX_MRS];
    sel4::with_ipc_buffer(|b| {
        for (w, r) in words[..n].iter_mut().zip(&b.msg_regs()[..n]) {
            w.write(*r);
        }
    });
    // The first n are written.
    f(unsafe { &*(&words[..n] as *const [MaybeUninit<u64>] as *const [u64]) })
}

/// Serve the call `info` describes, of protocol P: `f(label, args, reply)`
/// writes the reply's words (P's `serve`) and returns their count, or None
/// to leave the caller unanswered.  The arguments are taken out of the
/// message registers first, so do it before any invocation; the reply's
/// MessageInfo, its words in the message registers.
pub fn serve<P: Protocol>(info: &sel4::MessageInfo, f: impl FnOnce(u64, &[u64], &mut [u64]) -> Option<usize>) -> Option<sel4::MessageInfo> {
    // Words past the longest call's arguments are ignored.
    with_words(info.length().min(P::MAX_WORDS), |args| {
        let mut out = [const { MaybeUninit::<u64>::uninit() }; MAX_MRS];
        let out = &mut out[..P::MAX_REPLY_WORDS];
        out.iter_mut().for_each(|w| {
            w.write(0);
        });
        // All of `out` is written.
        let out = unsafe { &mut *(out as *mut [MaybeUninit<u64>] as *mut [u64]) };
        let n = f(info.label(), args, out)?;
        Some(reply(&out[..n]))
    })
}

/// Run `f`, whose invocations overwrite the message registers, without
/// losing the `n` words of a message there: one received but not yet
/// served (a call, or a fault, which seL4 delivers in the registers too),
/// or a reply not yet sent.
fn keeping<R>(n: usize, f: impl FnOnce() -> R) -> R {
    with_words(n, |words| {
        let r = f();
        sel4::with_ipc_buffer_mut(|b| b.msg_regs_mut()[..words.len()].copy_from_slice(words));
        r
    })
}

/// `keeping`, for a message of unknown length: all the registers.
pub fn preserving<R>(f: impl FnOnce() -> R) -> R {
    keeping(MAX_MRS, f)
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
    /// A signal: `badge` is some of SIGNALS (0 for an idle turn, after
    /// Next::Poll found nothing).
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
    let mut polled = false;
    loop {
        keeping(info.length(), || s.received());
        let mut answer = None;
        if (polled && badge == 0) || badge & S::SIGNALS != 0 {
            s.signal(badge);
        } else if badge & S::FAULT != 0 {
            s.fault(badge, &info);
            reply.unanswered();
        } else {
            answer = match S::Sender::of_badge(badge) {
                Some(from) => s.call(from, badge, &info),
                None => {
                    s.unknown(badge, &info);
                    Some(refuse())
                }
            };
            if answer.is_none() {
                reply.unanswered();
            }
        }
        let next = match &answer {
            Some(a) => keeping(a.length(), || s.next()),
            None => s.next(),
        };
        polled = next == Next::Poll;
        (info, badge) = match (next, answer) {
            (Next::Wait, Some(a)) => ep.reply_recv(a, reply.cap()),
            (Next::Wait, None) => ep.recv(reply.cap()),
            (Next::Poll, a) => {
                if let Some(a) = a {
                    reply.cap().send(a);
                }
                ep.nb_recv(reply.cap())
            }
        };
    }
}

/// A capability type, as the kind protocols declare that a call passes
/// (wire::Cap): `Caps::passed_in` and `passed_out` take it, so that the
/// capability put in an exchange slot, or taken from it, is of the kind
/// the call declares there.
pub trait Kind: sel4::CapType {
    const KIND: Cap;
}

impl Kind for sel4::cap_type::Untyped {
    const KIND: Cap = Cap::Untyped;
}
impl Kind for sel4::cap_type::CNode {
    const KIND: Cap = Cap::CNode;
}
impl Kind for sel4::cap_type::Granule {
    const KIND: Cap = Cap::Granule;
}
impl Kind for sel4::cap_type::Notification {
    const KIND: Cap = Cap::Notification;
}

/// The kind of `cap`.
pub const fn kind_of<T: Kind>(_: &sel4::Cap<T>) -> Cap {
    T::KIND
}

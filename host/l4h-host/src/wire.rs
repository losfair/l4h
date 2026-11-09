//! Declarations of how host components talk to each other, as data the
//! compiler checks (DESIGN.md §10, "Wiring declarations"):
//!
//! - `badge_space!`: the badge bits one receiver (an endpoint and the
//!   notification bound to its thread) can see.  Every range is declared
//!   once, and the space fails to compile if two overlap.  `SIGNALS` is
//!   the union of its notification bits, for the serve loop's dispatch.
//! - `protocol!`: the calls on one endpoint: label, typed arguments, typed
//!   reply, and who may make each.  It generates the `Request` enum and its
//!   decoder, a `Server` trait whose methods a server implements, a `serve`
//!   function that dispatches to them, and a `Client` trait with a method
//!   per call for anything that can `Call`.  Arguments are copied out of
//!   the message registers before a handler runs and the reply is written
//!   after it returns, so a handler's own invocations cannot clobber
//!   either.  The reply's first word is 0 or an errno.
//!
//! Like the rest of l4h-host this makes no seL4 call: a component supplies
//! `Call` over its endpoint capability.

use crate::fixed::ArrayVec;

/// Message registers of an IPC buffer (seL4_MsgMaxLength).
pub const MAX_MRS: usize = 120;

pub use crate::errno::{EINVAL, Errno};
/// The reply's first word when the server failed: its keeper answers
/// everything with it (l4h_rt::abort_trap), and a reply too short for its
/// type is taken as one.
pub const FAILED: Errno = u64::MAX;
/// What a `Server` method returns to leave its caller unanswered (a
/// stopped or destroyed caller): `serve` then writes no reply.  Never on
/// the wire.
pub const NO_REPLY: Errno = u64::MAX - 2;

/// A call, as a client posts it: what `protocol!`'s Request implements.
pub trait Message {
    /// Words of the longest call's arguments.
    const MAX_WORDS: usize;
    fn label(&self) -> u64;
    /// Write the arguments into `out` (at least MAX_WORDS long): their
    /// length.
    fn encode(&self, out: &mut [u64]) -> usize;
}

/// A range of badge bits, [lo, hi).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bits {
    pub lo: u32,
    pub hi: u32,
}

impl Bits {
    pub const fn new(lo: u32, hi: u32) -> Self {
        assert!(lo < hi && hi <= 64, "badge bits out of range");
        Bits { lo, hi }
    }

    pub const fn bit(n: u32) -> Self {
        Self::new(n, n + 1)
    }

    pub const fn width(self) -> u32 {
        self.hi - self.lo
    }

    pub const fn mask(self) -> u64 {
        (u64::MAX >> (64 - self.width())) << self.lo
    }

    /// The field's value in `badge`.
    pub const fn get(self, badge: u64) -> u64 {
        (badge & self.mask()) >> self.lo
    }

    /// `v` in the field.  Panics if it does not fit.
    pub const fn put(self, v: u64) -> u64 {
        assert!(v <= self.mask() >> self.lo, "badge field overflow");
        v << self.lo
    }

    /// Bit `n` of a range of independent signals.
    pub const fn nth(self, n: usize) -> u64 {
        assert!(n < self.width() as usize, "badge bit out of range");
        1 << (self.lo + n as u32)
    }
}

/// Whether no two of the ranges, of all the groups, share a bit.
pub const fn disjoint(groups: &[&[Bits]]) -> bool {
    let mut seen = 0u64;
    let mut g = 0;
    while g < groups.len() {
        let mut i = 0;
        while i < groups[g].len() {
            let m = groups[g][i].mask();
            if seen & m != 0 {
                return false;
            }
            seen |= m;
            i += 1;
        }
        g += 1;
    }
    true
}

/// Whether the labels are all different.
pub const fn distinct(labels: &[u64]) -> bool {
    let mut i = 0;
    while i < labels.len() {
        let mut j = i + 1;
        while j < labels.len() {
            if labels[i] == labels[j] {
                return false;
            }
            j += 1;
        }
        i += 1;
    }
    true
}

pub const fn max(v: &[usize]) -> usize {
    let mut m = 0;
    let mut i = 0;
    while i < v.len() {
        if v[i] > m {
            m = v[i];
        }
        i += 1;
    }
    m
}

/// A value carried in message registers.
pub trait Wire: Sized {
    /// The most words it takes.
    const MAX_WORDS: usize;
    /// Write it at the start of `out` (at least MAX_WORDS long): the
    /// words used.
    fn put(&self, out: &mut [u64]) -> usize;
    /// Read it from the start of `words`: it and the words used, or None
    /// if `words` is too short or holds no valid value.
    fn get(words: &[u64]) -> Option<(Self, usize)>;
}

impl Wire for () {
    const MAX_WORDS: usize = 0;
    fn put(&self, _: &mut [u64]) -> usize {
        0
    }
    fn get(_: &[u64]) -> Option<(Self, usize)> {
        Some(((), 0))
    }
}

impl Wire for u64 {
    const MAX_WORDS: usize = 1;
    fn put(&self, out: &mut [u64]) -> usize {
        out[0] = *self;
        1
    }
    fn get(words: &[u64]) -> Option<(Self, usize)> {
        words.first().map(|&w| (w, 1))
    }
}

/// Narrower integers: a word that does not fit is invalid, not truncated.
macro_rules! wire_int {
    ($($t:ty),*) => {$(
        impl Wire for $t {
            const MAX_WORDS: usize = 1;
            fn put(&self, out: &mut [u64]) -> usize {
                out[0] = *self as u64;
                1
            }
            fn get(words: &[u64]) -> Option<(Self, usize)> {
                let w = *words.first()?;
                <$t>::try_from(w).ok().map(|v| (v, 1))
            }
        }
    )*};
}
wire_int!(usize, u32, u16, u8);

impl Wire for bool {
    const MAX_WORDS: usize = 1;
    fn put(&self, out: &mut [u64]) -> usize {
        out[0] = *self as u64;
        1
    }
    fn get(words: &[u64]) -> Option<(Self, usize)> {
        match *words.first()? {
            0 => Some((false, 1)),
            1 => Some((true, 1)),
            _ => None,
        }
    }
}

impl<const N: usize> Wire for [u64; N] {
    const MAX_WORDS: usize = N;
    fn put(&self, out: &mut [u64]) -> usize {
        out[..N].copy_from_slice(self);
        N
    }
    fn get(words: &[u64]) -> Option<(Self, usize)> {
        Some((words.get(..N)?.try_into().ok()?, N))
    }
}

impl<A: Wire, B: Wire> Wire for (A, B) {
    const MAX_WORDS: usize = A::MAX_WORDS + B::MAX_WORDS;
    fn put(&self, out: &mut [u64]) -> usize {
        let n = self.0.put(out);
        n + self.1.put(&mut out[n..])
    }
    fn get(words: &[u64]) -> Option<(Self, usize)> {
        let (a, n) = A::get(words)?;
        let (b, m) = B::get(&words[n..])?;
        Some(((a, b), n + m))
    }
}

/// A list of at most N: its length, then its items.
impl<T: Wire, const N: usize> Wire for ArrayVec<T, N> {
    const MAX_WORDS: usize = 1 + N * T::MAX_WORDS;
    fn put(&self, out: &mut [u64]) -> usize {
        out[0] = self.len() as u64;
        let mut at = 1;
        for v in self.iter() {
            at += v.put(&mut out[at..]);
        }
        at
    }
    fn get(words: &[u64]) -> Option<(Self, usize)> {
        let (len, mut at) = usize::get(words)?;
        if len > N {
            return None;
        }
        let mut v = ArrayVec::new();
        for _ in 0..len {
            let (x, n) = T::get(&words[at..])?;
            at += n;
            v.must_push(x);
        }
        Some((v, at))
    }
}

/// At most N items, without a length: the rest of the message.  Only a
/// message's last field.
#[derive(Clone, Debug, Default)]
pub struct Tail<T, const N: usize>(pub ArrayVec<T, N>);

impl<T: PartialEq, const N: usize> PartialEq for Tail<T, N> {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_slice() == other.0.as_slice()
    }
}
impl<T: Eq, const N: usize> Eq for Tail<T, N> {}

impl<T: Wire, const N: usize> Wire for Tail<T, N> {
    const MAX_WORDS: usize = N * T::MAX_WORDS;
    fn put(&self, out: &mut [u64]) -> usize {
        let mut at = 0;
        for v in self.0.iter() {
            at += v.put(&mut out[at..]);
        }
        at
    }
    fn get(words: &[u64]) -> Option<(Self, usize)> {
        let mut v = ArrayVec::new();
        let mut at = 0;
        while at < words.len() {
            let (x, n) = T::get(&words[at..])?;
            if n == 0 {
                return None;
            }
            at += n;
            v.push(x).ok()?;
        }
        Some((Tail(v), at))
    }
}

/// A struct carried field by field, in order.
#[macro_export]
macro_rules! wire_struct {
    (
        $(#[$m:meta])*
        $vis:vis struct $name:ident {
            $( $(#[$fm:meta])* $fvis:vis $field:ident : $fty:ty ),* $(,)?
        }
    ) => {
        $(#[$m])*
        $vis struct $name {
            $( $(#[$fm])* $fvis $field: $fty ),*
        }

        impl $crate::wire::Wire for $name {
            const MAX_WORDS: usize = 0 $(+ <$fty as $crate::wire::Wire>::MAX_WORDS)*;
            #[allow(unused_mut)]
            fn put(&self, out: &mut [u64]) -> usize {
                let mut at = 0;
                $( at += $crate::wire::Wire::put(&self.$field, &mut out[at..]); )*
                at
            }
            #[allow(unused_mut)]
            fn get(words: &[u64]) -> Option<(Self, usize)> {
                let mut at = 0;
                $(
                    let ($field, n) = <$fty as $crate::wire::Wire>::get(&words[at..])?;
                    at += n;
                )*
                Some(($name { $($field),* }, at))
            }
        }
    };
}

/// An endpoint a client calls.
pub trait Call {
    /// Call with `label` and `args` in message registers 0..; the reply's
    /// message registers go into `reply`.  Returns the reply's length.
    fn ipc(&self, label: u64, args: &[u64], reply: &mut [u64]) -> usize;
}

/// The reply of a call, as `protocol!`'s clients see it: its value, or
/// the errno the server gave (FAILED if it failed).
pub fn reply<R: Wire>(words: &[u64]) -> Result<R, Errno> {
    match words.first() {
        None => Err(FAILED),
        Some(0) => R::get(&words[1..]).map(|(v, _)| v).ok_or(FAILED),
        Some(&e) => Err(e),
    }
}

/// A client's result, with a failed server (FAILED) taken as EIO.
pub fn eio_if_failed<T>(r: Result<T, Errno>) -> Result<T, Errno> {
    r.map_err(|e| if e == FAILED { crate::errno::EIO } else { e })
}

/// Declare the badge bits of a receiver.
///
/// ```ignore
/// badge_space! {
///     pub mod recv: super::parent {  // a space whose ranges this one shares
///         field ID: 0..16;         // a value (Bits: ID.get(b), ID.put(v))
///         flag VMMGR: 61;          // a bit of an endpoint's badge (u64)
///         signal TIMER: 40;        // a notification bit (u64, in SIGNALS)
///         signals LINK: 44..51;    // a range of notification bits (Bits)
///     }
/// }
/// ```
///
/// The space does not compile if two of its ranges, or its and the
/// included space's, overlap.  It re-exports what it includes.
#[macro_export]
macro_rules! badge_space {
    (
        $(#[$doc:meta])*
        $vis:vis mod $name:ident $(: $inc:path)? {
            $( $(#[$m:meta])* $kind:ident $item:ident : $lo:literal $(.. $hi:expr)? ; )*
        }
    ) => {
        $(#[$doc])*
        $vis mod $name {
            $( pub use $inc::*; use $inc as included; )?
            $( $crate::badge_space!(@item $(#[$m])* $kind $item $lo $($hi)?); )*
            /// This space's own ranges (not its includes').
            pub const OWN: &[$crate::wire::Bits] = &[ $( $crate::badge_space!(@bits $lo $($hi)?) ),* ];
            /// Every notification bit: a badge with one came from the
            /// bound notification, not a call.
            pub const SIGNALS: u64 = 0 $(| $crate::badge_space!(@signals_of $inc))? $(| $crate::badge_space!(@signal $kind $lo $($hi)?))*;
            const _: () = assert!($crate::wire::disjoint(&[OWN $(, $crate::badge_space!(@own_of $inc))?]), "overlapping badge bits");
        }
    };
    (@item $(#[$m:meta])* flag $item:ident $lo:literal) => { $(#[$m])* pub const $item: u64 = 1 << $lo; };
    (@item $(#[$m:meta])* signal $item:ident $lo:literal) => { $(#[$m])* pub const $item: u64 = 1 << $lo; };
    (@item $(#[$m:meta])* field $item:ident $lo:literal $hi:expr) => {
        $(#[$m])* pub const $item: $crate::wire::Bits = $crate::wire::Bits::new($lo, $hi);
    };
    (@item $(#[$m:meta])* signals $item:ident $lo:literal $hi:expr) => {
        $(#[$m])* pub const $item: $crate::wire::Bits = $crate::wire::Bits::new($lo, $hi);
    };
    // Only to make the use of `included` depend on there being an include.
    (@signals_of $inc:path) => { included::SIGNALS };
    (@own_of $inc:path) => { included::OWN };
    (@bits $lo:literal) => { $crate::wire::Bits::bit($lo) };
    (@bits $lo:literal $hi:expr) => { $crate::wire::Bits::new($lo, $hi) };
    (@signal signal $lo:literal) => { (1u64 << $lo) };
    (@signal signals $lo:literal $hi:expr) => { $crate::wire::Bits::new($lo, $hi).mask() };
    (@signal $kind:ident $lo:literal $($hi:expr)?) => { 0 };
}

/// Declare who calls a protocol, by the badge of their capability in a
/// badge space (in scope as `$space`): its flags, and at most one field,
/// which the variant carries or which is fixed to a value.  A mailbox's
/// poster has no badge.
///
/// ```ignore
/// senders! {
///     pub enum Sender in recv {
///         Root: [];                           // unbadged
///         Vmmgr: [VMMGR];
///         Vmm(GUEST): [VMM];                  // VMM | GUEST.put(guest)
///         Trustd: [COMPONENT] ID = TRUSTD_ID; // COMPONENT | ID.put(TRUSTD_ID)
///         Root: mailbox;                      // posts in the mailbox
///     }
/// }
/// ```
///
/// `of_badge` takes a badge to its sender only if it has no other bits;
/// `badge` is the badge to mint for one.  The declaration does not compile
/// if a sender's badge does not decode to it.
#[macro_export]
macro_rules! senders {
    (
        $(#[$doc:meta])*
        $vis:vis enum $name:ident in $space:ident {
            $( $(#[$m:meta])* $v:ident $(($field:ident))? : $spec:tt $($fixed:ident = $val:expr)? ; )*
        }
    ) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        $vis enum $name {
            $( $(#[$m])* $v $(($crate::senders!(@usize $field)))? ),*
        }

        impl $name {
            /// The sender a badge is, if it is exactly one's.
            #[allow(unused_variables)]
            pub const fn of_badge(badge: u64) -> Option<Self> {
                $( $crate::senders!(@of $space, badge, $v, $spec, [$($field)?], [$($fixed = $val)?]); )*
                None
            }

            /// The badge to mint for the sender's capability (none for a
            /// mailbox's poster: 0).
            #[allow(irrefutable_let_patterns, unreachable_code)]
            pub const fn badge(self) -> u64 {
                $( $crate::senders!(@badge $space, self, $v, $spec, [$($field)?], [$($fixed = $val)?]); )*
                0
            }
        }

        const _: () = {
            // The space is a badge space.
            let _: &[$crate::wire::Bits] = $space::OWN;
            $( $crate::senders!(@check $name, $v, $spec, [$($field)?]); )*
        };
    };
    (@usize $field:ident) => { usize };
    (@flags $space:ident, [$($flag:ident)|*]) => { 0 $(| $space::$flag)* };
    (@fixed $space:ident, []) => { 0 };
    (@fixed $space:ident, [$fixed:ident = $val:expr]) => { $space::$fixed.put($val as u64) };
    (@of $space:ident, $b:ident, $v:ident, mailbox, [], []) => {};
    (@of $space:ident, $b:ident, $v:ident, $spec:tt, [], [$($fx:tt)*]) => {
        if $b == $crate::senders!(@flags $space, $spec) | $crate::senders!(@fixed $space, [$($fx)*]) {
            return Some(Self::$v);
        }
    };
    (@of $space:ident, $b:ident, $v:ident, $spec:tt, [$field:ident], []) => {
        if $b & !$space::$field.mask() == $crate::senders!(@flags $space, $spec) {
            return Some(Self::$v($space::$field.get($b) as usize));
        }
    };
    (@badge $space:ident, $s:ident, $v:ident, mailbox, [], []) => {
        if let Self::$v = $s {
            return 0;
        }
    };
    (@badge $space:ident, $s:ident, $v:ident, $spec:tt, [], [$($fx:tt)*]) => {
        if let Self::$v = $s {
            return $crate::senders!(@flags $space, $spec) | $crate::senders!(@fixed $space, [$($fx)*]);
        }
    };
    (@badge $space:ident, $s:ident, $v:ident, $spec:tt, [$field:ident], []) => {
        if let Self::$v(x) = $s {
            return $crate::senders!(@flags $space, $spec) | $space::$field.put(x as u64);
        }
    };
    (@check $name:ident, $v:ident, mailbox, []) => {};
    (@check $name:ident, $v:ident, $spec:tt, []) => {
        assert!(matches!($name::of_badge($name::$v.badge()), Some($name::$v)), "a sender's badge is another's");
    };
    (@check $name:ident, $v:ident, $spec:tt, [$field:ident]) => {
        assert!(matches!($name::of_badge($name::$v(1).badge()), Some($name::$v(1))), "a sender's badge is another's");
    };
}

/// Declare the calls on an endpoint.
///
/// ```ignore
/// protocol! {
///     pub mod call (from: Sender) {
///         /// Doc of the call, on its Request variant and both methods.
///         GuestGive / guest_give = 5 from [Vmmgr] (guest: usize, first: usize) -> ();
///     }
/// }
/// ```
///
/// `Sender` is a type of the enclosing module, an enum of who calls, which
/// the server makes from the badge; `from [..]` lists its variants that may
/// make the call.  Argument and reply types are `Wire`.
#[macro_export]
macro_rules! protocol {
    (
        $(#[$doc:meta])*
        $vis:vis mod $name:ident (from: $sender:ident) {
            $(
                $(#[$m:meta])*
                $variant:ident / $method:ident = $label:literal from [$($role:ident),+ $(,)?]
                    ( $($arg:ident : $aty:ty),* $(,)? ) -> $rty:ty;
            )*
        }
    ) => {
        $(#[$doc])*
        $vis mod $name {
            #[allow(unused_imports)]
            use super::*;
            #[allow(unused_imports)]
            use $crate::wire::{Call, Wire};

            pub type Sender = super::$sender;

            /// A decoded call.  No heap: it lives on the server's stack.
            #[derive(Clone, Debug)]
            #[allow(clippy::large_enum_variant)]
            pub enum Request {
                $( $(#[$m])* $variant { $($arg: $aty),* } ),*
            }

            const _: () = assert!($crate::wire::distinct(&[$($label),*]), "two calls share a label");

            impl Request {
                /// Words of the longest call's arguments.
                pub const MAX_WORDS: usize =
                    $crate::wire::max(&[$( 0 $(+ <$aty as $crate::wire::Wire>::MAX_WORDS)* ),*]);
                /// Words of the longest reply, its errno included.
                pub const MAX_REPLY_WORDS: usize =
                    1 + $crate::wire::max(&[$( <$rty as $crate::wire::Wire>::MAX_WORDS ),*]);

                pub const fn label(&self) -> u64 {
                    match self { $( Self::$variant { .. } => $label ),* }
                }

                /// Whether `from` may make the call `label`.
                pub fn allowed(label: u64, from: Sender) -> bool {
                    match label {
                        $( $label => matches!(from, $( super::$sender::$role { .. } )|+), )*
                        _ => false,
                    }
                }

                /// The call `label` with arguments `args`: EINVAL if it is
                /// unknown, `from` may not make it, or its arguments are
                /// not valid.  Words past the arguments are ignored.
                #[allow(unused_mut, unused_variables, unused_assignments)]
                pub fn decode(label: u64, args: &[u64], from: Sender) -> Result<Self, $crate::errno::Errno> {
                    if !Self::allowed(label, from) {
                        return Err($crate::wire::EINVAL);
                    }
                    match label {
                        $( $label => {
                            let mut at = 0;
                            $(
                                let ($arg, n) = <$aty as $crate::wire::Wire>::get(&args[at..])
                                    .ok_or($crate::wire::EINVAL)?;
                                at += n;
                            )*
                            Ok(Self::$variant { $($arg),* })
                        } )*
                        _ => Err($crate::wire::EINVAL),
                    }
                }

                /// Write the arguments into `out`: their length.
                #[allow(unused_mut, unused_variables)]
                pub fn encode(&self, out: &mut [u64]) -> usize {
                    match self {
                        $( Self::$variant { $($arg),* } => {
                            let mut at = 0;
                            $( at += $crate::wire::Wire::put($arg, &mut out[at..]); )*
                            at
                        } )*
                    }
                }
            }

            impl $crate::wire::Message for Request {
                const MAX_WORDS: usize = Request::MAX_WORDS;
                fn label(&self) -> u64 {
                    Request::label(self)
                }
                fn encode(&self, out: &mut [u64]) -> usize {
                    Request::encode(self, out)
                }
            }

            /// The reply type of the call with label L.
            pub trait ReplyOf<const L: u64> {
                type T;
            }
            /// What implements ReplyOf for every call.
            pub struct Calls;
            $( impl ReplyOf<$label> for Calls { type T = $rty; } )*

            /// Each call's reply type, for a client that takes the reply
            /// later (a mailbox's answer): `wire::reply::<reply::Call>(words)`.
            pub mod reply {
                $( pub type $variant = <super::Calls as super::ReplyOf<$label>>::T; )*
            }

            const _: () = assert!(Request::MAX_WORDS <= $crate::wire::MAX_MRS
                && Request::MAX_REPLY_WORDS <= $crate::wire::MAX_MRS, "call longer than the IPC buffer");

            /// What the server implements: a method per call, made only by
            /// the senders its declaration allows.
            pub trait Server {
                $( $(#[$m])* fn $method(&mut self, from: Sender, $($arg: $aty),*) -> Result<$rty, $crate::errno::Errno>; )*
            }

            /// Decode the call `label` from `from`, run its method, and
            /// write the reply (0 and its value, or the errno) into `out`
            /// (at least Request::MAX_REPLY_WORDS long): the reply's
            /// length, or None if the method returned wire::NO_REPLY.
            pub fn serve<S: Server + ?Sized>(
                s: &mut S, label: u64, args: &[u64], from: Sender, out: &mut [u64],
            ) -> Option<usize> {
                let r = match Request::decode(label, args, from) {
                    $( Ok(Request::$variant { $($arg),* }) => s.$method(from, $($arg),*)
                        .map(|v| $crate::wire::Wire::put(&v, &mut out[1..])), )*
                    Err(e) => Err(e),
                };
                match r {
                    Ok(n) => {
                        out[0] = 0;
                        Some(1 + n)
                    }
                    Err($crate::wire::NO_REPLY) => None,
                    Err(e) => {
                        out[0] = e;
                        Some(1)
                    }
                }
            }

            /// A method per call, for anything that can call the endpoint.
            pub trait Client: $crate::wire::Call {
                $(
                    $(#[$m])*
                    fn $method(&self, $($arg: $aty),*) -> Result<$rty, $crate::errno::Errno> {
                        let req = Request::$variant { $($arg),* };
                        let mut args = [0u64; Request::MAX_WORDS];
                        let n = req.encode(&mut args);
                        let mut reply = [0u64; Request::MAX_REPLY_WORDS];
                        let len = self.ipc($label, &args[..n], &mut reply).min(reply.len());
                        $crate::wire::reply::<$rty>(&reply[..len])
                    }
                )*
            }

            impl<T: $crate::wire::Call + ?Sized> Client for T {}
        }
    };
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use super::*;

    crate::badge_space! {
        pub mod parent {
            field ID: 0..16;
            flag FAULT: 24;
        }
    }

    crate::badge_space! {
        pub mod space: super::parent {
            flag CALLER: 30;
            signal TIMER: 40;
            signals LINK: 44..47;
        }
    }

    #[test]
    fn badge_space() {
        assert_eq!(space::FAULT, 1 << 24);
        assert_eq!(space::ID.put(5) | space::FAULT, (1 << 24) | 5);
        assert_eq!(space::ID.get(0xdead_beef), 0xbeef);
        assert_eq!(space::LINK.nth(2), 1 << 46);
        assert_eq!(space::SIGNALS, (1 << 40) | (0b111 << 44));
        assert!(!disjoint(&[&[Bits::new(0, 16)], &[Bits::bit(15)]]));
        assert!(disjoint(&[&[Bits::new(0, 16), Bits::bit(16)]]));
        assert_eq!(Bits::new(0, 64).mask(), u64::MAX);
    }

    #[test]
    #[should_panic]
    fn field_overflow() {
        space::ID.put(1 << 16);
    }

    crate::senders! {
        pub enum Who in space {
            Boss: [CALLER];
            Guest(ID): [FAULT];
            Poster: mailbox;
        }
    }

    crate::wire_struct! {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct Pair {
            pub a: u64,
            pub b: u8,
        }
    }

    crate::protocol! {
        pub mod demo (from: Who) {
            /// Add.
            Add / add = 1 from [Boss] (x: u64, y: u8) -> u64;
            Pairs / pairs = 2 from [Boss, Guest] (list: ArrayVec<Pair, 4>) -> Tail<u64, 4>;
            Ping / ping = 3 from [Guest] () -> ();
        }
    }

    struct Srv;
    impl demo::Server for Srv {
        fn add(&mut self, _: Who, x: u64, y: u8) -> Result<u64, Errno> {
            x.checked_add(y as u64).ok_or(EINVAL)
        }
        fn pairs(&mut self, _: Who, list: ArrayVec<Pair, 4>) -> Result<Tail<u64, 4>, Errno> {
            Ok(Tail(list.iter().map(|p| p.a + p.b as u64).collect()))
        }
        fn ping(&mut self, from: Who) -> Result<(), Errno> {
            match from {
                Who::Guest(7) => Ok(()),
                Who::Guest(8) => Err(NO_REPLY),
                _ => Err(16),
            }
        }
    }

    /// A client whose calls go straight to Srv.
    struct Loop(Who);
    impl Call for Loop {
        fn ipc(&self, label: u64, args: &[u64], reply: &mut [u64]) -> usize {
            let mut out = [0; demo::Request::MAX_REPLY_WORDS];
            let n = demo::serve(&mut Srv, label, args, self.0, &mut out).unwrap_or(0);
            reply[..n].copy_from_slice(&out[..n]);
            n
        }
    }

    #[test]
    fn protocol() {
        use demo::Client;
        let boss = Loop(Who::Boss);
        assert_eq!(boss.add(2, 3), Ok(5));
        assert_eq!(boss.add(u64::MAX, 1), Err(EINVAL));
        let list: ArrayVec<Pair, 4> = [Pair { a: 1, b: 2 }, Pair { a: 10, b: 20 }].into_iter().collect();
        assert_eq!(boss.pairs(list.clone()).unwrap().0.as_slice(), &[3, 30]);
        // Senders the declaration does not allow.
        assert_eq!(boss.ping(), Err(EINVAL));
        assert_eq!(Loop(Who::Guest(1)).add(1, 1), Err(EINVAL));
        assert_eq!(Loop(Who::Guest(1)).ping(), Err(16));
        assert_eq!(Loop(Who::Guest(7)).ping(), Ok(()));
        // No reply: the client sees no words, as from a failed server.
        assert_eq!(Loop(Who::Guest(8)).ping(), Err(FAILED));
        let mut out = [0; demo::Request::MAX_REPLY_WORDS];
        assert_eq!(demo::serve(&mut Srv, 3, &[], Who::Guest(8), &mut out), None);
        // A reply taken later, by its call's type.
        assert_eq!(reply::<demo::reply::Add>(&[0, 9]), Ok(9));
        assert_eq!(demo::Request::MAX_WORDS, 1 + 4 * 2);
        assert_eq!(demo::Request::MAX_REPLY_WORDS, 1 + 4);
    }

    #[test]
    fn senders() {
        assert_eq!(Who::Boss.badge(), space::CALLER);
        assert_eq!(Who::Guest(9).badge(), space::FAULT | 9);
        assert_eq!(Who::of_badge(space::FAULT | 9), Some(Who::Guest(9)));
        assert_eq!(Who::of_badge(space::CALLER), Some(Who::Boss));
        // Exactly: no stray bits, and a mailbox's poster from no badge.
        assert_eq!(Who::of_badge(space::CALLER | 1), None);
        assert_eq!(Who::of_badge(space::FAULT | space::TIMER), None);
        assert_eq!(Who::of_badge(0), None);
        assert_eq!(Who::Poster.badge(), 0);
    }

    #[test]
    fn decode_rejects() {
        use demo::Request;
        // Unknown label, missing arguments, a word too wide for its type, a
        // list longer than its bound.
        assert_eq!(Request::decode(9, &[], Who::Boss).unwrap_err(), EINVAL);
        assert_eq!(Request::decode(1, &[1], Who::Boss).unwrap_err(), EINVAL);
        assert_eq!(Request::decode(1, &[1, 256], Who::Boss).unwrap_err(), EINVAL);
        assert_eq!(Request::decode(2, &[5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], Who::Boss).unwrap_err(), EINVAL);
        assert!(matches!(Request::decode(1, &[1, 255, 99], Who::Boss), Ok(Request::Add { x: 1, y: 255 })));
    }

    #[test]
    fn reply_words() {
        assert_eq!(reply::<u64>(&[0, 7]), Ok(7));
        assert_eq!(reply::<u64>(&[0]), Err(FAILED));
        assert_eq!(reply::<u64>(&[FAILED]), Err(FAILED));
        assert_eq!(reply::<()>(&[]), Err(FAILED));
        assert_eq!(reply::<()>(&[12]), Err(12));
    }
}

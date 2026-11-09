//! Minting the wiring's capabilities (l4h_host::wiring): a capability's
//! rights and badge, and its slot when it has one, come from its edge, and
//! what it is minted from must be the edge's target's object: an
//! `Obj<T, O>`, which is T's O by its type.  An Obj is claimed where the
//! object is made or received (`Obj::claim`, `Component::obj`).  Nothing
//! else mints a badged capability but a CNode's guard (clippy's
//! disallowed-methods, host/clippy.toml).

use core::marker::PhantomData;

use l4h_host::wiring::{E, Edge, Rights, o, p};
use l4h_host::wire::Protocol;
use sel4::{AbsoluteCPtr, CapRights, CapRightsBuilder};

/// Target T's object O (a capability to it in the caller's CSpace).
pub struct Obj<T, O>(AbsoluteCPtr, PhantomData<(T, O)>);

impl<T, O> Clone for Obj<T, O> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T, O> Copy for Obj<T, O> {}

impl<T: p::IsParty, O: o::IsObject> Obj<T, O> {
    /// The claim that `cap` is T's O, where it is made or received.
    pub fn claim(cap: AbsoluteCPtr) -> Self {
        Obj(cap, PhantomData)
    }

    pub fn cptr(&self) -> &AbsoluteCPtr {
        &self.0
    }
}

/// The rights a capability of `e` carries.
pub fn rights(e: &Edge) -> CapRights {
    match e.rights {
        Rights::Call => CapRightsBuilder::none().write(true).grant_reply(true).build(),
        Rights::Signal => CapRights::write_only(),
        Rights::Bind | Rights::Fault | Rights::KeeperFault => CapRights::all(),
    }
}

/// Mint instance `i` of `e` into `dst` from `src`: into a slot the minter
/// chose (the edge's At::Chosen, or a slot it passes on from), an IRQ
/// handler's notification or a fault endpoint.
pub fn mint<H, T, O, P>(dst: &AbsoluteCPtr, e: &E<H, T, O, P>, i: usize, src: &Obj<T, O>) -> sel4::Result<()>
where
    H: p::IsParty,
    T: p::IsParty,
    O: o::IsObject,
    P: Protocol,
{
    mint_dyn(dst, e, i, src.cptr())
}

/// Mint a capability to `cnode` (in `local`, the caller's CNode) with
/// guard `guard` into `dst`: the one mint that is no edge.
pub fn mint_cnode(dst: &AbsoluteCPtr, local: sel4::cap::CNode, cnode: sel4::cap::CNode, guard: sel4::CNodeCapData) -> sel4::Result<()> {
    #[allow(clippy::disallowed_methods)]
    dst.mint(&local.absolute_cptr(cnode), CapRights::all(), guard.into_word())
}

/// Mint an edge found at run time (wiring::parent_call, parent_fault),
/// whose target the caller checks.
pub(crate) fn mint_dyn(dst: &AbsoluteCPtr, e: &Edge, i: usize, src: &AbsoluteCPtr) -> sel4::Result<()> {
    #[allow(clippy::disallowed_methods)]
    dst.mint(src, rights(e), e.badge(i))
}

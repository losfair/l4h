//! Minting the wiring's capabilities (l4h_host::wiring): a capability's
//! rights and badge, and its slot when it has one, come from its edge, and
//! what it is minted from must be the edge's target's object: an
//! `Obj<T, O>`, which is T's O by its type.  An Obj is claimed where the
//! object is made or received (`Obj::claim`, which names the party and
//! the object; `Component::obj`), and only the edge's minter mints it
//! (`minter`).  A capability its holder got from another holder is passed
//! on from its edge too (`pass`).  Nothing else mints a badged capability
//! but a CNode's guard (clippy's disallowed-methods, host/clippy.toml).

use core::marker::PhantomData;
use core::sync::atomic::{AtomicU8, Ordering};

use l4h_host::wiring::{At, E, Edge, Party, Rights, o, p};
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
    /// The claim that `cap` is `_party`'s `_object`, where it is made or
    /// received.  Both are named, so that the claim says what the
    /// capability is, not what the edge it is minted for wants.
    pub fn claim(_party: T, _object: O, cap: AbsoluteCPtr) -> Self {
        Obj(cap, PhantomData)
    }

    /// `cap` as T's O, for a caller that checked it is (Component::obj).
    pub(crate) fn of(cap: AbsoluteCPtr) -> Self {
        Obj(cap, PhantomData)
    }

    pub fn cptr(&self) -> &AbsoluteCPtr {
        &self.0
    }
}

/// Who this task is, as a minter (0: not said yet).
static MINTER: AtomicU8 = AtomicU8::new(0);

/// This task is `me`: it mints the edges the wiring says it does
/// (Edge::minted_by), and no others.
pub fn minter(me: Party) {
    MINTER.store(me as u8 + 1, Ordering::Relaxed);
}

/// Stop unless this task mints `e`.
fn minted_here(e: &Edge) {
    assert!(MINTER.load(Ordering::Relaxed) == e.minted_by as u8 + 1, "{} ({}) is {:?}'s to mint", e.name, e.what, e.minted_by);
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
    minted_here(e);
    #[allow(clippy::disallowed_methods)]
    dst.mint(src, rights(e), e.badge(i))
}

/// Pass on a capability of `e` that was minted already, `minted` (its
/// minter's own, or one a call passed to this task), into `dst`, a slot
/// the edge leaves to its minter (At::Chosen).  Its badge is its
/// minter's; its rights are at most the edge's.
pub fn pass<H, T, O, P>(dst: &AbsoluteCPtr, e: &E<H, T, O, P>, minted: &AbsoluteCPtr) -> sel4::Result<()>
where
    H: p::IsParty,
    T: p::IsParty,
    O: o::IsObject,
    P: Protocol,
{
    assert!(matches!(e.at, At::Chosen), "{} is in a slot of its holder's: Component::pass_edge", e.name);
    dst.copy(minted, rights(e))
}

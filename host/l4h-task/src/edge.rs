//! Minting the wiring's capabilities (l4h_host::wiring): a capability's
//! rights and badge, and its slot when it has one, come from its Edge.
//! tests/check-wiring.sh keeps IPC badges out of other mints.

use l4h_host::wiring::{Edge, Rights};
use sel4::{AbsoluteCPtr, CapRights, CapRightsBuilder};

/// The rights a capability of `e` carries.
pub fn rights(e: &Edge) -> CapRights {
    match e.rights {
        Rights::Call => CapRightsBuilder::none().write(true).grant_reply(true).build(),
        Rights::Signal => CapRights::write_only(),
        Rights::Bind | Rights::Fault | Rights::KeeperFault => CapRights::all(),
    }
}

/// Mint instance `i` of `e` into `dst` from `src`, its target's object:
/// into a slot the minter chose (the edge's At::Chosen, or a slot it
/// passes on from), an IRQ handler's notification or a fault endpoint.
pub fn mint(dst: &AbsoluteCPtr, e: &Edge, i: usize, src: &AbsoluteCPtr) -> sel4::Result<()> {
    dst.mint(src, rights(e), e.badge(i))
}

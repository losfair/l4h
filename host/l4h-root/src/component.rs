//! Component spawning through l4h-task, with local CSpace conveniences.

pub use l4h_task::component::{Component, SpawnArgs, SpawnContext, audit_in, create, start};
pub use l4h_task::cap_at as root_cap;
pub use l4h_task::edge::{Obj, mint as mint_edge};
pub use l4h_host::wiring::{o, p};

/// Root's own notification, bound to its thread (main.rs): the target of
/// the edges root receives signals on.
pub fn root_ntfn(ntfn: sel4::cap::Notification) -> Obj<p::Root, o::Notification> {
    Obj::claim(abs_of(ntfn))
}

/// A capability in this task's CSpace, expressed as an absolute pointer.
pub fn abs_of(c: impl sel4::HasCPtrWithDepth) -> sel4::AbsoluteCPtr {
    crate::slot::CNODE.cap().absolute_cptr(c)
}

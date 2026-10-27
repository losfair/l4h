//! Component spawning through l4h-task, with local CSpace conveniences.

pub use l4h_task::component::{Component, SpawnArgs, SpawnContext, ROOT_BADGE_COMPONENT, component_badge, create, start};
pub use l4h_task::cap_at as root_cap;

/// A capability in this task's CSpace, expressed as an absolute pointer.
pub fn abs_of(c: impl sel4::HasCPtrWithDepth) -> sel4::AbsoluteCPtr {
    crate::slot::CNODE.cap().absolute_cptr(c)
}

//! Scratch mappings used to read and write frames belonging to guests
//! and components, in the caller-supplied VSpace and virtual address.

use sel4::{CapRights, VmAttributes, cap, cap_type};

use crate::mem::{Alloc, ObjCtx, Slot};
use crate::vspace::map_frame;

pub struct Window {
    cnode: cap::CNode,
    vspace: cap::VSpace,
    slot: Slot,
    va: usize,
}

impl Window {
    /// Reserve one page at `va` in `vspace` for scratch mappings.
    pub fn new(alloc: &mut Alloc, vspace: cap::VSpace, va: usize) -> Self {
        assert_eq!(va % 4096, 0);
        let cnode = alloc.slots.cnode();
        let slot = alloc.slots.alloc();
        // Pre-create the paging structures for the window so that mapping
        // never has to allocate.
        let probe = alloc.object_cap::<cap_type::Granule>(crate::vspace::FRAME_BP);
        let mut ctx = ObjCtx::global(alloc);
        map_frame(&mut ctx, vspace, probe, va, CapRights::read_write(), VmAttributes::DEFAULT);
        probe.frame_unmap().unwrap();
        Self { cnode, vspace, slot, va }
    }

    /// Temporarily map the frame `frame` (a capability anywhere reachable
    /// from the caller's CSpace) and run `f` on its contents.
    pub fn with_frame<R>(&mut self, frame: &sel4::AbsoluteCPtr, f: impl FnOnce(*mut u8) -> R) -> R {
        self.with_frame_attrs(frame, VmAttributes::DEFAULT, f)
    }

    /// `with_frame` with mapping attributes `attrs` (device registers are
    /// mapped uncached).
    pub fn with_frame_attrs<R>(&mut self, frame: &sel4::AbsoluteCPtr, attrs: VmAttributes, f: impl FnOnce(*mut u8) -> R) -> R {
        let dst = self.cnode.absolute_cptr(crate::cap_at::<cap_type::Null>(self.slot));
        dst.copy(frame, CapRights::read_write()).expect("window copy");
        let cap = crate::cap_at::<cap_type::Granule>(self.slot);
        cap.frame_map(self.vspace, self.va, CapRights::read_write(), attrs).expect("window map");
        let r = f(self.va as *mut u8);
        // ELF loading writes through this alias. Make those instructions
        // visible before another VSpace (or core) starts executing them.
        #[cfg(target_arch = "aarch64")]
        if attrs.has(VmAttributes::PAGE_CACHEABLE) {
            let error = sel4::with_ipc_buffer_mut(|ipc| {
                ipc.inner_mut().seL4_ARM_Page_Unify_Instruction(cap.bits(), 0, 4096)
            });
            assert_eq!(error, 0, "window instruction-cache maintenance");
        }
        cap.frame_unmap().unwrap();
        dst.delete().unwrap();
        r
    }
}

/// Two scratch windows for operations that map a source and destination.
pub struct Windows {
    pub a: Window,
    pub b: Window,
}

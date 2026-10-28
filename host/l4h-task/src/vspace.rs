//! Building address spaces: mapping frames and creating the paging
//! structures they need.

use sel4::{CapRights, ObjectBlueprint, VmAttributes, cap, cap_type};

use crate::mem::ObjCtx;

#[cfg(target_arch = "aarch64")]
pub use aarch64::*;
#[cfg(target_arch = "x86_64")]
pub use x86_64::*;

fn is_failed_lookup(e: sel4::Error) -> bool {
    e == sel4::Error::FailedLookup
}

/// aarch64: a VSpace root and page tables at every level below it.
#[cfg(target_arch = "aarch64")]
mod aarch64 {
    use super::*;
    use sel4::{ObjectBlueprintAArch64, ObjectBlueprintArm};

    const PT_BP: ObjectBlueprint = ObjectBlueprint::Arch(ObjectBlueprintArm::PT);
    /// The root of an address space (named after x86_64's top level).
    pub const PML4_BP: ObjectBlueprint =
        ObjectBlueprint::Arch(ObjectBlueprintArm::SeL4Arch(ObjectBlueprintAArch64::VSpace));
    pub const FRAME_BP: ObjectBlueprint = ObjectBlueprint::Arch(ObjectBlueprintArm::SmallPage);
    pub const LARGE_PAGE_BP: ObjectBlueprint = ObjectBlueprint::Arch(ObjectBlueprintArm::LargePage);

    /// Map `frame` at `vaddr` in `vspace`, creating page tables from `ctx`
    /// as needed (each failed lookup adds the missing level).
    pub fn map_frame(
        ctx: &mut ObjCtx,
        vspace: cap::VSpace,
        frame: cap::Granule,
        vaddr: usize,
        rights: CapRights,
        attrs: VmAttributes,
    ) {
        loop {
            match frame.frame_map(vspace, vaddr, rights.clone(), attrs) {
                Ok(()) => return,
                Err(e) if is_failed_lookup(e) => loop {
                    let pt = ctx.cap::<cap_type::PT>(PT_BP);
                    match pt.pt_map(vspace, vaddr, VmAttributes::DEFAULT) {
                        Ok(()) => break,
                        Err(e) if is_failed_lookup(e) => continue,
                        Err(e) => panic!("pt_map({:#x}) failed: {:?}", vaddr, e),
                    }
                },
                Err(e) => panic!("frame_map({:#x}) failed: {:?}", vaddr, e),
            }
        }
    }

    /// Map the 2 MiB page `frame` at `vaddr` (2 MiB aligned) in `vspace`.
    /// A page table made for a failed lookup lands at the highest missing
    /// level, so this never makes a last-level table where the page goes.
    pub fn map_large_page(ctx: &mut ObjCtx, vspace: cap::VSpace, frame: cap::LargePage, vaddr: usize, rights: CapRights) {
        loop {
            match frame.frame_map(vspace, vaddr, rights.clone(), VmAttributes::DEFAULT) {
                Ok(()) => return,
                Err(e) if is_failed_lookup(e) => {
                    let pt = ctx.cap::<cap_type::PT>(PT_BP);
                    pt.pt_map(vspace, vaddr, VmAttributes::DEFAULT)
                        .unwrap_or_else(|e| panic!("pt_map({:#x}) failed: {:?}", vaddr, e));
                }
                Err(e) => panic!("frame_map({:#x}) failed: {:?}", vaddr, e),
            }
        }
    }

    /// x86_64's TLB bitmaps have no counterpart: seL4 invalidates the
    /// TLBs of all cores with broadcast instructions, without IPIs.
    pub fn flush_tlb_bitmap(_vspace: cap::VSpace) {}
}

#[cfg(target_arch = "x86_64")]
mod x86_64 {
use super::*;
use sel4::{ObjectBlueprintArch, ObjectBlueprintX64, ObjectBlueprintX86};

const PDPT_BP: ObjectBlueprint =
    ObjectBlueprint::Arch(ObjectBlueprintX86::SeL4Arch(ObjectBlueprintX64::PDPT));
const PD_BP: ObjectBlueprint = ObjectBlueprint::Arch(ObjectBlueprintX86::PageDirectory);
const PT_BP: ObjectBlueprint = ObjectBlueprint::Arch(ObjectBlueprintX86::PageTable);
pub const PML4_BP: ObjectBlueprint =
    ObjectBlueprint::Arch(ObjectBlueprintX86::SeL4Arch(ObjectBlueprintX64::PML4));
pub const FRAME_BP: ObjectBlueprint = ObjectBlueprint::Arch(ObjectBlueprintX86::_4k);
pub const LARGE_PAGE_BP: ObjectBlueprint = ObjectBlueprint::Arch(ObjectBlueprintX86::LargePage);

#[allow(dead_code)]
const _: Option<ObjectBlueprintArch> = None;

/// Drop the cores that are not running `vspace` from its TLB bitmap.
///
/// seL4 adds a core to a VSpace's bitmap when the core first switches to
/// it, and each page unmap in the VSpace then interrupts every core in
/// the bitmap and waits, holding the kernel lock, until all have
/// answered.  A core leaves the bitmap only when the VSpace's whole PCID
/// is flushed (it then drops the stale entries it may still hold), which
/// is what this does (seL4_X64_PML4_Flush, patch 0017): one round of
/// IPIs to the cores in the bitmap, and the VSpace's TLB entries lost on
/// those running it.  Call it when threads of the VSpace have left cores
/// for good.
pub fn flush_tlb_bitmap(vspace: cap::VSpace) {
    let err = sel4::with_ipc_buffer_mut(|ipc| ipc.inner_mut().seL4_X64_PML4_Flush(vspace.bits()));
    if err != 0 {
        log!("l4h-task: PML4_Flush({:#x}) failed: {}", vspace.bits(), err);
    }
}

/// Map `frame` at `vaddr` in `vspace`, creating intermediate tables from
/// `ctx` as needed.
pub fn map_frame(
    ctx: &mut ObjCtx,
    vspace: cap::VSpace,
    frame: cap::Granule,
    vaddr: usize,
    rights: CapRights,
    attrs: VmAttributes,
) {
    loop {
        match frame.frame_map(vspace, vaddr, rights.clone(), attrs) {
            Ok(()) => return,
            Err(e) if is_failed_lookup(e) => ensure_pt(ctx, vspace, vaddr),
            Err(e) => panic!("frame_map({:#x}) failed: {:?}", vaddr, e),
        }
    }
}

/// Map the 2 MiB page `frame` at `vaddr` (2 MiB aligned) in `vspace`,
/// creating the page directory and PDPT from `ctx` as needed.
pub fn map_large_page(ctx: &mut ObjCtx, vspace: cap::VSpace, frame: cap::LargePage, vaddr: usize, rights: CapRights) {
    loop {
        match frame.frame_map(vspace, vaddr, rights.clone(), VmAttributes::DEFAULT) {
            Ok(()) => return,
            Err(e) if is_failed_lookup(e) => ensure_pd(ctx, vspace, vaddr),
            Err(e) => panic!("frame_map({:#x}) failed: {:?}", vaddr, e),
        }
    }
}

fn ensure_pt(ctx: &mut ObjCtx, vspace: cap::VSpace, vaddr: usize) {
    let pt = ctx.cap::<cap_type::PageTable>(PT_BP);
    loop {
        match pt.page_table_map(vspace, vaddr, VmAttributes::DEFAULT) {
            Ok(()) => return,
            Err(e) if is_failed_lookup(e) => ensure_pd(ctx, vspace, vaddr),
            Err(e) => panic!("page_table_map({:#x}) failed: {:?}", vaddr, e),
        }
    }
}

fn ensure_pd(ctx: &mut ObjCtx, vspace: cap::VSpace, vaddr: usize) {
    let pd = ctx.cap::<cap_type::PageDirectory>(PD_BP);
    loop {
        match pd.page_directory_map(vspace, vaddr, VmAttributes::DEFAULT) {
            Ok(()) => return,
            Err(e) if is_failed_lookup(e) => {
                let pdpt = ctx.cap::<cap_type::PDPT>(PDPT_BP);
                pdpt.pdpt_map(vspace, vaddr, VmAttributes::DEFAULT)
                    .unwrap_or_else(|e| panic!("pdpt_map({:#x}) failed: {:?}", vaddr, e));
            }
            Err(e) => panic!("page_directory_map({:#x}) failed: {:?}", vaddr, e),
        }
    }
}
}

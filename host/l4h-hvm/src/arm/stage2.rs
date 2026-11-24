//! Mapping guest RAM as it is first touched (DESIGN.md §5.11), as ept.rs on
//! x86-64: a 2 MiB block's Untyped, which memd gave us at the block's index
//! of the block CNode, becomes a large frame, mapped in the guest's Stage-2
//! and, through a copy, here at RAM_VA + its GPA.  vmmgr made the tables
//! both go in, and mapped the boot blocks itself.  Only the I/O thread maps
//! (a vCPU thread asks it, hvm::call::Map).
//!
//! The guest runs with its caches off until it turns them on, and fetches
//! what was written through the data side: a mapped block is made coherent
//! for instructions unless CTR_EL0 says the hardware keeps it so (IDC and
//! DIC), and what l4h-hvm loaded is cleaned to the point of coherency
//! (`clean_range`).

use l4h_rt::host::hvm as hv;
use l4h_rt::{cap, sel4};
use sel4::{CapRights, ObjectBlueprint, ObjectBlueprintArm, VmAttributes, cap_type};

use crate::guest::GuestMem;
use crate::sync::Global;

const BLOCK: u64 = 2 << 20;
/// CTR_EL0's IDC and DIC.
const CTR_COHERENT: u64 = 3 << 28;

struct Ctx {
    mem: GuestMem,
    radix: usize,
    guest: u32,
    /// The hardware keeps instruction fetches coherent (CTR_EL0).
    coherent: bool,
}

static CTX: Global<Ctx> = Global::new();

/// Set up mapping (once, on the I/O thread, before anything is loaded).
pub fn init(mem: GuestMem, block_radix: u32, guest: u32, ctr_el0: u64) {
    CTX.set(Ctx { mem, radix: block_radix as usize, guest, coherent: ctr_el0 & CTR_COHERENT == CTR_COHERENT });
}

const LARGE_PAGE: ObjectBlueprint = ObjectBlueprint::Arch(ObjectBlueprintArm::LargePage);

fn slot(c: u64) -> sel4::AbsoluteCPtr {
    cap::<cap_type::CNode>(l4h_rt::host::SLOT_CNODE).absolute_cptr(cap::<cap_type::Null>(c))
}

fn keep(cnode: u64, b: usize) -> sel4::AbsoluteCPtr {
    cap::<cap_type::CNode>(cnode).absolute_cptr_from_bits_with_depth(b as u64, CTX.get().radix)
}

fn check(e: sel4::sys::seL4_Error::Type) -> sel4::Result<()> {
    match sel4::Error::from_sys(e) {
        None => Ok(()),
        Some(e) => Err(e),
    }
}

/// Unify the instruction cache over [start, end) of the frame at `frame`.
fn unify(frame: u64, start: u64, end: u64) -> sel4::Result<()> {
    if CTX.get().coherent {
        return Ok(());
    }
    check(sel4::with_ipc_buffer_mut(|b| b.inner_mut().seL4_ARM_Page_Unify_Instruction(frame, start, end)))
}

/// How far `map_block` got.
#[derive(Clone, Copy, Default)]
struct Installed {
    /// The block's Untyped is in SLOT_SCRATCH_UT.
    ut_moved: bool,
    here: bool,
    stage2: bool,
    kept: bool,
}

/// Take back what a failed `map_block` did, last first, and leave its
/// scratch slots empty.  Each step is tried whatever became of the one
/// before: nothing is to stay mapped.  If a slot cannot be cleaned, the next
/// block could not use it: the guest ends here.
fn undo(b: usize, done: Installed) {
    let mut clean = true;
    if done.ut_moved {
        clean &= keep(hv::SLOT_BLOCKS, b).move_(&slot(hv::SLOT_SCRATCH_UT)).is_ok();
    }
    if done.kept {
        clean &= slot(hv::SLOT_SCRATCH_EPT).move_(&keep(hv::SLOT_KEEP_EPT, b)).is_ok();
    }
    if done.stage2 {
        clean &= cap::<cap_type::LargePage>(hv::SLOT_SCRATCH_EPT).frame_unmap().is_ok();
    }
    if done.here {
        clean &= cap::<cap_type::LargePage>(hv::SLOT_SCRATCH_HVM).frame_unmap().is_ok();
    }
    clean &= slot(hv::SLOT_SCRATCH_HVM).delete().is_ok();
    clean &= slot(hv::SLOT_SCRATCH_EPT).delete().is_ok();
    if !clean {
        l4h_rt::log!("l4h-hvm: guest {}: RAM block {}: cannot undo its mapping", CTX.get().guest, b);
        crate::sys::power(l4h_abi::POWER_CRASH);
    }
}

/// Map block `b` if it is not yet (the I/O thread): false if it cannot be,
/// which ends the guest.
pub fn map_block(b: usize) -> bool {
    let ctx = CTX.get();
    let mem = &ctx.mem;
    if mem.is_mapped(b) {
        return true;
    }
    if b >= mem.blocks() {
        return false;
    }
    let gpa = mem.block_gpa(b);
    let mut done = Installed::default();
    let r = (|| -> sel4::Result<()> {
        slot(hv::SLOT_SCRATCH_UT).move_(&keep(hv::SLOT_BLOCKS, b))?;
        done.ut_moved = true;
        let ut = cap::<cap_type::Untyped>(hv::SLOT_SCRATCH_UT);
        let dest = cap::<cap_type::CNode>(l4h_rt::host::SLOT_CNODE).absolute_cptr_for_self();
        let made = ut.untyped_retype(&LARGE_PAGE, &dest, hv::SLOT_SCRATCH_EPT as usize, 1);
        // The Untyped goes back where memd revokes it, used or not.
        keep(hv::SLOT_BLOCKS, b).move_(&slot(hv::SLOT_SCRATCH_UT))?;
        done.ut_moved = false;
        made?;
        slot(hv::SLOT_SCRATCH_HVM).copy(&slot(hv::SLOT_SCRATCH_EPT), CapRights::read_write())?;
        // Here first, and coherent for instructions, before the guest can
        // reach it: a vCPU may already be fetching from this block.
        let here = cap::<cap_type::LargePage>(hv::SLOT_SCRATCH_HVM);
        here.frame_map(cap::<cap_type::VSpace>(l4h_rt::host::SLOT_VSPACE), hv::RAM_VA + gpa as usize, CapRights::read_write(),
            VmAttributes::DEFAULT)?;
        done.here = true;
        unify(hv::SLOT_SCRATCH_HVM, 0, BLOCK)?;
        let s2 = cap::<cap_type::LargePage>(hv::SLOT_SCRATCH_EPT);
        s2.frame_map(cap::<cap_type::VSpace>(hv::SLOT_EPT), gpa as usize, CapRights::read_write(), VmAttributes::DEFAULT)?;
        done.stage2 = true;
        keep(hv::SLOT_KEEP_EPT, b).move_(&slot(hv::SLOT_SCRATCH_EPT))?;
        done.kept = true;
        keep(hv::SLOT_KEEP_HVM, b).move_(&slot(hv::SLOT_SCRATCH_HVM))?;
        Ok(())
    })();
    match r {
        Ok(()) => {
            mem.set_mapped(b);
            true
        }
        Err(e) => {
            undo(b, done);
            l4h_rt::log!("l4h-hvm: guest {}: RAM block {} at {:#x}: {:?}", ctx.guest, b, gpa, e);
            false
        }
    }
}

/// Make [gpa, gpa + len) of RAM, which l4h-hvm wrote, what a guest with its
/// caches off reads and fetches (the I/O thread, before any vCPU runs).
pub fn clean_range(gpa: u64, len: u64) -> sel4::Result<()> {
    let ctx = CTX.get();
    let mem = &ctx.mem;
    if len == 0 {
        return Ok(());
    }
    let mut at = gpa;
    let end = gpa + len;
    while at < end {
        let b = mem.block_of(at);
        let base = mem.block_gpa(b);
        let (start, stop) = (at - base, (end - base).min(BLOCK));
        slot(hv::SLOT_SCRATCH_EPT).move_(&keep(hv::SLOT_KEEP_EPT, b))?;
        let r = check(sel4::with_ipc_buffer_mut(|i| {
            i.inner_mut().seL4_ARM_Page_CleanInvalidate_Data(hv::SLOT_SCRATCH_EPT, start, stop)
        }))
        .and_then(|()| unify(hv::SLOT_SCRATCH_EPT, start, stop));
        keep(hv::SLOT_KEEP_EPT, b).move_(&slot(hv::SLOT_SCRATCH_EPT))?;
        r?;
        at = base + stop;
    }
    Ok(())
}

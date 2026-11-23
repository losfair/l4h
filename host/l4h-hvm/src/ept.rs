//! Mapping guest RAM as it is first touched (DESIGN.md §5.11): a 2 MiB
//! block's Untyped, which memd gave us at the block's index of the block
//! CNode, becomes a large frame, mapped in the guest's EPT and, through a
//! copy, here at RAM_VA + its GPA.  vmmgr made the tables both go in, and
//! mapped the boot blocks itself.  Only the I/O thread maps (a vCPU thread
//! asks it, hvm::call::Map): one thread, so no lock, and no thread that
//! waits for another kept off its core (sync.rs).

use l4h_rt::host::hvm as hv;
use l4h_rt::{cap, sel4};
use sel4::{CapRights, ObjectBlueprint, VmAttributes, cap_type};

use crate::guest::GuestMem;
use crate::sync::Global;

/// What mapping needs, from before the machine (crate::vm) exists: the
/// kernel's loading maps blocks too.
struct Ctx {
    mem: GuestMem,
    radix: usize,
    guest: u32,
}

static CTX: Global<Ctx> = Global::new();

/// Set up mapping (once, on the I/O thread, before anything is loaded).
pub fn init(mem: GuestMem, block_radix: u32, guest: u32) {
    CTX.set(Ctx { mem, radix: block_radix as usize, guest });
}

const LARGE_PAGE: ObjectBlueprint = ObjectBlueprint::Arch(sel4::ObjectBlueprintX86::LargePage);

fn slot(c: u64) -> sel4::AbsoluteCPtr {
    cap::<cap_type::CNode>(l4h_rt::host::SLOT_CNODE).absolute_cptr(cap::<cap_type::Null>(c))
}

fn keep(cnode: u64, b: usize) -> sel4::AbsoluteCPtr {
    cap::<cap_type::CNode>(cnode).absolute_cptr_from_bits_with_depth(b as u64, CTX.get().radix)
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
    let r = (|| -> sel4::Result<()> {
        slot(hv::SLOT_SCRATCH_UT).move_(&keep(hv::SLOT_BLOCKS, b))?;
        let ut = cap::<cap_type::Untyped>(hv::SLOT_SCRATCH_UT);
        let dest = cap::<cap_type::CNode>(l4h_rt::host::SLOT_CNODE).absolute_cptr_for_self();
        let made = ut.untyped_retype(&LARGE_PAGE, &dest, hv::SLOT_SCRATCH_EPT as usize, 1);
        // The Untyped goes back where memd revokes it, used or not.
        keep(hv::SLOT_BLOCKS, b).move_(&slot(hv::SLOT_SCRATCH_UT))?;
        made?;
        slot(hv::SLOT_SCRATCH_HVM).copy(&slot(hv::SLOT_SCRATCH_EPT), CapRights::read_write())?;
        let ept = cap::<cap_type::LargePage>(hv::SLOT_SCRATCH_EPT);
        ept.ept_frame_map(cap::<cap_type::EPTPML4>(hv::SLOT_EPT), gpa as usize, CapRights::read_write(), VmAttributes::EPT_DEFAULT)?;
        let here = cap::<cap_type::LargePage>(hv::SLOT_SCRATCH_HVM);
        here.frame_map(cap::<cap_type::VSpace>(l4h_rt::host::SLOT_VSPACE), hv::RAM_VA + gpa as usize, CapRights::read_write(),
            VmAttributes::DEFAULT)?;
        keep(hv::SLOT_KEEP_EPT, b).move_(&slot(hv::SLOT_SCRATCH_EPT))?;
        keep(hv::SLOT_KEEP_HVM, b).move_(&slot(hv::SLOT_SCRATCH_HVM))?;
        Ok(())
    })();
    match r {
        Ok(()) => {
            mem.set_mapped(b);
            true
        }
        Err(e) => {
            l4h_rt::log!("l4h-hvm: guest {}: RAM block {} at {:#x}: {:?}", ctx.guest, b, gpa, e);
            false
        }
    }
}

//! The microkernel-specific guest ABI provider, embedded in this host build.
//! Immutable code is mapped RX in the guest kernel VSpace. Its mutable state
//! and TLS live in the guest's own RAM; no code is mapped in process VSpaces.

use l4h_abi as abi;
use sel4::{CapRights, VmAttributes, cap_type};

use crate::guest::{Guest, abs};
use crate::mem::Alloc;
use crate::vspace::{FRAME_BP, map_frame};
use crate::window::Window;

pub static IMAGE: &[u8] = include_bytes!(env!("L4H_GUEST_PROVIDER"));

pub fn map(g: &mut Guest, alloc: &mut Alloc, win: &mut Window) {
    assert!(IMAGE.len() <= abi::PROVIDER_MAX as usize && IMAGE.len() >= 32);
    for (i, data) in IMAGE.chunks(4096).enumerate() {
        let frame = g.arena.object_cap::<cap_type::Granule>(alloc, FRAME_BP);
        win.with_frame(&abs(frame), |p| unsafe {
            core::ptr::write_bytes(p, 0, 4096);
            core::ptr::copy_nonoverlapping(data.as_ptr(), p, data.len());
        });
        let vspace = g.vspace;
        map_frame(&mut g.ctx(alloc), vspace, frame, abi::PROVIDER_VA as usize + i * 4096,
            CapRights::read_only(), VmAttributes::DEFAULT);
    }
}

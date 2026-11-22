//! No HVM guests: the kernel has no VT-x support, or is not x86_64
//! (hvm.rs).  Nothing here is reached: `available` is false, so the
//! control API refuses HVM guests (ENODEV), and no guest has `Hvm`.

use l4h_host::errno::Errno;

use crate::ctl;
use crate::guest::{DevKind, Guest, GuestConfig};
use crate::mem::Alloc;
use crate::{AsidPools, HostInfo};

pub fn available(_: &HostInfo) -> bool {
    false
}

/// What an HVM guest has (never made here).
pub enum Hvm {}

pub struct Plan {
    pub estimate: usize,
    pub slots: usize,
}

pub fn plan(_: &GuestConfig) -> Option<Plan> {
    None
}

pub fn create(_: usize, _: &GuestConfig, _: &mut Alloc, _: &mut AsidPools, _: &HostInfo, _: &[(usize, usize)])
    -> Result<Guest, Option<Guest>> {
    Err(None)
}

pub fn add_device(_: &mut Guest, _: &mut Alloc, _: DevKind) -> Option<usize> {
    None
}

pub fn load_cost(_: &Guest, _: usize, _: usize) -> Option<(usize, usize)> {
    None
}

pub fn load_ram(_: &mut Guest, _: &mut Alloc, _: usize, _: *const u8, _: usize) -> bool {
    false
}

pub fn boot(_: &mut Guest, _: &mut Alloc, _: (u64, u64), _: (u64, u64), _: u64, _: &[u8]) -> Result<(), Errno> {
    Err(ctl::ENODEV)
}

pub fn start_bytes(_: &Guest) -> usize {
    0
}

pub fn start_slots(_: &Guest) -> usize {
    0
}

pub fn spawn(_: &mut Guest, _: &mut Alloc, _: &mut crate::window::Window, _: &mut AsidPools, _: &HostInfo,
    _: crate::sched::budget::Plan) -> sel4::Result<crate::component::Component> {
    Err(sel4::Error::IllegalOperation)
}

pub fn signal(_: &Guest, _: &mut Alloc) {}

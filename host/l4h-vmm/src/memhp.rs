//! The memory device (L4H_DEV_MEM, DESIGN.md §8.5): the guest's hotplug
//! target and state in its device page, and its plug and unplug requests
//! (in the page too), which go to l4h-memd.  memd checks every request against
//! its own state; this only relays them.

use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{Ordering, fence};

use l4h_abi as abi;
use l4h_rt::host::{self, memd};
use l4h_rt::{cap, sel4};
use sel4::cap_type;

use crate::guest::Vcpus;

const EIO: i64 = 5;

pub struct MemDev {
    page: *mut abi::MemPage,
    event: u32,
    count: usize,
}

fn mr(i: usize) -> u64 {
    sel4::with_ipc_buffer(|b| b.msg_regs()[i])
}

fn set_mr(i: usize, v: u64) {
    sel4::with_ipc_buffer_mut(|b| b.msg_regs_mut()[i] = v)
}

/// Call memd; its errno, or Err(()) if memd failed (its keeper answers
/// u64::MAX).
fn call(label: u64, args: &[u64]) -> Result<u64, ()> {
    for (i, &a) in args.iter().enumerate() {
        set_mr(i, a);
    }
    cap::<cap_type::Endpoint>(host::VMM_SLOT_MEMD_EP).call(sel4::MessageInfo::new(label, 0, 0, args.len()));
    match mr(0) {
        u64::MAX => Err(()),
        e => Ok(e),
    }
}

impl MemDev {
    pub fn new(page_va: usize, event: u32, count: usize) -> Self {
        MemDev { page: page_va as *mut abi::MemPage, event, count }
    }

    /// Copy memd's state of the guest into the device page.  Returns
    /// whether the target changed.
    pub fn refresh(&mut self) -> bool {
        if call(memd::MEMD_HP_STATE, &[]) != Ok(0) {
            return false;
        }
        let (target, plugged) = (mr(1) as u32, mr(2) as u32);
        let map: [u64; memd::HP_MAP_WORDS] = core::array::from_fn(|w| mr(3 + w));
        unsafe {
            let p = self.page;
            let changed = addr_of_mut!((*p).target).read_volatile() != target;
            addr_of_mut!((*p).target).write_volatile(target);
            addr_of_mut!((*p).plugged).write_volatile(plugged);
            addr_of_mut!((*p).plugged_map).write_volatile(map);
            fence(Ordering::Release);
            let g = addr_of_mut!((*p).generation).read_volatile();
            addr_of_mut!((*p).generation).write_volatile(g.wrapping_add(1));
            changed
        }
    }

    /// l4h-root changed the target: tell the guest.
    pub fn target_changed(&mut self, vcpus: &Vcpus) {
        self.refresh();
        vcpus.raise(0, self.event);
    }

    /// A plug or unplug request: the result as -errno.
    fn serve(&mut self, op: u64, m: u64) -> i64 {
        let label = match op {
            abi::MEM_PLUG => memd::MEMD_HP_PLUG,
            abi::MEM_UNPLUG => memd::MEMD_HP_UNPLUG,
            _ => return -22,
        };
        if m >= self.count as u64 {
            return -22;
        }
        let r = match call(label, &[m]) {
            Ok(e) => -(e as i64),
            Err(()) => return -EIO,
        };
        self.refresh();
        r
    }

    /// The guest kicked: serve the request in the device page if it is a
    /// new one, and raise the device's event.
    pub fn request(&mut self, vcpus: &Vcpus) {
        let p = self.page;
        let seq = unsafe { addr_of!((*p).req_seq).read_volatile() };
        if seq == unsafe { addr_of!((*p).done_seq).read_volatile() } {
            return;
        }
        fence(Ordering::Acquire);
        let (op, m) = unsafe { (addr_of!((*p).req_op).read_volatile(), addr_of!((*p).req_block).read_volatile()) };
        let r = self.serve(op as u64, m as u64);
        unsafe {
            addr_of_mut!((*p).result).write_volatile(r);
            fence(Ordering::Release);
            addr_of_mut!((*p).done_seq).write_volatile(seq);
        }
        vcpus.raise(0, self.event);
    }
}

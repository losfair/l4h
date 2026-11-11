//! The memory device (L4H_DEV_MEM, DESIGN.md §8.5): the guest's hotplug
//! target and state in its device page, and its plug and unplug requests
//! (in the page too), which go to l4h-memd.  memd checks every request against
//! its own state; this only relays them.

use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{Ordering, fence};

use l4h_abi as abi;
use l4h_rt::ipc::Endpoint;
use l4h_rt::host::memd::call::Client;
use l4h_rt::host;


use crate::guest::Vcpus;


pub struct MemDev {
    page: *mut abi::MemPage,
    event: u32,
    count: usize,
    /// The page is behind memd's state: memd did not answer the last
    /// `hp_state` (EBUSY: this VMM's calls came faster than memd takes
    /// them, memd::HP_CALLS; or memd has failed).
    stale: bool,
    /// A transient EBUSY gets a timed retry even if the guest is idle at
    /// its old target. Other errors wait for an explicit device signal.
    retry_at: u64,
    retry_ticks: u64,
}

/// memd's endpoint for this guest (l4h_host::memd::call, badged as
/// Sender::Vmm of the guest).
fn memd() -> Endpoint<host::memd::call::Proto> {
    Endpoint::of(&host::wiring::VMM_MEMD, host::wiring::p::Vmm, 0)
}

impl MemDev {
    pub fn new(page_va: usize, event: u32, count: usize, hz: u64) -> Self {
        let retry_ticks = hz.saturating_mul(host::memd::HP_CALL_GAP_US).div_ceil(1_000_000).max(1);
        MemDev { page: page_va as *mut abi::MemPage, event, count, stale: false, retry_at: 0, retry_ticks }
    }

    /// Copy memd's state of the guest into the device page.  Returns
    /// whether the target changed.  If memd does not answer with it, the
    /// page stays as it was, which is how the guest last saw it, and is
    /// marked stale.
    pub fn refresh(&mut self) -> bool {
        let st = match memd().hp_state() {
            Ok(st) => st,
            Err(e) => {
                self.stale = true;
                self.retry_at = if e == host::errno::EBUSY {
                    host::ticks::now().saturating_add(self.retry_ticks)
                } else { 0 };
                return false;
            }
        };
        self.stale = false;
        self.retry_at = 0;
        let (target, plugged, map) = (st.target as u32, st.plugged as u32, st.map);
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

    pub fn deadline(&self) -> u64 {
        self.retry_at
    }

    /// Called on each VMM turn, including the retry timer's wakeup. A
    /// failed refresh schedules its next attempt without busy polling.
    pub fn retry(&mut self, vcpus: &Vcpus) {
        if self.retry_at != 0 && host::ticks::now() >= self.retry_at && self.refresh() {
            vcpus.raise(0, self.event);
        }
    }

    /// l4h-vmmgr changed the target: tell the guest.
    pub fn target_changed(&mut self, vcpus: &Vcpus) {
        self.refresh();
        vcpus.raise(0, self.event);
    }

    /// A plug or unplug request: the result as -errno.
    fn serve(&mut self, op: u64, m: u64) -> i64 {
        let plug = match op {
            abi::MEM_PLUG => true,
            abi::MEM_UNPLUG => false,
            _ => return host::errno::negative(host::errno::EINVAL),
        };
        if m >= self.count as u64 {
            return host::errno::negative(host::errno::EINVAL);
        }
        let m = m as usize;
        let r = match host::wire::eio_if_failed(if plug { memd().hp_plug(m) } else { memd().hp_unplug(m) }) {
            Ok(()) => 0,
            Err(e) => host::errno::negative(e),
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
            // No new request: the kick is still a turn to bring a stale
            // page up to date, and the guest hears of a target it missed.
            if self.stale && self.refresh() {
                vcpus.raise(0, self.event);
            }
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

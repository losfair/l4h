//! Control completions after vmmgr fails. Keep only the already-mapped
//! pages and a prebadged notification: Guest and Alloc may be mid-update.

use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, Ordering, fence};

use l4h_abi as abi;
use l4h_rt::{FailureHandler, cap, sel4};

pub static HANDLER: FailureHandler = FailureHandler {
    notification_badges: l4h_host::badges::vmmgr::SIGNALS,
    notified: complete,
};

struct Control {
    page: AtomicPtr<u8>,
    events: AtomicPtr<abi::EventPage>,
    event: AtomicU32,
    notify: AtomicU64,
}

static CONTROLS: [Control; crate::MAX_GUESTS] = [const { Control {
    page: AtomicPtr::new(core::ptr::null_mut()),
    events: AtomicPtr::new(core::ptr::null_mut()),
    event: AtomicU32::new(0),
    notify: AtomicU64::new(0),
} }; crate::MAX_GUESTS];

/// Publish only after all resources exist, before the guest can run.
///
/// # Safety
/// The pages and the BADGE_EVENT notification must stay valid until
/// `remove(id)`. Only the main thread may register or remove a guest;
/// remove any previous registration before reusing its id.
pub unsafe fn register(id: usize, page: *mut u8, events: *mut abi::EventPage, event: u32, notify: u64) {
    let c = &CONTROLS[id];
    c.events.store(events, Ordering::Relaxed);
    c.event.store(event, Ordering::Relaxed);
    c.notify.store(notify, Ordering::Relaxed);
    c.page.store(page, Ordering::Release);
}

/// Stop serving the guest before revoking its pages or notification.
pub fn remove(id: usize) {
    CONTROLS[id].page.store(core::ptr::null_mut(), Ordering::Release);
}

fn complete(badge: u64) {
    if badge != 0 && badge & l4h_host::badges::vmmgr::CTL_KICK == 0 {
        return;
    }
    for c in &CONTROLS {
        let page = c.page.load(Ordering::Acquire);
        if page.is_null() {
            continue;
        }
        unsafe {
            let sync = page.add(abi::CTL_SYNC_OFF).cast::<abi::CtlSync>();
            let seq = addr_of!((*sync).seq).read_volatile();
            if seq != addr_of!((*sync).done).read_volatile() {
                fence(Ordering::Acquire);
                page.add(abi::CTL_RESP_OFF).cast::<abi::CtlResp>().write_volatile(abi::CtlResp {
                    status: -5, // EIO
                    vals: [0; 6],
                    data: [0; abi::CTL_DATA_MAX],
                });
                fence(Ordering::Release);
                addr_of_mut!((*sync).done).write_volatile(seq);
            }
            let events = c.events.load(Ordering::Relaxed);
            let event = c.event.load(Ordering::Relaxed) as usize;
            let word = &*addr_of!((*events).pending[event / 64]).cast::<AtomicU64>();
            word.fetch_or(1 << (event % 64), Ordering::SeqCst);
        }
        // Also wake a request completed just before failure, including a
        // failure between setting the event bit and signalling the guest.
        cap::<sel4::cap_type::Notification>(c.notify.load(Ordering::Relaxed)).signal();
    }
}

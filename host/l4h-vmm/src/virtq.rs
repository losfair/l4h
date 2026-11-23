//! Device side of a split virtqueue in guest memory.

use core::sync::atomic::{Ordering, fence};

use l4h_rt::host::fixed::ArrayVec;

use crate::guest::GuestMem;

pub const VIRTQ_DESC_F_NEXT: u16 = 1;
pub const VIRTQ_DESC_F_WRITE: u16 = 2;
pub const VIRTQ_DESC_F_INDIRECT: u16 = 4;
const VIRTQ_AVAIL_F_NO_INTERRUPT: u16 = 1;
const VIRTQ_USED_F_NO_NOTIFY: u16 = 1;

/// One buffer of a descriptor chain.
#[derive(Clone, Copy, Debug)]
pub struct Buf {
    pub gpa: u64,
    pub len: u32,
    pub write: bool,
}

#[derive(Default)]
pub struct Queue {
    pub ready: bool,
    pub num: u16,
    desc: u64,
    avail: u64,
    used: u64,
    last_avail: u16,
    used_idx: u16,
    published_used: u16,
    /// VIRTIO_RING_F_EVENT_IDX negotiated (`set_event_idx`): the driver's
    /// used_event decides interrupts, our avail_event its notifications.
    event_idx: bool,
    /// The used index at the last interrupt decision (event index).
    signalled_used: Option<u16>,
}

#[derive(Debug)]
pub enum ChainError {
    BadAddress,
    /// Longer than the queue size (which a loop always is).
    TooLong,
}

impl Queue {
    /// Activate the queue; addresses must lie in the I/O pool and be aligned
    /// as the virtio specification requires.
    pub fn setup(&mut self, mem: &GuestMem, num: u32, num_max: u32, desc: u64, avail: u64, used: u64) -> bool {
        if num == 0 || num > num_max || !num.is_power_of_two() {
            return false;
        }
        if desc % 16 != 0 || avail % 2 != 0 || used % 4 != 0 {
            return false;
        }
        let n = num as u64;
        if !mem.valid(desc, 16 * n) || !mem.valid(avail, 6 + 2 * n) || !mem.valid(used, 6 + 8 * n) {
            return false;
        }
        *self = Queue {
            ready: true, num: num as u16, desc, avail, used, last_avail: 0, used_idx: 0, published_used: 0,
            event_idx: false, signalled_used: None,
        };
        true
    }

    /// Whether VIRTIO_RING_F_EVENT_IDX was negotiated for this queue.
    pub fn set_event_idx(&mut self, on: bool) {
        self.event_idx = on;
        self.signalled_used = None;
    }

    pub fn reset(&mut self) {
        *self = Queue::default();
    }

    /// Next available chain head, if any.
    pub fn pop(&mut self, mem: &GuestMem) -> Option<u16> {
        if !self.ready {
            return None;
        }
        let idx = mem.read::<u16>(self.avail + 2);
        if idx == self.last_avail {
            return None;
        }
        fence(Ordering::Acquire);
        let slot = (self.last_avail % self.num) as u64;
        let head = mem.read::<u16>(self.avail + 4 + 2 * slot);
        self.last_avail = self.last_avail.wrapping_add(1);
        Some(head)
    }

    /// Collect the buffers of the chain starting at `head`.  A driver must
    /// not offer a chain longer than the queue size, indirect descriptors
    /// included (virtio 1.x §2.7.5.3.1), so one that is longer, or longer
    /// than `out` holds, is refused; this also ends a chain that loops.
    pub fn chain<const N: usize>(&self, mem: &GuestMem, head: u16, out: &mut ArrayVec<Buf, N>) -> Result<(), ChainError> {
        out.clear();
        if head >= self.num {
            return Err(ChainError::BadAddress);
        }
        let (mut table, mut size) = (self.desc, self.num as u64);
        let mut i = head as u64;
        let mut indirect = false;
        let max = (self.num as usize).min(N);
        loop {
            let d = table + 16 * i;
            let addr = mem.read::<u64>(d);
            let len = mem.read::<u32>(d + 8);
            let flags = mem.read::<u16>(d + 12);
            let next = mem.read::<u16>(d + 14);
            if flags & VIRTQ_DESC_F_INDIRECT != 0 {
                if indirect || addr % 16 != 0 || len % 16 != 0 || len == 0 || !mem.valid(addr, len as u64) {
                    return Err(ChainError::BadAddress);
                }
                table = addr;
                size = len as u64 / 16;
                i = 0;
                indirect = true;
                continue;
            }
            if !mem.valid(addr, len as u64) {
                return Err(ChainError::BadAddress);
            }
            if out.len() == max {
                return Err(ChainError::TooLong);
            }
            let _ = out.push(Buf { gpa: addr, len, write: flags & VIRTQ_DESC_F_WRITE != 0 });
            if flags & VIRTQ_DESC_F_NEXT == 0 {
                return Ok(());
            }
            i = next as u64;
            if i >= size {
                return Err(ChainError::BadAddress);
            }
        }
    }

    /// Return a chain to the driver.
    pub fn push(&mut self, mem: &GuestMem, head: u16, written: u32) {
        self.push_deferred(mem, head, written);
        self.publish_used(mem);
    }

    /// Stage a completion; the caller publishes the whole batch before
    /// checking interrupt suppression or returning to the event loop.
    pub fn push_deferred(&mut self, mem: &GuestMem, head: u16, written: u32) {
        let slot = (self.used_idx % self.num) as u64;
        mem.write::<u32>(self.used + 4 + 8 * slot, head as u32);
        mem.write::<u32>(self.used + 8 + 8 * slot, written);
        self.used_idx = self.used_idx.wrapping_add(1);
    }

    pub fn publish_used(&mut self, mem: &GuestMem) {
        if self.published_used != self.used_idx {
            fence(Ordering::Release);
            mem.write::<u16>(self.used + 2, self.used_idx);
            self.published_used = self.used_idx;
        }
    }

    pub fn used_idx(&self) -> u16 {
        self.used_idx
    }

    /// Whether the driver wants an interrupt for used buffers (without the
    /// event index).
    pub fn wants_interrupt(&self, mem: &GuestMem) -> bool {
        fence(Ordering::SeqCst);
        mem.read::<u16>(self.avail) & VIRTQ_AVAIL_F_NO_INTERRUPT == 0
    }

    /// Whether the driver wants an interrupt for the used buffers published
    /// since the last call: with the event index, when the used index has
    /// passed its used_event since then (virtio 1.x, 2.7.10), as vhost's
    /// signalled_used; otherwise unless it set NO_INTERRUPT.
    pub fn should_interrupt(&mut self, mem: &GuestMem) -> bool {
        if !self.event_idx {
            return self.wants_interrupt(mem);
        }
        fence(Ordering::SeqCst);
        let new = self.published_used;
        let Some(old) = self.signalled_used.replace(new) else { return true };
        let event = mem.read::<u16>(self.avail + 4 + 2 * self.num as u64);
        need_event(event, new, old)
    }

    /// The device stops asking for notifications while it works through the
    /// queue (without the event index: VIRTQ_USED_F_NO_NOTIFY; with it,
    /// avail_event stays where it was, behind what the driver adds).
    pub fn disable_notify(&mut self, mem: &GuestMem) {
        if self.ready && !self.event_idx {
            mem.write::<u16>(self.used, VIRTQ_USED_F_NO_NOTIFY);
        }
    }

    /// The device is about to wait for a notification: ask for one at the
    /// next available entry.  Whether entries came meanwhile, which the
    /// caller then takes without one (they may have been added while
    /// notifications were off).
    pub fn enable_notify(&mut self, mem: &GuestMem) -> bool {
        if !self.ready {
            return false;
        }
        if self.event_idx {
            mem.write::<u16>(self.used + 4 + 8 * self.num as u64, self.last_avail);
        } else {
            mem.write::<u16>(self.used, 0);
        }
        fence(Ordering::SeqCst);
        mem.read::<u16>(self.avail + 2) != self.last_avail
    }
}

/// virtio's vring_need_event: whether the index moving from `old` to `new`
/// passed `event`.
pub fn need_event(event: u16, new: u16, old: u16) -> bool {
    new.wrapping_sub(event).wrapping_sub(1) < new.wrapping_sub(old)
}

#[cfg(test)]
mod event_tests {
    use super::need_event;

    #[test]
    fn need_event_matches_virtio() {
        assert!(need_event(4, 5, 4), "passing it");
        assert!(!need_event(9, 5, 4), "not yet");
        assert!(need_event(4, 9, 1), "passed within a batch");
        assert!(!need_event(0, 5, 4), "passed before");
        assert!(need_event(0xffff, 1, 0xfffe), "across the wrap");
    }
}

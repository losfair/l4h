//! Device side of a split virtqueue in guest memory.

use core::sync::atomic::{Ordering, fence};

use l4h_rt::host::fixed::ArrayVec;

use crate::guest::GuestMem;

pub const VIRTQ_DESC_F_NEXT: u16 = 1;
pub const VIRTQ_DESC_F_WRITE: u16 = 2;
pub const VIRTQ_DESC_F_INDIRECT: u16 = 4;
const VIRTQ_AVAIL_F_NO_INTERRUPT: u16 = 1;

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
        *self = Queue { ready: true, num: num as u16, desc, avail, used, last_avail: 0, used_idx: 0, published_used: 0 };
        true
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

    /// Whether the driver wants an interrupt for used buffers.
    pub fn wants_interrupt(&self, mem: &GuestMem) -> bool {
        fence(Ordering::SeqCst);
        mem.read::<u16>(self.avail) & VIRTQ_AVAIL_F_NO_INTERRUPT == 0
    }
}

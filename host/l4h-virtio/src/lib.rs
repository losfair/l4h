//! Driver side of a virtio 1.x PCI device ("modern" interface) and its
//! split virtqueues, shared by blkd and netd.  Split virtqueues of legacy
//! (0.9.5) devices are supported too; their registers are I/O ports, which
//! the driver accesses itself.  The device structures are
//! mapped uncached by l4h-root; DMA memory is physically contiguous.

#![no_std]

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::Ordering;
#[cfg(not(target_arch = "aarch64"))]
use core::sync::atomic::fence;

/// Order coherent DMA memory against device registers and completion writes.
/// ARM devices can sit outside the CPU inner-shareable domain.
pub fn dma_fence(ordering: Ordering) {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        match ordering {
            Ordering::Release => core::arch::asm!("dmb oshst", options(nostack)),
            Ordering::Acquire => core::arch::asm!("dmb oshld", options(nostack)),
            _ => core::arch::asm!("dmb osh", options(nostack)),
        }
    }
    #[cfg(not(target_arch = "aarch64"))]
    fence(ordering);
}

pub const STATUS_ACK: u8 = 1;
pub const STATUS_DRIVER: u8 = 2;
pub const STATUS_DRIVER_OK: u8 = 4;
pub const STATUS_FEATURES_OK: u8 = 8;
pub const STATUS_FAILED: u8 = 128;

pub const F_VERSION_1: u64 = 1 << 32;
pub const F_INDIRECT_DESC: u64 = 1 << 28;
/// The device's DMA goes through the platform's IOMMU.  Host drivers
/// accept it when offered: the addresses they give are physical ones,
/// which root maps 1:1 in the device's IOMMU domain (l4h-root iommu.rs).
pub const F_ACCESS_PLATFORM: u64 = 1 << 33;

pub const DESC_F_NEXT: u16 = 1;
pub const DESC_F_WRITE: u16 = 2;
pub const DESC_F_INDIRECT: u16 = 4;

pub const NO_VECTOR: u16 = 0xffff;

/// Registers of a legacy virtio PCI device (I/O BAR 0), with MSI-X on.
pub mod legacy {
    pub const DEVICE_FEATURES: u16 = 0x00;
    pub const GUEST_FEATURES: u16 = 0x04;
    pub const QUEUE_PFN: u16 = 0x08;
    pub const QUEUE_SIZE: u16 = 0x0c;
    pub const QUEUE_SELECT: u16 = 0x0e;
    pub const QUEUE_NOTIFY: u16 = 0x10;
    pub const STATUS: u16 = 0x12;
    pub const CONFIG_VECTOR: u16 = 0x14;
    pub const QUEUE_VECTOR: u16 = 0x16;
    pub const DEVICE_CONFIG: u16 = 0x18;
}

// Common configuration structure offsets.
const DEVICE_FEATURE_SELECT: usize = 0x00;
const DEVICE_FEATURE: usize = 0x04;
const DRIVER_FEATURE_SELECT: usize = 0x08;
const DRIVER_FEATURE: usize = 0x0c;
const MSIX_CONFIG: usize = 0x10;
const DEVICE_STATUS: usize = 0x14;
const QUEUE_SELECT: usize = 0x16;
const QUEUE_SIZE: usize = 0x18;
const QUEUE_MSIX_VECTOR: usize = 0x1a;
const QUEUE_ENABLE: usize = 0x1c;
const QUEUE_NOTIFY_OFF: usize = 0x1e;
const QUEUE_DESC: usize = 0x20;
const QUEUE_DRIVER: usize = 0x28;
const QUEUE_DEVICE: usize = 0x30;

#[derive(Clone, Copy)]
pub struct Mmio(pub usize);

impl Mmio {
    pub fn r8(&self, off: usize) -> u8 {
        unsafe { read_volatile((self.0 + off) as *const u8) }
    }
    pub fn r16(&self, off: usize) -> u16 {
        unsafe { read_volatile((self.0 + off) as *const u16) }
    }
    pub fn r32(&self, off: usize) -> u32 {
        unsafe { read_volatile((self.0 + off) as *const u32) }
    }
    pub fn r64(&self, off: usize) -> u64 {
        self.r32(off) as u64 | ((self.r32(off + 4) as u64) << 32)
    }
    pub fn w8(&self, off: usize, v: u8) {
        unsafe { write_volatile((self.0 + off) as *mut u8, v) }
    }
    pub fn w16(&self, off: usize, v: u16) {
        unsafe { write_volatile((self.0 + off) as *mut u16, v) }
    }
    pub fn w32(&self, off: usize, v: u32) {
        unsafe { write_volatile((self.0 + off) as *mut u32, v) }
    }
    pub fn w64(&self, off: usize, v: u64) {
        self.w32(off, v as u32);
        self.w32(off + 4, (v >> 32) as u32);
    }
}

/// Bump allocator over the DMA region.
pub struct Dma {
    va: usize,
    paddr: u64,
    size: usize,
    used: usize,
}

impl Dma {
    pub fn new(va: usize, paddr: u64, size: usize) -> Self {
        Dma { va, paddr, size, used: 0 }
    }

    /// Bytes not yet allocated.
    pub fn remaining(&self) -> usize {
        self.size - self.used
    }

    /// Zeroed memory: (virtual address, physical address).
    pub fn alloc(&mut self, size: usize, align: usize) -> (usize, u64) {
        let off = (self.used + align - 1) & !(align - 1);
        // Sizes can derive from device registers: no `off + size` to wrap.
        assert!(off <= self.size && size <= self.size - off, "out of DMA memory");
        self.used = off + size;
        unsafe { core::ptr::write_bytes((self.va + off) as *mut u8, 0, size) };
        (self.va + off, self.paddr + off as u64)
    }
}

pub struct Device {
    pub common: Mmio,
    pub notify: Mmio,
    pub notify_mult: u32,
    /// Bytes of the notify structure, which every queue's doorbell must be
    /// in: its offset is the device's.
    pub notify_len: usize,
    pub device: Mmio,
}

/// How long a reset waits for the device status to read 0, in
/// milliseconds: a device that works does within a few reads.  A time and
/// not a count of reads, each of which is a round trip to the device or a
/// trap to its hypervisor, and takes anything from 100 ns to many
/// microseconds.
pub const RESET_MS: u64 = 1000;

impl Device {
    /// Reset the device and acknowledge it: false if its status does not
    /// read 0 before `expired` says the time is up (RESET_MS, which the
    /// caller measures: l4h_rt::timeout_ms): the device has failed, and
    /// the driver must not go on with it.  The status is read once at
    /// least.
    #[must_use]
    pub fn reset(&self, mut expired: impl FnMut() -> bool) -> bool {
        self.common.w8(DEVICE_STATUS, 0);
        loop {
            if self.common.r8(DEVICE_STATUS) == 0 {
                self.common.w8(DEVICE_STATUS, STATUS_ACK | STATUS_DRIVER);
                return true;
            }
            if expired() {
                return false;
            }
            core::hint::spin_loop();
        }
    }

    pub fn features(&self) -> u64 {
        self.common.w32(DEVICE_FEATURE_SELECT, 0);
        let lo = self.common.r32(DEVICE_FEATURE) as u64;
        self.common.w32(DEVICE_FEATURE_SELECT, 1);
        let hi = self.common.r32(DEVICE_FEATURE) as u64;
        lo | (hi << 32)
    }

    /// Negotiate `features`; false if the device rejects them.
    pub fn set_features(&self, features: u64) -> bool {
        self.common.w32(DRIVER_FEATURE_SELECT, 0);
        self.common.w32(DRIVER_FEATURE, features as u32);
        self.common.w32(DRIVER_FEATURE_SELECT, 1);
        self.common.w32(DRIVER_FEATURE, (features >> 32) as u32);
        let s = self.common.r8(DEVICE_STATUS);
        self.common.w8(DEVICE_STATUS, s | STATUS_FEATURES_OK);
        self.common.r8(DEVICE_STATUS) & STATUS_FEATURES_OK != 0
    }

    pub fn driver_ok(&self) {
        let s = self.common.r8(DEVICE_STATUS);
        self.common.w8(DEVICE_STATUS, s | STATUS_DRIVER_OK);
    }

    pub fn fail(&self) {
        let s = self.common.r8(DEVICE_STATUS);
        self.common.w8(DEVICE_STATUS, s | STATUS_FAILED);
    }

    /// Set up queue `idx` with at most `max` entries, interrupting on MSI-X
    /// vector `vector`.
    pub fn setup_queue(&self, dma: &mut Dma, idx: u16, max: u16, vector: u16) -> Option<Virtq> {
        self.common.w16(MSIX_CONFIG, NO_VECTOR);
        self.common.w16(QUEUE_SELECT, idx);
        let dev_max = self.common.r16(QUEUE_SIZE);
        if dev_max == 0 {
            return None;
        }
        // Queue sizes need not be powers of two in virtio 1.x split rings,
        // but keep it simple.
        let mut n = dev_max.min(max);
        while !n.is_power_of_two() {
            n &= n - 1;
        }
        self.common.w16(QUEUE_SIZE, n);
        let (desc_va, desc_pa) = dma.alloc(16 * n as usize, 4096);
        let (avail_va, avail_pa) = dma.alloc(6 + 2 * n as usize, 4096);
        let (used_va, used_pa) = dma.alloc(6 + 8 * n as usize, 4096);
        self.common.w64(QUEUE_DESC, desc_pa);
        self.common.w64(QUEUE_DRIVER, avail_pa);
        self.common.w64(QUEUE_DEVICE, used_pa);
        self.common.w16(QUEUE_MSIX_VECTOR, vector);
        if self.common.r16(QUEUE_MSIX_VECTOR) != vector {
            return None;
        }
        // Both factors are the device's (16 and 32 bits: no overflow), and
        // the driver writes the doorbell: inside the notify structure.
        let notify_off = self.common.r16(QUEUE_NOTIFY_OFF) as usize * self.notify_mult as usize;
        if notify_off.checked_add(2).is_none_or(|end| end > self.notify_len) {
            return None;
        }
        self.common.w16(QUEUE_ENABLE, 1);
        Some(Virtq {
            idx,
            num: n,
            desc: desc_va,
            avail: avail_va,
            used: used_va,
            notify: Some(Mmio(self.notify.0 + notify_off)),
            avail_idx: 0,
            last_used: 0,
        })
    }
}

/// A split virtqueue owned by the driver.
pub struct Virtq {
    pub idx: u16,
    pub num: u16,
    desc: usize,
    avail: usize,
    used: usize,
    notify: Option<Mmio>,
    avail_idx: u16,
    last_used: u16,
}

/// Bytes of a legacy virtqueue of `num` entries: descriptors and available
/// ring, then the used ring at the next 4 KiB boundary.
pub fn legacy_ring_size(num: u16) -> usize {
    let n = num as usize;
    (16 * n + 6 + 2 * n).next_multiple_of(4096) + (6 + 8 * n).next_multiple_of(4096)
}

impl Virtq {
    /// Queue `idx` of a legacy device, in the zeroed, page-aligned
    /// `legacy_ring_size(num)` bytes at `va`.  The driver notifies the
    /// device itself (`notify` does nothing).
    pub fn legacy(idx: u16, num: u16, va: usize) -> Self {
        let n = num as usize;
        Virtq {
            idx,
            num,
            desc: va,
            avail: va + 16 * n,
            used: va + (16 * n + 6 + 2 * n).next_multiple_of(4096),
            notify: None,
            avail_idx: 0,
            last_used: 0,
        }
    }

    pub fn set_desc(&self, i: u16, addr: u64, len: u32, flags: u16, next: u16) {
        let d = Mmio(self.desc + 16 * i as usize);
        d.w64(0, addr);
        d.w32(8, len);
        d.w16(12, flags);
        d.w16(14, next);
    }

    /// Make the chain starting at `head` available (without notifying).
    pub fn submit(&mut self, head: u16) {
        let a = Mmio(self.avail);
        a.w16(4 + 2 * (self.avail_idx % self.num) as usize, head);
        dma_fence(Ordering::Release);
        self.avail_idx = self.avail_idx.wrapping_add(1);
        a.w16(2, self.avail_idx);
    }

    pub fn notify(&self) {
        dma_fence(Ordering::SeqCst);
        if let Some(n) = self.notify {
            n.w16(0, self.idx);
        }
    }

    /// Ask the device for an interrupt per used buffer, or not
    /// (VIRTQ_AVAIL_F_NO_INTERRUPT).  A driver draining the queue anyway
    /// turns them off; after turning them on again it must re-check
    /// `has_used` for buffers used in between.
    pub fn set_interrupts(&self, on: bool) {
        Mmio(self.avail).w16(0, if on { 0 } else { 1 });
        dma_fence(Ordering::SeqCst);
    }

    /// Whether the device wants to hear of new buffers: it sets
    /// VIRTQ_USED_F_NO_NOTIFY while it is processing the queue anyway.
    pub fn wants_notify(&self) -> bool {
        dma_fence(Ordering::SeqCst);
        Mmio(self.used).r16(0) & 1 == 0
    }

    pub fn has_used(&self) -> bool {
        dma_fence(Ordering::SeqCst);
        Mmio(self.used).r16(2) != self.last_used
    }

    /// Next used element: (id, written length).
    pub fn pop_used(&mut self) -> Option<(u32, u32)> {
        let u = Mmio(self.used);
        if u.r16(2) == self.last_used {
            return None;
        }
        dma_fence(Ordering::Acquire);
        let slot = (self.last_used % self.num) as usize;
        let id = u.r32(4 + 8 * slot);
        let len = u.r32(8 + 8 * slot);
        self.last_used = self.last_used.wrapping_add(1);
        Some((id, len))
    }
}

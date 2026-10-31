//! virtio-l4h device model: the shared register page and its commit ops
//! (L4H_HC_DEV_WRITE), independent of the device type.

use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use l4h_abi as abi;

use crate::guest::{GuestMem, Vcpus};
use crate::virtq::Queue;

pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;
/// Device addresses are subject to platform rules: here, they must lie in
/// the guest's I/O pool.  Required, so that a driver that would put rings
/// or buffers in guest RAM gets no device at all.
pub const VIRTIO_F_ACCESS_PLATFORM: u64 = 1 << 33;
pub const VIRTIO_RING_F_INDIRECT_DESC: u64 = 1 << 28;

const STATUS_FEATURES_OK: u32 = 8;
const STATUS_DRIVER_OK: u32 = 4;
const STATUS_NEEDS_RESET: u32 = 64;
const STATUS_FAILED: u32 = 128;

/// What a device type implements on top of the common model.
pub trait Backend {
    fn device_id(&self) -> u32;
    fn features(&self) -> u64;
    fn num_queues(&self) -> usize;
    fn queue_irqs(&self) -> bool { false }
    fn queue_max(&self, q: usize) -> u32;
    /// Write the device configuration space.
    fn init_config(&self, config: &mut [u8]);
    /// Process available buffers on queue `q`.  Returns true if buffers
    /// were returned to the driver.
    fn kick(&mut self, mem: &GuestMem, queues: &mut [Queue], q: usize) -> bool;
    /// Backend completions arrived.  Returns true if buffers were returned.
    fn complete(&mut self, mem: &GuestMem, queues: &mut [Queue]) -> bool;
    /// Whether `complete` may have work: completions in the backend's
    /// ring, or requests waiting for room in it.  The completion signal is
    /// shared by all devices, so this must be cheap.
    fn pending(&self) -> bool;
    /// Queues that need another attempt after a backend completion.
    fn retry_queues(&self) -> u64 { u64::MAX }
    /// Wait until no request can still access guest memory (devices DMA
    /// into it), dropping the completions: the driver is resetting the
    /// device or a queue and may reuse the buffers once we return.
    fn drain(&mut self) {}
    fn drain_queue(&mut self, _mem: &GuestMem, _queues: &mut [Queue], _q: usize) -> u64 { self.drain(); 0 }
    /// The driver reset the device (after `drain`).
    fn reset(&mut self);
    /// The driver accepted `features` (FEATURES_OK).
    fn features_accepted(&mut self, _features: u64) {}
}

pub struct Device<B: Backend> {
    regs: *mut abi::VirtioRegs,
    pub event: u32,
    queue_event_base: u32,
    next_queue: usize,
    queues: [Queue; abi::VIRTIO_MAX_QUEUES],
    features: u64,
    /// The driver's features were accepted (FEATURES_OK).
    features_ok: bool,
    /// A queue was refused (an address outside the I/O pool, a bad size):
    /// DRIVER_OK fails until the device is reset.
    queue_error: bool,
    pub backend: B,
}

impl<B: Backend> Device<B> {
    pub fn new(page_va: usize, event: u32, backend: B) -> Self {
        let d = Device {
            regs: page_va as *mut abi::VirtioRegs,
            event,
            queue_event_base: if backend.queue_irqs() {
                abi::VIRTIO_QUEUE_EVENT_BASE as u32 + (event - 16) * abi::VIRTIO_QUEUE_IRQS as u32
            } else { 0 },
            next_queue: 0,
            queues: Default::default(),
            features: backend.features() | VIRTIO_F_VERSION_1 | VIRTIO_F_ACCESS_PLATFORM,
            features_ok: false,
            queue_error: false,
            backend,
        };
        unsafe {
            let config = core::slice::from_raw_parts_mut(
                (page_va + abi::VIRTIO_CONFIG_OFF) as *mut u8,
                abi::VIRTIO_CONFIG_SIZE,
            );
            config.fill(0);
            d.backend.init_config(config);
            let r = d.regs;
            addr_of_mut!((*r).version).write_volatile(1);
            addr_of_mut!((*r).queue_event_base).write_volatile(d.queue_event_base);
            for q in 0..abi::VIRTIO_QUEUE_IRQS {
                addr_of_mut!((*r).queue_irq_vcpu[q]).write_volatile(u32::MAX);
            }
            addr_of_mut!((*r).device_id).write_volatile(d.backend.device_id());
            addr_of_mut!((*r).vendor_id).write_volatile(0x6c34);
            addr_of_mut!((*r).device_features).write_volatile(d.features);
            addr_of_mut!((*r).num_queues).write_volatile(d.backend.num_queues() as u32);
            for q in 0..d.backend.num_queues() {
                addr_of_mut!((*r).queues[q].num_max).write_volatile(d.backend.queue_max(q));
            }
            core::sync::atomic::fence(Ordering::Release);
            addr_of_mut!((*r).magic).write_volatile(abi::VIRTIO_MAGIC);
        }
        d
    }

    fn status(&self) -> u32 {
        unsafe { addr_of!((*self.regs).status).read_volatile() }
    }

    fn set_status(&self, s: u32) {
        unsafe { addr_of_mut!((*self.regs).status).write_volatile(s) }
    }

    fn reset(&mut self) {
        self.backend.drain();
        for q in self.queues.iter_mut() {
            q.reset();
        }
        self.backend.reset();
        unsafe {
            let r = self.regs;
            addr_of_mut!((*r).driver_features).write_volatile(0);
            for q in 0..abi::VIRTIO_QUEUE_IRQS {
                addr_of_mut!((*r).queue_irq_vcpu[q]).write_volatile(u32::MAX);
            }
            for q in 0..abi::VIRTIO_MAX_QUEUES {
                addr_of_mut!((*r).queues[q].ready).write_volatile(0);
            }
            self.isr().store(0, Ordering::SeqCst);
            self.kick_word().store(0, Ordering::SeqCst);
        }
        self.next_queue = 0;
        self.features_ok = false;
        self.queue_error = false;
        self.set_status(0);
    }

    fn isr(&self) -> &AtomicU32 {
        unsafe { &*(addr_of!((*self.regs).isr) as *const AtomicU32) }
    }

    fn kick_word(&self) -> &AtomicU64 {
        unsafe { &*(addr_of!((*self.regs).kick) as *const AtomicU64) }
    }

    fn irq_vcpu(&self) -> usize {
        unsafe { addr_of!((*self.regs).irq_vcpu).read_volatile() as usize }
    }

    /// L4H_HC_DEV_WRITE.
    pub fn op(&mut self, mem: &GuestMem, vcpus: &Vcpus, op: u64, a: u64, _b: u64) -> u64 {
        match op {
            abi::VIRTIO_OP_STATUS => {
                let mut s = self.status();
                if s == 0 {
                    self.reset();
                    return 0;
                }
                if s & STATUS_FEATURES_OK != 0 && !self.features_ok {
                    let drv = unsafe { addr_of!((*self.regs).driver_features).read_volatile() };
                    let required = VIRTIO_F_VERSION_1 | VIRTIO_F_ACCESS_PLATFORM;
                    if drv & !self.features != 0 || drv & required != required {
                        s &= !STATUS_FEATURES_OK;
                        self.set_status(s);
                    } else {
                        self.features_ok = true;
                        self.backend.features_accepted(drv);
                    }
                }
                if s & STATUS_DRIVER_OK != 0 && (!self.features_ok || self.queue_error) {
                    // A queue outside the I/O pool, or features never
                    // accepted: the device stays unusable until reset.
                    self.set_status((s & !STATUS_DRIVER_OK) | STATUS_NEEDS_RESET);
                    return u64::MAX;
                }
                if s & STATUS_DRIVER_OK != 0 && s & STATUS_FAILED == 0 {
                    // Buffers may have been queued before DRIVER_OK.
                    self.poll(mem, vcpus, u64::MAX);
                }
                0
            }
            abi::VIRTIO_OP_FEATURES => 0,
            abi::VIRTIO_OP_QUEUE => {
                let q = a as usize;
                if q >= self.backend.num_queues() {
                    return u64::MAX;
                }
                let regs = unsafe { addr_of!((*self.regs).queues[q]).read_volatile() };
                if self.queues[q].ready {
                    // Reconfiguring a live queue: its requests must not
                    // complete into the new one.
                    let completed = self.backend.drain_queue(mem, &mut self.queues, q);
                    for other in 0..self.backend.num_queues() {
                        if completed & (1 << other) != 0 { self.interrupt(mem, vcpus, other); }
                    }
                }
                if regs.ready == 0 {
                    self.queues[q].reset();
                    self.poll(mem, vcpus, u64::MAX);
                    return 0;
                }
                if !self.queues[q].setup(mem, regs.num, self.backend.queue_max(q), regs.desc, regs.driver, regs.device) {
                    unsafe { addr_of_mut!((*self.regs).queues[q].ready).write_volatile(0) };
                    self.queue_error = true;
                    return u64::MAX;
                }
                self.poll(mem, vcpus, u64::MAX);
                0
            }
            abi::VIRTIO_OP_CONFIG => 0,
            abi::VIRTIO_OP_IRQ_VCPU => {
                if a == 0 {
                    if self.irq_vcpu() >= vcpus.n {
                        unsafe { addr_of_mut!((*self.regs).irq_vcpu).write_volatile(0) };
                    }
                } else {
                    let q = (a - 1) as usize;
                    if self.queue_event_base == 0 || q >= abi::VIRTIO_QUEUE_IRQS || q >= self.backend.num_queues() { return u64::MAX; }
                    if unsafe { addr_of!((*self.regs).queue_irq_vcpu[q]).read_volatile() } as usize >= vcpus.n {
                        unsafe { addr_of_mut!((*self.regs).queue_irq_vcpu[q]).write_volatile(0) };
                    }
                }
                0
            }
            _ => u64::MAX,
        }
    }

    fn interrupt(&self, mem: &GuestMem, vcpus: &Vcpus, q: usize) {
        if self.queues[q].ready && self.queues[q].wants_interrupt(mem) {
            let cpu = if self.queue_event_base != 0 && q < abi::VIRTIO_QUEUE_IRQS {
                unsafe { addr_of!((*self.regs).queue_irq_vcpu[q]).read_volatile() }
            } else { u32::MAX };
            if (cpu as usize) < vcpus.n {
                vcpus.raise(cpu as usize, self.queue_event_base + q as u32);
            } else {
                self.isr().fetch_or(abi::VIRTIO_ISR_VRING, Ordering::SeqCst);
                vcpus.raise(self.irq_vcpu().min(vcpus.n - 1), self.event);
            }
        }
    }

    /// The guest kicked: process queues whose kick bits are set (all
    /// queues in `extra`).
    pub fn poll(&mut self, mem: &GuestMem, vcpus: &Vcpus, extra: u64) {
        // The kick signal is shared by all devices: load first, so that the
        // guest's cache line stays shared for a device it did not kick.
        let kick = self.kick_word();
        if extra == 0 && kick.load(Ordering::Relaxed) == 0 {
            return;
        }
        let bits = kick.swap(0, Ordering::SeqCst) | extra;
        if self.status() & STATUS_DRIVER_OK == 0 {
            return;
        }
        let count = self.backend.num_queues();
        let first = self.next_queue % count;
        if self.backend.queue_irqs() { self.next_queue = (first + 1) % count; }
        for offset in 0..count {
            let q = (first + offset) % count;
            if bits & (1 << q) != 0 && self.backend.kick(mem, &mut self.queues, q) {
                self.interrupt(mem, vcpus, q);
            }
        }
    }

    /// A backend signalled completions, maybe this one.
    pub fn complete(&mut self, mem: &GuestMem, vcpus: &Vcpus) {
        if !self.backend.pending() {
            return;
        }
        let used: [u16; abi::VIRTIO_MAX_QUEUES] = core::array::from_fn(|q| self.queues[q].used_idx());
        if self.backend.complete(mem, &mut self.queues) {
            for q in 0..self.backend.num_queues() {
                if self.queues[q].used_idx() != used[q] { self.interrupt(mem, vcpus, q); }
            }
        }
        // A completion must not read every idle queue's shared avail ring.
        self.poll(mem, vcpus, self.backend.retry_queues());
    }
}

//! A virtio 1.x device on PCI ("modern" interface, DESIGN.md §5.11):
//! vendor 0x1af4, device 0x1040 + type, its structures in BAR0 (16 KiB:
//! common configuration, notifications, ISR, device configuration) and its
//! MSI-X table and PBA in BAR2 (8 KiB), with INTx when MSI-X is off.  The
//! I/O thread owns it, and its backend (blk.rs, net.rs): vCPU threads
//! call it for every register but the notifications, which they post in
//! `Kicks` without a call.  No VIRTIO_F_ACCESS_PLATFORM: buffers are
//! guest-physical addresses of RAM, which l4h-hvm maps.  Free of seL4.

use core::sync::atomic::{AtomicU64, Ordering};

use super::apic::Message;
use super::pci::{self, Config};
use crate::guest::GuestMem;
use crate::virtq::Queue;

pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;
pub const VIRTIO_RING_F_INDIRECT_DESC: u64 = 1 << 28;
/// The event index (virtq.rs): notifications and interrupts only when the
/// other side's index passes the event, as Linux drivers and vhost use it.
pub const VIRTIO_RING_F_EVENT_IDX: u64 = 1 << 29;
pub const NO_VECTOR: u16 = 0xffff;
pub const MAX_QUEUES: usize = 8;

pub const BAR0_SIZE: u64 = 0x4000;
pub const BAR2_SIZE: u64 = 0x2000;
const COMMON: u64 = 0x0000;
const COMMON_LEN: u64 = 0x38;
pub const NOTIFY: u64 = 0x1000;
pub const NOTIFY_MULTIPLIER: u64 = 4;
const ISR: u64 = 0x2000;
const DEVICE: u64 = 0x3000;
const DEVICE_LEN: u64 = 0x1000;
const PBA: u64 = 0x1000;

const STATUS_DRIVER_OK: u8 = 4;
const STATUS_FEATURES_OK: u8 = 8;
const STATUS_NEEDS_RESET: u8 = 64;

const ISR_QUEUE: u8 = 1;
const ISR_CONFIG: u8 = 2;

const MSIX_ENABLE: u16 = 1 << 15;
const MSIX_MASK: u16 = 1 << 14;

/// The guest's notifications of each device's queues, which a vCPU posts
/// (a bit per queue) and the I/O thread takes.
pub struct Kicks(pub [AtomicU64; pci::SLOTS]);

impl Kicks {
    pub const fn new() -> Self {
        Kicks([const { AtomicU64::new(0) }; pci::SLOTS])
    }

    /// Queue `q` of slot `slot` was notified: whether nothing was posted
    /// for the slot before (the I/O thread is to be signalled).
    pub fn post(&self, slot: usize, q: usize) -> bool {
        self.0[slot].fetch_or(1 << q, Ordering::SeqCst) == 0
    }

    pub fn take(&self, slot: usize) -> u64 {
        self.0[slot].swap(0, Ordering::SeqCst)
    }
}

impl Default for Kicks {
    fn default() -> Self {
        Self::new()
    }
}

/// What a device type adds to the transport (blk.rs, net.rs).
pub trait Backend {
    /// The virtio device type (1 net, 2 block).
    fn device_type(&self) -> u16;
    /// Its feature bits (VERSION_1 and INDIRECT_DESC are the transport's).
    fn features(&self) -> u64;
    fn num_queues(&self) -> usize;
    fn queue_max(&self, q: usize) -> u16;
    /// Its configuration structure.
    fn config(&self) -> &[u8];
    fn features_accepted(&mut self, _features: u64) {}
    /// Take queue `q`'s new buffers: the queues it put used buffers in.
    fn kick(&mut self, mem: &GuestMem, queues: &mut [Queue], q: usize) -> u64;
    /// What its backend completed: the queues it put used buffers in.
    fn complete(&mut self, mem: &GuestMem, queues: &mut [Queue]) -> u64;
    /// Queues whose work waits for the backend (room in its ring, an
    /// earlier request), to take again after `complete`.
    fn retry(&self) -> u64 {
        0
    }
    /// Queues with work left now (a turn ended at its batch), to take
    /// again without a notification.
    fn more(&self) -> u64 {
        0
    }
    /// Whether it may have work, from memory alone: the I/O thread spins
    /// on it while devices poll (`more`), between its turns.  Those that
    /// cannot tell say no, and are served at the next turn.
    fn ready(&self, _mem: &GuestMem, _queues: &[Queue]) -> bool {
        false
    }
    /// Its configuration changed (a link went up or down).
    fn config_changed(&mut self) -> bool {
        false
    }
    /// The driver resets the device or a queue: no request may still
    /// reach guest memory once this returns.
    fn reset(&mut self);
}

#[derive(Clone, Copy, Default)]
struct QueueRegs {
    size: u16,
    vector: u16,
    enabled: bool,
    desc: u64,
    driver: u64,
    device: u64,
}

#[derive(Clone, Copy, Default)]
struct MsixEntry {
    addr: u64,
    data: u32,
    ctrl: u32,
}

/// An interrupt the transport raises.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Irq {
    Msi(Message),
    /// INTx's level (its pin is pci::intx_gsi(slot, 1)).
    Intx(bool),
}

pub struct Transport<B: Backend> {
    pub cfg: Config,
    msix_cap: usize,
    pci_cfg_cap: usize,
    status: u8,
    generation: u8,
    dfsel: u32,
    gfsel: u32,
    driver_features: u64,
    msix_config: u16,
    queue_sel: u16,
    regs: [QueueRegs; MAX_QUEUES],
    pub queues: [Queue; MAX_QUEUES],
    isr: u8,
    msix: [MsixEntry; MAX_QUEUES + 1],
    pba: u64,
    intx: bool,
    pub backend: B,
}

fn vendor_cap(cfg_type: u8, bar: u8, offset: u32, len: u32, extra: Option<u32>) -> ([u8; 18], usize) {
    let cap_len = if extra.is_some() { 20 } else { 16 };
    let mut b = [0u8; 18];
    b[0] = cap_len;
    b[1] = cfg_type;
    b[2] = bar;
    b[6..10].copy_from_slice(&offset.to_le_bytes());
    b[10..14].copy_from_slice(&len.to_le_bytes());
    if let Some(x) = extra {
        b[14..18].copy_from_slice(&x.to_le_bytes());
    }
    (b, cap_len as usize - 2)
}

impl<B: Backend> Transport<B> {
    /// The device in slot `slot` (1-31), with its BARs where the slot's
    /// part of the window is.
    pub fn new(slot: usize, backend: B) -> Self {
        let ty = backend.device_type();
        let class = match ty {
            1 => 0x02_0000,
            2 => 0x01_8000,
            _ => 0xff_0000,
        };
        let mut cfg = Config::new(0x1af4, 0x1040 + ty, 1, class, (0x1af4, 0x40 + ty), 1);
        let base = pci::MMIO_BASE + slot as u64 * pci::SLOT_MMIO;
        cfg.bar64(0, BAR0_SIZE, base);
        cfg.bar64(2, BAR2_SIZE, base + BAR0_SIZE);
        let n = backend.num_queues().min(MAX_QUEUES);
        // MSI-X: a vector per queue and one for configuration changes.
        let mut msix = [0u8; 10];
        msix[0..2].copy_from_slice(&(n as u16).to_le_bytes());
        msix[2..6].copy_from_slice(&2u32.to_le_bytes());
        msix[6..10].copy_from_slice(&(PBA as u32 | 2).to_le_bytes());
        let msix_cap = cfg.add_cap(pci::CAP_MSIX, &msix);
        cfg.writable(msix_cap + 2, 2, (MSIX_ENABLE | MSIX_MASK) as u32);
        for (t, off, len, extra) in [
            (1, COMMON, COMMON_LEN, None),
            (2, NOTIFY, MAX_QUEUES as u64 * NOTIFY_MULTIPLIER, Some(NOTIFY_MULTIPLIER as u32)),
            (3, ISR, 4, None),
            (4, DEVICE, DEVICE_LEN, None),
        ] {
            let (b, len_b) = vendor_cap(t, 0, off as u32, len as u32, extra);
            cfg.add_cap(pci::CAP_VENDOR, &b[..len_b]);
        }
        // The PCI configuration access capability: bar, offset and length
        // are the guest's, then 4 bytes of data.
        let (b, len_b) = vendor_cap(5, 0, 0, 0, Some(0));
        let pci_cfg_cap = cfg.add_cap(pci::CAP_VENDOR, &b[..len_b]);
        cfg.writable(pci_cfg_cap + 4, 1, 0xff);
        cfg.writable(pci_cfg_cap + 8, 4, u32::MAX);
        cfg.writable(pci_cfg_cap + 12, 4, u32::MAX);
        cfg.writable(pci_cfg_cap + 16, 4, u32::MAX);
        let mut t = Transport {
            cfg, msix_cap, pci_cfg_cap, status: 0, generation: 0, dfsel: 0, gfsel: 0, driver_features: 0,
            msix_config: NO_VECTOR, queue_sel: 0, regs: [QueueRegs::default(); MAX_QUEUES],
            queues: Default::default(), isr: 0, msix: [MsixEntry { ctrl: 1, ..Default::default() }; MAX_QUEUES + 1],
            pba: 0, intx: false, backend,
        };
        t.reset_regs();
        t
    }

    fn nqueues(&self) -> usize {
        self.backend.num_queues().min(MAX_QUEUES)
    }

    fn offered(&self) -> u64 {
        self.backend.features() | VIRTIO_F_VERSION_1 | VIRTIO_RING_F_INDIRECT_DESC | VIRTIO_RING_F_EVENT_IDX
    }

    fn reset_regs(&mut self) {
        for (q, r) in self.regs.iter_mut().enumerate() {
            *r = QueueRegs { size: self.backend.queue_max(q), vector: NO_VECTOR, ..Default::default() };
        }
        for q in self.queues.iter_mut() {
            q.reset();
        }
        self.status = 0;
        self.dfsel = 0;
        self.gfsel = 0;
        self.driver_features = 0;
        self.msix_config = NO_VECTOR;
        self.queue_sel = 0;
        self.isr = 0;
    }

    fn msix_ctl(&self) -> u16 {
        self.cfg.get(self.msix_cap + 2, 2) as u16
    }

    fn msix_on(&self) -> bool {
        self.msix_ctl() & MSIX_ENABLE != 0
    }

    /// Which BAR `gpa` is in, and the offset in it.
    pub fn bar_of(&self, gpa: u64) -> Option<(usize, u64)> {
        [0, 2].into_iter().find_map(|i| {
            let base = self.cfg.bar_addr(i)?;
            let off = gpa.checked_sub(base)?;
            (off < self.cfg.bar_size(i)).then_some((i, off))
        })
    }

    /// The queue a notification write at BAR0 offset `off` is for.
    pub fn notify_queue(off: u64) -> Option<usize> {
        let q = off.checked_sub(NOTIFY)? / NOTIFY_MULTIPLIER;
        (off < NOTIFY + MAX_QUEUES as u64 * NOTIFY_MULTIPLIER).then_some(q as usize)
    }

    fn common_image(&self) -> [u8; COMMON_LEN as usize] {
        let mut c = [0u8; COMMON_LEN as usize];
        let q = self.queue_sel as usize;
        let r = self.regs.get(q).copied().filter(|_| q < self.nqueues()).unwrap_or_default();
        let feat = match self.dfsel {
            0 => self.offered() as u32,
            1 => (self.offered() >> 32) as u32,
            _ => 0,
        };
        let drv = match self.gfsel {
            0 => self.driver_features as u32,
            1 => (self.driver_features >> 32) as u32,
            _ => 0,
        };
        c[0x00..0x04].copy_from_slice(&self.dfsel.to_le_bytes());
        c[0x04..0x08].copy_from_slice(&feat.to_le_bytes());
        c[0x08..0x0c].copy_from_slice(&self.gfsel.to_le_bytes());
        c[0x0c..0x10].copy_from_slice(&drv.to_le_bytes());
        c[0x10..0x12].copy_from_slice(&self.msix_config.to_le_bytes());
        c[0x12..0x14].copy_from_slice(&(self.nqueues() as u16).to_le_bytes());
        c[0x14] = self.status;
        c[0x15] = self.generation;
        c[0x16..0x18].copy_from_slice(&self.queue_sel.to_le_bytes());
        c[0x18..0x1a].copy_from_slice(&r.size.to_le_bytes());
        c[0x1a..0x1c].copy_from_slice(&r.vector.to_le_bytes());
        c[0x1c..0x1e].copy_from_slice(&(r.enabled as u16).to_le_bytes());
        c[0x1e..0x20].copy_from_slice(&(q as u16).to_le_bytes());
        c[0x20..0x28].copy_from_slice(&r.desc.to_le_bytes());
        c[0x28..0x30].copy_from_slice(&r.driver.to_le_bytes());
        c[0x30..0x38].copy_from_slice(&r.device.to_le_bytes());
        c
    }

    fn bytes_at(src: &[u8], off: u64, size: u8) -> u64 {
        let off = off as usize;
        (0..size as usize).fold(0, |v, i| v | (*src.get(off + i).unwrap_or(&0) as u64) << (8 * i))
    }

    /// The guest reads `size` bytes at `off` of BAR `bar`.
    pub fn read(&mut self, bar: usize, off: u64, size: u8, out: &mut impl FnMut(Irq)) -> u64 {
        match (bar, off) {
            (0, COMMON..0x38) => Self::bytes_at(&self.common_image(), off, size),
            (0, ISR..0x2004) => {
                // Reading ISR clears it, and drops INTx.
                let v = self.isr as u64;
                self.isr = 0;
                self.update_intx(out);
                if off == ISR { v } else { 0 }
            }
            (0, DEVICE..0x4000) => Self::bytes_at(self.backend.config(), off - DEVICE, size),
            (2, 0..PBA) => {
                let i = (off / 16) as usize;
                let Some(e) = self.msix.get(i).filter(|_| i <= self.nqueues()) else { return 0 };
                let words = [e.addr as u32, (e.addr >> 32) as u32, e.data, e.ctrl];
                let w = words[((off % 16) / 4) as usize] as u64;
                if size == 8 && off.is_multiple_of(8) { w | (words[((off % 16) / 4 + 1) as usize] as u64) << 32 } else { w >> (8 * (off % 4)) }
            }
            (2, PBA..0x2000) => {
                let p = self.pba;
                if off - PBA >= 8 { 0 } else { p >> (8 * (off - PBA)) }
            }
            _ => 0,
        }
    }

    /// The guest writes `size` bytes of `val` at `off` of BAR `bar`.
    pub fn write(&mut self, mem: &GuestMem, bar: usize, off: u64, size: u8, val: u64, out: &mut impl FnMut(Irq)) {
        match (bar, off) {
            (0, COMMON..0x38) => self.write_common(mem, off, size, val, out),
            // A notification that did not take vcpu.rs's fast path (an
            // access the I/O thread was asked for, or VIRTIO_PCI_CAP_PCI_CFG).
            (0, NOTIFY..ISR) => {
                if let Some(q) = Self::notify_queue(off).filter(|_| off.is_multiple_of(NOTIFY_MULTIPLIER)) {
                    self.poll(mem, 1 << q, out);
                }
            }
            (2, 0..PBA) => {
                let i = (off / 16) as usize;
                if i > self.nqueues() || i >= self.msix.len() {
                    return;
                }
                let e = &mut self.msix[i];
                match (off % 16, size) {
                    (0, 8) => e.addr = val,
                    (0, _) => e.addr = (e.addr & !0xffff_ffff) | (val & 0xffff_ffff),
                    (4, _) => e.addr = (e.addr & 0xffff_ffff) | (val << 32),
                    (8, 8) => {
                        e.data = val as u32;
                        e.ctrl = (val >> 32) as u32 & 1;
                    }
                    (8, _) => e.data = val as u32,
                    (12, _) => e.ctrl = val as u32 & 1,
                    _ => {}
                }
                self.msix_pending(out);
            }
            _ => {}
        }
    }

    fn write_common(&mut self, mem: &GuestMem, off: u64, size: u8, val: u64, out: &mut impl FnMut(Irq)) {
        let q = self.queue_sel as usize;
        let live = q < self.nqueues();
        let set_half = |old: u64, hi: bool| if hi { (old & 0xffff_ffff) | (val << 32) } else if size == 8 { val } else { (old & !0xffff_ffff) | (val & 0xffff_ffff) };
        match off {
            0x00 => self.dfsel = val as u32,
            0x08 => self.gfsel = val as u32,
            0x0c if self.status & STATUS_FEATURES_OK == 0 => match self.gfsel {
                0 => self.driver_features = (self.driver_features & !0xffff_ffff) | (val & 0xffff_ffff),
                1 => self.driver_features = (self.driver_features & 0xffff_ffff) | (val << 32),
                _ => {}
            },
            0x10 => self.msix_config = self.vector(val as u16),
            0x14 => self.write_status(mem, val as u8, out),
            0x16 => self.queue_sel = val as u16,
            0x18 if live && !self.regs[q].enabled => {
                let n = val as u16;
                // A split ring's size is a power of two, up to the maximum.
                if n.is_power_of_two() && n <= self.backend.queue_max(q) {
                    self.regs[q].size = n;
                }
            }
            0x1a if live => self.regs[q].vector = self.vector(val as u16),
            0x1c if live && val & 1 != 0 && !self.regs[q].enabled => {
                let r = self.regs[q];
                let max = self.backend.queue_max(q) as u32;
                if self.queues[q].setup(mem, r.size as u32, max, r.desc, r.driver, r.device) {
                    self.queues[q].set_event_idx(self.driver_features & VIRTIO_RING_F_EVENT_IDX != 0);
                    self.regs[q].enabled = true;
                    if self.status & STATUS_DRIVER_OK != 0 {
                        self.poll(mem, 1 << q, out);
                    }
                } else {
                    // Rings outside RAM: the device is unusable until reset.
                    self.status |= STATUS_NEEDS_RESET;
                    self.config_interrupt(out);
                }
            }
            0x20 | 0x24 if live && !self.regs[q].enabled => self.regs[q].desc = set_half(self.regs[q].desc, off == 0x24),
            0x28 | 0x2c if live && !self.regs[q].enabled => self.regs[q].driver = set_half(self.regs[q].driver, off == 0x2c),
            0x30 | 0x34 if live && !self.regs[q].enabled => self.regs[q].device = set_half(self.regs[q].device, off == 0x34),
            _ => {}
        }
    }

    /// A vector the guest sets: NO_VECTOR if there is no such table entry.
    fn vector(&self, v: u16) -> u16 {
        if (v as usize) <= self.nqueues() { v } else { NO_VECTOR }
    }

    fn write_status(&mut self, mem: &GuestMem, s: u8, out: &mut impl FnMut(Irq)) {
        if s == 0 {
            // The backend's requests must not complete into the buffers
            // the driver takes back.
            self.backend.reset();
            self.reset_regs();
            self.update_intx(out);
            return;
        }
        let mut s = s | (self.status & STATUS_NEEDS_RESET);
        if s & STATUS_FEATURES_OK != 0 && self.status & STATUS_FEATURES_OK == 0 {
            let f = self.driver_features;
            if f & !self.offered() != 0 || f & VIRTIO_F_VERSION_1 == 0 {
                s &= !STATUS_FEATURES_OK;
            } else {
                self.backend.features_accepted(f);
            }
        }
        let start = s & STATUS_DRIVER_OK != 0 && self.status & STATUS_DRIVER_OK == 0;
        self.status = s;
        if start {
            // Buffers may have been queued before DRIVER_OK.
            self.poll(mem, u64::MAX, out);
        }
    }

    fn driver_ok(&self) -> bool {
        self.status & STATUS_DRIVER_OK != 0 && self.status & STATUS_NEEDS_RESET == 0
    }

    /// Take the work of the queues in `bits` (notified, or to retry).
    pub fn poll(&mut self, mem: &GuestMem, bits: u64, out: &mut impl FnMut(Irq)) {
        if !self.driver_ok() {
            return;
        }
        let mut used = 0;
        for q in 0..self.nqueues() {
            if bits & (1 << q) != 0 && self.regs[q].enabled {
                used |= self.backend.kick(mem, &mut self.queues, q);
            }
        }
        self.interrupt(mem, used, out);
    }

    /// The backend signalled: its completions.  What they free (the
    /// queues, the I/O pool's pages) the caller retries, once every
    /// device's are in (io::completed): `retry`.
    pub fn complete(&mut self, mem: &GuestMem, out: &mut impl FnMut(Irq)) {
        if self.backend.config_changed() && self.driver_ok() {
            self.generation = self.generation.wrapping_add(1);
            self.config_interrupt(out);
        }
        if !self.driver_ok() {
            return;
        }
        let used = self.backend.complete(mem, &mut self.queues);
        self.interrupt(mem, used, out);
    }

    /// Queues that waited for room the backend may now have: again.
    pub fn retry(&mut self, mem: &GuestMem, out: &mut impl FnMut(Irq)) {
        let retry = self.backend.retry();
        if retry != 0 {
            self.poll(mem, retry, out);
        }
    }

    /// Interrupt for the queues in `used`, those whose drivers want it.
    fn interrupt(&mut self, mem: &GuestMem, used: u64, out: &mut impl FnMut(Irq)) {
        for q in 0..self.nqueues() {
            if used & (1 << q) == 0 || !self.queues[q].ready || !self.queues[q].should_interrupt(mem) {
                continue;
            }
            if self.msix_on() {
                let v = self.regs[q].vector;
                self.msix_send(v, out);
            } else {
                self.isr |= ISR_QUEUE;
                self.update_intx(out);
            }
        }
    }

    fn config_interrupt(&mut self, out: &mut impl FnMut(Irq)) {
        if self.msix_on() {
            let v = self.msix_config;
            self.msix_send(v, out);
        } else {
            self.isr |= ISR_CONFIG;
            self.update_intx(out);
        }
    }

    fn msix_send(&mut self, v: u16, out: &mut impl FnMut(Irq)) {
        let Some(e) = self.msix.get(v as usize).filter(|_| v != NO_VECTOR) else { return };
        if self.msix_ctl() & MSIX_MASK != 0 || e.ctrl & 1 != 0 {
            self.pba |= 1 << v;
            return;
        }
        if let Some(m) = Message::msi(e.addr, e.data) {
            out(Irq::Msi(m));
        }
    }

    /// Deliver pending vectors that are no longer masked.
    fn msix_pending(&mut self, out: &mut impl FnMut(Irq)) {
        if !self.msix_on() || self.msix_ctl() & MSIX_MASK != 0 {
            return;
        }
        for v in 0..self.msix.len() {
            if self.pba & (1 << v) != 0 && self.msix[v].ctrl & 1 == 0 {
                self.pba &= !(1 << v);
                self.msix_send(v as u16, out);
            }
        }
    }

    fn update_intx(&mut self, out: &mut impl FnMut(Irq)) {
        let level = self.isr != 0 && !self.msix_on() && self.cfg.command() & pci::CMD_INTX_DISABLE == 0;
        if level != self.intx {
            self.intx = level;
            out(Irq::Intx(level));
        }
    }

    /// The guest wrote configuration space at `off`: MSI-X's enable and
    /// mask bits, the command register's INTx disable, and the PCI
    /// configuration access capability.
    pub fn config_write(&mut self, mem: &GuestMem, off: u64, size: u8, val: u32, out: &mut impl FnMut(Irq)) {
        self.cfg.write(off, size, val);
        let data = self.pci_cfg_cap as u64 + 16;
        if off >= data && off < data + 4 {
            let (bar, at, len) = self.pci_cfg_window();
            if bar == 0 && len == size && len != 0 {
                self.write(mem, 0, at, len, val as u64 >> (8 * (off - data)), out);
            }
        }
        self.msix_pending(out);
        self.update_intx(out);
    }

    pub fn config_read(&mut self, off: u64, size: u8, out: &mut impl FnMut(Irq)) -> u32 {
        let data = self.pci_cfg_cap as u64 + 16;
        if off >= data && off < data + 4 {
            let (bar, at, len) = self.pci_cfg_window();
            if bar == 0 && len != 0 && len <= 4 {
                return (self.read(0, at, len, out) as u32) >> (8 * (off - data));
            }
            return 0;
        }
        self.cfg.read(off, size)
    }

    /// The BAR, offset and length the configuration access capability names.
    fn pci_cfg_window(&self) -> (u8, u64, u8) {
        let c = self.pci_cfg_cap;
        (self.cfg.get(c + 4, 1) as u8, self.cfg.get(c + 8, 4) as u64, self.cfg.get(c + 12, 4).min(4) as u8)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    struct Echo {
        cfg: [u8; 8],
        kicked: u64,
        resets: usize,
        accepted: u64,
    }

    impl Backend for Echo {
        fn device_type(&self) -> u16 {
            2
        }
        fn features(&self) -> u64 {
            1 << 6
        }
        fn num_queues(&self) -> usize {
            2
        }
        fn queue_max(&self, _: usize) -> u16 {
            16
        }
        fn config(&self) -> &[u8] {
            &self.cfg
        }
        fn features_accepted(&mut self, f: u64) {
            self.accepted = f;
        }
        fn kick(&mut self, mem: &GuestMem, queues: &mut [Queue], q: usize) -> u64 {
            self.kicked |= 1 << q;
            let mut any = 0;
            while let Some(h) = queues[q].pop(mem) {
                queues[q].push(mem, h, 0);
                any = 1 << q;
            }
            any
        }
        fn complete(&mut self, _: &GuestMem, _: &mut [Queue]) -> u64 {
            0
        }
        fn reset(&mut self) {
            self.resets += 1;
        }
    }

    fn device() -> Transport<Echo> {
        Transport::new(1, Echo { cfg: [1, 2, 3, 4, 5, 6, 7, 8], kicked: 0, resets: 0, accepted: 0 })
    }

    #[test]
    fn config_space_layout() {
        let t = device();
        assert_eq!(t.cfg.read(0, 4), 0x1042_1af4);
        assert_eq!(t.cfg.read(0x2c, 4), 0x0042_1af4);
        // Walk the capabilities: MSI-X, then the five virtio ones.
        let mut at = t.cfg.read(0x34, 1) as u64;
        let mut kinds = Vec::new();
        while at != 0 {
            let id = t.cfg.read(at, 1) as u8;
            kinds.push(if id == pci::CAP_VENDOR { t.cfg.read(at + 3, 1) as u8 } else { id });
            at = t.cfg.read(at + 1, 1) as u64;
        }
        assert_eq!(kinds, [pci::CAP_MSIX, 1, 2, 3, 4, 5]);
        // MSI-X table size (N - 1 = 2 for 2 queues and config), in BAR2.
        assert_eq!(t.cfg.read(t.msix_cap as u64 + 2, 2), 2);
        assert_eq!(t.cfg.read(t.msix_cap as u64 + 4, 4), 2);
    }

    #[test]
    fn negotiation_queues_and_interrupts() {
        let (mem, _buf) = crate::mem::tests::fake(1 << 20, 0);
        let mut t = device();
        let mut irqs = Vec::new();
        let mut out = |i| irqs.push(i);
        t.cfg.write(4, 2, 2);
        assert_eq!(t.bar_of(pci::MMIO_BASE + pci::SLOT_MMIO + 0x14), Some((0, 0x14)));
        assert_eq!(t.bar_of(pci::MMIO_BASE + pci::SLOT_MMIO + BAR0_SIZE + 0x10), Some((2, 0x10)));
        // Features: the device's and the transport's.
        t.write(&mem, 0, 0x00, 4, 1, &mut out);
        assert_eq!(t.read(0, 0x04, 4, &mut out), 1, "VERSION_1");
        t.write(&mem, 0, 0x00, 4, 0, &mut out);
        assert_eq!(t.read(0, 0x04, 4, &mut out) as u64, (1 << 6) | VIRTIO_RING_F_INDIRECT_DESC | VIRTIO_RING_F_EVENT_IDX);
        // Without VERSION_1, FEATURES_OK does not stick.
        t.write(&mem, 0, 0x14, 1, 1 | 2 | 8, &mut out);
        assert_eq!(t.read(0, 0x14, 1, &mut out) & 8, 0);
        t.write(&mem, 0, 0x08, 4, 1, &mut out);
        t.write(&mem, 0, 0x0c, 4, 1, &mut out);
        t.write(&mem, 0, 0x08, 4, 0, &mut out);
        t.write(&mem, 0, 0x0c, 4, 1 << 6, &mut out);
        t.write(&mem, 0, 0x14, 1, 1 | 2 | 8, &mut out);
        assert_eq!(t.read(0, 0x14, 1, &mut out) & 8, 8);
        assert_eq!(t.backend.accepted, VIRTIO_F_VERSION_1 | (1 << 6));
        // Queue 1: size, rings at 0x1000/0x2000/0x3000, vector 1.
        t.write(&mem, 0, 0x16, 2, 1, &mut out);
        assert_eq!(t.read(0, 0x18, 2, &mut out), 16);
        assert_eq!(t.read(0, 0x1e, 2, &mut out), 1, "notify offset");
        t.write(&mem, 0, 0x18, 2, 3, &mut out);
        assert_eq!(t.read(0, 0x18, 2, &mut out), 16, "not a power of two");
        t.write(&mem, 0, 0x18, 2, 8, &mut out);
        t.write(&mem, 0, 0x20, 8, 0x1000, &mut out);
        t.write(&mem, 0, 0x28, 4, 0x2000, &mut out);
        t.write(&mem, 0, 0x2c, 4, 0, &mut out);
        t.write(&mem, 0, 0x30, 8, 0x3000, &mut out);
        t.write(&mem, 0, 0x1a, 2, 1, &mut out);
        assert_eq!(t.read(0, 0x1a, 2, &mut out), 1);
        t.write(&mem, 0, 0x1a, 2, 9, &mut out);
        assert_eq!(t.read(0, 0x1a, 2, &mut out), NO_VECTOR as u64, "no such entry");
        t.write(&mem, 0, 0x1a, 2, 1, &mut out);
        t.write(&mem, 0, 0x1c, 2, 1, &mut out);
        assert_eq!(t.read(0, 0x1c, 2, &mut out), 1);
        // MSI-X entry 1, unmasked; MSI-X on.
        t.write(&mem, 2, 16, 4, 0xfee0_1000, &mut out);
        t.write(&mem, 2, 24, 4, 0x41, &mut out);
        t.write(&mem, 2, 28, 4, 0, &mut out);
        t.config_write(&mem, t.msix_cap as u64 + 2, 2, MSIX_ENABLE as u32, &mut out);
        t.write(&mem, 0, 0x14, 1, 1 | 2 | 8 | 4, &mut out);
        // A buffer in the avail ring, then a notification.
        mem.write::<u16>(0x1000 + 14, 0);
        mem.write::<u16>(0x2000 + 4, 0);
        mem.write::<u16>(0x2000 + 2, 1);
        t.poll(&mem, 1 << 1, &mut out);
        assert_eq!(mem.read::<u16>(0x3000 + 2), 1, "used");
        assert_eq!(irqs.len(), 1);
        assert!(matches!(irqs[0], Irq::Msi(m) if m.vector == 0x41 && m.dest == 1));
        // Masked: pending, then delivered when unmasked.
        let mut irqs = Vec::new();
        t.write(&mem, 2, 28, 4, 1, &mut |i| irqs.push(i));
        mem.write::<u16>(0x2000 + 2, 2);
        mem.write::<u16>(0x2000 + 6, 0);
        t.poll(&mem, 1 << 1, &mut |i| irqs.push(i));
        assert!(irqs.is_empty());
        assert_eq!(t.read(2, PBA, 8, &mut |i| irqs.push(i)), 2);
        t.write(&mem, 2, 28, 4, 0, &mut |i| irqs.push(i));
        assert_eq!(irqs.len(), 1);
        // INTx without MSI-X: ISR, read and cleared.
        let mut irqs = Vec::new();
        let cap = t.msix_cap as u64 + 2;
        t.config_write(&mem, cap, 2, 0, &mut |i| irqs.push(i));
        mem.write::<u16>(0x2000 + 2, 3);
        mem.write::<u16>(0x2000 + 8, 0);
        t.poll(&mem, 1 << 1, &mut |i| irqs.push(i));
        assert_eq!(irqs, [Irq::Intx(true)]);
        assert_eq!(t.read(0, ISR, 1, &mut |i| irqs.push(i)), 1);
        assert_eq!(irqs, [Irq::Intx(true), Irq::Intx(false)]);
        let mut out = |_| {};
        // Device configuration, and reset.
        assert_eq!(t.read(0, DEVICE + 2, 2, &mut out), 0x0403);
        t.write(&mem, 0, 0x14, 1, 0, &mut out);
        assert_eq!(t.backend.resets, 1);
        assert_eq!(t.read(0, 0x14, 1, &mut out), 0);
        t.write(&mem, 0, 0x16, 2, 1, &mut out);
        assert_eq!((t.read(0, 0x1c, 2, &mut out), t.read(0, 0x1a, 2, &mut out)), (0, NO_VECTOR as u64));
        // Rings outside RAM: NEEDS_RESET.
        t.write(&mem, 0, 0x14, 1, 1 | 2, &mut out);
        t.write(&mem, 0, 0x20, 8, 1 << 40, &mut out);
        t.write(&mem, 0, 0x1c, 2, 1, &mut out);
        assert_eq!(t.read(0, 0x14, 1, &mut out) & STATUS_NEEDS_RESET as u64, STATUS_NEEDS_RESET as u64);
        assert_eq!(Transport::<Echo>::notify_queue(NOTIFY + 4), Some(1));
        assert_eq!(Transport::<Echo>::notify_queue(NOTIFY + 4 * MAX_QUEUES as u64), None);
    }
}

//! PCI configuration: x86 I/O ports, or QEMU virt ECAM and GICv2m MSI.

#[cfg(target_arch = "x86_64")]
use sel4::cap_type;
use sel4::init_thread::slot;

use crate::mem::Alloc;

#[cfg(target_arch = "x86_64")]
const CONFIG_ADDRESS: u16 = 0xcf8;
#[cfg(target_arch = "x86_64")]
const CONFIG_DATA: u16 = 0xcfc;

pub struct Pci {
    /// IOPort capability for 0xcf8..0xcff (rust-sel4 has no IOPort type).
    #[cfg(target_arch = "x86_64")]
    port: u64,
    #[cfg(target_arch = "aarch64")]
    next_bar: core::cell::Cell<u64>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Bar {
    pub addr: u64,
    pub size: u64,
    pub is_io: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct Device {
    pub bus: u8,
    pub dev: u8,
    pub func: u8,
    pub vendor: u16,
    pub device: u16,
    pub class: u8,
    pub subclass: u8,
    pub prog_if: u8,
    pub revision: u8,
    pub bars: [Bar; 6],
    /// MSI capability's configuration offset, if present.
    pub msi: Option<u8>,
    /// MSI-X capability: config offset, table BAR/offset, table size.
    pub msix: Option<Msix>,
    /// Vendor-specific capabilities (virtio): (cap offset, cfg_type, bar, offset, length, notify multiplier).
    pub virtio_caps: VirtioCaps,
}

#[derive(Clone, Copy, Debug)]
pub struct Msix {
    pub cap: u8,
    pub table_bar: u8,
    pub table_offset: u32,
    pub table_size: u16,
}

#[derive(Clone, Copy, Debug)]
pub struct VirtioCap {
    pub cfg_type: u8,
    pub bar: u8,
    pub offset: u32,
    pub length: u32,
    pub notify_off_multiplier: u32,
}

/// Virtio capabilities kept per device.  A device may list several of one
/// type, of which a driver is to use the first it can (virtio 1.x §4.1.4);
/// ours only ever look at the first, so only the first of each type is
/// kept.  The spec defines fewer types than this.
const MAX_VIRTIO_CAPS: usize = 8;

/// A device's virtio capabilities, the first of each type, in the order
/// the device lists them.
#[derive(Clone, Copy, Debug)]
pub struct VirtioCaps {
    caps: [VirtioCap; MAX_VIRTIO_CAPS],
    len: usize,
}

impl VirtioCaps {
    const fn new() -> Self {
        let none = VirtioCap { cfg_type: 0, bar: 0, offset: 0, length: 0, notify_off_multiplier: 0 };
        VirtioCaps { caps: [none; MAX_VIRTIO_CAPS], len: 0 }
    }

    fn push(&mut self, c: VirtioCap) {
        if self.len < MAX_VIRTIO_CAPS && !self.iter().any(|o| o.cfg_type == c.cfg_type) {
            self.caps[self.len] = c;
            self.len += 1;
        }
    }
}

impl core::ops::Deref for VirtioCaps {
    type Target = [VirtioCap];

    fn deref(&self) -> &[VirtioCap] {
        &self.caps[..self.len]
    }
}

/// Formats an iterator's items as a list, for log lines.
pub struct List<I>(pub I);

impl<I: Iterator + Clone> core::fmt::Debug for List<I>
where
    I::Item: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_list().entries(self.0.clone()).finish()
    }
}

/// seL4 user interrupt vectors (CPU vector 0x30 + n, n <= 107 on x86),
/// split between the users so that they never collide.
pub const VECTOR_NIC_BASE: u64 = 0;
#[cfg(target_arch = "x86_64")]
pub const VECTOR_MONITOR: u64 = 8;
pub const VECTOR_DISK_BASE: u64 = 16;
/// Disk controllers beyond this many are left alone.
#[cfg(target_arch = "x86_64")]
pub const MAX_DISK_CTRLS: usize = 64;
#[cfg(target_arch = "aarch64")]
pub const MAX_DISK_CTRLS: usize = 48;

/// A capability for I/O ports [base, base + len), in a new root slot.
#[cfg(target_arch = "x86_64")]
pub fn io_ports(alloc: &mut Alloc, base: u16, len: u16) -> Option<sel4::cap::Null> {
    let s = alloc.slots.alloc();
    let cap = sel4::init_thread::Slot::<cap_type::Null>::from_index(s).cap();
    let dst = slot::CNODE.cap().absolute_cptr(cap);
    match slot::IO_PORT_CONTROL.cap().ioport_control_issue(base as u64, base as u64 + len as u64 - 1, &dst) {
        Ok(()) => Some(cap),
        Err(_) => {
            alloc.slots.free(s);
            None
        }
    }
}

/// Port I/O through an IOPort capability from io_ports.
#[cfg(target_arch = "x86_64")]
pub fn in8(io: sel4::cap::Null, port: u16) -> u8 {
    sel4::with_ipc_buffer_mut(|ipc| ipc.inner_mut().seL4_X86_IOPort_In8(io.bits(), port).result)
}

#[cfg(target_arch = "x86_64")]
pub fn out8(io: sel4::cap::Null, port: u16, v: u8) {
    sel4::with_ipc_buffer_mut(|ipc| ipc.inner_mut().seL4_X86_IOPort_Out8(io.bits(), port as u64, v as u64));
}

#[cfg(not(target_arch = "x86_64"))]
pub fn in8(_io: sel4::cap::Null, _port: u16) -> u8 {
    unreachable!("I/O ports")
}

#[cfg(not(target_arch = "x86_64"))]
pub fn out8(_io: sel4::cap::Null, _port: u16, _v: u8) {
    unreachable!("I/O ports")
}

#[cfg(not(target_arch = "x86_64"))]
pub fn io_ports(_alloc: &mut Alloc, _base: u16, _len: u16) -> Option<sel4::cap::Null> {
    None
}

/// An IRQ handler for MSI vector `vector` of `d`, into `dst`.
pub fn msi_irq(d: &Device, vector: u64, dst: &sel4::AbsoluteCPtr) {
    #[cfg(target_arch = "x86_64")]
    sel4::init_thread::slot::IRQ_CONTROL
        .cap()
        .irq_control_get_msi(d.bus as u64, d.dev as u64, d.func as u64, 0, vector, dst)
        .expect("MSI IRQ handler");
    #[cfg(target_arch = "aarch64")]
    {
        let _ = d;
        assert!(vector < 64);
        slot::IRQ_CONTROL.cap().irq_control_get_trigger_core(80 + vector, true, 0, dst)
            .expect("GICv2m IRQ handler");
    }
}

#[cfg(target_arch = "x86_64")]
impl Pci {
    pub fn new(alloc: &mut Alloc, _devmem: &mut crate::devmem::DevMem) -> Self {
        let s = alloc.slots.alloc();
        let dst = slot::CNODE.cap().absolute_cptr(sel4::init_thread::Slot::<cap_type::Null>::from_index(s).cap());
        slot::IO_PORT_CONTROL
            .cap()
            .ioport_control_issue(CONFIG_ADDRESS as u64, CONFIG_DATA as u64 + 3, &dst)
            .expect("PCI config I/O ports");
        Pci { port: s as u64 }
    }

    /// A byte to one of the ports root holds, 0xcf8..0xcff, such as the
    /// reset control register 0xcf9.
    pub fn out8(&self, port: u16, v: u8) {
        assert!((CONFIG_ADDRESS..CONFIG_DATA + 4).contains(&port));
        sel4::with_ipc_buffer_mut(|ipc| ipc.inner_mut().seL4_X86_IOPort_Out8(self.port, port as u64, v as u64));
    }

    fn addr(bus: u8, dev: u8, func: u8, off: u8) -> u64 {
        (1u64 << 31) | ((bus as u64) << 16) | ((dev as u64) << 11) | ((func as u64) << 8) | (off as u64 & 0xfc)
    }

    pub fn read32(&self, bus: u8, dev: u8, func: u8, off: u8) -> u32 {
        let port = self.port;
        sel4::with_ipc_buffer_mut(|ipc| {
            let ipc = ipc.inner_mut();
            ipc.seL4_X86_IOPort_Out32(port, CONFIG_ADDRESS as u64, Self::addr(bus, dev, func, off));
            ipc.seL4_X86_IOPort_In32(port, CONFIG_DATA).result
        })
    }

    pub fn write32(&self, bus: u8, dev: u8, func: u8, off: u8, val: u32) {
        let port = self.port;
        sel4::with_ipc_buffer_mut(|ipc| {
            let ipc = ipc.inner_mut();
            ipc.seL4_X86_IOPort_Out32(port, CONFIG_ADDRESS as u64, Self::addr(bus, dev, func, off));
            ipc.seL4_X86_IOPort_Out32(port, CONFIG_DATA as u64, val as u64);
        });
    }

}

impl Pci {
    pub fn read16(&self, bus: u8, dev: u8, func: u8, off: u8) -> u16 {
        (self.read32(bus, dev, func, off & !3) >> ((off & 2) * 8)) as u16
    }

    pub fn write16(&self, bus: u8, dev: u8, func: u8, off: u8, val: u16) {
        let old = self.read32(bus, dev, func, off & !3);
        let shift = (off & 2) * 8;
        let new = (old & !(0xffff << shift)) | ((val as u32) << shift);
        self.write32(bus, dev, func, off & !3, new);
    }

    fn read8(&self, bus: u8, dev: u8, func: u8, off: u8) -> u8 {
        (self.read32(bus, dev, func, off & !3) >> ((off & 3) * 8)) as u8
    }

    fn probe_bars(&self, bus: u8, dev: u8, func: u8) -> [Bar; 6] {
        let mut bars = [Bar::default(); 6];
        let cmd = self.read16(bus, dev, func, 4);
        // Disable decoding while sizing.
        self.write16(bus, dev, func, 4, cmd & !3);
        let mut i = 0;
        while i < 6 {
            let off = 0x10 + 4 * i as u8;
            let orig = self.read32(bus, dev, func, off);
            if orig & 1 != 0 {
                self.write32(bus, dev, func, off, 0xffff_ffff);
                let sz = self.read32(bus, dev, func, off) & !3;
                self.write32(bus, dev, func, off, orig);
                if sz != 0 {
                    bars[i] = Bar { addr: (orig & !3) as u64, size: ((!sz).wrapping_add(1) & 0xffff) as u64, is_io: true };
                }
                i += 1;
                continue;
            }
            let is64 = (orig >> 1) & 3 == 2;
            self.write32(bus, dev, func, off, 0xffff_ffff);
            let lo = self.read32(bus, dev, func, off) & !0xf;
            self.write32(bus, dev, func, off, orig);
            let mut addr = (orig & !0xf) as u64;
            let mut mask = lo as u64 | 0xffff_ffff_0000_0000;
            if is64 {
                let orig_hi = self.read32(bus, dev, func, off + 4);
                self.write32(bus, dev, func, off + 4, 0xffff_ffff);
                let hi = self.read32(bus, dev, func, off + 4);
                self.write32(bus, dev, func, off + 4, orig_hi);
                addr |= (orig_hi as u64) << 32;
                mask = ((hi as u64) << 32) | lo as u64;
            }
            if lo != 0 {
                bars[i] = Bar { addr, size: (!mask).wrapping_add(1), is_io: false };
            }
            i += if is64 { 2 } else { 1 };
        }
        self.write16(bus, dev, func, 4, cmd);
        bars
    }

    fn caps(&self, bus: u8, dev: u8, func: u8) -> (Option<Msix>, VirtioCaps, Option<u8>) {
        let mut msix = None;
        let mut msi = None;
        let mut virtio = VirtioCaps::new();
        if self.read16(bus, dev, func, 6) & 0x10 == 0 {
            return (msix, virtio, msi);
        }
        let mut ptr = self.read8(bus, dev, func, 0x34) & !3;
        let mut guard = 0;
        while ptr != 0 && guard < 48 {
            let id = self.read8(bus, dev, func, ptr);
            match id {
                0x05 => msi = Some(ptr),
                0x11 => {
                    let ctrl = self.read16(bus, dev, func, ptr + 2);
                    let table = self.read32(bus, dev, func, ptr + 4);
                    msix = Some(Msix {
                        cap: ptr,
                        table_bar: (table & 7) as u8,
                        table_offset: table & !7,
                        table_size: (ctrl & 0x7ff) + 1,
                    });
                }
                0x09 => {
                    let cfg_type = self.read8(bus, dev, func, ptr + 3);
                    let bar = self.read8(bus, dev, func, ptr + 4);
                    let offset = self.read32(bus, dev, func, ptr + 8);
                    let length = self.read32(bus, dev, func, ptr + 12);
                    let mult = if cfg_type == 2 { self.read32(bus, dev, func, ptr + 16) } else { 0 };
                    virtio.push(VirtioCap { cfg_type, bar, offset, length, notify_off_multiplier: mult });
                }
                _ => {}
            }
            ptr = self.read8(bus, dev, func, ptr + 1) & !3;
            guard += 1;
        }
        (msix, virtio, msi)
    }

    /// Every PCI function, in bus, device, function order, each probed as
    /// the iterator reaches it.
    pub fn enumerate(&self) -> Devices<'_> {
        Devices { pci: self, next: 0, multi: false, bars: true }
    }

    /// Every function, without its BARs: sizing them stops decoding
    /// meanwhile, which a running display must not see.
    pub fn functions(&self) -> Devices<'_> {
        Devices { pci: self, next: 0, multi: false, bars: false }
    }

    /// The function at bus:dev.func, if there is one, with its BARs sized
    /// if `size_bars`.
    fn probe(&self, bus: u8, dev: u8, func: u8, size_bars: bool) -> Option<Device> {
        let id = self.read32(bus, dev, func, 0);
        if id & 0xffff == 0xffff {
            return None;
        }
        let class = self.read32(bus, dev, func, 8);
        let header = self.read8(bus, dev, func, 0xe) & 0x7f;
        let (msix, virtio_caps, msi) = self.caps(bus, dev, func);
        #[allow(unused_mut)]
        let mut bars = if header == 0 && size_bars { self.probe_bars(bus, dev, func) } else { [Bar::default(); 6] };
        #[cfg(target_arch = "aarch64")]
        for (n, b) in bars.iter_mut().enumerate() {
            if b.size == 0 || b.is_io { continue; }
            let addr = (self.next_bar.get() + b.size - 1) & !(b.size - 1);
            assert!(addr + b.size <= 0x3eff_0000, "PCI MMIO aperture exhausted");
            let off = 0x10 + 4 * n as u8;
            let flags = self.read32(bus, dev, func, off) & 0xf;
            self.write32(bus, dev, func, off, addr as u32 | flags);
            if flags & 6 == 4 { self.write32(bus, dev, func, off + 4, 0); }
            b.addr = addr;
            self.next_bar.set(addr + b.size);
        }
        Some(Device {
            bus,
            dev,
            func,
            vendor: id as u16,
            device: (id >> 16) as u16,
            class: (class >> 24) as u8,
            subclass: (class >> 16) as u8,
            prog_if: (class >> 8) as u8,
            revision: class as u8,
            bars,
            msi,
            msix,
            virtio_caps,
        })
    }

    /// Enable memory decoding and bus mastering, disable INTx.
    pub fn enable(&self, d: &Device) {
        let cmd = self.read16(d.bus, d.dev, d.func, 4);
        self.write16(d.bus, d.dev, d.func, 4, cmd | 0x2 | 0x4 | 0x400);
    }

    /// Enable I/O space decoding (registers of a legacy virtio device).
    pub fn enable_io(&self, d: &Device) {
        let cmd = self.read16(d.bus, d.dev, d.func, 4);
        self.write16(d.bus, d.dev, d.func, 4, cmd | 0x1);
    }

    /// Enable memory decoding only (to reach the registers), disable INTx.
    pub fn enable_memory(&self, d: &Device) {
        let cmd = self.read16(d.bus, d.dev, d.func, 4);
        self.write16(d.bus, d.dev, d.func, 4, cmd | 0x2 | 0x400);
    }

    fn mask_msi_vectors(&self, d: &Device, m: u8, ctrl: u16) {
        if ctrl & 0x100 != 0 {
            // Per-vector masking: Mask Bits follows the message data, not
            // the read-only Pending Bits at the next offset.
            let off = if ctrl & 0x80 != 0 { m + 0x10 } else { m + 0x0c };
            self.write32(d.bus, d.dev, d.func, off, u32::MAX);
        }
    }

    /// Stop the device: no DMA, no memory decoding, MSI-X off.  This alone
    /// does not quiesce a device that has commands (blkd::reset does).
    pub fn disable(&self, d: &Device) {
        let cmd = self.read16(d.bus, d.dev, d.func, 4);
        self.write16(d.bus, d.dev, d.func, 4, (cmd & !0x6) | 0x400);
        if let Some(m) = d.msi {
            let ctrl = self.read16(d.bus, d.dev, d.func, m + 2);
            self.write16(d.bus, d.dev, d.func, m + 2, ctrl & !0x71);
            self.mask_msi_vectors(d, m, ctrl);
        }
        if let Some(m) = d.msix {
            let ctrl = self.read16(d.bus, d.dev, d.func, m.cap + 2);
            self.write16(d.bus, d.dev, d.func, m.cap + 2, ctrl & !0xc000);
        }
    }

    /// Quiesce an endpoint for a host handoff, leaving memory and I/O decoding
    /// intact for the next host's drivers and display. Bridges and IOMMUs are
    /// untouched: their command registers and table walks still work.
    pub fn quiesce(&self, d: &Device) {
        if self.read8(d.bus, d.dev, d.func, 0xe) & 0x7f != 0 || (d.class == 0x08 && d.subclass == 0x06) {
            return;
        }
        let cmd = self.read16(d.bus, d.dev, d.func, 4) | 0x400;
        self.write16(d.bus, d.dev, d.func, 4, cmd & !0x4);
        if let Some(m) = d.msi {
            let ctrl = self.read16(d.bus, d.dev, d.func, m + 2);
            self.write16(d.bus, d.dev, d.func, m + 2, ctrl & !1);
            self.mask_msi_vectors(d, m, ctrl);
        }
        if let Some(m) = d.msix {
            let ctrl = self.read16(d.bus, d.dev, d.func, m.cap + 2);
            self.write16(d.bus, d.dev, d.func, m.cap + 2, (ctrl | 0x4000) & !0x8000);
        }
    }

    /// Enable MSI-X with all vectors unmasked at the function level.
    pub fn enable_msix(&self, d: &Device) {
        if let Some(m) = d.msix {
            let ctrl = self.read16(d.bus, d.dev, d.func, m.cap + 2);
            self.write16(d.bus, d.dev, d.func, m.cap + 2, (ctrl | 0x8000) & !0x4000);
        }
    }
}

/// The PCI functions, from Pci::enumerate.
pub struct Devices<'a> {
    pci: &'a Pci,
    /// The next function to look at, as bus << 8 | dev << 3 | func.
    next: u32,
    /// Its device has several functions.
    multi: bool,
    /// Size each function's BARs.
    bars: bool,
}

impl Iterator for Devices<'_> {
    type Item = Device;

    fn next(&mut self) -> Option<Device> {
        let end = if cfg!(target_arch = "aarch64") { 16 << 8 } else { 256 << 8 };
        while self.next < end {
            let (bus, dev, func) = ((self.next >> 8) as u8, (self.next >> 3 & 0x1f) as u8, (self.next & 7) as u8);
            if func == 0 {
                if self.pci.read32(bus, dev, 0, 0) & 0xffff == 0xffff {
                    self.next += 8;
                    continue;
                }
                self.multi = self.pci.read8(bus, dev, 0, 0xe) & 0x80 != 0;
            }
            // Functions 1-7 only of a multi-function device.
            self.next += if self.multi { 1 } else { 8 };
            if let Some(d) = self.pci.probe(bus, dev, func, self.bars) {
                return Some(d);
            }
        }
        None
    }
}

/// MSI target address, and data for a reserved interrupt slot.
pub const fn msi_address() -> u64 {
    #[cfg(target_arch = "x86_64")] { 0xfee0_0000 }
    #[cfg(target_arch = "aarch64")] { 0x0802_0040 }
}
pub const fn msi_data(vector: u64) -> u32 {
    #[cfg(target_arch = "x86_64")] { 0x30 + vector as u32 }
    #[cfg(target_arch = "aarch64")] { 80 + vector as u32 }
}

#[cfg(target_arch = "aarch64")]
impl Pci {
    // QEMU virt, highmem-ecam=off: 16 MiB ECAM, buses 0..15.
    const ECAM_VA: usize = crate::layout::ECAM.base;
    pub fn new(alloc: &mut Alloc, devmem: &mut crate::devmem::DevMem) -> Self {
        use sel4::{CapRights, VmAttributes};
        use crate::mem::ObjCtx;
        let frames = devmem.frames(&mut alloc.slots, 0x3f00_0000, 1 << 24).expect("PCI ECAM frames");
        for (n, frame) in frames.map(crate::devmem::granule).enumerate() {
            crate::vspace::map_frame(&mut ObjCtx::global(alloc), slot::VSPACE.cap(), frame,
                Self::ECAM_VA + n * 4096, CapRights::read_write(), VmAttributes::EXECUTE_NEVER);
        }
        Self { next_bar: core::cell::Cell::new(0x1000_0000) }
    }
    fn config(&self, bus: u8, dev: u8, func: u8, off: u8) -> *mut u32 {
        assert!(bus < 16);
        (Self::ECAM_VA + ((bus as usize) << 20) + ((dev as usize) << 15)
            + ((func as usize) << 12) + (off as usize & !3)) as *mut u32
    }
    pub fn read32(&self, bus: u8, dev: u8, func: u8, off: u8) -> u32 {
        unsafe { self.config(bus, dev, func, off).read_volatile() }
    }
    pub fn write32(&self, bus: u8, dev: u8, func: u8, off: u8, value: u32) {
        unsafe { self.config(bus, dev, func, off).write_volatile(value); core::arch::asm!("dmb osh", options(nostack)); }
    }
}

//! PCI configuration: x86 I/O ports (ECAM for a multikernel partition,
//! partition.rs), or QEMU virt ECAM and GICv2m MSI.

#[cfg(target_arch = "x86_64")]
use sel4::cap_type;
use sel4::init_thread::slot;

use crate::mem::Alloc;
use l4h_abi as abi;
use l4h_host::fixed::{ArrayVec, StaticCell};

/// One small record per possible BDF, in .bss rather than on root's
/// stack. Kept at boot: serving the inventory must never probe BARs or
/// touch a device that a driver is now using.
const MAX_FUNCTIONS: usize = if cfg!(target_arch = "aarch64") { 16 << 8 } else { 256 << 8 };
pub type Inventory = ArrayVec<abi::CtlPci, MAX_FUNCTIONS>;
pub static INVENTORY: StaticCell<Inventory> = StaticCell::new(ArrayVec::new());

#[cfg(target_arch = "x86_64")]
const CONFIG_ADDRESS: u16 = 0xcf8;
#[cfg(target_arch = "x86_64")]
const CONFIG_DATA: u16 = 0xcfc;

pub struct Pci {
    /// IOPort capability for 0xcf8..0xcff (rust-sel4 has no IOPort type).
    #[cfg(target_arch = "x86_64")]
    port: u64,
    /// A partition reaches its own functions through ECAM, each one's
    /// page mapped at ECAM_X86 + bdf * 4096: the address-then-data ports
    /// are shared with the other partitions' roots.
    #[cfg(target_arch = "x86_64")]
    ecam: bool,
    /// A partition on a machine without ECAM (no MCFG): the ports, under
    /// the partitions' lock (iommu/shared.rs), with the same reach as
    /// ECAM would give it (ECAM_MAPPED, ECAM_WRITABLE).
    #[cfg(target_arch = "x86_64")]
    shared_ports: bool,
    /// The ECAM pages in ECAM_MAPPED are mapped (`ecam`, or
    /// `map_extended`): extended configuration space, ACS's (acs.rs), is
    /// reachable through them.  The ports reach only the first 256 bytes.
    #[cfg(target_arch = "x86_64")]
    ext: bool,
    /// ECAM windows mapped whole (`map_extended`): MCFG base, and the
    /// physical range of its buses.
    #[cfg(target_arch = "x86_64")]
    windows: l4h_host::fixed::ArrayVec<(u64, u64, u64), { l4h_host::trust::MAX_ECAM }>,
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
    /// MSI-X capability: config offset, table BAR/offset, table size.
    pub msix: Option<Msix>,
    /// Plain MSI capability (xHCI controllers of Intel PCHs have no MSI-X).
    pub msi: Option<Msi>,
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

/// An MSI capability: its config offset, 64-bit addresses, per-vector
/// masking.
#[derive(Clone, Copy, Debug)]
pub struct Msi {
    pub cap: u8,
    pub is64: bool,
    pub maskable: bool,
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

/// seL4 user interrupt vectors (CPU vector 0x30 + n, n < 108, on x86;
/// GICv2m SPI 80 + n, n < 64, on aarch64), which root hands out from one
/// pool as it drives devices (`vector_alloc`): a disk controller's, an
/// xHCI's, a NIC's, each keeping its own until reboot.  No kind of device
/// has a share of its own, so a host with many NICs and few disks has
/// vectors for all of them.  Only those another party
/// chose are kept out: the serial monitor's I/O APIC pin, and the
/// multikernel doorbells, partition P's at LINK_VECTOR_BASE + P (its link
/// to netd) and CONTROL_VECTOR_BASE + P (its control channel to root).
#[cfg(target_arch = "x86_64")]
pub const VECTORS: u64 = 108;
#[cfg(target_arch = "aarch64")]
pub const VECTORS: u64 = 64;
#[cfg(target_arch = "x86_64")]
pub const VECTOR_MONITOR: u64 = 8;

/// The vectors handed out, a bit each (vector v: word v / 64).
static VECTORS_USED: [core::sync::atomic::AtomicU64; 2] = {
    let r = reserved_vectors();
    [core::sync::atomic::AtomicU64::new(r as u64), core::sync::atomic::AtomicU64::new((r >> 64) as u64)]
};

const fn reserved_vectors() -> u128 {
    let mut used = !0u128 << VECTORS;
    #[cfg(target_arch = "x86_64")]
    {
        used |= 1 << VECTOR_MONITOR;
        let p = l4h_partition::MAX_PARTITIONS as u32;
        used |= ((1u128 << p) - 1) << l4h_partition::LINK_VECTOR_BASE;
        used |= ((1u128 << p) - 1) << l4h_partition::CONTROL_VECTOR_BASE;
    }
    used
}
#[cfg(target_arch = "x86_64")]
const _: () = assert!((l4h_partition::CONTROL_VECTOR_BASE as usize + l4h_partition::MAX_PARTITIONS) as u64 <= VECTORS);

/// A free vector, now the caller's, lowest first; None when all are used.
/// Root is one thread: a load and a store.
pub fn vector_alloc() -> Option<u64> {
    use core::sync::atomic::Ordering::Relaxed;
    for (w, word) in VECTORS_USED.iter().enumerate() {
        let used = word.load(Relaxed);
        if used != u64::MAX {
            let b = (!used).trailing_zeros() as u64;
            word.store(used | 1 << b, Relaxed);
            return Some(w as u64 * 64 + b);
        }
    }
    None
}

/// Disk controllers beyond this many are left alone.
#[cfg(target_arch = "x86_64")]
pub const MAX_DISK_CTRLS: usize = 64;
#[cfg(target_arch = "aarch64")]
pub const MAX_DISK_CTRLS: usize = 48;

/// A capability for I/O ports [base, base + len), in a new root slot.
#[cfg(target_arch = "x86_64")]
pub fn io_ports(alloc: &mut Alloc, base: u16, len: u16) -> Option<sel4::cap::Null> {
    if len == 0 {
        return None;
    }
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

/// The functions whose ECAM pages a partition mapped, a bit per BDF.
#[cfg(target_arch = "x86_64")]
static ECAM_MAPPED: [core::sync::atomic::AtomicU64; 1024] = [const { core::sync::atomic::AtomicU64::new(0) }; 1024];
/// Of those, the partition's own: the only ones written.
#[cfg(target_arch = "x86_64")]
static ECAM_WRITABLE: [core::sync::atomic::AtomicU64; 1024] = [const { core::sync::atomic::AtomicU64::new(0) }; 1024];

/// Report a write to a function that is not this partition's, which
/// `write32` refuses: the first few only.  trustd's AML can ask for such
/// writes as often as it likes (trustd::hw), and must not fill root's log
/// or the serial port with them.
#[cfg(target_arch = "x86_64")]
fn refused_write(bus: u8, dev: u8, func: u8) {
    use core::sync::atomic::{AtomicU32, Ordering};
    const MAX: u32 = 8;
    static LOGGED: AtomicU32 = AtomicU32::new(0);
    // Root is one thread.
    let n = LOGGED.load(Ordering::Relaxed);
    if n < MAX {
        LOGGED.store(n + 1, Ordering::Relaxed);
        log!("l4h-root: write to PCI function {:02x}:{:02x}.{}, which is not this partition's, refused{}", bus, dev, func,
            if n + 1 == MAX { " (further ones are not logged)" } else { "" });
    }
}

/// Whether function `bdf` is this partition's (always, with the machine
/// to itself): another partition's may read as present but is not ours
/// to program.
#[cfg(target_arch = "x86_64")]
pub fn ours(bdf: u16) -> bool {
    crate::partition::get().is_none()
        || ECAM_WRITABLE[bdf as usize / 64].load(core::sync::atomic::Ordering::Relaxed) & (1 << (bdf % 64)) != 0
}

impl Pci {
    /// Identity only, before the device is handed to a driver. PCI and
    /// CardBus headers carry subsystem IDs at different offsets. Bridges
    /// may carry them in the optional subsystem-ID capability instead.
    pub fn identity(&self, d: &Device) -> abi::CtlPci {
        let (bus, dev, func) = (d.bus, d.dev, d.func);
        let subsystem = match self.read8(bus, dev, func, 0x0e) & 0x7f {
            0 => self.read32(bus, dev, func, 0x2c),
            2 => self.read32(bus, dev, func, 0x40),
            1 => {
                let mut id = 0;
                if self.read16(bus, dev, func, 6) & 0x10 != 0 {
                    let mut off = self.read8(bus, dev, func, 0x34) & !3;
                    for _ in 0..48 {
                        if off < 0x40 { break; }
                        if self.read8(bus, dev, func, off) == 0x0d && off <= 0xf8 {
                            id = self.read32(bus, dev, func, off + 4);
                            break;
                        }
                        off = self.read8(bus, dev, func, off + 1) & !3;
                    }
                }
                id
            }
            _ => 0,
        };
        abi::CtlPci {
            bdf: (bus as u16) << 8 | (dev as u16) << 3 | func as u16,
            vendor: d.vendor,
            device: d.device,
            subsystem_vendor: subsystem as u16,
            subsystem_device: (subsystem >> 16) as u16,
            class: d.class,
            subclass: d.subclass,
            prog_if: d.prog_if,
            revision: d.revision,
            owner: abi::PCI_OWNER_NONE,
        }
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
        let Some(d) = crate::partition::get() else { return Pci { port: s as u64, ecam: false, shared_ports: false, ext: false, windows: l4h_host::fixed::ArrayVec::new() } };
        let others = d.owners().iter().filter(|o| o.partition as u32 != d.index).map(|o| o.bdf);
        if d.ecam_base == 0 {
            // No ECAM: the ports, for what ECAM would reach.
            let set = |map: &[core::sync::atomic::AtomicU64; 1024], bdf: u16| {
                map[bdf as usize / 64].fetch_or(1 << (bdf % 64), core::sync::atomic::Ordering::Relaxed);
            };
            for f in d.funcs() {
                set(&ECAM_MAPPED, f.bdf);
                set(&ECAM_WRITABLE, f.bdf);
            }
            for bdf in d.upstream().iter().copied().chain(others) {
                set(&ECAM_MAPPED, bdf);
            }
            assert!(d.count == 1 || crate::iommu::shared::get().is_some(), "l4h-root: PCI configuration needs the partitions' lock");
            info!("l4h-root: no ECAM: PCI configuration through ports, under the partitions' lock");
            return Pci { port: s as u64, ecam: false, shared_ports: true, ext: false, windows: l4h_host::fixed::ArrayVec::new() };
        }
        for f in d.funcs() {
            let paddr = d.ecam_base as usize + ((f.bdf as usize) << 12);
            if (f.bdf >> 8) as u8 > d.ecam_bus_end
                || crate::partition::map(alloc, _devmem, paddr, 4096, Self::ecam_va(f.bdf)).is_none()
            {
                panic!("PCI function {:02x}:{:02x}.{}: no ECAM page", f.bdf >> 8, (f.bdf >> 3) & 0x1f, f.bdf & 7);
            }
            ECAM_MAPPED[f.bdf as usize / 64].fetch_or(1 << (f.bdf % 64), core::sync::atomic::Ordering::Relaxed);
            ECAM_WRITABLE[f.bdf as usize / 64].fetch_or(1 << (f.bdf % 64), core::sync::atomic::Ordering::Relaxed);
        }
        // Other partitions' bridges above ours, and the IOMMUs' functions;
        // in partition 0, which builds every unit's context tables, every
        // other partition's function: read-only, so that a stray write
        // faults instead of reprogramming another partition's hardware.
        // The IOMMU code reads them like any function (device scopes,
        // requester aliases).
        for bdf in d.upstream().iter().copied().chain(others) {
            let paddr = d.ecam_base as usize + ((bdf as usize) << 12);
            if (bdf >> 8) as u8 > d.ecam_bus_end || crate::partition::map_rights(alloc, _devmem, paddr, 4096,
                Self::ecam_va(bdf), sel4::CapRights::read_only()).is_none() {
                log!("l4h-root: another partition's PCI function {:02x}:{:02x}.{}: no ECAM page", bdf >> 8, (bdf >> 3) & 0x1f, bdf & 7);
                continue;
            }
            ECAM_MAPPED[bdf as usize / 64].fetch_or(1 << (bdf % 64), core::sync::atomic::Ordering::Relaxed);
        }
        info!("l4h-root: PCI configuration through ECAM");
        Pci { port: s as u64, ecam: true, shared_ports: false, ext: true, windows: l4h_host::fixed::ArrayVec::new() }
    }

    /// Map ECAM window `w` (of the MCFG, segment 0) whole into ECAM_X86,
    /// where each function's page is at its BDF's (`ecam_va`), so that
    /// root reaches the extended configuration space of its PCI Express
    /// functions (acs.rs); a partition has its own functions' pages
    /// already (`new`).  Other accesses still use the ports.  The window
    /// goes in a few carves of 2 MiB frames (acs::blocks), not one per
    /// function, which would fill the device memory table on a large
    /// server and leave no room for the BARs carved next.  Only functions
    /// whose ECAM vendor and device ID match the ports' are used: a wrong
    /// MCFG gets no writes.  Returns the functions found and those that
    /// did not match.  The window becomes root's: trustd's AML reaches it
    /// through `ecam_memory`.
    pub fn map_extended(&mut self, alloc: &mut Alloc, devmem: &mut crate::devmem::DevMem, w: &l4h_host::trust::Ecam)
        -> Result<(usize, usize), &'static str> {
        use sel4::CapRights;
        use crate::mem::ObjCtx;
        if crate::partition::get().is_some() || w.segment != 0 {
            return Err("not this partition's");
        }
        if w.base % (1 << 20) != 0 {
            return Err("base not 1 MiB aligned");
        }
        let start = w.base.checked_add((w.bus_lo as u64) << 20).ok_or("past the address space")?;
        let end = w.base.checked_add((w.bus_hi as u64 + 1) << 20).ok_or("past the address space")?;
        if self.windows.is_full() {
            return Err("too many windows");
        }
        let va = |pa: u64| crate::layout::ECAM_X86.base + (pa - w.base) as usize;
        // The whole plan first: a window that cannot all be carved is not
        // carved at all.  Carving a block only splits Untypeds, so each
        // later block stays inside a free one (they are buddies).
        // A block per bus with an odd-MiB base; more only if free device
        // memory is split below 1 MiB, which then refuses the window.
        let mut plan = l4h_host::fixed::ArrayVec::<(u64, u32), 256>::new();
        for b in crate::acs::blocks(start, end, w.base, |at| devmem.free_bits(at as usize)) {
            if b.1 < 12 {
                return Err("not free device memory");
            }
            plan.push(b).map_err(|_| "split into too many pieces of device memory")?;
        }
        for &(at, bits) in plan.iter() {
            let ok = alloc.global(|alloc| {
                if bits >= 21 {
                    let frames = alloc.slots.global(|slots| devmem.large_frames(slots, at as usize, 1 << bits))?;
                    for (i, s) in frames.enumerate() {
                        let f = sel4::init_thread::Slot::<cap_type::LargePage>::from_index(s).cap();
                        crate::vspace::map_large_page_attrs(&mut ObjCtx::global(alloc), slot::VSPACE.cap(), f,
                            va(at) + (i << 21), CapRights::read_write(), crate::blkd::DEVICE_ATTRS);
                    }
                } else {
                    let frames = alloc.slots.global(|slots| devmem.frames(slots, at as usize, 1 << bits))?;
                    for (i, s) in frames.enumerate() {
                        crate::vspace::map_frame(&mut ObjCtx::global(alloc), slot::VSPACE.cap(), crate::devmem::granule(s),
                            va(at) + (i << 12), CapRights::read_write(), crate::blkd::DEVICE_ATTRS);
                    }
                }
                Some(())
            });
            // The device memory table is full: what was mapped stays so, unused.
            ok.ok_or("the device memory table is full")?;
        }
        self.windows.must_push((w.base, start, end));
        self.ext = true;
        let (mut n, mut mismatched) = (0, 0);
        for bdf in self.pcie_functions(w.bus_lo, w.bus_hi) {
            let id = unsafe { (Self::ecam_va(bdf) as *const u32).read_volatile() };
            if id != crate::acs::Config::read(self, bdf, 0) {
                mismatched += 1;
                continue;
            }
            ECAM_MAPPED[bdf as usize / 64].fetch_or(1 << (bdf % 64), core::sync::atomic::Ordering::Relaxed);
            ECAM_WRITABLE[bdf as usize / 64].fetch_or(1 << (bdf % 64), core::sync::atomic::Ordering::Relaxed);
            n += 1;
        }
        Ok((n, mismatched))
    }

    /// The PCI Express functions on buses lo..=hi, through the ports.
    fn pcie_functions(&self, lo: u8, hi: u8) -> impl Iterator<Item = u16> + '_ {
        (lo as u32..=hi as u32).flat_map(move |bus| (0..32u32).map(move |dev| (bus as u8, dev as u8)))
            .filter(move |&(bus, dev)| self.read32(bus, dev, 0, 0) & 0xffff != 0xffff)
            .flat_map(move |(bus, dev)| {
                let funcs = if self.read8(bus, dev, 0, 0xe) & 0x80 != 0 { 8 } else { 1 };
                (0..funcs).map(move |func| (bus as u16) << 8 | (dev as u16) << 3 | func as u16)
            })
            .filter(move |&bdf| crate::acs::Config::read(self, bdf, 0) & 0xffff != 0xffff
                && crate::acs::pcie_type(self, bdf).is_some())
    }

    /// An access of trustd's AML (trustd::hw) to memory in an ECAM window
    /// root mapped (`map_extended`), which device memory no longer has:
    /// through root's mapping.  The caller has applied the AML's policy;
    /// `width` is 1, 2, 4 or 8 and `paddr` aligned to it.  None if
    /// `paddr` is in no such window.
    pub fn ecam_memory(&self, paddr: usize, width: usize, write: bool, value: u64) -> Option<u64> {
        let pa = paddr as u64;
        let &(base, _, _) = self.windows.iter().find(|&&(_, s, e)| s <= pa && pa.checked_add(width as u64).is_some_and(|x| x <= e))?;
        let p = crate::layout::ECAM_X86.base + (pa - base) as usize;
        Some(unsafe {
            match (width, write) {
                (1, false) => (p as *const u8).read_volatile() as u64,
                (2, false) => (p as *const u16).read_volatile() as u64,
                (4, false) => (p as *const u32).read_volatile() as u64,
                (_, false) => (p as *const u64).read_volatile(),
                (1, true) => { (p as *mut u8).write_volatile(value as u8); 0 }
                (2, true) => { (p as *mut u16).write_volatile(value as u16); 0 }
                (4, true) => { (p as *mut u32).write_volatile(value as u32); 0 }
                (_, true) => { (p as *mut u64).write_volatile(value); 0 }
            }
        })
    }

    /// Turn on ACS in every function root can write that has it (acs.rs),
    /// mapping the MCFG's segment 0 `windows` first if a partition has
    /// not; check it in the bridges above a partition's functions, which
    /// it maps read-only; and report the PCIe ports with functions below
    /// them that do not isolate them, including those root cannot reach.
    pub fn enable_acs(&mut self, alloc: &mut Alloc, devmem: &mut crate::devmem::DevMem, windows: &[l4h_host::trust::Ecam]) {
        use crate::acs::{self, Acs, Bits};
        let partition = crate::partition::get().is_some();
        if !partition {
            let mut covered = [0u64; 4];
            for w in windows.iter().filter(|w| w.segment == 0) {
                let buses = w.bus_lo as usize..=w.bus_hi as usize;
                if buses.clone().any(|b| covered[b / 64] & (1 << (b % 64)) != 0) {
                    log!("l4h-root: ECAM at {:#x}, buses {:02x}-{:02x}, overlaps another window: unused", w.base, w.bus_lo, w.bus_hi);
                    continue;
                }
                buses.for_each(|b| covered[b / 64] |= 1 << (b % 64));
                match self.map_extended(alloc, devmem, w) {
                    Ok((n, 0)) => info!("l4h-root: ECAM at {:#x}, buses {:02x}-{:02x}: {} PCIe functions", w.base, w.bus_lo, w.bus_hi, n),
                    Ok((n, bad)) => log!("l4h-root: ECAM at {:#x}, buses {:02x}-{:02x}: {} PCIe functions, {} whose ECAM ID differs from the ports' (left alone)",
                        w.base, w.bus_lo, w.bus_hi, n, bad),
                    Err(why) => log!("l4h-root: ECAM at {:#x}, buses {:02x}-{:02x}: unused, {}", w.base, w.bus_lo, w.bus_hi, why),
                }
            }
        }
        if !self.ext {
            log!("l4h-root: no usable ECAM (MCFG): PCIe ACS is off, and devices behind a PCIe switch or root port may reach each other without the IOMMU");
        }
        let (mut on, mut open) = (0, 0);
        for bdf in self.reachable() {
            let (b, d, f) = (bdf >> 8, bdf >> 3 & 0x1f, bdf & 7);
            let ty = acs::pcie_type(self, bdf);
            let r = if Self::bit(&ECAM_WRITABLE, bdf) { acs::enable(self, bdf) } else { acs::state(self, bdf) };
            if let Acs::Present { cap, before, after } = r && Self::bit(&ECAM_WRITABLE, bdf) {
                if after & cap & acs::ENABLE != cap & acs::ENABLE {
                    log!("l4h-root: pci {:02x}:{:02x}.{}: ACS control is {} after root set {}", b, d, f, Bits(after), Bits(before | cap & acs::ENABLE));
                } else if after != before {
                    on += 1;
                    info!("l4h-root: pci {:02x}:{:02x}.{}: ACS {} (was {})", b, d, f, Bits(after), Bits(before));
                }
            }
            if !r.isolates() && let Some(port) = port_name(ty) && acs::has_children(self, bdf) {
                open += 1;
                let why = if r == Acs::Absent { "has no ACS" } else { "does not isolate with ACS" };
                log!("l4h-root: pci {:02x}:{:02x}.{}: {} {}: the devices below it may reach each other without the IOMMU", b, d, f, port, why);
            }
        }
        // Ports whose extended space root cannot read at all: outside the
        // windows, or whose ECAM ID did not match.  A partition's other
        // functions are other partitions' business.
        if !partition {
            for bdf in self.pcie_functions(0, u8::MAX) {
                if Self::bit(&ECAM_MAPPED, bdf) {
                    continue;
                }
                if let Some(port) = port_name(acs::pcie_type(self, bdf)) && acs::has_children(self, bdf) {
                    open += 1;
                    log!("l4h-root: pci {:02x}:{:02x}.{}: {} without ECAM: its ACS cannot be set, and the devices below it may reach each other without the IOMMU",
                        bdf >> 8, bdf >> 3 & 0x1f, bdf & 7, port);
                }
            }
        }
        info!("l4h-root: PCIe ACS set in {} functions; {} ports with devices do not isolate them", on, open);
    }

    /// The functions whose extended configuration space root can read.
    fn reachable(&self) -> impl Iterator<Item = u16> + '_ {
        (0..=u16::MAX).filter(move |&bdf| self.ext && Self::bit(&ECAM_MAPPED, bdf))
    }

    fn ecam_va(bdf: u16) -> usize {
        crate::layout::ECAM_X86.base + (bdf as usize) * 4096
    }

    /// The function's ECAM page, if this partition has it.
    fn ecam_page(&self, bus: u8, dev: u8, func: u8) -> Option<usize> {
        let bdf = (bus as u16) << 8 | (dev as u16) << 3 | func as u16;
        let mapped = ECAM_MAPPED[bdf as usize / 64].load(core::sync::atomic::Ordering::Relaxed) & (1 << (bdf % 64)) != 0;
        mapped.then(|| Self::ecam_va(bdf))
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
        if self.ecam {
            // Another partition's function, or none, reads as absent.
            return self.ecam_page(bus, dev, func)
                .map_or(u32::MAX, |p| unsafe { ((p + (off as usize & 0xfc)) as *const u32).read_volatile() });
        }
        let bdf = (bus as u16) << 8 | (dev as u16) << 3 | func as u16;
        if self.shared_ports && !Self::bit(&ECAM_MAPPED, bdf) {
            return u32::MAX;
        }
        let port = self.port;
        self.ports(|| sel4::with_ipc_buffer_mut(|ipc| {
            let ipc = ipc.inner_mut();
            ipc.seL4_X86_IOPort_Out32(port, CONFIG_ADDRESS as u64, Self::addr(bus, dev, func, off));
            ipc.seL4_X86_IOPort_In32(port, CONFIG_DATA).result
        }))
    }

    fn bit(map: &[core::sync::atomic::AtomicU64; 1024], bdf: u16) -> bool {
        map[bdf as usize / 64].load(core::sync::atomic::Ordering::Relaxed) & (1 << (bdf % 64)) != 0
    }

    /// An address-then-data access to the ports, under the partitions'
    /// lock when others use them too.
    fn ports<R>(&self, f: impl FnOnce() -> R) -> R {
        let lock = if self.shared_ports { crate::iommu::shared::get() } else { None };
        if let Some(s) = lock {
            s.lock_pci();
        }
        let r = f();
        if let Some(s) = lock {
            s.unlock_pci();
        }
        r
    }

    /// A dword of extended configuration space, through the function's
    /// ECAM page.
    pub fn read_ext32(&self, bdf: u16, off: u16) -> Option<u32> {
        if !self.ext || off >= 4096 {
            return None;
        }
        let p = self.ecam_page((bdf >> 8) as u8, (bdf >> 3 & 0x1f) as u8, (bdf & 7) as u8)?;
        Some(unsafe { ((p + (off as usize & 0xffc)) as *const u32).read_volatile() })
    }

    /// Write one: false unless the page is mapped and the function this
    /// partition's.
    pub fn write_ext32(&self, bdf: u16, off: u16, val: u32) -> bool {
        if !self.ext || off >= 4096 || !Self::bit(&ECAM_WRITABLE, bdf) {
            return false;
        }
        let Some(p) = self.ecam_page((bdf >> 8) as u8, (bdf >> 3 & 0x1f) as u8, (bdf & 7) as u8) else { return false };
        unsafe { ((p + (off as usize & 0xffc)) as *mut u32).write_volatile(val) };
        true
    }

    pub fn write32(&self, bus: u8, dev: u8, func: u8, off: u8, val: u32) {
        if self.ecam {
            let bdf = (bus as u16) << 8 | (dev as u16) << 3 | func as u16;
            if ECAM_WRITABLE[bdf as usize / 64].load(core::sync::atomic::Ordering::Relaxed) & (1 << (bdf % 64)) == 0 {
                refused_write(bus, dev, func);
                return;
            }
            if let Some(p) = self.ecam_page(bus, dev, func) {
                unsafe { ((p + (off as usize & 0xfc)) as *mut u32).write_volatile(val) };
            }
            return;
        }
        if self.shared_ports && !Self::bit(&ECAM_WRITABLE, (bus as u16) << 8 | (dev as u16) << 3 | func as u16) {
            refused_write(bus, dev, func);
            return;
        }
        let port = self.port;
        self.ports(|| sel4::with_ipc_buffer_mut(|ipc| {
            let ipc = ipc.inner_mut();
            ipc.seL4_X86_IOPort_Out32(port, CONFIG_ADDRESS as u64, Self::addr(bus, dev, func, off));
            ipc.seL4_X86_IOPort_Out32(port, CONFIG_DATA as u64, val as u64);
        }));
    }

}

#[cfg(target_arch = "x86_64")]
impl crate::acs::Config for Pci {
    fn read(&self, bdf: u16, off: u8) -> u32 {
        self.read32((bdf >> 8) as u8, (bdf >> 3 & 0x1f) as u8, (bdf & 7) as u8, off)
    }
    fn read_ext(&self, bdf: u16, off: u16) -> Option<u32> {
        self.read_ext32(bdf, off)
    }
    fn write_ext(&self, bdf: u16, off: u16, val: u32) -> bool {
        self.write_ext32(bdf, off, val)
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

    /// The capabilities of a function with BARs `bars`.  The device says
    /// where they are and what they point at: one that does not fit in
    /// configuration space, or whose table or structure is not inside a
    /// memory BAR, is ignored (users index `bars` with it, and map and
    /// write the pages it names).
    fn caps(&self, bus: u8, dev: u8, func: u8, bars: &[Bar; 6]) -> (Option<Msix>, Option<Msi>, VirtioCaps) {
        let mut msix = None;
        let mut msi = None;
        let mut virtio = VirtioCaps::new();
        if self.read16(bus, dev, func, 6) & 0x10 == 0 {
            return (msix, msi, virtio);
        }
        let inside = |bar: u8, off: u32, len: u64| bars.get(bar as usize).is_some_and(|b| !b.is_io && off as u64 + len <= b.size);
        let mut ptr = self.read8(bus, dev, func, 0x34) & !3;
        let mut guard = 0;
        while ptr != 0 && guard < 48 {
            let fits = |len: usize| ptr as usize + len <= 0x100;
            let id = self.read8(bus, dev, func, ptr);
            match id {
                0x11 if fits(12) => {
                    let ctrl = self.read16(bus, dev, func, ptr + 2);
                    let table = self.read32(bus, dev, func, ptr + 4);
                    let m = Msix { cap: ptr, table_bar: (table & 7) as u8, table_offset: table & !7, table_size: (ctrl & 0x7ff) + 1 };
                    if inside(m.table_bar, m.table_offset, m.table_size as u64 * 16) {
                        msix = Some(m);
                    }
                }
                0x05 => {
                    let ctrl = self.read16(bus, dev, func, ptr + 2);
                    let m = Msi { cap: ptr, is64: ctrl & 0x80 != 0, maskable: ctrl & 0x100 != 0 };
                    // Through the data, and the mask bits (enable_msi).
                    if fits(if m.is64 { 0x10 } else { 0xc } + if m.maskable { 4 } else { 0 }) {
                        msi = Some(m);
                    }
                }
                0x09 if fits(16) => {
                    let cfg_type = self.read8(bus, dev, func, ptr + 3);
                    let bar = self.read8(bus, dev, func, ptr + 4);
                    let offset = self.read32(bus, dev, func, ptr + 8);
                    let length = self.read32(bus, dev, func, ptr + 12);
                    // The notify structure's multiplier follows.
                    if inside(bar, offset, length as u64) && (cfg_type != 2 || fits(20)) {
                        let mult = if cfg_type == 2 { self.read32(bus, dev, func, ptr + 16) } else { 0 };
                        virtio.push(VirtioCap { cfg_type, bar, offset, length, notify_off_multiplier: mult });
                    }
                }
                _ => {}
            }
            ptr = self.read8(bus, dev, func, ptr + 1) & !3;
            guard += 1;
        }
        (msix, msi, virtio)
    }

    /// Every PCI function, in bus, device, function order, each probed as
    /// the iterator reaches it.
    pub fn enumerate(&self) -> Devices<'_> {
        Devices { pci: self, next: 0, multi: false, list: crate::partition::get().map(|d| d.funcs()) }
    }

    /// The function at bus:dev.func, if there is one.
    fn probe(&self, bus: u8, dev: u8, func: u8) -> Option<Device> {
        let id = self.read32(bus, dev, func, 0);
        if id & 0xffff == 0xffff {
            return None;
        }
        let class = self.read32(bus, dev, func, 8);
        let header = self.read8(bus, dev, func, 0xe) & 0x7f;
        // A partition never sizes a BAR: sizing stops the function
        // decoding, and the shim sized them all before any kernel ran.
        let bdf = (bus as u16) << 8 | (dev as u16) << 3 | func as u16;
        #[allow(unused_mut)]
        let mut bars = match crate::partition::get().and_then(|d| d.funcs().iter().find(|f| f.bdf == bdf)) {
            Some(f) => core::array::from_fn(|i| {
                let b = f.bars[i];
                Bar { addr: b.addr, size: b.size, is_io: b.flags & l4h_partition::BAR_IO != 0 }
            }),
            None if header == 0 => self.probe_bars(bus, dev, func),
            None => [Bar::default(); 6],
        };
        #[cfg(target_arch = "aarch64")]
        for (n, b) in bars.iter_mut().enumerate() {
            if b.size == 0 || b.is_io { continue; }
            // The size is the device's: a power of two, and the BAR must fit.
            let end = Some(b.size).filter(|s| s.is_power_of_two())
                .and_then(|s| self.next_bar.get().checked_next_multiple_of(s)?.checked_add(s))
                .filter(|&end| end <= 0x3eff_0000);
            let Some(end) = end else {
                log!("l4h-root: pci {:02x}:{:02x}.{}: BAR {} of {:#x} bytes does not fit the MMIO aperture, unused", bus, dev, func, n, b.size);
                *b = Bar::default();
                continue;
            };
            let addr = end - b.size;
            let off = 0x10 + 4 * n as u8;
            let flags = self.read32(bus, dev, func, off) & 0xf;
            self.write32(bus, dev, func, off, addr as u32 | flags);
            if flags & 6 == 4 { self.write32(bus, dev, func, off + 4, 0); }
            b.addr = addr;
            self.next_bar.set(addr + b.size);
        }
        let (msix, msi, virtio_caps) = self.caps(bus, dev, func, &bars);
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
            msix,
            msi,
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

    /// Stop the device: no DMA, no memory decoding, MSI-X off.  This alone
    /// does not quiesce a device that has commands (blkd::reset does).
    pub fn disable(&self, d: &Device) {
        let cmd = self.read16(d.bus, d.dev, d.func, 4);
        self.write16(d.bus, d.dev, d.func, 4, (cmd & !0x6) | 0x400);
        if let Some(m) = d.msix {
            let ctrl = self.read16(d.bus, d.dev, d.func, m.cap + 2);
            self.write16(d.bus, d.dev, d.func, m.cap + 2, ctrl & !0x8000);
        }
        self.disable_msi(d);
    }

    /// Program plain MSI with one vector (`address`, `data`) and enable it,
    /// INTx off.  MSI-X, if the function also has it, stays off.
    pub fn enable_msi(&self, d: &Device, address: u64, data: u32) {
        let Some(m) = d.msi else { return };
        let (b, dv, f, c) = (d.bus, d.dev, d.func, m.cap);
        let ctrl = self.read16(b, dv, f, c + 2);
        // Disabled while it changes; one vector (Multiple Message Enable 0).
        self.write16(b, dv, f, c + 2, ctrl & !(1 | 0x70));
        self.write32(b, dv, f, c + 4, address as u32);
        let data_off = if m.is64 {
            self.write32(b, dv, f, c + 8, (address >> 32) as u32);
            c + 12
        } else {
            c + 8
        };
        self.write16(b, dv, f, data_off, data as u16);
        if m.maskable {
            // The mask bits follow the data (and a reserved word).
            self.write32(b, dv, f, data_off + 4, 0);
        }
        let cmd = self.read16(b, dv, f, 4);
        self.write16(b, dv, f, 4, cmd | 0x400);
        self.write16(b, dv, f, c + 2, (ctrl & !0x70) | 1);
    }

    /// Turn plain MSI off.
    pub fn disable_msi(&self, d: &Device) {
        if let Some(m) = d.msi {
            let ctrl = self.read16(d.bus, d.dev, d.func, m.cap + 2);
            self.write16(d.bus, d.dev, d.func, m.cap + 2, ctrl & !1);
        }
    }

    /// Turn bus mastering on or off, leaving decoding as it is.  Off,
    /// the device issues no more DMA, and what it already issued has
    /// reached memory on return: the command register is read back, and
    /// that read's completion may not pass the device's posted writes
    /// (PCIe 6.0 §2.4.1, root-issued requests carry no Relaxed Ordering).
    pub fn bus_master(&self, d: &Device, on: bool) {
        let cmd = self.read16(d.bus, d.dev, d.func, 4);
        self.write16(d.bus, d.dev, d.func, 4, if on { cmd | 0x4 } else { cmd & !0x4 });
        if !on {
            let _ = self.read16(d.bus, d.dev, d.func, 4);
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
    /// A partition's functions, instead of a scan of every bus.
    list: Option<&'static [l4h_partition::Func]>,
}

impl Iterator for Devices<'_> {
    type Item = Device;

    fn next(&mut self) -> Option<Device> {
        if let Some(list) = self.list {
            while let Some(f) = list.get(self.next as usize) {
                self.next += 1;
                if let Some(d) = self.pci.probe((f.bdf >> 8) as u8, (f.bdf >> 3 & 0x1f) as u8, (f.bdf & 7) as u8) {
                    return Some(d);
                }
            }
            return None;
        }
        let end = MAX_FUNCTIONS as u32;
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
            if let Some(d) = self.pci.probe(bus, dev, func) {
                return Some(d);
            }
        }
        None
    }
}

/// MSI target address, and data for a reserved interrupt slot.
pub fn msi_address() -> u64 {
    // Physical destination mode, to the partition's first CPU (APIC ID 0
    // when root has the machine to itself).  The shim gives no partition a
    // first CPU above APIC ID 255.
    #[cfg(target_arch = "x86_64")] { 0xfee0_0000 | (crate::partition::msi_dest() as u64 & 0xff) << 12 }
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

/// What the log calls a PCIe port of Device/Port Type `ty` (acs::pcie_type),
/// if ACS isolation below it matters.
#[cfg(target_arch = "x86_64")]
fn port_name(ty: Option<u8>) -> Option<&'static str> {
    match ty {
        Some(crate::acs::ROOT_PORT) => Some("root port"),
        Some(crate::acs::DOWNSTREAM_PORT) => Some("switch downstream port"),
        _ => None,
    }
}

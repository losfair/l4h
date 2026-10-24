//! Passing a disk (virtio-blk, virtio-scsi or NVMe PCI device) through to
//! a guest: a blkd component drives the device, and the guest's l4h-vmm
//! presents it as virtio-l4h.

use core::ops::Range;
use core::ptr::addr_of_mut;
use core::sync::atomic::{AtomicUsize, Ordering};

use sel4::{CapRights, VmAttributes, cap, cap_type};

use l4h_abi as abi;
use l4h_host::{self as host, blk};

use crate::component::{self, Component, SpawnArgs, abs_of};
use crate::devmem::DevMem;
use crate::guest::Guest;
use crate::amdvi::{AmdVi, Domain};
use crate::mem::{Alloc, Arena, Dest, Slot};
use crate::pci::{self, Pci};
use crate::vmm;
use crate::vspace::FRAME_BP;
use crate::window::Window;
use crate::{AsidPools, HostInfo};

static BLKD_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/l4h-blkd.elf"));

const PAGE: usize = 4096;

/// Disk windows start and end on a multiple of this many 512-byte sectors
/// (4 KiB), the largest logical block size blkd supports: devices address
/// whole blocks, so an unaligned window would reach outside itself.
pub const WINDOW_ALIGN: u64 = 8;

/// Mapping attributes for device registers.
#[cfg(target_arch = "x86_64")]
pub const DEVICE_ATTRS: VmAttributes = VmAttributes::CACHE_DISABLED;
#[cfg(target_arch = "aarch64")]
pub const DEVICE_ATTRS: VmAttributes = VmAttributes::EXECUTE_NEVER;

/// Mapping attributes for device memory written in bursts (ENA's LLQ):
/// write-combining where the architecture has it.
fn wc_attrs() -> VmAttributes {
    #[cfg(target_arch = "x86_64")]
    return VmAttributes::from_inner(sel4::sys::seL4_X86_VMAttributes::seL4_X86_WriteCombining);
    #[cfg(target_arch = "aarch64")]
    return DEVICE_ATTRS;
}
const DMA_BITS: usize = 22;
/// Each BAR is mapped at MMIO_VA + bar * BAR_STRIDE.
pub const BAR_STRIDE: usize = 0x100_0000;

const VIRTIO_VENDOR: u16 = 0x1af4;
const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
const VIRTIO_PCI_CAP_ISR_CFG: u8 = 3;
const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;

/// A disk controller (PCI device) and its persistent blkd.  Its disks are
/// the units blkd finds: one, or each logical unit of a virtio-scsi
/// controller.
pub struct Controller {
    pub pci: pci::Device,
    pub kind: u32,
    /// MSI vector (seL4 delivers vector n at CPU vector 0x30 + n).
    vector: u64,
    /// Frames of the BARs the driver uses, carved once.
    bars: BarCache,
    /// blkd's client channels, shared by the controller's disks: this
    /// controller's row of CLIENTS.
    pub clients: &'static mut [Option<Attachment>; blk::MAX_CLIENTS],
    /// Reset, provisioning or drain failed: the device may still access
    /// its DMA targets, so it is quarantined until host reboot.
    pub failed: bool,
    /// IOPort capability for the registers of a legacy virtio device,
    /// issued once.
    io: Option<cap::Null>,
    driver: Option<Blkd>,
    /// The device's IOMMU domain: blkd's DMA memory and its clients'
    /// I/O pools.
    dom: Domain,
}

/// A host disk: unit `unit` of controller `ctrl`.
pub struct Disk {
    pub ctrl: usize,
    pub unit: u64,
    /// Known once the controller's blkd runs (0 before).
    pub capacity: u64,
    pub block_size: u32,
    pub read_only: bool,
    /// Where the unit is on the controller (blk::BLKD_INFO).
    pub address: u64,
}

impl Disk {
    pub fn new(ctrl: usize, unit: u64) -> Self {
        Disk { ctrl, unit, capacity: 0, block_size: 0, read_only: false, address: 0 }
    }
}

/// The client slots of every controller, in .bss: one controller's are
/// 20 KiB, too much to pass by value on root's 64 KiB stack.  Controllers
/// live until reboot, so each takes the next row, CLIENT_ROWS of them.
static mut CLIENTS: [[Option<Attachment>; blk::MAX_CLIENTS]; pci::MAX_DISK_CTRLS] =
    [const { [const { None }; blk::MAX_CLIENTS] }; pci::MAX_DISK_CTRLS];
static CLIENT_ROWS: AtomicUsize = AtomicUsize::new(0);

impl Controller {
    /// At most pci::MAX_DISK_CTRLS controllers can be made.
    pub fn new(pci: pci::Device, vector: u64) -> Self {
        let kind = if is_nvme(&pci) {
            blk::BLKD_NVME
        } else if is_virtio_scsi(&pci) {
            blk::BLKD_VIRTIO_SCSI
        } else {
            blk::BLKD_VIRTIO
        };
        let row = CLIENT_ROWS.fetch_add(1, Ordering::Relaxed);
        assert!(row < pci::MAX_DISK_CTRLS, "more than {} disk controllers", pci::MAX_DISK_CTRLS);
        // Each row is handed out once, so this is its only reference.
        let clients = unsafe { &mut (*addr_of_mut!(CLIENTS))[row] };
        Controller { pci, kind, vector, bars: [const { None }; 6], clients, failed: false, io: None, driver: None, dom: Domain::NONE }
    }

    /// The attachments of disk `disk`, with their client indices.
    pub fn attachments(&self, disk: usize) -> impl Iterator<Item = (usize, &Attachment)> {
        self.clients.iter().enumerate().filter_map(move |(i, a)| a.as_ref().filter(|a| a.disk == disk).map(|a| (i, a)))
    }

    /// The first VM disk `disk` is attached to.
    pub fn owner(&self, disk: usize) -> Option<usize> {
        self.attachments(disk).next().map(|(_, a)| a.vm)
    }

    /// Ask blkd about `unit`: (disk geometry, number of units), None if
    /// there is no such unit.
    pub fn info(&self, unit: u64) -> (Option<Disk>, u64) {
        let capacity = call(self.driver.as_ref().expect("started blkd").comp.service_ep, blk::BLKD_INFO, &[unit]);
        let units = crate::mr(3);
        let disk = (capacity != u64::MAX).then(|| Disk {
            ctrl: 0, unit, capacity,
            block_size: crate::mr(1) as u32,
            read_only: crate::mr(2) != 0,
            address: crate::mr(4),
        });
        (disk, units)
    }

    /// Base of the I/O BAR of a legacy virtio device.
    fn legacy_io(&self) -> Option<u16> {
        is_legacy_virtio(&self.pci).then_some(self.pci.bars[0].addr as u16)
    }

    /// The IOPort capability of a legacy device, issued on first use.
    fn io_cap(&mut self, alloc: &mut Alloc) -> Option<cap::Null> {
        if self.io.is_none() {
            let base = self.legacy_io()?;
            self.io = pci::io_ports(alloc, base, self.pci.bars[0].size as u16);
        }
        self.io
    }

    pub fn kind_name(&self) -> &'static str {
        match self.kind {
            blk::BLKD_NVME => "nvme",
            blk::BLKD_VIRTIO_SCSI => "virtio-scsi",
            _ => "virtio-blk",
        }
    }
}

pub fn is_virtio_blk(d: &pci::Device) -> bool {
    d.vendor == VIRTIO_VENDOR
        && (d.device == 0x1042 || d.device == 0x1001)
        && d.virtio_caps.iter().any(|c| c.cfg_type == VIRTIO_PCI_CAP_COMMON_CFG)
        && d.msix.is_some()
}

/// A virtio 0.9.5 ("legacy") device: registers in I/O BAR 0, no virtio
/// capabilities.  GCE's virtio-net and virtio-scsi are legacy devices.
pub fn is_legacy_virtio(d: &pci::Device) -> bool {
    cfg!(target_arch = "x86_64") && d.virtio_caps.is_empty() && d.bars[0].is_io && d.bars[0].size >= 0x20
}

/// A virtio-scsi controller, modern or legacy (as on GCE).
pub fn is_virtio_scsi(d: &pci::Device) -> bool {
    d.vendor == VIRTIO_VENDOR
        && (d.device == 0x1048 || d.device == 0x1004)
        && (d.virtio_caps.iter().any(|c| c.cfg_type == VIRTIO_PCI_CAP_COMMON_CFG) || (d.device == 0x1004 && is_legacy_virtio(d)))
        && d.msix.is_some()
}

pub fn is_nvme(d: &pci::Device) -> bool {
    d.class == 0x01 && d.subclass == 0x08 && d.prog_if == 0x02 && d.msix.is_some() && d.bars[0].size >= 0x2000
}

/// Disks l4h can pass through.
pub fn is_disk(d: &pci::Device) -> bool {
    is_virtio_blk(d) || is_virtio_scsi(d) || is_nvme(d)
}

pub struct Attachment {
    pub vm: usize,
    /// Host disk index.
    pub disk: usize,
    pub window: blk::DiskWindow,
    pub read_only: bool,
    /// The client's I/O pool: physical address and size.
    pool: (usize, usize),
}

struct Blkd {
    comp: Component,
    arena: Arena,
    /// Slots of the frames of the staging buffer (the end of the DMA
    /// memory).
    staging: Range<Slot>,
}

fn bdf(d: &pci::Device) -> u32 {
    ((d.bus as u32) << 8) | ((d.dev as u32) << 3) | d.func as u32
}

/// Start one persistent driver for the physical controller, at boot: the
/// host fails to boot if there is no memory for it.  Never for a
/// controller whose reset failed: it must stay disabled.
#[allow(clippy::too_many_arguments)]
pub fn start(
    id: u32,
    disk: &mut Controller,
    pci: &Pci,
    iommu: &mut AmdVi,
    devmem: &mut DevMem,
    alloc: &mut Alloc,
    win: &mut Window,
    asids: &mut AsidPools,
    host_info: &HostInfo,
) {
    assert!(
        !disk.failed,
        "l4h-root: cannot start disk {:02x}:{:02x}.{}: reset failed",
        disk.pci.bus, disk.pci.dev, disk.pci.func
    );
    let io = disk.io_cap(alloc);
    let legacy_io = disk.legacy_io();
    let d = &disk.pci;
    let bar_va = |b: u8| host::MMIO_VA + b as usize * BAR_STRIDE;
    let msix = d.msix.unwrap();
    let msix_table = blk::PciRegion {
        va: (bar_va(msix.table_bar) + msix.table_offset as usize) as u64,
        len: msix.table_size as u64 * 16,
    };
    // The BARs to map, bit b for BAR b.
    let (regions, bars) = if disk.kind == blk::BLKD_NVME {
        (None, 1u8)
    } else if legacy_io.is_some() {
        (None, 0)
    } else {
        (Some(virtio_regions(d, bar_va)), virtio_bar_mask(d))
    };
    let bars = bars | 1 << msix.table_bar;

    let mut arena = alloc.arena(8 << 20).expect("blkd arena");

    // ---- DMA memory: one physically contiguous chunk.
    let dma_slot = alloc.slots.alloc();
    let mut dma_region = alloc.split(DMA_BITS, dma_slot).expect("blkd DMA memory");
    let dma_paddr = dma_region.paddr;
    let n_dma = (1 << DMA_BITS) / PAGE;
    let dma_frames = alloc.slots.alloc_range(n_dma);
    dma_region
        .retype(&FRAME_BP, n_dma, Dest::root(dma_frames.start))
        .expect("blkd DMA frames");
    arena.own(dma_slot, dma_paddr, DMA_BITS);
    // The device reaches this memory, and the pools of attached clients.
    let dom = iommu.attach(alloc, d);
    iommu.map(alloc, dom, dma_paddr, 1 << DMA_BITS, true);

    // Plain integers: all zeroes is a valid (empty) configuration.
    let mut cfg: blk::BlkdConfig = unsafe { core::mem::zeroed() };
    cfg.kind = disk.kind;
    cfg.legacy_io = legacy_io.unwrap_or(0) as u32;
    cfg.bar0 = blk::PciRegion { va: bar_va(0) as u64, len: d.bars[0].size };
    cfg.pci_bdf = bdf(d);
    let vector = disk.vector;
    cfg.msi_data = iommu.msi_data(dom, vector);
    cfg.msi_address = pci::msi_address();
    if let Some(VirtioRegions { common, notify, notify_mult, isr, device, .. }) = regions {
        cfg.common = common;
        cfg.notify = notify;
        cfg.notify_off_multiplier = notify_mult;
        cfg.isr = isr;
        cfg.device = device;
    }
    cfg.msix_table = msix_table;
    cfg.dma_va = host::DMA_VA as u64;
    cfg.dma_paddr = dma_paddr as u64;
    // Keep a 1 MiB scratch buffer beyond the driver's queue allocator.
    cfg.dma_size = (1 << DMA_BITS) - blk::STAGING_SIZE as u64;
    let cfg_bytes = unsafe {
        core::slice::from_raw_parts(&cfg as *const blk::BlkdConfig as *const u8, core::mem::size_of::<blk::BlkdConfig>())
    };

    let args = SpawnArgs {
        id,
        kind: host::KIND_BLKD,
        elf: BLKD_ELF,
        core: 0,
        prio: abi::PRIO_KERNEL + 2,
        budget_us: host_info.timeslice_us,
        period_us: host_info.timeslice_us,
        config: cfg_bytes,
        ntfn: None,
        service_ep: None,
        cnode: None,
        cnode_bits: None,
    };
    let comp = component::create(&args, alloc, &mut arena, win, asids, host_info);

    // Mapping caps are kept in a CNode of the arena, sized for the BARs.
    let keep_bits = keep_bits(n_dma + bar_pages(d, bars));
    let keep = arena.object_cap::<cap_type::CNode>(alloc, sel4::ObjectBlueprint::CNode { size_bits: keep_bits });
    let mut keep_next = 0u64;
    let mut keep_slot = || {
        let s = keep.absolute_cptr_from_bits_with_depth(keep_next, keep_bits);
        keep_next += 1;
        s
    };

    // ---- Device BARs (uncached).
    map_bar_mask(&comp, alloc, &mut arena, devmem, d, &mut disk.bars, bars, 0, bar_va, &mut keep_slot);
    for i in 0..n_dma {
        let f = sel4::init_thread::Slot::<cap_type::Granule>::from_index(dma_frames.start + i).cap();
        comp.map_copy(alloc, &mut arena, &abs_of(f), host::DMA_VA + i * PAGE, CapRights::read_write(), VmAttributes::DEFAULT, keep_slot());
    }
    // ---- Interrupt, notifications.
    let irq_slot = alloc.slots.global(|s| s.alloc());
    pci::msi_irq(d, vector, &abs_of(sel4::init_thread::Slot::<cap_type::Null>::from_index(irq_slot).cap()));
    let irq = sel4::init_thread::Slot::<cap_type::IrqHandler>::from_index(irq_slot).cap();
    let irq_ntfn_slot = alloc.slots.alloc();
    let irq_ntfn = sel4::init_thread::Slot::<cap_type::Notification>::from_index(irq_ntfn_slot).cap();
    abs_of(irq_ntfn).mint(&abs_of(comp.ntfn), CapRights::all(), blk::BLKD_BADGE_IRQ).expect("IRQ notification");
    irq.irq_handler_set_notification(irq_ntfn).expect("IRQ set notification");
    comp.give(blk::BLKD_SLOT_IRQ, irq, CapRights::all());
    if legacy_io.is_some() {
        comp.give(blk::BLKD_SLOT_IOPORT, io.expect("legacy virtio I/O ports"), CapRights::all());
        pci.enable_io(d);
    }
    pci.enable(d);
    pci.enable_msix(d);
    component::start(&comp);

    let staging = dma_frames.start + n_dma - blk::STAGING_SIZE / PAGE..dma_frames.end;
    disk.driver = Some(Blkd { comp, arena, staging });
    disk.dom = dom;
}

/// A call to blkd.  One that has failed answers u64::MAX (l4h_rt::abort_trap).
fn call(ep: cap::Endpoint, label: u64, args: &[u64]) -> u64 {
    for (i, &v) in args.iter().enumerate() { crate::set_mr(i, v); }
    ep.call(sel4::MessageInfo::new(label, 0, 0, args.len()));
    crate::mr(0)
}

/// Attach a checked window of host disk `disk` to one client of its
/// running shared controller.
#[allow(clippy::too_many_arguments)]
pub fn attach(ctrl: &mut Controller, disk: usize, client: &mut Guest, dev_index: usize,
    window: blk::DiskWindow, read_only: bool, alloc: &mut Alloc, iommu: &mut AmdVi) -> (usize, vmm::Backend) {
    let i = ctrl.clients.iter().position(Option::is_none).expect("free block client");
    let driver = ctrl.driver.as_mut().expect("started blkd");
    let chan: l4h_host::fixed::ArrayVec<cap::Granule, { blk::CHANNEL_PAGES }> = (0..blk::CHANNEL_PAGES)
        .map(|_| client.arena.object_cap::<cap_type::Granule>(alloc, FRAME_BP)).collect();
    let keep = client.arena.object_cap::<cap_type::CNode>(alloc, sel4::ObjectBlueprint::CNode { size_bits: 10 });
    // Initial values are delivered via the service call, not guest-chosen IDs.
    for (page, f) in chan.iter().enumerate() {
        alloc.global(|alloc| driver.comp.map_copy(alloc, &mut driver.arena, &abs_of(*f), blk::channel_va(i) + page * PAGE,
            CapRights::read_write(), VmAttributes::DEFAULT,
            keep.absolute_cptr_from_bits_with_depth(page as u64, 10)));
    }
    driver.comp.give_badged(blk::BLKD_SLOT_CLIENT_DONE + i as u64, client.vmm_ntfn,
        CapRights::write_only(), 1 << (host::VMM_BADGE_DONE_SHIFT as usize + dev_index));
    let kick_slot = alloc.slots.alloc();
    let kick = sel4::init_thread::Slot::<cap_type::Notification>::from_index(kick_slot).cap();
    abs_of(kick).mint(&abs_of(driver.comp.ntfn), CapRights::write_only(), blk::BLKD_BADGE_KICK).expect("blkd kick");
    // Reads write the pool, writes read it.
    let pool = (client.pool.paddr, client.pool.size);
    iommu.map(alloc, ctrl.dom, pool.0, pool.1, true);
    ctrl.clients[i] = Some(Attachment { vm: client.id, disk, window, read_only, pool });
    (i, vmm::Backend::Blk { chan, kick })
}

/// Publish root-owned client configuration, then activate the channel.
/// EIO if blkd has failed (the controller is then quarantined).
pub fn activate(ctrl: &mut Controller, unit: u64, i: usize, client: &Guest, backend: &vmm::Backend, win: &mut Window,
    pci: &Pci) -> Result<(), i64> {
    let vmm::Backend::Blk { chan, .. } = backend else { unreachable!() };
    let a = ctrl.clients[i].as_ref().unwrap();
    let read_only = a.read_only;
    win.with_frame(&abs_of(chan[0]), |p| unsafe {
        let c = p as *mut blk::Channel;
        core::ptr::addr_of_mut!((*c).capacity_sectors).write(a.window.sectors);
        core::ptr::addr_of_mut!((*c).lba_start).write(a.window.start);
        core::ptr::addr_of_mut!((*c).read_only).write(read_only as u32);
        core::ptr::addr_of_mut!((*c).pool).write(blk::Pool {
            gpa: client.pool.gpa as u64, paddr: client.pool.paddr as u64, size: client.pool.size as u64,
        });
    });
    if call(ctrl.driver.as_ref().unwrap().comp.service_ep, blk::BLKD_ADD, &[i as u64, unit]) != 0 {
        quarantine(ctrl, pci);
        return Err(crate::ctl::EIO);
    }
    Ok(())
}

/// Stop using controller `disk` until host reboot: its blkd is suspended
/// and the device can no longer reach memory.
fn quarantine(disk: &mut Controller, pci: &Pci) {
    disk.failed = true;
    let _ = disk.driver.as_ref().unwrap().comp.tcb.tcb_suspend();
    pci.disable(&disk.pci);
}

/// Drain this client before its memory is reused, then take its pool
/// away from the device. A timeout quarantines the controller and all
/// its DMA targets until host reboot. Whether the device can no longer
/// reach the pool: drained, or cut off by the IOMMU.
pub fn remove(disk: &mut Controller, i: usize, pci: &Pci, iommu: &mut AmdVi) -> bool {
    let driver = disk.driver.as_ref().unwrap();
    let quiet = !disk.failed && call(driver.comp.service_ep, blk::BLKD_REMOVE, &[i as u64]) == 0;
    if !quiet {
        quarantine(disk, pci);
    }
    let _ = disk.driver.as_ref().unwrap().comp.slot(blk::BLKD_SLOT_CLIENT_DONE + i as u64).delete();
    if let Some(a) = disk.clients[i].take() {
        iommu.unmap(disk.dom, a.pool.0, a.pool.1);
    }
    quiet || disk.dom != Domain::NONE
}

/// Provision an unattached range of host disk `index`. Data copies occur
/// only during seeding. A zero-length request flushes the disk. Never
/// trust discard to zero.
#[allow(clippy::too_many_arguments)]
pub fn write(ctrl: &mut Controller, index: usize, dk: &Disk, sector: u64, len: usize, from: Option<*const u8>,
    pci: &Pci, win: &mut Window) -> Result<(), i64> {
    if ctrl.failed { return Err(crate::ctl::EIO); }
    if dk.read_only { return Err(crate::ctl::EPERM); }
    if len > blk::STAGING_SIZE { return Err(crate::ctl::EINVAL); }
    if len != 0 {
        let w = blk::DiskWindow::new(sector, (len / 512) as u64, dk.capacity).ok_or(crate::ctl::EINVAL)?;
        if len % 4096 != 0 { return Err(crate::ctl::EINVAL); }
        if ctrl.attachments(index).any(|(_, a)| a.window.overlaps(w)) { return Err(crate::ctl::EBUSY); }
    }
    let disk = ctrl;
    let driver = disk.driver.as_ref().unwrap();
    for (i, s) in driver.staging.clone().take(len.div_ceil(PAGE)).enumerate() {
        let f = sel4::init_thread::Slot::<cap_type::Granule>::from_index(s).cap();
        win.with_frame(&abs_of(f), |p| unsafe {
            if let Some(from) = from { core::ptr::copy_nonoverlapping(from.add(i * PAGE), p, PAGE); }
            else { core::ptr::write_bytes(p, 0, PAGE); }
        });
    }
    let status = if len == 0 {
        call(driver.comp.service_ep, blk::BLKD_FLUSH, &[dk.unit])
    } else {
        call(driver.comp.service_ep, blk::BLKD_WRITE, &[sector, len as u64, dk.unit])
    };
    if status == 0 { return Ok(()); }
    if status == u64::MAX {
        quarantine(disk, pci);
    }
    Err(crate::ctl::EIO)
}

/// NVMe controller registers (in BAR 0).
const NVME_CAP: usize = 0x00;
const NVME_CC: usize = 0x14;
const NVME_CSTS: usize = 0x1c;
/// Offset of `device_status` in the virtio-pci common configuration.
const VIRTIO_DEVICE_STATUS: usize = 20;
/// Device status register of a legacy virtio device (I/O BAR 0).
const VIRTIO_LEGACY_STATUS: u16 = 0x12;
/// The virtio spec sets no bound on a reset.
const VIRTIO_RESET_MS: u64 = 2000;

/// Reset `disk` so that it can no longer access memory: NVMe clears
/// CC.EN and waits for CSTS.RDY to clear (within CAP.TO), which aborts all
/// commands and deletes the queues; virtio writes 0 to the device status
/// and waits until it reads back 0.  Memory (or I/O) decoding is turned on
/// for this; bus mastering is left as it is, so that DMA the device
/// finishes while resetting lands in memory that is still the client's.
/// On failure, marks the disk failed and returns false.
pub fn reset(disk: &mut Controller, pci: &Pci, alloc: &mut Alloc, devmem: &mut DevMem, win: &mut Window, ticks_per_ms: u64) -> bool {
    if disk.failed {
        return false;
    }
    if let Some(base) = disk.legacy_io() {
        let ok = match disk.io_cap(alloc) {
            Some(io) => {
                pci.enable_io(&disk.pci);
                pci::out8(io, base + VIRTIO_LEGACY_STATUS, 0);
                let end = host::ticks::now() + VIRTIO_RESET_MS * ticks_per_ms;
                loop {
                    if pci::in8(io, base + VIRTIO_LEGACY_STATUS) == 0 { break true; }
                    if host::ticks::now() > end { break false; }
                    core::hint::spin_loop();
                }
            }
            None => false,
        };
        if !ok {
            let p = &disk.pci;
            sel4::debug_println!("l4h-root: disk {:02x}:{:02x}.{}: device did not reset; it stays disabled", p.bus, p.dev, p.func);
            disk.failed = true;
        }
        return ok;
    }
    let nvme = disk.kind == blk::BLKD_NVME;
    let (bar, off) = if nvme {
        (0, 0)
    } else {
        let c = disk.pci.virtio_caps.iter().find(|c| c.cfg_type == VIRTIO_PCI_CAP_COMMON_CFG).unwrap();
        (c.bar, c.offset as usize + VIRTIO_DEVICE_STATUS)
    };
    let frame = crate::devmem::granule(bar_frames(alloc, devmem, &disk.pci, &mut disk.bars, bar).start + off / PAGE);
    pci.enable_memory(&disk.pci);
    let ok = win.with_frame_attrs(&abs_of(frame), DEVICE_ATTRS, |page| unsafe {
        let r32 = |o: usize| (page.add(o) as *const u32).read_volatile();
        let w32 = |o: usize, v: u32| (page.add(o) as *mut u32).write_volatile(v);
        let wait = |ms: u64, done: &dyn Fn() -> bool| {
            let end = host::ticks::now() + ms * ticks_per_ms;
            while !done() {
                if host::ticks::now() > end {
                    return false;
                }
                core::hint::spin_loop();
            }
            true
        };
        if nvme {
            if r32(NVME_CSTS) == u32::MAX {
                return false;
            }
            // CAP.TO: the worst-case time to become (not) ready, in 500 ms.
            let to_ms = ((r32(NVME_CAP) >> 24) & 0xff).max(1) as u64 * 500;
            // Clear EN and any shutdown request.
            w32(NVME_CC, r32(NVME_CC) & !(1 | (3 << 14)));
            wait(to_ms, &|| r32(NVME_CSTS) & 1 == 0)
        } else {
            let status = page.add(off % PAGE);
            status.write_volatile(0);
            wait(VIRTIO_RESET_MS, &|| status.read_volatile() == 0)
        }
    });
    if !ok {
        let p = &disk.pci;
        sel4::debug_println!("l4h-root: disk {:02x}:{:02x}.{}: device did not reset; it stays disabled", p.bus, p.dev, p.func);
        disk.failed = true;
    }
    ok
}

/// The virtio-pci structures of a device, at the addresses its BARs are
/// mapped at (`bar_va`).
pub struct VirtioRegions {
    pub common: blk::PciRegion,
    pub notify: blk::PciRegion,
    pub notify_mult: u32,
    pub isr: blk::PciRegion,
    pub device: blk::PciRegion,
    pub msix_table: blk::PciRegion,
}

pub fn virtio_regions(d: &pci::Device, bar_va: impl Fn(u8) -> usize) -> VirtioRegions {
    let region = |cfg_type: u8| -> (blk::PciRegion, u32) {
        let c = d
            .virtio_caps
            .iter()
            .find(|c| c.cfg_type == cfg_type)
            .unwrap_or_else(|| panic!("virtio device {:x}: no capability {}", bdf(d), cfg_type));
        let va = bar_va(c.bar) + c.offset as usize;
        (blk::PciRegion { va: va as u64, len: c.length as u64 }, c.notify_off_multiplier)
    };
    let msix = d.msix.unwrap();
    VirtioRegions {
        common: region(VIRTIO_PCI_CAP_COMMON_CFG).0,
        notify: region(VIRTIO_PCI_CAP_NOTIFY_CFG).0,
        notify_mult: region(VIRTIO_PCI_CAP_NOTIFY_CFG).1,
        isr: region(VIRTIO_PCI_CAP_ISR_CFG).0,
        device: region(VIRTIO_PCI_CAP_DEVICE_CFG).0,
        msix_table: blk::PciRegion {
            va: (bar_va(msix.table_bar) + msix.table_offset as usize) as u64,
            len: msix.table_size as u64 * 16,
        },
    }
}

/// BARs holding a virtio device's common, notify, ISR and device
/// structures (types 1-4; PCI config access and shared memory are unused)
/// and its MSI-X table, bit b for BAR b.
pub fn virtio_bar_mask(d: &pci::Device) -> u8 {
    let caps = d.virtio_caps.iter().filter(|c| (1..=4).contains(&c.cfg_type));
    caps.map(|c| c.bar).chain(d.msix.map(|m| m.table_bar)).fold(0, |m, b| m | 1 << b)
}

/// Pages of BARs `bars` (bit b for BAR b) of `d`: what map_bar_mask maps.
pub fn bar_pages(d: &pci::Device, bars: u8) -> usize {
    (0..6).filter(|b| bars & 1 << b != 0).map(|b| (d.bars[b].size as usize).div_ceil(PAGE)).sum()
}

/// Radix of a CNode keeping the mapping caps of `pages` pages.
pub fn keep_bits(pages: usize) -> usize {
    pages.next_power_of_two().trailing_zeros().max(1) as usize
}

/// The frames of a device's BARs, carved on first use: their slots, by
/// BAR.
pub type BarCache = [Option<Range<Slot>>; 6];

/// Map BARs `bars` (bit b for BAR b) of `d` into `comp`, uncached, or
/// write-combining for those in `wc`.  BAR frames are carved once and
/// cached in `cache`.
#[allow(clippy::too_many_arguments)]
pub fn map_bar_mask(
    comp: &Component,
    alloc: &mut Alloc,
    arena: &mut Arena,
    devmem: &mut DevMem,
    d: &pci::Device,
    cache: &mut BarCache,
    bars: u8,
    wc: u8,
    bar_va: impl Fn(u8) -> usize,
    keep: &mut impl FnMut() -> sel4::AbsoluteCPtr,
) {
    for b in (0..6).filter(|b| bars & 1 << b != 0) {
        let frames = bar_frames(alloc, devmem, d, cache, b);
        let attrs = if wc & 1 << b != 0 { wc_attrs() } else { DEVICE_ATTRS };
        for (i, f) in frames.map(crate::devmem::granule).enumerate() {
            comp.map_copy(
                alloc,
                arena,
                &abs_of(f),
                bar_va(b) + i * PAGE,
                CapRights::read_write(),
                attrs,
                keep(),
            );
        }
    }
}

/// The frames of BAR `b` of `d`, carved on first use and cached in `cache`.
fn bar_frames(alloc: &mut Alloc, devmem: &mut DevMem, d: &pci::Device, cache: &mut BarCache, b: u8) -> Range<Slot> {
    cache[b as usize]
        .get_or_insert_with(|| {
            let bar = d.bars[b as usize];
            assert!(!bar.is_io && bar.size > 0 && bar.size as usize <= BAR_STRIDE, "virtio BAR {} unusable", b);
            alloc
                .slots
                .global(|slots| devmem.frames(slots, bar.addr as usize, bar.size as usize))
                .unwrap_or_else(|| panic!("no device untyped for BAR {} at {:#x}", b, bar.addr))
        })
        .clone()
}

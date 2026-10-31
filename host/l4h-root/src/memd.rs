//! l4h-memd (DESIGN.md §8.4), the owner of the host's free memory and of
//! every guest's RAM: spawning it and handing it the free memory, the free
//! page reporting device it drives, the calls l4h-root makes to it, and
//! vmmgr's capabilities to it.
//!
//! memd runs before any guest.  The root task's own objects come from
//! grants of memd's (mem.rs).  Guests' RAM is between vmmgr and memd
//! (l4h-vmmgr's memd.rs), and memory a guest plugs while it runs (DESIGN.md
//! §8.5) between its l4h-vmm and memd.

use l4h_abi as abi;
use l4h_host as host;
use l4h_host::memd::{self, BalloonConfig, MemdConfig};
use l4h_task::memd::MemdLink;
use sel4::{CapRights, ObjectBlueprint, VmAttributes, cap, cap_type};

use crate::component::{self, Component, SpawnArgs, abs_of};
use crate::devmem::DevMem;
use crate::iommu::Iommu;
use crate::mem::{Alloc, Arena, Dest, ObjCtx, Slot};
use crate::pci::{self, Pci};
use crate::vspace::{FRAME_BP, map_frame};
use crate::window::Window;
use crate::{AsidPools, HostInfo};

static MEMD_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/l4h-memd.elf"));

pub const MEMD_ID: u32 = 0x400;
// memd keeps state (and a status record) for every guest id.
const _: () = assert!(crate::MAX_GUESTS <= memd::MAX_GUESTS);
/// memd's status page in the root task.
const STATUS_VA: usize = crate::layout::MEMD_STATUS.base;
/// Mapping capabilities besides the table's: the status page, and the
/// balloon's BARs and DMA.  A balloon whose BARs need more is left off.
const KEEP_OTHERS: usize = 64;
const PAGE: usize = 4096;

const VIRTIO_VENDOR: u16 = 0x1af4;
const DEVICE_MODERN: u16 = 0x1045;
const DEVICE_TRANSITIONAL: u16 = 0x1002;
const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;

fn root_cap<T: sel4::CapType>(s: Slot) -> sel4::Cap<T> {
    sel4::init_thread::Slot::<T>::from_index(s).cap()
}

fn link(alloc: &Alloc) -> MemdLink {
    alloc.memd.expect("memd is not running")
}

/// Give vmmgr its capabilities to memd: its endpoint (badged BADGE_VMMGR),
/// the mailbox it shares with memd, and an endpoint for each guest's
/// l4h-vmm (badged BADGE_VMM | guest), which vmmgr cannot mint.
pub fn give_vmmgr(alloc: &mut Alloc, arena: &mut Arena, vmmgr: &Component) {
    use l4h_host::vmmgr as proto;
    let m = link(alloc);
    let call = sel4::CapRightsBuilder::none().write(true).grant_reply(true).build();
    vmmgr.give_badged(proto::SLOT_MEMD_EP, m.endpoint(), call.clone(), memd::BADGE_VMMGR);
    for g in 0..memd::MAX_GUESTS {
        vmmgr.give_badged(proto::SLOT_VMM_MEMD_EP + g as u64, m.endpoint(), call.clone(), memd::BADGE_VMM | g as u64);
    }
    let mailbox = arena.object_cap::<cap_type::CNode>(alloc, ObjectBlueprint::CNode { size_bits: memd::MAILBOX_RADIX });
    vmmgr.give(proto::SLOT_MEMD_MAILBOX, mailbox, CapRights::all());
    m.slot(memd::SLOT_MAILBOX).copy(&abs_of(mailbox), CapRights::all()).expect("memd: vmmgr mailbox");
}

/// memd, as l4h-root keeps it.
pub struct Memd {
    comp: Component,
    arena: Arena,
    keep: cap::CNode,
    keep_bits: usize,
    keep_next: u64,
    /// The status page memd writes.
    status: cap::Granule,
}

impl Memd {
    /// Map memd's status page into vmmgr, read-only, keeping the mapping
    /// capability in `keep`.
    pub fn map_status(&self, vmmgr: &Component, alloc: &mut Alloc, arena: &mut Arena, keep: sel4::AbsoluteCPtr) {
        let va = l4h_host::vmmgr::MEMD_STATUS_VA;
        vmmgr.map_copy(alloc, arena, &abs_of(self.status), va, CapRights::read_only(), VmAttributes::DEFAULT, keep);
    }

    fn keep_left(&self) -> usize {
        (1 << self.keep_bits) - self.keep_next as usize
    }

    fn keep_slot(&mut self) -> sel4::AbsoluteCPtr {
        assert!(self.keep_next < 1 << self.keep_bits, "memd: keep CNode full");
        self.keep_next += 1;
        self.keep.absolute_cptr_from_bits_with_depth(self.keep_next - 1, self.keep_bits)
    }

    /// Have memd report free memory through `d`, a virtio-balloon: map its
    /// BARs (or give it its I/O ports, if it is a legacy device) and DMA
    /// pages into memd, and enable it.
    /// Free page reports name memory the balloon never reads, so it is
    /// given its DMA pages only: one that translates them through the
    /// IOMMU (QEMU's `iommu_platform=on`) cannot report.
    pub fn attach_balloon(&mut self, d: &pci::Device, pci: &Pci, iommu: &mut Iommu, alloc: &mut Alloc, devmem: &mut DevMem) {
        let mut cfg = BalloonConfig::default();
        let legacy = crate::blkd::is_legacy_virtio(d);
        if legacy {
            let bar = d.bars[0];
            if self.keep_left() < memd::DMA_PAGES {
                return;
            }
            let Some(io) = pci::io_ports(alloc, bar.addr as u16, bar.size as u16) else {
                return;
            };
            self.comp.give(memd::SLOT_BALLOON_IOPORT, io, CapRights::all());
            cfg.legacy_io = bar.addr;
        } else {
            let cap = |t: u8| d.virtio_caps.iter().find(|c| c.cfg_type == t).copied();
            let (Some(common), Some(notify), Some(device)) =
                (cap(VIRTIO_PCI_CAP_COMMON_CFG), cap(VIRTIO_PCI_CAP_NOTIFY_CFG), cap(VIRTIO_PCI_CAP_DEVICE_CFG))
            else {
                return;
            };
            // BARs mapped, one bit each.
            let mut mapped = 0u8;
            for c in [common, notify, device] {
                if mapped & (1 << c.bar) != 0 {
                    continue;
                }
                let bar = d.bars[c.bar as usize];
                let pages = (bar.size as usize).div_ceil(PAGE);
                if bar.is_io || bar.size == 0 || bar.size as usize > memd::BAR_STRIDE || pages + memd::DMA_PAGES > self.keep_left() {
                    return;
                }
                let Some(frames) = alloc.slots.global(|s| devmem.frames(s, bar.addr as usize, bar.size as usize)) else {
                    return;
                };
                for (i, f) in frames.map(crate::devmem::granule).enumerate() {
                    let va = memd::BALLOON_VA + c.bar as usize * memd::BAR_STRIDE + i * PAGE;
                    let keep = self.keep_slot();
                    self.comp.map_copy(alloc, &mut self.arena, &abs_of(f), va, CapRights::read_write(), crate::blkd::DEVICE_ATTRS, keep);
                }
                mapped |= 1 << c.bar;
            }
            let packed = |c: pci::VirtioCap| ((c.bar as u64) << 32) | c.offset as u64;
            cfg.common = packed(common);
            cfg.notify = packed(notify);
            cfg.device = packed(device);
            cfg.notify_mult = notify.notify_off_multiplier as u64;
        }
        let frames = alloc.slots.global(|s| s.alloc_range(memd::DMA_PAGES));
        let Some(paddr) = self.arena.retype(alloc, &FRAME_BP, memd::DMA_PAGES, Dest::new(crate::slot::CNODE.cap(), frames.start)) else {
            return;
        };
        for (i, s) in frames.enumerate() {
            let keep = self.keep_slot();
            let f = abs_of(root_cap::<cap_type::Granule>(s));
            self.comp.map_copy(alloc, &mut self.arena, &f, memd::DMA_VA + i * PAGE, CapRights::read_write(), VmAttributes::DEFAULT, keep);
        }
        cfg.dma_paddr = paddr as u64;
        let dom = iommu.attach(alloc, d);
        iommu.map(alloc, dom, paddr, memd::DMA_PAGES * PAGE, crate::iommu::Access::ReadWrite);
        if legacy {
            pci.enable_io(d);
        }
        pci.enable(d);
        if link(alloc).call(memd::MEMD_BALLOON, &cfg.to_mrs()) != 0 {
            pci.disable(d);
        }
    }
}

/// A virtio-balloon, modern or legacy.
pub fn is_balloon(d: &pci::Device) -> bool {
    d.vendor == VIRTIO_VENDOR
        && (d.device == DEVICE_MODERN || d.device == DEVICE_TRANSITIONAL)
        && (d.virtio_caps.iter().any(|c| c.cfg_type == VIRTIO_PCI_CAP_COMMON_CFG)
            || d.device == DEVICE_TRANSITIONAL && crate::blkd::is_legacy_virtio(d))
}

/// Spawn memd and hand it all free memory.
pub fn spawn(alloc: &mut Alloc, win: &mut Window, asids: &mut AsidPools, info: &HostInfo) -> Memd {
    let units = alloc.memd_units();
    let bits = memd::cnode_bits(units);
    let table_pages = memd::table_bytes(units) / PAGE;
    let cfg = MemdConfig { cnode_bits: bits as u64, units };
    let cfg_bytes = unsafe {
        core::slice::from_raw_parts(&cfg as *const MemdConfig as *const u8, core::mem::size_of::<MemdConfig>())
    };
    // Its CNode, table (with its page tables), image and paging
    // structures.
    let mut arena = alloc.arena((32 << bits) + table_pages * PAGE * 513 / 512 + (2 << 20)).expect("memory for memd");
    let args = SpawnArgs {
        id: MEMD_ID,
        kind: host::KIND_MEMD,
        elf: MEMD_ELF,
        // Above every guest: l4h-root waits for it.
        prio: abi::PRIO_KERNEL + 2,
        budget_us: info.timeslice_us,
        period_us: info.timeslice_us,
        config: cfg_bytes,
        ntfn: None,
        service_ep: None,
        cnode: None,
        cnode_bits: Some(bits),
    };
    let comp = component::create(
        &args, alloc, &mut arena, win, &mut |alloc, vspace| asids.assign(alloc, vspace),
        &info.spawn_context(0),
    );
    // Mapping capabilities: the table's, the status page, the balloon's
    // BARs and DMA.
    let keep_bits = (table_pages + KEEP_OTHERS).next_power_of_two().trailing_zeros() as usize;
    let keep = arena.object_cap::<cap_type::CNode>(alloc, ObjectBlueprint::CNode { size_bits: keep_bits });
    let status = alloc.object_cap::<cap_type::Granule>(FRAME_BP);
    let mut m = Memd { comp, arena, keep, keep_bits, keep_next: 0, status };

    // The table, zeroed as seL4 makes new frames.
    for p in 0..table_pages {
        let f = m.arena.object(alloc, FRAME_BP);
        let keep = m.keep_slot();
        let frame = abs_of(root_cap::<cap_type::Granule>(f));
        m.comp.map_copy(alloc, &mut m.arena, &frame, memd::TABLE_VA + p * PAGE, CapRights::read_write(), VmAttributes::DEFAULT, keep);
        frame.delete().expect("delete table frame");
        alloc.slots.free(f);
    }

    // The status page: memd writes it, l4h-root reads it.
    alloc.global(|alloc| {
        let copy = alloc.slots.alloc();
        abs_of(root_cap::<cap_type::Null>(copy)).copy(&abs_of(status), CapRights::all()).expect("status copy");
        map_frame(&mut ObjCtx::global(alloc), sel4::init_thread::slot::VSPACE.cap(), root_cap::<cap_type::Granule>(copy),
            STATUS_VA, CapRights::read_only(), VmAttributes::DEFAULT);
    });
    let keep = m.keep_slot();
    m.comp.map_copy(alloc, &mut m.arena, &abs_of(status), memd::STATUS_VA, CapRights::read_write(), VmAttributes::DEFAULT, keep);

    component::start(&m.comp);
    // The status mapping above remains readable for the root task's life.
    let link = unsafe {
        MemdLink::new(m.comp.service_ep, crate::slot::CNODE.cap(), m.comp.cnode, bits, memd::SLOT_XCHG, STATUS_VA)
    };
    alloc.hand_over(link);
    info!(
        "l4h-root: memd holds {} MiB, {} KiB of CNode, {} KiB of table",
        link.status().free_bytes >> 20, (32usize << bits) >> 10, table_pages * PAGE >> 10
    );
    m
}

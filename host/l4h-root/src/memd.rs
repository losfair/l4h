//! l4h-memd (DESIGN.md §16), the owner of the host's free memory and of
//! every guest's RAM: spawning it and handing it the free memory, the free
//! page reporting device it drives, and the calls l4h-root makes to it.
//!
//! memd runs before any guest.  The root task's own objects come from
//! grants of memd's (mem.rs).  A guest's RAM is taken by memd at create;
//! l4h-root gets copies of the blocks it fills with frames for the image
//! (the boot blocks), memd gives the guest copies of the others at boot,
//! and revokes all of them at destroy.  Memory a guest plugs while it runs
//! (DESIGN.md §17) is between its l4h-vmm and memd: l4h-root only sets
//! the target.

use l4h_abi as abi;
use l4h_host as host;
use l4h_host::memd::{self, BalloonConfig, MemdConfig, Status};
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

fn mr(i: usize) -> u64 {
    sel4::with_ipc_buffer(|b| b.msg_regs()[i])
}

fn set_mr(i: usize, v: u64) {
    sel4::with_ipc_buffer_mut(|b| b.msg_regs_mut()[i] = v)
}

/// What the allocator needs of memd: its endpoint, its CNode (for the
/// exchange slots) and its status page.
#[derive(Clone, Copy)]
pub struct MemdLink {
    ep: cap::Endpoint,
    cnode: cap::CNode,
    cnode_bits: usize,
}

impl MemdLink {
    fn slot(&self, i: u64) -> sel4::AbsoluteCPtr {
        self.cnode.absolute_cptr_from_bits_with_depth(i, self.cnode_bits)
    }

    fn xchg(&self, i: usize) -> sel4::AbsoluteCPtr {
        self.slot(memd::SLOT_XCHG + i as u64)
    }

    fn call(&self, label: u64, args: &[u64]) -> u64 {
        for (i, &a) in args.iter().enumerate() {
            set_mr(i, a);
        }
        self.ep.call(sel4::MessageInfo::new(label, 0, 0, args.len()));
        mr(0)
    }

    pub fn status(&self) -> Status {
        unsafe { (STATUS_VA as *const Status).read_volatile() }
    }

    /// An untouched Untyped of 2^bits bytes, into root slot `slot`: its
    /// physical address.
    pub fn alloc(&self, bits: usize, slot: Slot) -> Option<usize> {
        if self.call(memd::MEMD_ALLOC, &[bits as u64, 1]) != 0 {
            return None;
        }
        let paddr = mr(1) as usize;
        abs_of(root_cap::<cap_type::Null>(slot)).move_(&self.xchg(0)).expect("memd: take grant");
        Some(paddr)
    }

    /// Return untouched Untypeds (at most XCHG_SLOTS): (capability,
    /// physical address, size bits).  Their slots are left empty.
    pub fn free(&self, blocks: &[(cap::Untyped, usize, usize)]) {
        assert!(blocks.len() <= memd::XCHG_SLOTS);
        let mut args = [0; 1 + 2 * memd::XCHG_SLOTS];
        args[0] = blocks.len() as u64;
        for (i, &(ut, paddr, bits)) in blocks.iter().enumerate() {
            self.xchg(i).move_(&abs_of(ut)).expect("memd: return block");
            (args[1 + 2 * i], args[2 + 2 * i]) = (paddr as u64, bits as u64);
        }
        assert_eq!(self.call(memd::MEMD_FREE, &args[..1 + 2 * blocks.len()]), 0, "memd: free");
    }
}

fn link(alloc: &Alloc) -> MemdLink {
    alloc.memd.expect("memd is not running")
}

/// Take the RAM of guest `g`: `blocks` 2 MiB blocks.  `block_cn` is its
/// block CNode, of radix `radix`, into which memd gives the guest its
/// blocks at boot; `hp_cn` its hotplug CNode, for `hp_count` hotplug
/// blocks.
pub fn guest_create(alloc: &Alloc, g: usize, blocks: usize, block_cn: cap::CNode, radix: usize, hp_cn: cap::CNode, hp_count: usize) -> bool {
    let m = link(alloc);
    m.slot(memd::SLOT_GUEST_BCN + g as u64).copy(&abs_of(block_cn), CapRights::all()).expect("memd: give block CNode");
    m.slot(memd::SLOT_GUEST_HCN + g as u64).copy(&abs_of(hp_cn), CapRights::all()).expect("memd: give hotplug CNode");
    m.call(memd::MEMD_GUEST_CREATE, &[g as u64, blocks as u64, radix as u64, hp_count as u64]) == 0
}

/// Set the hotplug target of guest `g`, in hotplug blocks.
pub fn set_target(alloc: &Alloc, g: usize, target: usize) -> bool {
    link(alloc).call(memd::MEMD_SET_TARGET, &[g as u64, target as u64]) == 0
}

/// Hotplug target and plugged hotplug blocks of guest `g`.
pub fn hotplug(g: usize) -> memd::GuestHp {
    let st = STATUS_VA as *const Status;
    unsafe { core::ptr::addr_of!((*st).hp[g]).read_volatile() }
}

/// Mint the capability guest `g`'s l4h-vmm calls memd with into `dst`.
pub fn mint_vmm_ep(alloc: &Alloc, g: usize, dst: &sel4::AbsoluteCPtr) {
    let m = link(alloc);
    dst.mint(&abs_of(m.ep), sel4::CapRightsBuilder::none().write(true).grant_reply(true).build(), memd::BADGE_VMM | g as u64)
        .expect("memd: VMM endpoint");
}

/// A copy of block `b` of guest `g`, into root slot `slot`: its physical
/// address.
pub fn guest_copy(alloc: &Alloc, g: usize, b: usize, slot: Slot) -> usize {
    let m = link(alloc);
    assert_eq!(m.call(memd::MEMD_GUEST_COPY, &[g as u64, b as u64]), 0, "memd: copy of a guest block");
    let paddr = mr(1) as usize;
    abs_of(root_cap::<cap_type::Null>(slot)).move_(&m.xchg(0)).expect("memd: take block copy");
    paddr
}

/// Give guest `g` its blocks from `first` on, block b at index b + `skip`
/// of its block CNode (past its shared blocks, guest.rs).
pub fn guest_give(alloc: &Alloc, g: usize, first: usize, skip: usize) -> bool {
    link(alloc).call(memd::MEMD_GUEST_GIVE, &[g as u64, first as u64, skip as u64]) == 0
}

/// Revoke and free all the RAM of guest `g`.
pub fn guest_destroy(alloc: &Alloc, g: usize) {
    if let Some(m) = alloc.memd {
        m.call(memd::MEMD_GUEST_DESTROY, &[g as u64]);
    }
}

/// memd, as l4h-root keeps it.
pub struct Memd {
    comp: Component,
    arena: Arena,
    keep: cap::CNode,
    keep_bits: usize,
    keep_next: u64,
}

impl Memd {
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
        let Some(paddr) = self.arena.retype(alloc, &FRAME_BP, memd::DMA_PAGES, Dest::root(frames.start)) else {
            return;
        };
        for (i, s) in frames.enumerate() {
            let keep = self.keep_slot();
            let f = abs_of(root_cap::<cap_type::Granule>(s));
            self.comp.map_copy(alloc, &mut self.arena, &f, memd::DMA_VA + i * PAGE, CapRights::read_write(), VmAttributes::DEFAULT, keep);
        }
        cfg.dma_paddr = paddr as u64;
        let dom = iommu.attach(alloc, d);
        iommu.map(alloc, dom, paddr, memd::DMA_PAGES * PAGE, true);
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
        core: 0,
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
    let comp = component::create(&args, alloc, &mut arena, win, asids, info);
    // Mapping capabilities: the table's, the status page, the balloon's
    // BARs and DMA.
    let keep_bits = (table_pages + KEEP_OTHERS).next_power_of_two().trailing_zeros() as usize;
    let keep = arena.object_cap::<cap_type::CNode>(alloc, ObjectBlueprint::CNode { size_bits: keep_bits });
    let mut m = Memd { comp, arena, keep, keep_bits, keep_next: 0 };

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
    let status = alloc.object_cap::<cap_type::Granule>(FRAME_BP);
    alloc.global(|alloc| {
        let copy = alloc.slots.alloc();
        abs_of(root_cap::<cap_type::Null>(copy)).copy(&abs_of(status), CapRights::all()).expect("status copy");
        map_frame(&mut ObjCtx::global(alloc), sel4::init_thread::slot::VSPACE.cap(), root_cap::<cap_type::Granule>(copy),
            STATUS_VA, CapRights::read_only(), VmAttributes::DEFAULT);
    });
    let keep = m.keep_slot();
    m.comp.map_copy(alloc, &mut m.arena, &abs_of(status), memd::STATUS_VA, CapRights::read_write(), VmAttributes::DEFAULT, keep);

    component::start(&m.comp);
    let link = MemdLink { ep: m.comp.service_ep, cnode: m.comp.cnode, cnode_bits: bits };
    alloc.hand_over(link);
    info!(
        "l4h-root: memd holds {} MiB, {} KiB of CNode, {} KiB of table",
        link.status().free_bytes >> 20, (32usize << bits) >> 10, table_pages * PAGE >> 10
    );
    m
}

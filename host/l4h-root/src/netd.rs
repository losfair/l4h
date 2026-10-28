//! Networking: the netd component (switches and uplink NICs) and the ports
//! that connect guests' virtio-net devices to it.


use sel4::{CapRights, ObjectBlueprint, VmAttributes, cap, cap_type};

use l4h_abi as abi;
use l4h_host::fixed::ArrayVec;
use l4h_host::{self as host, net};

use crate::blkd::{BAR_STRIDE, VirtioRegions, bar_pages, is_legacy_virtio, keep_bits, map_bar_mask, virtio_bar_mask, virtio_regions};
use crate::component::{self, Component, SpawnArgs, abs_of};
use crate::devmem::DevMem;
use crate::iommu::Iommu;
use crate::mem::{Alloc, Arena, Dest, Slot, UtRegion};
use crate::pci::{self, Pci};
use crate::vmmgr::RootGuest;
use crate::vspace::FRAME_BP;
use crate::window::Window;
use crate::{AsidPools, HostInfo, ctl, mr, set_mr};

static NETD_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/l4h-netd.elf"));

const PAGE: usize = 4096;
const NIC_DMA_BITS: usize = 22;
/// Port memory: the channel plus the CNode keeping netd's mappings of it.
const PORT_BITS: usize = 22;
const PORT_KEEP_BITS: usize = l4h_host::vmmgr::PORT_RADIX;
const _: () = assert!(net::PORT_PAGES <= 1 << PORT_KEEP_BITS);
/// MSI vectors of NICs start here.
const NIC_MSI_BASE: u64 = crate::pci::VECTOR_NIC_BASE;
const NETD_ID: u32 = 0x200;

pub fn is_virtio_net(d: &pci::Device) -> bool {
    d.vendor == 0x1af4
        && (d.device == 0x1041 || d.device == 0x1000)
        && (d.virtio_caps.iter().any(|c| c.cfg_type == 1) || is_legacy(d))
        && d.msix.is_some()
}

/// A legacy virtio-net device, as on GCE.
fn is_legacy(d: &pci::Device) -> bool {
    d.device == 0x1000 && is_legacy_virtio(d)
}

/// Google Virtual NIC (gVNIC), as on GCE C3, N4, C4 and later: registers
/// in BAR 0, doorbells in BAR 2.  It needs three MSI-X entries (two
/// notification blocks and the management vector).
pub fn is_gvnic(d: &pci::Device) -> bool {
    let mem = |b: usize| !d.bars[b].is_io && d.bars[b].size != 0;
    d.vendor == 0x1ae0 && d.device == 0x0042 && mem(0) && mem(2) && d.msix.is_some_and(|m| m.table_size >= 3)
}

/// Intel X550 (Linux ixgbe), as on Latitude.sh m4.metal servers:
/// registers in BAR 0, MSI-X with an entry each for RX and TX.
pub fn is_ixgbe(d: &pci::Device) -> bool {
    // X550T, X550T1.
    d.vendor == 0x8086
        && matches!(d.device, 0x1563 | 0x15d1)
        && !d.bars[0].is_io
        && d.bars[0].size != 0
        && d.msix.is_some_and(|m| m.table_size >= 2)
}

/// Amazon Elastic Network Adapter (Linux ena), as on every Nitro EC2
/// instance: registers in BAR 0, MSI-X with the management entry and one
/// for the I/O queues.
pub fn is_ena(d: &pci::Device) -> bool {
    d.vendor == 0x1d0f
        && matches!(d.device, 0x0ec2 | 0x1ec2 | 0xec20 | 0xec21 | 0x0051)
        && !d.bars[0].is_io
        && d.bars[0].size != 0
        && d.msix.is_some_and(|m| m.table_size >= 2)
}

/// ENA's low-latency queue memory, BAR 2, if netd's window for it holds
/// it.  Without it, TX descriptors are in host memory.
fn ena_llq(d: &pci::Device) -> bool {
    let b = d.bars[2];
    is_ena(d) && !b.is_io && b.size != 0 && b.size as usize <= BAR_STRIDE
}

/// NICs netd can drive as an uplink.
pub fn is_uplink(d: &pci::Device) -> bool {
    is_virtio_net(d) || is_gvnic(d) || is_ena(d) || is_ixgbe(d)
}

pub struct Nic {
    pub pci: pci::Device,
    pub switch: Option<u32>,
}

pub struct PortInfo {
    pub vm: usize,
    pub switch: u32,
    pub mac: u64,
}

pub struct Netd {
    comp: Component,
    #[allow(dead_code)]
    arena: Arena,
    pub nics: ArrayVec<Nic, { net::MAX_NICS }>,
    pub ports: [Option<PortInfo>; net::MAX_PORTS],
    /// Switches 0..switches exist (they are never deleted).
    pub switches: u32,
}

pub fn bdf(d: &pci::Device) -> u32 {
    ((d.bus as u32) << 8) | ((d.dev as u32) << 3) | d.func as u32
}

fn call(ep: cap::Endpoint, label: u64, args: &[u64]) -> u64 {
    for (i, a) in args.iter().enumerate() {
        set_mr(i, *a);
    }
    ep.call(sel4::MessageInfo::new(label, 0, 0, args.len()));
    mr(0)
}

/// The BARs netd maps of NIC `d`, bit b for BAR b.
fn used_bars(d: &pci::Device) -> u8 {
    if is_gvnic(d) {
        1 | 1 << 2 | 1 << d.msix.unwrap().table_bar
    } else if is_ena(d) {
        1 | (ena_llq(d) as u8) << 2 | 1 << d.msix.unwrap().table_bar
    } else if is_ixgbe(d) {
        1 | 1 << d.msix.unwrap().table_bar
    } else {
        virtio_bar_mask(d)
    }
}

/// Start netd with the uplink NICs `nics`.
pub fn spawn(
    nics: &[pci::Device],
    pci: &Pci,
    iommu: &mut Iommu,
    devmem: &mut DevMem,
    alloc: &mut Alloc,
    win: &mut Window,
    asids: &mut AsidPools,
    info: &HostInfo,
) -> Netd {
    let nr_nics = nics.len().min(net::MAX_NICS);
    let mut arena = alloc.arena(16 << 20).expect("netd arena");
    // Plain integers: all zeros is a valid (empty) configuration.
    let mut cfg: net::NetdConfig = unsafe { core::mem::zeroed() };
    cfg.nr_nics = nr_nics as u32;
    let mut dma = ArrayVec::<_, { net::MAX_NICS }>::new();
    for (n, d) in nics[..nr_nics].iter().enumerate() {
        let bar_va = |b: u8| net::nic_bar_va(n, b as usize);
        let bar_region = |b: u8| l4h_host::blk::PciRegion { va: bar_va(b) as u64, len: d.bars[b as usize].size };
        let none = l4h_host::blk::PciRegion { va: 0, len: 0 };
        let gvnic = is_gvnic(d);
        let ena = is_ena(d);
        let ixgbe = is_ixgbe(d);
        let VirtioRegions { common, notify, notify_mult, isr, device, msix_table } = if is_legacy(d) || gvnic || ena || ixgbe {
            let msix = d.msix.unwrap();
            VirtioRegions {
                common: none,
                notify: none,
                notify_mult: 0,
                isr: none,
                device: none,
                msix_table: l4h_host::blk::PciRegion {
                    va: (bar_va(msix.table_bar) + msix.table_offset as usize) as u64,
                    len: msix.table_size as u64 * 16,
                },
            }
        } else {
            virtio_regions(d, bar_va)
        };
        let s = alloc.slots.alloc();
        let mut region = alloc.split(NIC_DMA_BITS, s).expect("NIC DMA memory");
        let paddr = region.paddr;
        let frames = alloc.slots.alloc_range((1 << NIC_DMA_BITS) / PAGE);
        region
            .retype(&FRAME_BP, frames.len(), Dest::new(crate::slot::CNODE.cap(), frames.start))
            .expect("NIC DMA frames");
        let _ = dma.push(frames);
        // The NIC reaches its DMA memory only.
        let dom = iommu.attach(alloc, d);
        iommu.map(alloc, dom, paddr, 1 << NIC_DMA_BITS, true);
        let (msi_address, msi_data) = iommu.msi(dom, NIC_MSI_BASE + n as u64);
        cfg.nics[n] = net::NicConfig {
            kind: if gvnic {
                net::NIC_GVNIC
            } else if ena {
                net::NIC_ENA
            } else if ixgbe {
                net::NIC_IXGBE
            } else {
                net::NIC_VIRTIO
            },
            revision: d.revision as u32,
            pci_bdf: bdf(d),
            msi_data,
            msi_address,
            common,
            notify,
            notify_off_multiplier: notify_mult,
            legacy_io: if is_legacy(d) { d.bars[0].addr as u32 } else { 0 },
            isr,
            device,
            msix_table,
            regs: if gvnic || ena || ixgbe { bar_region(0) } else { none },
            doorbells: if gvnic || ena_llq(d) { bar_region(2) } else { none },
            dma_paddr: paddr as u64,
            dma_size: 1 << NIC_DMA_BITS,
        };
    }
    let cfg_bytes = unsafe {
        core::slice::from_raw_parts(&cfg as *const net::NetdConfig as *const u8, core::mem::size_of::<net::NetdConfig>())
    };
    let args = SpawnArgs {
        id: NETD_ID,
        kind: host::KIND_NETD,
        elf: NETD_ELF,
        prio: abi::PRIO_KERNEL + 2,
        budget_us: info.timeslice_us,
        period_us: info.timeslice_us,
        config: cfg_bytes,
        ntfn: None,
        service_ep: None,
        cnode: None,
        cnode_bits: None,
    };
    let comp = component::create(
        &args, alloc, &mut arena, win, &mut |alloc, vspace| asids.assign(alloc, vspace),
        &info.spawn_context(0),
    );

    // Mapping caps of every NIC page: DMA buffers and BARs.
    let pages = nics[..nr_nics].iter().map(|d| (1 << NIC_DMA_BITS) / PAGE + bar_pages(d, used_bars(d))).sum();
    let keep_bits = keep_bits(pages);
    let keep = arena.object_cap::<cap_type::CNode>(alloc, ObjectBlueprint::CNode { size_bits: keep_bits });
    let mut keep_next = 0u64;
    let mut keep_slot = || {
        let s = keep.absolute_cptr_from_bits_with_depth(keep_next, keep_bits);
        keep_next += 1;
        s
    };
    let mut nic_list = ArrayVec::new();
    for (n, d) in nics.into_iter().take(nr_nics).enumerate() {
        let mut bars = [const { None }; 6];
        // ENA's LLQ is written in 128-byte bursts.
        let wc = (ena_llq(&d) as u8) << 2;
        map_bar_mask(&comp, alloc, &mut arena, devmem, &d, &mut bars, used_bars(&d), wc, |b| net::nic_bar_va(n, b as usize), &mut keep_slot);
        for (i, s) in dma[n].clone().enumerate() {
            let f = sel4::init_thread::Slot::<cap_type::Granule>::from_index(s).cap();
            comp.map_copy(alloc, &mut arena, &abs_of(f), net::nic_dma_va(n) + i * PAGE, CapRights::read_write(), VmAttributes::DEFAULT, keep_slot());
        }
        if is_legacy(&d) {
            let (base, len) = (d.bars[0].addr as u16, d.bars[0].size as u16);
            let io = pci::io_ports(alloc, base, len).expect("NIC I/O ports");
            comp.give(net::NETD_SLOT_IOPORT_BASE + n as u64, io, CapRights::all());
        }
        // Interrupt.
        let irq_slot = alloc.slots.alloc();
        pci::msi_irq(
            &d,
            NIC_MSI_BASE + n as u64,
            &abs_of(sel4::init_thread::Slot::<cap_type::Null>::from_index(irq_slot).cap()),
        );
        let irq = sel4::init_thread::Slot::<cap_type::IrqHandler>::from_index(irq_slot).cap();
        let ntfn_slot = alloc.slots.alloc();
        let ntfn = sel4::init_thread::Slot::<cap_type::Notification>::from_index(ntfn_slot).cap();
        abs_of(ntfn)
            .mint(&abs_of(comp.ntfn), CapRights::all(), 1 << (net::NETD_BADGE_IRQ_SHIFT as usize + n))
            .expect("NIC IRQ notification");
        irq.irq_handler_set_notification(ntfn).expect("NIC IRQ set notification");
        comp.give(net::NETD_SLOT_IRQ_BASE + n as u64, irq, CapRights::all());
        pci.enable(&d);
        pci.enable_msix(&d);
        let _ = nic_list.push(Nic { pci: *d, switch: None });
    }
    component::start(&comp);
    Netd { comp, arena, nics: nic_list, ports: [const { None }; net::MAX_PORTS], switches: 0 }
}

impl Netd {
    /// A new switch; ENOSPC once there are MAX_SWITCHES, the size of
    /// netd's table of them.
    pub fn try_create_switch(&mut self) -> Result<u32, i64> {
        if self.switches as usize >= net::MAX_SWITCHES {
            return Err(ctl::ENOSPC);
        }
        self.switches += 1;
        Ok(self.switches - 1)
    }

    /// A switch of the boot configuration.
    pub fn create_switch(&mut self) -> u32 {
        self.try_create_switch().expect("l4h-root: more switches than MAX_SWITCHES")
    }

    pub fn attach_uplink(&mut self, switch: u32, nic: usize) -> Result<(), i64> {
        if switch >= self.switches {
            return Err(ctl::ENOENT);
        }
        let n = self.nics.get_mut(nic).ok_or(ctl::ENOENT)?;
        if n.switch.is_some() {
            return Err(ctl::EBUSY);
        }
        // Root's arguments are valid: u64::MAX is a failed netd.
        if call(self.comp.service_ep, net::NETD_ATTACH_UPLINK, &[nic as u64, switch as u64]) == u64::MAX {
            return Err(ctl::EIO);
        }
        n.switch = Some(switch);
        Ok(())
    }

    /// The port a new port on `switch` would be.
    pub fn free_port(&self, switch: u32) -> Result<usize, i64> {
        if switch >= self.switches {
            return Err(ctl::ENOENT);
        }
        let p = self.ports.iter().position(|p| p.is_none()).ok_or(ctl::ENOSPC)?;
        // Removing a free port does nothing, unless netd has failed: then
        // it answers u64::MAX, and a new port could not work.
        if call(self.comp.service_ep, net::NETD_REMOVE_PORT, &[p as u64]) == u64::MAX {
            return Err(ctl::EIO);
        }
        Ok(p)
    }

    /// A port's memory, in its own root slot: taken before the guest's
    /// device, so that running out leaves nothing behind.
    pub fn port_memory(alloc: &mut Alloc) -> Result<(Slot, UtRegion), i64> {
        let s = alloc.slots.alloc();
        match alloc.split(PORT_BITS, s) {
            Some(region) => Ok((s, region)),
            None => {
                alloc.slots.free(s);
                Err(ctl::ENOMEM)
            }
        }
    }

    /// Connect a guest device of `g` to `switch` as port `p` (free_port),
    /// using `memory` (port_memory).  Returns for the guest's l4h-vmm the
    /// CNode of the port's frames (radix PORT_KEEP_BITS) and a kick
    /// capability, in a slot of its own.
    #[allow(clippy::too_many_arguments)]
    pub fn add_port(
        &mut self,
        g: &mut RootGuest,
        p: usize,
        switch: u32,
        mac: u64,
        lock: bool,
        isolated: bool,
        (s, region): (Slot, UtRegion),
        alloc: &mut Alloc,
    ) -> (cap::CNode, cap::Notification) {
        // Port memory is the guest's: it is reclaimed with it.
        g.arena.own(s, region.paddr, PORT_BITS);
        let mut pool = region;
        // CNodes keeping netd's mappings of the port, and its frames.
        let cnodes = alloc.slots.alloc_range(2);
        pool.retype(&ObjectBlueprint::CNode { size_bits: PORT_KEEP_BITS }, 2, Dest::new(crate::slot::CNODE.cap(), cnodes.start)).expect("port CNodes");
        let keep = sel4::init_thread::Slot::<cap_type::CNode>::from_index(cnodes.start).cap();
        let chan = sel4::init_thread::Slot::<cap_type::CNode>::from_index(cnodes.start + 1).cap();
        pool.retype(&FRAME_BP, net::PORT_PAGES, Dest { cnode: abs_of(chan), offset: 0 }).expect("port frames");
        for i in 0..net::PORT_PAGES {
            let f = chan.absolute_cptr_from_bits_with_depth(i as u64, PORT_KEEP_BITS);
            let dst = keep.absolute_cptr_from_bits_with_depth(i as u64, PORT_KEEP_BITS);
            // Paging structures for the port come from netd's own pool, and
            // outlive the guest: their root slots must not be tracked into
            // it, or destroying it deletes them (and the arena regions they
            // grew into) while other ports still use them.
            let (comp, arena) = (&self.comp, &mut self.arena);
            alloc.global(|alloc| {
                comp.map_copy(alloc, arena, &f, net::port_va(p) + i * PAGE, CapRights::read_write(), VmAttributes::DEFAULT, dst)
            });
        }
        self.comp.give_badged(
            net::NETD_SLOT_CLIENT_BASE + p as u64,
            g.vmm_ntfn,
            CapRights::write_only(),
            host::VMM_BADGE_DONE,
        );
        let kick_slot = alloc.slots.alloc();
        let kick = sel4::init_thread::Slot::<cap_type::Notification>::from_index(kick_slot).cap();
        abs_of(kick).mint(&abs_of(self.comp.ntfn), CapRights::write_only(), 1 << p).expect("port kick");
        let flags = if lock { net::NETD_PORT_MAC_LOCK } else { 0 } | if isolated { net::NETD_PORT_ISOLATED } else { 0 };
        // netd answered free_port: a failure now is a fault since, which
        // leaves this port (reclaimed with the guest) as dead as the rest.
        if call(self.comp.service_ep, net::NETD_ADD_PORT, &[p as u64, switch as u64, mac, flags]) == u64::MAX {
            log!("l4h-root: netd failed adding port {}", p);
        }
        self.ports[p] = Some(PortInfo { vm: g.id, switch, mac });
        (chan, kick)
    }

    /// Disconnect port `p`; netd stops using its memory.
    pub fn remove_port(&mut self, p: usize) {
        if self.ports.get_mut(p).and_then(|i| i.take()).is_some() {
            call(self.comp.service_ep, net::NETD_REMOVE_PORT, &[p as u64]);
            let _ = self.comp.slot(net::NETD_SLOT_CLIENT_BASE + p as u64).delete();
        }
    }

    /// CPU time netd used since the last call, in timer ticks.
    pub fn consumed(&self) -> u64 {
        crate::sched_consumed(self.comp.sc)
    }

    /// The MAC address of host NIC `n`.
    pub fn nic_mac(&self, n: usize) -> Option<u64> {
        let m = call(self.comp.service_ep, net::NETD_NIC_MAC, &[n as u64]);
        (m != u64::MAX).then_some(m)
    }

    /// (rx frames, tx frames, drops) of port `p`, None if netd has failed.
    pub fn port_stats(&self, p: usize) -> Option<(u64, u64, u64)> {
        let rx = call(self.comp.service_ep, net::NETD_PORT_STATS, &[p as u64]);
        (rx != u64::MAX).then(|| (rx, mr(1), mr(2)))
    }
}

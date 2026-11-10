//! Networking: the netd component (switches and uplink NICs), the ports
//! that connect guests' virtio-net devices to it, and the links to other
//! partitions' netds.

use core::sync::atomic::Ordering;

use l4h_host::errno::Errno;
use sel4::{CapRights, ObjectBlueprint, VmAttributes, cap, cap_type};

use l4h_host::{badges, wiring};
use l4h_host::net::call::Request;
use l4h_host::fixed::ArrayVec;
use l4h_host::{self as host, net};

use crate::blkd::{BAR_STRIDE, VirtioRegions, bar_pages, is_legacy_virtio, keep_bits, map_bar_mask, virtio_bar_mask, virtio_regions};
use crate::component::{self, Component, SpawnArgs, abs_of};
use crate::devmem::DevMem;
use crate::iommu::Iommu;
use crate::mailbox::{self, Mailbox};
use l4h_host::mailbox::RING;
use crate::mem::{Alloc, Arena, Dest, Slot, UtRegion};
use crate::pci::{self, Pci};
use crate::vmmgr::RootGuest;
use crate::vspace::FRAME_BP;
use crate::window::Window;
use crate::{AsidPools, Host, HostInfo, ctl};

static NETD_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/l4h-netd.elf"));

const PAGE: usize = 4096;
fn nic_dma_bits(d: &pci::Device) -> usize {
    if is_mlx5(d) { 25 } else { 22 }
}

// Map the init segment, MSI-X table and lower UAR aperture. An allocated
// UAR beyond this mapping is rejected by the driver before any MMIO access.
fn mapped_device(d: &pci::Device) -> pci::Device {
    let mut mapped = *d;
    if is_mlx5(d) {
        mapped.bars[0].size = mapped.bars[0].size.min(BAR_STRIDE as u64);
    }
    mapped
}
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

pub fn is_mlx5(d: &pci::Device) -> bool {
    let aperture = d.bars[0].size.min(BAR_STRIDE as u64);
    d.vendor == 0x15b3 && d.device == 0x1017 && !d.bars[0].is_io
        && aperture >= 0x10000
        && d.msix.is_some_and(|m| m.table_bar == 0 && m.table_size >= 1
            && m.table_offset as u64 + m.table_size as u64 * 16 <= aperture)
}

/// NICs netd can drive as an uplink.
pub fn is_uplink(d: &pci::Device) -> bool {
    is_virtio_net(d) || is_gvnic(d) || is_ena(d) || is_ixgbe(d) || is_mlx5(d)
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

/// A steering endpoint (DESIGN.md §9.3): an address on a switch and the
/// peer its steered traffic comes from and returns to.
#[derive(Clone, Copy)]
pub struct Endpoint {
    pub switch: u32,
    pub mac: u64,
    pub peer: u64,
}

/// A steering rule: an endpoint's frames matching (IP, proto, port) go to
/// a target port.  `matches` and `ip` as CTL_STEER_SET's args.
#[derive(Clone, Copy)]
pub struct SteerRule {
    pub ep: usize,
    pub matches: u64,
    pub ip: (u64, u64),
    pub targets: u64,
}

/// A link to another partition (`link.pA-pB` in l4h-mk.conf, DESIGN.md
/// §11.4): a channel of its own that the two netds write and read
/// directly.  Root never touches the frames: it maps the channel into
/// netd, points the receive doorbell at netd, and rings the peer's
/// doorbell when netd asks (only root holds IRQControl), which netd does
/// only when the peer's netd said it is going to sleep.
pub struct Link {
    pub peer: u32,
    peer_slot: u32,
    peer_vector: u32,
}

pub struct Netd {
    comp: Component,
    #[allow(dead_code)]
    arena: Arena,
    /// Commands to netd, which it does not answer: root validates them
    /// and keeps their state (net::call::add_port).
    mailbox: Mailbox,
    /// netd faulted (`fault`): it is suspended, and commands to it go
    /// nowhere.
    failed: bool,
    /// Removals in the ring, by number mod RING: the port, and what waits
    /// for netd to let go of its memory (vmmgr::Zombie).
    removals: [Option<(usize, Option<usize>)>; RING],
    /// Ports being removed: netd may still use them (held), and the
    /// removal may wait for room in the ring (backlog), with its zombie.
    held: u64,
    backlog: u64,
    zombies: [Option<usize>; net::MAX_PORTS],
    pub nics: ArrayVec<Nic, { net::MAX_NICS }>,
    pub ports: [Option<PortInfo>; net::MAX_PORTS],
    /// Switches 0..switches exist (they are never deleted).
    pub switches: u32,
    /// Mirrors of netd's steering tables, by id.
    pub endpoints: [Option<Endpoint>; net::MAX_STEER_ENDPOINTS],
    pub rules: [Option<SteerRule>; net::MAX_STEER_RULES],
    pub links: ArrayVec<Link, { net::MAX_LINKS }>,
}

pub fn bdf(d: &pci::Device) -> u32 {
    ((d.bus as u32) << 8) | ((d.dev as u32) << 3) | d.func as u32
}

/// Make netd panic, for tests/run-logdtest.sh.  It has no keeper: its
/// fault comes to root, which fails it (`fault`).
pub fn inject_panic(h: &mut Host) {
    let _ = h.netd.post(Request::TestPanic {});
}

/// Make netd stop, for tests/run-logdtest.sh, as a compromised netd
/// might: root goes on, and what waits for netd stays pending.
pub fn inject_hang(h: &mut Host) {
    let _ = h.netd.post(Request::TestHang {});
}

/// The BARs netd maps of NIC `d`, bit b for BAR b.
fn used_bars(d: &pci::Device) -> u8 {
    if is_gvnic(d) {
        1 | 1 << 2 | 1 << d.msix.unwrap().table_bar
    } else if is_ena(d) {
        1 | (ena_llq(d) as u8) << 2 | 1 << d.msix.unwrap().table_bar
    } else if is_ixgbe(d) || is_mlx5(d) {
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
        let mlx5 = is_mlx5(d);
        let dma_bits = nic_dma_bits(d);
        let VirtioRegions { common, notify, notify_mult, isr, device, msix_table } = if is_legacy(d) || gvnic || ena || ixgbe || mlx5 {
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
        let mut region = alloc.split(dma_bits, s).expect("NIC DMA memory");
        let paddr = region.paddr;
        let frames = alloc.slots.alloc_range((1 << dma_bits) / PAGE);
        region
            .retype(&FRAME_BP, frames.len(), Dest::new(crate::slot::CNODE.cap(), frames.start))
            .expect("NIC DMA frames");
        let _ = dma.push(frames);
        // The NIC reaches its DMA memory only.
        let dom = iommu.attach(alloc, d);
        iommu.map(alloc, dom, paddr, 1 << dma_bits, true);
        let (msi_address, msi_data) = iommu.msi(dom, NIC_MSI_BASE + n as u64);
        cfg.nics[n] = net::NicConfig {
            kind: if gvnic {
                net::NIC_GVNIC
            } else if ena {
                net::NIC_ENA
            } else if mlx5 {
                net::NIC_MLX5
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
            regs: if gvnic || ena || ixgbe || mlx5 { l4h_host::blk::PciRegion { va: bar_va(0) as u64, len: mapped_device(d).bars[0].size } } else { none },
            doorbells: if gvnic || ena_llq(d) { bar_region(2) } else { none },
            dma_paddr: paddr as u64,
            dma_size: 1 << dma_bits,
        };
    }
    let cfg_bytes = unsafe {
        core::slice::from_raw_parts(&cfg as *const net::NetdConfig as *const u8, core::mem::size_of::<net::NetdConfig>())
    };
    let args = SpawnArgs {
        id: NETD_ID,
        kind: host::KIND_NETD,
        elf: NETD_ELF,
        prio: host::PRIO_SERVICE,
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

    // Mapping caps of the mailbox and every NIC page: DMA buffers and BARs.
    let pages = host::mailbox::MAILBOX_PAGES + nics[..nr_nics].iter().map(|d| (1 << nic_dma_bits(d)) / PAGE + bar_pages(&mapped_device(d), used_bars(d))).sum::<usize>();
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
        map_bar_mask(&comp, alloc, &mut arena, devmem, &mapped_device(&d), &mut bars, used_bars(&d), wc, |b| net::nic_bar_va(n, b as usize), &mut keep_slot);
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
        component::mint_edge(&abs_of(ntfn), &wiring::IRQ_NETD, n, &comp.obj()).expect("NIC IRQ notification");
        irq.irq_handler_set_notification(ntfn).expect("NIC IRQ set notification");
        comp.give(net::NETD_SLOT_IRQ_BASE + n as u64, irq, CapRights::all());
        pci.enable(&d);
        pci.enable_msix(&d);
        let _ = nic_list.push(Nic { pci: *d, switch: None });
    }
    let mailbox = Mailbox::new(&comp, mailbox::NETD_MAILBOX, &wiring::ROOT_NETD_CALL, &wiring::NETD_DONE, alloc, &mut arena, &mut keep_slot);
    component::start(&comp);
    Netd {
        comp,
        arena,
        mailbox,
        removals: [None; RING],
        failed: false,
        held: 0,
        backlog: 0,
        zombies: [None; net::MAX_PORTS],
        nics: nic_list,
        ports: [const { None }; net::MAX_PORTS],
        switches: 0,
        endpoints: [None; net::MAX_STEER_ENDPOINTS],
        rules: [None; net::MAX_STEER_RULES],
        links: ArrayVec::new(),
    }
}

impl Netd {
    /// Post a command; EBUSY if netd has left the ring full.
    /// Post a command: dropped once netd has failed, as root keeps the
    /// state commands set and reads nothing back.
    fn post(&mut self, req: Request) -> Result<(), Errno> {
        if self.failed {
            return Ok(());
        }
        self.mailbox.send(&req).map(|_| ()).ok_or(ctl::EBUSY)
    }

    /// Whether a command can be posted now.
    pub fn room(&self) -> bool {
        self.mailbox.room()
    }

    /// Whether netd has published its NICs' MACs, or never will.
    pub fn ready(&self) -> bool {
        self.failed || self.published().ready.load(Ordering::Acquire) != 0
    }

    fn published(&self) -> &net::Published {
        self.mailbox.published::<net::Published>()
    }

    /// A new switch; ENOSPC once there are MAX_SWITCHES, the size of
    /// netd's table of them.
    pub fn try_create_switch(&mut self) -> Result<u32, Errno> {
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

    pub fn attach_uplink(&mut self, switch: u32, nic: usize) -> Result<(), Errno> {
        if switch >= self.switches {
            return Err(ctl::ENOENT);
        }
        let n = self.nics.get_mut(nic).ok_or(ctl::ENOENT)?;
        if n.switch.is_some() {
            return Err(ctl::EBUSY);
        }
        if !self.failed {
            self.mailbox.send(&Request::AttachUplink { nic: nic as usize, switch: switch as usize }).ok_or(ctl::EBUSY)?;
        }
        n.switch = Some(switch);
        Ok(())
    }

    /// The port a new port on `switch` would be.
    pub fn free_port(&self, switch: u32) -> Result<usize, Errno> {
        if switch >= self.switches {
            return Err(ctl::ENOENT);
        }
        // A port being removed is netd's until it says it is done.
        let p = (0..net::MAX_PORTS).find(|&p| self.ports[p].is_none() && self.held & (1 << p) == 0).ok_or(ctl::ENOSPC)?;
        Ok(p)
    }

    /// A port's memory, in its own root slot: taken before the guest's
    /// device, so that running out leaves nothing behind.
    pub fn port_memory(alloc: &mut Alloc) -> Result<(Slot, UtRegion), Errno> {
        let s = alloc.slots.alloc();
        match alloc.split(PORT_BITS, s) {
            Some(region) => Ok((s, region)),
            None => {
                alloc.slots.free(s);
                Err(ctl::ENOMEM)
            }
        }
    }

    /// Connect a guest device of `g` to `switch` as port `p` (free_port,
    /// then give_port_done), using `memory` (port_memory).  Returns for the guest's l4h-vmm the
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
        let kick_slot = alloc.slots.alloc();
        let kick = sel4::init_thread::Slot::<cap_type::Notification>::from_index(kick_slot).cap();
        component::mint_edge(&abs_of(kick), &wiring::VMM_NETD_KICK, p, &self.comp.obj()).expect("port kick");
        // Only root grants a dom0 port the physical uplink's identity.
        // A bond keeps both permanent MACs but can send with either
        // member's MAC on either link. Do not unlock arbitrary sources.
        let uplink = self.nics.iter().position(|n| n.switch == Some(switch));
        let physical = g.dom0 && uplink.is_some_and(|n| self.nic_mac(n) == Some(mac))
            && !self.ports.iter().flatten().any(|p| p.vm == g.id && p.switch == switch && p.mac == mac);
        let alias = if physical && switch < 2 {
            self.nics.iter().position(|n| n.switch == Some(1 - switch)).and_then(|n| self.nic_mac(n)).unwrap_or(0)
        } else { 0 };
        let flags = if lock { net::NETD_PORT_MAC_LOCK } else { 0 }
            | if isolated { net::NETD_PORT_ISOLATED } else { 0 }
            | if physical { net::NETD_PORT_UPLINK } else { 0 };
        // The caller made sure of room in the ring (`room`).
        if self.post(Request::AddPort { port: p, switch: switch as usize, mac, flags, alias }).is_err() {
            log!("l4h-root: netd has no room for port {}", p);
        }
        self.ports[p] = Some(PortInfo { vm: g.id, switch, mac });
        (chan, kick)
    }

    /// Disconnect port `p`.  netd stops using its memory, and `zombie`
    /// (vmmgr::Zombie), which holds it, is told once netd has said so
    /// (`poll`).
    pub fn remove_port(h: &mut Host, p: usize, zombie: Option<usize>) {
        let n = &mut h.netd;
        if n.ports.get_mut(p).and_then(|i| i.take()).is_none() {
            crate::vmmgr::zombie_done(h, zombie, true);
            return;
        }
        // The port leaves every rule; netd does the same.
        for r in n.rules.iter_mut() {
            if r.is_some_and(|r| r.targets & (1 << p) != 0) {
                *r = None;
            }
        }
        n.held |= 1 << p;
        n.backlog |= 1 << p;
        n.zombies[p] = zombie;
        n.flush_backlog();
    }

    /// Post the removals that wait for room in the ring.  A failed netd
    /// keeps them for `poll`.
    fn flush_backlog(&mut self) {
        while self.backlog != 0 && !self.failed {
            let p = self.backlog.trailing_zeros() as usize;
            let Some(k) = self.mailbox.send(&Request::RemovePort { port: p }) else { break };
            self.removals[k as usize % RING] = Some((p, self.zombies[p].take()));
            self.backlog &= !(1 << p);
        }
    }

    /// Ports netd has let go of: their memory can be reclaimed.  A
    /// failed netd, suspended, lets go of every port at once.
    pub fn poll(h: &mut Host) {
        loop {
            let n = &mut h.netd;
            let next = if n.failed { n.mailbox.abandon() } else { n.mailbox.answer().map(|(k, _)| k) };
            let Some(k) = next else { break };
            let Some((p, zombie)) = n.removals[k as usize % RING].take() else { continue };
            Self::released(h, p, zombie);
        }
        while h.netd.failed && h.netd.backlog != 0 {
            let p = h.netd.backlog.trailing_zeros() as usize;
            h.netd.backlog &= !(1 << p);
            let zombie = h.netd.zombies[p].take();
            Self::released(h, p, zombie);
        }
        h.netd.flush_backlog();
    }

    /// netd no longer uses port `p`'s memory.
    fn released(h: &mut Host, p: usize, zombie: Option<usize>) {
        h.netd.take_port_done(p);
        h.netd.held &= !(1 << p);
        crate::vmmgr::zombie_done(h, zombie, true);
    }

    /// Component `id`'s fault, if it is netd's: suspend it, and let go of
    /// what it has not answered.  Whether it was netd's.
    pub fn fault(h: &mut Host, id: u32) -> bool {
        if id != NETD_ID {
            return false;
        }
        h.netd.fail(&h.pci);
        Self::poll(h);
        true
    }

    /// Stop using netd until reboot (it faulted, or misbehaved): suspend
    /// it, and cut the uplink NICs off from memory, as blkd's and usbd's
    /// quarantines disable their controllers: a suspended driver must not
    /// leave devices it programmed still bus-mastering.  `poll` then lets
    /// go of what it has not answered.
    pub fn fail(&mut self, pci: &Pci) {
        if self.failed {
            return;
        }
        log!("l4h-root: netd failed: guest networking stops until reboot");
        self.failed = true;
        let _ = self.comp.tcb.tcb_suspend();
        for nic in self.nics.iter() {
            pci.disable(&nic.pci);
        }
    }

    /// Give netd port `p`'s done notification, to guest `g`'s VMM, before
    /// anything is allocated for the port (`add_port`).  EIO, netd failed,
    /// if netd keeps filling the slot.
    pub fn give_port_done(&mut self, p: usize, g: &RootGuest, pci: &Pci) -> Result<(), Errno> {
        if self.comp.give_edge_live(&wiring::NETD_VMM_DONE, p, 0, &g.vmm_ntfn).is_err() {
            self.fail(pci);
            return Err(ctl::EIO);
        }
        Ok(())
    }

    /// Take back port `p`'s done notification (`give_port_done`): netd is
    /// done with the port, or it is not added after all.
    pub fn take_port_done(&self, p: usize) {
        let _ = self.comp.slot(net::NETD_SLOT_CLIENT_BASE + p as u64).delete();
    }

    /// Put the link channel `ch` of partition `me` on `switch`, as netd's
    /// link l (returned).  netd gets the channel mapped (by the CPU only:
    /// no device reaches it), its doorbell's IRQ handler, and `ntfn`
    /// badged for the link, to ask root to ring the peer's doorbell.
    pub fn add_link(
        &mut self,
        ch: &l4h_partition::Channel,
        me: u32,
        switch: u32,
        ntfn: cap::Notification,
        alloc: &mut Alloc,
        devmem: &mut DevMem,
        pci: &Pci,
    ) -> Result<usize, Errno> {
        let l = self.links.len();
        if l >= net::MAX_LINKS || switch >= self.switches {
            return Err(ctl::ENOSPC);
        }
        let size = ch.size as usize;
        if size > net::LINK_CHANNEL_MAX || size % PAGE != 0 {
            return Err(ctl::EINVAL);
        }
        let bits = keep_bits(size / PAGE);
        let keep = self.arena.object_cap::<cap_type::CNode>(alloc, ObjectBlueprint::CNode { size_bits: bits });
        let (comp, arena) = (&self.comp, &mut self.arena);
        let mut i = 0;
        devmem
            .frames_range(alloc, ch.paddr as usize, size, |alloc, frames| {
                for s in frames {
                    let dst = keep.absolute_cptr_from_bits_with_depth(i as u64, bits);
                    let f = abs_of(crate::devmem::granule(s));
                    comp.map_copy(alloc, arena, &f, net::link_va(l) + i * PAGE, CapRights::read_write(), VmAttributes::DEFAULT, dst);
                    i += 1;
                }
            })
            .ok_or(ctl::ENOMEM)?;
        // The doorbell wakes netd directly, badged as the link; netd acks
        // it.  netd's kick to itself carries the same badge.
        let badged = alloc.slots.alloc();
        let badged = sel4::init_thread::Slot::<cap_type::Notification>::from_index(badged).cap();
        component::mint_edge(&abs_of(badged), &wiring::DOORBELL_NETD, l, &self.comp.obj()).expect("link doorbell badge");
        let mut given = match crate::channel::doorbell(alloc, ch.vector, badged) {
            Some(irq) => self.comp.give_live(net::NETD_SLOT_LINK_IRQ_BASE + l as u64, irq, CapRights::all(), "link doorbell"),
            None => {
                log!("l4h-root: no doorbell from partition {} for the link", ch.peer);
                Ok(())
            }
        };
        given = given.and_then(|()| self.comp.give_edge_live(&wiring::NETD_LINK_SELF, l, l, &self.comp.obj()));
        given = given.and_then(|()| self.comp.give_edge_live(&wiring::NETD_LINK_RING, l, l, &component::root_ntfn(ntfn)));
        // A netd that keeps filling these slots misbehaves: what was set up
        // for the link stays with it, stopped until reboot.
        if given.is_err() {
            self.fail(pci);
            return Err(ctl::EIO);
        }
        self.post(Request::AddLink { link: l, switch: switch as usize, size: ch.size as u64, me: me as u32, peer: ch.peer as u32 })?;
        self.links.must_push(Link { peer: ch.peer, peer_slot: ch.peer_slot, peer_vector: ch.peer_vector });
        Ok(l)
    }

    /// netd asked for the doorbells of the links in `badge` (root's
    /// notification): ring them.  Constant work per link, however many
    /// frames netd wrote, and the notification merges repeated asks.
    pub fn link_ring(&self, badge: u64) {
        for (l, k) in self.links.iter().enumerate() {
            if badge & badges::root::LINK.nth(l) != 0 {
                crate::channel::ring(k.peer_slot, k.peer_vector);
            }
        }
    }

    /// CPU time netd used since the last call, in timer ticks.
    pub fn consumed(&self) -> u64 {
        crate::sched_consumed(self.comp.sc)
    }

    /// The MAC address of host NIC `n`, as netd published it.
    pub fn nic_mac(&self, n: usize) -> Option<u64> {
        let p = self.published();
        let m = p.nic_mac.get(n).filter(|_| n < self.nics.len() && p.ready.load(Ordering::Acquire) != 0)?;
        Some(m.load(Ordering::Relaxed) & 0xffff_ffff_ffff)
    }

    /// (rx frames, tx frames, drops) of port `p`, as netd published them.
    pub fn port_stats(&self, p: usize) -> Option<(u64, u64, u64)> {
        let [rx, tx, drops] = self.published().ports.get(p)?.each_ref().map(|c| c.load(Ordering::Relaxed));
        Some((rx, tx, drops))
    }
}

fn is_unicast_mac(m: u64) -> bool {
    m != 0 && m >> 48 == 0 && (m >> 40) & 1 == 0
}

/// An IP a rule may match: not unspecified, multicast or broadcast.
fn steerable_ip(v6: bool, hi: u64, lo: u64) -> bool {
    if v6 {
        (hi, lo) != (0, 0) && hi >> 56 != 0xff
    } else {
        lo != 0 && lo != 0xffff_ffff && lo >> 28 != 0xe
    }
}

impl Netd {
    /// The MAC of switch `sw`'s uplink NIC, if it has one.
    fn uplink_mac(&self, sw: u32) -> Option<u64> {
        let n = self.nics.iter().position(|n| n.switch == Some(sw))?;
        self.nic_mac(n)
    }

    /// Set the endpoint (switch, mac): a new one, or a new peer for an
    /// existing one.  Returns its id.
    pub fn ep_set(&mut self, switch: u32, mac: u64, peer: u64) -> Result<usize, Errno> {
        if switch >= self.switches {
            return Err(ctl::ENOENT);
        }
        if !is_unicast_mac(mac) || !is_unicast_mac(peer) || mac == peer {
            return Err(ctl::EINVAL);
        }
        // An address on the switch: never one behind its uplink.
        let on_switch = self.ports.iter().flatten().any(|p| p.switch == switch && p.mac == mac);
        if !on_switch && self.uplink_mac(switch) != Some(mac) {
            return Err(ctl::EINVAL);
        }
        let id = match self.endpoints.iter().position(|e| e.is_some_and(|e| e.switch == switch && e.mac == mac)) {
            Some(id) => id,
            None => self.endpoints.iter().position(|e| e.is_none()).ok_or(ctl::ENOSPC)?,
        };
        self.post(Request::EpSet { ep: id, switch: switch as usize, mac, peer })?;
        self.endpoints[id] = Some(Endpoint { switch, mac, peer });
        Ok(id)
    }

    /// Delete endpoint `id` and its rules.
    pub fn ep_del(&mut self, id: usize) -> Result<(), Errno> {
        self.endpoints.get(id).copied().flatten().ok_or(ctl::ENOENT)?;
        self.post(Request::EpDel { ep: id })?;
        self.endpoints[id] = None;
        for r in self.rules.iter_mut() {
            if r.is_some_and(|r| r.ep == id) {
                *r = None;
            }
        }
        Ok(())
    }

    /// Set the rule (ep, matches, ip): a new one, or new targets for an
    /// existing one.  Returns its id.
    pub fn steer_set(&mut self, ep: usize, matches: u64, ip: (u64, u64), targets: u64) -> Result<usize, Errno> {
        let e = self.endpoints.get(ep).copied().flatten().ok_or(ctl::ENOENT)?;
        let (family, proto, port) = (matches as u8, (matches >> 8) as u8, (matches >> 16) as u16);
        let v6 = match family {
            4 if ip.0 == 0 && ip.1 >> 32 == 0 => false,
            6 => true,
            _ => return Err(ctl::EINVAL),
        };
        if matches >> 32 != 0 || (proto == 0 && port != 0) || (port != 0 && proto != 6 && proto != 17) {
            return Err(ctl::EINVAL);
        }
        if !steerable_ip(v6, ip.0, ip.1) || targets.count_ones() != 1 {
            return Err(ctl::EINVAL);
        }
        let t = targets.trailing_zeros() as usize;
        let target = self.ports.get(t).and_then(|p| p.as_ref()).ok_or(ctl::ENOENT)?;
        if target.mac == e.mac {
            return Err(ctl::EINVAL);
        }
        let same = |r: &SteerRule| r.matches == matches && r.ip == ip;
        // A target takes an address from one endpoint only: its frames
        // from that address must leave through the endpoint whose rule
        // steered the request in, which the most specific return match
        // then always names.
        let same_ip = |r: &SteerRule| r.matches as u8 == family && r.ip == ip;
        if self.rules.iter().flatten().any(|r| same_ip(r) && r.ep != ep && r.targets & targets != 0) {
            return Err(ctl::EEXIST);
        }
        let id = match self.rules.iter().position(|r| r.is_some_and(|r| r.ep == ep && same(&r))) {
            Some(id) => id,
            None => self.rules.iter().position(|r| r.is_none()).ok_or(ctl::ENOSPC)?,
        };
        self.post(Request::SteerSet { rule: id, ep: ep as usize, matches: matches as u64, ip_hi: ip.0, ip_lo: ip.1, targets })?;
        self.rules[id] = Some(SteerRule { ep, matches, ip, targets });
        Ok(id)
    }

    pub fn steer_del(&mut self, id: usize) -> Result<(), Errno> {
        self.rules.get(id).copied().flatten().ok_or(ctl::ENOENT)?;
        self.post(Request::SteerDel { rule: id })?;
        self.rules[id] = None;
        Ok(())
    }

    /// (inbound frames, return frames) of rule `id`, as netd published
    /// them.
    pub fn steer_stats(&self, id: usize) -> Option<(u64, u64)> {
        let [i, o] = self.published().rules.get(id)?.each_ref().map(|c| c.load(Ordering::Relaxed));
        Some((i, o))
    }
}

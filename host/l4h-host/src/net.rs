//! netd: the L2 virtual switches and the uplink NIC drivers (virtio-net,
//! Google gVNIC, Amazon ENA and Intel X550).
//!
//! A port channel is one shared region between netd and a client (a
//! guest's l4h-vmm, one per virtio-net device) with a TX ring (client ->
//! switch) and an RX ring (switch -> client) of fixed-size frame slots.
//! Frames are copied into and out of the slots.  Each frame carries its
//! virtio-net header (struct virtio_net_hdr_v1): offloads (checksum, TSO)
//! travel through the switch as metadata, so a slot holds a whole 64 KiB
//! TSO frame.

pub const RING_SIZE: usize = 24;
pub const SLOT_SIZE: usize = 68 * 1024;
pub const HDR_SIZE: usize = 12;
pub const MAX_FRAME: usize = SLOT_SIZE - 32;
/// Ethernet header + 1500 bytes of payload.
pub const MTU_FRAME: usize = 1514;

/// virtio_net_hdr_v1 flags and GSO types.
pub const HDR_F_NEEDS_CSUM: u8 = 1;
pub const GSO_NONE: u8 = 0;

#[repr(C)]
pub struct Slot {
    pub len: u32,
    pub reserved: u32,
    pub hdr: [u8; HDR_SIZE],
    pub pad: [u8; 12],
    pub data: [u8; MAX_FRAME],
}

#[repr(C)]
pub struct RingIdx {
    pub head: u32,
    pub pad0: [u32; 15],
    pub tail: u32,
    pub pad1: [u32; 15],
}

#[repr(C)]
pub struct Port {
    pub tx: RingIdx,
    pub rx: RingIdx,
    pub mac: [u8; 8],
    /// netd publishes one packed LinkState, so carrier, speed and duplex
    /// change together. This field grants no port permissions.
    pub link_state: u32,
    /// Set by the client: its guest accepts frames with checksum offload
    /// (NEEDS_CSUM) and TSO (GSO types); otherwise netd completes the
    /// checksum and segments TSO frames for it.
    pub rx_csum: u32,
    pub rx_gso: u32,
    /// Set by netd while it holds frames for a full RX ring: the client
    /// kicks netd after freeing RX slots.
    pub rx_wanted: u32,
    pub reserved: [u32; 10],
    pub tx_slots: [Slot; RING_SIZE],
    pub rx_slots: [Slot; RING_SIZE],
}

pub const PORT_PAGES: usize = core::mem::size_of::<Port>().div_ceil(4096);

/// Ports netd serves; port p kicks netd with badge bit p.
pub const MAX_PORTS: usize = 48;
/// Uplink NICs; NIC n interrupts with badge bit NETD_BADGE_IRQ_SHIFT + n.
pub const MAX_NICS: usize = 4;
pub const NETD_BADGE_IRQ_SHIFT: u32 = 48;
/// Links to other partitions' netds (multikernel, DESIGN.md §11.4): one
/// to each other partition.  Link l's doorbell (and netd's own kick to
/// read on later) signals badge bit NETD_BADGE_LINK_SHIFT + l.
pub const MAX_LINKS: usize = 7;
pub const NETD_BADGE_LINK_SHIFT: u32 = 52;
/// A link's channel, at most (l4h_partition::LINK_CHANNEL_SIZE).
pub const LINK_CHANNEL_MAX: usize = 1 << 20;
/// Switches: one per port and NIC is the most that can carry traffic at
/// once.  Root refuses to create more, so netd keeps a fixed table of them
/// indexed by switch number.
pub const MAX_SWITCHES: usize = MAX_PORTS + MAX_NICS;

/// netd address space: port p at port_va(p); NIC n's BARs and DMA memory.
pub const fn port_va(p: usize) -> usize {
    crate::SHARED_VA + p * 0x40_0000
}
/// Link l's channel.
pub const fn link_va(l: usize) -> usize {
    crate::SHARED_VA + 0x1000_0000 + l * LINK_CHANNEL_MAX
}
pub const fn nic_bar_va(n: usize, bar: usize) -> usize {
    crate::MMIO_VA + n * 0x800_0000 + bar * 0x100_0000
}
pub const fn nic_dma_va(n: usize) -> usize {
    crate::DMA_VA + n * 0x200_0000
}

/// netd CSpace: IRQ handler of NIC n, notification of the client of port p
/// (badged with its "done" bit).
pub const NETD_SLOT_IRQ_BASE: u64 = 32;
/// I/O port capability of a legacy virtio NIC n (NicConfig::legacy_io).
pub const NETD_SLOT_IOPORT_BASE: u64 = 40;
/// Link l: the IRQ handler of its doorbell; root's notification, badged
/// for the link, which asks root to ring the peer's doorbell (netd cannot:
/// only root holds IRQControl); and netd's own, badged as the doorbell.
pub const NETD_SLOT_LINK_IRQ_BASE: u64 = 48;
pub const NETD_SLOT_LINK_RING_BASE: u64 = 56;
pub const NETD_SLOT_CLIENT_BASE: u64 = 64;
pub const NETD_SLOT_LINK_KICK_BASE: u64 = NETD_SLOT_CLIENT_BASE + MAX_PORTS as u64;

/// Calls from l4h-root to netd's service endpoint.
/// MR0 = port, MR1 = switch, MR2 = MAC (low 48 bits), MR3 = flags.
pub const NETD_ADD_PORT: u64 = 1;
pub const NETD_PORT_MAC_LOCK: u64 = 1 << 0;
pub const NETD_PORT_ISOLATED: u64 = 1 << 1;
/// Root-selected dom0 port of the physical uplink. MR4 is its one
/// additional allowed source MAC (0: none). Ordinary guests cannot set it.
pub const NETD_PORT_UPLINK: u64 = 1 << 2;
/// MR0 = port.  netd no longer touches the port's memory when this returns.
pub const NETD_REMOVE_PORT: u64 = 2;
/// MR0 = NIC, MR1 = switch.
pub const NETD_ATTACH_UPLINK: u64 = 3;
/// MR0 = port -> MR0 = rx frames, MR1 = tx frames, MR2 = drops.
pub const NETD_PORT_STATS: u64 = 4;
/// MR0 = NIC -> MR0 = its MAC address (low 48 bits).
pub const NETD_NIC_MAC: u64 = 5;
/// Steering (DESIGN.md §9.3).  Root allocates the ids and validates;
/// netd checks bounds and that targets exist.  u64::MAX in MR0 is a
/// failure.
/// MR0 = endpoint, MR1 = switch, MR2 = MAC, MR3 = peer MAC.  Setting an
/// endpoint with the same switch and MAC changes only its peer.
pub const NETD_EP_SET: u64 = 6;
/// MR0 = endpoint; deletes its rules too.
pub const NETD_EP_DEL: u64 = 7;
/// MR0 = rule, MR1 = endpoint, MR2 = match (abi::CTL_STEER_SET args[1]),
/// MR3 = IP bits 127-64, MR4 = IP bits 63-0, MR5 = target port mask.
pub const NETD_STEER_SET: u64 = 8;
/// MR0 = rule.
pub const NETD_STEER_DEL: u64 = 9;
/// MR0 = rule -> MR0 = inbound frames, MR1 = return frames.
pub const NETD_STEER_STATS: u64 = 10;
/// MR0 = link, MR1 = switch, MR2 = channel size, MR3 = this partition,
/// MR4 = the peer.  The channel is mapped at link_va(link) and the
/// NETD_SLOT_LINK_* capabilities given.  Links last until the machine
/// reboots.
pub const NETD_ADD_LINK: u64 = 11;
/// Endpoints and rules netd holds.
pub const MAX_STEER_ENDPOINTS: usize = 16;
pub const MAX_STEER_RULES: usize = 128;

/// NicConfig::kind.
pub const NIC_VIRTIO: u32 = 0;
pub const NIC_GVNIC: u32 = 1;
pub const NIC_IXGBE: u32 = 2;
pub const NIC_ENA: u32 = 3;
pub const NIC_MLX5: u32 = 4;

/// A single-word link snapshot. Speed 0 and duplex 0 mean unknown.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LinkState(pub u32);

impl LinkState {
    pub const VIRTUAL: Self = Self(1);
    pub const DOWN: Self = Self(0);
    pub const fn ethernet(up: bool, speed_mbps: u32) -> Self {
        Self(up as u32 | (speed_mbps << 1) | (2 << 29))
    }
    pub const fn up(self) -> bool { self.0 & 1 != 0 }
    pub const fn speed(self) -> u32 {
        let speed = (self.0 >> 1) & 0x0fff_ffff;
        if speed == 0 { u32::MAX } else { speed }
    }
    pub const fn duplex(self) -> u8 {
        match self.0 >> 29 & 3 { 1 => 0, 2 => 1, _ => 0xff }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct NicConfig {
    pub kind: u32,
    /// PCI revision ID (gVNIC: 0 takes the admin queue by page frame; ENA:
    /// bit 0 has registers read directly).
    pub revision: u32,
    pub pci_bdf: u32,
    pub msi_data: u32,
    pub msi_address: u64,
    pub common: crate::blk::PciRegion,
    pub notify: crate::blk::PciRegion,
    pub notify_off_multiplier: u32,
    /// Legacy (virtio 0.9.5) device: the I/O port base of its registers,
    /// with the capability in NETD_SLOT_IOPORT_BASE + n; 0 for a modern
    /// device (common/notify/isr/device are then used).
    pub legacy_io: u32,
    pub isr: crate::blk::PciRegion,
    pub device: crate::blk::PciRegion,
    pub msix_table: crate::blk::PciRegion,
    /// gVNIC: register BAR 0 and doorbell BAR 2; X550: register BAR 0;
    /// ENA: register BAR 0 and, if netd can use it, the LLQ memory in BAR 2,
    /// mapped write-combining.
    pub regs: crate::blk::PciRegion,
    pub doorbells: crate::blk::PciRegion,
    pub dma_paddr: u64,
    pub dma_size: u64,
}

#[repr(C)]
pub struct NetdConfig {
    pub nr_nics: u32,
    pub reserved: u32,
    pub nics: [NicConfig; MAX_NICS],
}

const _: () = assert!(PORT_PAGES * 4096 <= 0x40_0000 - 0x1_0000);
const _: () = assert!(port_va(MAX_PORTS) <= link_va(0) && link_va(MAX_LINKS) <= crate::MMIO_VA);
const _: () = assert!(
    NETD_BADGE_IRQ_SHIFT as usize + MAX_NICS <= NETD_BADGE_LINK_SHIFT as usize
        && NETD_BADGE_LINK_SHIFT as usize + MAX_LINKS <= 64
        && NETD_SLOT_IOPORT_BASE as usize + MAX_NICS <= NETD_SLOT_LINK_IRQ_BASE as usize
        && NETD_SLOT_LINK_IRQ_BASE as usize + MAX_LINKS <= NETD_SLOT_LINK_RING_BASE as usize
        && NETD_SLOT_LINK_RING_BASE as usize + MAX_LINKS <= NETD_SLOT_CLIENT_BASE as usize
        && NETD_SLOT_LINK_KICK_BASE as usize + MAX_LINKS <= 1 << crate::CNODE_BITS
);

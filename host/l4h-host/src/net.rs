//! netd: the L2 virtual switches.  Uplink NICs are driven outside it, by
//! nicds (crate::nicd), each joined to netd by an uplink channel
//! (crate::uplink).
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
pub struct Port {
    /// Frames the client sends (it produces, netd consumes), and those it
    /// receives.  Each side keeps its own index (crate::spsc).
    pub tx: crate::spsc::RingIdx,
    pub rx: crate::spsc::RingIdx,
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

/// Ports netd serves; port p kicks netd with badges::netd::PORT bit p.
pub const MAX_PORTS: usize = 48;
/// Uplinks: channels to nicds.  Any of them signals badges::netd::UPLINK,
/// and netd looks at them all.
pub const MAX_UPLINKS: usize = 16;
/// Links to other partitions' netds (multikernel, DESIGN.md §11.4): one
/// to each other partition.  Link l's doorbell (and netd's own kick to
/// read on later) signals badges::netd::LINK bit l.
pub const MAX_LINKS: usize = 7;
/// Room for a link's channel in netd's address space: a channel is
/// l4h_partition::LINK_CHANNEL_SIZE bytes, which root and netd check.
pub const LINK_CHANNEL_MAX: usize = 2 << 20;
/// Switches: one per port and NIC is the most that can carry traffic at
/// once.  Root refuses to create more, so netd keeps a fixed table of them
/// indexed by switch number.
pub const MAX_SWITCHES: usize = MAX_PORTS + MAX_UPLINKS;

/// netd address space: port p at port_va(p), link l's channel, uplink n's.
pub const fn port_va(p: usize) -> usize {
    crate::SHARED_VA + p * 0x40_0000
}
/// Link l's channel.
pub const fn link_va(l: usize) -> usize {
    crate::SHARED_VA + 0x1000_0000 + l * LINK_CHANNEL_MAX
}
pub const fn uplink_va(n: usize) -> usize {
    crate::MMIO_VA + n * UPLINK_CHANNEL_MAX
}
pub const UPLINK_CHANNEL_MAX: usize = crate::uplink::MAX_CHANNEL_SIZE.next_power_of_two();

/// netd CSpace: uplink n's nicd's notification (badged
/// badges::nicd::NETD), notification of the client of port p (badged with
/// its "done" bit).
pub const NETD_SLOT_UPLINK_BASE: u64 = 32;
/// Link l: the IRQ handler of its doorbell; root's notification, badged
/// for the link, which asks root to ring the peer's doorbell (netd cannot:
/// only root holds IRQControl); and netd's own, badged as the doorbell.
pub const NETD_SLOT_LINK_IRQ_BASE: u64 = 48;
pub const NETD_SLOT_LINK_RING_BASE: u64 = 56;
pub const NETD_SLOT_CLIENT_BASE: u64 = 64;
pub const NETD_SLOT_LINK_KICK_BASE: u64 = NETD_SLOT_CLIENT_BASE + MAX_PORTS as u64;

/// Flags of `add_port`.
pub const NETD_PORT_MAC_LOCK: u64 = 1 << 0;
pub const NETD_PORT_ISOLATED: u64 = 1 << 1;
/// Root-selected dom0 port of the physical uplink, whose `alias` is its one
/// additional allowed source MAC (0: none).  Ordinary guests cannot set it.
pub const NETD_PORT_UPLINK: u64 = 1 << 2;
/// The port sends only from the addresses IpSet gives it (DESIGN.md §9.3,
/// L3 filtering); it starts with none.
pub const NETD_PORT_IP_FILTER: u64 = 1 << 3;
/// Prefixes a filtered port may send from.
pub const MAX_PORT_IPS: usize = 16;

/// Whether IpSet's (`prefix`, `ip_hi`, `ip_lo`) is an IPv4 or IPv6 prefix
/// with no bits set past its length.
pub fn ip_prefix_ok(prefix: u64, ip_hi: u64, ip_lo: u64) -> bool {
    let (family, len) = (prefix as u8, (prefix >> 8) as u8 as u32);
    let ip = (ip_hi as u128) << 64 | ip_lo as u128;
    let bits = match family {
        4 if ip >> 32 == 0 => 32,
        6 => 128,
        _ => return false,
    };
    // The host part: its bits shifted out of the top must be all there is.
    prefix >> 16 == 0 && len <= bits && (len == bits || ip << (128 - (bits - len)) == 0)
}

use crate::badges::driver as recv;

crate::senders! {
    /// Who posts in the mailbox: l4h-root alone.
    pub enum Sender in recv {
        Root: mailbox;
    }
}

crate::protocol! {
    /// Commands from l4h-root (crate::mailbox, crate::wire::protocol),
    /// which netd carries out in order.  Root has validated them, keeps
    /// their state, and reads only the answers' count: they are done.
    /// Label 10 is unused: netd publishes its counters and uplinks' MACs
    /// instead (Published).
    pub mod call (from: Sender) {
        /// Port `port` on `switch`, with MAC `mac` (low 48 bits) and
        /// NETD_PORT_* `flags`.
        AddPort / add_port = 1 from [Root] (port: usize, switch: usize, mac: u64, flags: u64, alias: u64) -> ();
        /// netd no longer touches the port's memory, nor signals its
        /// client, once it has counted this done.
        RemovePort / remove_port = 2 from [Root] (port: usize) -> ();
        /// Put uplink `nic` on `switch`.  It stays there across its nicd's
        /// restarts (RemoveUplink, AddUplink).
        AttachUplink / attach_uplink = 3 from [Root] (nic: usize, switch: usize) -> ();
        /// Steering (DESIGN.md §9.3).  Root allocates the ids and
        /// validates; netd checks bounds and that targets exist, and
        /// ignores a command that fails them.  Setting an endpoint with the
        /// same switch and MAC changes only its peer.
        EpSet / ep_set = 6 from [Root] (ep: usize, switch: usize, mac: u64, peer: u64) -> ();
        /// Delete an endpoint, and its rules.
        EpDel / ep_del = 7 from [Root] (ep: usize) -> ();
        /// `matches` is abi::CTL_STEER_SET's args[1]; `targets` a port mask.
        SteerSet / steer_set = 8 from [Root] (rule: usize, ep: usize, matches: u64, ip_hi: u64, ip_lo: u64, targets: u64) -> ();
        SteerDel / steer_del = 9 from [Root] (rule: usize) -> ();
        /// L3 filtering: port `port` may send from the prefix in slot
        /// `slot` (below MAX_PORT_IPS).  `prefix` is family | length << 8,
        /// the address as SteerSet's.  netd ignores it for a port without
        /// NETD_PORT_IP_FILTER.
        IpSet / ip_set = 12 from [Root] (port: usize, slot: usize, prefix: u64, ip_hi: u64, ip_lo: u64) -> ();
        IpDel / ip_del = 13 from [Root] (port: usize, slot: usize) -> ();
        /// Link `link` to partition `peer`, on `switch`, with a channel of
        /// `size` bytes (l4h_partition::LINK_CHANNEL_SIZE: netd refuses
        /// another) mapped at link_va(link) and the NETD_SLOT_LINK_*
        /// capabilities given.  Links last until the machine reboots.
        AddLink / add_link = 11 from [Root] (link: usize, switch: usize, size: u64, me: u32, peer: u32) -> ();
        /// Uplink `nic`'s channel is mapped at uplink_va(nic), fresh (all
        /// zeros), with data areas of 2^data_bits, and its nicd's
        /// notification is at NETD_SLOT_UPLINK_BASE + nic.  netd reads the
        /// offer once the nicd sets ready.
        AddUplink / add_uplink = 4 from [Root] (nic: usize, data_bits: u32) -> ();
        /// netd no longer touches uplink `nic`'s channel, nor signals its
        /// nicd, once it has counted this done.  Its switch stays.
        RemoveUplink / remove_uplink = 5 from [Root] (nic: usize) -> ();
        /// `crate::TEST_INJECT` only: panic.
        TestPanic / test_panic = 0x7e57 from [Root] () -> ();
        /// `crate::TEST_INJECT` only: stop for good without failing, as a
        /// compromised netd might.
        TestHang / test_hang = 0x7e58 from [Root] () -> ();
    }
}
const _: () = assert!(call::Request::MAX_WORDS <= crate::mailbox::ARGS
    && call::Request::MAX_REPLY_WORDS <= crate::mailbox::ANSWER);

/// Endpoints and rules netd holds.
pub const MAX_STEER_ENDPOINTS: usize = 16;
pub const MAX_STEER_RULES: usize = 128;

/// What netd publishes for root (host::mailbox::PUBLISHED_OFFSET).  The
/// counters are netd's word: root only reports them.
#[repr(C)]
pub struct Published {
    /// Non-zero once netd serves.
    pub ready: core::sync::atomic::AtomicU64,
    /// Per uplink (UPLINK_*): state | generation << 8 (AddUplinks seen),
    /// the MAC of its offer (low 48 bits) | mac_mode << 48, its link state,
    /// and rx frames, tx frames, drops.  The offer is the nicd's, as netd
    /// checked it (uplink::Offer::checked): root checks the MAC again
    /// before it uses it.
    pub uplinks: [[core::sync::atomic::AtomicU64; 6]; MAX_UPLINKS],
    /// Per port: rx frames, tx frames, drops.
    pub ports: [[core::sync::atomic::AtomicU64; 3]; MAX_PORTS],
    /// Per rule: inbound frames, return frames.
    pub rules: [[core::sync::atomic::AtomicU64; 2]; MAX_STEER_RULES],
}
const _: () = assert!(core::mem::size_of::<Published>() <= 4096);

/// Published::uplinks state: none, waiting for the offer, up (offer
/// read), refused (the offer), broken (the nicd broke the channel).
pub const UPLINK_NONE: u64 = 0;
pub const UPLINK_WAITING: u64 = 1;
pub const UPLINK_UP: u64 = 2;
pub const UPLINK_REFUSED: u64 = 3;
pub const UPLINK_BROKEN: u64 = 4;
/// Published::uplinks words.
pub const UPLINK_STATE: usize = 0;
pub const UPLINK_MAC: usize = 1;
pub const UPLINK_LINK: usize = 2;
pub const UPLINK_RX: usize = 3;
pub const UPLINK_TX: usize = 4;
pub const UPLINK_DROPS: usize = 5;

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

const _: () = assert!(PORT_PAGES * 4096 <= 0x40_0000 - 0x1_0000);
const _: () = assert!(port_va(MAX_PORTS) <= link_va(0) && link_va(MAX_LINKS) <= crate::MMIO_VA
    && uplink_va(MAX_UPLINKS) <= crate::DMA_VA);
const _: () = assert!(
    NETD_SLOT_UPLINK_BASE as usize + MAX_UPLINKS <= NETD_SLOT_LINK_IRQ_BASE as usize
        && NETD_SLOT_LINK_IRQ_BASE as usize + MAX_LINKS <= NETD_SLOT_LINK_RING_BASE as usize
        && NETD_SLOT_LINK_RING_BASE as usize + MAX_LINKS <= NETD_SLOT_CLIENT_BASE as usize
        && NETD_SLOT_LINK_KICK_BASE as usize + MAX_LINKS <= 1 << crate::CNODE_BITS
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_prefixes() {
        assert!(ip_prefix_ok(4 | 32 << 8, 0, 0x0a00_0005));
        assert!(ip_prefix_ok(4 | 24 << 8, 0, 0x0a00_0000));
        assert!(!ip_prefix_ok(4 | 24 << 8, 0, 0x0a00_0001));
        assert!(ip_prefix_ok(4, 0, 0));
        assert!(!ip_prefix_ok(4, 0, 1));
        assert!(!ip_prefix_ok(4 | 33 << 8, 0, 0));
        assert!(!ip_prefix_ok(4 | 32 << 8, 0, 1 << 32));
        assert!(!ip_prefix_ok(4 | 32 << 8, 1, 0));
        assert!(ip_prefix_ok(6 | 128 << 8, u64::MAX, u64::MAX));
        assert!(ip_prefix_ok(6 | 64 << 8, 0x2001_0db8_0000_0001, 0));
        assert!(!ip_prefix_ok(6 | 64 << 8, 0x2001_0db8_0000_0001, 1));
        assert!(ip_prefix_ok(6, 0, 0));
        assert!(!ip_prefix_ok(6, 1 << 63, 0));
        assert!(!ip_prefix_ok(6 | 129 << 8, 0, 0));
        assert!(!ip_prefix_ok(5, 0, 0));
        assert!(!ip_prefix_ok(4 | 1 << 16, 0, 0));
    }
}

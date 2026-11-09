//! l4h-memd, the owner of the host's free memory and of every guest's RAM
//! (DESIGN.md §8.4): its CSpace, the calls l4h-root and l4h-vmmgr make to
//! it, and the status page it keeps for them.
//!
//! memd's CSpace is one CNode of 2^cnode_bits slots (MemdConfig), with a
//! slot for every block it can hold (`block_slots`).  l4h-root holds a
//! capability to it.  A call's capabilities cross in the caller's
//! exchange area (`call::XCHG` slots; each call declares which it uses):
//! root's is at SLOT_XCHG in memd's CNode, vmmgr's is a CNode the two share
//! (SLOT_XCHG_CNODE).  memd never calls either.
//!
//! memd allocates nothing: what it knows of memory is a table with an
//! entry per 2 MiB of physical address space (TABLE_VA), which l4h-root
//! maps when it spawns memd, and memd never handles less than 2 MiB.

/// The I/O ports of a legacy balloon (BalloonConfig::legacy_io), which
/// l4h-root puts here before `call::balloon`.
pub const SLOT_BALLOON_IOPORT: u64 = crate::SLOT_FIRST_FREE;
/// Slot of guest g's block CNode (L4H_SLOT_BLOCKS of the guest), which
/// memd takes from vmmgr's exchange area at `guest_create` and deletes at
/// `guest_destroy`.
pub const SLOT_GUEST_BCN: u64 = 32;
const _: () = assert!(SLOT_BALLOON_IOPORT < SLOT_GUEST_BCN);
pub const MAX_GUESTS: usize = 64;
/// Slot of guest g's hotplug CNode (L4H_SLOT_HP of the guest, without its
/// guard), SLOT_GUEST_HCN + g, which memd takes from vmmgr's exchange area
/// at `guest_create` and deletes at `guest_destroy`.
pub const SLOT_GUEST_HCN: u64 = SLOT_GUEST_BCN + MAX_GUESTS as u64;
/// Root's exchange area: slots [SLOT_XCHG, SLOT_XCHG + XCHG_AREA) of
/// memd's CNode.  vmmgr's is the CNode in SLOT_XCHG_CNODE, of radix
/// XCHG_RADIX.
pub const SLOT_XCHG: u64 = 160;
pub const XCHG_RADIX: usize = 6;
pub const XCHG_AREA: usize = 1 << XCHG_RADIX;
/// Blocks an `alloc` or `free` passes, at most (`free` takes two message
/// registers for each).
pub const XCHG_SLOTS: usize = 32;
/// The blocks' slots start here (`block_slots`).
pub const SLOT_DYN_BASE: u64 = 256;
const _: () = assert!(SLOT_GUEST_HCN as usize + MAX_GUESTS <= SLOT_XCHG as usize);
const _: () = assert!(SLOT_XCHG as usize + XCHG_AREA <= SLOT_DYN_BASE as usize);

crate::senders! {
    /// Who calls memd, by the badge of its capability (badges::memd).
    /// l4h-root calls with an unbadged one, for its own memory; l4h-vmmgr
    /// with one badged VMMGR, for its own memory and guests' RAM, passing
    /// capabilities in its mailbox; a guest's l4h-vmm with one badged
    /// `VMM | GUEST`, for the hotplug calls of its own guest.
    pub enum Sender in recv {
        Root: [];
        Vmmgr: [VMMGR];
        Vmm(GUEST): [VMM];
    }
}

use crate::badges::memd as recv;
use crate::fixed::ArrayVec;
use crate::wire::Tail;

crate::protocol! {
    /// The calls on memd's service endpoint (crate::wire::protocol).  A
    /// reply's first word is 0 or an errno (ENOMEM, EINVAL; ENOSPC and EBUSY
    /// from the hotplug calls, DESIGN.md §8.5).
    ///
    /// vmmgr is less trusted than memd, so memd keeps the original of every
    /// block it grants vmmgr and gives it a copy: `free` then revokes the
    /// original, whatever vmmgr put in the mailbox.
    pub mod call (from: Sender, xchg: XCHG_AREA) {
        /// `count` (at most XCHG_SLOTS) Untypeds of 2^bits bytes
        /// (BLOCK_BITS..=MAX_BITS) without children, in the exchange
        /// slots: their physical addresses.
        Alloc / alloc = 1 from [Root, Vmmgr] (bits: usize, count: usize)
            caps { Out BLOCKS: Untyped [0; XCHG_SLOTS] } -> Tail<u64, XCHG_SLOTS>;
        /// Untypeds without children that the caller put in its exchange
        /// slots, (physical address, size bits) each, returned to the free
        /// memory.  Each is a block memd gave, or one of at least
        /// 2^BLOCK_BITS bytes in the units of the table.
        Free / free = 2 from [Root, Vmmgr] (blocks: ArrayVec<(usize, usize), XCHG_SLOTS>)
            caps { In BLOCKS: Untyped [0; XCHG_SLOTS] } -> ();
        /// Take the guest's RAM, `blocks` 2 MiB blocks, with its block
        /// CNode (of radix `radix`) and hotplug CNode (for `hp_count`
        /// hotplug blocks, at most HP_MAX).  Nothing is given yet, and its
        /// hotplug target is 0.
        GuestCreate / guest_create = 3 from [Vmmgr] (guest: usize, blocks: usize, radix: usize, hp_count: usize)
            caps { In BLOCK_CNODE: CNode [XCHG_SLOTS; 1], In HP_CNODE: CNode [XCHG_SLOTS + 1; 1] } -> ();
        /// A copy of the block's Untyped in exchange slot 0, for vmmgr to
        /// fill with frames (a boot block): its physical address.  Once
        /// per block, before `guest_give`.
        GuestCopy / guest_copy = 4 from [Vmmgr] (guest: usize, block: usize)
            caps { Out BLOCK: Untyped [0; 1] } -> u64;
        /// Copies of the Untypeds of blocks [first, blocks) into the
        /// guest's block CNode, block b at index b + skip (the guest's
        /// blocks of the shared kernel image have none).
        GuestGive / guest_give = 5 from [Vmmgr] (guest: usize, first: usize, skip: usize) -> ();
        /// Revoke every block of the guest's RAM, which deletes all that
        /// was made of them (its frames and objects, vmmgr's frames of its
        /// boot blocks), and free them.  A guest memd does not know is no
        /// error.
        GuestDestroy / guest_destroy = 6 from [Vmmgr] (guest: usize) -> ();
        /// Drive the free page reporting device, which l4h-root has
        /// mapped.  ENODEV if it cannot report.
        Balloon / balloon = 7 from [Root] (cfg: BalloonConfig) -> ();
        /// The guest's hotplug target, in hotplug blocks, clamped to its
        /// region.
        SetTarget / set_target = 8 from [Vmmgr] (guest: usize, target: usize) -> ();
        /// Plug hotplug block m of the caller's guest, copying the Untypeds
        /// of its 64 blocks into the guest's level-2 hotplug CNode in slot m
        /// of its hotplug CNode.
        HpPlug / hp_plug = 16 from [Vmm] (m: usize) -> ();
        /// Revoke and free the blocks of hotplug block m.
        HpUnplug / hp_unplug = 17 from [Vmm] (m: usize) -> ();
        /// The caller's guest's hotplug state.
        HpState / hp_state = 18 from [Vmm] () -> HpState;
    }
}

crate::wire_struct! {
    /// A guest's hotplug state (call::Client::hp_state).
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct HpState {
        pub target: u64,
        pub plugged: u64,
        pub map: [u64; HP_MAP_WORDS],
    }
}

/// Slot of vmmgr's exchange area: a CNode memd shares with it, of radix
/// XCHG_RADIX.  (It was SLOT_BALLOON_IOPORT's slot, which a legacy
/// balloon's I/O ports also took.)
pub const SLOT_XCHG_CNODE: u64 = SLOT_BALLOON_IOPORT + 1;
const _: () = assert!(SLOT_XCHG_CNODE < SLOT_GUEST_BCN);
/// Hotplug blocks of a region, at most, and the words of its bitmap.
pub const HP_MAX: usize = 512;
pub const HP_MAP_WORDS: usize = HP_MAX / 64;
/// A guest plugs or unplugs at most HP_RATE hotplug blocks a second, after
/// a burst of HP_BURST.
pub const HP_RATE: u64 = 8;
pub const HP_BURST: u64 = 16;

/// Guest RAM comes in blocks of 2^BLOCK_BITS bytes, the smallest memd
/// handles: a unit of its table.
pub const BLOCK_BITS: usize = 21;
/// The largest block (seL4's largest Untyped).
pub const MAX_BITS: usize = 47;
/// Block sizes memd handles: 2^(BLOCK_BITS + order) bytes, order < ORDERS.
pub const ORDERS: usize = MAX_BITS - BLOCK_BITS + 1;

/// memd's table: an entry of UNIT_BYTES per 2 MiB unit of physical
/// address space, from 0 to units << BLOCK_BITS (MemdConfig), zeroed.
pub const TABLE_VA: usize = crate::SHARED_VA + 0x100_0000_0000;
pub const UNIT_BYTES: usize = 24;

pub const fn table_bytes(units: u64) -> usize {
    (units as usize * UNIT_BYTES).next_multiple_of(4096)
}
// The table of a 48-bit physical address space fits below MMIO_VA.
const _: () = assert!(TABLE_VA + table_bytes(1 << (48 - BLOCK_BITS)) <= crate::MMIO_VA);

/// Slots for the blocks of a table of `units`: one for each block of each
/// order that fits, at SLOT_DYN_BASE + first + index, where `first` is
/// the sum of the counts of the smaller orders.
pub const fn block_slots(units: u64) -> u64 {
    let mut n = 0;
    let mut k = 0;
    while k < ORDERS {
        n += units.div_ceil(1 << k);
        k += 1;
    }
    n
}

/// Radix of memd's CNode for a table of `units`.
pub const fn cnode_bits(units: u64) -> usize {
    (SLOT_DYN_BASE + block_slots(units)).next_power_of_two().trailing_zeros() as usize
}

/// memd's status page, mapped read-only in l4h-root.  memd updates it
/// after every call and report.
pub const STATUS_VA: usize = crate::SHARED_VA;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Status {
    /// Bytes in free blocks (not given to l4h-root or a guest).
    pub free_bytes: u64,
    /// Of those, reported to the hypervisor.
    pub reported_bytes: u64,
    /// Free blocks, and the size of the largest.
    pub free_blocks: u64,
    pub largest_block: u64,
    /// Bytes of guest RAM memd holds, plugged memory included.
    pub guest_bytes: u64,
    /// Of those, plugged (hotplug blocks).
    pub plugged_bytes: u64,
    /// Per guest: hotplug target and plugged hotplug blocks.
    pub hp: [GuestHp; MAX_GUESTS],
}

#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct GuestHp {
    pub target: u16,
    pub plugged: u16,
    pub count: u16,
    pub reserved: u16,
}

const _: () = assert!(core::mem::size_of::<Status>() <= 4096);

/// The free page reporting device (a virtio-balloon on PCI): its BARs are
/// mapped at BALLOON_VA + bar * BAR_STRIDE, three DMA pages at DMA_VA.
pub const BALLOON_VA: usize = crate::MMIO_VA;
pub const BAR_STRIDE: usize = 0x100_0000;
pub const DMA_VA: usize = crate::DMA_VA;
pub const DMA_PAGES: usize = 3;

crate::wire_struct! {
    /// Where the device's capability structures are: (BAR, offset) of the
    /// common, notify and device configuration, packed as bar << 32 | offset.
    #[derive(Clone, Copy, Default, Debug)]
    pub struct BalloonConfig {
        pub common: u64,
        pub notify: u64,
        pub device: u64,
        pub notify_mult: u64,
        pub dma_paddr: u64,
        /// A legacy device: the base of its I/O ports, in
        /// SLOT_BALLOON_IOPORT (the others are then 0); 0 for a modern one.
        pub legacy_io: u64,
    }
}

impl BalloonConfig {
    pub fn va(packed: u64) -> usize {
        BALLOON_VA + (packed >> 32) as usize * BAR_STRIDE + (packed & 0xffff_ffff) as usize
    }
}

/// memd's configuration in its info page.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct MemdConfig {
    pub cnode_bits: u64,
    /// Entries of the table at TABLE_VA.
    pub units: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The labels, words and badges memd's callers used before the
    /// protocol was declared.
    #[test]
    fn unchanged() {
        use call::Request;
        let r = |label, args: &[u64], from| Request::decode(label, args, from).map(|r| r.label());
        assert_eq!(r(1, &[21, 1], Sender::Root), Ok(1));
        assert_eq!(r(2, &[0], Sender::Vmmgr), Ok(2));
        assert_eq!(r(3, &[0, 1, 1, 0], Sender::Vmmgr), Ok(3));
        assert_eq!(r(5, &[0, 0, 0], Sender::Vmmgr), Ok(5));
        assert_eq!(r(7, &[0; 6], Sender::Root), Ok(7));
        assert_eq!(r(18, &[], Sender::Vmm(3)), Ok(18));
        // What memd refused before: guest calls from root, root's from
        // vmmgr, anything but hotplug from a VMM.
        assert_eq!(r(3, &[0, 1, 1, 0], Sender::Root), Err(crate::wire::EINVAL));
        assert_eq!(r(7, &[0; 6], Sender::Vmmgr), Err(crate::wire::EINVAL));
        assert_eq!(r(1, &[21, 1], Sender::Vmm(0)), Err(crate::wire::EINVAL));
        assert_eq!(r(16, &[0], Sender::Vmmgr), Err(crate::wire::EINVAL));
        assert_eq!(call::Request::MAX_WORDS, 1 + 2 * XCHG_SLOTS);
        assert_eq!(call::Request::MAX_REPLY_WORDS, 1 + XCHG_SLOTS);
        for s in [Sender::Root, Sender::Vmmgr, Sender::Vmm(0), Sender::Vmm(MAX_GUESTS - 1)] {
            assert_eq!(Sender::of_badge(s.badge()), Some(s));
        }
        assert_eq!(Sender::Vmmgr.badge(), 1 << 61);
        assert_eq!(Sender::Vmm(5).badge(), (1 << 62) | 5);
        assert_eq!(Sender::of_badge(recv::TIMER), None);
    }
}

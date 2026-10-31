//! l4h-memd, the owner of the host's free memory and of every guest's RAM
//! (DESIGN.md §8.4): its CSpace, the calls l4h-root and l4h-vmmgr make to
//! it, and the status page it keeps for them.
//!
//! memd's CSpace is one CNode of 2^cnode_bits slots (MemdConfig), with a
//! slot for every block it can hold (`block_slots`).  l4h-root holds a
//! capability to it, and passes Untypeds by moving them into the exchange
//! slots below.  vmmgr passes them through its mailbox (SLOT_MAILBOX).
//! memd never calls either.
//!
//! memd allocates nothing: what it knows of memory is a table with an
//! entry per 2 MiB of physical address space (TABLE_VA), which l4h-root
//! maps when it spawns memd, and memd never handles less than 2 MiB.

/// The I/O ports of a legacy balloon (BalloonConfig::legacy_io), which
/// l4h-root puts here before MEMD_BALLOON.
pub const SLOT_BALLOON_IOPORT: u64 = crate::SLOT_FIRST_FREE;
/// Slot of guest g's block CNode (L4H_SLOT_BLOCKS of the guest), which
/// memd takes from vmmgr's mailbox at MEMD_GUEST_CREATE and deletes at
/// MEMD_GUEST_DESTROY.
pub const SLOT_GUEST_BCN: u64 = 32;
const _: () = assert!(SLOT_BALLOON_IOPORT < SLOT_GUEST_BCN);
pub const MAX_GUESTS: usize = 64;
/// Slot of guest g's hotplug CNode (L4H_SLOT_HP of the guest, without its
/// guard), SLOT_GUEST_HCN + g, which memd takes from vmmgr's mailbox at
/// MEMD_GUEST_CREATE and deletes at MEMD_GUEST_DESTROY.
pub const SLOT_GUEST_HCN: u64 = SLOT_GUEST_BCN + MAX_GUESTS as u64;
/// Exchange slots: Untypeds passed by MEMD_ALLOC, MEMD_FREE and
/// MEMD_GUEST_COPY, slot SLOT_XCHG + i for the i-th.  A call passes at
/// most XCHG_SLOTS (MEMD_FREE takes two message registers for each).
pub const SLOT_XCHG: u64 = 160;
pub const XCHG_SLOTS: usize = 32;
/// The blocks' slots start here (`block_slots`).
pub const SLOT_DYN_BASE: u64 = 256;
const _: () = assert!(SLOT_GUEST_HCN as usize + MAX_GUESTS <= SLOT_XCHG as usize);
const _: () = assert!(SLOT_XCHG as usize + XCHG_SLOTS <= SLOT_DYN_BASE as usize);

/// Labels of calls on memd's service endpoint.  The reply's MR0 is 0 or
/// an errno (ENOMEM, EINVAL).  l4h-root calls with an unbadged capability,
/// for its own memory (MEMD_ALLOC, MEMD_FREE, MEMD_BALLOON); l4h-vmmgr
/// with one badged BADGE_VMMGR, for its own memory and guests' RAM (all
/// but MEMD_BALLOON), passing capabilities in its mailbox; a guest's
/// l4h-vmm with one badged `BADGE_VMM | guest`, which may make the
/// MEMD_HP_* calls only.
///
/// vmmgr is less trusted than memd, so memd keeps the original of every
/// block it grants vmmgr and gives it a copy: MEMD_FREE then revokes the
/// original, whatever vmmgr put in the mailbox.
///
/// MR0 = size bits (BLOCK_BITS..=MAX_BITS), MR1 = count (<= XCHG_SLOTS): `count` Untypeds of
/// 2^bits bytes without children, in the exchange slots; MR1.. of the
/// reply = their physical addresses.
pub const MEMD_ALLOC: u64 = 1;
/// MR0 = count (<= XCHG_SLOTS), MR1.. = (physical address, size bits) of
/// each: Untypeds without children that the caller put in its exchange
/// slots, returned to the free memory.  Each is a block memd gave, or one
/// of at least 2^BLOCK_BITS bytes in the units of the table.
pub const MEMD_FREE: u64 = 2;
/// MR0 = guest, MR1 = blocks, MR2 = radix of its block CNode, MR3 =
/// hotplug blocks in its region (at most abi::HP_MAX), its block and
/// hotplug CNodes in the mailbox: take the guest's RAM, `blocks` 2 MiB
/// blocks.  Nothing is given yet, and its hotplug
/// target is 0.
pub const MEMD_GUEST_CREATE: u64 = 3;
/// MR0 = guest, MR1 = block: a copy of the block's Untyped in exchange
/// slot 0, for vmmgr to fill with frames (a boot block); reply MR1 =
/// its physical address.  Once per block, before MEMD_GUEST_GIVE.
pub const MEMD_GUEST_COPY: u64 = 4;
/// MR0 = guest, MR1 = first block, MR2 = skip: copies of the Untypeds of
/// blocks [first, blocks) into the guest's block CNode, block b at index
/// b + skip (the guest's blocks of the shared kernel image have none).
pub const MEMD_GUEST_GIVE: u64 = 5;
/// MR0 = guest: revoke every block of its RAM, which deletes all that was
/// made of them (its frames and objects, vmmgr's frames of its boot
/// blocks), and free them.  A guest memd does not know is no error.
pub const MEMD_GUEST_DESTROY: u64 = 6;
/// MR0..MR5 = the free page reporting device (BalloonConfig), which
/// l4h-root has mapped: drive it.  Reply MR0 = 0, or ENODEV if it cannot
/// report.
pub const MEMD_BALLOON: u64 = 7;
/// MR0 = guest, MR1 = hotplug blocks: its target, clamped to its region.
pub const MEMD_SET_TARGET: u64 = 8;

/// From a guest's l4h-vmm (the guest is the badge's), DESIGN.md §8.5.  The
/// reply's MR0 is 0 or an errno: EINVAL, ENOSPC, EBUSY.
/// MR0 = m: plug hotplug block m, copying the Untypeds of its 64 blocks
/// into the guest's level-2 hotplug CNode in slot m of its hotplug CNode.
pub const MEMD_HP_PLUG: u64 = 16;
/// MR0 = m: revoke and free the blocks of hotplug block m.
pub const MEMD_HP_UNPLUG: u64 = 17;
/// Reply MR1 = target, MR2 = plugged, MR3.. = the plugged bitmap
/// (HP_MAP_WORDS words).
pub const MEMD_HP_STATE: u64 = 18;

/// Badge bit of a VMM's capability to memd's service endpoint; the low 16
/// bits are its guest.
pub const BADGE_VMM: u64 = 1 << 62;
/// l4h-vmmgr's badge.
pub const BADGE_VMMGR: u64 = 1 << 61;

/// Slot of the mailbox CNode memd shares with vmmgr: vmmgr's exchange
/// slots (MAILBOX_XCHG + i, as SLOT_XCHG + i is root's) and the guest
/// CNodes of MEMD_GUEST_CREATE.
pub const SLOT_MAILBOX: u64 = 16;
pub const MAILBOX_RADIX: usize = 6;
pub const MAILBOX_XCHG: u64 = 0;
pub const MAILBOX_BCN: u64 = XCHG_SLOTS as u64;
pub const MAILBOX_HCN: u64 = MAILBOX_BCN + 1;
const _: () = assert!(MAILBOX_HCN < 1 << MAILBOX_RADIX && SLOT_MAILBOX < SLOT_GUEST_BCN);
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

impl BalloonConfig {
    pub fn to_mrs(&self) -> [u64; 6] {
        [self.common, self.notify, self.device, self.notify_mult, self.dma_paddr, self.legacy_io]
    }

    pub fn from_mrs(m: [u64; 6]) -> Self {
        BalloonConfig { common: m[0], notify: m[1], device: m[2], notify_mult: m[3], dma_paddr: m[4], legacy_io: m[5] }
    }

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

/// Badge of memd's timer, on its bound notification.  l4h-root calls
/// with an unbadged capability.
pub const BADGE_TIMER: u64 = 1;

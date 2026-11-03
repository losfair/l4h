//! The multikernel partition descriptor and the memory shared between
//! partitions (DESIGN.md §11.4).
//!
//! `l4h-mkshim` boots several seL4 kernels on one x86_64 machine, one per
//! partition, and gives each partition's root task a [`Descriptor`] as the
//! boot module `l4h-partition`: which partition it is, the PCI functions it
//! owns, the clock rates and wall clock the shim measured, the console
//! ring its kernel prints to, its channels to other partitions and its
//! share of the IOMMU.  Without the module root runs as the only kernel on
//! the machine, as before.
//!
//! Everything here is `repr(C)`, fixed-size and little-endian; the shim
//! and root build from this one definition.

#![no_std]

/// `Descriptor::magic`.
pub const MAGIC: [u8; 8] = *b"L4HPART1";
/// `Descriptor::version`: bumped on any incompatible change.
pub const VERSION: u32 = 1;

/// Partitions on one machine, at most.
pub const MAX_PARTITIONS: usize = 8;
/// PCI functions of one partition, at most.  Partition 0 has every
/// function no other partition lists, bridges included.
pub const MAX_FUNCS: usize = 256;
/// Functions a partition reads but does not own, at most (`upstream`).
pub const MAX_UPSTREAM: usize = 64;
/// Channels of one partition, at most: one to each other partition.
pub const MAX_CHANNELS: usize = MAX_PARTITIONS - 1;

/// Each kernel's slot: kernel K is linked at `SLOT_BASE + K * SLOT_STRIDE`
/// (tools/build-kernel.sh, L4H_KERNEL_SLOT) and its root task image follows
/// it there.
/// Above 16 MiB: firmware keeps ranges below it (OVMF has ACPI NVS at 8 MiB),
/// and the slots end where the shim is loaded (272 MiB).
pub const SLOT_BASE: u64 = 16 << 20;
pub const SLOT_STRIDE: u64 = 32 << 20;

/// The page below 1 MiB where partition K's kernel starts its APs (and the
/// shim its first CPU): seL4's usual 0x1000 for partition 0.
pub const fn ap_boot_page(k: usize) -> u64 {
    0x1000 * (k as u64 + 1)
}

/// `Descriptor::flags`: this is partition 0, which owns the machine-global
/// devices (I/O APICs, serial port, RTC, reset, TPM, framebuffer).
pub const FLAG_PRIMARY: u32 = 1;

/// `Bar::flags`.
pub const BAR_IO: u32 = 1;
pub const BAR_64: u32 = 2;
pub const BAR_PREFETCH: u32 = 4;

/// A base address register, sized by the shim before any kernel ran.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Bar {
    pub addr: u64,
    /// 0: not implemented.
    pub size: u64,
    pub flags: u32,
    pub _pad: u32,
}

/// A PCI function of the partition (segment 0).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Func {
    /// bus << 8 | device << 3 | function.
    pub bdf: u16,
    /// Header type (0 endpoint, 1 bridge), without the multi-function bit.
    pub header: u8,
    pub _pad: u8,
    pub vendor: u16,
    pub device: u16,
    /// class << 16 | subclass << 8 | prog_if.
    pub class: u32,
    pub _pad2: u32,
    pub bars: [Bar; 6],
}

/// A ring in memory reserved from every partition's RAM.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Ring {
    pub paddr: u64,
    pub size: u64,
}

/// A channel between this partition and `peer`: `size` bytes at `paddr`,
/// two `MsgRing`s of `size / 2`, the first written by the partition with
/// the lower index.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Channel {
    pub paddr: u64,
    pub size: u64,
    pub peer: u32,
    /// CHANNEL_* bits: what the channel carries.
    pub kind: u32,
    /// The user vector (as for an MSI handler) this partition's doorbell
    /// arrives on.
    pub vector: u32,
    /// The peer's entry in this kernel's peers= list
    /// (seL4_IRQControl_SendPeer), and the vector to ring it on.
    pub peer_slot: u32,
    pub peer_vector: u32,
    pub _pad: u32,
}

/// `Channel::kind`: control traffic (heartbeat, console, clock, RTC,
/// TPM) between the primary and a secondary.
pub const CHANNEL_CONTROL: u32 = 1;
/// A virtual wire between the two partitions' netds (`link.pA-pB = 1` in
/// l4h-mk.conf): MSG_FRAME messages.
pub const CHANNEL_LINK: u32 = 2;

/// The IOMMU state shared by all partitions (DESIGN.md §11.4): `size`
/// bytes at `paddr`, laid out as the IOMMU_* constants say.  Of each
/// unit's domain IDs and interrupt remapping entries, this partition owns
/// part `share` of `shares` equal parts.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Iommu {
    pub paddr: u64,
    pub size: u64,
    pub share: u32,
    pub shares: u32,
    pub _pad: [u32; 2],
}

impl Iommu {
    /// This partition's part of `0..n`.
    pub fn part(&self, n: u32) -> core::ops::Range<u32> {
        let shares = self.shares.max(1);
        (n / shares * self.share)..(n / shares * (self.share + 1))
    }
}

/// One partition, as the primary sees the machine.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct PartInfo {
    pub boot_apic: u32,
    pub cpus: u32,
    pub mem_mib: u64,
    /// The partition's kernel console ring (none for the primary).
    pub console: Ring,
}

/// Which partition owns a PCI function (the primary's table).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Owner {
    pub bdf: u16,
    pub partition: u8,
    pub _pad: u8,
}

/// The descriptor, the boot module `l4h-partition`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Descriptor {
    pub magic: [u8; 8],
    pub version: u32,
    /// size_of::<Descriptor>().
    pub size: u32,
    pub index: u32,
    pub count: u32,
    pub flags: u32,
    /// APIC ID of the partition's first CPU, where MSIs go.
    pub boot_apic: u32,
    /// TSC and APIC timer rates the shim measured (also on the kernel's
    /// command line).
    pub tsc_khz: u64,
    pub apic_khz: u64,
    /// Wall clock at boot (ns since the epoch, 0 if unknown) and the TSC
    /// when the shim read it.
    pub epoch_ns: u64,
    pub epoch_tsc: u64,
    /// PCI ECAM (MCFG) for segment 0, buses [bus_start, bus_end].
    pub ecam_base: u64,
    pub ecam_bus_start: u8,
    pub ecam_bus_end: u8,
    pub _pad: [u8; 6],
    /// The lowest physical address of the partition's RAM.
    pub mem_base: u64,
    /// This partition's kernel console ring (none for the primary).
    pub console: Ring,
    pub iommu: Iommu,
    pub nchannels: u32,
    pub nfuncs: u32,
    pub nowners: u32,
    pub _pad2: u32,
    pub channels: [Channel; MAX_CHANNELS],
    /// The primary only: every partition.
    pub parts: [PartInfo; MAX_PARTITIONS],
    pub funcs: [Func; MAX_FUNCS],
    /// The primary only: the owner of every assigned function.
    pub owners: [Owner; MAX_PARTITIONS * MAX_FUNCS],
    pub nupstream: u32,
    pub _pad3: u32,
    /// Functions another partition owns whose configuration space this
    /// one may read, never write (bus << 8 | device << 3 | function): the
    /// bridges above its own functions, and function 0 of their devices,
    /// which say how its requester IDs reach an IOMMU and which IOMMU
    /// unit's device scope covers them; and the IOMMUs' own functions.
    pub upstream: [u16; MAX_UPSTREAM],
}

impl Descriptor {
    pub const fn zeroed() -> Self {
        // All fields are integers.
        unsafe { core::mem::zeroed() }
    }

    pub fn is_primary(&self) -> bool {
        self.flags & FLAG_PRIMARY != 0
    }

    /// The descriptor in `bytes` (a boot module), if it is one this build
    /// understands.
    pub fn from_bytes(bytes: &[u8]) -> Option<&Descriptor> {
        if bytes.len() < core::mem::size_of::<Descriptor>()
            || (bytes.as_ptr() as usize) % core::mem::align_of::<Descriptor>() != 0
        {
            return None;
        }
        let d = unsafe { &*(bytes.as_ptr() as *const Descriptor) };
        (d.magic == MAGIC && d.version == VERSION && d.size as usize == core::mem::size_of::<Descriptor>()
            && d.count as usize <= MAX_PARTITIONS && d.index < d.count
            && d.nchannels as usize <= MAX_CHANNELS && d.nfuncs as usize <= MAX_FUNCS
            && d.nowners as usize <= MAX_PARTITIONS * MAX_FUNCS && d.nupstream as usize <= MAX_UPSTREAM)
            .then_some(d)
    }

    pub fn funcs(&self) -> &[Func] {
        &self.funcs[..self.nfuncs as usize]
    }

    pub fn channels(&self) -> &[Channel] {
        &self.channels[..self.nchannels as usize]
    }

    pub fn owners(&self) -> &[Owner] {
        &self.owners[..self.nowners as usize]
    }

    pub fn upstream(&self) -> &[u16] {
        &self.upstream[..self.nupstream as usize]
    }

    pub fn parts(&self) -> &[PartInfo] {
        &self.parts[..self.count as usize]
    }
}

/// The kernel console ring (kernel patch 0035, console_ring=): a 64-byte
/// header whose first word counts the bytes ever written, then the bytes,
/// as a circle.  The reader keeps its own count and skips what the kernel
/// overwrote.
pub const CONSOLE_RING_HEADER: usize = 64;
pub const CONSOLE_RING_SIZE: u64 = 64 << 10;

/// Size of a channel: two message rings.
pub const CHANNEL_SIZE: u64 = 256 << 10;

/// The size of the shared IOMMU region.
pub const IOMMU_REGION_SIZE: u64 = 8 << 20;

/// Layout of the shared IOMMU region (DESIGN.md §11.4), from its start:
/// the control page; then for each unit (at most `IOMMU_MAX_UNITS`, in
/// DMAR/IVRS order) `IOMMU_UNIT_SIZE` bytes at `IOMMU_UNIT_BASE + unit *
/// IOMMU_UNIT_SIZE` for its command queue, event log, VT-d root table and
/// interrupt remapping table; then from `IOMMU_TABLES_BASE` to the end the
/// AMD device table (all units share one) or the VT-d context tables,
/// which the primary hands out in order.
pub const IOMMU_MAX_UNITS: usize = 16;
pub const IOMMU_UNIT_BASE: u64 = 64 << 10;
pub const IOMMU_UNIT_SIZE: u64 = 64 << 10;
pub const IOMMU_TABLES_BASE: u64 = 2 << 20;

/// The control page at the start of the shared IOMMU region.
#[repr(C)]
pub struct IommuControl {
    /// IOMMU_READY_* once the primary initialized the IOMMUs (or found
    /// none); 0 before.
    pub ready: core::sync::atomic::AtomicU32,
    /// The units the primary enabled, and whether it remaps interrupts
    /// (every partition must then send remappable MSIs).
    pub units: core::sync::atomic::AtomicU32,
    pub intremap: core::sync::atomic::AtomicU32,
    pub _pad: [u32; 13],
    pub locks: [IommuLock; IOMMU_MAX_UNITS],
}

pub const IOMMU_READY_ON: u32 = 1;
pub const IOMMU_READY_ABSENT: u32 = 2;
/// There is an IOMMU, but the primary does not confine DMA with it
/// (`iommu=0`, or it could not be used): neither does anyone else.
pub const IOMMU_READY_OFF: u32 = 3;

/// A ticket lock around one unit's command queue, in its own cache line.
#[repr(C, align(64))]
pub struct IommuLock {
    pub next: core::sync::atomic::AtomicU32,
    pub serving: core::sync::atomic::AtomicU32,
    /// The partition holding the lock, for a waiter that times out.
    pub holder: core::sync::atomic::AtomicU32,
    /// Completion word for the unit's wait descriptors (VT-d) or
    /// COMPLETION_WAIT (AMD), written by the IOMMU.
    pub done: core::sync::atomic::AtomicU64,
}

/// A message ring of a channel: one writer, one reader, both in the
/// header's partitions.  The writer never waits for the reader: a header
/// word counts the bytes ever written, and a reader that falls behind by
/// more than the ring loses messages (and knows it).  Messages are
/// `[u32 length][u32 type][payload]`, padded to 8 bytes; a message never
/// wraps: type 0 fills the rest of the ring instead.
pub const MSG_RING_HEADER: usize = 64;
pub const MSG_PAD: u32 = 0;

/// Message types on a control channel.
pub const MSG_HEARTBEAT: u32 = 1;
/// Secondary → primary: please set the RTC to payload u64 ns.
pub const MSG_RTC_SET: u32 = 2;
/// Primary → secondary: wall clock now, u64 ns and the TSC it was read at.
pub const MSG_CLOCK: u32 = 3;
/// Secondary → primary: a request for the primary's trustd
/// (payload: u64 id, then the request); the reply has the same id.
pub const MSG_TPM_REQUEST: u32 = 4;
pub const MSG_TPM_REPLY: u32 = 5;
/// A link channel's frames: the payload is one Ethernet frame.
pub const MSG_FRAME: u32 = 6;

const _: () = assert!(core::mem::size_of::<Func>() == 160);
const _: () = assert!(core::mem::size_of::<IommuControl>() <= 4096);
const _: () = assert!(IOMMU_UNIT_BASE + IOMMU_MAX_UNITS as u64 * IOMMU_UNIT_SIZE <= IOMMU_TABLES_BASE);
const _: () = assert!(IOMMU_TABLES_BASE + (2 << 20) <= IOMMU_REGION_SIZE);

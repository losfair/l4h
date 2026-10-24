//! Definitions shared by l4h-root and the host components it spawns
//! (l4h-vmm, blkd, netd, trustd, memd): the component address-space and CSpace layout,
//! the component info page, and the inter-component queue formats.

#![no_std]

pub mod blk;
pub mod fixed;
pub mod gpu;
pub mod iopool;
pub mod memd;
pub mod net;
pub mod trust;

/// Whether host components print informational messages.  Every print is a
/// synchronous serial write by the seL4 kernel, which stalls the core for
/// the whole message, so release builds (`L4H_RELEASE=1` when the host is
/// built) print critical errors only; informational messages use `info!`.
pub const VERBOSE: bool = match option_env!("L4H_RELEASE") {
    Some(v) => !matches!(v.as_bytes(), [b'1']),
    None => true,
};

/// Component address-space layout.
pub const INFO_VA: usize = 0x1000_0000;
pub const INFO_SIZE: usize = 0x4000;
pub const IPCBUF_VA: usize = 0x1001_0000;
/// The keeper's (has_keeper kinds).
pub const KEEPER_IPCBUF_VA: usize = IPCBUF_VA + 0x1000;
pub const STACK_TOP: usize = 0x1100_0000;
pub const STACK_SIZE: usize = 512 * 1024;
/// Shared regions (device pages, queues, buffers) are mapped from here.
pub const SHARED_VA: usize = 0x2000_0000_0000;
/// Device MMIO (drivers).
pub const MMIO_VA: usize = 0x3000_0000_0000;
/// DMA memory (drivers).
pub const DMA_VA: usize = 0x3800_0000_0000;
/// The guest's I/O pool (l4h-vmm): GPA g in the pool is mapped at
/// IO_POOL_VA + (g - io_pool_gpa).  l4h-vmm never maps guest RAM.
pub const IO_POOL_VA: usize = 0x4000_0000_0000;

/// Component CSpace: one CNode of 2^CNODE_BITS slots resolving the whole
/// CPtr, so a CPtr is simply a slot number.
pub const CNODE_BITS: usize = 12;
// blkd: every client's channel and "done" notification slot fit.
const _: () = assert!(blk::CHANNEL_VA + blk::MAX_CLIENTS * blk::CHANNEL_STRIDE <= MMIO_VA);
const _: () = assert!(blk::BLKD_SLOT_CLIENT_DONE as usize + blk::MAX_CLIENTS <= 1 << CNODE_BITS);
pub const SLOT_CNODE: u64 = 1;
pub const SLOT_VSPACE: u64 = 2;
pub const SLOT_TCB: u64 = 3;
/// Endpoint to l4h-root (badged with the component id).
pub const SLOT_ROOT_EP: u64 = 4;
/// Notification bound to the component's TCB.
pub const SLOT_NTFN: u64 = 5;
/// Endpoint the component serves (if any).
pub const SLOT_SERVICE_EP: u64 = 6;
/// Reply object for receiving on SLOT_SERVICE_EP.
pub const SLOT_REPLY: u64 = 7;
/// A keeper's thread (has_keeper kinds): it waits on SLOT_FAULT_EP, the
/// main thread's fault endpoint, and once the main thread has faulted
/// answers SLOT_SERVICE_EP for it.
pub const SLOT_KEEPER: u64 = 8;
pub const SLOT_FAULT_EP: u64 = 9;
/// The keeper's reply object for SLOT_FAULT_EP (never answered).
pub const SLOT_KEEPER_REPLY: u64 = 10;
/// First component-specific slot.
pub const SLOT_FIRST_FREE: u64 = 16;

pub const INFO_MAGIC: u64 = 0x4f464e4948344c00; // "\0L4HINFO"

pub const KIND_VMM: u32 = 1;
pub const KIND_BLKD: u32 = 2;
pub const KIND_NETD: u32 = 3;
pub const KIND_TRUSTD: u32 = 4;
pub const KIND_MEMD: u32 = 5;

/// The kinds l4h-root calls synchronously (blkd, netd, memd): root could
/// not wait for their faults to be reported, so a keeper thread answers
/// for a failed one.
pub const fn has_keeper(kind: u32) -> bool {
    matches!(kind, KIND_BLKD | KIND_NETD | KIND_MEMD)
}

/// Driver address-space layout: the device structures, then DMA memory.
pub const fn blkd_chan_va() -> usize {
    SHARED_VA
}

/// Header of the component info page at INFO_VA.  The kind-specific
/// configuration follows at `config`.
#[repr(C)]
pub struct InfoHeader {
    pub magic: u64,
    pub kind: u32,
    pub id: u32,
    pub tsc_hz: u64,
    pub reserved: [u64; 5],
}

pub const CONFIG_OFFSET: usize = 64;

/// Labels of calls from components to l4h-root (SLOT_ROOT_EP).
pub const ROOT_CALL_GUEST_POWER: u64 = 1; // MR0 = guest id, MR1 = abi POWER_*
pub const ROOT_CALL_LOG: u64 = 2;
/// l4h-vmm has initialised the device pages: start the guest (MR0 = guest id).
pub const ROOT_CALL_VMM_READY: u64 = 3;
/// dom0's l4h-vmm: execute the control request in dom0's control page.
pub const ROOT_CALL_CTL: u64 = 4;
/// trustd: a hardware access for the firmware's AML (trust::HW_*).
pub const ROOT_CALL_HW: u64 = 5;
/// trustd: it answered guest MR0's request; raise its device's event.
pub const ROOT_CALL_ATTEST_DONE: u64 = 6;

/// Badge bit set on every endpoint capability l4h-root gives to a guest
/// for l4h-vmm's service endpoint; notification badges never have it.
pub const VMM_BADGE_HYPERCALL: u64 = 1 << 63;

/// Per-guest l4h-vmm configuration.
pub const VMM_MAX_DEVICES: usize = 16;

/// Device kinds served by l4h-vmm.
pub const VDEV_CONSOLE: u32 = 0;
pub const VDEV_BLK: u32 = 1;
pub const VDEV_NET: u32 = 2;
pub const VDEV_CTL: u32 = 3;
/// virtio-gpu: chan_va is its display area (gpu::VMM_DISPLAY_VA, chan_size
/// bytes), its tables are at gpu::VMM_GPU_STATE_VA, and width and height
/// are its scanout's.
pub const VDEV_GPU: u32 = 4;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct VmmDevice {
    pub kind: u32,
    /// Index in the guest's boot info device table.
    pub guest_index: u32,
    /// Event line raised on the guest vCPU.
    pub event: u32,
    pub reserved0: u32,
    /// VA of the shared device page in the VMM.
    pub page_va: u64,
    /// Backend channel (VDEV_BLK / VDEV_NET): queue region VA and size,
    /// notification slot to kick the backend server.
    pub chan_va: u64,
    pub chan_size: u64,
    pub chan_kick_slot: u64,
    pub mac: [u8; 8],
    /// Block devices: capacity in 512-byte sectors, read-only flag.
    pub capacity: u64,
    pub read_only: u32,
    pub reserved1: u32,
    /// VDEV_GPU: the scanout's size in pixels.
    pub width: u32,
    pub height: u32,
}

#[repr(C)]
pub struct VmmConfig {
    pub guest_id: u32,
    pub nr_vcpus: u32,
    /// The guest's I/O pool (guest-physical range), mapped at IO_POOL_VA:
    /// every address a virtio device uses must lie in it.
    pub io_pool_gpa: u64,
    pub io_pool_size: u64,
    pub nr_devices: u32,
    pub reserved0: u32,
    /// Slot of the badged (L4H_BADGE_EVENT) notification of vCPU v is
    /// VCPU_NTFN_SLOT_BASE + v; its event page is at event_page_va(v).
    pub dom0: u32,
    /// Also copy console output to the host serial port (with a prefix
    /// unless dom0).
    pub serial: u32,
    pub devices: [VmmDevice; VMM_MAX_DEVICES],
    /// Wall clock (ns since the Unix epoch, 0 if unknown) at tick count
    /// epoch_ticks.
    pub epoch_ns: u64,
    pub epoch_ticks: u64,
}

pub const VCPU_NTFN_SLOT_BASE: u64 = 64;
pub const fn vmm_event_page_va(v: usize) -> usize {
    SHARED_VA + v * 0x1000
}
pub const fn vmm_device_page_va(d: usize) -> usize {
    SHARED_VA + 0x100_0000 + d * 0x1000
}
/// Console output ring of the guest, shared by l4h-vmm (writer) and
/// l4h-root (reader).
pub const VMM_CONSOLE_RING_VA: usize = SHARED_VA + 0x80_0000;
pub const CONSOLE_RING_PAGES: usize = 4;
pub const CONSOLE_RING_DATA: usize = CONSOLE_RING_PAGES * 4096 - 64;

#[repr(C)]
pub struct ConsoleRing {
    /// Total bytes ever written; byte i is at data[i % CONSOLE_RING_DATA].
    pub head: u64,
    pub reserved: [u64; 7],
    pub data: [u8; CONSOLE_RING_DATA],
}

pub const fn vmm_chan_va(d: usize) -> usize {
    SHARED_VA + 0x1000_0000 + d * 0x100_0000
}

/// Badges of the VMM's bound notification: bit d = kick from guest device d,
/// bit 32 + d = completion from the backend of device d.
pub const VMM_BADGE_KICK_SHIFT: u32 = 0;
pub const VMM_BADGE_DONE_SHIFT: u32 = 32;

/// The architectural time counter that seL4 deadlines (seL4_TCB_SetTimer)
/// are expressed in: the TSC on x86_64, the virtual counter on aarch64.
pub mod ticks {
    #[cfg(target_arch = "x86_64")]
    pub fn now() -> u64 {
        let lo: u32;
        let hi: u32;
        unsafe { core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack)) };
        ((hi as u64) << 32) | lo as u64
    }

    #[cfg(target_arch = "aarch64")]
    pub fn now() -> u64 {
        let v: u64;
        unsafe { core::arch::asm!("isb", "mrs {}, cntvct_el0", out(reg) v, options(nomem, nostack)) };
        v
    }

    /// Counter frequency, where the architecture defines a register for it.
    #[cfg(target_arch = "aarch64")]
    pub fn hz() -> u64 {
        let v: u64;
        unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) v, options(nomem, nostack)) };
        v
    }
}

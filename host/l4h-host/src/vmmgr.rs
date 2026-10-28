//! l4h-vmmgr, the guest manager (DESIGN.md §9.3): its CSpace, its
//! configuration, its calls to l4h-root, and the pages the two share.
//!
//! vmmgr builds guests and runs their lifecycle, schedules their vCPUs and
//! serves dom0's control API.  l4h-root keeps the hardware and the memory
//! devices reach: guests' I/O pools, disk channels and netd ports.  vmmgr
//! calls root (VMMGR_*), never the other way round: root tells it of
//! events through the events page and its notification.
//!
//! Capabilities cross in vmmgr's exchange slots, which root reaches through
//! the CNode it holds of vmmgr's (root dominates vmmgr).  Root empties a
//! slot before it puts a capability there, and takes none from vmmgr.  Root takes ids,
//! disk numbers, windows and sizes from vmmgr, and checks them against its
//! own tables, but never a physical address.

use crate::memd;

pub const VMMGR_ID: u32 = 0x500;

/// Radix of vmmgr's CNode, a single level (guard 64 - CNODE_BITS) like
/// root's own: every guest object has a slot in it.
pub const CNODE_BITS: usize = 18;

/// vmmgr's slots, after the standard ones (crate::SLOT_*).
///
/// memd's service endpoint, badged memd::BADGE_VMMGR.
pub const SLOT_MEMD_EP: u64 = 16;
/// The mailbox CNode it shares with memd (memd::MAILBOX_*).
pub const SLOT_MEMD_MAILBOX: u64 = 17;
/// trustd's flags service, badged trust::FLAGS_ROOT: ACT for the host
/// bits of the console.
pub const SLOT_FLAGS_EP: u64 = 18;
/// The CNode of the boot module frames root maps into vmmgr (radix
/// `VmmgrConfig::modules_radix`): frame i is page i of MODULES_VA.
pub const SLOT_MODULES: u64 = 19;
/// The CNode of dom0's control data area (CTL_DATA_PAGES frames): host
/// memory that root allocates once, mapped into every dom0.
pub const SLOT_CTL_DATA: u64 = 20;
/// Exchange slots: SLOT_XCHG + i.
pub const SLOT_XCHG: u64 = 32;
pub const XCHG_SLOTS: usize = 32;
/// SchedControl of core c: SLOT_SCHED_CONTROL + c.
pub const SLOT_SCHED_CONTROL: u64 = 64;
pub const MAX_CORES: usize = 64;
/// ASID pools: SLOT_ASID_POOL + i, `VmmgrConfig::asid_pools` of them.
pub const SLOT_ASID_POOL: u64 = SLOT_SCHED_CONTROL + MAX_CORES as u64;
pub const MAX_ASID_POOLS: usize = 8;
/// memd's endpoint for guest g's l4h-vmm (badged memd::BADGE_VMM | g),
/// which vmmgr copies into it: SLOT_VMM_MEMD_EP + g.
pub const SLOT_VMM_MEMD_EP: u64 = SLOT_ASID_POOL + MAX_ASID_POOLS as u64;
/// Shared log frames, also mapped into each guest's VMM.
pub const SLOT_LOG_FRAMES: u64 = SLOT_VMM_MEMD_EP + memd::MAX_GUESTS as u64;
/// vmmgr's own allocations start here.
pub const SLOT_DYN_BASE: u64 = 256;
const _: () = assert!(SLOT_LOG_FRAMES + crate::log::PAGES as u64 <= SLOT_DYN_BASE);
const _: () = assert!(SLOT_XCHG + XCHG_SLOTS as u64 <= SLOT_SCHED_CONTROL);

/// Pages of dom0's control data area.
pub const CTL_DATA_PAGES: usize = l4h_abi::CTL_LOAD_MAX as usize / 4096;
pub const CTL_DATA_RADIX: usize = CTL_DATA_PAGES.trailing_zeros() as usize;

/// Where root maps things into vmmgr, above its image and stacks.
///
/// The boot modules vmmgr loads from (guest kernel, module image, dom0's
/// initramfs), page after page.
pub const MODULES_VA: usize = 0x5000_0000_0000;
pub const MODULES_SIZE: usize = 64 << 30;
/// trustd's flags, read-only.
pub const FLAGS_VA: usize = 0x5100_0000_0000;
/// memd's status page, read-only.
pub const MEMD_STATUS_VA: usize = 0x5100_0010_0000;
/// The events page (`Events`), read-write: root sets, vmmgr clears.
pub const EVENTS_VA: usize = 0x5100_0020_0000;
/// The status page (`Status`): vmmgr writes, root reads.
pub const STATUS_VA: usize = 0x5100_0030_0000;
/// The result page: root writes a host op's data (`HOST_OP`), vmmgr
/// reads it.
pub const RESULT_VA: usize = 0x5100_0040_0000;
/// dom0's control data area, CTL_DATA_PAGES pages.
pub const CTL_DATA_VA: usize = 0x5100_0100_0000;

/// Badge of root's signals on vmmgr's bound notification: the events page
/// has news.
pub const BADGE_ROOT_EVENT: u64 = 1 << 42;

/// Calls from vmmgr to l4h-root, on its SLOT_ROOT_EP.  The reply's MR0 is
/// 0 or an errno, values follow.
///
/// MR0 = guest, MR1 = I/O pool bytes (a power of two), MR2 = its GPA, MR3
/// = dom0.  Root makes the pool and the guest's l4h-vmm notification,
/// which backends signal (root's, so that it is one).  Exchange slot 0 =
/// the CNode of the pool's frames (radix: the pool's pages), slot 3 = the
/// notification, and if the guest gets an attestation device, slot 1 its
/// page and slot 2 its kick capability (badged).  MR1 = the guest's
/// instance, MR2 = whether it has an attestation device.
pub const VMMGR_GUEST_NEW: u64 = 0x100;
/// MR0 = guest, stopped and torn down by vmmgr: drain its disks, remove
/// its ports, forget it in trustd, revoke its pool.  MR1 = bytes of pool
/// kept out of use (a disk could not be stopped).
pub const VMMGR_GUEST_DEL: u64 = 0x101;
/// MR0 = guest, MR1 = its device index, MR2 = host disk, MR3 = read-only,
/// MR4 = first sector, MR5 = sectors (0: to the end).  Exchange slots
/// [0, blk::CHANNEL_PAGES) = the channel frames, the next = blkd's kick.
pub const VMMGR_DISK_ATTACH: u64 = 0x102;
/// MR0 = guest, MR1 = its device index, MR2 = switch, MR3 = MAC (0:
/// choose), MR4 = MAC lock, MR5 = isolated.  Exchange slot 0 = the CNode
/// of the port's frames (radix PORT_RADIX), slot 1 = netd's kick.  MR1 =
/// the MAC.
pub const VMMGR_NIC_ADD: u64 = 0x103;
/// MR0 = guest, MR1 = its RAM bytes, MR2 = vCPUs, MR3 = trust::RECORD_*
/// flags, MR4..MR7 = its launch digest: it starts, its reports describe
/// it from now on.
pub const VMMGR_TRUST_REGISTER: u64 = 0x104;
/// MR0 = a control op that root serves (abi::CTL_*: host, disks,
/// switches, NICs), MR1..MR6 = its args.  MR1..MR6 of the reply = its
/// vals; its data is in the result page.  The data area of dom0's control
/// device is the source of CTL_BLK_WRITE.
pub const VMMGR_HOST_OP: u64 = 0x105;

/// Radix of the CNode of a netd port's frames.
pub const PORT_RADIX: usize = 10;

/// What root has for vmmgr, on the events page.
#[repr(C)]
pub struct Events {
    /// Bit g: trustd answered guest g, raise its attestation device's event.
    pub attest_done: core::sync::atomic::AtomicU64,
    /// A serial monitor command (MONITOR_*), 0 once vmmgr took it.
    pub monitor: core::sync::atomic::AtomicU64,
}

/// Monitor commands, (cmd << 32) | arg.
pub const MONITOR_DESTROY: u64 = 1;
pub const MONITOR_RESTART_DOM0: u64 = 2;

/// A guest as vmmgr reports it to root (for the dashboard and the
/// monitor), under a sequence count: odd while it is being written.
#[repr(C)]
pub struct GuestStatus {
    pub seq: core::sync::atomic::AtomicU32,
    /// 0: no guest; abi::VM_CREATED, VM_RUNNING or VM_STOPPED, plus one.
    pub state: u8,
    pub dom0: u8,
    pub vcpus: u8,
    pub cap_pct: u8,
    pub ram_mb: u32,
    /// CPU used in the last balancer period, permille of a core.
    pub cpu: u32,
    /// The cores of its first CORES vCPUs.
    pub cores: [u8; STATUS_CORES],
    pub name: [u8; l4h_abi::CTL_NAME_MAX],
}

pub const STATUS_CORES: usize = 8;

/// The status page.
#[repr(C)]
pub struct Status {
    pub guests: [GuestStatus; memd::MAX_GUESTS],
}
const _: () = assert!(core::mem::size_of::<Status>() <= 4096);

impl GuestStatus {
    /// A consistent copy of the fields, None while it is being written.
    pub fn read(&self) -> Option<GuestStatus> {
        use core::sync::atomic::{Ordering, fence};
        let seq = self.seq.load(Ordering::Acquire);
        if seq & 1 != 0 {
            return None;
        }
        let copy = unsafe { core::ptr::read_volatile(self) };
        fence(Ordering::Acquire);
        (self.seq.load(Ordering::Relaxed) == seq).then_some(copy)
    }
}

/// A boot module root mapped for vmmgr: at MODULES_VA + `offset`, `len`
/// bytes (len 0: none).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ModuleRange {
    pub offset: u64,
    pub len: u64,
}

/// One of dom0's disks: host disk `disk`, its first `sectors` (0: all).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Dom0Disk {
    pub disk: u64,
    pub sectors: u64,
}

/// One of dom0's vNICs: on `switch`, with MAC `mac` (0: choose).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Dom0Nic {
    pub switch: u64,
    pub mac: u64,
}

pub const DOM0_MAX_DISKS: usize = 16;
pub const DOM0_MAX_NICS: usize = 16;

/// vmmgr's configuration (its info page).
#[repr(C)]
pub struct VmmgrConfig {
    pub cores: u64,
    pub tsc_hz: u64,
    pub timeslice_us: u64,
    pub epoch_ns: u64,
    pub epoch_ticks: u64,
    pub cpu_id: [u64; 5],
    /// The topology (sched::topology::Topology): CPUs, each CPU's physical
    /// core, the placement order.
    pub topo_cpus: u64,
    pub topo_physical: [u8; MAX_CORES],
    pub topo_order: [u8; MAX_CORES],
    pub watchdog_secs: u64,
    /// trustd runs: its flags are at FLAGS_VA, SLOT_FLAGS_EP acts on them.
    pub trust: u64,
    /// ASID pools in its CSpace, and the ASIDs already used in each.
    pub asid_pools: u64,
    pub asids_used: [u64; MAX_ASID_POOLS],
    /// The CNode at SLOT_MODULES: its radix, and the pages mapped.
    pub modules_radix: u64,
    pub modules_pages: u64,
    pub kernel: ModuleRange,
    pub kmods: ModuleRange,
    pub dom0_initrd: ModuleRange,
    pub dom0_mem: u64,
    pub dom0_vcpus: u64,
    pub dom0_io_pool: u64,
    pub dom0_disks: u64,
    pub dom0_disk: [Dom0Disk; DOM0_MAX_DISKS],
    pub dom0_nics: u64,
    pub dom0_nic: [Dom0Nic; DOM0_MAX_NICS],
    pub dom0_cmdline: [u8; l4h_abi::CMDLINE_SIZE],
}
const _: () = assert!(crate::CONFIG_OFFSET + core::mem::size_of::<VmmgrConfig>() <= crate::INFO_SIZE);

//! l4h-vmmgr, the guest manager (DESIGN.md §10.3): its CSpace, its
//! configuration, its calls to l4h-root, and the pages the two share.
//!
//! vmmgr builds guests and runs their lifecycle, schedules their vCPUs and
//! serves dom0's control API.  l4h-root keeps the hardware and the memory
//! devices reach: guests' I/O pools, disk channels and netd ports.  vmmgr
//! calls root (crate::root::call), never the other way round: root posts
//! its notices in vmmgr's mailbox (`call`, from Sender::Root).
//!
//! Capabilities cross in vmmgr's exchange slots, which root reaches through
//! the CNode it holds of vmmgr's (root dominates vmmgr).  Root empties a
//! slot before it puts a capability there, and takes none from vmmgr.  Root takes ids,
//! disk numbers, windows and sizes from vmmgr, and checks them against its
//! own tables (a disk window against the disk's capacity; an extent list
//! is blkd's to read and check), but never a physical address.

use crate::memd;

pub const VMMGR_ID: u32 = 0x500;

/// Radix of vmmgr's CNode, a single level (guard 64 - CNODE_BITS) like
/// root's own: every guest object has a slot in it.
pub const CNODE_BITS: usize = 18;

/// vmmgr's slots, after the standard ones (crate::SLOT_*).
///
/// memd's service endpoint, badged as memd::Sender::Vmmgr.
pub const SLOT_MEMD_EP: u64 = 16;
/// Its exchange area with memd: the CNode the two share (memd::XCHG_RADIX).
pub const SLOT_MEMD_XCHG: u64 = 17;
/// trustd's flags service, badged as trust::Sender::Root: ACT for the host
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
/// memd's endpoint for guest g's l4h-vmm (badged as memd::Sender::Vmm(g)),
/// which vmmgr copies into it: SLOT_VMM_MEMD_EP + g.
pub const SLOT_VMM_MEMD_EP: u64 = SLOT_ASID_POOL + MAX_ASID_POOLS as u64;
/// The guests' VMMs' serial lanes, dom0's included (serial::VMM_PAGES
/// frames, from page 0 of serial::Lanes), each mapped into its VMM; in a
/// secondary partition, which has no lanes, the partition's serial ring
/// (serial::PAGES frames), mapped into every VMM.
pub const SLOT_SERIAL_FRAMES: u64 = 256;
const SERIAL_FRAMES: usize = if crate::serial::VMM_PAGES > crate::serial::PAGES { crate::serial::VMM_PAGES } else { crate::serial::PAGES };
/// The VMMs' log lanes (log::VMM_PAGES frames, from page 0 of the log
/// area), each mapped into its VMM.
pub const SLOT_LOG_FRAMES: u64 = SLOT_SERIAL_FRAMES + SERIAL_FRAMES as u64;
/// vmmgr's own allocations start here.
pub const SLOT_DYN_BASE: u64 = SLOT_LOG_FRAMES + crate::log::VMM_PAGES as u64;
const _: () = assert!(SLOT_VMM_MEMD_EP + memd::MAX_GUESTS as u64 <= SLOT_SERIAL_FRAMES);
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
/// The status page (`Status`): vmmgr writes, root reads.
pub const STATUS_VA: usize = 0x5100_0030_0000;
/// The result page: root writes a host op's data (`HOST_OP`), vmmgr
/// reads it.
pub const RESULT_VA: usize = 0x5100_0040_0000;
/// dom0's control data area, CTL_DATA_PAGES pages.
pub const CTL_DATA_VA: usize = 0x5100_0100_0000;


/// Requests root answers later (crate::root::Later), at most: tokens.
/// A driver that never answers leaves its token pending; the guest's
/// `guest_del` still answers ENOENT for it (and the token is free once
/// vmmgr has taken that and the driver has answered).  A disk controller holds at
/// most PENDING_PER_CTRL of them for requests blkd has not answered (EBUSY
/// past that), so drivers that never answer leave tokens for the others.
pub const MAX_PENDING: usize = 256;
pub const PENDING_PER_CTRL: usize = 2;

use crate::badges::vmmgr as recv;

crate::senders! {
    /// Who calls vmmgr: a guest's l4h-vmm, on its endpoint, badged with its
    /// guest (badges::vmmgr, COMPONENT | ID); l4h-root, in its mailbox
    /// (crate::mailbox), which root gives it.
    pub enum Sender in recv {
        Vmm(ID): [COMPONENT];
        Root: mailbox;
    }
}

crate::protocol! {
    /// The calls guests' l4h-vmms make on vmmgr's endpoint, whose guest is
    /// the badge's, and root's notices in vmmgr's mailbox, which root never
    /// waits on (a full ring keeps them in root until there is room).  A
    /// reply's first word is 0 or an errno; a caller vmmgr stops or
    /// destroys gets none.
    pub mod call (from: Sender) {
        /// The guest asks to power off, reboot or crash (abi::POWER_*).
        GuestPower / guest_power = 1 from [Vmm] (how: u64) -> ();
        /// The VMM has initialised the device pages: start the guest.
        VmmReady / vmm_ready = 3 from [Vmm] () -> ();
        /// Root has the answer of a request it answers later
        /// (crate::root::Later::Token): take it with root::call::result.
        OpDone / op_done = 0x10 from [Root] (token: usize) -> ();
        /// trustd answered guest `guest`: raise its attestation device's
        /// event.
        AttestDone / attest_done = 0x11 from [Root] (guest: usize) -> ();
        /// The serial monitor: destroy guest `guest`, which is not dom0.
        Destroy / destroy = 0x12 from [Root] (guest: usize) -> ();
        /// The serial monitor: restart dom0, or boot it if there is none.
        RestartDom0 / restart_dom0 = 0x13 from [Root] () -> ();
    }
}
const _: () = assert!(call::Request::MAX_WORDS <= crate::mailbox::ARGS
    && call::Request::MAX_REPLY_WORDS <= crate::mailbox::ANSWER);

/// Radix of the CNode of a USB controller's queue frames.
pub const USB_QUEUE_RADIX: usize = 7;

/// Radix of the CNode of a netd port's frames.
pub const PORT_RADIX: usize = 10;

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

/// One of dom0's disks: a window of host disk `disk` (sectors 0: to end).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Dom0Disk {
    pub disk: u64,
    pub start: u64,
    pub sectors: u64,
}

/// One of dom0's vNICs: on `switch`, with MAC `mac` (0: choose).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Dom0Nic {
    pub switch: u64,
    pub mac: u64,
}

pub const DOM0_MAX_DISKS: usize = crate::MAX_GUEST_DEVICES;
pub const DOM0_MAX_NICS: usize = crate::MAX_GUEST_DEVICES;

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
    /// The kernel makes VT-x objects: guests get EPT roots.
    pub vtx: u64,
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
    /// USB controllers (CTL_USB_INFO indices) every dom0 gets.
    pub dom0_usbs: u64,
    pub dom0_usb: [u64; crate::usb::MAX_GUEST_USB],
    pub dom0_cmdline: [u8; l4h_abi::CMDLINE_SIZE],
    /// SLOT_SERIAL_FRAMES holds the VMMs' serial lanes (partition 0), not
    /// the partition's ring.
    pub serial_lanes: u64,
}
const _: () = assert!(crate::CONFIG_OFFSET + core::mem::size_of::<VmmgrConfig>() <= crate::INFO_SIZE);

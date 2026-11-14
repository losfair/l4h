//! Rust mirror of `include/l4h/abi.h`, the l4h guest <-> host ABI.
//!
//! The C header is authoritative; the layout assertions at the bottom of
//! this file catch drift.

#![no_std]

pub const ABI_VERSION: u64 = 8;

pub const ROOT_CNODE_BITS: usize = 12;
pub const L2_INDEX_BITS: usize = 18;
pub const ROOT_GUARD_BITS: usize = 64 - ROOT_CNODE_BITS - L2_INDEX_BITS;

pub const fn cptr2(root: usize, idx: usize) -> u64 {
    ((root as u64) << L2_INDEX_BITS) | idx as u64
}
pub const fn cptr(root: usize) -> u64 {
    cptr2(root, 0)
}

pub const SLOT_META: usize = 1;
pub const CNODE_CPTR: u64 = cptr2(SLOT_META, 0);
pub const ROOT_DEPTH: usize = ROOT_GUARD_BITS + ROOT_CNODE_BITS;
pub const SLOT_VSPACE: usize = 2;
pub const SLOT_HYP_EP: usize = 3;
pub const SLOT_CONSOLE_KICK: usize = 5;


pub const SLOT_VCPU_BASE: usize = 64;
pub const VCPU_STRIDE: usize = 8;
pub const MAX_VCPUS: usize = 64;
pub const fn slot_vcpu(v: usize) -> usize {
    SLOT_VCPU_BASE + v * VCPU_STRIDE
}
pub const VCPU_KTCB: usize = 0;
pub const VCPU_EP: usize = 1;
pub const VCPU_NTFN: usize = 2;
pub const VCPU_SC_U: usize = 4;
pub const VCPU_IPI: usize = 5;
pub const VCPU_IPCBUF: usize = 6;
pub const VCPU_EVENT: usize = 7;

pub const BLOCK_SHIFT: usize = 21;
pub const BLOCK_SIZE: usize = 1 << BLOCK_SHIFT;
pub const RAM_L2_BITS: usize = 9;
pub const SLOT_RAM_L1_BASE: usize = 576;
pub const MAX_RAM_L1: usize = 64;
pub const MAX_BLOCKS: usize = MAX_RAM_L1 << RAM_L2_BITS;
pub const SLOT_BLOCKS: usize = 642;

pub const HP_SHIFT: usize = 27;
pub const HP_SIZE: usize = 1 << HP_SHIFT;
pub const HP_BITS: usize = HP_SHIFT - BLOCK_SHIFT;
pub const HP_BLOCKS: usize = 1 << HP_BITS;
pub const HP_L1_BITS: usize = 9;
pub const HP_MAX: usize = 1 << HP_L1_BITS;
pub const HP_L1_GUARD: usize = L2_INDEX_BITS - HP_L1_BITS - HP_BITS;
pub const SLOT_HP: usize = 643;
pub const GPA_END: usize = MAX_RAM_L1 << 30;

pub const SLOT_VSPACE_POOL: usize = 640;
pub const SLOT_DEV_CNODE: usize = 641;
pub const SLOT_EPT_POOL: usize = 644;
pub const MAX_EPT_ROOTS: usize = 8;
pub const SLOT_DYN_BASE: usize = 1024;

pub const SPECIAL_BASE: u64 = 0x0000_7ff0_0000_0000;
pub const BOOTINFO_VA: u64 = SPECIAL_BASE;
pub const BOOTINFO_SIZE: u64 = 0x4000;
pub const fn vcpu_area_va(v: usize) -> u64 {
    SPECIAL_BASE + 0x10_0000 + v as u64 * 0x4000
}
pub const fn vcpu_ipcbuf_va(v: usize) -> u64 {
    vcpu_area_va(v)
}
pub const fn vcpu_event_va(v: usize) -> u64 {
    vcpu_area_va(v) + 0x1000
}
pub const FPU_SCRATCH_OFFSET: usize = 1024;
pub const fn dev_area_va(d: usize) -> u64 {
    SPECIAL_BASE + 0x1000_0000 + d as u64 * 0x1_0000
}
pub const CTL_DATA_VA: u64 = SPECIAL_BASE + 0x2000_0000;
pub const KMOD_VA: u64 = SPECIAL_BASE + 0x3000_0000;
pub const KMOD_MAX: u64 = 0x1000_0000;
pub const SPECIAL_END: u64 = SPECIAL_BASE + 0x4000_0000;

pub const PRIO_KERNEL: u64 = 100;
pub const PRIO_USER: u64 = 99;

pub const BADGE_TIMER: u64 = 1 << 0;
pub const BADGE_IPI: u64 = 1 << 1;
pub const BADGE_EVENT: u64 = 1 << 2;
pub const EP_BADGE_TASK: u64 = 1 << 62;

pub const NR_EVENTS: usize = 512;

pub const CONSOLE_OUT_SIZE: usize = 3904;
pub const CONSOLE_OUT_WRAP: u32 = 2 * CONSOLE_OUT_SIZE as u32;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConsoleRec {
    pub seq: u32,
    pub len: u32,
}

#[repr(C)]
pub struct ConsoleOut {
    pub head: u32,
    pub tail: u32,
    pub lost: u32,
    pub want_space: u32,
    pub reserved: [u32; 12],
    pub data: [u8; CONSOLE_OUT_SIZE],
}

#[repr(C)]
pub struct EventPage {
    pub pending: [u64; NR_EVENTS / 64],
    pub steal_ns: u64,
    pub idle_ticks: u64,
    pub reserved: [u64; 6],
    pub console: ConsoleOut,
}

pub const BOOTINFO_MAGIC: u64 = 0x3154_4f4f_4248_344c;
pub const MAX_DEVICES: usize = 64;
pub const CMDLINE_SIZE: usize = 2048;

pub const DEV_NONE: u32 = 0;
pub const DEV_VIRTIO: u32 = 1;
pub const DEV_CONSOLE: u32 = 2;
pub const DEV_CTL: u32 = 3;
pub const DEV_ATTEST: u32 = 4;
pub const DEV_MEM: u32 = 5;
pub const DEV_USB: u32 = 6;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DevDesc {
    pub ty: u32,
    pub virtio_id: u32,
    pub page_va: u64,
    pub page_size: u64,
    pub event: u32,
    pub kick_slot: u32,
    pub data_va: u64,
    pub data_size: u64,
}


#[repr(C)]
pub struct BootInfo {
    pub magic: u64,
    pub abi_version: u64,
    pub guest_id: u64,
    pub ram_base_va: u64,
    pub ram_size: u64,
    pub kernel_end_gpa: u64,
    pub initrd_gpa: u64,
    pub initrd_size: u64,
    pub nr_vcpus: u64,
    pub tsc_hz: u64,
    pub nr_blocks: u64,
    pub nr_vspaces: u64,
    pub nr_devices: u64,
    pub flags: u64,
    pub io_pool_gpa: u64,
    pub io_pool_size: u64,
    pub boot_blocks: u64,
    pub cpu_id: [u64; 5],
    pub kmod_va: u64,
    pub kmod_size: u64,
    pub hp_gpa: u64,
    pub hp_count: u64,
    pub nr_ept_roots: u64,
    pub reserved: [u64; 5],
    pub devices: [DevDesc; MAX_DEVICES],
    pub cmdline: [u8; CMDLINE_SIZE],
}

pub const BOOT_DOM0: u64 = 1 << 0;

pub const VIRTIO_MAGIC: u32 = 0x7634_686c;
pub const VIRTIO_MAX_QUEUES: usize = 16;
pub const VIRTIO_QUEUE_IRQS: usize = 4;
pub const VIRTIO_QUEUE_EVENT_BASE: usize = 16 + MAX_DEVICES;
const _: () = assert!(VIRTIO_QUEUE_EVENT_BASE + MAX_DEVICES * VIRTIO_QUEUE_IRQS <= NR_EVENTS);
pub const VIRTIO_CONFIG_OFF: usize = 2048;
pub const VIRTIO_CONFIG_SIZE: usize = 2048;
pub const VIRTIO_ISR_VRING: u32 = 1;
pub const VIRTIO_ISR_CONFIG: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct VirtqRegs {
    pub num_max: u32,
    pub num: u32,
    pub ready: u32,
    pub reserved: u32,
    pub desc: u64,
    pub driver: u64,
    pub device: u64,
}

#[repr(C)]
pub struct VirtioRegs {
    pub magic: u32,
    pub version: u32,
    pub device_id: u32,
    pub vendor_id: u32,
    pub device_features: u64,
    pub driver_features: u64,
    pub status: u32,
    pub config_generation: u32,
    pub num_queues: u32,
    pub isr: u32,
    pub kick: u64,
    pub irq_vcpu: u32,
    pub queue_event_base: u32,
    pub queue_irq_vcpu: [u32; VIRTIO_QUEUE_IRQS],
    pub reserved: u64,
    pub queues: [VirtqRegs; VIRTIO_MAX_QUEUES],
}

pub const VIRTIO_OP_STATUS: u64 = 1;
pub const VIRTIO_OP_FEATURES: u64 = 2;
pub const VIRTIO_OP_QUEUE: u64 = 3;
pub const VIRTIO_OP_CONFIG: u64 = 4;
pub const VIRTIO_OP_IRQ_VCPU: u64 = 5;

pub const CONSOLE_IN_SIZE: usize = 4032;

#[repr(C)]
pub struct ConsolePage {
    pub in_head: u32,
    pub in_tail: u32,
    pub power_request: u32,
    pub reserved: [u32; 13],
    pub input: [u8; CONSOLE_IN_SIZE],
}


#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct MemPage {
    pub generation: u32,
    pub target: u32,
    pub plugged: u32,
    pub reserved0: u32,
    pub plugged_map: [u64; HP_MAX / 64],
    pub req_op: u32,
    pub req_block: u32,
    pub req_seq: u32,
    pub done_seq: u32,
    pub result: i64,
    pub reserved: [u64; 3],
}

pub const MEM_PLUG: u64 = 1;
pub const MEM_UNPLUG: u64 = 2;

/// Bump only for incompatible changes to existing ops (see abi.h).
pub const CTL_VERSION: u32 = 3;
pub const CTL_RESP_OFF: usize = 2048;
pub const CTL_SYNC_OFF: usize = 2040;
/// The seq of the last request the host has taken (a u32 it writes):
/// read it, and its data area, whether answered yet or not.
pub const CTL_TAKEN_OFF: usize = 4088;
const _: () = assert!(CTL_RESP_OFF + core::mem::size_of::<CtlResp>() <= CTL_TAKEN_OFF);
pub const CTL_DATA_MAX: usize = 1984;
pub const CTL_LOAD_MAX: u64 = 1 << 20;
pub const CTL_NAME_MAX: usize = 32;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CtlReq {
    pub op: u32,
    pub version: u32,
    pub args: [u64; 6],
    pub data: [u8; CTL_DATA_MAX],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CtlResp {
    pub status: i64,
    pub vals: [u64; 6],
    pub data: [u8; CTL_DATA_MAX],
}

#[repr(C)]
pub struct CtlSync {
    pub seq: u32,
    pub done: u32,
}

pub const CTL_HOST_INFO: u32 = 1;
pub const CTL_VM_CREATE: u32 = 2;
pub const CTL_VM_LOAD: u32 = 3;
pub const CTL_VM_START: u32 = 4;
pub const CTL_VM_DESTROY: u32 = 5;
pub const CTL_VM_LIST: u32 = 6;
pub const CTL_BLK_ATTACH: u32 = 7;
pub const CTL_CONSOLE_READ: u32 = 8;
pub const CTL_CONSOLE_WRITE: u32 = 9;
pub const CTL_DISK_INFO: u32 = 10;
pub const CTL_SWITCH_CREATE: u32 = 11;
pub const CTL_SWITCH_ATTACH_UPLINK: u32 = 12;
pub const CTL_NIC_CREATE: u32 = 13;
pub const CTL_SWITCH_INFO: u32 = 14;
pub const CTL_NIC_INFO: u32 = 15;
pub const CTL_VM_SET_SCHED: u32 = 16;
pub const CTL_VM_INFO: u32 = 17;
pub const CTL_VM_STATS: u32 = 18;
pub const CTL_VM_SHUTDOWN: u32 = 19;
pub const CTL_BLK_WRITE: u32 = 20;
pub const CTL_BLK_INFO: u32 = 21;
pub const CTL_HOST_REBOOT: u32 = 22;
pub const CTL_RTC_SET: u32 = 23;
pub const CTL_IOMMU_INFO: u32 = 24;
pub const CTL_HOST_VERSION: u32 = 25;
pub const CTL_GPU_ATTACH: u32 = 26;
pub const CTL_GPU_READ: u32 = 27;
pub const CTL_VM_SET_MEM: u32 = 28;
pub const CTL_VM_MEM_INFO: u32 = 29;
pub const CTL_VM_TRUST: u32 = 30;
pub const CTL_LOG_READ: u32 = 31;
pub const CTL_EP_SET: u32 = 32;
pub const CTL_EP_DEL: u32 = 33;
pub const CTL_EP_LIST: u32 = 34;
pub const CTL_STEER_SET: u32 = 35;
pub const CTL_STEER_DEL: u32 = 36;
pub const CTL_STEER_LIST: u32 = 37;
pub const CTL_PARTITION_INFO: u32 = 38;
pub const CTL_BLK_ATTACH_EXTENTS: u32 = 39;
pub const CTL_USB_INFO: u32 = 40;
pub const CTL_USB_ATTACH: u32 = 41;
pub const CTL_PCI_LIST: u32 = 42;
/// NIC drivers (DESIGN.md §9.8).  Bind NIC args[0] to the driver named by
/// args[1..3] (16 bytes, NUL padded; all zeros: the first that matches).
pub const CTL_NIC_BIND: u32 = 43;
pub const CTL_NIC_UNBIND: u32 = 44;
/// Stop NIC args[0]'s driver and start a fresh one.
pub const CTL_NIC_RESTART: u32 = 45;
/// A control message for NIC args[0]'s driver: args[2] bytes at args[1]
/// of the caller's control data area.  vals[0]: the answer's length,
/// which CTL_NIC_CTL_READ returns.
pub const CTL_NIC_CTL: u32 = 46;
pub const CTL_NIC_CTL_READ: u32 = 47;
/// Driver args[0] of the bundle: vals[0] = flags (DRIVER_BOOT) | class <<
/// 8 | matches << 16, data = name (16 bytes) then SHA-256 (32).
pub const CTL_DRIVER_INFO: u32 = 48;
/// Load a driver image: args[1] bytes at args[0] of the caller's control
/// data area.  vals[0]: its index.  Refused unless drivers are confined.
pub const CTL_DRIVER_LOAD: u32 = 49;
/// Test builds: make NIC args[0]'s driver panic (args[1] = 1) or hang (2).
pub const CTL_NIC_TEST: u32 = 50;
/// Firmware blob args[0] root has (all of them dom0's): vals[0] = its
/// length, data = its name (48 bytes, NUL padded) then SHA-256 (32).
pub const CTL_FIRMWARE_INFO: u32 = 51;
/// The args[0]th firmware name a bound NIC's driver asks for and root has
/// no blob of: data = the name (48 bytes, NUL padded).  ENOENT past them,
/// and for all where CTL_FIRMWARE_LOAD would be refused.
pub const CTL_FIRMWARE_WANTED: u32 = 52;
/// Load a firmware blob: args[1] bytes at args[0] of the caller's control
/// data area, its name (48 bytes, NUL padded) then its bytes.  vals[0]:
/// its index.  Refused unless drivers are confined; root restarts the
/// confined drivers that name it.
pub const CTL_FIRMWARE_LOAD: u32 = 53;
pub const FIRMWARE_NAME: usize = 48;
/// L3 filtering (DESIGN.md §9.3) of a port made with NIC_IP_FILTER:
/// args[0] port, [1] family (4, 6) | prefix length << 8, [2] and [3] the
/// address's bits 127-64 and 63-0 (IPv4 in bits 31-0), no bits set past
/// the length.  The port may send from the prefix (CTL_IP_ADD) or no
/// longer (CTL_IP_DEL).
pub const CTL_IP_ADD: u32 = 54;
pub const CTL_IP_DEL: u32 = 55;
/// args[0] port: vals[0] = count, vals[1] = 1 if the port is filtered;
/// data = CtlIp[count].
pub const CTL_IP_LIST: u32 = 56;
/// CTL_NIC_INFO: vals[0] BDF, [1] switch (u64::MAX: none), [2] MAC, [3]
/// state | trust << 8 | driver << 16 (0xff: none) | restarts << 32 |
/// isolation group size << 48, [4] vendor | device << 16, [5] the
/// driver's frames received | sent << 32 (low 32 bits each); data: the
/// driver's name, NUL, and why it last stopped.
pub const NIC_STATE_UNBOUND: u64 = 0;
pub const NIC_STATE_STARTING: u64 = 1;
pub const NIC_STATE_UP: u64 = 2;
pub const NIC_STATE_RESTARTING: u64 = 3;
pub const NIC_STATE_FAILED: u64 = 4;
/// Its driver runs outside the TCB (IOMMU, interrupt remapping, an
/// isolation group of its own), or is trusted.
pub const NIC_TRUST_CONFINED: u64 = 1;
pub const NIC_TRUST_TRUSTED: u64 = 2;
pub const DRIVER_BOOT: u64 = 1;
pub const PCI_OWNER_NONE: u16 = 0;
pub const PCI_OWNER_BLKD: u16 = 1;
pub const PCI_OWNER_NETD: u16 = 2;
pub const PCI_OWNER_MEMD: u16 = 3;
pub const PCI_OWNER_USBD: u16 = 4;
pub const PCI_OWNER_FIRMWARE: u16 = 5;
/// Root has disabled or quarantined the function; no active driver owns it.
pub const PCI_OWNER_ROOT: u16 = 6;
/// A NIC driver component (nicd).
pub const PCI_OWNER_NICD: u16 = 7;

/// A function from root's boot-time PCI inventory. No BARs, physical
/// addresses or configuration access. Subsystem IDs are zero if absent.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CtlPci {
    pub bdf: u16,
    pub vendor: u16,
    pub device: u16,
    pub subsystem_vendor: u16,
    pub subsystem_device: u16,
    pub class: u8,
    pub subclass: u8,
    pub prog_if: u8,
    pub revision: u8,
    pub owner: u16,
}
const _: () = assert!(core::mem::size_of::<CtlPci>() == 16);

pub const USB_STATE_FIRMWARE: u64 = 0;
pub const USB_STATE_IDLE: u64 = 1;
pub const USB_STATE_VM: u64 = 2;
pub const USB_STATE_FAILED: u64 = 3;
pub const USB_STATE_UNSUPPORTED: u64 = 4;
/// Extents of a disk made of them (CTL_BLK_ATTACH_EXTENTS), and the least
/// sectors of each when there are several.
pub const BLK_MAX_EXTENTS: u64 = 4096;
pub const BLK_MIN_EXTENT_SECTORS: u64 = 8192;
/// CTL_GPU_ATTACH: scanout sizes, and the I/O pool a VM with a GPU needs
/// (in images of its scanout).
pub const GPU_MIN: u32 = 64;
pub const GPU_MAX_WIDTH: u32 = 1920;
pub const GPU_MAX_HEIGHT: u32 = 1200;
pub const GPU_POOL_IMAGES: usize = 4;
/// CTL_IOMMU_INFO states: no IOMMU found (or none l4h drives), turned
/// off (`iommu=0`), confining devices, found but unusable.
pub const IOMMU_NONE: u64 = 0;
pub const IOMMU_OFF: u64 = 1;
pub const IOMMU_ON: u64 = 2;
pub const IOMMU_FAILED: u64 = 3;
pub const NIC_NO_MAC_LOCK: u64 = 1 << 0;
pub const NIC_ISOLATED: u64 = 1 << 1;
/// Send only IPv4, IPv6 and ARP from the addresses CTL_IP_ADD gives the
/// port (none at first), and no router advertisements or DHCP server
/// messages.  Not with NIC_NO_MAC_LOCK.
pub const NIC_IP_FILTER: u64 = 1 << 2;
/// CTL_BLK_ATTACH flags. A volatile attachment offers the guest no flush
/// and completes flushes at once: data the device caches can be lost on
/// power failure, for disks whose contents do not outlive the VM.
pub const BLK_RO: u64 = 1 << 0;
pub const BLK_VOLATILE: u64 = 1 << 1;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct CtlPort {
    pub vm: u32,
    pub port: u32,
    pub mac: u64,
    pub rx_frames: u64,
    pub tx_frames: u64,
    pub drops: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct CtlEp {
    pub id: u32,
    pub sw: u32,
    pub mac: u64,
    pub peer: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct CtlSteer {
    pub id: u32,
    pub ep: u32,
    pub matches: u64,
    pub ip_hi: u64,
    pub ip_lo: u64,
    pub targets: u64,
    pub in_frames: u64,
    pub out_frames: u64,
}

/// An address a filtered port may send from (CTL_IP_LIST): `prefix` and
/// the address as CTL_IP_ADD's args 1-3.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct CtlIp {
    pub prefix: u64,
    pub ip_hi: u64,
    pub ip_lo: u64,
}

pub const VM_CREATED: u32 = 1;
pub const VM_RUNNING: u32 = 2;
pub const VM_STOPPED: u32 = 3;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct CtlVm {
    pub id: u32,
    pub state: u32,
    pub vcpus: u32,
    pub reserved: u32,
    pub ram: u64,
    pub name: [u8; CTL_NAME_MAX],
}

pub const HC_POWER: u64 = 2;
pub const HC_DEV_WRITE: u64 = 3;
pub const HC_GET_TIME: u64 = 6;

pub const ATTEST_REPORT: u32 = 1;
pub const ATTEST_EVIDENCE: u32 = 2;
pub const ATTEST_ACTIVATE: u32 = 3;
pub const ATTEST_ACT: u32 = 4;
pub const ATTEST_SEAL: u32 = 5;
pub const FLAG_BITS: usize = 256;
pub const FLAG_HOST: usize = 0;
pub const FLAG_GUEST: usize = 64;
pub const FLAG_USER: usize = 128;
pub const FLAG_CONSOLE_IN: u64 = 1 << 0;
pub const FLAG_CONSOLE_OUT: u64 = 1 << 1;
pub const FLAGS_HOST_DEFINED: u64 = 3;
pub const ACT_SEAL: u32 = 1;
#[repr(C)]
pub struct AttestAct {
    pub bits: [u8; FLAG_BITS / 8],
    pub flags: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct AttestFlags {
    pub taint: [u8; FLAG_BITS / 8],
    pub seal: [u8; FLAG_BITS / 8],
}
pub const ATTEST_DATA_SIZE: usize = 64;
pub const ATTEST_FAILED: u32 = 1;
pub const ATTEST_NO_REPORTS: u32 = 2;
pub const ATTEST_PAGE_DATA: usize = 4096 - 64;

#[repr(C)]
pub struct AttestPage {
    pub seq: u32,
    pub op: u32,
    pub offset: u32,
    pub in_len: u32,
    pub blob_len: u32,
    pub done: u32,
    pub status: i32,
    pub total: u32,
    pub out_len: u32,
    pub state: u32,
    pub reserved: [u32; 6],
    pub data: [u8; ATTEST_PAGE_DATA],
}

pub const POWER_OFF: u64 = 0;
pub const POWER_REBOOT: u64 = 1;
pub const POWER_CRASH: u64 = 2;

const _: () = assert!(core::mem::size_of::<EventPage>() == 4096);
const _: () = assert!(core::mem::size_of::<AttestPage>() == 4096);
const _: () = assert!(core::mem::size_of::<AttestAct>() == 36);
const _: () = assert!(core::mem::size_of::<AttestFlags>() == 64);
const _: () = assert!(core::mem::size_of::<DevDesc>() == 48);
const _: () = assert!(
    core::mem::size_of::<BootInfo>()
        == 32 * 8 + MAX_DEVICES * 48 + CMDLINE_SIZE

);
const _: () = assert!(core::mem::size_of::<BootInfo>() as u64 <= BOOTINFO_SIZE);
const _: () = assert!(core::mem::size_of::<VirtioRegs>() == 88 + 16 * 40);
const _: () = assert!(core::mem::size_of::<VirtioRegs>() <= VIRTIO_CONFIG_OFF);
const _: () = assert!(core::mem::size_of::<ConsolePage>() == 4096);
const _: () = assert!(core::mem::size_of::<CtlReq>() <= CTL_SYNC_OFF);
const _: () = assert!(CTL_SYNC_OFF + core::mem::size_of::<CtlSync>() <= CTL_RESP_OFF);
const _: () = assert!(CTL_RESP_OFF + core::mem::size_of::<CtlResp>() <= 4096);
const _: () = assert!(core::mem::size_of::<CtlVm>() == 56);
const _: () = assert!(core::mem::size_of::<MemPage>() == 128);
const _: () = assert!(HP_L1_GUARD == 3 && MAX_RAM_L1 << 30 >> HP_SHIFT == HP_MAX);

/// USB host controllers (L4H_DEV_USB): the queue area shared by the guest
/// and l4h-usbd.
pub mod usb {
    use super::SPECIAL_BASE;

    pub const MAX_GUEST_USB: usize = 4;
    pub const fn area_va(n: usize) -> u64 {
        SPECIAL_BASE + 0x2800_0000 + n as u64 * 0x10_0000
    }
    pub const AREA_PAGES: usize = 101;
    pub const MAGIC: u32 = 0x6273_756c;
    pub const VERSION: u32 = 1;

    pub const CTL_SQ_SIZE: usize = 32;
    pub const XFER_SQ_SIZE: usize = 128;
    pub const CQ_SIZE: usize = 256;
    pub const EQ_SIZE: usize = 64;
    pub const CTL_SQ_OFF: usize = 0x2000;
    pub const XFER_SQ_OFF: usize = 0x4000;
    pub const CQ_OFF: usize = 0x44000;
    pub const EQ_OFF: usize = 0x64000;
    pub const MAX_SEGS: usize = 64;
    pub const MAX_ISO: usize = 48;
    pub const MAX_PORTS: usize = 255;
    pub const MAX_STREAMS: u32 = 16;

    pub const F_ISOCH: u32 = 1 << 0;
    pub const F_STREAMS: u32 = 1 << 1;
    pub const F_CSZ: u32 = 1 << 2;

    pub const READY: u32 = 1;
    pub const RESETTING: u32 = 2;
    pub const DEAD: u32 = 3;

    #[repr(C)]
    pub struct Index {
        pub v: u32,
        pub pad: [u32; 15],
    }

    #[repr(C)]
    pub struct Info {
        pub magic: u32,
        pub version: u32,
        pub features: u32,
        pub state: u32,
        pub max_slots: u32,
        pub max_ports: u32,
        pub usb2_ports: u32,
        pub usb3_ports: u32,
        pub max_streams: u32,
        pub max_transfer: u32,
        pub hci_version: u32,
        pub reset_done: u32,
        /// MFINDEX (bits 0..13) as usbd last read it, and a sequence
        /// (bits 14..31) that is odd while usbd updates it with mf_ticks.
        pub mfindex: u32,
        pub hc_resets: u32,
        /// The host counter (TSC, CNTVCT) when MFINDEX was read; 0: the
        /// controller is not running.
        pub mf_ticks: u64,
        pub usbd_waiting: Index,
        pub ctl_sq_tail: Index,
        pub xfer_sq_tail: Index,
        pub cq_head: Index,
        pub eq_head: Index,
        pub lost_events: Index,
        pub port_proto: [u8; MAX_PORTS + 1],
    }

    #[repr(C)]
    pub struct Ctrl {
        pub ctl_sq_head: Index,
        pub xfer_sq_head: Index,
        pub cq_tail: Index,
        pub eq_tail: Index,
        pub reset_seq: Index,
    }

    pub const OP_PORT_GET: u32 = 1;
    pub const OP_PORT_SET: u32 = 2;
    pub const OP_PORT_CLEAR: u32 = 3;
    pub const OP_SLOT_ENABLE: u32 = 4;
    pub const OP_SLOT_DISABLE: u32 = 5;
    pub const OP_ADDRESS: u32 = 6;
    pub const OP_EP_CONFIG: u32 = 7;
    pub const OP_HUB_CONFIG: u32 = 8;
    pub const OP_EP0_MPS: u32 = 9;
    pub const OP_DEV_RESET: u32 = 10;
    pub const OP_EP_RESET: u32 = 11;
    pub const OP_STREAMS_ALLOC: u32 = 12;
    pub const OP_STREAMS_FREE: u32 = 13;
    pub const OP_URB_CANCEL: u32 = 14;

    pub const PF_POWER: u32 = 1;
    pub const PF_RESET: u32 = 2;
    pub const PF_WARM_RESET: u32 = 3;
    pub const PF_LINK_STATE: u32 = 4;
    pub const PF_ENABLE: u32 = 5;
    pub const PF_WAKE: u32 = 6;
    pub const PF_CHANGE: u32 = 7;

    pub const SPEED_FULL: u32 = 1;
    pub const SPEED_LOW: u32 = 2;
    pub const SPEED_HIGH: u32 = 3;
    pub const SPEED_SUPER: u32 = 4;
    pub const SPEED_SUPER_PLUS: u32 = 5;

    pub const EP_ISOC_OUT: u8 = 1;
    pub const EP_BULK_OUT: u8 = 2;
    pub const EP_INT_OUT: u8 = 3;
    pub const EP_CONTROL: u8 = 4;
    pub const EP_ISOC_IN: u8 = 5;
    pub const EP_BULK_IN: u8 = 6;
    pub const EP_INT_IN: u8 = 7;

    #[repr(C)]
    #[derive(Clone, Copy, Default, Debug)]
    pub struct Ep {
        pub dci: u8,
        pub ty: u8,
        pub interval: u8,
        pub burst_mult: u8,
        pub max_packet: u16,
        pub max_esit: u16,
    }

    pub const CTL_EPS: usize = 30;

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub union CtlBody {
        pub eps: [Ep; CTL_EPS],
        pub arg: [u32; 60],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct CtlReq {
        pub op: u32,
        pub tag: u32,
        pub slot: u16,
        pub port: u8,
        pub n_eps: u8,
        pub drop: u32,
        pub body: CtlBody,
    }

    pub const XFER_CONTROL: u8 = 0;
    pub const XFER_BULK: u8 = 1;
    pub const XFER_INT: u8 = 2;
    pub const XFER_ISOC: u8 = 3;

    pub const XF_IN: u32 = 1 << 0;
    pub const XF_ZERO_PACKET: u32 = 1 << 1;
    pub const XF_SHORT_NOT_OK: u32 = 1 << 2;
    pub const XF_ISO_ASAP: u32 = 1 << 3;

    #[repr(C)]
    #[derive(Clone, Copy, Default, Debug)]
    pub struct Seg {
        pub gpa: u64,
        pub len: u32,
        pub reserved: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default, Debug)]
    pub struct Iso {
        pub offset: u32,
        pub len: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct XferReq {
        pub tag: u32,
        pub slot: u16,
        pub dci: u8,
        pub ty: u8,
        pub flags: u32,
        pub stream: u32,
        /// Ignored: usbd schedules isoch URBs (Cqe::start_frame).
        pub start_frame: u32,
        pub length: u32,
        pub n_segs: u16,
        pub n_iso: u16,
        pub reserved0: u32,
        pub setup: [u8; 8],
        pub reserved: [u32; 6],
        pub segs: [Seg; MAX_SEGS],
        pub iso: [Iso; MAX_ISO],
        pub pad: [u8; 2048 - 64 - 16 * MAX_SEGS - 8 * MAX_ISO],
    }

    pub const ST_OK: i32 = 0;
    pub const ST_INVALID: i32 = -22;
    pub const ST_NODEV: i32 = -19;
    pub const ST_STALL: i32 = -32;
    pub const ST_PROTO: i32 = -71;
    pub const ST_BABBLE: i32 = -75;
    pub const ST_SHORT: i32 = -121;
    pub const ST_CANCELLED: i32 = -104;
    pub const ST_SHUTDOWN: i32 = -108;
    pub const ST_TIMEOUT: i32 = -62;
    pub const ST_MISSED: i32 = -18;
    pub const ST_NOSPC: i32 = -28;
    pub const ST_IO: i32 = -5;
    /// URB_CANCEL of an URB still in the transfer SQ: usbd skips its
    /// record and never completes it (the guest gives it back).
    pub const ST_DROPPED: i32 = -125;

    pub const CQ_CTL: u32 = 1;
    pub const CQ_XFER: u32 = 2;

    #[repr(C)]
    #[derive(Clone, Copy, Default, Debug)]
    pub struct IsoStatus {
        pub status: i32,
        pub actual: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct Cqe {
        pub tag: u32,
        pub kind: u32,
        pub status: i32,
        pub actual: u32,
        /// Isoch: where usbd scheduled it (frames below high speed,
        /// microframes from it, as Linux's xHCI driver).
        pub start_frame: u32,
        pub error_count: u32,
        pub n_iso: u32,
        pub val: [u32; 2],
        pub reserved: [u32; 7],
        pub iso: [IsoStatus; MAX_ISO],
        pub pad: [u8; 512 - 64 - 8 * MAX_ISO],
    }

    pub const EV_PORT: u32 = 1;
    pub const EV_HC_RESET: u32 = 2;

    #[repr(C)]
    #[derive(Clone, Copy, Default, Debug)]
    pub struct Event {
        pub ty: u32,
        pub port: u32,
        pub portsc: u32,
        pub reserved: [u32; 5],
    }

    pub const DEVOP_IRQ_VCPU: u64 = 5;

    const _: () = assert!(core::mem::size_of::<Info>() <= 4096);
    const _: () = assert!(core::mem::offset_of!(Info, mf_ticks) == 56 && core::mem::offset_of!(Info, usbd_waiting) == 64);
    const _: () = assert!(core::mem::size_of::<Ctrl>() <= 4096);
    const _: () = assert!(core::mem::size_of::<Ep>() == 8);
    const _: () = assert!(core::mem::size_of::<CtlReq>() == 256);
    const _: () = assert!(core::mem::size_of::<XferReq>() == 2048);
    const _: () = assert!(core::mem::size_of::<Cqe>() == 512);
    const _: () = assert!(core::mem::size_of::<Event>() == 32);
    const _: () = assert!(CTL_SQ_OFF + CTL_SQ_SIZE * 256 == XFER_SQ_OFF);
    const _: () = assert!(XFER_SQ_OFF + XFER_SQ_SIZE * 2048 == CQ_OFF);
    const _: () = assert!(CQ_OFF + CQ_SIZE * 512 == EQ_OFF);
    const _: () = assert!(EQ_OFF + EQ_SIZE * 32 <= AREA_PAGES * 4096);
    const _: () = assert!(area_va(MAX_GUEST_USB) <= super::KMOD_VA);
    const _: () = assert!(core::mem::offset_of!(XferReq, segs) == 64);
    const _: () = assert!(core::mem::offset_of!(Cqe, iso) == 64);
    const _: () = assert!(core::mem::offset_of!(Info, usbd_waiting) == 64);
}

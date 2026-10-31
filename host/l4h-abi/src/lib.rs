//! Rust mirror of `include/l4h/abi.h`, the l4h guest <-> host ABI.
//!
//! The C header is authoritative; the layout assertions at the bottom of
//! this file catch drift.

#![no_std]

pub const ABI_VERSION: u64 = 6;

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
pub const FPU_SCRATCH_OFFSET: usize = 2048;
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
    pub reserved: [u64; 6],
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

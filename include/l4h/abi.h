/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * l4h guest <-> host ABI.
 *
 * This header is the single source of truth for the contract between
 * l4h-root / l4h-vmm and a paravirtualised guest kernel (ARCH=l4h). It is
 * included by the guest kernel and mirrored by host/l4h-abi (Rust).
 * Everything is fixed-width and little-endian; layouts must not depend on
 * the ISA.  See DESIGN.md §5.
 */
#ifndef L4H_ABI_H
#define L4H_ABI_H

#ifdef __KERNEL__
#include <linux/types.h>
typedef __u8 l4h_u8;
typedef __u16 l4h_u16;
typedef __u32 l4h_u32;
typedef __u64 l4h_u64;
typedef __s32 l4h_s32;
typedef __s64 l4h_s64;
#else
#include <stdint.h>
typedef uint8_t l4h_u8;
typedef uint16_t l4h_u16;
typedef uint32_t l4h_u32;
typedef uint64_t l4h_u64;
typedef int32_t l4h_s32;
typedef int64_t l4h_s64;
#endif

#define L4H_ABI_VERSION 4

/* ------------------------------------------------------------------------
 * Guest CSpace layout
 *
 * The guest's root CNode has 2^12 slots and a guard that makes it resolve
 * the top 46 bits of a CPtr (guard 34 bits of zero + 12 bits radix).  The
 * remaining 18 bits index second-level CNodes: host-created ones have
 * radix 18, guest-created ones must have radix + guard == 18.
 */
#define L4H_ROOT_CNODE_BITS     12
#define L4H_L2_INDEX_BITS       18
#define L4H_ROOT_GUARD_BITS     (64 - L4H_ROOT_CNODE_BITS - L4H_L2_INDEX_BITS)

/* In CNode operations with root = L4H_CNODE_CPTR, a slot of the root CNode
 * is addressed as (index = slot number, depth = L4H_ROOT_DEPTH), and a slot
 * of a second-level CNode as (index = L4H_CPTR2(root, idx), depth = 64). */
#define L4H_ROOT_DEPTH          (L4H_ROOT_GUARD_BITS + L4H_ROOT_CNODE_BITS)

/* CPtr of slot `idx` of the second-level CNode in root slot `root`. */
#define L4H_CPTR2(root, idx)    ((((l4h_u64)(root)) << L4H_L2_INDEX_BITS) | (l4h_u64)(idx))
/* CPtr of a capability held directly in root slot `root`. */
#define L4H_CPTR(root)          L4H_CPTR2(root, 0)

/* Root slot 1 holds a small "meta" CNode (radix 12, guard 6) whose slot 0
 * is a capability to the guest root CNode itself (with the 34-bit guard),
 * so that the root CNode can be named by a CPtr: L4H_CNODE_CPTR.  (A CNode
 * capability held directly in a root slot cannot be invoked, because seL4
 * keeps resolving through it.) */
#define L4H_SLOT_META           1
#define L4H_CNODE_CPTR          L4H_CPTR2(L4H_SLOT_META, 0)
/* Meta CNode slots [1, 4096) are free for the guest: any CNode capability
 * that must be named by a CPtr (e.g. the CSpace of a user thread) has to be
 * kept here, at L4H_CPTR2(L4H_SLOT_META, i). */
#define L4H_META_DYN_BASE       1
#define L4H_SLOT_VSPACE         2   /* guest-kernel VSpace root */
#define L4H_SLOT_HYP_EP         3   /* Call: hypercalls served by l4h-vmm */
#define L4H_SLOT_ASID_POOL      4   /* reserved */


/* Per-vCPU objects: root slots L4H_SLOT_VCPU(v) + L4H_VCPU_* */
#define L4H_SLOT_VCPU_BASE      64
#define L4H_VCPU_STRIDE         8
#define L4H_MAX_VCPUS           64
#define L4H_SLOT_VCPU(v)        (L4H_SLOT_VCPU_BASE + (v) * L4H_VCPU_STRIDE)
#define L4H_VCPU_KTCB           0   /* kernel-context TCB */
#define L4H_VCPU_EP             1   /* fault/IPC endpoint (receive side) */
#define L4H_VCPU_NTFN           2   /* notification bound to the kTCB */
#define L4H_VCPU_SC_U           4   /* scheduling context for user threads */
#define L4H_VCPU_IPI            5   /* N_v, badged L4H_BADGE_IPI (send only) */
#define L4H_VCPU_IPCBUF         6   /* frame: kTCB IPC buffer (+FPU scratch) */
#define L4H_VCPU_EVENT          7   /* frame: event page */

/* Guest RAM is a list of 2 MiB blocks; block b covers GPA
 * [b * L4H_BLOCK_SIZE, (b + 1) * L4H_BLOCK_SIZE).  See DESIGN.md §15.2.
 *
 * Boot blocks, [0, bootinfo.boot_blocks), hold the kernel image and initrd:
 * the host retyped them into frames and mapped them in the direct map, and
 * the guest has no Untyped for them.  For every other block, slot b of the
 * block CNode (root slot L4H_SLOT_BLOCKS) holds a copy of its 2 MiB Untyped:
 * the guest retypes it into frames or into seL4 objects, as it likes.
 *
 * Frames are named through two levels of RAM CNodes.  Root slot
 * L4H_SLOT_RAM_L1_BASE + n is a level-1 CNode (radix 9, no guard) for GPA
 * [n GiB, n+1 GiB); its slot j holds the level-2 CNode (radix 9) of block
 * 512 n + j, whose slot k holds the frame of the block's page k.  The host
 * fills the level-1 slots of boot blocks; the guest retypes level-2 CNodes
 * into the others. */
#define L4H_BLOCK_SHIFT         21
#define L4H_BLOCK_SIZE          (1ull << L4H_BLOCK_SHIFT)
#define L4H_RAM_L2_BITS         9   /* frames of a block: 2^9 */
#define L4H_SLOT_RAM_L1_BASE    576
#define L4H_MAX_RAM_L1          64
#define L4H_MAX_BLOCKS          (L4H_MAX_RAM_L1 << L4H_RAM_L2_BITS)
#define L4H_FRAME_CPTR(gpa)                                             \
	L4H_CPTR2(L4H_SLOT_RAM_L1_BASE + ((gpa) >> 30),                     \
		  ((gpa) >> 12) & ((1u << L4H_L2_INDEX_BITS) - 1))
#define L4H_SLOT_BLOCKS         642
#define L4H_BLOCK_CPTR(b)       L4H_CPTR2(L4H_SLOT_BLOCKS, b)

/* A CNode with bootinfo.nr_vspaces pre-assigned (ASID-bearing) VSpace
 * roots that the guest uses for its processes. */
#define L4H_SLOT_VSPACE_POOL    640
/* A CNode with device capabilities (indices from l4h_dev_desc). */
#define L4H_SLOT_DEV_CNODE      641

/* Root slots [L4H_SLOT_DYN_BASE, 4096) are free for the guest. */
#define L4H_SLOT_DYN_BASE       1024

/* ------------------------------------------------------------------------
 * Guest-kernel VSpace layout
 *
 * Guest RAM is mapped at bootinfo.ram_base_va: GPA g <-> VA ram_base_va + g.
 * The guest kernel ELF (the one l4h ships: guests do not bring their own)
 * is linked so that its first loadable segment starts at ram_base_va
 * (GPA 0).  The I/O pool follows RAM in the same direct map
 * (bootinfo.io_pool_gpa).  Host-provided pages live in the special region.
 */
#define L4H_SPECIAL_BASE        0x00007ff000000000ull
#define L4H_BOOTINFO_VA         L4H_SPECIAL_BASE
#define L4H_BOOTINFO_SIZE       0x4000ull
#define L4H_VCPU_AREA_VA(v)     (L4H_SPECIAL_BASE + 0x100000ull + (l4h_u64)(v) * 0x4000ull)
#define L4H_VCPU_IPCBUF_VA(v)   (L4H_VCPU_AREA_VA(v) + 0x0000)
#define L4H_VCPU_EVENT_VA(v)    (L4H_VCPU_AREA_VA(v) + 0x1000)
/* FPU transfers (seL4_TCB_ReadFPU/WriteFPU) use this offset in IPCBUF. */
#define L4H_FPU_SCRATCH_OFFSET  2048
#define L4H_DEV_AREA_VA(d)      (L4H_SPECIAL_BASE + 0x10000000ull + (l4h_u64)(d) * 0x10000ull)
/* Bulk data area of the control device (dom0 only, L4H_CTL_LOAD_MAX). */
#define L4H_CTL_DATA_VA         (L4H_SPECIAL_BASE + 0x20000000ull)
/* The kernel's modules and module build tree, read-only (bootinfo.kmod_size
 * bytes, at most L4H_KMOD_MAX). */
#define L4H_KMOD_VA             (L4H_SPECIAL_BASE + 0x30000000ull)
#define L4H_KMOD_MAX            0x10000000ull
/* First VA above the special region that the guest may never use. */
#define L4H_SPECIAL_END         (L4H_SPECIAL_BASE + 0x40000000ull)

/* ------------------------------------------------------------------------
 * Scheduling
 */
#define L4H_PRIO_KERNEL         100 /* kTCB priority and MCP */
#define L4H_PRIO_USER           99  /* priority of guest user threads */

/* ------------------------------------------------------------------------
 * Notification badges on N_v (bound to the vCPU's kTCB).  Endpoint badges
 * on EP_v (user-thread faults) always have L4H_EP_BADGE_TASK set, so a
 * badge received by seL4_Recv(EP_v) is unambiguous.
 */
#define L4H_BADGE_TIMER         (1ull << 0)  /* seL4_TCB_SetTimer expiry */
#define L4H_BADGE_IPI           (1ull << 1)  /* another vCPU kicked us */
#define L4H_BADGE_EVENT         (1ull << 2)  /* event page has pending bits */
#define L4H_EP_BADGE_TASK       (1ull << 62)

/* ------------------------------------------------------------------------
 * Event page (one per vCPU, shared with l4h-vmm).  Senders set bits with an
 * atomic OR and then signal N_v with L4H_BADGE_EVENT; the guest clears them
 * with an atomic exchange.
 */
#define L4H_NR_EVENTS           512
struct l4h_event_page {
	l4h_u64 pending[L4H_NR_EVENTS / 64];
	l4h_u64 steal_ns;      /* written by the host: time the vCPU was runnable
	                        * but not running, cumulative, monotonic */
	l4h_u64 idle_ticks;    /* written by the guest: time the vCPU blocked
	                        * idle, in time-counter ticks, cumulative (the
	                        * host derives steal_ns from it) */
	l4h_u64 reserved[502];
};

/* ------------------------------------------------------------------------
 * Boot info, mapped read-only at L4H_BOOTINFO_VA; the boot vCPU starts
 * with rdi (x0 on arm64) = L4H_BOOTINFO_VA.
 */
#define L4H_BOOTINFO_MAGIC      0x31544f4f4248344cull /* "L4HBOOT1" */
#define L4H_MAX_DEVICES         64
#define L4H_CMDLINE_SIZE        2048

enum l4h_dev_type {
	L4H_DEV_NONE = 0,
	L4H_DEV_VIRTIO = 1,     /* virtio-l4h transport, see l4h_virtio_regs */
	L4H_DEV_CONSOLE = 2,    /* hvc console ring */
	L4H_DEV_CTL = 3,        /* dom0 control channel (l4hctl) */
	L4H_DEV_ATTEST = 4,     /* attestation by l4h-trustd, see l4h_attest_page */
};

struct l4h_dev_desc {
	l4h_u32 type;           /* enum l4h_dev_type */
	l4h_u32 virtio_id;      /* VIRTIO_ID_* for L4H_DEV_VIRTIO */
	l4h_u64 page_va;        /* L4H_DEV_AREA_VA(index) */
	l4h_u64 page_size;      /* bytes mapped at page_va */
	l4h_u32 event;          /* event bit raised on the target vCPU */
	l4h_u32 kick_slot;      /* index in L4H_SLOT_DEV_CNODE: notification to kick the backend */
	/* L4H_DEV_CTL: a host-owned data area for bulk transfers (VM_LOAD),
	 * mapped read-write at data_va.  0 for other devices. */
	l4h_u64 data_va;
	l4h_u64 data_size;
};


struct l4h_bootinfo {
	l4h_u64 magic;
	l4h_u64 abi_version;
	l4h_u64 guest_id;
	l4h_u64 ram_base_va;
	l4h_u64 ram_size;
	l4h_u64 kernel_end_gpa;   /* end of the loaded kernel image, page aligned */
	l4h_u64 initrd_gpa;
	l4h_u64 initrd_size;
	l4h_u64 nr_vcpus;
	l4h_u64 tsc_hz;
	l4h_u64 nr_blocks;        /* RAM blocks: ram_size / L4H_BLOCK_SIZE */
	l4h_u64 nr_vspaces;
	l4h_u64 nr_devices;
	l4h_u64 flags;            /* L4H_BOOT_* */
	/* The I/O pool: host-owned memory mapped at ram_base_va + io_pool_gpa
	 * (2 MiB aligned, above RAM).  Every address a virtio device uses
	 * (rings, descriptor tables, buffers) must lie in it: devices and
	 * host components never access guest RAM.  The guest uses it through
	 * the DMA API only (restricted DMA, swiotlb). */
	l4h_u64 io_pool_gpa;
	l4h_u64 io_pool_size;
	l4h_u64 boot_blocks;      /* blocks [0, boot_blocks) are host frames */
	/* aarch64: the CPU's ID_AA64ISAR0/ISAR1/ISAR2/PFR0/PFR1_EL1, which the
	 * guest cannot read at EL0; all zero if unknown.  Unused on x86_64. */
	l4h_u64 cpu_id[5];
	/* An EROFS image of the guest kernel's /lib/modules: its modules and
	 * the tree to build more against (<release>/build), shared read-only
	 * by all guests at kmod_va.  kmod_size is 0 if the host has none. */
	l4h_u64 kmod_va;
	l4h_u64 kmod_size;
	l4h_u64 reserved[8];
	struct l4h_dev_desc devices[L4H_MAX_DEVICES];
	char cmdline[L4H_CMDLINE_SIZE];
};

#define L4H_BOOT_DOM0           (1ull << 0)

/* ------------------------------------------------------------------------
 * virtio-l4h: the shared device page of an L4H_DEV_VIRTIO device.
 *
 * The guest reads registers directly.  Fields with side effects (status,
 * driver features, queue setup, config writes) are written to the page and
 * then committed with L4H_HC_DEV_WRITE(device index, L4H_VIRTIO_OP_*).
 * Queue notifications: the guest atomically sets bit q in `kick` and then
 * signals the device's kick notification (L4H_SLOT_DEV_CNODE[kick_slot]).
 * Interrupts: the host atomically sets bits in `isr` and raises the
 * device's event line on the vCPU in `irq_vcpu`.
 */
#define L4H_VIRTIO_MAGIC        0x7634686cu /* "lh4v" */
#define L4H_VIRTIO_MAX_QUEUES   16
#define L4H_VIRTIO_CONFIG_OFF   2048
#define L4H_VIRTIO_CONFIG_SIZE  2048

#define L4H_VIRTIO_ISR_VRING    1u
#define L4H_VIRTIO_ISR_CONFIG   2u

struct l4h_virtq_regs {
	l4h_u32 num_max;        /* RO: maximum queue size, 0 if absent */
	l4h_u32 num;            /* RW: queue size chosen by the driver */
	l4h_u32 ready;          /* RW: committed with L4H_VIRTIO_OP_QUEUE */
	l4h_u32 reserved;
	l4h_u64 desc;           /* RW: guest-physical addresses */
	l4h_u64 driver;
	l4h_u64 device;
};

struct l4h_virtio_regs {
	l4h_u32 magic;
	l4h_u32 version;        /* 1 */
	l4h_u32 device_id;      /* VIRTIO_ID_* */
	l4h_u32 vendor_id;
	l4h_u64 device_features;
	l4h_u64 driver_features;
	l4h_u32 status;
	l4h_u32 config_generation;
	l4h_u32 num_queues;
	l4h_u32 isr;
	l4h_u64 kick;
	l4h_u32 irq_vcpu;
	l4h_u32 reserved0;
	l4h_u64 reserved[3];
	struct l4h_virtq_regs queues[L4H_VIRTIO_MAX_QUEUES];
};

enum l4h_virtio_op {
	L4H_VIRTIO_OP_STATUS = 1,       /* status written (0 = reset) */
	L4H_VIRTIO_OP_FEATURES = 2,     /* driver_features written */
	L4H_VIRTIO_OP_QUEUE = 3,        /* MR2 = queue index: ready/num/addresses */
	L4H_VIRTIO_OP_CONFIG = 4,       /* MR2 = offset, MR3 = length written */
	L4H_VIRTIO_OP_IRQ_VCPU = 5,     /* irq_vcpu written */
};

/* ------------------------------------------------------------------------
 * Console device (L4H_DEV_CONSOLE): input ring written by the host.
 * Output goes through L4H_HC_CONSOLE_WRITE.
 */
#define L4H_CONSOLE_IN_SIZE     4032
struct l4h_console_page {
	l4h_u32 in_head;        /* written by the host */
	l4h_u32 in_tail;        /* written by the guest */
	/* Set by the host, which then raises the device's event line: the
	 * guest should shut down cleanly (L4H_POWER_OFF + 1) or reboot
	 * (L4H_POWER_REBOOT + 1).  0 = no request. */
	l4h_u32 power_request;
	l4h_u32 reserved[13];
	l4h_u8 in[L4H_CONSOLE_IN_SIZE];
};

/* ------------------------------------------------------------------------
 * Control device (L4H_DEV_CTL, dom0 only): a request at offset 0 of the
 * device page and the response at L4H_CTL_RESP_OFF, exchanged with
 * L4H_HC_CTL.  Bulk data (images) is passed in the device's data area
 * (l4h_dev_desc.data_va), which belongs to the host: l4h-root never reads
 * dom0's RAM.  See DESIGN.md §9.1.
 */
#define L4H_CTL_VERSION         2
#define L4H_CTL_RESP_OFF        2048
#define L4H_CTL_DATA_MAX        1984
#define L4H_CTL_LOAD_MAX        (1u << 20)
#define L4H_CTL_NAME_MAX        32

struct l4h_ctl_req {
	l4h_u32 op;             /* enum l4h_ctl_op */
	l4h_u32 version;        /* L4H_CTL_VERSION */
	l4h_u64 args[6];
	l4h_u8 data[L4H_CTL_DATA_MAX];
};

struct l4h_ctl_resp {
	l4h_s64 status;         /* 0 or -errno */
	l4h_u64 vals[6];
	l4h_u8 data[L4H_CTL_DATA_MAX];
};

enum l4h_ctl_op {
	/* -> vals: cores, free bytes, total bytes, nr disks, nr vms, nr NICs */
	L4H_CTL_HOST_INFO = 1,
	/* args: ram bytes (rounded up to 2 MiB), vcpus, -, -, I/O pool bytes
	 * (0 = default, else a power of two from 1 MiB to 256 MiB); data:
	 * name -> vals[0] = vm, vals[1] = lowest GPA for the initrd (the
	 * kernel lies below it) */

	L4H_CTL_VM_CREATE = 2,
	/* args: vm, dst gpa, src offset in the control data area, len
	 * (<= L4H_CTL_LOAD_MAX) */
	L4H_CTL_VM_LOAD = 3,
	/* args: vm, initrd gpa, initrd size; data: cmdline.  The host loads
	 * its guest kernel and starts it.  Everything VM_LOAD wrote must lie
	 * in the initrd, which the launch digest covers (DESIGN.md §9.2). */
	L4H_CTL_VM_START = 4,
	/* args: vm */
	L4H_CTL_VM_DESTROY = 5,
	/* args: first vm -> data: struct l4h_ctl_vm[], vals[0] = count */
	L4H_CTL_VM_LIST = 6,
	/* args: vm, disk index, read-only, first sector, sectors (0 = to the
	 * end of the disk); sectors are 512 bytes */
	L4H_CTL_BLK_ATTACH = 7,
	/* args: vm, offset -> vals[0] = next offset, vals[1] = len,
	 * vals[2] = bytes lost; data: console output */
	L4H_CTL_CONSOLE_READ = 8,
	/* args: vm, len; data: console input */
	L4H_CTL_CONSOLE_WRITE = 9,
	/* args: disk index -> vals: bdf (bits 0-15; a virtio-scsi disk adds
	 * its target in bits 16-23 and LUN from bit 24), owner vm (or -1), failed (quarantined:
	 * attaching it fails with EIO), kind (0 virtio-blk, 1 NVMe, 2 virtio-scsi),
     * capacity (512-byte sectors), number of attachments. owner is the
     * first attached VM; use BLK_INFO to enumerate all windows. */
	L4H_CTL_DISK_INFO = 10,
	/* -> vals[0] = switch */
	L4H_CTL_SWITCH_CREATE = 11,
	/* args: switch, host NIC index */
	L4H_CTL_SWITCH_ATTACH_UPLINK = 12,
	/* args: vm, switch, MAC (low 48 bits, 0 = generate), flags
	 * (L4H_NIC_*) -> vals[0] = MAC */
	L4H_CTL_NIC_CREATE = 13,
	/* args: switch -> vals[0] = ports, vals[1] = uplink NIC (or -1);
	 * data: struct l4h_ctl_port[] */
	L4H_CTL_SWITCH_INFO = 14,
	/* args: NIC index -> vals: bdf, switch (or -1), MAC */
	L4H_CTL_NIC_INFO = 15,
	/* args: vm, CPU cap per vCPU in percent of a core (0 = none) */
	L4H_CTL_VM_SET_SCHED = 16,
	/* args: vm -> vals[v] = host core of vCPU v, for v < min(6, vCPUs) (the
	 * vCPU count is in L4H_CTL_VM_LIST) */
	L4H_CTL_VM_INFO = 17,
	/* args: vm, L4H_POWER_OFF or L4H_POWER_REBOOT: ask the guest to shut
	 * down or reboot cleanly */
	L4H_CTL_VM_SHUTDOWN = 19,
	/* args: vm -> vals[0] = CPU used in the last 100 ms (permille of a core,
	 * all vCPUs), vals[1] = CPU cap (percent per vCPU, 0 = none) */
	L4H_CTL_VM_STATS = 18,
    /* disk, sector, bytes (0 = flush, max L4H_CTL_LOAD_MAX), zero (0/1).
     * Writes the control data buffer or zeros to an UNATTACHED range.
     * Sector and length must be 4 KiB aligned. */
    L4H_CTL_BLK_WRITE = 20,
    /* disk, first attachment -> vals: next (0 = end), vm, start, sectors, read-only */
    L4H_CTL_BLK_INFO = 21,
	/* Reset the machine (ACPI reset register, then 0xcf9, then the
	 * keyboard controller); dom0 syncs its disks first.  Returns only if
	 * the machine did not reset: -EIO; -ENOSYS on aarch64. */
	L4H_CTL_HOST_REBOOT = 22,
	/* args[0]: UTC seconds since the Unix epoch. Set the machine RTC;
	 * does not change the host's boot-time clock anchor or guest clocks.
	 * -EINVAL for an unrepresentable date, -ENOSYS if no RTC is available,
	 * -EIO on hardware access failure. */
	L4H_CTL_RTC_SET = 23,
	/* -> vals: state (L4H_IOMMU_*), interrupts remapped (0/1), IOMMUs,
	 * devices confined, devices behind no IOMMU, events logged since
	 * boot.  AMD IOMMUs only (DESIGN.md §8.5).  dom0 only, like every
	 * control call. */
	L4H_CTL_IOMMU_INFO = 24,
	/* -> vals[0] = byte length (<= L4H_CTL_DATA_MAX); data: host build
	 * version in UTF-8, without a terminating NUL (e.g. v2026.10.1).
	 * This is independent of L4H_CTL_VERSION, the control ABI version. */
	L4H_CTL_HOST_VERSION = 25,
	/* args: vm, width, height.  Before VM_START: give the VM a virtio-gpu
	 * device (2D, one scanout of width x height pixels, each from
	 * L4H_GPU_MIN to L4H_GPU_MAX_WIDTH / L4H_GPU_MAX_HEIGHT) whose image
	 * GPU_READ returns.  One per VM; its I/O pool must hold
	 * L4H_GPU_POOL_IMAGES images, since the guest's buffers live there. */
	L4H_CTL_GPU_ATTACH = 26,
	/* args: vm, byte offset -> the VM's scanout image from that offset in
	 * the control data area, up to L4H_CTL_LOAD_MAX bytes; vals: bytes,
	 * width, height, stride (bytes from one row to the next), format (a
	 * VIRTIO_GPU_FORMAT_*, 4 bytes a pixel; 0 while nothing is shown),
	 * frame (it changes with every update).  -EAGAIN if the guest updated
	 * the image while it was copied. */
	L4H_CTL_GPU_READ = 27,
};

#define L4H_GPU_MIN             64
#define L4H_GPU_MAX_WIDTH       1920
#define L4H_GPU_MAX_HEIGHT      1200
#define L4H_GPU_POOL_IMAGES     4

#define L4H_IOMMU_NONE          0 /* none found, or none l4h drives */
#define L4H_IOMMU_OFF           1 /* iommu=0 */
#define L4H_IOMMU_ON            2 /* devices confined */
#define L4H_IOMMU_FAILED        3 /* found but unusable (see the serial log) */

#define L4H_NIC_NO_MAC_LOCK     (1ull << 0) /* allow any source MAC */
#define L4H_NIC_ISOLATED        (1ull << 1) /* no frames to or from other isolated ports */

struct l4h_ctl_port {
	l4h_u32 vm;
	l4h_u32 port;
	l4h_u64 mac;
	l4h_u64 rx_frames;
	l4h_u64 tx_frames;
	l4h_u64 drops;
};

enum l4h_vm_state {
	L4H_VM_CREATED = 1,
	L4H_VM_RUNNING = 2,
	L4H_VM_STOPPED = 3,
};

struct l4h_ctl_vm {
	l4h_u32 id;
	l4h_u32 state;          /* enum l4h_vm_state */
	l4h_u32 vcpus;
	l4h_u32 reserved;
	l4h_u64 ram;
	char name[L4H_CTL_NAME_MAX];
};

/* ------------------------------------------------------------------------
 * Hypercalls: seL4_Call(L4H_SLOT_HYP_EP) with the label below, arguments
 * in message registers, result in MR0.
 */
enum l4h_hypercall {
	L4H_HC_CONSOLE_WRITE = 1,   /* MR0 = len (<= 8*L4H_HC_CONSOLE_MAX_WORDS), MR1.. = bytes */
	L4H_HC_POWER = 2,           /* MR0 = L4H_POWER_* */
	L4H_HC_DEV_WRITE = 3,       /* MR0 = device index, MR1 = L4H_VIRTIO_OP_*, MR2.. = args */
	L4H_HC_DEV_READ = 4,        /* MR0 = device index, MR1 = register; returns MR0 */
	L4H_HC_SET_IRQ_AFFINITY = 5,/* MR0 = device index, MR1 = vCPU */
	L4H_HC_GET_TIME = 6,        /* returns MR0 = wall clock ns since epoch */
	L4H_HC_CTL = 7,             /* dom0: execute the request in the control device page */
};
#define L4H_HC_CONSOLE_MAX_WORDS 32

/* ------------------------------------------------------------------------
 * Attestation device (L4H_DEV_ATTEST, on hosts with a TPM): requests to
 * l4h-trustd in the device page.  The host proves what it booted with a
 * TPM quote over its signing key, and signs reports about the guest with
 * that key (DESIGN.md §9.2).  Requests are asynchronous:
 *
 * 1. The guest writes op, offset, in_len, blob_len and data, then a new
 *    seq (the previous one plus one), and signals the device's kick
 *    notification (L4H_SLOT_DEV_CNODE[kick_slot]).
 * 2. The host writes status, total, out_len and data, then done = seq,
 *    and raises the device's event line on vCPU 0.
 *
 * Results longer than L4H_ATTEST_PAGE_DATA come in pieces: the request's
 * offset says where the reply's data starts.  If the host's attestation
 * service fails, it sets state to L4H_ATTEST_FAILED and answers every
 * request so far with -EIO; later requests get no answer.
 *
 * - L4H_ATTEST_REPORT: data = 64 bytes of the guest's own (a verifier's
 *   nonce, a hash of a key).  Returns the report, a COSE_Sign1 (RFC 9052,
 *   ES256) over a CBOR map of claims.  The same data gives the same
 *   report, so it can be read in pieces.
 * - L4H_ATTEST_EVIDENCE: returns the host evidence, a CBOR map: the
 *   signing key, the TPM quote over it with the PCRs, the TPM's
 *   attestation key and its EK certificate.  It is the same for every
 *   guest until the host reboots.
 * - L4H_ATTEST_ACTIVATE: data = the credential blob (blob_len bytes) and
 *   the encrypted secret, the contents of the TPM2B_ID_OBJECT and
 *   TPM2B_ENCRYPTED_SECRET that TPM2_MakeCredential made for the
 *   attestation key.  Returns the decrypted credential, which proves to a
 *   verifier that the attestation key is in the TPM with that EK.  It can
 *   take the TPM seconds.
 *
 * status: 0 or -errno; -EIO: the TPM failed.
 */
enum l4h_attest_op {
	L4H_ATTEST_REPORT = 1,
	L4H_ATTEST_EVIDENCE = 2,
	L4H_ATTEST_ACTIVATE = 3,
};
#define L4H_ATTEST_DATA_SIZE    64
#define L4H_ATTEST_FAILED       1
#define L4H_ATTEST_PAGE_DATA    (4096 - 64)

struct l4h_attest_page {
	l4h_u32 seq;            /* guest: written last */
	l4h_u32 op;             /* enum l4h_attest_op */
	l4h_u32 offset;
	l4h_u32 in_len;         /* bytes of data in the request */
	l4h_u32 blob_len;       /* L4H_ATTEST_ACTIVATE */
	l4h_u32 done;           /* host: written last */
	l4h_s32 status;
	l4h_u32 total;          /* the whole result's length */
	l4h_u32 out_len;        /* bytes of data in the reply, from offset */
	l4h_u32 state;          /* host: L4H_ATTEST_FAILED, or 0 */
	l4h_u32 reserved[6];
	l4h_u8 data[L4H_ATTEST_PAGE_DATA];
};

enum l4h_power {
	L4H_POWER_OFF = 0,
	L4H_POWER_REBOOT = 1,
	L4H_POWER_CRASH = 2,
};

#endif /* L4H_ABI_H */

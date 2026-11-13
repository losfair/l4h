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

#define L4H_ABI_VERSION 8

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
#define L4H_SLOT_CONSOLE_KICK   5   /* notification: console output written */


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
 * [b * L4H_BLOCK_SIZE, (b + 1) * L4H_BLOCK_SIZE).  See DESIGN.md §8.2.
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

/* Memory hotplug.  Above the I/O pool, from bootinfo.hp_gpa to the 64 GiB
 * guest-physical limit, guest RAM comes and goes in hotplug blocks of
 * 128 MiB (L4H_HP_BLOCKS 2 MiB blocks): hotplug block m is GPA
 * [hp_gpa + m * L4H_HP_SIZE, +L4H_HP_SIZE), for m < bootinfo.hp_count.
 *
 * Root slot L4H_SLOT_HP is a level-1 CNode (radix 9, guard 3) made by the
 * host.  Its slot m is empty until the guest retypes a level-2 CNode
 * (radix 6, no guard) there; plugging m (l4h_mem_page) puts the copy of the
 * Untyped of block i of the hotplug block in its slot i, which the guest
 * names L4H_HP_BLOCK_CPTR(m, i).  Unplugging m revokes them.  Frames of
 * hotplugged memory are named by L4H_FRAME_CPTR, like the rest of RAM: the
 * guest makes the level-1 RAM CNodes of the region (root slots
 * L4H_SLOT_RAM_L1_BASE + n) itself.  See DESIGN.md §8.5. */
#define L4H_HP_SHIFT            27
#define L4H_HP_SIZE             (1ull << L4H_HP_SHIFT)
#define L4H_HP_BITS             (L4H_HP_SHIFT - L4H_BLOCK_SHIFT)
#define L4H_HP_BLOCKS           (1u << L4H_HP_BITS)
#define L4H_HP_L1_BITS          9
#define L4H_HP_MAX              (1u << L4H_HP_L1_BITS)
#define L4H_HP_L1_GUARD         (L4H_L2_INDEX_BITS - L4H_HP_L1_BITS - L4H_HP_BITS)
#define L4H_SLOT_HP             643
#define L4H_HP_L2_CPTR(m)       L4H_CPTR2(L4H_SLOT_HP, (l4h_u64)(m) << L4H_HP_BITS)
#define L4H_HP_BLOCK_CPTR(m, i) L4H_CPTR2(L4H_SLOT_HP, ((l4h_u64)(m) << L4H_HP_BITS) | (i))
/* The end of guest-physical space: RAM, the I/O pool and the region. */
#define L4H_GPA_END             ((l4h_u64)L4H_MAX_RAM_L1 << 30)

/* A CNode with bootinfo.nr_vspaces pre-assigned (ASID-bearing) VSpace
 * roots that the guest uses for its processes. */
#define L4H_SLOT_VSPACE_POOL    640
/* A CNode with device capabilities (indices from l4h_dev_desc). */
#define L4H_SLOT_DEV_CNODE      641
/* A CNode with bootinfo.nr_ept_roots pre-assigned EPT roots, one for each VM
 * the guest's KVM runs at a time.  None where the host has no usable VT-x:
 * nr_ept_roots is also how the guest learns whether it has. */
#define L4H_SLOT_EPT_POOL       644
#define L4H_MAX_EPT_ROOTS       8

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
/* Queue areas of USB controllers (L4H_USB_AREA_VA(n), n < L4H_MAX_GUEST_USB),
 * from L4H_SPECIAL_BASE + 0x28000000. */
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
/* Console output of one vCPU, which only that vCPU writes: a ring of
 * records, each a struct l4h_console_rec and len bytes, at
 * data[offset % L4H_CONSOLE_OUT_SIZE] (records wrap around).  Head and
 * tail wrap at L4H_CONSOLE_OUT_WRAP, a multiple of the ring size: native
 * u32 wrap would alias unread bytes because the size is not a power of
 * two.  Their distance modulo WRAP is at most SIZE (full), or 0 (empty).
 * The guest writes a record at head, advances head past it, then signals
 * L4H_SLOT_CONSOLE_KICK if the host had caught up (tail equal to the old
 * head, read after head is written).  The host prints the records of all
 * vCPUs in seq order, advancing each tail, then checks the heads again.
 * A reserved sequence may not be published yet. The host waits up to
 * 100 ms for a gap, then reports the missing records and skips it;
 * records published after their sequences were skipped are discarded.
 * This bounds the delay a stalled writer can impose on other vCPUs,
 * at the cost of losing late output, including tty output. Poweroff
 * flushing skips gaps immediately.
 *
 * Writers never wait.  When a record does not fit, the guest writes what
 * fits; output it gives up on is added to `lost`, which the host reports.
 * A writer that will try again (the tty) sets want_space and kicks: the
 * host clears it once it has read that ring, and raises the console
 * device's event. */
#define L4H_CONSOLE_OUT_SIZE    3904
#define L4H_CONSOLE_OUT_WRAP    (2u * L4H_CONSOLE_OUT_SIZE)
struct l4h_console_rec {
	l4h_u32 seq;            /* from a counter shared by the guest's vCPUs */
	l4h_u32 len;
};
struct l4h_console_out {
	l4h_u32 head;           /* written by the guest */
	l4h_u32 tail;           /* written by the host */
	l4h_u32 lost;           /* written by the guest: bytes, cumulative */
	l4h_u32 want_space;     /* set by the guest, cleared by the host */
	l4h_u32 reserved[12];
	l4h_u8 data[L4H_CONSOLE_OUT_SIZE];
};

struct l4h_event_page {
	l4h_u64 pending[L4H_NR_EVENTS / 64];
	l4h_u64 steal_ns;      /* written by the host: time the vCPU was runnable
	                        * but not running, cumulative, monotonic */
	l4h_u64 idle_ticks;    /* written by the guest: time the vCPU blocked
	                        * idle or waiting for a spinlock, in
	                        * time-counter ticks, cumulative (the host
	                        * derives steal_ns from it) */
	l4h_u64 reserved[6];
	struct l4h_console_out console;
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
	L4H_DEV_MEM = 5,        /* memory hotplug, see l4h_mem_page */
	L4H_DEV_USB = 6,        /* an xHCI controller driven by l4h-usbd, see l4h_usb_info */
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
	/* The memory hotplug region (L4H_SLOT_HP): hp_count hotplug blocks
	 * from hp_gpa (128 MiB aligned, above the I/O pool). */
	l4h_u64 hp_gpa;
	l4h_u64 hp_count;
	l4h_u64 nr_ept_roots;     /* L4H_SLOT_EPT_POOL */
	l4h_u64 reserved[5];
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
 * Device interrupts set `isr` and raise the boot-info event on `irq_vcpu`.
 * A valid queue_irq_vcpu[q] instead routes queue q to queue_event_base + q.
 * Such queue events do not use the shared `isr`. IRQ_VCPU commits a route.
 * Queue event slots are separate from all boot-info device event slots.
 */
#define L4H_VIRTIO_MAGIC        0x7634686cu /* "lh4v" */
#define L4H_VIRTIO_MAX_QUEUES   16
#define L4H_VIRTIO_QUEUE_IRQS    4
#define L4H_VIRTIO_QUEUE_EVENT_BASE (16 + L4H_MAX_DEVICES)
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
	/* Zero uses the device IRQ. Otherwise each queue has its own event. */
	l4h_u32 queue_event_base;
	/* UINT32_MAX uses irq_vcpu and the device IRQ for this queue. */
	l4h_u32 queue_irq_vcpu[L4H_VIRTIO_QUEUE_IRQS];
	l4h_u64 reserved;
	struct l4h_virtq_regs queues[L4H_VIRTIO_MAX_QUEUES];
};

enum l4h_virtio_op {
	L4H_VIRTIO_OP_STATUS = 1,       /* status written (0 = reset) */
	L4H_VIRTIO_OP_FEATURES = 2,     /* driver_features written */
	L4H_VIRTIO_OP_QUEUE = 3,        /* MR2 = queue index: ready/num/addresses */
	L4H_VIRTIO_OP_CONFIG = 4,       /* MR2 = offset, MR3 = length written */
	L4H_VIRTIO_OP_IRQ_VCPU = 5,     /* MR2=0: device, MR2=q+1: queue */
};

/* ------------------------------------------------------------------------
 * Console device (L4H_DEV_CONSOLE): input ring written by the host.
 * Output goes through each vCPU's ring (struct l4h_console_out).  The
 * device's event: a power request, or room in a ring (want_space).
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
 * Memory device (L4H_DEV_MEM): the hotplug target and state, written by the
 * host, which raises the device's event when the target changes.  The guest
 * plugs and unplugs hotplug blocks until `plugged` equals `target`.
 *
 * A request: the guest writes req_op and req_block, then a new req_seq
 * (the previous one plus one), and signals the device's kick notification.
 * The host writes result, then done_seq = req_seq, and raises the device's
 * event line.
 */
struct l4h_mem_page {
	l4h_u32 generation;     /* bumped after every change */
	l4h_u32 target;         /* hotplug blocks */
	l4h_u32 plugged;
	l4h_u32 reserved0;
	l4h_u64 plugged_map[L4H_HP_MAX / 64]; /* bit m: hotplug block m is plugged */
	l4h_u32 req_op;         /* written by the guest: enum l4h_mem_op */
	l4h_u32 req_block;
	l4h_u32 req_seq;
	l4h_u32 done_seq;       /* written by the host */
	l4h_s64 result;
	l4h_u64 reserved[3];
};

/* req_op of l4h_mem_page.  result: 0, or -EINVAL
 * (out of range, already plugged or not plugged, no level-2 CNode in its
 * slot or a slot of it not empty), -ENOSPC (a plug with as many plugged as
 * the target), -EBUSY (the host is short of memory, or the guest plugs and
 * unplugs too fast: try again later), -EIO (the host failed). */
enum l4h_mem_op {
	L4H_MEM_PLUG = 1,
	L4H_MEM_UNPLUG = 2,
};

/* ------------------------------------------------------------------------
 * Control device (L4H_DEV_CTL, dom0 only): a request at offset 0 of the
 * device page and the response at L4H_CTL_RESP_OFF.  The guest writes a
 * new seq in the l4h_ctl_sync at L4H_CTL_SYNC_OFF (the previous one plus
 * one) and signals the device's kick notification; the host writes the
 * response, then done = seq, and raises the device's event line.  A request
 * that waits for a driver may be answered much later, or never: the host
 * writes its seq at L4H_CTL_TAKEN_OFF (a u32) once it has read the
 * request and the data area, and raises the event, and the guest may then
 * write the next request, which takes the place of the one waiting.  Bulk
 * data (images) is passed in the device's data area (l4h_dev_desc.data_va),
 * which belongs to the host: the host never reads dom0's RAM.  See
 * DESIGN.md §10.1.
 *
 * l4h-root refuses every request whose version is not its own, so a bump
 * makes l4hctl of one release unable to talk to the host of another, in
 * both directions (3 did, for two new ops only).  Bump it only when an
 * existing request or response changes meaning or layout.  A new op needs
 * none: a host that does not know it answers -ENOSYS.
 */
#define L4H_CTL_VERSION         3
#define L4H_CTL_RESP_OFF        2048
#define L4H_CTL_SYNC_OFF        2040    /* between request and response */
#define L4H_CTL_TAKEN_OFF       4088    /* after the response */
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

struct l4h_ctl_sync {
	l4h_u32 seq;            /* written by the guest */
	l4h_u32 done;           /* written by the host */
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
	 * in the initrd, which the launch digest covers (DESIGN.md §10.2). */
	L4H_CTL_VM_START = 4,
	/* args: vm */
	L4H_CTL_VM_DESTROY = 5,
	/* args: first vm -> data: struct l4h_ctl_vm[], vals[0] = count */
	L4H_CTL_VM_LIST = 6,
	/* args: vm, disk index, flags (L4H_BLK_*), first sector, sectors
	 * (0 = to the end of the disk); sectors are 512 bytes */
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
	/* args: vm, CPU cap per vCPU in percent of a core (0 = none).
	 * vCPU 0's cap includes its VMM's CPU time. */
	L4H_CTL_VM_SET_SCHED = 16,
	/* args: vm -> vals[v] = host core of vCPU v, for v < min(6, vCPUs) (the
	 * vCPU count is in L4H_CTL_VM_LIST) */
	L4H_CTL_VM_INFO = 17,
	/* args: vm, L4H_POWER_OFF or L4H_POWER_REBOOT: ask the guest to shut
	 * down or reboot cleanly */
	L4H_CTL_VM_SHUTDOWN = 19,
	/* args: vm -> vals[0] = CPU used in the last 100 ms (permille of a core,
	 * all vCPUs and the VMM), vals[1] = CPU cap (percent per vCPU, 0 = none) */
	L4H_CTL_VM_STATS = 18,
    /* disk, sector, bytes (0 = flush, max L4H_CTL_LOAD_MAX), zero (0/1).
     * Writes the control data buffer or zeros to an UNATTACHED range.
     * Sector and length must be 4 KiB aligned. */
    L4H_CTL_BLK_WRITE = 20,
    /* disk, cursor (0 = first) -> vals: next (0 = end), vm, start, sectors,
     * read-only, extent: one row per window, or per extent (in guest order,
     * extent 0 first) of a disk made of them.  start is ~0 if the host
     * cannot tell (the disk's controller failed). */
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
	 * boot.  AMD-Vi or Intel VT-d (DESIGN.md §9.5).  dom0 only, like every
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
	/* args: vm, target bytes: plug or unplug memory until the VM has this
	 * much.  The part above its boot RAM is rounded up to whole hotplug
	 * blocks (L4H_HP_SIZE) and clamped to its region; returns at once, the
	 * guest plugs and unplugs as it can (DESIGN.md §8.5). */
	L4H_CTL_VM_SET_MEM = 28,
	/* args: vm -> vals: boot bytes, region bytes, target bytes, plugged
	 * bytes (all host memory: a hotplug block counts L4H_HP_SIZE) */
	L4H_CTL_VM_MEM_INFO = 29,
	/* vm -> taint bits 0-63, seal bits 0-63 (host actions only) */
	L4H_CTL_VM_TRUST = 30,
	/* Host diagnostics, readable only by dom0. args: cursor (0 starts at
	 * boot), snapshot end (0 selects now); both are host times, in ticks,
	 * to pass back as they come. vals: next cursor, data bytes, lost
	 * records, snapshot end. Data is whole UTF-8 lines, oldest first, with
	 * seconds since host start and the id of the component whose log the
	 * line is in (root: 0); control characters are replaced. Reads do not
	 * consume records. Lost includes overwritten, dropped or concurrently
	 * publishing records. The snapshot end returned is the one given (an
	 * end still to come counts as 0), and stays so: a snapshot is done when
	 * next reaches it. A read can be short of it, even empty, while a
	 * record is still being written; read on, with what it returned, after
	 * a moment. A future cursor, or one past the end given, returns
	 * EINVAL. */
	L4H_CTL_LOG_READ = 31,
	/* Steering (DESIGN.md §9.3): dom0 hands part of an address's traffic
	 * to another port, rewriting only MAC addresses.
	 *
	 * args: switch, MAC, peer MAC (low 48 bits) -> vals[0] = endpoint.
	 * MAC must be that of a port on the switch or of its uplink NIC; peer
	 * is the gateway its steered traffic comes from and returns to.
	 * Setting an existing (switch, MAC) changes its peer.  -ENOENT (no
	 * switch), -EINVAL, -ENOSPC. */
	L4H_CTL_EP_SET = 32,
	/* args: endpoint; deletes its steering rules too */
	L4H_CTL_EP_DEL = 33,
	/* args: first endpoint -> vals[0] = count; data: struct l4h_ctl_ep[] */
	L4H_CTL_EP_LIST = 34,
	/* args: endpoint, family | proto << 8 | port << 16 (family 4 or 6;
	 * proto 0 = any, then port 0; port 0 = any, and only for proto 6 or
	 * 17), IP bits 127-64, IP bits 63-0 (IPv4 in bits 31-0), target port
	 * mask (exactly one bit for now) -> vals[0] = rule.  Frames from the
	 * peer to the endpoint MAC matching (dst IP, proto, dst port) go to the
	 * target with its MAC; the target's frames matching (src IP, proto, src
	 * port) leave as endpoint MAC -> peer.  Most specific match wins.
	 * Setting an existing (endpoint, match) replaces its targets.  A rule
	 * leaves a target port when that port is removed.  -ENOENT, -EINVAL,
	 * -EEXIST (the target has rules for this IP under another endpoint),
	 * -ENOSPC. */
	L4H_CTL_STEER_SET = 35,
	/* args: rule */
	L4H_CTL_STEER_DEL = 36,
	/* args: first rule -> vals[0] = count; data: struct l4h_ctl_steer[] */
	L4H_CTL_STEER_LIST = 37,
	/* -> vals[0] = this host's partition, vals[1] = partitions on the
	 * machine (1: l4h has the machine to itself), vals[2] = APIC ID of
	 * the partition's first CPU, vals[3] = partitions heard from
	 * (a bit each; partition 0 only).  DESIGN.md §11.4. */
	L4H_CTL_PARTITION_INFO = 38,
	/* args: vm, disk index, flags (L4H_BLK_*), offset in the control data area,
	 * extent count (1..L4H_BLK_MAX_EXTENTS); data area: struct
	 * l4h_ctl_extent[count] in guest order.  Like BLK_ATTACH, but the
	 * guest's disk is the extents joined, e.g. an LVM linear LV.  Each
	 * extent is 4 KiB aligned, and at least L4H_BLK_MIN_EXTENT_SECTORS
	 * long if there are several.  -EINVAL: no such disk (bad alignment or
	 * bounds, extents that overlap); -EBUSY: conflicts with another
	 * attachment or a dom0 boot range. */
	L4H_CTL_BLK_ATTACH_EXTENTS = 39,
	/* args: controller index -> vals: bdf, vendor | device << 16, USB 2
	 * ports | USB 3 ports << 16, state (L4H_USB_STATE_*), owner vm (or -1),
	 * requests refused (counted by usbd); data: the reason, for
	 * L4H_USB_STATE_UNSUPPORTED.  -ENOENT past the last controller.  xHCI
	 * controllers (DESIGN.md §9.7), listed at boot and left to the
	 * firmware until the first USB_ATTACH claims one. */
	L4H_CTL_USB_INFO = 40,
	/* args: vm, controller index.  Before VM_START: give the VM the whole
	 * controller.  Claims it first if it is still the firmware's.  -EBUSY
	 * (another VM has it), -EIO (failed), -ENODEV (unsupported), -ENOSPC
	 * (no device slot, or L4H_MAX_GUEST_USB already), -ENOMEM. */
	L4H_CTL_USB_ATTACH = 41,
	/* args: first BDF (bus << 8 | dev << 3 | func, inclusive) -> vals:
	 * count; data: l4h_ctl_pci[count], in BDF order. Continue from the
	 * last BDF + 1; count 0 ends the list. Read-only boot inventory of
	 * every function root enumerated (this partition's, on multikernel).
	 * No configuration-space accesses or BAR probing at query time. */
	L4H_CTL_PCI_LIST = 42,
};

#define L4H_PCI_OWNER_NONE     0 /* no host service assigned */
#define L4H_PCI_OWNER_BLKD     1
#define L4H_PCI_OWNER_NETD     2
#define L4H_PCI_OWNER_MEMD     3
#define L4H_PCI_OWNER_USBD     4
#define L4H_PCI_OWNER_FIRMWARE 5 /* xHCI not claimed by usbd */
#define L4H_PCI_OWNER_ROOT     6 /* disabled or quarantined, no active driver */

struct l4h_ctl_pci {
	l4h_u16 bdf;
	l4h_u16 vendor;
	l4h_u16 device;
	l4h_u16 subsystem_vendor; /* 0 when not supplied by this header */
	l4h_u16 subsystem_device;
	l4h_u8 class;
	l4h_u8 subclass;
	l4h_u8 prog_if;
	l4h_u8 revision;
	l4h_u16 owner;            /* L4H_PCI_OWNER_*; host service, not VM */
};

#define L4H_USB_STATE_FIRMWARE    0 /* not claimed: the firmware has it */
#define L4H_USB_STATE_IDLE        1 /* claimed, halted, no VM */
#define L4H_USB_STATE_VM          2 /* a VM has it */
#define L4H_USB_STATE_FAILED      3 /* claim, attach, reset or drain failed: until reboot */
#define L4H_USB_STATE_UNSUPPORTED 4

struct l4h_ctl_extent {
	l4h_u64 start;          /* 512-byte sectors */
	l4h_u64 sectors;
};

#define L4H_BLK_MAX_EXTENTS        4096
#define L4H_BLK_MIN_EXTENT_SECTORS 8192

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

#define L4H_BLK_RO              (1ull << 0) /* read-only */
#define L4H_BLK_VOLATILE        (1ull << 1) /* no flush: the guest sees no write cache */

struct l4h_ctl_port {
	l4h_u32 vm;
	l4h_u32 port;
	l4h_u64 mac;
	l4h_u64 rx_frames;
	l4h_u64 tx_frames;
	l4h_u64 drops;
};

struct l4h_ctl_ep {
	l4h_u32 id;
	l4h_u32 sw;
	l4h_u64 mac;
	l4h_u64 peer;
};

struct l4h_ctl_steer {
	l4h_u32 id;
	l4h_u32 ep;
	l4h_u64 match;          /* as L4H_CTL_STEER_SET args[1] */
	l4h_u64 ip_hi, ip_lo;
	l4h_u64 targets;
	l4h_u64 in_frames;
	l4h_u64 out_frames;
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
/* ------------------------------------------------------------------------
 * USB host controller (L4H_DEV_USB): a whole xHCI controller, which
 * l4h-usbd drives for the guest (DESIGN.md §9.7).  The guest's USB core
 * does enumeration, hubs and class drivers; it sends host-controller
 * operations (slots, contexts, endpoints, root-hub ports) and one URB per
 * transfer record.  The guest never names a DMA address other than I/O
 * pool segments, never touches the controller, and never sees usbd's
 * memory.
 *
 * The queue area (page_va, page_size = L4H_USB_AREA_PAGES pages at
 * L4H_USB_AREA_VA(n)) is host memory shared with usbd:
 *
 *   page 0       read-only   struct l4h_usb_info (usbd -> guest)
 *   page 1       read-write  struct l4h_usb_ctrl (guest -> usbd)
 *   pages 2-3    read-write  control SQ, L4H_USB_CTL_SQ_SIZE records
 *   pages 4-67   read-write  transfer SQ, L4H_USB_XFER_SQ_SIZE records
 *   pages 68-99  read-only   completion queue (CQ), shared by both SQs
 *   page 100     read-only   event queue (EQ)
 *
 * Indices are free-running u32s; entry i is at [i % size].  The producer
 * owns the head, the consumer the tail.  usbd copies a record before it
 * checks it, and checks every index the guest writes against its own
 * copies.  It accepts a request only while fewer than L4H_USB_CQ_SIZE are
 * accepted and not yet consumed from the CQ, so the CQ never overflows; a
 * transfer only while fewer than L4H_USB_CQ_SIZE - 1, so a control request
 * (URB_CANCEL) always gets in once the guest consumes its completions.
 *
 * Kicks: after writing a head or a tail of its own (or `reset_seq`), the
 * guest signals kick_slot if `usbd_waiting` is set.  usbd sets it and
 * looks at the indices again before it waits.
 *
 * Interrupts: usbd signals the guest's VMM, which raises the device's
 * event on the vCPU the guest chose with L4H_HC_DEV_WRITE(index,
 * L4H_USB_DEVOP_IRQ_VCPU, vcpu).  The handler drains the CQ and the EQ,
 * then looks at cq_head and eq_head again.
 *
 * Control requests complete in order.  Transfers complete in order per
 * endpoint (and stream); a URB_CANCEL completes the URB it names with
 * L4H_USB_ST_CANCELLED once the controller can no longer touch its
 * buffers, then completes itself.
 *
 * Reset: the guest writes reset_seq = the previous one plus one and kicks.
 * usbd sets state = L4H_USB_RESETTING, halts and resets the controller
 * (every slot is gone), completes every request it had accepted with
 * L4H_USB_ST_SHUTDOWN (they fit in the CQ), restarts the controller, then
 * writes reset_done = reset_seq and state = L4H_USB_READY, and raises
 * the event.  Indices carry on: records still in the SQs are served
 * after the reset (those naming a slot fail with L4H_USB_ST_NODEV).  A
 * driver starting afresh sets its SQ heads to usbd's tails and its CQ and
 * EQ tails to usbd's heads (page 0).  A controller error does the same of
 * usbd's own accord, followed by an L4H_USB_EV_HC_RESET event.
 */
#define L4H_MAX_GUEST_USB       4
#define L4H_USB_AREA_VA(n)      (L4H_SPECIAL_BASE + 0x28000000ull + (l4h_u64)(n) * 0x100000ull)
#define L4H_USB_AREA_PAGES      101
#define L4H_USB_MAGIC           0x6273756cu /* "lusb" */
#define L4H_USB_VERSION         1

#define L4H_USB_CTL_SQ_SIZE     32
#define L4H_USB_XFER_SQ_SIZE    128
#define L4H_USB_CQ_SIZE         256
#define L4H_USB_EQ_SIZE         64
#define L4H_USB_CTL_SQ_OFF      0x2000
#define L4H_USB_XFER_SQ_OFF     0x4000
#define L4H_USB_CQ_OFF          0x44000
#define L4H_USB_EQ_OFF          0x64000
#define L4H_USB_MAX_SEGS        64   /* a 256 KiB request of 4 KiB pages */
#define L4H_USB_MAX_ISO         48
#define L4H_USB_MAX_PORTS       255
#define L4H_USB_MAX_STREAMS     16

/* l4h_usb_info.features */
#define L4H_USB_F_ISOCH         (1u << 0)
#define L4H_USB_F_STREAMS       (1u << 1)
#define L4H_USB_F_CSZ           (1u << 2) /* 64-byte contexts (informational) */

/* l4h_usb_info.state */
#define L4H_USB_READY           1
#define L4H_USB_RESETTING       2
#define L4H_USB_DEAD            3   /* the controller failed: nothing completes */

struct l4h_usb_index {
	l4h_u32 v;
	l4h_u32 pad[15];
};

/* Page 0, written by usbd only. */
struct l4h_usb_info {
	l4h_u32 magic;
	l4h_u32 version;
	l4h_u32 features;       /* L4H_USB_F_* */
	l4h_u32 state;          /* L4H_USB_READY, ... */
	l4h_u32 max_slots;      /* slot handles are 1..max_slots */
	l4h_u32 max_ports;      /* root ports are 1..max_ports */
	l4h_u32 usb2_ports;     /* ports with port_proto 2 */
	l4h_u32 usb3_ports;     /* ports with port_proto 3 */
	l4h_u32 max_streams;    /* per endpoint, a power of two (0: none) */
	l4h_u32 max_transfer;   /* bytes of one URB */
	l4h_u32 hci_version;    /* HCIVERSION, as BCD */
	l4h_u32 reset_done;     /* the last reset_seq completed */
	l4h_u32 mfindex;        /* bits 0..13: MFINDEX, as usbd last read it; 14..31: a
	                         * sequence, odd while usbd updates it with mf_ticks */
	l4h_u32 hc_resets;      /* resets so far, for any reason */
	l4h_u64 mf_ticks;       /* the host counter (TSC, CNTVCT) when MFINDEX was read;
	                         * 0: the controller is not running.  MFINDEX advances 8000
	                         * times a second from there */
	struct l4h_usb_index usbd_waiting;
	struct l4h_usb_index ctl_sq_tail;
	struct l4h_usb_index xfer_sq_tail;
	struct l4h_usb_index cq_head;
	struct l4h_usb_index eq_head;
	struct l4h_usb_index lost_events; /* EQ was full: the guest rescans every port */
	/* port_proto[p]: USB major revision (2 or 3) of root port p, 0: none */
	l4h_u8 port_proto[L4H_USB_MAX_PORTS + 1];
};

/* Page 1, written by the guest only. */
struct l4h_usb_ctrl {
	struct l4h_usb_index ctl_sq_head;
	struct l4h_usb_index xfer_sq_head;
	struct l4h_usb_index cq_tail;
	struct l4h_usb_index eq_tail;
	struct l4h_usb_index reset_seq;
};

/* Control SQ ops (l4h_usb_ctl_req.op). */
enum l4h_usb_op {
	/* port -> val[0] = PORTSC */
	L4H_USB_OP_PORT_GET = 1,
	/* port, arg[0] = L4H_USB_PF_*, arg[1] = value */
	L4H_USB_OP_PORT_SET = 2,
	L4H_USB_OP_PORT_CLEAR = 3,
	/* -> val[0] = slot handle */
	L4H_USB_OP_SLOT_ENABLE = 4,
	/* slot: its transfers complete first */
	L4H_USB_OP_SLOT_DISABLE = 5,
	/* slot, port = root port, arg[0] = route string, arg[1] = speed
	 * (L4H_USB_SPEED_*), arg[2] = TT hub slot (0: none), arg[3] = TT port
	 * and arg[4] = multi-TT (both 0 without a TT hub), arg[5] = ep0 max packet, arg[6] = BSR (address
	 * later) -> val[0] = the device's USB address */
	L4H_USB_OP_ADDRESS = 6,
	/* slot, drop = DCIs dropped (bit n = DCI n), n_eps entries in eps:
	 * endpoints added (or changed: drop and add) */
	L4H_USB_OP_EP_CONFIG = 7,
	/* slot, arg[0] = ports, arg[1] = TT think time (0-3), arg[2] = multi-TT */
	L4H_USB_OP_HUB_CONFIG = 8,
	/* slot, arg[0] = ep0 max packet */
	L4H_USB_OP_EP0_MPS = 9,
	/* slot: Reset Device; every endpoint but ep0 is gone */
	L4H_USB_OP_DEV_RESET = 10,
	/* slot, arg[0] = DCI: clear the halt and the data toggle */
	L4H_USB_OP_EP_RESET = 11,
	/* slot, drop = DCIs, arg[0] = streams (a power of two, at least
	 * 4 and at most max_streams; stream IDs are 1..streams-1) */
	L4H_USB_OP_STREAMS_ALLOC = 12,
	L4H_USB_OP_STREAMS_FREE = 13,
	/* arg[0] = the tag of a transfer */
	L4H_USB_OP_URB_CANCEL = 14,
};

/* Port features (L4H_USB_OP_PORT_SET / PORT_CLEAR arg[0]). */
enum l4h_usb_port_feature {
	L4H_USB_PF_POWER = 1,
	L4H_USB_PF_RESET = 2,           /* set only */
	L4H_USB_PF_WARM_RESET = 3,      /* set only, USB 3 ports */
	L4H_USB_PF_LINK_STATE = 4,      /* set only: value = PLS 0 (U0), 3 (U3), 4 (disabled), 5 (RxDetect), 15 (resume) */
	L4H_USB_PF_ENABLE = 5,          /* clear only: disable a USB 2 port */
	L4H_USB_PF_WAKE = 6,            /* set: value = bit 0 connect, 1 disconnect, 2 over-current */
	L4H_USB_PF_CHANGE = 7,          /* clear only: value = PORTSC change bits (17-23) */
};

#define L4H_USB_SPEED_FULL      1
#define L4H_USB_SPEED_LOW       2
#define L4H_USB_SPEED_HIGH      3
#define L4H_USB_SPEED_SUPER     4
#define L4H_USB_SPEED_SUPER_PLUS 5

/* xHCI endpoint types. */
#define L4H_USB_EP_ISOC_OUT     1
#define L4H_USB_EP_BULK_OUT     2
#define L4H_USB_EP_INT_OUT      3
#define L4H_USB_EP_CONTROL      4
#define L4H_USB_EP_ISOC_IN      5
#define L4H_USB_EP_BULK_IN      6
#define L4H_USB_EP_INT_IN       7

struct l4h_usb_ep {
	l4h_u8 dci;             /* 2..31 */
	l4h_u8 type;            /* L4H_USB_EP_* */
	/* xHCI interval (2^n * 125 us), 0..15: 3..10 for a low or full speed
	 * interrupt endpoint, from 3 for full speed isoch, 0 for control and
	 * bulk below high speed and at SuperSpeed */
	l4h_u8 interval;
	l4h_u8 burst_mult;      /* max burst (bits 0-3), mult (bits 4-5) */
	l4h_u16 max_packet;
	l4h_u16 max_esit;       /* max ESIT payload, bytes */
};

#define L4H_USB_CTL_EPS         30

struct l4h_usb_ctl_req {
	l4h_u32 op;             /* enum l4h_usb_op */
	l4h_u32 tag;            /* returned in the completion */
	l4h_u16 slot;
	l4h_u8 port;
	l4h_u8 n_eps;
	l4h_u32 drop;
	union {
		struct l4h_usb_ep eps[L4H_USB_CTL_EPS];
		l4h_u32 arg[60];
	};
};

/* Transfer SQ records (2 KiB): one URB each. */
#define L4H_USB_XFER_CONTROL    0
#define L4H_USB_XFER_BULK       1
#define L4H_USB_XFER_INT        2
#define L4H_USB_XFER_ISOC       3

#define L4H_USB_XF_IN           (1u << 0)  /* device to host */
#define L4H_USB_XF_ZERO_PACKET  (1u << 1)  /* OUT: end with a zero-length packet */
#define L4H_USB_XF_SHORT_NOT_OK (1u << 2)  /* IN: a short packet is an error */
#define L4H_USB_XF_ISO_ASAP     (1u << 3)  /* no Frame IDs: as soon as possible */

struct l4h_usb_seg {
	l4h_u64 gpa;            /* in the I/O pool */
	l4h_u32 len;
	l4h_u32 reserved;
};

struct l4h_usb_iso {
	l4h_u32 offset;         /* in the transfer's data */
	l4h_u32 len;
};

struct l4h_usb_xfer_req {
	l4h_u32 tag;
	l4h_u16 slot;
	l4h_u8 dci;             /* 1 (ep0) .. 31 */
	l4h_u8 type;            /* L4H_USB_XFER_* */
	l4h_u32 flags;          /* L4H_USB_XF_* */
	l4h_u32 stream;         /* 0: none */
	l4h_u32 start_frame;    /* ignored: usbd schedules isoch URBs (the CQE says where) */
	l4h_u32 length;         /* bytes: the segments together */
	l4h_u16 n_segs;
	l4h_u16 n_iso;
	l4h_u32 reserved0;
	l4h_u8 setup[8];        /* control transfers */
	l4h_u32 reserved[6];
	struct l4h_usb_seg segs[L4H_USB_MAX_SEGS];
	struct l4h_usb_iso iso[L4H_USB_MAX_ISO];
	l4h_u8 pad[2048 - 64 - 16 * L4H_USB_MAX_SEGS - 8 * L4H_USB_MAX_ISO];
};

/* Completion status: 0 or a negative errno, as Linux's USB core uses them. */
#define L4H_USB_ST_OK           0
#define L4H_USB_ST_INVALID      (-22)   /* -EINVAL: refused by usbd */
#define L4H_USB_ST_NODEV        (-19)   /* -ENODEV: no such slot or device */
#define L4H_USB_ST_STALL        (-32)   /* -EPIPE */
#define L4H_USB_ST_PROTO        (-71)   /* -EPROTO: transaction error */
#define L4H_USB_ST_BABBLE       (-75)   /* -EOVERFLOW */
#define L4H_USB_ST_SHORT        (-121)  /* -EREMOTEIO: short, with SHORT_NOT_OK */
#define L4H_USB_ST_CANCELLED    (-104)  /* -ECONNRESET */
#define L4H_USB_ST_SHUTDOWN     (-108)  /* -ESHUTDOWN: controller reset */
#define L4H_USB_ST_TIMEOUT      (-62)   /* -ETIME: a command timed out */
#define L4H_USB_ST_MISSED       (-18)   /* -EXDEV: isoch packet not sent */
#define L4H_USB_ST_NOSPC        (-28)   /* -ENOSPC: no slot, ring or bandwidth */
#define L4H_USB_ST_IO           (-5)    /* -EIO: any other failure */
#define L4H_USB_ST_DROPPED      (-125)  /* -ECANCELED: URB_CANCEL of an URB still in the
                                         * transfer SQ: usbd skips its record and never
                                         * completes it */

#define L4H_USB_CQ_CTL          1u      /* l4h_usb_cqe.kind: a control request */
#define L4H_USB_CQ_XFER         2u      /* a transfer */

struct l4h_usb_cqe {
	l4h_u32 tag;
	l4h_u32 kind;           /* L4H_USB_CQ_* */
	l4h_s32 status;
	l4h_u32 actual;         /* bytes transferred */
	l4h_u32 start_frame;    /* isoch: where usbd scheduled it (frames below high speed,
	                         * microframes from it, as Linux's xHCI driver) */
	l4h_u32 error_count;    /* isoch packets with errors */
	l4h_u32 n_iso;
	l4h_u32 val[2];
	l4h_u32 reserved[7];
	struct {
		l4h_s32 status;
		l4h_u32 actual;
	} iso[L4H_USB_MAX_ISO];
	l4h_u8 pad[512 - 64 - 8 * L4H_USB_MAX_ISO];
};

#define L4H_USB_EV_PORT         1       /* port, portsc: a change bit is set */
#define L4H_USB_EV_HC_RESET     2       /* every slot is gone: re-enumerate */

struct l4h_usb_event {
	l4h_u32 type;           /* L4H_USB_EV_* */
	l4h_u32 port;
	l4h_u32 portsc;
	l4h_u32 reserved[5];
};

/* L4H_HC_DEV_WRITE ops of an L4H_DEV_USB device. */
#define L4H_USB_DEVOP_IRQ_VCPU  5       /* MR2 = vCPU of the device's event */

/*
 * Hypercalls, on L4H_SLOT_HYP_EP.  A reply's MR0 is 0 or an errno, its
 * value follows in MR1 (host/l4h-host/src/hypercall.rs declares the host's
 * side).  L4H_HC_POWER is not answered.
 */
enum l4h_hypercall {
	L4H_HC_POWER = 2,         /* MR0 = L4H_POWER_* */
	L4H_HC_DEV_WRITE = 3,       /* MR0 = device index, MR1 = L4H_VIRTIO_OP_*, MR2, MR3 = args; returns the op's result */
	L4H_HC_GET_TIME = 6,        /* returns wall clock ns since epoch */
};

/* ------------------------------------------------------------------------
 * Attestation/flags device (L4H_DEV_ATTEST, flags work without a TPM): requests to
 * l4h-trustd in the device page.  The host proves what it booted with a
 * TPM quote over its signing key, and signs reports about the guest with
 * that key (DESIGN.md §10.2).  Requests are asynchronous:
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
	/* data: l4h_attest_act (or 32 bytes, flags=0). All or nothing;
	 * -EPERM if any bit is sealed. Returns l4h_attest_flags. */
	L4H_ATTEST_ACT = 4,
	/* data: 32-byte bitmap, defined host bits or userspace bits only.
	 * Returns l4h_attest_flags. */
	L4H_ATTEST_SEAL = 5,
};
#define L4H_FLAG_BITS           256
#define L4H_FLAG_HOST           0   /* 0-31 host; 32-63 reserved for host */
#define L4H_FLAG_GUEST          64  /* 64 + Linux TAINT_*; not sealable */
#define L4H_FLAG_USER           128 /* 128-255: workload-defined gates */
#define L4H_FLAG_CONSOLE_IN     (1u << 0)
#define L4H_FLAG_CONSOLE_OUT    (1u << 1) /* text console and GPU_READ */
#define L4H_FLAGS_HOST_DEFINED  0x3u
#define L4H_ACT_SEAL            (1u << 0) /* userspace bits: at most once */

/* Bit n is bit n % 8 of byte n / 8. Empty ACT reads both bitmaps. */
struct l4h_attest_act {
	l4h_u8 bits[L4H_FLAG_BITS / 8];
	l4h_u32 flags;
};
struct l4h_attest_flags {
	l4h_u8 taint[L4H_FLAG_BITS / 8];
	l4h_u8 seal[L4H_FLAG_BITS / 8];
};

#define L4H_ATTEST_DATA_SIZE    64
#define L4H_ATTEST_FAILED       1
#define L4H_ATTEST_NO_REPORTS   2 /* no TPM: ACT/SEAL work, reports -ENODEV */
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
	l4h_u32 state;          /* host: L4H_ATTEST_FAILED / NO_REPORTS bits */
	l4h_u32 reserved[6];
	l4h_u8 data[L4H_ATTEST_PAGE_DATA];
};

enum l4h_power {
	L4H_POWER_OFF = 0,
	L4H_POWER_REBOOT = 1,
	L4H_POWER_CRASH = 2,
};

#endif /* L4H_ABI_H */

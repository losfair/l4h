/* SPDX-License-Identifier: GPL-2.0 */
/*
 * arch/arm64/kvm's view of asm/memory.h in the l4h guest kernel: the memory
 * attribute indices and address sizes that KVM's Stage-2 code uses.  The
 * kernel's own address space is l4h's (asm/page.h).
 */
#ifndef __L4H_KVM_ASM_MEMORY_H
#define __L4H_KVM_ASM_MEMORY_H
#include <linux/const.h>
#include <linux/sizes.h>
#include <asm/page.h>

#define VA_BITS			48
#define vabits_actual		((u64)VA_BITS)
#define MT_NORMAL		0
#define MT_NORMAL_TAGGED	1
#define MT_NORMAL_NC		2
#define MT_DEVICE_nGnRnE	3
#define MT_DEVICE_nGnRE		4
#define MT_S2_NORMAL		0xf
#define MT_S2_NORMAL_NC		0x5
#define MT_S2_DEVICE_nGnRE	0x1
#define MT_S2_FWB_NORMAL	6
#define MT_S2_FWB_NORMAL_NC	5
#define MT_S2_FWB_DEVICE_nGnRE	1
#define __tag_reset(addr)	(addr)
#define __tag_set(addr, tag)	(addr)

#endif

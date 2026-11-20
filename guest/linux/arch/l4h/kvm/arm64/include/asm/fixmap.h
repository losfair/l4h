/* SPDX-License-Identifier: GPL-2.0 */
/*
 * No fixmap in the l4h guest kernel.  KVM maps a nested guest's VNCR page
 * there, and nested virtualization is not offered (no ARM64_HAS_NESTED_VIRT).
 */
#ifndef __L4H_KVM_ASM_FIXMAP_H
#define __L4H_KVM_ASM_FIXMAP_H
#include <linux/bug.h>
#include <linux/types.h>
enum fixed_addresses {
	FIX_VNCR,
	__end_of_fixed_addresses
};
static inline unsigned long fix_to_virt(unsigned int idx)
{
	BUG();
	return 0;
}
static inline void __set_fixmap(enum fixed_addresses idx, phys_addr_t phys, pgprot_t prot)
{
	BUG();
}
#define clear_fixmap(idx)	__set_fixmap(idx, 0, __pgprot(0))
#endif

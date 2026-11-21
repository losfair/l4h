/* SPDX-License-Identifier: GPL-2.0 */
/*
 * No code patching in the l4h guest kernel: an alternative is its default
 * code, and a capability test reads the capability bitmap that
 * arch/l4h/kvm/arm64 fills in from the ID registers in bootinfo.
 */
#ifndef __ASM_ALTERNATIVE_MACROS_H
#define __ASM_ALTERNATIVE_MACROS_H
#include <linux/const.h>
#include <vdso/bits.h>
#include <asm/cpucaps.h>

#define ARM64_CB_BIT	15
#define ALTINSTR_ENTRY(cpucap)
#define ALTERNATIVE(oldinstr, newinstr, ...)	oldinstr
#define ALTERNATIVE_CB(oldinstr, cpucap, cb)	oldinstr

#ifndef __ASSEMBLY__
#include <linux/types.h>
#include <linux/bitops.h>
extern unsigned long l4h_kvm_cpucaps[];

static __always_inline bool alternative_has_cap_likely(const unsigned long cpucap)
{
	return cpucap_is_possible(cpucap) && test_bit(cpucap, l4h_kvm_cpucaps);
}

static __always_inline bool alternative_has_cap_unlikely(const unsigned long cpucap)
{
	return cpucap_is_possible(cpucap) && test_bit(cpucap, l4h_kvm_cpucaps);
}
#endif

#endif

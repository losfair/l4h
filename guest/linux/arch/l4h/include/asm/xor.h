/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_UM_XOR_H
#define _ASM_UM_XOR_H

#ifdef __x86_64__

#define TT_CPU_INF_XOR_DEFAULT (AVX_SELECT(&xor_block_sse_pf64))

#include <asm/cpufeature.h>
#include <../../x86/include/asm/xor.h>
#include <linux/time-internal.h>

#ifdef CONFIG_UML_TIME_TRAVEL_SUPPORT
#undef XOR_SELECT_TEMPLATE
/* pick an arbitrary one - measuring isn't possible with inf-cpu */
#define XOR_SELECT_TEMPLATE(x)	\
	(time_travel_mode == TT_MODE_INFCPU ? TT_CPU_INF_XOR_DEFAULT : x)
#endif

#else

/*
 * AArch64: the generic C routines.  The relative include above reaches
 * arch/x86 only through x86's own include path, which an arm64 build
 * does not have.
 */
#include <asm-generic/xor.h>

#endif

#endif

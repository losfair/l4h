/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _ASM_UM_FPU_API_H
#define _ASM_UM_FPU_API_H

#include <linux/types.h>

#ifdef CONFIG_UML_ARM64

/* Copyright (c) 2020 Cambridge Greys Ltd
 * Copyright (c) 2020 Red Hat Inc.
 * A set of "dummy" defines: arm64 l4h code uses kernel_neon_begin/end
 * (asm/neon.h) instead. */
#define kernel_fpu_begin() (void)0
#define kernel_fpu_end() (void)0

static inline bool irq_fpu_usable(void)
{
	return true;
}

#else /* x86_64 */

/*
 * Kernel-mode FPU/SIMD on l4h x86_64.
 *
 * The guest kernel runs on one seL4 thread per vCPU (kTCB) and every user
 * thread has its own seL4 TCB, so seL4 keeps user FPU/SIMD state (x87, SSE,
 * AVX: KernelXSaveFeatureSet) apart from the kernel's: the vector registers
 * a kTCB sees never hold user state, and nothing has to be saved here.
 *
 * The kTCB's registers are shared by every guest kernel context that runs
 * on that vCPU: tasks switched with kernel_setjmp/longjmp, which keep no
 * vector state, and softirqs and interrupt handlers, which the guest runs
 * (it polls for events) from local_irq_enable(), local_bh_enable(),
 * preempt_enable() and the like.  A SIMD section must therefore not be
 * preempted, migrated, or entered again from softirq or hardirq context,
 * as on x86: kernel_fpu_begin() disables bottom halves (and with them
 * preemption) and marks the vCPU busy; irq_fpu_usable() is false until
 * kernel_fpu_end().  See arch/l4h/x86/fpu.c.
 */
#include <linux/bottom_half.h>
#include <asm/cpufeature.h>

/*
 * From x86's asm/fpu/types.h, which cannot be included here (it pulls in
 * x86 page and task-size definitions that clash with l4h's).
 */
#define MXCSR_DEFAULT			0x1f80
#define XFEATURE_MASK_FP		(1 << 0)
#define XFEATURE_MASK_SSE		(1 << 1)
#define XFEATURE_MASK_YMM		(1 << 2)
#define XFEATURE_MASK_OPMASK		(1 << 5)
#define XFEATURE_MASK_ZMM_Hi256		(1 << 6)
#define XFEATURE_MASK_Hi16_ZMM		(1 << 7)
#define XFEATURE_MASK_FPSSE		(XFEATURE_MASK_FP | XFEATURE_MASK_SSE)
#define XFEATURE_MASK_AVX512		(XFEATURE_MASK_OPMASK \
					 | XFEATURE_MASK_ZMM_Hi256 \
					 | XFEATURE_MASK_Hi16_ZMM)

#define KFPU_387	_BITUL(0)	/* 387 state will be initialized */
#define KFPU_MXCSR	_BITUL(1)	/* MXCSR will be initialized */

/* A KVM guest's registers may be in the kTCB's (arch/l4h/kvm/fpu.c). */
void l4h_kvm_fpu_save(void);

extern void kernel_fpu_begin_mask(unsigned int kfpu_mask);
extern void kernel_fpu_end(void);
extern bool irq_fpu_usable(void);

static inline void kernel_fpu_begin(void)
{
	/* 64-bit code that uses 387 instructions must request KFPU_387. */
	kernel_fpu_begin_mask(KFPU_MXCSR);
}

/* XSAVE state components seL4 enables in XCR0 and keeps per thread. */
extern u64 l4h_xfeatures;

static inline int cpu_has_xfeatures(u64 xfeatures_needed, const char **feature_name)
{
	if (feature_name)
		*feature_name = NULL;
	return (l4h_xfeatures & xfeatures_needed) == xfeatures_needed;
}

#endif /* CONFIG_UML_ARM64 */

#endif

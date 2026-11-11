/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_UM_BARRIER_H_
#define _ASM_UM_BARRIER_H_

#include <asm/cpufeatures.h>
#include <asm/alternative.h>

/*
 * Force strict CPU ordering.
 * And yes, this is required on UP too when we're talking
 * to devices.
 */

#define mb()	asm volatile("mfence" : : : "memory")
#define rmb()	asm volatile("lfence" : : : "memory")
#define wmb()	asm volatile("sfence" : : : "memory")

/*
 * Between CPUs, as in arch/x86/include/asm/barrier.h.  UML left these to
 * asm-generic, which builds every one of them from the fences above: an
 * MFENCE in each spin_unlock() and set_current_state(), an LFENCE in each
 * seqlock read.  A vCPU is a thread on an x86 CPU, which reorders only a
 * store with a later load: loads and stores need no instruction to stay in
 * order, a locked instruction is a full barrier, and it is cheaper than
 * MFENCE.  The host's components share the guest's memory from other
 * cores of the same machine, so the same holds towards them (dma_*, and
 * virt_*, which asm-generic takes from __smp_*).
 */
#define __dma_rmb()	barrier()
#define __dma_wmb()	barrier()

#define __smp_mb()	asm volatile("lock addl $0,-4(%%rsp)" ::: "memory", "cc")
#define __smp_rmb()	barrier()
#define __smp_wmb()	barrier()
#define __smp_store_mb(var, value) do { (void)xchg(&var, value); } while (0)

#define __smp_store_release(p, v)					\
do {									\
	compiletime_assert_atomic_type(*p);				\
	barrier();							\
	WRITE_ONCE(*p, v);						\
} while (0)

#define __smp_load_acquire(p)						\
({									\
	typeof(*p) ___p1 = READ_ONCE(*p);				\
	compiletime_assert_atomic_type(*p);				\
	barrier();							\
	___p1;								\
})

/* Atomic operations are locked instructions, which already serialize. */
#define __smp_mb__before_atomic()	do { } while (0)
#define __smp_mb__after_atomic()	do { } while (0)

#include <asm-generic/barrier.h>

#endif

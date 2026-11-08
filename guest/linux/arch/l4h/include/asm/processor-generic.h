/* SPDX-License-Identifier: GPL-2.0 */
/* 
 * Copyright (C) 2000 - 2007 Jeff Dike (jdike@{addtoit,linux.intel}.com)
 */

#ifndef __UM_PROCESSOR_GENERIC_H
#define __UM_PROCESSOR_GENERIC_H

#include <l4h_sys.h>
#include <l4h_caps.h>

struct pt_regs;

struct task_struct;

#include <asm/ptrace.h>
#include <sysdep/archsetjmp.h>

#include <linux/prefetch.h>

#include <asm/cpufeatures.h>

struct mm_struct;

struct thread_struct {
	struct pt_regs *segv_regs;
	struct task_struct *prev_sched;
	struct arch_thread arch;
	jmp_buf switch_buf;
	struct {
		struct {
			int (*proc)(void *);
			void *arg;
		} thread;
	} request;

	void *segv_continue;

	/* seL4 user context of this thread (see os-sel4/user.c) */
	struct l4h_uctx uctx;
	struct l4h_obj utcb_obj, reply_obj;
	struct mm_struct *running_mm;	/* counted in its context.l4h.running */
	u64 vs_gen;			/* VSpace generation the TCB is bound to */

	/* Contains variable sized FP registers */
	struct pt_regs regs;
};

#define INIT_THREAD \
{ \
	.regs		   	= EMPTY_REGS,	\
	.prev_sched		= NULL, \
	.arch			= INIT_ARCH_THREAD, \
	.uctx			= { .fault_ep_vcpu = -1, .sc_vcpu = -1 }, \
	.request		= { } \
}

/*
 * User space process size: 3GB (default).
 */
extern unsigned long task_size;

#define TASK_SIZE (task_size)

#undef STACK_TOP
#undef STACK_TOP_MAX

extern unsigned long stacksizelim;

#define STACK_ROOM	(stacksizelim)
/* The top of user space holds the vDSO and, on x86_64, its data pages
 * below it (arch_setup_additional_pages()).  The stack starts below that
 * area and a guard page; randomize_stack_top() only moves it further down.
 * A stack overlapping the data pages made installing them fail the exec
 * past its point of no return. */
#define L4H_VDSO_AREA	(16 * PAGE_SIZE)
#define STACK_TOP	(TASK_SIZE - L4H_VDSO_AREA - PAGE_SIZE)
#define STACK_TOP_MAX	STACK_TOP

/* This decides where the kernel will search for a free chunk of vm
 * space during mmap's.
 */
#define TASK_UNMAPPED_BASE	(0x40000000)

extern void start_thread(struct pt_regs *regs, unsigned long entry, 
			 unsigned long stack);

struct cpuinfo_um {
	unsigned long loops_per_jiffy;
	int cache_alignment;
	union {
		__u32		x86_capability[NCAPINTS + NBUGINTS];
		unsigned long	x86_capability_alignment;
	};
	/* From CPUID, for arch/x86/kvm (kvm/init.c). */
	__u8			x86;
	__u8			x86_vendor;
	__u8			x86_model;
	__u8			x86_stepping;
	__u8			x86_phys_bits;
	__u8			x86_virt_bits;
	__u8			x86_cache_bits;
	__u16			x86_power;
	__u32			extended_cpuid_level;
};

extern struct cpuinfo_um boot_cpu_data;

#define cache_line_size()	(boot_cpu_data.cache_alignment)

#define KSTK_REG(tsk, reg) get_thread_reg(reg, &tsk->thread.switch_buf)
extern unsigned long __get_wchan(struct task_struct *p);

#endif

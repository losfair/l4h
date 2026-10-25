/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_L4H_KEMU_H
#define _ASM_L4H_KEMU_H

#include <linux/personality.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <asm/prctl.h>

#include <l4h_uctx.h>

#define KEMU_ARCH_VECTOR_CACHE 1
u32 kemu_arch_read_fpu(u64 xmm[8][2]);

/*
 * l4h keeps registers in an array and the syscall number separately.
 * Keep these accessors as lvalues for assignments and swap().
 */
#define kemu_reg(regs, name) kemu_reg_##name(regs)
#define kemu_reg_ax PT_REGS_AX
#define kemu_reg_bx PT_REGS_BX
#define kemu_reg_cx PT_REGS_CX
#define kemu_reg_dx PT_REGS_DX
#define kemu_reg_si PT_REGS_SI
#define kemu_reg_di PT_REGS_DI
#define kemu_reg_bp PT_REGS_BP
#define kemu_reg_sp PT_REGS_SP
#define kemu_reg_ip PT_REGS_IP
#define kemu_reg_r8 PT_REGS_R8
#define kemu_reg_r9 PT_REGS_R9
#define kemu_reg_r10 PT_REGS_R10
#define kemu_reg_r11 PT_REGS_R11
#define kemu_reg_r12 PT_REGS_R12
#define kemu_reg_r13 PT_REGS_R13
#define kemu_reg_r14 PT_REGS_R14
#define kemu_reg_r15 PT_REGS_R15
#define kemu_reg_flags PT_REGS_EFLAGS
#define kemu_reg_orig_ax PT_REGS_SYSCALL_NR

static inline long kemu_syscall_enter(struct pt_regs *regs)
{
	/*
	 * Exit tracing belongs in the entry caller, after kemu_svc() has
	 * written the result to the emulated state (including ptrace stops).
	 */
	return syscall_trace_enter(regs) || secure_computing() ?
		-1 : kemu_reg(regs, orig_ax);
}

static inline void kemu_set_gs(unsigned long base)
{
	arch_prctl(current, ARCH_SET_GS, (unsigned long __user *)base);
}

static inline void kemu_clone_tls(struct task_struct *p, unsigned long gs,
				 bool reset_fs)
{
	struct pt_regs *regs = task_pt_regs(p);

	if (reset_fs)
		regs->regs.gp[HOST_FS_BASE] = 0;
	regs->regs.gp[HOST_GS_BASE] = gs;
	l4h_seg_dirty(p);
}

static inline long kemu_fault_trap(void)
{
	return current->thread.arch.faultinfo.trap_no;
}

static inline unsigned long kemu_fault_address(void)
{
	return current->thread.arch.faultinfo.cr2;
}

static inline unsigned long kemu_fault_error(void)
{
	return current->thread.arch.faultinfo.error_code;
}

static inline void kemu_set_personality(void)
{
	set_personality(PER_LINUX);
}

#endif

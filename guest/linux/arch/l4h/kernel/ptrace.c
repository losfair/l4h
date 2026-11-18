// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2000 - 2007 Jeff Dike (jdike@{addtoit,linux.intel}.com)
 */

#include <linux/kemu.h>
#include <linux/audit.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <asm/ptrace-abi.h>
#include <l4h_uctx.h>

#define CREATE_TRACE_POINTS
#include <trace/events/syscalls.h>

void user_enable_single_step(struct task_struct *child)
{
#ifdef CONFIG_KEMU
	if (task_is_kemu(child)) {
		kemu_user_step(child, true);
		return;
	}
#endif
	set_tsk_thread_flag(child, TIF_SINGLESTEP);

#ifdef SUBARCH_SET_SINGLESTEPPING
	SUBARCH_SET_SINGLESTEPPING(child, 1);
#endif
}

void user_disable_single_step(struct task_struct *child)
{
#ifdef CONFIG_KEMU
	if (task_is_kemu(child)) {
		kemu_user_step(child, false);
		return;
	}
#endif
	clear_tsk_thread_flag(child, TIF_SINGLESTEP);

#ifdef SUBARCH_SET_SINGLESTEPPING
	SUBARCH_SET_SINGLESTEPPING(child, 0);
#endif
}

/*
 * Called by kernel/ptrace.c when detaching..
 */
void ptrace_disable(struct task_struct *child)
{
	user_disable_single_step(child);
}

long arch_ptrace(struct task_struct *child, long request,
		 unsigned long addr, unsigned long data)
{
	int i, ret;
	unsigned long __user *p = (void __user *)data;
	void __user *vp = p;

	if (request == PTRACE_SYSEMU_SINGLESTEP)
		return -EIO;

#ifdef CONFIG_KEMU
	if (task_is_kemu(child))
		return kemu_arch_ptrace(child, request, addr, data);
#endif

	switch (request) {
	case PTRACE_SINGLESTEP:
		/* Hardware single-step remains unavailable for native tasks. */
		return -EIO;
	/* read the word at location addr in the USER area. */
	case PTRACE_PEEKUSR:
		ret = peek_user(child, addr, data);
		break;

	/* write the word at location addr in the USER area */
	case PTRACE_POKEUSR:
		ret = poke_user(child, addr, data);
		break;

	/*
	 * The whole set, as the regset (genregs_get/genregs_set) and x86's
	 * copy_regset_*_user() do it: from the registers as they are (read
	 * from the TCB if they are only there), and with the first
	 * error, a fault on the buffer or a value putreg() refuses (a
	 * selector, or a base past user space), not success.  The registers
	 * before it are set.
	 */
#ifdef PTRACE_GETREGS
	case PTRACE_GETREGS: { /* Get all gp regs from the child. */
		if (!access_ok(p, MAX_REG_OFFSET)) {
			ret = -EIO;
			break;
		}
		l4h_sync_regs(child);
		l4h_sync_seg(child);
		for (i = 0, ret = 0; i < MAX_REG_OFFSET && !ret; i += sizeof(long))
			ret = __put_user(getreg(child, i), p++);
		break;
	}
#endif
#ifdef PTRACE_SETREGS
	case PTRACE_SETREGS: { /* Set all gp regs in the child. */
		unsigned long tmp = 0;
		if (!access_ok(p, MAX_REG_OFFSET)) {
			ret = -EIO;
			break;
		}
		l4h_sync_regs(child);
		l4h_sync_seg(child);
		l4h_seg_dirty(child);
		for (i = 0, ret = 0; i < MAX_REG_OFFSET && !ret; i += sizeof(long)) {
			ret = __get_user(tmp, p++);
			if (!ret)
				ret = putreg(child, i, tmp);
		}
		break;
	}
#endif
	case PTRACE_GET_THREAD_AREA:
		ret = ptrace_get_thread_area(child, addr, vp);
		break;

	case PTRACE_SET_THREAD_AREA:
		ret = ptrace_set_thread_area(child, addr, vp);
		break;

	default:
		ret = ptrace_request(child, request, addr, data);
		if (ret == -EIO)
			ret = subarch_ptrace(child, request, addr, data);
		break;
	}

	return ret;
}

static void send_sigtrap(struct uml_pt_regs *regs, int error_code)
{
	/* Send us the fake SIGTRAP */
	force_sig_fault(SIGTRAP, TRAP_BRKPT,
			/* User-mode eip? */
			UPT_IS_USER(regs) ? (void __user *) UPT_IP(regs) : NULL);
}

/*
 * XXX Check TIF_SINGLESTEP for singlestepping check and
 * PT_PTRACED vs TIF_SYSCALL_TRACE for syscall tracing check
 */
int syscall_trace_enter(struct pt_regs *regs)
{
	unsigned long flags = read_thread_flags();

	/* The tracer first, as in generic entry: the tracepoint and audit see
	 * the syscall it may have changed, and none it skipped. */
	if (flags & (_TIF_SYSCALL_TRACE | _TIF_SYSCALL_EMU)) {
		int ret = ptrace_report_syscall_entry(regs);

		/* Use the flags from before the stop: this syscall stays skipped
		 * even if the tracer resumes with CONT, SYSCALL or DETACH. */
		if (ret || (flags & _TIF_SYSCALL_EMU))
			return 1;
	}

	if (test_thread_flag(TIF_SYSCALL_TRACEPOINT))
		trace_sys_enter(regs, UPT_SYSCALL_NR(&regs->regs));

	audit_syscall_entry(UPT_SYSCALL_NR(&regs->regs),
			    UPT_SYSCALL_ARG1(&regs->regs),
			    UPT_SYSCALL_ARG2(&regs->regs),
			    UPT_SYSCALL_ARG3(&regs->regs),
			    UPT_SYSCALL_ARG4(&regs->regs));
	return 0;
}

void syscall_trace_leave(struct pt_regs *regs)
{
	int ptraced = current->ptrace;

	audit_syscall_exit(regs);

	/* Fake a debug trap */
	if (test_thread_flag(TIF_SINGLESTEP))
		send_sigtrap(&regs->regs, 0);

	if (test_thread_flag(TIF_SYSCALL_TRACEPOINT))
		trace_sys_exit(regs, PT_REGS_SYSCALL_RET(regs));

	if (!test_thread_flag(TIF_SYSCALL_TRACE))
		return;

	ptrace_report_syscall_exit(regs, 0);
	/* force do_signal() --> is_syscall() */
	if (ptraced & PT_PTRACED)
		set_thread_flag(TIF_SIGPENDING);
}

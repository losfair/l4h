// SPDX-License-Identifier: GPL-2.0
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <asm/ptrace-abi.h>
#include <l4h_uctx.h>

void clear_flushed_tls(struct task_struct *task)
{
}

int arch_set_tls(struct task_struct *t, unsigned long tls)
{
	/*
	 * If CLONE_SETTLS is set, we need to save the thread id
	 * so it can be set during context switches.  As on x86
	 * (do_arch_prctl_64, which its CLONE_SETTLS takes), not a base
	 * past user space: seL4 would make it 0, and the child's fs base
	 * would differ from what ARCH_GET_FS and ptrace say.
	 */
	if (tls >= TASK_SIZE_MAX)
		return -EPERM;
	t->thread.regs.regs.gp[FS_BASE / sizeof(unsigned long)] = tls;
	l4h_seg_dirty(t);

	return 0;
}

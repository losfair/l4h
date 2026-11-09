/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __UM_ASM_SYSCALL_H
#define __UM_ASM_SYSCALL_H

#include <asm/syscall-generic.h>
#include <uapi/linux/audit.h>
#include <linux/kemu.h>

typedef asmlinkage long (*sys_call_ptr_t)(unsigned long, unsigned long,
					  unsigned long, unsigned long,
					  unsigned long, unsigned long);

extern const sys_call_ptr_t sys_call_table[];

static inline int syscall_get_arch(struct task_struct *task)
{
	if (task_is_kemu(task))
		return AUDIT_ARCH_AARCH64;
	return AUDIT_ARCH_X86_64;
}

#endif /* __UM_ASM_SYSCALL_H */

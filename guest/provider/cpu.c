/* SPDX-License-Identifier: GPL-2.0 */
#include "private.h"

void l4h_provider_init_cpu(void)
{
	__sel4_ipc_buffer = l4h_this_vcpu()->ipcbuf;
}

int l4h_start_vcpu(int cpu, unsigned long sp, void (*fn)(int cpu), void *task)
{
	struct l4h_vcpu *v = &l4h_vcpus[cpu];
	seL4_UserContext regs = { 0 };

	if (cpu <= 0 || (unsigned long)cpu >= l4h_bootinfo->nr_vcpus)
		return -1;
	v->start_task = task;
	v->start_fn = fn;
	v->start_sp = sp;
#ifdef __aarch64__
	regs.pc = (seL4_Word)l4h_provider_state()->secondary_entry;
	regs.sp = sp;
	regs.x0 = cpu;
#else
	regs.rip = (seL4_Word)l4h_provider_state()->secondary_entry;
	regs.rsp = sp;
	regs.rdi = cpu;
#endif
	return seL4_TCB_WriteRegisters(v->ktcb, 1, 0, sizeof(regs) / sizeof(seL4_Word), &regs);
}

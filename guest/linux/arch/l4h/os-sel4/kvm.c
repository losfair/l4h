// SPDX-License-Identifier: GPL-2.0
/*
 * seL4 VCPUs and EPT, for arch/l4h/kvm (x86_64).
 */
#include "l4h_os.h"
#include <sel4/arch/vmenter.h>

int l4h_vcpu_set_tcb(unsigned long vcpu, unsigned long tcb)
{
	return seL4_X86_VCPU_SetTCB(vcpu, tcb);
}

int l4h_tcb_set_ept(unsigned long tcb, unsigned long ept)
{
	return seL4_TCB_SetEPTRoot(tcb, ept);
}

unsigned long l4h_vcpu_read(unsigned long vcpu, unsigned long field, int *err)
{
	seL4_X86_VCPU_ReadVMCS_t r = seL4_X86_VCPU_ReadVMCS(vcpu, field);

	*err = r.error;
	return r.value;
}

int l4h_vcpu_write(unsigned long vcpu, unsigned long field, unsigned long value)
{
	return seL4_X86_VCPU_WriteVMCS(vcpu, field, value).error;
}

int l4h_vcpu_read_msr(unsigned long vcpu, unsigned long msr, unsigned long *value)
{
	seL4_X86_VCPU_ReadMSR_t r = seL4_X86_VCPU_ReadMSR(vcpu, msr);

	*value = r.value;
	return r.error;
}

int l4h_vcpu_write_msr(unsigned long vcpu, unsigned long msr, unsigned long value)
{
	return seL4_X86_VCPU_WriteMSR(vcpu, msr, value).error;
}

int l4h_vcpu_write_cr2(unsigned long vcpu, unsigned long value)
{
	return l4h_vcpu_write_msr(vcpu, SEL4_VCPU_MSR_CR2, value);
}

int l4h_vcpu_write_xcr0(unsigned long vcpu, unsigned long long value)
{
	return l4h_vcpu_write_msr(vcpu, SEL4_VCPU_MSR_XCR0, value);
}

int l4h_vcpu_flush_tlb(unsigned long vcpu)
{
	return seL4_X86_VCPU_FlushTLB(vcpu);
}

int l4h_vcpu_write_regs(unsigned long vcpu, const unsigned long *gp)
{
	seL4_VCPUContext c = {
		.eax = gp[L4H_VMX_RAX], .ebx = gp[L4H_VMX_RBX], .ecx = gp[L4H_VMX_RCX],
		.edx = gp[L4H_VMX_RDX], .esi = gp[L4H_VMX_RSI], .edi = gp[L4H_VMX_RDI],
		.ebp = gp[L4H_VMX_RBP], .r8 = gp[L4H_VMX_R8], .r9 = gp[L4H_VMX_R9],
		.r10 = gp[L4H_VMX_R10], .r11 = gp[L4H_VMX_R11], .r12 = gp[L4H_VMX_R12],
		.r13 = gp[L4H_VMX_R13], .r14 = gp[L4H_VMX_R14], .r15 = gp[L4H_VMX_R15],
	};

	return seL4_X86_VCPU_WriteRegisters(vcpu, &c);
}

/* Run the VCPU bound to this kTCB until a fault or a notification. */
void l4h_vcpu_enter(struct l4h_vmexit *x, unsigned long rip, unsigned long controls,
		    unsigned long intr_info)
{
	struct l4h_vcpu *v = l4h_this_vcpu();
	seL4_Word badge = 0;
	int i;

	seL4_SetMR(SEL4_VMENTER_CALL_EIP_MR, rip);
	seL4_SetMR(SEL4_VMENTER_CALL_CONTROL_PPC_MR, controls);
	seL4_SetMR(SEL4_VMENTER_CALL_INTERRUPT_INFO_MR, intr_info);
	x->fault = seL4_VMEnter(&badge) == SEL4_VMENTER_RESULT_FAULT;
	if (!x->fault)
		__atomic_or_fetch(&v->ntfn_pending, badge, __ATOMIC_RELEASE);
	x->rip = seL4_GetMR(SEL4_VMENTER_CALL_EIP_MR);
	x->intr_info = seL4_GetMR(SEL4_VMENTER_CALL_INTERRUPT_INFO_MR);
	x->reason = seL4_GetMR(SEL4_VMENTER_FAULT_REASON_MR);
	x->qualification = seL4_GetMR(SEL4_VMENTER_FAULT_QUALIFICATION_MR);
	x->instr_len = seL4_GetMR(SEL4_VMENTER_FAULT_INSTRUCTION_LEN_MR);
	x->gpa = seL4_GetMR(SEL4_VMENTER_FAULT_GUEST_PHYSICAL_MR);
	x->rflags = seL4_GetMR(SEL4_VMENTER_FAULT_RFLAGS_MR);
	x->interruptibility = seL4_GetMR(SEL4_VMENTER_FAULT_GUEST_INT_MR);
	for (i = 0; i < 15; i++)
		x->gp[i] = seL4_GetMR(SEL4_VMENTER_FAULT_EAX + i);
	x->exit_intr_info = seL4_GetMR(SEL4_VMENTER_FAULT_EXIT_INTR_INFO);
	x->exit_intr_error = seL4_GetMR(SEL4_VMENTER_FAULT_EXIT_INTR_ERROR);
	x->idt_vector_info = seL4_GetMR(SEL4_VMENTER_FAULT_IDT_VECTOR_INFO);
	x->idt_vector_error = seL4_GetMR(SEL4_VMENTER_FAULT_IDT_VECTOR_ERROR);
	x->cr2 = seL4_GetMR(SEL4_VMENTER_FAULT_CR2);
}

int l4h_ept_map_table(int level, unsigned long table, unsigned long ept, unsigned long gpa)
{
	switch (level) {
	case 0:
		return seL4_X86_EPTPT_Map(table, ept, gpa, seL4_X86_EPT_Default_VMAttributes);
	case 1:
		return seL4_X86_EPTPD_Map(table, ept, gpa, seL4_X86_EPT_Default_VMAttributes);
	case 2:
		return seL4_X86_EPTPDPT_Map(table, ept, gpa, seL4_X86_EPT_Default_VMAttributes);
	}
	return seL4_InvalidArgument;
}

int l4h_ept_map_frame(unsigned long frame, unsigned long ept, unsigned long gpa, int writable)
{
	return seL4_X86_Page_MapEPT(frame, ept, gpa, writable ? seL4_ReadWrite : seL4_CanRead,
				    seL4_X86_EPT_Default_VMAttributes);
}

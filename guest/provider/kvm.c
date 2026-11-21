// SPDX-License-Identifier: GPL-2.0
/*
 * seL4 VCPUs and EPT, for arch/l4h/kvm (x86_64), and FL4 VCPUs and
 * Stage-2 (AArch64).
 */
#include "private.h"
#if defined(__x86_64__) && defined(CONFIG_VTX)
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

int l4h_vcpu_read_vmcb(unsigned long vcpu, unsigned long offset, unsigned long count,
		       unsigned long *words)
{
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(X86VCPUReadVMCB, 0, 0, 2);
	unsigned long i;

	seL4_SetMR(0, offset);
	seL4_SetMR(1, count);
	tag = seL4_Call(vcpu, tag);
	if (seL4_MessageInfo_get_label(tag))
		return seL4_MessageInfo_get_label(tag);
	for (i = 0; i < count; i++)
		words[i] = seL4_GetMR(i);
	return 0;
}

int l4h_vcpu_write_vmcb(unsigned long vcpu, unsigned long offset, unsigned long value,
			unsigned long *written)
{
	seL4_X86_VCPU_WriteVMCB_t r = seL4_X86_VCPU_WriteVMCB(vcpu, offset, value);

	*written = r.written;
	return r.error;
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
	x->cr3 = seL4_GetMR(SEL4_VMENTER_FAULT_CR3_MR);
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

#else
/* Every slot exists, including on providers without nested virtualization. */

int l4h_vcpu_set_tcb(unsigned long vcpu, unsigned long tcb)
{
	(void)vcpu;
	(void)tcb;
	return seL4_IllegalOperation;
}

int l4h_tcb_set_ept(unsigned long tcb, unsigned long ept)
{
	(void)tcb;
	(void)ept;
	return seL4_IllegalOperation;
}

unsigned long l4h_vcpu_read(unsigned long vcpu, unsigned long field, int *err)
{
	(void)vcpu;
	(void)field;
	(void)err;
	*err = seL4_IllegalOperation;
	return 0;
}

int l4h_vcpu_write(unsigned long vcpu, unsigned long field, unsigned long value)
{
	(void)vcpu;
	(void)field;
	(void)value;
	return seL4_IllegalOperation;
}

int l4h_vcpu_read_msr(unsigned long vcpu, unsigned long msr, unsigned long *value)
{
	(void)vcpu;
	(void)msr;
	(void)value;
	return seL4_IllegalOperation;
}

int l4h_vcpu_write_msr(unsigned long vcpu, unsigned long msr, unsigned long value)
{
	(void)vcpu;
	(void)msr;
	(void)value;
	return seL4_IllegalOperation;
}

int l4h_vcpu_write_cr2(unsigned long vcpu, unsigned long value)
{
	(void)vcpu;
	(void)value;
	return seL4_IllegalOperation;
}

int l4h_vcpu_write_xcr0(unsigned long vcpu, unsigned long long value)
{
	(void)vcpu;
	(void)value;
	return seL4_IllegalOperation;
}

int l4h_vcpu_flush_tlb(unsigned long vcpu)
{
	(void)vcpu;
	return seL4_IllegalOperation;
}

int l4h_vcpu_read_vmcb(unsigned long vcpu, unsigned long offset, unsigned long count, unsigned long *words)
{
	(void)vcpu;
	(void)offset;
	(void)count;
	(void)words;
	return seL4_IllegalOperation;
}

int l4h_vcpu_write_vmcb(unsigned long vcpu, unsigned long offset, unsigned long value, unsigned long *written)
{
	(void)vcpu;
	(void)offset;
	(void)value;
	(void)written;
	return seL4_IllegalOperation;
}

int l4h_vcpu_write_regs(unsigned long vcpu, const unsigned long *gp)
{
	(void)vcpu;
	(void)gp;
	return seL4_IllegalOperation;
}

void l4h_vcpu_enter(struct l4h_vmexit *x, unsigned long rip, unsigned long controls, unsigned long intr_info)
{
	(void)x;
	(void)rip;
	(void)controls;
	(void)intr_info;
	panic("l4h: ABI provider does not support nested KVM\n");
}

int l4h_ept_map_table(int level, unsigned long table, unsigned long ept, unsigned long gpa)
{
	(void)level;
	(void)table;
	(void)ept;
	(void)gpa;
	return seL4_IllegalOperation;
}

int l4h_ept_map_frame(unsigned long frame, unsigned long ept, unsigned long gpa, int writable)
{
	(void)frame;
	(void)ept;
	(void)gpa;
	(void)writable;
	return seL4_IllegalOperation;
}

#endif

/*
 * FL4 VCPUs and Stage-2 (AArch64 at EL2), for arch/l4h/kvm on arm64.
 *
 * A VM's vCPU is a TCB of the guest kernel's, bound to a VCPU and with a
 * Stage-2 root (L4H_SLOT_EPT_POOL) as its VSpace.  It runs like a user
 * context (user.c): this vCPU's kernel thread lends it SC_U and receives
 * its faults on the vCPU endpoint, through the badged fault endpoint in
 * u->fault_ep.  Its registers are the VCPU's (l4h_arm_vcpu_write_state),
 * never gp[].
 */
#ifdef L4H_ARM_VIRT

int l4h_arm_vcpu_set_tcb(unsigned long vcpu, unsigned long tcb)
{
	return seL4_ARM_VCPU_SetTCB(vcpu, tcb);
}

int l4h_arm_vcpu_read_reg(unsigned long vcpu, unsigned long field, unsigned long *val)
{
	seL4_ARM_VCPU_ReadRegs_t r = seL4_ARM_VCPU_ReadRegs(vcpu, field);

	*val = r.error ? 0 : r.value;
	return r.error;
}

int l4h_arm_vcpu_write_reg(unsigned long vcpu, unsigned long field, unsigned long val)
{
	return seL4_ARM_VCPU_WriteRegs(vcpu, field, val);
}

int l4h_arm_vcpu_inject_irq(unsigned long vcpu, unsigned int virq, unsigned int prio,
			    unsigned int group, unsigned int index)
{
	/* The invocation's narrow fields would truncate silently. */
	if (virq > 0xffff || prio > 0xff || group > 0xff || index > 0xff)
		return seL4_RangeError;
	return seL4_ARM_VCPU_InjectIRQ(vcpu, virq, prio, group, index);
}

int l4h_arm_vcpu_ack_vppi(unsigned long vcpu, unsigned long irq)
{
	return seL4_ARM_VCPU_AckVPPI(vcpu, irq);
}

int l4h_arm_vcpu_read_state(unsigned long vcpu, unsigned long frame, unsigned long offset,
			    unsigned long mask)
{
	return seL4_ARM_VCPU_ReadState(vcpu, frame, offset, mask);
}

int l4h_arm_vcpu_write_state(unsigned long vcpu, unsigned long frame, unsigned long offset,
			     unsigned long mask)
{
	return seL4_ARM_VCPU_WriteState(vcpu, frame, offset, mask);
}

int l4h_arm_vcpu_read_state_self(unsigned long vcpu, unsigned long mask)
{
	struct l4h_vcpu *v = l4h_this_vcpu();

	return seL4_ARM_VCPU_ReadState(vcpu, VCPU_CAP(v->id, L4H_VCPU_IPCBUF),
				       L4H_VCPU_STATE_OFFSET, mask);
}

int l4h_arm_s2_map_table(unsigned long table, unsigned long s2_root, unsigned long ipa)
{
	return seL4_ARM_PageTable_Map(table, s2_root, ipa, seL4_ARM_Default_VMAttributes);
}

int l4h_arm_s2_map_frame(unsigned long frame, unsigned long s2_root, unsigned long ipa, int prot)
{
	seL4_CapRights_t r = (prot & L4H_PROT_WRITE) ? seL4_ReadWrite :
			     (prot & (L4H_PROT_READ | L4H_PROT_EXEC)) ? seL4_CanRead : seL4_NoRights;
	seL4_ARM_VMAttributes attr = ((prot & L4H_PROT_DEVICE) ? 0 : seL4_ARM_PageCacheable) |
				     ((prot & L4H_PROT_EXEC) ? 0 : seL4_ARM_ExecuteNever);
	int err = seL4_ARM_Page_Map(frame, s2_root, ipa, r, attr);

	/* The guest fetches what its host wrote through the data side; with
	 * CTR_EL0.IDC and DIC the hardware keeps them coherent itself. */
	if (!err && (prot & L4H_PROT_EXEC) && !(prot & L4H_PROT_DEVICE) &&
	    (l4h_bootinfo->arm_virt.ctr_el0 & (3ull << 28)) != (3ull << 28))
		err = seL4_ARM_Page_Unify_Instruction(frame, 0, (prot & L4H_PROT_LARGE) ? 1ul << 21 : 4096);
	return err;
}

_Static_assert(L4H_VCPU_STATE_OFFSET >= L4H_FPU_SCRATCH_OFFSET + seL4_FPUStateSize,
	       "VCPU state overlaps FPU scratch");
_Static_assert(L4H_VCPU_STATE_OFFSET + sizeof(struct l4h_arm_vcpu_state) <= (1ul << seL4_PageBits),
	       "VCPU state must fit in IPC buffer frame");
_Static_assert(L4H_VCPU_STATE_OFFSET % 64 == 0, "VCPU state alignment");

int l4h_arm_vcpu_enter(unsigned long vcpu, unsigned long in_mask, unsigned long out_mask,
		       struct l4h_arm_vmexit *x)
{
	seL4_ARM_VCPU_Run_t r = seL4_ARM_VCPU_Run(vcpu, L4H_VCPU_STATE_OFFSET, in_mask, out_mask);

	*x = (struct l4h_arm_vmexit){ 0 };
	if (r.error) {
		x->stop = L4H_ARM_STOP_OTHER;
		return x->stop;
	}
	switch (r.stop) {
	case seL4_ARM_VCPURunStop_Interrupt:
		/* The events that stopped it, taken off the notification. */
		if (r.w1)
			__atomic_or_fetch(&l4h_this_vcpu()->ntfn_pending, r.w1, __ATOMIC_RELEASE);
		x->stop = L4H_ARM_STOP_INTERRUPT;
		break;
	case seL4_ARM_VCPURunStop_VMFault:
		x->stop = L4H_ARM_STOP_VMFAULT;
		x->esr = r.w1;
		x->ipa = r.w2;
		x->far = r.w3;
		x->is_prefetch = (r.w1 >> 26) == 0x20;
		break;
	case seL4_ARM_VCPURunStop_VCPUFault:
		x->stop = L4H_ARM_STOP_VCPUFAULT;
		x->esr = r.w1;
		x->far = r.w2;
		x->hpfar = r.w3;
		break;
	case seL4_ARM_VCPURunStop_VGICMaint:
		x->stop = L4H_ARM_STOP_VGIC_MAINT;
		if (r.w1) {
			x->vgic_idx_valid = 1;
			x->vgic_idx = (unsigned int)__builtin_ctzll(r.w1);
		}
		break;
	case seL4_ARM_VCPURunStop_VPPI:
		x->stop = L4H_ARM_STOP_VPPI;
		x->vppi_irq = r.w1;
		break;
	default:
		x->stop = L4H_ARM_STOP_OTHER;
		break;
	}
	return x->stop;
}

int l4h_arm_vcpu_run(struct l4h_uctx *u, struct l4h_arm_vmexit *x)
{
	struct l4h_vcpu *v = l4h_this_vcpu();
	seL4_MessageInfo_t info;
	seL4_Word badge;
	unsigned long len;

	l4h_BUG_ON(u->fault_ep_vcpu != v->id);
	l4h_bind_sc(v, u);
	switch (u->state) {
	case L4H_UCTX_FRESH:
		/* Its registers are the VCPU's, written beforehand. */
		l4h_BUG_ON(seL4_TCB_Resume(u->tcb));
		info = seL4_Recv(v->ep, &badge, u->reply);
		break;
	case L4H_UCTX_PREEMPTED:
		/* A fault it raises before we block here is queued on the
		 * endpoint and received now. */
		info = seL4_Recv(v->ep, &badge, u->reply);
		break;
	case L4H_UCTX_FAULTED:
		info = seL4_ReplyRecv(v->ep, seL4_MessageInfo_new(0, 0, 0, 0), &badge, u->reply);
		break;
	default:
		panic("l4h_arm_vcpu_run: bad uctx state %d\n", u->state);
	}

	*x = (struct l4h_arm_vmexit){ 0 };
	if (!(badge & L4H_EP_BADGE_TASK)) {
		/* An event preempted the guest: as in l4h_user_run(), take
		 * SC_U away now, and collect a fault queued meanwhile. */
		__atomic_or_fetch(&v->ntfn_pending, badge, __ATOMIC_RELEASE);
		l4h_user_deschedule(u);
		for (;;) {
			badge = 0;
			info = seL4_NBRecv(v->ep, &badge, u->reply);
			if (!badge || (badge & L4H_EP_BADGE_TASK))
				break;
			__atomic_or_fetch(&v->ntfn_pending, badge, __ATOMIC_RELEASE);
		}
		if (!(badge & L4H_EP_BADGE_TASK)) {
			u->state = L4H_UCTX_PREEMPTED;
			u->stop = L4H_STOP_INTERRUPT;
			x->stop = L4H_ARM_STOP_INTERRUPT;
			return x->stop;
		}
		/* Report the fault now; the event stays in ntfn_pending. */
	}
	if (badge != u->badge)
		panic("l4h: VM fault from unexpected context %lx (running %lx)\n",
		      (unsigned long)badge, u->badge);

	u->state = L4H_UCTX_FAULTED;
	len = seL4_MessageInfo_get_length(info);
	switch (seL4_MessageInfo_get_label(info)) {
	case seL4_Fault_VMFault:
		x->stop = L4H_ARM_STOP_VMFAULT;
		x->fault_ip = seL4_GetMR(seL4_VMFault_IP);
		x->ipa = seL4_GetMR(seL4_VMFault_Addr);
		x->is_prefetch = !!seL4_GetMR(seL4_VMFault_PrefetchFault);
		x->esr = seL4_GetMR(seL4_VMFault_FSR);
		break;
	case seL4_Fault_VCPUFault:
		x->stop = L4H_ARM_STOP_VCPUFAULT;
		x->esr = seL4_GetMR(seL4_VCPUFault_HSR);
		break;
	case seL4_Fault_VGICMaintenance:
		x->stop = L4H_ARM_STOP_VGIC_MAINT;
		x->vgic_idx_valid = len >= 1;
		x->vgic_idx = len >= 1 ? seL4_GetMR(seL4_VGICMaintenance_IDX) : 0;
		break;
	case seL4_Fault_VPPIEvent:
		x->stop = L4H_ARM_STOP_VPPI;
		x->vppi_irq = seL4_GetMR(seL4_VPPIEvent_IRQ);
		break;
	default:
		x->stop = L4H_ARM_STOP_OTHER;
		break;
	}
	u->stop = L4H_STOP_EXCEPTION;
	return x->stop;
}

#else
/* Every slot exists, including on providers without FL4's EL2 VCPUs. */

int l4h_arm_vcpu_set_tcb(unsigned long vcpu, unsigned long tcb)
{
	(void)vcpu;
	(void)tcb;
	return seL4_IllegalOperation;
}

int l4h_arm_vcpu_read_reg(unsigned long vcpu, unsigned long field, unsigned long *val)
{
	(void)vcpu;
	(void)field;
	*val = 0;
	return seL4_IllegalOperation;
}

int l4h_arm_vcpu_write_reg(unsigned long vcpu, unsigned long field, unsigned long val)
{
	(void)vcpu;
	(void)field;
	(void)val;
	return seL4_IllegalOperation;
}

int l4h_arm_vcpu_inject_irq(unsigned long vcpu, unsigned int virq, unsigned int prio,
			    unsigned int group, unsigned int index)
{
	(void)vcpu;
	(void)virq;
	(void)prio;
	(void)group;
	(void)index;
	return seL4_IllegalOperation;
}

int l4h_arm_vcpu_ack_vppi(unsigned long vcpu, unsigned long irq)
{
	(void)vcpu;
	(void)irq;
	return seL4_IllegalOperation;
}

int l4h_arm_vcpu_read_state(unsigned long vcpu, unsigned long frame, unsigned long offset,
			    unsigned long mask)
{
	(void)vcpu;
	(void)frame;
	(void)offset;
	(void)mask;
	return seL4_IllegalOperation;
}

int l4h_arm_vcpu_write_state(unsigned long vcpu, unsigned long frame, unsigned long offset,
			     unsigned long mask)
{
	(void)vcpu;
	(void)frame;
	(void)offset;
	(void)mask;
	return seL4_IllegalOperation;
}

int l4h_arm_vcpu_read_state_self(unsigned long vcpu, unsigned long mask)
{
	(void)vcpu;
	(void)mask;
	return seL4_IllegalOperation;
}

int l4h_arm_s2_map_table(unsigned long table, unsigned long s2_root, unsigned long ipa)
{
	(void)table;
	(void)s2_root;
	(void)ipa;
	return seL4_IllegalOperation;
}

int l4h_arm_s2_map_frame(unsigned long frame, unsigned long s2_root, unsigned long ipa, int prot)
{
	(void)frame;
	(void)s2_root;
	(void)ipa;
	(void)prot;
	return seL4_IllegalOperation;
}

int l4h_arm_vcpu_run(struct l4h_uctx *u, struct l4h_arm_vmexit *x)
{
	(void)u;
	(void)x;
	panic("l4h: ABI provider does not support AArch64 KVM\n");
}

int l4h_arm_vcpu_enter(unsigned long vcpu, unsigned long in_mask, unsigned long out_mask,
		       struct l4h_arm_vmexit *x)
{
	(void)vcpu;
	(void)in_mask;
	(void)out_mask;
	(void)x;
	panic("l4h: ABI provider does not support AArch64 KVM\n");
}

#endif

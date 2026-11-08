// SPDX-License-Identifier: GPL-2.0
/*
 * KVM's vendor backend for the l4h guest kernel: kvm_x86_ops on seL4 VCPUs
 * (DESIGN.md §5.10).
 *
 * The role of arch/x86/kvm/vmx/vmx.c, without VMX instructions: the guest
 * kernel runs in ring 3, seL4 holds the VMCS, and each read or write of a
 * field is a system call.  So guest state comes with the exit where it can
 * (struct l4h_vmexit), reads go through a small cache that lives until the
 * next VM entry, and the kTCB of the current L4H vCPU runs the guest with
 * seL4_VMEnter: an exit is that call returning, and a notification (timer,
 * IPI, device) ends it the same way, as an external interrupt would.
 *
 * Left out, because seL4's VCPU interface has no way to do them: APICv and
 * posted interrupts, PML, nested VMX, AVX-512 and other state outside XCR0
 * in seL4, and the performance counters.  CR0, CR4 and the debug registers
 * always exit, and hardware breakpoints in the guest do not fire.
 */
/* compat.h has the one of arch/x86/kvm. */
#undef pr_fmt
#define pr_fmt(fmt) "l4h-kvm: " fmt

#include <linux/kvm_host.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/percpu.h>
#include <asm/vmx.h>
#include <l4h_sys.h>
#include "cpuid.h"
#include "kvm_cache_regs.h"
#include "lapic.h"
#include "mmu.h"
#include "mmu/spte.h"
#include "pmu.h"
#include "x86.h"
#include "kvm_emulate.h"
#include "l4h_kvm.h"

#define VMCS_CACHE_SIZE 64


struct vmcs_cached {
	u32 field;
	u32 gen;
	unsigned long value;
};

struct vcpu_l4h {
	struct kvm_vcpu vcpu;
	struct l4h_obj obj;
	u64 id;
	int bound_cpu;		/* the vCPU whose kTCB it is bound to, or -1 */

	struct vmcs_cached cache[VMCS_CACHE_SIZE];
	u32 gen;

	/* Controls, as we last wrote them. */
	u32 exec_control, entry_control;
	u32 exception_bitmap;

	/* The event for the next VM entry. */
	u32 entry_intr, entry_error, entry_len;

	struct l4h_vmexit x;
	unsigned long rflags, hw_cr2;
	/* What seL4 has of the general-purpose registers. */
	unsigned long hw_gp[L4H_VMX_NR_GP];
};

static inline struct vcpu_l4h *to_l4h(struct kvm_vcpu *vcpu)
{
	return container_of(vcpu, struct vcpu_l4h, vcpu);
}

static inline unsigned long cap(struct kvm_vcpu *vcpu)
{
	return to_l4h(vcpu)->obj.cptr;
}

/* ---- the VMCS */

static unsigned long vmcs_rd(struct kvm_vcpu *vcpu, u32 field)
{
	struct vcpu_l4h *l = to_l4h(vcpu);
	struct vmcs_cached *c = &l->cache[(field ^ (field >> 8)) % VMCS_CACHE_SIZE];
	int err;

	if (c->field == field && c->gen == l->gen)
		return c->value;
	c->value = l4h_vcpu_read(l->obj.cptr, field, &err);
	WARN_ONCE(err, "l4h-kvm: read of VMCS field %x: %d\n", field, err);
	c->field = field;
	c->gen = l->gen;
	return c->value;
}

static void vmcs_wr(struct kvm_vcpu *vcpu, u32 field, unsigned long value)
{
	struct vcpu_l4h *l = to_l4h(vcpu);
	struct vmcs_cached *c = &l->cache[(field ^ (field >> 8)) % VMCS_CACHE_SIZE];
	int err = l4h_vcpu_write(l->obj.cptr, field, value);

	WARN_ONCE(err, "l4h-kvm: write of VMCS field %x: %d\n", field, err);
	/* seL4 may have adjusted it to the CPU's fixed bits. */
	if (c->field == field)
		c->gen = l->gen - 1;
}

/* ---- segments */

static const struct {
	u32 selector, base, limit, ar;
} seg_fields[] = {
#define SEG(s, S) [VCPU_SREG_##S] = { GUEST_##S##_SELECTOR, GUEST_##S##_BASE, \
				      GUEST_##S##_LIMIT, GUEST_##S##_AR_BYTES }
	SEG(cs, CS), SEG(ds, DS), SEG(es, ES), SEG(fs, FS), SEG(gs, GS), SEG(ss, SS),
	SEG(tr, TR), SEG(ldtr, LDTR),
#undef SEG
};

static u64 l4h_get_segment_base(struct kvm_vcpu *vcpu, int seg)
{
	return vmcs_rd(vcpu, seg_fields[seg].base);
}

static void l4h_get_segment(struct kvm_vcpu *vcpu, struct kvm_segment *var, int seg)
{
	u32 ar = vmcs_rd(vcpu, seg_fields[seg].ar);

	var->base = vmcs_rd(vcpu, seg_fields[seg].base);
	var->limit = vmcs_rd(vcpu, seg_fields[seg].limit);
	var->selector = vmcs_rd(vcpu, seg_fields[seg].selector);
	var->unusable = (ar >> 16) & 1;
	var->type = ar & 15;
	var->s = (ar >> 4) & 1;
	var->dpl = (ar >> 5) & 3;
	/* A usable segment has to be present, and some userspace forgets
	 * "unusable": see vmx_get_segment(). */
	var->present = !var->unusable;
	var->avl = (ar >> 12) & 1;
	var->l = (ar >> 13) & 1;
	var->db = (ar >> 14) & 1;
	var->g = (ar >> 15) & 1;
}

static u32 segment_access_rights(struct kvm_segment *var)
{
	u32 ar = var->type & 15;

	ar |= (var->s & 1) << 4;
	ar |= (var->dpl & 3) << 5;
	ar |= (var->present & 1) << 7;
	ar |= (var->avl & 1) << 12;
	ar |= (var->l & 1) << 13;
	ar |= (var->db & 1) << 14;
	ar |= (var->g & 1) << 15;
	ar |= (var->unusable || !var->present) << 16;
	return ar;
}

static void l4h_set_segment(struct kvm_vcpu *vcpu, struct kvm_segment *var, int seg)
{
	vmcs_wr(vcpu, seg_fields[seg].base, var->base);
	vmcs_wr(vcpu, seg_fields[seg].limit, var->limit);
	vmcs_wr(vcpu, seg_fields[seg].selector, var->selector);
	/* An unrestricted guest needs "accessed": old QEMUs leave it clear
	 * at reset, which then fails the VM entry. */
	if (seg != VCPU_SREG_LDTR)
		var->type |= 1;
	vmcs_wr(vcpu, seg_fields[seg].ar, segment_access_rights(var));
}

static int l4h_get_cpl(struct kvm_vcpu *vcpu)
{
	return (vmcs_rd(vcpu, GUEST_SS_AR_BYTES) >> 5) & 3;
}

static void l4h_get_cs_db_l_bits(struct kvm_vcpu *vcpu, int *db, int *l)
{
	u32 ar = vmcs_rd(vcpu, GUEST_CS_AR_BYTES);

	*db = (ar >> 14) & 1;
	*l = (ar >> 13) & 1;
}

static void l4h_get_idt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	dt->size = vmcs_rd(vcpu, GUEST_IDTR_LIMIT);
	dt->address = vmcs_rd(vcpu, GUEST_IDTR_BASE);
}

static void l4h_set_idt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	vmcs_wr(vcpu, GUEST_IDTR_LIMIT, dt->size);
	vmcs_wr(vcpu, GUEST_IDTR_BASE, dt->address);
}

static void l4h_get_gdt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	dt->size = vmcs_rd(vcpu, GUEST_GDTR_LIMIT);
	dt->address = vmcs_rd(vcpu, GUEST_GDTR_BASE);
}

static void l4h_set_gdt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	vmcs_wr(vcpu, GUEST_GDTR_LIMIT, dt->size);
	vmcs_wr(vcpu, GUEST_GDTR_BASE, dt->address);
}

/* ---- control registers */

static void entry_control_update(struct kvm_vcpu *vcpu, u32 set, u32 clear)
{
	struct vcpu_l4h *l = to_l4h(vcpu);
	u32 v = (l->entry_control & ~clear) | set;

	if (v != l->entry_control) {
		l->entry_control = v;
		vmcs_wr(vcpu, VM_ENTRY_CONTROLS, v);
	}
}

static int l4h_set_efer(struct kvm_vcpu *vcpu, u64 efer)
{
	u64 hw = efer;

	vcpu->arch.efer = efer;
	if (efer & EFER_LMA) {
		entry_control_update(vcpu, VM_ENTRY_IA32E_MODE, 0);
	} else {
		entry_control_update(vcpu, 0, VM_ENTRY_IA32E_MODE);
		hw &= ~EFER_LME;
	}
	vmcs_wr(vcpu, GUEST_IA32_EFER, hw);
	return 0;
}

static void enter_lmode(struct kvm_vcpu *vcpu)
{
	u32 ar = vmcs_rd(vcpu, GUEST_TR_AR_BYTES);

	if ((ar & VMX_AR_TYPE_MASK) != VMX_AR_TYPE_BUSY_64_TSS)
		vmcs_wr(vcpu, GUEST_TR_AR_BYTES, (ar & ~VMX_AR_TYPE_MASK) | VMX_AR_TYPE_BUSY_64_TSS);
	l4h_set_efer(vcpu, vcpu->arch.efer | EFER_LMA);
}

static bool l4h_is_valid_cr0(struct kvm_vcpu *vcpu, unsigned long cr0)
{
	return true;
}

static void l4h_set_cr0(struct kvm_vcpu *vcpu, unsigned long cr0)
{
	unsigned long old = kvm_read_cr0(vcpu);

	if (vcpu->arch.efer & EFER_LME) {
		if (!(old & X86_CR0_PG) && (cr0 & X86_CR0_PG))
			enter_lmode(vcpu);
		else if ((old & X86_CR0_PG) && !(cr0 & X86_CR0_PG))
			l4h_set_efer(vcpu, vcpu->arch.efer & ~EFER_LMA);
	}
	vcpu->arch.cr0 = cr0;
	kvm_register_mark_available(vcpu, VCPU_EXREG_CR0);
	vmcs_wr(vcpu, CR0_READ_SHADOW, cr0);
	vmcs_wr(vcpu, GUEST_CR0, cr0 | X86_CR0_NE);
}

static bool l4h_is_valid_cr4(struct kvm_vcpu *vcpu, unsigned long cr4)
{
	return !(cr4 & X86_CR4_VMXE);
}

static void l4h_set_cr4(struct kvm_vcpu *vcpu, unsigned long cr4)
{
	unsigned long hw = cr4 | X86_CR4_VMXE;

	vcpu->arch.cr4 = cr4;
	kvm_register_mark_available(vcpu, VCPU_EXREG_CR4);
	if (!is_paging(vcpu))
		hw &= ~(X86_CR4_SMEP | X86_CR4_SMAP | X86_CR4_PKE);
	vmcs_wr(vcpu, CR4_READ_SHADOW, cr4);
	vmcs_wr(vcpu, GUEST_CR4, hw);
}

/* The EPT root is the kTCB's (vcpu_load): this only keeps CR3 current. */
static void l4h_load_mmu_pgd(struct kvm_vcpu *vcpu, hpa_t root_hpa, int root_level)
{
}

static unsigned long l4h_get_rflags(struct kvm_vcpu *vcpu)
{
	if (!kvm_register_is_available(vcpu, VCPU_EXREG_RFLAGS)) {
		kvm_register_mark_available(vcpu, VCPU_EXREG_RFLAGS);
		to_l4h(vcpu)->rflags = vmcs_rd(vcpu, GUEST_RFLAGS);
	}
	return to_l4h(vcpu)->rflags;
}

static void l4h_set_rflags(struct kvm_vcpu *vcpu, unsigned long rflags)
{
	vmcs_wr(vcpu, GUEST_RFLAGS, rflags);
	to_l4h(vcpu)->rflags = rflags;
	kvm_register_mark_available(vcpu, VCPU_EXREG_RFLAGS);
}

static bool l4h_get_if_flag(struct kvm_vcpu *vcpu)
{
	return l4h_get_rflags(vcpu) & X86_EFLAGS_IF;
}

static void l4h_cache_reg(struct kvm_vcpu *vcpu, enum kvm_reg reg)
{
	struct kvm_mmu *mmu = vcpu->arch.walk_mmu;

	kvm_register_mark_available(vcpu, reg);
	switch (reg) {
	case VCPU_REGS_RSP:
		vcpu->arch.regs[VCPU_REGS_RSP] = vmcs_rd(vcpu, GUEST_RSP);
		break;
	case VCPU_EXREG_CR3:
		vcpu->arch.cr3 = vmcs_rd(vcpu, GUEST_CR3);
		break;
	case VCPU_EXREG_PDPTR:
		mmu->pdptrs[0] = vmcs_rd(vcpu, GUEST_PDPTR0);
		mmu->pdptrs[1] = vmcs_rd(vcpu, GUEST_PDPTR1);
		mmu->pdptrs[2] = vmcs_rd(vcpu, GUEST_PDPTR2);
		mmu->pdptrs[3] = vmcs_rd(vcpu, GUEST_PDPTR3);
		break;
	default:
		break;
	}
}

/* ---- exceptions and interrupts */

static void update_exception_bitmap(struct kvm_vcpu *vcpu)
{
	struct vcpu_l4h *l = to_l4h(vcpu);
	u32 eb = BIT(UD_VECTOR) | BIT(MC_VECTOR) | BIT(DB_VECTOR) | BIT(AC_VECTOR);

	if (vcpu->guest_debug & KVM_GUESTDBG_USE_SW_BP)
		eb |= BIT(BP_VECTOR);
	if (eb != l->exception_bitmap) {
		l->exception_bitmap = eb;
		vmcs_wr(vcpu, EXCEPTION_BITMAP, eb);
	}
}

static void exec_control_update(struct kvm_vcpu *vcpu, u32 set, u32 clear)
{
	struct vcpu_l4h *l = to_l4h(vcpu);

	l->exec_control = (l->exec_control & ~clear) | set;
}

static u32 l4h_get_interrupt_shadow(struct kvm_vcpu *vcpu)
{
	u32 intr = vmcs_rd(vcpu, GUEST_INTERRUPTIBILITY_INFO);
	u32 mask = 0;

	if (intr & GUEST_INTR_STATE_STI)
		mask |= KVM_X86_SHADOW_INT_STI;
	if (intr & GUEST_INTR_STATE_MOV_SS)
		mask |= KVM_X86_SHADOW_INT_MOV_SS;
	return mask;
}

static void l4h_set_interrupt_shadow(struct kvm_vcpu *vcpu, int mask)
{
	u32 old = vmcs_rd(vcpu, GUEST_INTERRUPTIBILITY_INFO);
	u32 intr = old & ~(GUEST_INTR_STATE_STI | GUEST_INTR_STATE_MOV_SS);

	if (mask & KVM_X86_SHADOW_INT_MOV_SS)
		intr |= GUEST_INTR_STATE_MOV_SS;
	else if (mask & KVM_X86_SHADOW_INT_STI)
		intr |= GUEST_INTR_STATE_STI;
	if (intr != old)
		vmcs_wr(vcpu, GUEST_INTERRUPTIBILITY_INFO, intr);
}

static int l4h_skip_emulated_instruction(struct kvm_vcpu *vcpu)
{
	unsigned long orig = kvm_rip_read(vcpu), rip = orig + to_l4h(vcpu)->x.instr_len;

	/* Wrap, outside 64-bit mode, as the CPU would. */
	if (unlikely(((rip ^ orig) >> 31) == 3) && !is_64_bit_mode(vcpu))
		rip = (u32)rip;
	kvm_rip_write(vcpu, rip);
	l4h_set_interrupt_shadow(vcpu, 0);
	return 1;
}

static void set_entry_event(struct kvm_vcpu *vcpu, u32 intr, u32 error, u32 len)
{
	struct vcpu_l4h *l = to_l4h(vcpu);

	l->entry_intr = intr;
	l->entry_error = error;
	l->entry_len = len;
	if (intr & INTR_INFO_DELIVER_CODE_MASK)
		vmcs_wr(vcpu, VM_ENTRY_EXCEPTION_ERROR_CODE, error);
	if (len)
		vmcs_wr(vcpu, VM_ENTRY_INSTRUCTION_LEN, len);
}

static void l4h_inject_exception(struct kvm_vcpu *vcpu)
{
	struct kvm_queued_exception *ex = &vcpu->arch.exception;
	u32 intr = ex->vector | INTR_INFO_VALID_MASK, len = 0;

	kvm_deliver_exception_payload(vcpu, ex);
	if (ex->has_error_code)
		intr |= INTR_INFO_DELIVER_CODE_MASK;
	if (kvm_exception_is_soft(ex->vector)) {
		intr |= INTR_TYPE_SOFT_EXCEPTION;
		len = vcpu->arch.event_exit_inst_len;
	} else {
		intr |= INTR_TYPE_HARD_EXCEPTION;
	}
	set_entry_event(vcpu, intr, ex->error_code, len);
}

static void l4h_inject_irq(struct kvm_vcpu *vcpu, bool reinjected)
{
	u32 intr = vcpu->arch.interrupt.nr | INTR_INFO_VALID_MASK, len = 0;

	++vcpu->stat.irq_injections;
	if (vcpu->arch.interrupt.soft) {
		intr |= INTR_TYPE_SOFT_INTR;
		len = vcpu->arch.event_exit_inst_len;
	} else {
		intr |= INTR_TYPE_EXT_INTR;
	}
	set_entry_event(vcpu, intr, 0, len);
}

static void l4h_inject_nmi(struct kvm_vcpu *vcpu)
{
	++vcpu->stat.nmi_injections;
	set_entry_event(vcpu, NMI_VECTOR | INTR_TYPE_NMI_INTR | INTR_INFO_VALID_MASK, 0, 0);
}

static bool l4h_get_nmi_mask(struct kvm_vcpu *vcpu)
{
	return vmcs_rd(vcpu, GUEST_INTERRUPTIBILITY_INFO) & GUEST_INTR_STATE_NMI;
}

static void l4h_set_nmi_mask(struct kvm_vcpu *vcpu, bool masked)
{
	u32 intr = vmcs_rd(vcpu, GUEST_INTERRUPTIBILITY_INFO);

	if (masked)
		intr |= GUEST_INTR_STATE_NMI;
	else
		intr &= ~GUEST_INTR_STATE_NMI;
	vmcs_wr(vcpu, GUEST_INTERRUPTIBILITY_INFO, intr);
}

static int l4h_interrupt_allowed(struct kvm_vcpu *vcpu, bool for_injection)
{
	return (l4h_get_rflags(vcpu) & X86_EFLAGS_IF) &&
	       !(vmcs_rd(vcpu, GUEST_INTERRUPTIBILITY_INFO) &
		 (GUEST_INTR_STATE_STI | GUEST_INTR_STATE_MOV_SS));
}

static int l4h_nmi_allowed(struct kvm_vcpu *vcpu, bool for_injection)
{
	return !(vmcs_rd(vcpu, GUEST_INTERRUPTIBILITY_INFO) &
		 (GUEST_INTR_STATE_MOV_SS | GUEST_INTR_STATE_STI | GUEST_INTR_STATE_NMI));
}

static void l4h_enable_nmi_window(struct kvm_vcpu *vcpu)
{
	exec_control_update(vcpu, CPU_BASED_NMI_WINDOW_EXITING, 0);
}

static void l4h_enable_irq_window(struct kvm_vcpu *vcpu)
{
	exec_control_update(vcpu, CPU_BASED_INTR_WINDOW_EXITING, 0);
}

static void l4h_deliver_interrupt(struct kvm_lapic *apic, int delivery_mode, int trig_mode,
				  int vector)
{
	struct kvm_vcpu *vcpu = apic->vcpu;

	kvm_lapic_set_irr(vector, apic);
	kvm_make_request(KVM_REQ_EVENT, vcpu);
	kvm_vcpu_kick(vcpu);
}

/* An event that was being delivered when the VCPU stopped goes back to KVM's
 * queues, to go in again. */
static void complete_interrupts(struct kvm_vcpu *vcpu, u32 info, u32 error, u32 len)
{
	u32 type = info & VECTORING_INFO_TYPE_MASK;
	u8 vector = info & VECTORING_INFO_VECTOR_MASK;

	vcpu->arch.nmi_injected = false;
	kvm_clear_exception_queue(vcpu);
	kvm_clear_interrupt_queue(vcpu);
	if (!(info & VECTORING_INFO_VALID_MASK))
		return;
	kvm_make_request(KVM_REQ_EVENT, vcpu);
	switch (type) {
	case INTR_TYPE_NMI_INTR:
		vcpu->arch.nmi_injected = true;
		l4h_set_nmi_mask(vcpu, false);
		break;
	case INTR_TYPE_SOFT_EXCEPTION:
		vcpu->arch.event_exit_inst_len = len;
		fallthrough;
	case INTR_TYPE_HARD_EXCEPTION:
		kvm_requeue_exception(vcpu, vector, info & VECTORING_INFO_DELIVER_CODE_MASK, error);
		break;
	case INTR_TYPE_SOFT_INTR:
		vcpu->arch.event_exit_inst_len = len;
		fallthrough;
	case INTR_TYPE_EXT_INTR:
		kvm_queue_interrupt(vcpu, vector, type == INTR_TYPE_SOFT_INTR);
		break;
	}
}

static void l4h_cancel_injection(struct kvm_vcpu *vcpu)
{
	struct vcpu_l4h *l = to_l4h(vcpu);

	complete_interrupts(vcpu, l->entry_intr, l->entry_error, l->entry_len);
	l->entry_intr = 0;
}

/* ---- MSRs */

static bool syscall_msr(u32 index)
{
	return index == MSR_STAR || index == MSR_LSTAR || index == MSR_CSTAR ||
	       index == MSR_SYSCALL_MASK || index == MSR_KERNEL_GS_BASE;
}

static int l4h_get_msr(struct kvm_vcpu *vcpu, struct msr_data *msr)
{
	switch (msr->index) {
	case MSR_FS_BASE:
		msr->data = vmcs_rd(vcpu, GUEST_FS_BASE);
		return 0;
	case MSR_GS_BASE:
		msr->data = vmcs_rd(vcpu, GUEST_GS_BASE);
		return 0;
	case MSR_IA32_SYSENTER_CS:
		msr->data = vmcs_rd(vcpu, GUEST_SYSENTER_CS);
		return 0;
	case MSR_IA32_SYSENTER_EIP:
		msr->data = vmcs_rd(vcpu, GUEST_SYSENTER_EIP);
		return 0;
	case MSR_IA32_SYSENTER_ESP:
		msr->data = vmcs_rd(vcpu, GUEST_SYSENTER_ESP);
		return 0;
	case MSR_IA32_DEBUGCTLMSR:
		msr->data = 0;
		return 0;
	}
	if (syscall_msr(msr->index)) {
		unsigned long v;

		if (l4h_vcpu_read_msr(cap(vcpu), msr->index, &v))
			return 1;
		msr->data = v;
		return 0;
	}
	return kvm_get_msr_common(vcpu, msr);
}

static int l4h_set_msr(struct kvm_vcpu *vcpu, struct msr_data *msr)
{
	u64 data = msr->data;

	switch (msr->index) {
	case MSR_FS_BASE:
		vmcs_wr(vcpu, GUEST_FS_BASE, data);
		return 0;
	case MSR_GS_BASE:
		vmcs_wr(vcpu, GUEST_GS_BASE, data);
		return 0;
	case MSR_IA32_SYSENTER_CS:
		vmcs_wr(vcpu, GUEST_SYSENTER_CS, data);
		return 0;
	case MSR_IA32_SYSENTER_EIP:
		vmcs_wr(vcpu, GUEST_SYSENTER_EIP, data);
		return 0;
	case MSR_IA32_SYSENTER_ESP:
		vmcs_wr(vcpu, GUEST_SYSENTER_ESP, data);
		return 0;
	case MSR_IA32_DEBUGCTLMSR:
		return data ? 1 : 0;
	case MSR_IA32_CR_PAT:
		if (!kvm_pat_valid(data))
			return 1;
		vmcs_wr(vcpu, GUEST_IA32_PAT, data);
		vcpu->arch.pat = data;
		return 0;
	}
	if (syscall_msr(msr->index))
		return l4h_vcpu_write_msr(cap(vcpu), msr->index, data) ? 1 : 0;
	return kvm_set_msr_common(vcpu, msr);
}

static bool l4h_has_emulated_msr(struct kvm *kvm, u32 index)
{
	switch (index) {
	case MSR_IA32_VMX_BASIC ... MSR_IA32_VMX_VMFUNC:
	case MSR_IA32_SMBASE:
	case MSR_AMD64_VIRT_SPEC_CTRL:
	case MSR_AMD64_TSC_RATIO:
		return false;
	}
	return true;
}

static int l4h_get_feature_msr(u32 msr, u64 *data)
{
	return KVM_MSR_RET_UNSUPPORTED;
}

/* ---- TLBs */

/*
 * Page table changes are flushed where they are made: seL4 invalidates every
 * core that has entered a VM when it removes an EPT leaf or table (patch
 * 0039), before ept.c returns.  Adding one needs nothing, as no TLB holds a
 * not-present entry.  tests/guest/kvmtest.c checks both (slot_replace,
 * dirty_log).
 */
static void l4h_flush_tlb_noop(struct kvm_vcpu *vcpu)
{
}

static void l4h_flush_tlb_guest(struct kvm_vcpu *vcpu)
{
	if (WARN_ON_ONCE(l4h_vcpu_flush_tlb(cap(vcpu))))
		kvm_make_request(KVM_REQ_TRIPLE_FAULT, vcpu);
}

static void l4h_flush_tlb_gva(struct kvm_vcpu *vcpu, gva_t addr)
{
	l4h_flush_tlb_guest(vcpu);
}

/* ---- vCPUs */

static atomic64_t next_vcpu_id = ATOMIC64_INIT(1);

/* What each kTCB is set up to run. */
static DEFINE_PER_CPU(u64, bound_vcpu);
static DEFINE_PER_CPU(unsigned long, bound_ept);

static void l4h_vcpu_load(struct kvm_vcpu *vcpu, int cpu)
{
	struct vcpu_l4h *l = to_l4h(vcpu);
	unsigned long ktcb = l4h_this_vcpu()->ktcb, root = to_ept(vcpu->kvm)->root;

	/* A binding has two ends: binding the VCPU to another kTCB, or
	 * another VCPU to this one, undoes it. */
	if (this_cpu_read(bound_vcpu) != l->id || l->bound_cpu != cpu) {
		WARN_ON_ONCE(l4h_vcpu_set_tcb(l->obj.cptr, ktcb));
		this_cpu_write(bound_vcpu, l->id);
		l->bound_cpu = cpu;
	}
	if (this_cpu_read(bound_ept) != root) {
		WARN_ON_ONCE(l4h_tcb_set_ept(ktcb, root));
		this_cpu_write(bound_ept, root);
	}
}

static void l4h_vcpu_put(struct kvm_vcpu *vcpu)
{
}

static int l4h_vcpu_create(struct kvm_vcpu *vcpu)
{
	struct vcpu_l4h *l = to_l4h(vcpu);
	u32 sec = SECONDARY_EXEC_ENABLE_EPT | SECONDARY_EXEC_UNRESTRICTED_GUEST |
		  SECONDARY_EXEC_ENABLE_INVPCID | SECONDARY_EXEC_WBINVD_EXITING;
	int err;

	for (;;) {
		err = l4h_obj_alloc(L4H_OBJ_VCPU, 0, &l->obj);
		if (err != -ENOMEM || !l4h_objmem_wait())
			break;
	}
	if (err)
		return err;
	l->id = atomic64_inc_return(&next_vcpu_id);
	l->bound_cpu = -1;
	/* A valid generation is never the initial 0. */
	l->gen = 1;

	vmcs_wr(vcpu, SECONDARY_VM_EXEC_CONTROL, sec);
	if (!(vmcs_rd(vcpu, SECONDARY_VM_EXEC_CONTROL) & SECONDARY_EXEC_UNRESTRICTED_GUEST)) {
		pr_warn_once("the CPU has no unrestricted guest\n");
		l4h_obj_free(&l->obj);
		return -EOPNOTSUPP;
	}
	l->entry_control = VM_ENTRY_LOAD_IA32_PAT | VM_ENTRY_LOAD_IA32_EFER;
	vmcs_wr(vcpu, VM_ENTRY_CONTROLS, l->entry_control);
	vmcs_wr(vcpu, CR0_GUEST_HOST_MASK, ~0ul);
	vmcs_wr(vcpu, CR4_GUEST_HOST_MASK, ~0ul);
	l->exec_control = CPU_BASED_HLT_EXITING | CPU_BASED_USE_TSC_OFFSETTING |
			  CPU_BASED_CR8_LOAD_EXITING | CPU_BASED_CR8_STORE_EXITING;
	update_exception_bitmap(vcpu);
	vcpu->arch.cr0_guest_owned_bits = 0;
	vcpu->arch.cr4_guest_owned_bits = 0;
	vcpu->arch.pat = MSR_IA32_CR_PAT_DEFAULT;
	return 0;
}

static void l4h_vcpu_free(struct kvm_vcpu *vcpu)
{
	l4h_obj_free(&to_l4h(vcpu)->obj);
}

static void seg_setup(struct kvm_vcpu *vcpu, int seg)
{
	u32 ar = 0x93;

	if (seg == VCPU_SREG_CS)
		ar |= 0x08;	/* code segment */
	vmcs_wr(vcpu, seg_fields[seg].selector, 0);
	vmcs_wr(vcpu, seg_fields[seg].base, 0);
	vmcs_wr(vcpu, seg_fields[seg].limit, 0xffff);
	vmcs_wr(vcpu, seg_fields[seg].ar, ar);
}

static void l4h_vcpu_reset(struct kvm_vcpu *vcpu, bool init_event)
{
	seg_setup(vcpu, VCPU_SREG_CS);
	vmcs_wr(vcpu, GUEST_CS_SELECTOR, 0xf000);
	vmcs_wr(vcpu, GUEST_CS_BASE, 0xffff0000ul);
	seg_setup(vcpu, VCPU_SREG_DS);
	seg_setup(vcpu, VCPU_SREG_ES);
	seg_setup(vcpu, VCPU_SREG_FS);
	seg_setup(vcpu, VCPU_SREG_GS);
	seg_setup(vcpu, VCPU_SREG_SS);

	vmcs_wr(vcpu, GUEST_TR_SELECTOR, 0);
	vmcs_wr(vcpu, GUEST_TR_BASE, 0);
	vmcs_wr(vcpu, GUEST_TR_LIMIT, 0xffff);
	vmcs_wr(vcpu, GUEST_TR_AR_BYTES, 0x008b);
	vmcs_wr(vcpu, GUEST_LDTR_SELECTOR, 0);
	vmcs_wr(vcpu, GUEST_LDTR_BASE, 0);
	vmcs_wr(vcpu, GUEST_LDTR_LIMIT, 0xffff);
	vmcs_wr(vcpu, GUEST_LDTR_AR_BYTES, 0x00082);
	vmcs_wr(vcpu, GUEST_GDTR_BASE, 0);
	vmcs_wr(vcpu, GUEST_GDTR_LIMIT, 0xffff);
	vmcs_wr(vcpu, GUEST_IDTR_BASE, 0);
	vmcs_wr(vcpu, GUEST_IDTR_LIMIT, 0xffff);
	vmcs_wr(vcpu, GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_ACTIVE);
	vmcs_wr(vcpu, GUEST_INTERRUPTIBILITY_INFO, 0);
	vmcs_wr(vcpu, GUEST_PENDING_DBG_EXCEPTIONS, 0);
	vmcs_wr(vcpu, GUEST_IA32_PAT, vcpu->arch.pat);
	vmcs_wr(vcpu, GUEST_DR7, DR7_FIXED_1);
	to_l4h(vcpu)->entry_intr = 0;
	kvm_set_cr8(vcpu, 0);
}

static void l4h_prepare_switch(struct kvm_vcpu *vcpu)
{
}

static int l4h_vcpu_pre_run(struct kvm_vcpu *vcpu)
{
	return 1;
}

/* KVM's own GPR accessors do not mark them dirty (VMX keeps them in
 * memory), so compare with what seL4 has. */
static void sync_to_vcpu(struct kvm_vcpu *vcpu)
{
	struct vcpu_l4h *l = to_l4h(vcpu);
	unsigned long *r = vcpu->arch.regs;
	struct kvm_mmu *mmu = vcpu->arch.walk_mmu;
	unsigned long gp[L4H_VMX_NR_GP] = {
		[L4H_VMX_RAX] = r[VCPU_REGS_RAX], [L4H_VMX_RBX] = r[VCPU_REGS_RBX],
		[L4H_VMX_RCX] = r[VCPU_REGS_RCX], [L4H_VMX_RDX] = r[VCPU_REGS_RDX],
		[L4H_VMX_RSI] = r[VCPU_REGS_RSI], [L4H_VMX_RDI] = r[VCPU_REGS_RDI],
		[L4H_VMX_RBP] = r[VCPU_REGS_RBP], [L4H_VMX_R8] = r[VCPU_REGS_R8],
		[L4H_VMX_R9] = r[VCPU_REGS_R9], [L4H_VMX_R10] = r[VCPU_REGS_R10],
		[L4H_VMX_R11] = r[VCPU_REGS_R11], [L4H_VMX_R12] = r[VCPU_REGS_R12],
		[L4H_VMX_R13] = r[VCPU_REGS_R13], [L4H_VMX_R14] = r[VCPU_REGS_R14],
		[L4H_VMX_R15] = r[VCPU_REGS_R15],
	};

	if (memcmp(gp, l->hw_gp, sizeof(gp))) {
		WARN_ON_ONCE(l4h_vcpu_write_regs(l->obj.cptr, gp));
		memcpy(l->hw_gp, gp, sizeof(gp));
	}
	if (kvm_register_is_dirty(vcpu, VCPU_REGS_RSP))
		vmcs_wr(vcpu, GUEST_RSP, r[VCPU_REGS_RSP]);
	if (kvm_register_is_dirty(vcpu, VCPU_EXREG_CR3))
		vmcs_wr(vcpu, GUEST_CR3, vcpu->arch.cr3);
	if (kvm_register_is_dirty(vcpu, VCPU_EXREG_PDPTR) && is_pae_paging(vcpu)) {
		vmcs_wr(vcpu, GUEST_PDPTR0, mmu->pdptrs[0]);
		vmcs_wr(vcpu, GUEST_PDPTR1, mmu->pdptrs[1]);
		vmcs_wr(vcpu, GUEST_PDPTR2, mmu->pdptrs[2]);
		vmcs_wr(vcpu, GUEST_PDPTR3, mmu->pdptrs[3]);
	}
	if (vcpu->arch.cr2 != l->hw_cr2) {
		WARN_ON_ONCE(l4h_vcpu_write_cr2(l->obj.cptr, vcpu->arch.cr2));
		l->hw_cr2 = vcpu->arch.cr2;
	}
	vcpu->arch.regs_dirty = 0;
}

static void sync_from_exit(struct kvm_vcpu *vcpu)
{
	struct vcpu_l4h *l = to_l4h(vcpu);
	struct l4h_vmexit *x = &l->x;
	unsigned long *r = vcpu->arch.regs;
	struct vmcs_cached *c;

	r[VCPU_REGS_RAX] = x->gp[L4H_VMX_RAX];
	r[VCPU_REGS_RBX] = x->gp[L4H_VMX_RBX];
	r[VCPU_REGS_RCX] = x->gp[L4H_VMX_RCX];
	r[VCPU_REGS_RDX] = x->gp[L4H_VMX_RDX];
	r[VCPU_REGS_RSI] = x->gp[L4H_VMX_RSI];
	r[VCPU_REGS_RDI] = x->gp[L4H_VMX_RDI];
	r[VCPU_REGS_RBP] = x->gp[L4H_VMX_RBP];
	r[VCPU_REGS_R8] = x->gp[L4H_VMX_R8];
	r[VCPU_REGS_R9] = x->gp[L4H_VMX_R9];
	r[VCPU_REGS_R10] = x->gp[L4H_VMX_R10];
	r[VCPU_REGS_R11] = x->gp[L4H_VMX_R11];
	r[VCPU_REGS_R12] = x->gp[L4H_VMX_R12];
	r[VCPU_REGS_R13] = x->gp[L4H_VMX_R13];
	r[VCPU_REGS_R14] = x->gp[L4H_VMX_R14];
	r[VCPU_REGS_R15] = x->gp[L4H_VMX_R15];
	memcpy(l->hw_gp, x->gp, sizeof(l->hw_gp));
	vcpu->arch.regs[VCPU_REGS_RIP] = x->rip;
	l->rflags = x->rflags;
	vcpu->arch.cr2 = l->hw_cr2 = x->cr2;

	/* The VM ran: what we cached of the guest's state is gone. */
	l->gen++;
	c = &l->cache[(GUEST_INTERRUPTIBILITY_INFO ^ (GUEST_INTERRUPTIBILITY_INFO >> 8)) %
		      VMCS_CACHE_SIZE];
	c->field = GUEST_INTERRUPTIBILITY_INFO;
	c->gen = l->gen;
	c->value = x->interruptibility;

	/* Read when needed: most exits need neither RSP nor CR3. */
	vcpu->arch.regs_avail = ~0u & ~(BIT(VCPU_REGS_RSP) | BIT(VCPU_EXREG_CR3) |
					BIT(VCPU_EXREG_PDPTR));
	vcpu->arch.regs_dirty = 0;
}

static fastpath_t l4h_vcpu_run(struct kvm_vcpu *vcpu, u64 run_flags)
{
	struct vcpu_l4h *l = to_l4h(vcpu);
	struct l4h_vmexit *x = &l->x;
	u32 info, error, len;

	/* An event taken off the notification earlier would not end the
	 * VMEnter, and interrupts are off until it returns. */
	if (l4h_events_pending()) {
		x->fault = 0;
		x->reason = EXIT_REASON_EXTERNAL_INTERRUPT;
		complete_interrupts(vcpu, l->entry_intr, l->entry_error, l->entry_len);
		l->entry_intr = 0;
		return EXIT_FASTPATH_NONE;
	}
	sync_to_vcpu(vcpu);
	l4h_kvm_fpu_load(vcpu);
	l4h_vcpu_enter(x, kvm_rip_read(vcpu), l->exec_control, l->entry_intr);
	sync_from_exit(vcpu);

	if (x->intr_info & INTR_INFO_VALID_MASK) {
		/* It never went in: the call was over before the VM ran. */
		info = x->intr_info;
		error = l->entry_error;
		len = l->entry_len;
	} else {
		info = x->idt_vector_info;
		error = x->idt_vector_error;
		len = x->instr_len;
	}
	l->entry_intr = 0;
	/* An exit from a faulting IRET out of an NMI handler has unblocked
	 * NMIs early: the SDM's "NMI unblocking due to IRET". */
	if ((x->exit_intr_info & INTR_INFO_VALID_MASK) &&
	    (x->exit_intr_info & INTR_INFO_UNBLOCK_NMI) &&
	    (x->exit_intr_info & INTR_INFO_VECTOR_MASK) != DF_VECTOR &&
	    !(info & VECTORING_INFO_VALID_MASK))
		l4h_set_nmi_mask(vcpu, true);
	complete_interrupts(vcpu, info, error, len);
	return EXIT_FASTPATH_NONE;
}

/* ---- VM exits */

static int internal_error(struct kvm_vcpu *vcpu)
{
	struct l4h_vmexit *x = &to_l4h(vcpu)->x;

	vcpu->run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
	vcpu->run->internal.suberror = KVM_INTERNAL_ERROR_UNEXPECTED_EXIT_REASON;
	vcpu->run->internal.ndata = 2;
	vcpu->run->internal.data[0] = x->reason;
	vcpu->run->internal.data[1] = vcpu->arch.last_vmentry_cpu;
	return 0;
}

static int handle_exception(struct kvm_vcpu *vcpu)
{
	struct l4h_vmexit *x = &to_l4h(vcpu)->x;
	u32 info = x->exit_intr_info, vector = info & INTR_INFO_VECTOR_MASK;
	u32 error = info & INTR_INFO_DELIVER_CODE_MASK ? x->exit_intr_error : 0;

	if ((info & INTR_INFO_INTR_TYPE_MASK) == INTR_TYPE_NMI_INTR)
		return 1;
	switch (vector) {
	case UD_VECTOR:
		return handle_ud(vcpu);
	case AC_VECTOR:
		kvm_queue_exception_e(vcpu, AC_VECTOR, error);
		return 1;
	case DB_VECTOR:
		if (!(vcpu->guest_debug & (KVM_GUESTDBG_SINGLESTEP | KVM_GUESTDBG_USE_HW_BP))) {
			kvm_queue_exception_p(vcpu, DB_VECTOR, x->qualification);
			return 1;
		}
		vcpu->run->debug.arch.dr6 = x->qualification | DR6_ACTIVE_LOW;
		vcpu->run->debug.arch.dr7 = vcpu->arch.dr7;
		fallthrough;
	case BP_VECTOR:
		vcpu->arch.event_exit_inst_len = x->instr_len;
		vcpu->run->exit_reason = KVM_EXIT_DEBUG;
		vcpu->run->debug.arch.pc = kvm_get_linear_rip(vcpu);
		vcpu->run->debug.arch.exception = vector;
		return 0;
	case MC_VECTOR:
		return 1;
	}
	vcpu->run->exit_reason = KVM_EXIT_EXCEPTION;
	vcpu->run->ex.exception = vector;
	vcpu->run->ex.error_code = error;
	return 0;
}

static int handle_io(struct kvm_vcpu *vcpu)
{
	unsigned long q = to_l4h(vcpu)->x.qualification;
	int size = (q & 7) + 1, in = (q & 8) != 0;

	++vcpu->stat.io_exits;
	if (q & 16)
		return kvm_emulate_instruction(vcpu, 0);
	return kvm_fast_pio(vcpu, size, q >> 16, in);
}

static int handle_cr(struct kvm_vcpu *vcpu)
{
	unsigned long q = to_l4h(vcpu)->x.qualification, val;
	int cr = q & 15, reg = (q >> 8) & 15, err;

	switch ((q >> 4) & 3) {
	case 0: /* mov to cr */
		val = kvm_register_read(vcpu, reg);
		switch (cr) {
		case 0:
			err = kvm_set_cr0(vcpu, val);
			return kvm_complete_insn_gp(vcpu, err);
		case 3:
			err = kvm_set_cr3(vcpu, val);
			return kvm_complete_insn_gp(vcpu, err);
		case 4:
			err = kvm_set_cr4(vcpu, val);
			return kvm_complete_insn_gp(vcpu, err);
		case 8: {
			u8 prev = kvm_get_cr8(vcpu);

			err = kvm_set_cr8(vcpu, val);
			if (lapic_in_kernel(vcpu) || err || prev <= (u8)val)
				return kvm_complete_insn_gp(vcpu, err);
			kvm_skip_emulated_instruction(vcpu);
			vcpu->run->exit_reason = KVM_EXIT_SET_TPR;
			return 0;
		}
		}
		break;
	case 1: /* mov from cr */
		if (cr == 3)
			val = kvm_read_cr3(vcpu);
		else if (cr == 8)
			val = kvm_get_cr8(vcpu);
		else
			break;
		kvm_register_write(vcpu, reg, val);
		return kvm_skip_emulated_instruction(vcpu);
	case 2: /* clts */
		err = kvm_set_cr0(vcpu, kvm_read_cr0(vcpu) & ~X86_CR0_TS);
		return kvm_complete_insn_gp(vcpu, err);
	case 3: /* lmsw */
		kvm_lmsw(vcpu, (q >> 16) & 15);
		return kvm_skip_emulated_instruction(vcpu);
	}
	return internal_error(vcpu);
}

/* The debug registers are KVM's only: see the head of this file. */
static int handle_dr(struct kvm_vcpu *vcpu)
{
	unsigned long q = to_l4h(vcpu)->x.qualification;
	int dr = q & 7, reg = (q >> 8) & 15, err = 1;

	if (!kvm_require_dr(vcpu, dr))
		return 1;
	if (l4h_get_cpl(vcpu) == 0) {
		if (q & 16) {
			kvm_register_write(vcpu, reg, kvm_get_dr(vcpu, dr));
			err = 0;
		} else {
			err = kvm_set_dr(vcpu, dr, kvm_register_read(vcpu, reg));
		}
	}
	return kvm_complete_insn_gp(vcpu, err);
}

static int handle_task_switch(struct kvm_vcpu *vcpu)
{
	struct l4h_vmexit *x = &to_l4h(vcpu)->x;
	int idt_v = x->idt_vector_info & VECTORING_INFO_VALID_MASK;
	int type = x->idt_vector_info & VECTORING_INFO_TYPE_MASK;
	int idt_index = x->idt_vector_info & VECTORING_INFO_VECTOR_MASK;
	int reason = (u32)x->qualification >> 30;
	bool has_error_code = false;
	u32 error_code = 0;

	if (reason == TASK_SWITCH_GATE && idt_v) {
		switch (type) {
		case INTR_TYPE_NMI_INTR:
			vcpu->arch.nmi_injected = false;
			l4h_set_nmi_mask(vcpu, true);
			break;
		case INTR_TYPE_EXT_INTR:
		case INTR_TYPE_SOFT_INTR:
			kvm_clear_interrupt_queue(vcpu);
			break;
		case INTR_TYPE_HARD_EXCEPTION:
			if (x->idt_vector_info & VECTORING_INFO_DELIVER_CODE_MASK) {
				has_error_code = true;
				error_code = x->idt_vector_error;
			}
			fallthrough;
		case INTR_TYPE_SOFT_EXCEPTION:
			kvm_clear_exception_queue(vcpu);
			break;
		}
	}
	if (!idt_v || (type != INTR_TYPE_HARD_EXCEPTION && type != INTR_TYPE_EXT_INTR &&
		       type != INTR_TYPE_NMI_INTR))
		l4h_skip_emulated_instruction(vcpu);
	return kvm_task_switch(vcpu, (u16)x->qualification,
			       type == INTR_TYPE_SOFT_INTR ? idt_index : -1,
			       reason, has_error_code, error_code);
}

static int handle_ept_violation(struct kvm_vcpu *vcpu)
{
	struct l4h_vmexit *x = &to_l4h(vcpu)->x;
	unsigned long q = x->qualification;
	u64 error;

	if (!(x->idt_vector_info & VECTORING_INFO_VALID_MASK) && (q & INTR_INFO_UNBLOCK_NMI))
		l4h_set_nmi_mask(vcpu, true);
	error = (q & EPT_VIOLATION_ACC_READ) ? PFERR_USER_MASK : 0;
	error |= (q & EPT_VIOLATION_ACC_WRITE) ? PFERR_WRITE_MASK : 0;
	error |= (q & EPT_VIOLATION_ACC_INSTR) ? PFERR_FETCH_MASK : 0;
	error |= (q & EPT_VIOLATION_PROT_MASK) ? PFERR_PRESENT_MASK : 0;
	if (q & EPT_VIOLATION_GVA_IS_VALID)
		error |= (q & EPT_VIOLATION_GVA_TRANSLATED) ?
			 PFERR_GUEST_FINAL_MASK : PFERR_GUEST_PAGE_MASK;
	return kvm_mmu_page_fault(vcpu, x->gpa, error, NULL, 0);
}

static int l4h_handle_exit(struct kvm_vcpu *vcpu, fastpath_t fastpath)
{
	struct vcpu_l4h *l = to_l4h(vcpu);
	struct l4h_vmexit *x = &l->x;

	switch (x->reason) {
	case EXIT_REASON_EXCEPTION_NMI:
		return handle_exception(vcpu);
	case EXIT_REASON_EXTERNAL_INTERRUPT:
		++vcpu->stat.irq_exits;
		return 1;
	case EXIT_REASON_TRIPLE_FAULT:
		vcpu->run->exit_reason = KVM_EXIT_SHUTDOWN;
		vcpu->mmio_needed = 0;
		return 0;
	case EXIT_REASON_INIT_SIGNAL:
	case EXIT_REASON_SIPI_SIGNAL:
		return 1;
	case EXIT_REASON_INTERRUPT_WINDOW:
		exec_control_update(vcpu, 0, CPU_BASED_INTR_WINDOW_EXITING);
		kvm_make_request(KVM_REQ_EVENT, vcpu);
		++vcpu->stat.irq_window_exits;
		return 1;
	case EXIT_REASON_NMI_WINDOW:
		exec_control_update(vcpu, 0, CPU_BASED_NMI_WINDOW_EXITING);
		kvm_make_request(KVM_REQ_EVENT, vcpu);
		++vcpu->stat.nmi_window_exits;
		return 1;
	case EXIT_REASON_TASK_SWITCH:
		return handle_task_switch(vcpu);
	case EXIT_REASON_CPUID:
		return kvm_emulate_cpuid(vcpu);
	case EXIT_REASON_HLT:
		return kvm_emulate_halt(vcpu);
	case EXIT_REASON_INVD:
		return kvm_emulate_invd(vcpu);
	case EXIT_REASON_WBINVD:
		return kvm_emulate_wbinvd(vcpu);
	case EXIT_REASON_RDPMC:
		return kvm_emulate_rdpmc(vcpu);
	case EXIT_REASON_VMCALL:
		return kvm_emulate_hypercall(vcpu);
	case EXIT_REASON_VMCLEAR ... EXIT_REASON_VMON:
	case EXIT_REASON_INVEPT:
	case EXIT_REASON_INVVPID:
		kvm_queue_exception(vcpu, UD_VECTOR);
		return 1;
	case EXIT_REASON_CR_ACCESS:
		return handle_cr(vcpu);
	case EXIT_REASON_DR_ACCESS:
		return handle_dr(vcpu);
	case EXIT_REASON_IO_INSTRUCTION:
		return handle_io(vcpu);
	case EXIT_REASON_MSR_READ:
		return kvm_emulate_rdmsr(vcpu);
	case EXIT_REASON_MSR_WRITE:
		return kvm_emulate_wrmsr(vcpu);
	case EXIT_REASON_MWAIT_INSTRUCTION:
		return kvm_emulate_mwait(vcpu);
	case EXIT_REASON_MONITOR_INSTRUCTION:
		return kvm_emulate_monitor(vcpu);
	case EXIT_REASON_PAUSE_INSTRUCTION:
		return kvm_skip_emulated_instruction(vcpu);
	case EXIT_REASON_EPT_VIOLATION:
		return handle_ept_violation(vcpu);
	case EXIT_REASON_XSETBV:
		return kvm_emulate_xsetbv(vcpu);
	case EXIT_REASON_INVALID_STATE:
	case EXIT_REASON_MSR_LOAD_FAIL:
	case 0xffffffff:	/* the entry instruction failed */
		vcpu->run->exit_reason = KVM_EXIT_FAIL_ENTRY;
		vcpu->run->fail_entry.hardware_entry_failure_reason = x->reason;
		vcpu->run->fail_entry.cpu = vcpu->arch.last_vmentry_cpu;
		return 0;
	}
	return internal_error(vcpu);
}

static void l4h_get_exit_info(struct kvm_vcpu *vcpu, u32 *reason, u64 *info1, u64 *info2,
			      u32 *intr_info, u32 *error_code)
{
	struct l4h_vmexit *x = &to_l4h(vcpu)->x;

	*reason = x->reason;
	*info1 = x->qualification;
	*info2 = 0;
	*intr_info = x->exit_intr_info;
	*error_code = x->exit_intr_error;
}

static void l4h_get_entry_info(struct kvm_vcpu *vcpu, u32 *intr_info, u32 *error_code)
{
	*intr_info = to_l4h(vcpu)->entry_intr;
	*error_code = to_l4h(vcpu)->entry_error;
}

/* ---- VMs and the rest of the interface */

static void l4h_nop_vcpu(struct kvm_vcpu *vcpu)
{
}

static int l4h_vm_init(struct kvm *kvm)
{
	return l4h_ept_init(to_ept(kvm));
}

static void l4h_vm_destroy(struct kvm *kvm)
{
}

/* After KVM's last use of the MMU; maybe with no l4h_vm_init() before it. */
void l4h_kvm_vm_free(struct kvm *kvm)
{
	if (to_ept(kvm)->root)
		l4h_ept_destroy(to_ept(kvm));
}

static int l4h_ok(void)
{
	return 0;
}

static void l4h_disable_cpu(void)
{
}

static void l4h_vcpu_after_set_cpuid(struct kvm_vcpu *vcpu)
{
	update_exception_bitmap(vcpu);
}

static void l4h_set_dr7(struct kvm_vcpu *vcpu, unsigned long value)
{
}

static void l4h_refresh_apicv(struct kvm_vcpu *vcpu)
{
}

static bool l4h_has_wbinvd_exit(void)
{
	return true;
}

static u64 l4h_l2_zero(struct kvm_vcpu *vcpu)
{
	return 0;
}

static void l4h_write_tsc_offset(struct kvm_vcpu *vcpu)
{
	vmcs_wr(vcpu, TSC_OFFSET, vcpu->arch.tsc_offset);
}

static int l4h_check_intercept(struct kvm_vcpu *vcpu, struct x86_instruction_info *info,
			       enum x86_intercept_stage stage,
			       struct x86_exception *exception)
{
	return X86EMUL_CONTINUE;
}

static int l4h_check_emulate_instruction(struct kvm_vcpu *vcpu, int emul_type, void *insn,
					 int insn_len)
{
	return X86EMUL_CONTINUE;
}

static void l4h_patch_hypercall(struct kvm_vcpu *vcpu, unsigned char *hypercall)
{
	hypercall[0] = 0x0f;
	hypercall[1] = 0x01;
	hypercall[2] = 0xc1;	/* vmcall */
}

static void l4h_handle_exit_irqoff(struct kvm_vcpu *vcpu)
{
}

static void l4h_setup_mce(struct kvm_vcpu *vcpu)
{
}

static bool l4h_init_signal_blocked(struct kvm_vcpu *vcpu)
{
	return false;
}

static void l4h_sync_dirty_debug_regs(struct kvm_vcpu *vcpu)
{
}

/* No nested VMX: a guest never enters guest mode, and none of these runs. */
static bool l4h_is_exception_vmexit(struct kvm_vcpu *vcpu, u8 vector, u32 error_code)
{
	return false;
}

static int l4h_nested_check_events(struct kvm_vcpu *vcpu)
{
	return 0;
}

static int l4h_nested_get_state(struct kvm_vcpu *vcpu, struct kvm_nested_state __user *state,
				unsigned int size)
{
	return -EINVAL;
}

static int l4h_nested_set_state(struct kvm_vcpu *vcpu, struct kvm_nested_state __user *ustate,
				struct kvm_nested_state *state)
{
	return -EINVAL;
}

static bool l4h_nested_state_pages(struct kvm_vcpu *vcpu)
{
	return true;
}

static const struct kvm_x86_nested_ops l4h_nested_ops = {
	.leave_nested = l4h_nop_vcpu,
	.is_exception_vmexit = l4h_is_exception_vmexit,
	.check_events = l4h_nested_check_events,
	.triple_fault = l4h_nop_vcpu,
	.get_state = l4h_nested_get_state,
	.set_state = l4h_nested_set_state,
	.get_nested_state_pages = l4h_nested_state_pages,
	.hv_inject_synthetic_vmexit_post_tlb_flush = l4h_nop_vcpu,
};

static struct kvm_x86_ops l4h_x86_ops __initdata = {
	.nested_ops = &l4h_nested_ops,
	.name = "l4h",
	.vm_size = sizeof(struct kvm_l4h),
	.check_processor_compatibility = l4h_ok,
	.enable_virtualization_cpu = l4h_ok,
	.disable_virtualization_cpu = l4h_disable_cpu,
	.hardware_unsetup = l4h_disable_cpu,
	.has_emulated_msr = l4h_has_emulated_msr,
	.vcpu_after_set_cpuid = l4h_vcpu_after_set_cpuid,
	.vm_init = l4h_vm_init,
	.vm_destroy = l4h_vm_destroy,
	.vcpu_create = l4h_vcpu_create,
	.vcpu_free = l4h_vcpu_free,
	.vcpu_reset = l4h_vcpu_reset,
	.prepare_switch_to_guest = l4h_prepare_switch,
	.vcpu_load = l4h_vcpu_load,
	.vcpu_put = l4h_vcpu_put,
	.update_exception_bitmap = update_exception_bitmap,
	.get_feature_msr = l4h_get_feature_msr,
	.get_msr = l4h_get_msr,
	.set_msr = l4h_set_msr,
	.get_segment_base = l4h_get_segment_base,
	.get_segment = l4h_get_segment,
	.set_segment = l4h_set_segment,
	.get_cpl = l4h_get_cpl,
	.get_cpl_no_cache = l4h_get_cpl,
	.get_cs_db_l_bits = l4h_get_cs_db_l_bits,
	.is_valid_cr0 = l4h_is_valid_cr0,
	.set_cr0 = l4h_set_cr0,
	.is_valid_cr4 = l4h_is_valid_cr4,
	.set_cr4 = l4h_set_cr4,
	.set_efer = l4h_set_efer,
	.get_idt = l4h_get_idt,
	.set_idt = l4h_set_idt,
	.get_gdt = l4h_get_gdt,
	.set_gdt = l4h_set_gdt,
	.sync_dirty_debug_regs = l4h_sync_dirty_debug_regs,
	.set_dr7 = l4h_set_dr7,
	.cache_reg = l4h_cache_reg,
	.get_rflags = l4h_get_rflags,
	.set_rflags = l4h_set_rflags,
	.get_if_flag = l4h_get_if_flag,
	.flush_tlb_all = l4h_flush_tlb_noop,
	.flush_tlb_current = l4h_flush_tlb_noop,
	.flush_tlb_gva = l4h_flush_tlb_gva,
	.flush_tlb_guest = l4h_flush_tlb_guest,
	.vcpu_pre_run = l4h_vcpu_pre_run,
	.vcpu_run = l4h_vcpu_run,
	.handle_exit = l4h_handle_exit,
	.skip_emulated_instruction = l4h_skip_emulated_instruction,
	.set_interrupt_shadow = l4h_set_interrupt_shadow,
	.get_interrupt_shadow = l4h_get_interrupt_shadow,
	.patch_hypercall = l4h_patch_hypercall,
	.inject_irq = l4h_inject_irq,
	.inject_nmi = l4h_inject_nmi,
	.inject_exception = l4h_inject_exception,
	.cancel_injection = l4h_cancel_injection,
	.interrupt_allowed = l4h_interrupt_allowed,
	.nmi_allowed = l4h_nmi_allowed,
	.get_nmi_mask = l4h_get_nmi_mask,
	.set_nmi_mask = l4h_set_nmi_mask,
	.enable_nmi_window = l4h_enable_nmi_window,
	.enable_irq_window = l4h_enable_irq_window,
	.refresh_apicv_exec_ctrl = l4h_refresh_apicv,
	.deliver_interrupt = l4h_deliver_interrupt,
	.load_mmu_pgd = l4h_load_mmu_pgd,
	.has_wbinvd_exit = l4h_has_wbinvd_exit,
	.get_l2_tsc_offset = l4h_l2_zero,
	.get_l2_tsc_multiplier = l4h_l2_zero,
	.write_tsc_offset = l4h_write_tsc_offset,
	.write_tsc_multiplier = l4h_nop_vcpu,
	.get_exit_info = l4h_get_exit_info,
	.get_entry_info = l4h_get_entry_info,
	.check_intercept = l4h_check_intercept,
	.handle_exit_irqoff = l4h_handle_exit_irqoff,
	.setup_mce = l4h_setup_mce,
	.check_emulate_instruction = l4h_check_emulate_instruction,
	.apic_init_signal_blocked = l4h_init_signal_blocked,
	.recalc_intercepts = l4h_nop_vcpu,
	.complete_emulated_msr = kvm_complete_insn_gp,
	.vcpu_deliver_sipi_vector = kvm_vcpu_deliver_sipi_vector,
};

/* What neither seL4's VCPU interface nor XCR0 lets a guest have. */
static void __init set_cpu_caps(void)
{
	kvm_set_cpu_caps();
	kvm_cpu_cap_clear(X86_FEATURE_VMX);
	kvm_cpu_cap_clear(X86_FEATURE_PDCM);
	kvm_cpu_cap_clear(X86_FEATURE_DS);
	kvm_cpu_cap_clear(X86_FEATURE_DTES64);
	kvm_cpu_cap_clear(X86_FEATURE_XSAVES);
	kvm_cpu_cap_clear(X86_FEATURE_RDTSCP);
	kvm_cpu_cap_clear(X86_FEATURE_RDPID);
	kvm_cpu_cap_clear(X86_FEATURE_PKU);
	kvm_cpu_cap_clear(X86_FEATURE_OSPKE);
	kvm_cpu_cap_clear(X86_FEATURE_WAITPKG);
	kvm_cpu_cap_clear(X86_FEATURE_SHSTK);
	kvm_cpu_cap_clear(X86_FEATURE_IBT);
	kvm_cpu_cap_clear(X86_FEATURE_INTEL_PT);
	kvm_cpu_cap_clear(X86_FEATURE_SGX);
	kvm_cpu_cap_clear(X86_FEATURE_SGX_LC);
	kvm_cpu_cap_clear(X86_FEATURE_SGX1);
	kvm_cpu_cap_clear(X86_FEATURE_SGX2);
	kvm_cpu_cap_clear(X86_FEATURE_MPX);
	kvm_cpu_cap_clear(X86_FEATURE_LAM);
	kvm_cpu_cap_clear(X86_FEATURE_FRED);
	kvm_cpu_cap_clear(X86_FEATURE_LKGS);
	kvm_cpu_cap_clear(X86_FEATURE_XFD);
	/* The guest could not switch these MSRs. */
	kvm_cpu_cap_clear(X86_FEATURE_SPEC_CTRL);
	kvm_cpu_cap_clear(X86_FEATURE_INTEL_STIBP);
	kvm_cpu_cap_clear(X86_FEATURE_SPEC_CTRL_SSBD);
	kvm_cpu_cap_clear(X86_FEATURE_ARCH_CAPABILITIES);
	kvm_cpu_cap_clear(X86_FEATURE_FLUSH_L1D);
	kvm_caps.supported_xss = 0;
}

static int __init l4h_hardware_setup(void)
{
	enable_apicv = false;
	enable_pmu = false;
	/* No accessed and dirty bits: seL4's EPT has them off.  Write
	 * protection serves dirty logging. */
	kvm_mmu_set_ept_masks(false, false);
	/* The hardware walks the EPT, where those SPTEs do not exist. */
	enable_mmio_caching = false;
	kvm_configure_mmu(true, 0, 4, PG_LEVEL_2M);
	if (boot_cpu_has(X86_FEATURE_NX))
		kvm_enable_efer_bits(EFER_NX);
	set_cpu_caps();
	return 0;
}

/* No counters: enable_pmu is off, and none of these is called. */
static struct kvm_pmc *l4h_pmc_none(struct kvm_vcpu *vcpu, unsigned int idx, u64 *mask)
{
	return NULL;
}

static struct kvm_pmc *l4h_msr_pmc_none(struct kvm_vcpu *vcpu, u32 msr)
{
	return NULL;
}

static bool l4h_pmu_msr_invalid(struct kvm_vcpu *vcpu, u32 msr)
{
	return false;
}

static int l4h_pmu_msr_fail(struct kvm_vcpu *vcpu, struct msr_data *msr)
{
	return 1;
}

static struct kvm_pmu_ops l4h_pmu_ops __initdata = {
	.rdpmc_ecx_to_pmc = l4h_pmc_none,
	.msr_idx_to_pmc = l4h_msr_pmc_none,
	.is_valid_msr = l4h_pmu_msr_invalid,
	.get_msr = l4h_pmu_msr_fail,
	.set_msr = l4h_pmu_msr_fail,
	.refresh = l4h_nop_vcpu,
	.init = l4h_nop_vcpu,
	.MAX_NR_GP_COUNTERS = 0,
	.MIN_NR_GP_COUNTERS = 0,
};

static struct kvm_x86_init_ops l4h_init_ops __initdata = {
	.hardware_setup = l4h_hardware_setup,
	.runtime_ops = &l4h_x86_ops,
	.pmu_ops = &l4h_pmu_ops,
};

/* Fill in what x86's boot code would have about the CPU, before KVM's
 * module init reads it (the physical address width, for SPTEs). */
static int __init cpu_setup(void)
{
	struct cpuinfo_um *c = &boot_cpu_data;
	u32 eax, ebx, ecx, edx;

	cpuid(0, &eax, &ebx, &ecx, &edx);
	c->x86_vendor = ebx == 0x756e6547 ? X86_VENDOR_INTEL : X86_VENDOR_AMD;
	eax = cpuid_eax(1);
	c->x86 = (eax >> 8) & 15;
	if (c->x86 == 15)
		c->x86 += (eax >> 20) & 0xff;
	c->x86_model = (eax >> 4) & 15;
	if (c->x86 >= 6)
		c->x86_model |= (eax >> 12) & 0xf0;
	c->x86_stepping = eax & 15;
	c->extended_cpuid_level = cpuid_eax(0x80000000);
	eax = c->extended_cpuid_level >= 0x80000008 ? cpuid_eax(0x80000008) : 36;
	c->x86_phys_bits = c->x86_cache_bits = eax & 0xff;
	c->x86_virt_bits = (eax >> 8) & 0xff;
	/* MSR_TSC_AUX is the host's: seL4 does not switch it. */
	clear_bit(X86_FEATURE_RDTSCP, (unsigned long *)c->x86_capability);
	clear_bit(X86_FEATURE_RDPID, (unsigned long *)c->x86_capability);
	return 0;
}
arch_initcall(cpu_setup);

static int __init l4h_kvm_init(void)
{
	int err;

	if (!l4h_bootinfo->nr_ept_roots) {
		pr_info("no VT-x on this host\n");
		return 0;
	}
	enable_pmu = false;
	l4h_kvm_fpu_init();
	l4h_ept_pool_init(l4h_bootinfo->nr_ept_roots);
	err = kvm_x86_vendor_init(&l4h_init_ops);
	if (err)
		return err;
	err = kvm_init(sizeof(struct vcpu_l4h), __alignof__(struct vcpu_l4h), THIS_MODULE);
	if (err)
		kvm_x86_vendor_exit();
	return err;
}
late_initcall(l4h_kvm_init);

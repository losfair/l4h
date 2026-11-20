// SPDX-License-Identifier: GPL-2.0
/*
 * KVM vCPUs on FL4 VCPUs: the world switch of a VHE host (__kvm_vcpu_run).
 *
 * Each KVM vCPU has an FL4 VCPU object bound to a TCB of ours whose VSpace
 * is the VM's Stage-2 root and whose fault endpoint, badged for it, is the
 * endpoint of the vCPU of ours it runs on.  It runs as a user context does
 * (guest/provider l4h_arm_vcpu_run(), user.c): our kernel thread lends it
 * this vCPU's user scheduling context and receives its exits as faults;
 * an event for this vCPU stops it.  Unlike a user context, the TCB never
 * traps syscalls: they are the guest's.
 *
 * KVM keeps a VM's registers in memory (vcpu->arch.ctxt, never
 * SYSREGS_ON_CPU).  What a VHE host keeps in the CPU while a vCPU is
 * loaded, the virtual timer and the VGIC, is in `state`, the page FL4
 * transfers a VCPU's registers through: arch/arm64/kvm reaches it with its
 * system register accesses (init.c, vgic.c), as it would the hardware's.
 * Around each entry, the rest of the context goes into `state` and back.
 */
#undef pr_fmt
#define pr_fmt(fmt) "l4h-kvm: " fmt

#include <linux/kvm_host.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>
#include <kvm/arm_arch_timer.h>
#include <l4h_sys.h>
#include "l4h_kvm_arm64.h"

/* uctx.c's: a CNode with nothing in it. */
#define EMPTY_CNODE	L4H_CPTR2(L4H_SLOT_META, L4H_META_DYN_BASE)
/* Fault badges of VM TCBs: never a user context's. */
#define VM_BADGE	(L4H_EP_BADGE_TASK | (1ull << 61))

DEFINE_PER_CPU(struct l4h_arm_vcpu *, l4h_loaded_vcpu);
static atomic64_t vm_tcb_ids = ATOMIC64_INIT(0);

/* EL1 registers FL4 switches (seL4_VCPUReg), with KVM's names for them. */
static const struct {
	u8 fl4;
	u16 kvm;
} el1_regs[] = {
	{ L4H_ARM_VCPUREG_SCTLR, SCTLR_EL1 },
	{ L4H_ARM_VCPUREG_CPACR, CPACR_EL1 },
	{ L4H_ARM_VCPUREG_TCR, TCR_EL1 },
	{ L4H_ARM_VCPUREG_TTBR0, TTBR0_EL1 },
	{ L4H_ARM_VCPUREG_TTBR1, TTBR1_EL1 },
	{ L4H_ARM_VCPUREG_MAIR, MAIR_EL1 },
	{ L4H_ARM_VCPUREG_AMAIR, AMAIR_EL1 },
	{ L4H_ARM_VCPUREG_CIDR, CONTEXTIDR_EL1 },
	{ L4H_ARM_VCPUREG_AFSR0, AFSR0_EL1 },
	{ L4H_ARM_VCPUREG_AFSR1, AFSR1_EL1 },
	{ L4H_ARM_VCPUREG_ESR, ESR_EL1 },
	{ L4H_ARM_VCPUREG_FAR, FAR_EL1 },
	{ L4H_ARM_VCPUREG_PAR, PAR_EL1 },
	{ L4H_ARM_VCPUREG_VBAR, VBAR_EL1 },
	{ L4H_ARM_VCPUREG_TPIDR_EL1, TPIDR_EL1 },
	{ L4H_ARM_VCPUREG_SP_EL1, SP_EL1 },
	{ L4H_ARM_VCPUREG_ELR_EL1, ELR_EL1 },
	{ L4H_ARM_VCPUREG_SPSR_EL1, SPSR_EL1 },
	{ L4H_ARM_VCPUREG_CSSELR_EL1, CSSELR_EL1 },
	{ L4H_ARM_VCPUREG_CNTKCTL_EL1, CNTKCTL_EL1 },
	{ L4H_ARM_VCPUREG_ACTLR_EL1, ACTLR_EL1 },
	{ L4H_ARM_VCPUREG_MDSCR_EL1, MDSCR_EL1 },
	{ L4H_ARM_VCPUREG_MDCCINT_EL1, MDCCINT_EL1 },
};

/* gprs[] of struct l4h_arm_vcpu_state. */
#define GPR_SP_EL0	31
#define GPR_PC		32
#define GPR_PSTATE	33
#define GPR_TPIDR_EL0	35
#define GPR_TPIDRRO_EL0	36

static inline struct l4h_arm_vcpu *to_l4h(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.l4h;
}

int l4h_arm_vcpu_create(struct kvm_vcpu *vcpu)
{
	struct l4h_s2 *s = to_s2(vcpu->kvm);
	struct l4h_arm_vcpu *v;
	struct page *page;
	int err;

	if (!s)
		return -EINVAL;
	v = kzalloc(sizeof(*v), GFP_KERNEL_ACCOUNT);
	if (!v)
		return -ENOMEM;
	page = alloc_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (!page) {
		err = -ENOMEM;
		goto fail;
	}
	v->vcpu = vcpu;
	v->state = page_address(page);
	v->state_frame = L4H_FRAME_CPTR(page_to_phys(page));
	v->s2_root = s->root;
	for (;;) {
		err = l4h_obj_alloc(L4H_OBJ_VCPU, 0, &v->vcpu_obj);
		if (err != -ENOMEM || !l4h_objmem_wait())
			break;
	}
	if (err)
		goto fail_page;
	err = l4h_obj_alloc(L4H_OBJ_TCB, 0, &v->tcb_obj);
	if (err)
		goto fail_vcpu;
	err = l4h_obj_alloc(L4H_OBJ_REPLY, 0, &v->reply_obj);
	if (err)
		goto fail_tcb;
	v->uctx.fault_ep = l4h_slot_alloc();
	if (!v->uctx.fault_ep) {
		err = -ENOMEM;
		goto fail_reply;
	}
	v->uctx.tcb = v->tcb_obj.cptr;
	v->uctx.reply = v->reply_obj.cptr;
	v->uctx.badge = VM_BADGE | atomic64_inc_return(&vm_tcb_ids);
	v->uctx.fault_ep_vcpu = -1;
	v->uctx.sc_vcpu = -1;
	v->uctx.vspace = s->root;
	/* FP on, and the guest's own syscalls. */
	if (l4h_tcb_set_flags(v->uctx.tcb, 1 /* fpuDisabled */, 0) ||
	    l4h_tcb_configure_user(v->uctx.tcb, EMPTY_CNODE, s->root) ||
	    l4h_arm_vcpu_set_tcb(v->vcpu_obj.cptr, v->uctx.tcb)) {
		err = -EINVAL;
		goto fail_ep;
	}
	v->uctx.state = L4H_UCTX_FRESH;
	vcpu->arch.l4h = v;
	return 0;

fail_ep:
	l4h_slot_free(v->uctx.fault_ep);
fail_reply:
	l4h_obj_free(&v->reply_obj);
fail_tcb:
	l4h_obj_free(&v->tcb_obj);
fail_vcpu:
	l4h_obj_free(&v->vcpu_obj);
fail_page:
	__free_page(page);
fail:
	kfree(v);
	return err;
}

void l4h_arm_vcpu_destroy(struct kvm_vcpu *vcpu)
{
	struct l4h_arm_vcpu *v = to_l4h(vcpu);

	if (!v)
		return;
	vcpu->arch.l4h = NULL;
	/* vcpu_put() gave the scheduling context back. */
	WARN_ON(v->uctx.sc_vcpu >= 0);
	l4h_obj_free(&v->vcpu_obj);
	l4h_obj_free(&v->tcb_obj);
	l4h_obj_free(&v->reply_obj);
	l4h_slot_delete(v->uctx.fault_ep);
	free_page((unsigned long)v->state);
	kfree(v);
}

/* ---- loading */

void l4h_arm_vcpu_load(struct kvm_vcpu *vcpu)
{
	this_cpu_write(l4h_loaded_vcpu, to_l4h(vcpu));
}

/* The task may leave this vCPU of ours: our scheduling context stays. */
void l4h_arm_vcpu_put(struct kvm_vcpu *vcpu)
{
	struct l4h_arm_vcpu *v = to_l4h(vcpu);

	if (v)
		l4h_user_deschedule(&v->uctx);
	this_cpu_write(l4h_loaded_vcpu, NULL);
}

void kvm_vcpu_load_vhe(struct kvm_vcpu *vcpu)
{
}

void kvm_vcpu_put_vhe(struct kvm_vcpu *vcpu)
{
}

/* FP/SIMD is synced around each entry (__kvm_vcpu_run()). */
void kvm_arch_vcpu_load_fp(struct kvm_vcpu *vcpu)
{
}

void kvm_arch_vcpu_put_fp(struct kvm_vcpu *vcpu)
{
}

void kvm_arch_vcpu_ctxflush_fp(struct kvm_vcpu *vcpu)
{
}

void kvm_arch_vcpu_ctxsync_fp(struct kvm_vcpu *vcpu)
{
}

/*
 * The virtual timer of the loaded vCPU, as a VHE host reaches it
 * (CNTV_*_EL02, CNTVOFF_EL2), for arch_timer.c.  ISTATUS is what it would
 * read now.
 */
bool l4h_sysreg_vcpu(u32 enc, u64 *val, bool write)
{
	struct l4h_arm_vcpu *v = this_cpu_read(l4h_loaded_vcpu);
	u64 *r;

	if (!v)
		return false;
	switch (enc) {
	case SYS_CNTV_CTL_EL02:
	case SYS_CNTV_CTL_EL0:
		r = &v->state->regs[L4H_ARM_VCPUREG_CNTV_CTL];
		if (write) {
			*r = *val & ~ARCH_TIMER_CTRL_IT_STAT;
		} else {
			u64 now = kvm_phys_timer_read() - v->state->regs[L4H_ARM_VCPUREG_CNTVOFF];

			*val = *r & ~ARCH_TIMER_CTRL_IT_STAT;
			if ((*r & ARCH_TIMER_CTRL_ENABLE) &&
			    now >= v->state->regs[L4H_ARM_VCPUREG_CNTV_CVAL])
				*val |= ARCH_TIMER_CTRL_IT_STAT;
		}
		return true;
	case SYS_CNTV_CVAL_EL02:
	case SYS_CNTV_CVAL_EL0:
		r = &v->state->regs[L4H_ARM_VCPUREG_CNTV_CVAL];
		break;
	case SYS_CNTVOFF_EL2:
		r = &v->state->regs[L4H_ARM_VCPUREG_CNTVOFF];
		break;
	default:
		return false;
	}
	if (write)
		*r = *val;
	else
		*val = *r;
	return true;
}

void __kvm_timer_set_cntvoff(u64 cntvoff)
{
	l4h_kvm_write_sysreg(SYS_CNTVOFF_EL2, cntvoff);
}

/* ---- the world switch */

static void ctxt_to_state(struct kvm_vcpu *vcpu, struct l4h_arm_vcpu_state *st)
{
	struct kvm_cpu_context *ctxt = &vcpu->arch.ctxt;
	int i;

	for (i = 0; i < 31; i++)
		st->gprs[i] = ctxt->regs.regs[i];
	st->gprs[GPR_SP_EL0] = ctxt->regs.sp;
	st->gprs[GPR_PC] = ctxt->regs.pc;
	st->gprs[GPR_PSTATE] = ctxt->regs.pstate;
	st->gprs[GPR_TPIDR_EL0] = ctxt_sys_reg(ctxt, TPIDR_EL0);
	st->gprs[GPR_TPIDRRO_EL0] = ctxt_sys_reg(ctxt, TPIDRRO_EL0);
	for (i = 0; i < ARRAY_SIZE(el1_regs); i++)
		st->regs[el1_regs[i].fl4] = ctxt_sys_reg(ctxt, el1_regs[i].kvm);
	st->regs[L4H_ARM_VCPUREG_VMPIDR_EL2] = ctxt_sys_reg(ctxt, MPIDR_EL1);
	st->regs[L4H_ARM_VCPUREG_VPIDR_EL2] = kvm_read_vm_id_reg(vcpu->kvm, SYS_MIDR_EL1);
	st->regs[L4H_ARM_VCPUREG_HCR_EL2] = vcpu->arch.hcr_el2;
	st->regs[L4H_ARM_VCPUREG_VSESR_EL2] = ctxt_sys_reg(ctxt, VSESR_EL2);
}

static void state_to_ctxt(struct kvm_vcpu *vcpu, const struct l4h_arm_vcpu_state *st)
{
	struct kvm_cpu_context *ctxt = &vcpu->arch.ctxt;
	int i;

	for (i = 0; i < 31; i++)
		ctxt->regs.regs[i] = st->gprs[i];
	ctxt->regs.sp = st->gprs[GPR_SP_EL0];
	ctxt->regs.pc = st->gprs[GPR_PC];
	ctxt->regs.pstate = st->gprs[GPR_PSTATE];
	ctxt_sys_reg(ctxt, TPIDR_EL0) = st->gprs[GPR_TPIDR_EL0];
	ctxt_sys_reg(ctxt, TPIDRRO_EL0) = st->gprs[GPR_TPIDRRO_EL0];
	for (i = 0; i < ARRAY_SIZE(el1_regs); i++)
		ctxt_sys_reg(ctxt, el1_regs[i].kvm) = st->regs[el1_regs[i].fl4];
}

/*
 * The level of the virtual timer's interrupt, after FL4 ran the guest
 * with the timer in the CPU.  FL4 masks PPI 27 when it fires (a VPPI exit)
 * until we acknowledge it: keep it masked while the interrupt is pending,
 * as arch_timer.c does with a host interrupt controller without an active
 * state, or the guest would make no progress.
 */
static void sync_vtimer(struct kvm_vcpu *vcpu, struct l4h_arm_vcpu *v)
{
	bool level;

	l4h_kvm_timer_sync(vcpu, &level);
	if (v->vppi_masked && !level) {
		WARN_ON_ONCE(l4h_arm_vcpu_ack_vppi(v->vcpu_obj.cptr, 27));
		v->vppi_masked = false;
	}
}

/* The fault endpoint of the vCPU of ours we are on, badged for this VCPU. */
static void bind_fault_ep(struct l4h_arm_vcpu *v)
{
	int cpu = l4h_this_vcpu_id();

	if (v->uctx.fault_ep_vcpu == cpu)
		return;
	if (v->uctx.sc_vcpu >= 0)
		l4h_user_deschedule(&v->uctx);
	if (v->uctx.fault_ep_vcpu >= 0)
		WARN_ON(l4h_cnode_delete(v->uctx.fault_ep, 64));
	if (l4h_cnode_mint(v->uctx.fault_ep, 64, L4H_SLOT_VCPU(cpu) + L4H_VCPU_EP,
			   L4H_ROOT_DEPTH, L4H_RIGHTS_ALL, v->uctx.badge))
		panic("l4h: cannot mint a VM fault endpoint\n");
	if (l4h_tcb_set_space(v->uctx.tcb, v->uctx.fault_ep, EMPTY_CNODE, v->s2_root))
		panic("l4h: cannot set a VM TCB's fault endpoint\n");
	v->uctx.fault_ep_vcpu = cpu;
}

int __kvm_vcpu_run(struct kvm_vcpu *vcpu)
{
	struct l4h_arm_vcpu *v = to_l4h(vcpu);
	struct l4h_arm_vcpu_state *st = v->state;
	struct l4h_arm_vmexit x;
	struct l4h_uctx *owner;
	int ret = ARM_EXCEPTION_IRQ;

	/* Pending exceptions and PC increments, as hyp code applies them. */
	__kvm_adjust_pc(vcpu);

	bind_fault_ep(v);
	/* The VMM's own user context holds our scheduling context while it
	 * waits in KVM_RUN: the guest takes it, and it gets it back when it
	 * returns to user mode (l4h_user_run()). */
	owner = l4h_this_vcpu()->sc_owner;
	if (owner && owner != &v->uctx)
		l4h_user_deschedule(owner);
	ctxt_to_state(vcpu, st);
	if (l4h_arm_vcpu_write_state(v->vcpu_obj.cptr, v->state_frame, 0, L4H_ARM_VCPU_STATE_ALL) ||
	    l4h_fpu_write(&v->uctx, &vcpu->arch.ctxt.fp_regs, sizeof(vcpu->arch.ctxt.fp_regs))) {
		pr_err_ratelimited("cannot load vCPU %d's state\n", vcpu->vcpu_id);
		return ARM_EXCEPTION_IL;
	}

	l4h_arm_vcpu_run(&v->uctx, &x);

	if (l4h_arm_vcpu_read_state(v->vcpu_obj.cptr, v->state_frame, 0, L4H_ARM_VCPU_STATE_ALL) ||
	    l4h_fpu_read(&v->uctx, &vcpu->arch.ctxt.fp_regs, sizeof(vcpu->arch.ctxt.fp_regs))) {
		pr_err_ratelimited("cannot save vCPU %d's state\n", vcpu->vcpu_id);
		return ARM_EXCEPTION_IL;
	}
	state_to_ctxt(vcpu, st);
	switch (x.stop) {
	case L4H_ARM_STOP_VMFAULT:
		vcpu->arch.fault.esr_el2 = x.esr;
		vcpu->arch.fault.far_el2 = st->regs[L4H_ARM_VCPUREG_FAR_EL2];
		/* A valid FIPA (KVM checks NS, the hardware's "valid" bit). */
		vcpu->arch.fault.hpfar_el2 = ((x.ipa >> 8) & HPFAR_EL2_FIPA) | HPFAR_EL2_NS;
		ret = ARM_EXCEPTION_TRAP;
		break;
	case L4H_ARM_STOP_VCPUFAULT:
		vcpu->arch.fault.esr_el2 = x.esr;
		vcpu->arch.fault.far_el2 = st->regs[L4H_ARM_VCPUREG_FAR_EL2];
		vcpu->arch.fault.hpfar_el2 = st->regs[L4H_ARM_VCPUREG_HPFAR_EL2] | HPFAR_EL2_NS;
		ret = ARM_EXCEPTION_TRAP;
		break;
	case L4H_ARM_STOP_VPPI:
		if (x.vppi_irq == 27)
			v->vppi_masked = true;
		else
			WARN_ON_ONCE(l4h_arm_vcpu_ack_vppi(v->vcpu_obj.cptr, x.vppi_irq));
		break;
	case L4H_ARM_STOP_VGIC_MAINT:
	case L4H_ARM_STOP_INTERRUPT:
		/* vgic.c's sync and the events stopped it, nothing else. */
		break;
	default:
		pr_err_ratelimited("vCPU %d: unexpected FL4 exit %d\n", vcpu->vcpu_id, x.stop);
		ret = ARM_EXCEPTION_IL;
		break;
	}
	sync_vtimer(vcpu, v);
	return ret;
}

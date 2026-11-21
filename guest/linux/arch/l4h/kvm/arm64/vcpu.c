// SPDX-License-Identifier: GPL-2.0
/*
 * KVM vCPUs on FL4 VCPUs: the world switch of a VHE host (__kvm_vcpu_run).
 *
 * Each KVM vCPU has an FL4 VCPU object bound to a TCB of ours whose VSpace
 * is the VM's Stage-2 root.  Our kernel thread enters it itself
 * (seL4_ARM_VCPU_Run, guest/provider kvm.c l4h_arm_vcpu_enter()), on its
 * own scheduling context, until the guest exits or an event of this vCPU
 * of ours stops it: the TCB never runs on its own, and never traps
 * syscalls (they are the guest's).
 *
 * KVM keeps a VM's registers in memory (vcpu->arch.ctxt, never
 * SYSREGS_ON_CPU).  What a VHE host keeps in the CPU while a vCPU is
 * loaded, the virtual timer and the VGIC, is in `state`, our copy of what
 * FL4 holds: arch/arm64/kvm reaches it with its system register accesses
 * (init.c, vgic.c), as it would the hardware's.  Each entry sends FL4 the
 * groups of registers (L4H_ARM_VCPU_STATE_*) that changed since it last
 * had them and takes back those the guest changes, through the state area
 * of our vCPU's IPC buffer.  FP/SIMD stays in the TCB until KVM needs it.
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

DEFINE_PER_CPU(struct l4h_arm_vcpu *, l4h_loaded_vcpu);

/* EL1 registers FL4 switches (seL4_VCPUReg) in L4H_ARM_VCPU_STATE_EL1_SYSREGS,
 * with KVM's names for them.  CNTKCTL_EL1 is the TIMER group's. */
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
	{ L4H_ARM_VCPUREG_ACTLR_EL1, ACTLR_EL1 },
	{ L4H_ARM_VCPUREG_MDSCR_EL1, MDSCR_EL1 },
	{ L4H_ARM_VCPUREG_MDCCINT_EL1, MDCCINT_EL1 },
};

/* gprs[] of struct l4h_arm_vcpu_state. */
#define GPR_SP_EL0	31
#define GPR_PC		32
#define GPR_PSTATE	33
#define GPR_FAULT_IP	34
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
	int err;

	if (!s)
		return -EINVAL;
	v = kzalloc(sizeof(*v), GFP_KERNEL_ACCOUNT);
	if (!v)
		return -ENOMEM;
	v->state = kzalloc(sizeof(*v->state), GFP_KERNEL_ACCOUNT);
	if (!v->state) {
		err = -ENOMEM;
		goto fail;
	}
	v->vcpu = vcpu;
	v->s2_root = s->root;
	v->fp_state = L4H_FP_DIRTY;
	for (;;) {
		err = l4h_obj_alloc(L4H_OBJ_VCPU, 0, &v->vcpu_obj);
		if (err != -ENOMEM || !l4h_objmem_wait())
			break;
	}
	if (err)
		goto fail_state;
	err = l4h_obj_alloc(L4H_OBJ_TCB, 0, &v->tcb_obj);
	if (err)
		goto fail_vcpu;
	v->uctx.tcb = v->tcb_obj.cptr;
	v->uctx.vspace = s->root;
	v->uctx.fault_ep_vcpu = -1;
	v->uctx.sc_vcpu = -1;
	/* FP on, and the guest's own syscalls. */
	if (l4h_tcb_set_flags(v->uctx.tcb, 1 /* fpuDisabled */, 0) ||
	    l4h_tcb_configure_user(v->uctx.tcb, EMPTY_CNODE, s->root) ||
	    l4h_arm_vcpu_set_tcb(v->vcpu_obj.cptr, v->uctx.tcb)) {
		err = -EINVAL;
		goto fail_tcb;
	}
	vcpu->arch.l4h = v;
	return 0;

fail_tcb:
	l4h_obj_free(&v->tcb_obj);
fail_vcpu:
	l4h_obj_free(&v->vcpu_obj);
fail_state:
	kfree(v->state);
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
	l4h_obj_free(&v->vcpu_obj);
	l4h_obj_free(&v->tcb_obj);
	kfree(v->state);
	kfree(v);
}

/* ---- loading */

void l4h_arm_vcpu_load(struct kvm_vcpu *vcpu)
{
	this_cpu_write(l4h_loaded_vcpu, to_l4h(vcpu));
}

void l4h_arm_vcpu_put(struct kvm_vcpu *vcpu)
{
	this_cpu_write(l4h_loaded_vcpu, NULL);
}

void kvm_vcpu_load_vhe(struct kvm_vcpu *vcpu)
{
}

void kvm_vcpu_put_vhe(struct kvm_vcpu *vcpu)
{
}

/*
 * FP/SIMD: vcpu->arch.ctxt.fp_regs goes into the TCB before an entry when
 * KVM changed it (L4H_FP_DIRTY) and stays there (L4H_FP_IN_TCB), the guest
 * running with it, until KVM reads it (ONE_REG, guest.c) or resets it.
 */
void l4h_arm_vcpu_sync_fp(struct kvm_vcpu *vcpu, bool write)
{
	struct l4h_arm_vcpu *v = to_l4h(vcpu);

	if (!v)
		return;
	if (v->fp_state == L4H_FP_IN_TCB) {
		/* The IPC buffer's FPU scratch area is this vCPU of ours'. */
		preempt_disable();
		WARN_ON(l4h_fpu_read(&v->uctx, &vcpu->arch.ctxt.fp_regs,
				     sizeof(vcpu->arch.ctxt.fp_regs)));
		preempt_enable();
		v->fp_state = L4H_FP_IN_REGS;
	}
	if (write)
		v->fp_state = L4H_FP_DIRTY;
}

void l4h_arm_vcpu_reset_fp(struct kvm_vcpu *vcpu)
{
	struct l4h_arm_vcpu *v = to_l4h(vcpu);

	if (v)
		v->fp_state = L4H_FP_DIRTY;
}

/* Nothing to do on load and put: see l4h_arm_vcpu_sync_fp(). */
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
			if (*r != (*val & ~ARCH_TIMER_CTRL_IT_STAT))
				v->timer_dirty = true;
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
	if (write) {
		if (*r != *val)
			v->timer_dirty = true;
		*r = *val;
	} else {
		*val = *r;
	}
	return true;
}

void __kvm_timer_set_cntvoff(u64 cntvoff)
{
	l4h_kvm_write_sysreg(SYS_CNTVOFF_EL2, cntvoff);
}

/* ---- the world switch */

/*
 * What goes into FL4 for an entry: the groups of `ctxt` that differ from
 * what FL4 holds (v->state), all of them the first time, into `st` (the
 * IPC buffer's state area, which other VCPUs used since).  A group sent
 * is whole in `st`.  Returns the in_mask.
 */
static unsigned long ctxt_to_state(struct kvm_vcpu *vcpu, struct l4h_arm_vcpu *v,
				   struct l4h_arm_vcpu_state *st)
{
	struct kvm_cpu_context *ctxt = &vcpu->arch.ctxt;
	struct l4h_arm_vcpu_state *cur = v->state;
	unsigned long mask = 0;
	u64 gprs[37], hyp[4];
	static const u8 hyp_regs[4] = {
		L4H_ARM_VCPUREG_VMPIDR_EL2, L4H_ARM_VCPUREG_VPIDR_EL2,
		L4H_ARM_VCPUREG_HCR_EL2, L4H_ARM_VCPUREG_VSESR_EL2,
	};
	u64 cntkctl = ctxt_sys_reg(ctxt, CNTKCTL_EL1);
	int i;

	memcpy(gprs, ctxt->regs.regs, sizeof(ctxt->regs.regs));
	gprs[GPR_SP_EL0] = ctxt->regs.sp;
	gprs[GPR_PC] = ctxt->regs.pc;
	gprs[GPR_PSTATE] = ctxt->regs.pstate;
	gprs[GPR_FAULT_IP] = ctxt->regs.pc;	/* FL4 sets it */
	gprs[GPR_TPIDR_EL0] = ctxt_sys_reg(ctxt, TPIDR_EL0);
	gprs[GPR_TPIDRRO_EL0] = ctxt_sys_reg(ctxt, TPIDRRO_EL0);
	if (!v->synced || memcmp(gprs, cur->gprs, (GPR_PSTATE + 1) * sizeof(u64)) ||
	    gprs[GPR_TPIDR_EL0] != cur->gprs[GPR_TPIDR_EL0] ||
	    gprs[GPR_TPIDRRO_EL0] != cur->gprs[GPR_TPIDRRO_EL0]) {
		memcpy(cur->gprs, gprs, sizeof(gprs));
		memcpy(st->gprs, gprs, sizeof(gprs));
		mask |= L4H_ARM_VCPU_STATE_GPRS;
	}

	hyp[0] = ctxt_sys_reg(ctxt, MPIDR_EL1);
	hyp[1] = kvm_read_vm_id_reg(vcpu->kvm, SYS_MIDR_EL1);
	hyp[2] = vcpu->arch.hcr_el2;
	hyp[3] = ctxt_sys_reg(ctxt, VSESR_EL2);
	for (i = 0; i < ARRAY_SIZE(hyp_regs); i++) {
		if (!v->synced || cur->regs[hyp_regs[i]] != hyp[i]) {
			cur->regs[hyp_regs[i]] = hyp[i];
			mask |= L4H_ARM_VCPU_STATE_HYP;
		}
	}
	cur->regs[L4H_ARM_VCPUREG_VDISR_EL2] = 0;

	for (i = 0; i < ARRAY_SIZE(el1_regs); i++) {
		u64 r = ctxt_sys_reg(ctxt, el1_regs[i].kvm);

		if (!v->synced || cur->regs[el1_regs[i].fl4] != r) {
			cur->regs[el1_regs[i].fl4] = r;
			mask |= L4H_ARM_VCPU_STATE_EL1_SYSREGS;
		}
	}
	/* Both groups have VMPIDR_EL2. */
	if (mask & (L4H_ARM_VCPU_STATE_EL1_SYSREGS | L4H_ARM_VCPU_STATE_HYP)) {
		for (i = 0; i < ARRAY_SIZE(el1_regs); i++)
			st->regs[el1_regs[i].fl4] = cur->regs[el1_regs[i].fl4];
		for (i = 0; i < ARRAY_SIZE(hyp_regs); i++)
			st->regs[hyp_regs[i]] = cur->regs[hyp_regs[i]];
		st->regs[L4H_ARM_VCPUREG_VDISR_EL2] = 0;
	}

	if (!v->synced || v->timer_dirty || cur->regs[L4H_ARM_VCPUREG_CNTKCTL_EL1] != cntkctl) {
		cur->regs[L4H_ARM_VCPUREG_CNTKCTL_EL1] = cntkctl;
		for (i = L4H_ARM_VCPUREG_CNTV_CTL; i <= L4H_ARM_VCPUREG_CNTKCTL_EL1; i++)
			st->regs[i] = cur->regs[i];
		st->vppi_masked = v->vppi_masked ? 1 : 0;
		v->timer_dirty = false;
		mask |= L4H_ARM_VCPU_STATE_TIMER;
	}

	if (!v->synced || v->vgic_dirty) {
		for (i = L4H_ARM_VCPUREG_VGIC_HCR; i <= L4H_ARM_VCPUREG_VGIC_LR15; i++)
			st->regs[i] = cur->regs[i];
		v->vgic_dirty = false;
		mask |= L4H_ARM_VCPU_STATE_VGIC;
	}
	return mask;
}

/* What the guest changed (the groups in `mask`), from `st` into v->state
 * and `ctxt`. */
static void state_to_ctxt(struct kvm_vcpu *vcpu, struct l4h_arm_vcpu *v,
			  const struct l4h_arm_vcpu_state *st, unsigned long mask)
{
	struct kvm_cpu_context *ctxt = &vcpu->arch.ctxt;
	struct l4h_arm_vcpu_state *cur = v->state;
	int i;

	if (mask & L4H_ARM_VCPU_STATE_GPRS) {
		memcpy(cur->gprs, st->gprs, sizeof(cur->gprs));
		memcpy(ctxt->regs.regs, st->gprs, sizeof(ctxt->regs.regs));
		ctxt->regs.sp = st->gprs[GPR_SP_EL0];
		ctxt->regs.pc = st->gprs[GPR_PC];
		ctxt->regs.pstate = st->gprs[GPR_PSTATE];
		ctxt_sys_reg(ctxt, TPIDR_EL0) = st->gprs[GPR_TPIDR_EL0];
		ctxt_sys_reg(ctxt, TPIDRRO_EL0) = st->gprs[GPR_TPIDRRO_EL0];
	}
	if (mask & L4H_ARM_VCPU_STATE_EL1_SYSREGS) {
		for (i = 0; i < ARRAY_SIZE(el1_regs); i++) {
			cur->regs[el1_regs[i].fl4] = st->regs[el1_regs[i].fl4];
			ctxt_sys_reg(ctxt, el1_regs[i].kvm) = st->regs[el1_regs[i].fl4];
		}
	}
	if (mask & L4H_ARM_VCPU_STATE_TIMER) {
		cur->regs[L4H_ARM_VCPUREG_CNTV_CTL] = st->regs[L4H_ARM_VCPUREG_CNTV_CTL];
		cur->regs[L4H_ARM_VCPUREG_CNTV_CVAL] = st->regs[L4H_ARM_VCPUREG_CNTV_CVAL];
		cur->regs[L4H_ARM_VCPUREG_CNTKCTL_EL1] = st->regs[L4H_ARM_VCPUREG_CNTKCTL_EL1];
		ctxt_sys_reg(ctxt, CNTKCTL_EL1) = st->regs[L4H_ARM_VCPUREG_CNTKCTL_EL1];
		v->vppi_masked = !!(st->vppi_masked & 1);
	}
	/* Not vgic_dirty: FL4 has these. */
	if (mask & L4H_ARM_VCPU_STATE_VGIC)
		for (i = L4H_ARM_VCPUREG_VGIC_HCR; i <= L4H_ARM_VCPUREG_VGIC_LR15; i++)
			cur->regs[i] = st->regs[i];
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

int __kvm_vcpu_run(struct kvm_vcpu *vcpu)
{
	struct l4h_arm_vcpu *v = to_l4h(vcpu);
	/* Preemption is off: this vCPU of ours' IPC buffer. */
	struct l4h_arm_vcpu_state *st =
		(void *)((char *)l4h_this_vcpu()->ipcbuf + L4H_VCPU_STATE_OFFSET);
	unsigned long in, out;
	struct l4h_arm_vmexit x;
	int ret = ARM_EXCEPTION_IRQ;

	/* An event taken off the notification earlier would not end
	 * seL4_ARM_VCPU_Run, and interrupts are off until it returns. */
	if (l4h_events_pending())
		return ARM_EXCEPTION_IRQ;

	/* Pending exceptions and PC increments, as hyp code applies them. */
	__kvm_adjust_pc(vcpu);

	if (v->fp_state == L4H_FP_DIRTY) {
		if (l4h_fpu_write(&v->uctx, &vcpu->arch.ctxt.fp_regs,
				  sizeof(vcpu->arch.ctxt.fp_regs))) {
			pr_err_ratelimited("cannot load vCPU %d's FP state\n", vcpu->vcpu_id);
			return ARM_EXCEPTION_IL;
		}
		v->fp_state = L4H_FP_IN_TCB;
	} else if (v->fp_state == L4H_FP_IN_REGS) {
		/* The guest changes the TCB's. */
		v->fp_state = L4H_FP_IN_TCB;
	}
	in = ctxt_to_state(vcpu, v, st);
	out = L4H_ARM_VCPU_STATE_GPRS | L4H_ARM_VCPU_STATE_EL1_SYSREGS | L4H_ARM_VCPU_STATE_TIMER;
	/* On GICv3 the guest touches ICH_* only with VGIC_HCR set; on GICv2
	 * the mapped GICV page updates GICH_VMCR even when GICH_HCR is 0. */
	if (v->state->regs[L4H_ARM_VCPUREG_VGIC_HCR] ||
	    (l4h_bootinfo->arm_virt.gic_version == 2 && irqchip_in_kernel(vcpu->kvm)))
		out |= L4H_ARM_VCPU_STATE_VGIC;

	l4h_arm_vcpu_enter(v->vcpu_obj.cptr, in, out, &x);

	if (x.stop == L4H_ARM_STOP_OTHER) {
		/* FL4 refused the entry: it may have taken some of `in`. */
		v->synced = false;
		pr_err_ratelimited("vCPU %d: FL4 cannot run it\n", vcpu->vcpu_id);
		return ARM_EXCEPTION_IL;
	}
	state_to_ctxt(vcpu, v, st, out);
	v->synced = true;
	switch (x.stop) {
	case L4H_ARM_STOP_VMFAULT:
		vcpu->arch.fault.esr_el2 = x.esr;
		vcpu->arch.fault.far_el2 = x.far;
		/* A valid FIPA (KVM checks NS, the hardware's "valid" bit). */
		vcpu->arch.fault.hpfar_el2 = ((x.ipa >> 8) & HPFAR_EL2_FIPA) | HPFAR_EL2_NS;
		ret = ARM_EXCEPTION_TRAP;
		break;
	case L4H_ARM_STOP_VCPUFAULT:
		vcpu->arch.fault.esr_el2 = x.esr;
		vcpu->arch.fault.far_el2 = x.far;
		vcpu->arch.fault.hpfar_el2 = x.hpfar | HPFAR_EL2_NS;
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

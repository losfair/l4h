// SPDX-License-Identifier: GPL-2.0
/*
 * KVM's AMD-V backend for the l4h guest kernel: kvm_x86_ops on seL4 VCPUs
 * with a VMCB (DESIGN.md §5.10, seL4 patch 0040).
 *
 * The role of arch/x86/kvm/svm/svm.c, which it follows, without SVM
 * instructions: seL4 holds the VMCB and runs it with VMRUN.  The VMCB is
 * plain memory to seL4, so a read costs one system call for up to 32 words:
 * reads go through a copy of it that lives until the next VM entry, filled
 * 32 words at a time.  Writes go through to seL4, which keeps the host's
 * intercepts on and the fields it owns to itself (nCR3, the ASID, the
 * permission maps).  The exit brings RIP, RFLAGS, the interrupt state, CR2,
 * CR3 and the general-purpose registers, as on VT-x.
 *
 * What vmx.c leaves out is left out here too, and for the same reasons:
 * AVIC, nested SVM, the PMU, PKU, XSAVES, RDTSCP and RDPID, and hardware
 * breakpoints in the guest.  The debug registers always exit.  Without
 * decode assists (nested KVM does not offer them), CR, DR and string I/O
 * exits go through KVM's emulator; NMI windows use the IRET intercept.
 */
/* compat.h has the one of arch/x86/kvm. */
#undef pr_fmt
#define pr_fmt(fmt) "l4h-kvm: " fmt

#include <linux/kvm_host.h>
#include <linux/module.h>
#include <linux/init.h>
#include <asm/svm.h>
#include <l4h_sys.h>
#include "cpuid.h"
#include "kvm_cache_regs.h"
#include "lapic.h"
#include "mmu.h"
#include "x86.h"
#include "kvm_emulate.h"
#include "l4h_kvm.h"

#define VMCB_OFF(f)	offsetof(struct vmcb, f)
#define VMCB_SAVE(f)	(VMCB_OFF(save) + offsetof(struct vmcb_save_area, f))
/* What seL4 lets userspace read: the control area and the save area. */
#define VMCB_WORDS	(VMCB_SAVE(spec_ctrl) / 8 + 1)
#define VMCB_CHUNK	32
#define VMCB_CHUNKS	DIV_ROUND_UP(VMCB_WORDS, VMCB_CHUNK)

/* Intercept bits within their 32-bit vectors. */
#define I1(x)		BIT(INTERCEPT_##x - INTERCEPT_INTR)
#define I2(x)		BIT(INTERCEPT_##x - INTERCEPT_VMRUN)
#define CR_READ(n)	BIT(n)
#define CR_WRITE(n)	BIT(16 + (n))
/* System segment types, as svm.c has them. */
#define SEG_TYPE_LDT		2
#define SEG_TYPE_BUSY_TSS16	3

struct vcpu_svm_l4h {
	struct l4h_vcpu_obj base;

	/* The VMCB as seL4 had it after the last exit, by chunks of
	 * VMCB_CHUNK words that are valid while their gen is gen. */
	u64 vmcb[VMCB_CHUNKS * VMCB_CHUNK];
	u32 chunk_gen[VMCB_CHUNKS];
	u32 gen;

	/* Intercepts, as we last wrote them; misc1 goes in with each entry. */
	u32 intercept_cr, intercept_exc, intercept_misc1, intercept_misc2;

	/* The event for the next VM entry, and NEXT_RIP for a soft one. */
	u32 event_inj, event_inj_err;
	u64 entry_next_rip;
	/* NEXT_RIP of the last exit, or 0: what the CPU would leave there. */
	u64 next_rip;
	bool soft_int_injected;
	u64 soft_int_csbase, soft_int_old_rip, soft_int_next_rip;

	bool nmi_masked, awaiting_iret_completion, nmi_singlestep;
	u64 nmi_iret_rip, nmi_singlestep_guest_rflags;

	struct l4h_vmexit x;
	unsigned long rflags, hw_cr2;
	u32 int_state;
	/* What seL4 has of the general-purpose registers. */
	unsigned long hw_gp[L4H_VMX_NR_GP];
	u64 msr_decfg;
};

static inline struct vcpu_svm_l4h *to_svm(struct kvm_vcpu *vcpu)
{
	return container_of(vcpu, struct vcpu_svm_l4h, base.vcpu);
}

static inline unsigned long cap(struct kvm_vcpu *vcpu)
{
	return to_svm(vcpu)->base.obj.cptr;
}

/* ---- the VMCB */

static u64 vmcb_rd(struct kvm_vcpu *vcpu, unsigned int offset)
{
	struct vcpu_svm_l4h *s = to_svm(vcpu);
	unsigned int word = offset / 8, chunk = word / VMCB_CHUNK;

	if (s->chunk_gen[chunk] != s->gen) {
		unsigned int first = chunk * VMCB_CHUNK;
		int err = l4h_vcpu_read_vmcb(cap(vcpu), first * 8,
					     min(VMCB_CHUNK, VMCB_WORDS - first),
					     (unsigned long *)&s->vmcb[first]);

		WARN_ONCE(err, "l4h-kvm: read of VMCB words at %x: %d\n", first * 8, err);
		s->chunk_gen[chunk] = s->gen;
	}
	return s->vmcb[word];
}

static void vmcb_wr(struct kvm_vcpu *vcpu, unsigned int offset, u64 value)
{
	struct vcpu_svm_l4h *s = to_svm(vcpu);
	unsigned int word = offset / 8;
	unsigned long written;
	int err = l4h_vcpu_write_vmcb(cap(vcpu), offset, value, &written);

	WARN_ONCE(err, "l4h-kvm: write of VMCB word %x: %d\n", offset, err);
	/* seL4 may have kept some bits. */
	if (!err)
		s->vmcb[word] = written;
}

/* A field narrower than its word, in place. */
static u64 vmcb_rd_field(struct kvm_vcpu *vcpu, unsigned int offset, unsigned int bytes)
{
	u64 v = vmcb_rd(vcpu, offset & ~7) >> ((offset & 7) * 8);

	return bytes == 8 ? v : v & (BIT_ULL(bytes * 8) - 1);
}

static void vmcb_wr_field(struct kvm_vcpu *vcpu, unsigned int offset, unsigned int bytes, u64 value)
{
	unsigned int shift = (offset & 7) * 8;
	u64 mask = (bytes == 8 ? ~0ull : BIT_ULL(bytes * 8) - 1) << shift;
	u64 word = vmcb_rd(vcpu, offset & ~7);
	u64 new = (word & ~mask) | ((value << shift) & mask);

	if (new != word)
		vmcb_wr(vcpu, offset & ~7, new);
}

#define rd(vcpu, f)	vmcb_rd_field(vcpu, VMCB_SAVE(f), sizeof(((struct vmcb_save_area *)0)->f))
#define wr(vcpu, f, v)	vmcb_wr_field(vcpu, VMCB_SAVE(f), sizeof(((struct vmcb_save_area *)0)->f), v)

static void set_intercepts(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm_l4h *s = to_svm(vcpu);

	vmcb_wr(vcpu, VMCB_OFF(control.intercepts[INTERCEPT_CR]), s->intercept_cr);
	vmcb_wr(vcpu, VMCB_OFF(control.intercepts[INTERCEPT_EXCEPTION]),
		s->intercept_exc | (u64)s->intercept_misc1 << 32);
	vmcb_wr(vcpu, VMCB_OFF(control.intercepts[INTERCEPT_WORD4]), s->intercept_misc2);
}

static void cr_intercept_update(struct kvm_vcpu *vcpu, u32 set, u32 clear)
{
	struct vcpu_svm_l4h *s = to_svm(vcpu);
	u32 v = (s->intercept_cr & ~clear) | set;

	if (v != s->intercept_cr) {
		s->intercept_cr = v;
		vmcb_wr(vcpu, VMCB_OFF(control.intercepts[INTERCEPT_CR]), v);
	}
}

/* misc1 goes in with the next entry. */
static void misc1_update(struct kvm_vcpu *vcpu, u32 set, u32 clear)
{
	struct vcpu_svm_l4h *s = to_svm(vcpu);

	s->intercept_misc1 = (s->intercept_misc1 & ~clear) | set;
}

/* ---- segments */

static unsigned int seg_offset(int seg)
{
	switch (seg) {
	case VCPU_SREG_CS:
		return VMCB_SAVE(cs);
	case VCPU_SREG_DS:
		return VMCB_SAVE(ds);
	case VCPU_SREG_ES:
		return VMCB_SAVE(es);
	case VCPU_SREG_FS:
		return VMCB_SAVE(fs);
	case VCPU_SREG_GS:
		return VMCB_SAVE(gs);
	case VCPU_SREG_SS:
		return VMCB_SAVE(ss);
	case VCPU_SREG_TR:
		return VMCB_SAVE(tr);
	case VCPU_SREG_LDTR:
		return VMCB_SAVE(ldtr);
	}
	BUG();
}

/* A vmcb_seg: selector, attrib and limit, then the base. */
static u64 l4h_get_segment_base(struct kvm_vcpu *vcpu, int seg)
{
	return vmcb_rd(vcpu, seg_offset(seg) + 8);
}

static void l4h_get_segment(struct kvm_vcpu *vcpu, struct kvm_segment *var, int seg)
{
	unsigned int off = seg_offset(seg);
	u64 w = vmcb_rd(vcpu, off);
	u16 attrib = w >> 16;

	var->base = vmcb_rd(vcpu, off + 8);
	var->limit = w >> 32;
	var->selector = w;
	var->type = attrib & SVM_SELECTOR_TYPE_MASK;
	var->s = (attrib >> SVM_SELECTOR_S_SHIFT) & 1;
	var->dpl = (attrib >> SVM_SELECTOR_DPL_SHIFT) & 3;
	var->present = (attrib >> SVM_SELECTOR_P_SHIFT) & 1;
	var->avl = (attrib >> SVM_SELECTOR_AVL_SHIFT) & 1;
	var->l = (attrib >> SVM_SELECTOR_L_SHIFT) & 1;
	var->db = (attrib >> SVM_SELECTOR_DB_SHIFT) & 1;
	/* As svm_get_segment(): the CPU does not observe G, and has no
	 * "unusable". */
	var->g = var->limit > 0xfffff;
	var->unusable = !var->present;
	switch (seg) {
	case VCPU_SREG_TR:
		var->type |= 0x2;
		break;
	case VCPU_SREG_DS:
	case VCPU_SREG_ES:
	case VCPU_SREG_FS:
	case VCPU_SREG_GS:
		if (!var->unusable)
			var->type |= 0x1;
		break;
	case VCPU_SREG_SS:
		if (var->unusable)
			var->db = 0;
		var->dpl = rd(vcpu, cpl);
		break;
	}
}

static void l4h_set_segment(struct kvm_vcpu *vcpu, struct kvm_segment *var, int seg)
{
	unsigned int off = seg_offset(seg);
	u16 attrib = var->type & SVM_SELECTOR_TYPE_MASK;

	attrib |= (var->s & 1) << SVM_SELECTOR_S_SHIFT;
	attrib |= (var->dpl & 3) << SVM_SELECTOR_DPL_SHIFT;
	attrib |= ((var->present & 1) && !var->unusable) << SVM_SELECTOR_P_SHIFT;
	attrib |= (var->avl & 1) << SVM_SELECTOR_AVL_SHIFT;
	attrib |= (var->l & 1) << SVM_SELECTOR_L_SHIFT;
	attrib |= (var->db & 1) << SVM_SELECTOR_DB_SHIFT;
	attrib |= (var->g & 1) << SVM_SELECTOR_G_SHIFT;
	if (vmcb_rd(vcpu, off + 8) != var->base)
		vmcb_wr(vcpu, off + 8, var->base);
	vmcb_wr_field(vcpu, off, 8, var->selector | (u64)attrib << 16 | (u64)var->limit << 32);
	/* As svm_set_segment(), with svm_get_segment(). */
	if (seg == VCPU_SREG_SS)
		wr(vcpu, cpl, var->dpl & 3);
}

static int l4h_get_cpl(struct kvm_vcpu *vcpu)
{
	return rd(vcpu, cpl);
}

static void l4h_get_cs_db_l_bits(struct kvm_vcpu *vcpu, int *db, int *l)
{
	u16 attrib = vmcb_rd(vcpu, VMCB_SAVE(cs)) >> 16;

	*db = (attrib >> SVM_SELECTOR_DB_SHIFT) & 1;
	*l = (attrib >> SVM_SELECTOR_L_SHIFT) & 1;
}

static void get_dt(struct kvm_vcpu *vcpu, unsigned int off, struct desc_ptr *dt)
{
	dt->size = vmcb_rd(vcpu, off) >> 32;
	dt->address = vmcb_rd(vcpu, off + 8);
}

static void set_dt(struct kvm_vcpu *vcpu, unsigned int off, struct desc_ptr *dt)
{
	vmcb_wr_field(vcpu, off + 4, 4, dt->size);
	if (vmcb_rd(vcpu, off + 8) != dt->address)
		vmcb_wr(vcpu, off + 8, dt->address);
}

static void l4h_get_idt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	get_dt(vcpu, VMCB_SAVE(idtr), dt);
}

static void l4h_set_idt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	set_dt(vcpu, VMCB_SAVE(idtr), dt);
}

static void l4h_get_gdt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	get_dt(vcpu, VMCB_SAVE(gdtr), dt);
}

static void l4h_set_gdt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	set_dt(vcpu, VMCB_SAVE(gdtr), dt);
}

/* ---- control registers */

static int l4h_set_efer(struct kvm_vcpu *vcpu, u64 efer)
{
	vcpu->arch.efer = efer;
	/* VMRUN requires SVME, which seL4 also keeps. */
	wr(vcpu, efer, efer | EFER_SVME);
	return 0;
}

static bool l4h_is_valid_cr0(struct kvm_vcpu *vcpu, unsigned long cr0)
{
	return true;
}

/* CR0 writes always exit, so KVM's view stays current; reads exit only
 * when the CPU's CR0 differs from the guest's. */
static void l4h_set_cr0(struct kvm_vcpu *vcpu, unsigned long cr0)
{
	u64 hcr0 = cr0;

	if (vcpu->arch.efer & EFER_LME) {
		if (!is_paging(vcpu) && (cr0 & X86_CR0_PG)) {
			vcpu->arch.efer |= EFER_LMA;
			wr(vcpu, efer, vcpu->arch.efer | EFER_SVME);
		}
		if (is_paging(vcpu) && !(cr0 & X86_CR0_PG)) {
			vcpu->arch.efer &= ~EFER_LMA;
			wr(vcpu, efer, (vcpu->arch.efer & ~EFER_LME) | EFER_SVME);
		}
	}
	vcpu->arch.cr0 = cr0;
	kvm_register_mark_available(vcpu, VCPU_EXREG_CR0);
	if (kvm_check_has_quirk(vcpu->kvm, KVM_X86_QUIRK_CD_NW_CLEARED))
		hcr0 &= ~(X86_CR0_CD | X86_CR0_NW);
	wr(vcpu, cr0, hcr0);
	if (hcr0 == cr0)
		cr_intercept_update(vcpu, 0, CR_READ(0));
	else
		cr_intercept_update(vcpu, CR_READ(0), 0);
}

static bool l4h_is_valid_cr4(struct kvm_vcpu *vcpu, unsigned long cr4)
{
	return !(cr4 & X86_CR4_VMXE);
}

static void l4h_set_cr4(struct kvm_vcpu *vcpu, unsigned long cr4)
{
	unsigned long old = vcpu->arch.cr4;

	vcpu->arch.cr4 = cr4;
	kvm_register_mark_available(vcpu, VCPU_EXREG_CR4);
	wr(vcpu, cr4, cr4);
	if ((cr4 ^ old) & (X86_CR4_OSXSAVE | X86_CR4_PKE))
		vcpu->arch.cpuid_dynamic_bits_dirty = true;
}

/* The nested page table root is the kTCB's (vcpu_load). */
static void l4h_load_mmu_pgd(struct kvm_vcpu *vcpu, hpa_t root_hpa, int root_level)
{
}

static unsigned long l4h_get_rflags(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm_l4h *s = to_svm(vcpu);
	unsigned long rflags = s->rflags;

	if (s->nmi_singlestep) {
		if (!(s->nmi_singlestep_guest_rflags & X86_EFLAGS_TF))
			rflags &= ~X86_EFLAGS_TF;
		if (!(s->nmi_singlestep_guest_rflags & X86_EFLAGS_RF))
			rflags &= ~X86_EFLAGS_RF;
	}
	return rflags;
}

static void l4h_set_rflags(struct kvm_vcpu *vcpu, unsigned long rflags)
{
	struct vcpu_svm_l4h *s = to_svm(vcpu);

	/* As svm_set_rflags(): TF and RF stay while single-stepping to an
	 * NMI window. */
	if (s->nmi_singlestep)
		rflags |= X86_EFLAGS_TF | X86_EFLAGS_RF;
	if (rflags != s->rflags)
		wr(vcpu, rflags, rflags);
	s->rflags = rflags;
}

static bool l4h_get_if_flag(struct kvm_vcpu *vcpu)
{
	return to_svm(vcpu)->rflags & X86_EFLAGS_IF;
}

static void l4h_cache_reg(struct kvm_vcpu *vcpu, enum kvm_reg reg)
{
	kvm_register_mark_available(vcpu, reg);
	switch (reg) {
	case VCPU_REGS_RSP:
		vcpu->arch.regs[VCPU_REGS_RSP] = rd(vcpu, rsp);
		break;
	case VCPU_EXREG_PDPTR:
		/* As with NPT on bare metal: the CPU loads them itself. */
		load_pdptrs(vcpu, kvm_read_cr3(vcpu));
		break;
	default:
		break;
	}
}

/* ---- exceptions and interrupts */

static void update_exception_bitmap(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm_l4h *s = to_svm(vcpu);
	/* seL4 keeps #DB, #AC and #MC on (patch 0040). */
	u32 eb = BIT(UD_VECTOR) | BIT(MC_VECTOR) | BIT(DB_VECTOR) | BIT(AC_VECTOR);

	if (vcpu->guest_debug & KVM_GUESTDBG_USE_SW_BP)
		eb |= BIT(BP_VECTOR);
	if (eb != s->intercept_exc) {
		s->intercept_exc = eb;
		vmcb_wr(vcpu, VMCB_OFF(control.intercepts[INTERCEPT_EXCEPTION]),
			eb | (u64)s->intercept_misc1 << 32);
	}
}

static u32 l4h_get_interrupt_shadow(struct kvm_vcpu *vcpu)
{
	return to_svm(vcpu)->int_state & SVM_INTERRUPT_SHADOW_MASK ?
	       KVM_X86_SHADOW_INT_STI | KVM_X86_SHADOW_INT_MOV_SS : 0;
}

static void l4h_set_interrupt_shadow(struct kvm_vcpu *vcpu, int mask)
{
	struct vcpu_svm_l4h *s = to_svm(vcpu);
	u32 v = mask ? s->int_state | SVM_INTERRUPT_SHADOW_MASK :
		       s->int_state & ~SVM_INTERRUPT_SHADOW_MASK;

	if (v != s->int_state) {
		s->int_state = v;
		vmcb_wr(vcpu, VMCB_OFF(control.int_state), v);
	}
}

/* As __svm_skip_emulated_instruction(): NEXT_RIP where the CPU gave it,
 * the emulator where it did not. */
static int skip_instruction(struct kvm_vcpu *vcpu, int emul_type, bool commit_side_effects)
{
	struct vcpu_svm_l4h *s = to_svm(vcpu);
	unsigned long old_rflags = s->rflags;

	if (!s->next_rip) {
		if (!kvm_emulate_instruction(vcpu, emul_type))
			return 0;
		if (unlikely(!commit_side_effects))
			l4h_set_rflags(vcpu, old_rflags);
	} else {
		kvm_rip_write(vcpu, s->next_rip);
	}
	if (likely(commit_side_effects))
		l4h_set_interrupt_shadow(vcpu, 0);
	return 1;
}

static int l4h_skip_emulated_instruction(struct kvm_vcpu *vcpu)
{
	return skip_instruction(vcpu, EMULTYPE_SKIP, true);
}

/* As svm_update_soft_interrupt_rip(): the CPU pushes NEXT_RIP for an INTn,
 * INT3 or INTO it injects. */
static int update_soft_interrupt_rip(struct kvm_vcpu *vcpu, u8 vector)
{
	struct vcpu_svm_l4h *s = to_svm(vcpu);
	unsigned long rip, old_rip = kvm_rip_read(vcpu);

	if (!skip_instruction(vcpu, EMULTYPE_SKIP | EMULTYPE_SKIP_SOFT_INT |
			      EMULTYPE_SET_SOFT_INT_VECTOR(vector), false))
		return -EIO;
	rip = kvm_rip_read(vcpu);
	s->soft_int_injected = true;
	s->soft_int_csbase = l4h_get_segment_base(vcpu, VCPU_SREG_CS);
	s->soft_int_old_rip = old_rip;
	s->soft_int_next_rip = rip;
	kvm_rip_write(vcpu, old_rip);
	s->entry_next_rip = rip;
	return 0;
}

static void l4h_inject_exception(struct kvm_vcpu *vcpu)
{
	struct kvm_queued_exception *ex = &vcpu->arch.exception;
	struct vcpu_svm_l4h *s = to_svm(vcpu);

	kvm_deliver_exception_payload(vcpu, ex);
	if (kvm_exception_is_soft(ex->vector) && update_soft_interrupt_rip(vcpu, ex->vector))
		return;
	s->event_inj = ex->vector | SVM_EVTINJ_VALID | SVM_EVTINJ_TYPE_EXEPT |
		       (ex->has_error_code ? SVM_EVTINJ_VALID_ERR : 0);
	s->event_inj_err = ex->error_code;
}

static void l4h_inject_irq(struct kvm_vcpu *vcpu, bool reinjected)
{
	struct kvm_queued_interrupt *intr = &vcpu->arch.interrupt;
	struct vcpu_svm_l4h *s = to_svm(vcpu);
	u32 type = SVM_EVTINJ_TYPE_INTR;

	if (intr->soft) {
		if (update_soft_interrupt_rip(vcpu, intr->nr))
			return;
		type = SVM_EVTINJ_TYPE_SOFT;
	}
	++vcpu->stat.irq_injections;
	s->event_inj = intr->nr | SVM_EVTINJ_VALID | type;
}

/* Without vNMI, NMI masking is ours to track, up to the guest's IRET. */
static void l4h_set_nmi_mask(struct kvm_vcpu *vcpu, bool masked)
{
	to_svm(vcpu)->nmi_masked = masked;
	if (masked)
		misc1_update(vcpu, I1(IRET), 0);
	else
		misc1_update(vcpu, 0, I1(IRET));
}

static bool l4h_get_nmi_mask(struct kvm_vcpu *vcpu)
{
	return to_svm(vcpu)->nmi_masked;
}

static void l4h_inject_nmi(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm_l4h *s = to_svm(vcpu);

	s->event_inj = SVM_EVTINJ_VALID | SVM_EVTINJ_TYPE_NMI;
	l4h_set_nmi_mask(vcpu, true);
	++vcpu->stat.nmi_injections;
}

static int l4h_interrupt_allowed(struct kvm_vcpu *vcpu, bool for_injection)
{
	struct vcpu_svm_l4h *s = to_svm(vcpu);

	return (s->rflags & X86_EFLAGS_IF) && !(s->int_state & SVM_INTERRUPT_SHADOW_MASK);
}

static int l4h_nmi_allowed(struct kvm_vcpu *vcpu, bool for_injection)
{
	struct vcpu_svm_l4h *s = to_svm(vcpu);

	return !s->nmi_masked && !(s->int_state & SVM_INTERRUPT_SHADOW_MASK);
}

/* As svm_set_vintr(): a virtual interrupt at the highest priority, which
 * the CPU takes, and exits for, as soon as the guest can take one. */
static void l4h_enable_irq_window(struct kvm_vcpu *vcpu)
{
	u64 ctl = vmcb_rd(vcpu, VMCB_OFF(control.int_ctl));

	ctl &= ~((u64)0xff << 32 | V_INTR_PRIO_MASK);
	ctl |= V_IRQ_MASK | (0xf << V_INTR_PRIO_SHIFT);
	vmcb_wr_field(vcpu, VMCB_OFF(control.int_ctl), 8, ctl);
	misc1_update(vcpu, I1(VINTR), 0);
}

static void clear_vintr(struct kvm_vcpu *vcpu)
{
	misc1_update(vcpu, 0, I1(VINTR));
	vmcb_wr_field(vcpu, VMCB_OFF(control.int_ctl), 4,
		      vmcb_rd_field(vcpu, VMCB_OFF(control.int_ctl), 4) & ~V_IRQ_INJECTION_BITS_MASK);
}

/* As svm_enable_nmi_window(): an NMI masked until an IRET waits for the
 * IRET intercept; anything else that blocks it, single-step over. */
static void l4h_enable_nmi_window(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm_l4h *s = to_svm(vcpu);

	if (s->nmi_masked && !s->awaiting_iret_completion)
		return;
	s->nmi_singlestep_guest_rflags = l4h_get_rflags(vcpu);
	s->nmi_singlestep = true;
	l4h_set_rflags(vcpu, s->rflags);
}

static void disable_nmi_singlestep(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm_l4h *s = to_svm(vcpu);
	unsigned long rflags = l4h_get_rflags(vcpu);

	s->nmi_singlestep = false;
	l4h_set_rflags(vcpu, rflags);
}

static void l4h_deliver_interrupt(struct kvm_lapic *apic, int delivery_mode, int trig_mode,
				  int vector)
{
	struct kvm_vcpu *vcpu = apic->vcpu;

	kvm_lapic_set_irr(vector, apic);
	kvm_make_request(KVM_REQ_EVENT, vcpu);
	kvm_vcpu_kick(vcpu);
}

/* As svm_complete_interrupts(): an event being delivered when the VCPU
 * stopped goes back to KVM's queues, to go in again. */
static void complete_interrupts(struct kvm_vcpu *vcpu, u32 info, u32 error)
{
	struct vcpu_svm_l4h *s = to_svm(vcpu);
	u8 vector = info & SVM_EXITINTINFO_VEC_MASK;
	u32 type = info & SVM_EXITINTINFO_TYPE_MASK;
	bool soft_int_injected = s->soft_int_injected;

	s->soft_int_injected = false;
	if (s->awaiting_iret_completion && kvm_rip_read(vcpu) != s->nmi_iret_rip) {
		s->awaiting_iret_completion = false;
		s->nmi_masked = false;
		kvm_make_request(KVM_REQ_EVENT, vcpu);
	}
	vcpu->arch.nmi_injected = false;
	kvm_clear_exception_queue(vcpu);
	kvm_clear_interrupt_queue(vcpu);
	if (!(info & SVM_EXITINTINFO_VALID))
		return;
	kvm_make_request(KVM_REQ_EVENT, vcpu);
	/* svm_complete_soft_interrupt(): the CPU dropped NEXT_RIP. */
	if (soft_int_injected &&
	    (type == SVM_EXITINTINFO_TYPE_SOFT ||
	     (type == SVM_EXITINTINFO_TYPE_EXEPT && kvm_exception_is_soft(vector))) &&
	    kvm_is_linear_rip(vcpu, s->soft_int_old_rip + s->soft_int_csbase))
		s->next_rip = s->soft_int_next_rip;
	switch (type) {
	case SVM_EXITINTINFO_TYPE_NMI:
		vcpu->arch.nmi_injected = true;
		break;
	case SVM_EXITINTINFO_TYPE_EXEPT:
		kvm_requeue_exception(vcpu, vector, info & SVM_EXITINTINFO_VALID_ERR,
				      info & SVM_EXITINTINFO_VALID_ERR ? error : 0);
		break;
	case SVM_EXITINTINFO_TYPE_INTR:
		kvm_queue_interrupt(vcpu, vector, false);
		break;
	case SVM_EXITINTINFO_TYPE_SOFT:
		kvm_queue_interrupt(vcpu, vector, true);
		break;
	}
}

static void l4h_cancel_injection(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm_l4h *s = to_svm(vcpu);

	complete_interrupts(vcpu, s->event_inj, s->event_inj_err);
	s->event_inj = 0;
	s->entry_next_rip = 0;
}

/* ---- MSRs */

/* The MSRs that VMLOAD and VMSAVE switch, in the save area. */
static int vmcb_msr(u32 index)
{
	switch (index) {
	case MSR_FS_BASE:
		return VMCB_SAVE(fs.base);
	case MSR_GS_BASE:
		return VMCB_SAVE(gs.base);
	case MSR_KERNEL_GS_BASE:
		return VMCB_SAVE(kernel_gs_base);
	case MSR_STAR:
		return VMCB_SAVE(star);
	case MSR_LSTAR:
		return VMCB_SAVE(lstar);
	case MSR_CSTAR:
		return VMCB_SAVE(cstar);
	case MSR_SYSCALL_MASK:
		return VMCB_SAVE(sfmask);
	case MSR_IA32_SYSENTER_CS:
		return VMCB_SAVE(sysenter_cs);
	case MSR_IA32_SYSENTER_ESP:
		return VMCB_SAVE(sysenter_esp);
	case MSR_IA32_SYSENTER_EIP:
		return VMCB_SAVE(sysenter_eip);
	}
	return -1;
}

static int l4h_get_msr(struct kvm_vcpu *vcpu, struct msr_data *msr)
{
	int off = vmcb_msr(msr->index);

	if (off >= 0) {
		msr->data = vmcb_rd(vcpu, off);
		return 0;
	}
	switch (msr->index) {
	case MSR_IA32_DEBUGCTLMSR:
	case MSR_F15H_IC_CFG:
	case MSR_VM_CR:
	case MSR_VM_HSAVE_PA:
		msr->data = 0;
		return 0;
	case MSR_AMD64_DE_CFG:
		msr->data = to_svm(vcpu)->msr_decfg;
		return 0;
	}
	return kvm_get_msr_common(vcpu, msr);
}

static int l4h_set_msr(struct kvm_vcpu *vcpu, struct msr_data *msr)
{
	int off = vmcb_msr(msr->index);
	u64 data = msr->data;
	unsigned long written;

	if (off >= 0) {
		/* seL4 checks addresses as the CPU would on a WRMSR. */
		if (l4h_vcpu_write_vmcb(cap(vcpu), off, data, &written))
			return 1;
		to_svm(vcpu)->vmcb[off / 8] = written;
		return 0;
	}
	switch (msr->index) {
	case MSR_IA32_DEBUGCTLMSR:
		return data ? 1 : 0;
	case MSR_IA32_CR_PAT:
		if (!kvm_pat_valid(data))
			return 1;
		wr(vcpu, g_pat, data);
		vcpu->arch.pat = data;
		return 0;
	case MSR_AMD64_DE_CFG:
		/* As svm_set_msr(): what svm_get_feature_msr() offers, LFENCE
		 * serializing. */
		if (data & ~MSR_AMD64_DE_CFG_LFENCE_SERIALIZE)
			return 1;
		to_svm(vcpu)->msr_decfg = data;
		return 0;
	case MSR_F15H_IC_CFG:
	case MSR_VM_IGNNE:
		return 0;
	case MSR_VM_CR:
	case MSR_VM_HSAVE_PA:
		/* No nested SVM. */
		return data ? 1 : 0;
	}
	return kvm_set_msr_common(vcpu, msr);
}

/* ---- TLBs */

/*
 * As in vmx.c: flush_tlb_all follows TDP changes, and seL4 gives every VCPU
 * on every core that has run one a new ASID when it removes a nested page
 * table leaf or table (patch 0040), before ept.c returns; adding one needs
 * nothing.  The other flushes are of what the guest's own paging produced
 * (after CR4 or PCID changes too), which takes a real one.  A VCPU that
 * moves to another core gets a new ASID there, so no flush done elsewhere
 * is missed.
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

static int l4h_vcpu_create(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm_l4h *s = to_svm(vcpu);
	int err = l4h_kvm_vcpu_alloc(&s->base);

	if (err)
		return err;
	/* A valid generation is never the initial 0. */
	s->gen = 1;
	/* As init_vmcb() with NPT, without the ones seL4 keeps on. */
	s->intercept_cr = CR_READ(0) | CR_READ(8) | CR_WRITE(0) | CR_WRITE(4) | CR_WRITE(8);
	s->intercept_misc1 = I1(CPUID) | I1(INVD) | I1(HLT) | I1(TASK_SWITCH) | I1(RSM);
	s->intercept_misc2 = I2(VMMCALL) | I2(WBINVD) | I2(RDTSCP);
	set_intercepts(vcpu);
	update_exception_bitmap(vcpu);
	vcpu->arch.cr0_guest_owned_bits = 0;
	vcpu->arch.cr4_guest_owned_bits = 0;
	vcpu->arch.pat = MSR_IA32_CR_PAT_DEFAULT;
	return 0;
}

static void seg_setup(struct kvm_vcpu *vcpu, int seg, u16 selector, u64 base, u16 attrib)
{
	unsigned int off = seg_offset(seg);

	vmcb_wr(vcpu, off + 8, base);
	vmcb_wr_field(vcpu, off, 8, selector | (u64)attrib << 16 | (u64)0xffff << 32);
}

/* As init_vmcb() and svm_vcpu_reset(). */
static void l4h_vcpu_reset(struct kvm_vcpu *vcpu, bool init_event)
{
	struct vcpu_svm_l4h *s = to_svm(vcpu);
	const u16 data = SVM_SELECTOR_P_MASK | SVM_SELECTOR_S_MASK | SVM_SELECTOR_WRITE_MASK;

	seg_setup(vcpu, VCPU_SREG_CS, 0xf000, 0xffff0000, SVM_SELECTOR_READ_MASK |
		  SVM_SELECTOR_P_MASK | SVM_SELECTOR_S_MASK | SVM_SELECTOR_CODE_MASK);
	seg_setup(vcpu, VCPU_SREG_DS, 0, 0, data);
	seg_setup(vcpu, VCPU_SREG_ES, 0, 0, data);
	seg_setup(vcpu, VCPU_SREG_FS, 0, 0, data);
	seg_setup(vcpu, VCPU_SREG_GS, 0, 0, data);
	seg_setup(vcpu, VCPU_SREG_SS, 0, 0, data);
	seg_setup(vcpu, VCPU_SREG_LDTR, 0, 0, SVM_SELECTOR_P_MASK | SEG_TYPE_LDT);
	seg_setup(vcpu, VCPU_SREG_TR, 0, 0, SVM_SELECTOR_P_MASK | SEG_TYPE_BUSY_TSS16);
	set_dt(vcpu, VMCB_SAVE(gdtr), &(struct desc_ptr){ .size = 0xffff });
	set_dt(vcpu, VMCB_SAVE(idtr), &(struct desc_ptr){ .size = 0xffff });
	wr(vcpu, cpl, 0);
	wr(vcpu, g_pat, vcpu->arch.pat);
	wr(vcpu, dr6, DR6_ACTIVE_LOW);
	wr(vcpu, dr7, DR7_FIXED_1);
	l4h_set_interrupt_shadow(vcpu, 0);
	s->event_inj = 0;
	s->entry_next_rip = 0;
	s->nmi_masked = false;
	s->awaiting_iret_completion = false;
	s->nmi_singlestep = false;
	misc1_update(vcpu, 0, I1(IRET) | I1(VINTR));
	if (!init_event)
		s->msr_decfg = 0;
	kvm_set_cr8(vcpu, 0);
}

static void l4h_prepare_switch(struct kvm_vcpu *vcpu)
{
}

static int l4h_vcpu_pre_run(struct kvm_vcpu *vcpu)
{
	return 1;
}

/* KVM's own GPR accessors do not mark them dirty (SVM keeps them in
 * memory), so compare with what seL4 has. */
static void sync_to_vcpu(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm_l4h *s = to_svm(vcpu);
	unsigned long *r = vcpu->arch.regs;
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

	if (memcmp(gp, s->hw_gp, sizeof(gp))) {
		WARN_ON_ONCE(l4h_vcpu_write_regs(s->base.obj.cptr, gp));
		memcpy(s->hw_gp, gp, sizeof(gp));
	}
	if (kvm_register_is_dirty(vcpu, VCPU_REGS_RSP))
		wr(vcpu, rsp, r[VCPU_REGS_RSP]);
	if (kvm_register_is_dirty(vcpu, VCPU_EXREG_CR3))
		wr(vcpu, cr3, vcpu->arch.cr3);
	if (vcpu->arch.cr2 != s->hw_cr2) {
		wr(vcpu, cr2, vcpu->arch.cr2);
		s->hw_cr2 = vcpu->arch.cr2;
	}
	l4h_kvm_sync_xcr0(vcpu);
	vcpu->arch.regs_dirty = 0;
}

static void sync_from_exit(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm_l4h *s = to_svm(vcpu);
	struct l4h_vmexit *x = &s->x;
	unsigned long *r = vcpu->arch.regs;

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
	memcpy(s->hw_gp, x->gp, sizeof(s->hw_gp));
	r[VCPU_REGS_RIP] = x->rip;
	s->rflags = x->rflags;
	s->int_state = x->interruptibility;
	vcpu->arch.cr2 = s->hw_cr2 = x->cr2;
	vcpu->arch.cr3 = x->cr3;
	s->next_rip = x->fault && x->instr_len ? x->rip + x->instr_len : 0;

	/* The VM ran: what we had of the VMCB is gone. */
	s->gen++;
	/* Read when needed: RSP, and the PDPTEs of a PAE guest. */
	vcpu->arch.regs_avail = ~0u & ~(BIT(VCPU_REGS_RSP) | BIT(VCPU_EXREG_PDPTR));
	vcpu->arch.regs_dirty = 0;
}

static fastpath_t l4h_vcpu_run(struct kvm_vcpu *vcpu, u64 run_flags)
{
	struct vcpu_svm_l4h *s = to_svm(vcpu);
	struct l4h_vmexit *x = &s->x;
	u32 info, error;

	/* An event taken off the notification earlier would not end the
	 * VMEnter, and interrupts are off until it returns. */
	if (l4h_events_pending()) {
		x->fault = 0;
		x->reason = SVM_EXIT_INTR;
		l4h_cancel_injection(vcpu);
		return EXIT_FASTPATH_NONE;
	}
	/*
	 * As svm_vcpu_run(): the event this entry injects would push the
	 * single-step TF and RF in its frame, where handle_db() cannot take
	 * them back.  Upstream forces an immediate exit to open the NMI window
	 * after delivery; nothing makes VMEnter return that early, so it is
	 * looked at again at the next exit.
	 */
	if (s->nmi_singlestep && (s->event_inj & SVM_EVTINJ_VALID)) {
		disable_nmi_singlestep(vcpu);
		kvm_make_request(KVM_REQ_EVENT, vcpu);
	}
	sync_to_vcpu(vcpu);
	if (s->event_inj & SVM_EVTINJ_VALID_ERR)
		vmcb_wr(vcpu, VMCB_OFF(control.event_inj), s->event_inj | (u64)s->event_inj_err << 32);
	if (s->entry_next_rip) {
		vmcb_wr(vcpu, VMCB_OFF(control.next_rip), s->entry_next_rip);
		s->entry_next_rip = 0;
	}
	l4h_kvm_fpu_load(vcpu);
	l4h_vcpu_enter(x, kvm_rip_read(vcpu), s->intercept_misc1, s->event_inj);
	sync_from_exit(vcpu);

	if (x->intr_info & SVM_EVTINJ_VALID) {
		/* It never went in: the call was over before the VM ran. */
		info = x->intr_info;
		error = s->event_inj_err;
	} else {
		info = x->idt_vector_info;
		error = x->idt_vector_error;
	}
	s->event_inj = 0;
	complete_interrupts(vcpu, info, error);
	return EXIT_FASTPATH_NONE;
}

/* ---- VM exits */

static int internal_error(struct kvm_vcpu *vcpu)
{
	return l4h_kvm_internal_error(vcpu, to_svm(vcpu)->x.reason);
}

static int handle_db(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm_l4h *s = to_svm(vcpu);
	struct kvm_run *run = vcpu->run;

	if (!(vcpu->guest_debug & (KVM_GUESTDBG_SINGLESTEP | KVM_GUESTDBG_USE_HW_BP)) &&
	    !s->nmi_singlestep) {
		kvm_queue_exception_p(vcpu, DB_VECTOR, rd(vcpu, dr6) ^ DR6_ACTIVE_LOW);
		return 1;
	}
	if (s->nmi_singlestep) {
		disable_nmi_singlestep(vcpu);
		kvm_make_request(KVM_REQ_EVENT, vcpu);
	}
	if (vcpu->guest_debug & (KVM_GUESTDBG_SINGLESTEP | KVM_GUESTDBG_USE_HW_BP)) {
		run->exit_reason = KVM_EXIT_DEBUG;
		run->debug.arch.dr6 = rd(vcpu, dr6);
		run->debug.arch.dr7 = vcpu->arch.dr7;
		run->debug.arch.pc = kvm_get_linear_rip(vcpu);
		run->debug.arch.exception = DB_VECTOR;
		return 0;
	}
	return 1;
}

static int handle_exception(struct kvm_vcpu *vcpu, u32 vector)
{
	struct kvm_run *run = vcpu->run;

	switch (vector) {
	case UD_VECTOR:
		return handle_ud(vcpu);
	case DB_VECTOR:
		return handle_db(vcpu);
	case AC_VECTOR:
		kvm_queue_exception_e(vcpu, AC_VECTOR, 0);
		return 1;
	case BP_VECTOR:
		run->exit_reason = KVM_EXIT_DEBUG;
		run->debug.arch.pc = kvm_get_linear_rip(vcpu);
		run->debug.arch.exception = BP_VECTOR;
		return 0;
	case MC_VECTOR:
		return 1;
	}
	run->exit_reason = KVM_EXIT_EXCEPTION;
	run->ex.exception = vector;
	run->ex.error_code = to_svm(vcpu)->x.qualification;
	return 0;
}

static int handle_io(struct kvm_vcpu *vcpu)
{
	u32 info = to_svm(vcpu)->x.qualification;
	int size = (info & SVM_IOIO_SIZE_MASK) >> SVM_IOIO_SIZE_SHIFT;

	++vcpu->stat.io_exits;
	if (info & SVM_IOIO_STR_MASK)
		return kvm_emulate_instruction(vcpu, 0);
	return kvm_fast_pio(vcpu, size, info >> 16, info & SVM_IOIO_TYPE_MASK);
}

#define CR_VALID BIT_ULL(63)

/* As cr_interception(), which without decode assists emulates. */
static int handle_cr(struct kvm_vcpu *vcpu)
{
	struct l4h_vmexit *x = &to_svm(vcpu)->x;
	int cr = x->reason - SVM_EXIT_READ_CR0, reg = x->qualification & SVM_EXITINFO_REG_MASK;
	unsigned long val;
	int err = 0;

	if (!(x->qualification & CR_VALID))
		return kvm_emulate_instruction(vcpu, 0);
	if (cr >= 16) {
		cr -= 16;
		val = kvm_register_read(vcpu, reg);
		switch (cr) {
		case 0:
			err = kvm_set_cr0(vcpu, val);
			break;
		case 3:
			err = kvm_set_cr3(vcpu, val);
			break;
		case 4:
			err = kvm_set_cr4(vcpu, val);
			break;
		case 8:
			err = kvm_set_cr8(vcpu, val);
			break;
		default:
			kvm_queue_exception(vcpu, UD_VECTOR);
			return 1;
		}
	} else {
		switch (cr) {
		case 0:
			val = kvm_read_cr0(vcpu);
			break;
		case 2:
			val = vcpu->arch.cr2;
			break;
		case 3:
			val = kvm_read_cr3(vcpu);
			break;
		case 4:
			val = kvm_read_cr4(vcpu);
			break;
		case 8:
			val = kvm_get_cr8(vcpu);
			break;
		default:
			kvm_queue_exception(vcpu, UD_VECTOR);
			return 1;
		}
		kvm_register_write(vcpu, reg, val);
	}
	return kvm_complete_insn_gp(vcpu, err);
}

static int handle_task_switch(struct kvm_vcpu *vcpu)
{
	struct l4h_vmexit *x = &to_svm(vcpu)->x;
	u32 type = x->idt_vector_info & SVM_EXITINTINFO_TYPE_MASK;
	u32 idt_v = x->idt_vector_info & SVM_EXITINTINFO_VALID;
	int int_vec = x->idt_vector_info & SVM_EVTINJ_VEC_MASK;
	u16 tss_selector = x->qualification;
	bool has_error_code = false;
	u32 error_code = 0;
	int reason;

	if (x->gpa & BIT_ULL(SVM_EXITINFOSHIFT_TS_REASON_IRET))
		reason = TASK_SWITCH_IRET;
	else if (x->gpa & BIT_ULL(SVM_EXITINFOSHIFT_TS_REASON_JMP))
		reason = TASK_SWITCH_JMP;
	else if (idt_v)
		reason = TASK_SWITCH_GATE;
	else
		reason = TASK_SWITCH_CALL;
	if (reason == TASK_SWITCH_GATE) {
		switch (type) {
		case SVM_EXITINTINFO_TYPE_NMI:
			vcpu->arch.nmi_injected = false;
			break;
		case SVM_EXITINTINFO_TYPE_EXEPT:
			if (x->gpa & BIT_ULL(SVM_EXITINFOSHIFT_TS_HAS_ERROR_CODE)) {
				has_error_code = true;
				error_code = (u32)x->gpa;
			}
			kvm_clear_exception_queue(vcpu);
			break;
		case SVM_EXITINTINFO_TYPE_INTR:
		case SVM_EXITINTINFO_TYPE_SOFT:
			kvm_clear_interrupt_queue(vcpu);
			break;
		}
	}
	if (reason != TASK_SWITCH_GATE || type == SVM_EXITINTINFO_TYPE_SOFT ||
	    (type == SVM_EXITINTINFO_TYPE_EXEPT && (int_vec == OF_VECTOR || int_vec == BP_VECTOR))) {
		if (!l4h_skip_emulated_instruction(vcpu))
			return 0;
	}
	if (type != SVM_EXITINTINFO_TYPE_SOFT)
		int_vec = -1;
	return kvm_task_switch(vcpu, tss_selector, int_vec, reason, has_error_code, error_code);
}

/* As iret_interception(): NMIs are unmasked once the IRET is done, which is
 * when RIP has moved (complete_interrupts()). */
static int handle_iret(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm_l4h *s = to_svm(vcpu);

	++vcpu->stat.nmi_window_exits;
	s->awaiting_iret_completion = true;
	misc1_update(vcpu, 0, I1(IRET));
	s->nmi_iret_rip = kvm_rip_read(vcpu);
	kvm_make_request(KVM_REQ_EVENT, vcpu);
	return 1;
}

static int handle_npf(struct kvm_vcpu *vcpu)
{
	struct l4h_vmexit *x = &to_svm(vcpu)->x;
	u64 error = x->qualification;

	if (WARN_ON_ONCE(error & PFERR_SYNTHETIC_MASK))
		error &= ~PFERR_SYNTHETIC_MASK;
	return kvm_mmu_page_fault(vcpu, x->gpa, error, NULL, 0);
}

/* As shutdown_interception(): the VMCB is undefined, and seL4 has reset its
 * save area. */
static int handle_shutdown(struct kvm_vcpu *vcpu)
{
	to_svm(vcpu)->gen++;
	kvm_vcpu_reset(vcpu, true);
	vcpu->run->exit_reason = KVM_EXIT_SHUTDOWN;
	return 0;
}

static int l4h_handle_exit(struct kvm_vcpu *vcpu, fastpath_t fastpath)
{
	struct l4h_vmexit *x = &to_svm(vcpu)->x;
	u32 reason = x->reason;

	if (reason >= SVM_EXIT_READ_CR0 && reason <= SVM_EXIT_WRITE_CR0 + 15)
		return handle_cr(vcpu);
	if (reason >= SVM_EXIT_READ_DR0 && reason <= SVM_EXIT_WRITE_DR0 + 15)
		/* The debug registers are KVM's only. */
		return kvm_emulate_instruction(vcpu, 0);
	if (reason >= SVM_EXIT_EXCP_BASE && reason < SVM_EXIT_EXCP_BASE + 32)
		return handle_exception(vcpu, reason - SVM_EXIT_EXCP_BASE);
	switch (reason) {
	case SVM_EXIT_INTR:
		++vcpu->stat.irq_exits;
		return 1;
	case SVM_EXIT_NMI:
	case SVM_EXIT_SMI:
	case SVM_EXIT_INIT:
		return 1;
	case SVM_EXIT_VINTR:
		clear_vintr(vcpu);
		kvm_make_request(KVM_REQ_EVENT, vcpu);
		++vcpu->stat.irq_window_exits;
		return 1;
	case SVM_EXIT_CPUID:
		return kvm_emulate_cpuid(vcpu);
	case SVM_EXIT_IRET:
		return handle_iret(vcpu);
	case SVM_EXIT_INVD:
		return kvm_emulate_invd(vcpu);
	case SVM_EXIT_RDPMC:
		/* seL4 always intercepts it: with no PMU, a #GP. */
		return kvm_emulate_rdpmc(vcpu);
	case SVM_EXIT_PAUSE:
		return kvm_skip_emulated_instruction(vcpu);
	case SVM_EXIT_HLT:
		return kvm_emulate_halt(vcpu);
	case SVM_EXIT_IOIO:
		return handle_io(vcpu);
	case SVM_EXIT_MSR:
		return x->qualification ? kvm_emulate_wrmsr(vcpu) : kvm_emulate_rdmsr(vcpu);
	case SVM_EXIT_TASK_SWITCH:
		return handle_task_switch(vcpu);
	case SVM_EXIT_SHUTDOWN:
		return handle_shutdown(vcpu);
	case SVM_EXIT_VMMCALL:
		return kvm_emulate_hypercall(vcpu);
	case SVM_EXIT_WBINVD:
		return kvm_emulate_wbinvd(vcpu);
	case SVM_EXIT_MONITOR:
		return kvm_emulate_monitor(vcpu);
	case SVM_EXIT_MWAIT:
	case SVM_EXIT_MWAIT_COND:
		return kvm_emulate_mwait(vcpu);
	case SVM_EXIT_XSETBV:
		return kvm_emulate_xsetbv(vcpu);
	case SVM_EXIT_NPF:
		return handle_npf(vcpu);
	case SVM_EXIT_RSM:
	case SVM_EXIT_INVLPGA:
	case SVM_EXIT_VMRUN:
	case SVM_EXIT_VMLOAD:
	case SVM_EXIT_VMSAVE:
	case SVM_EXIT_STGI:
	case SVM_EXIT_CLGI:
	case SVM_EXIT_SKINIT:
	case SVM_EXIT_RDTSCP:
	case SVM_EXIT_RDPRU:
		kvm_queue_exception(vcpu, UD_VECTOR);
		return 1;
	case 0xffffffff:	/* VMRUN found the guest state invalid */
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
	struct l4h_vmexit *x = &to_svm(vcpu)->x;

	*reason = x->reason;
	*info1 = x->qualification;
	*info2 = x->gpa;
	*intr_info = x->idt_vector_info;
	*error_code = x->idt_vector_info & SVM_EXITINTINFO_VALID_ERR ? x->idt_vector_error : 0;
}

static void l4h_get_entry_info(struct kvm_vcpu *vcpu, u32 *intr_info, u32 *error_code)
{
	*intr_info = to_svm(vcpu)->event_inj;
	*error_code = to_svm(vcpu)->event_inj_err;
}

/* ---- the rest of the interface */

static void l4h_vcpu_after_set_cpuid(struct kvm_vcpu *vcpu)
{
	update_exception_bitmap(vcpu);
}

/* Not loaded into the CPU: see the head of this file. */
static void l4h_set_dr7(struct kvm_vcpu *vcpu, unsigned long value)
{
}

static void l4h_sync_dirty_debug_regs(struct kvm_vcpu *vcpu)
{
}

static void l4h_refresh_apicv(struct kvm_vcpu *vcpu)
{
}

static void l4h_write_tsc_offset(struct kvm_vcpu *vcpu)
{
	vmcb_wr(vcpu, VMCB_OFF(control.tsc_offset), vcpu->arch.tsc_offset);
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
	hypercall[2] = 0xd9;	/* vmmcall */
}

static void l4h_handle_exit_irqoff(struct kvm_vcpu *vcpu)
{
}

static struct kvm_x86_ops l4h_svm_ops __initdata = {
	.nested_ops = &l4h_nested_ops,
	.name = "l4h-svm",
	.vm_size = sizeof(struct kvm_l4h),
	.check_processor_compatibility = l4h_kvm_ok,
	.enable_virtualization_cpu = l4h_kvm_ok,
	.disable_virtualization_cpu = l4h_kvm_nop,
	.hardware_unsetup = l4h_kvm_nop,
	.has_emulated_msr = l4h_kvm_has_emulated_msr,
	.vcpu_after_set_cpuid = l4h_vcpu_after_set_cpuid,
	.vm_init = l4h_kvm_vm_init,
	.vm_destroy = l4h_kvm_nop_vm,
	.vcpu_create = l4h_vcpu_create,
	.vcpu_free = l4h_kvm_vcpu_free,
	.vcpu_reset = l4h_vcpu_reset,
	.prepare_switch_to_guest = l4h_prepare_switch,
	.vcpu_load = l4h_kvm_vcpu_load,
	.vcpu_put = l4h_kvm_vcpu_put,
	.update_exception_bitmap = update_exception_bitmap,
	.get_feature_msr = l4h_kvm_get_feature_msr,
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
	.flush_tlb_current = l4h_flush_tlb_guest,
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
	.has_wbinvd_exit = l4h_kvm_true,
	.get_l2_tsc_offset = l4h_kvm_l2_zero,
	.get_l2_tsc_multiplier = l4h_kvm_l2_zero,
	.write_tsc_offset = l4h_write_tsc_offset,
	.write_tsc_multiplier = l4h_kvm_nop_vcpu,
	.get_exit_info = l4h_get_exit_info,
	.get_entry_info = l4h_get_entry_info,
	.check_intercept = l4h_kvm_check_intercept,
	.handle_exit_irqoff = l4h_handle_exit_irqoff,
	.setup_mce = l4h_kvm_nop_vcpu,
	.check_emulate_instruction = l4h_check_emulate_instruction,
	.apic_init_signal_blocked = l4h_kvm_init_signal_blocked,
	.recalc_intercepts = l4h_kvm_nop_vcpu,
	.complete_emulated_msr = kvm_complete_insn_gp,
	.vcpu_deliver_sipi_vector = kvm_vcpu_deliver_sipi_vector,
};

static int __init l4h_hardware_setup(void)
{
	enable_apicv = false;
	enable_pmu = false;
	/*
	 * KVM's SPTEs are software only here, as on VT-x (ept.c mirrors their
	 * leaves into the nested page table): the same masks serve, without
	 * accessed and dirty bits.
	 */
	kvm_mmu_set_ept_masks(false, false);
	enable_mmio_caching = false;
	kvm_configure_mmu(true, 0, 4, PG_LEVEL_2M);
	if (boot_cpu_has(X86_FEATURE_NX))
		kvm_enable_efer_bits(EFER_NX);
	if (boot_cpu_has(X86_FEATURE_FXSR_OPT))
		kvm_enable_efer_bits(EFER_FFXSR);
	l4h_kvm_set_cpu_caps();
	return 0;
}

static struct kvm_x86_init_ops l4h_init_ops __initdata = {
	.hardware_setup = l4h_hardware_setup,
	.runtime_ops = &l4h_svm_ops,
	.pmu_ops = &l4h_pmu_ops,
};

int __init l4h_svm_init(void)
{
	int err = kvm_x86_vendor_init(&l4h_init_ops);

	if (err)
		return err;
	err = kvm_init(sizeof(struct vcpu_svm_l4h), __alignof__(struct vcpu_svm_l4h), THIS_MODULE);
	if (err)
		kvm_x86_vendor_exit();
	return err;
}

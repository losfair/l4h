// SPDX-License-Identifier: GPL-2.0
/*
 * The VGIC's hardware side: the list registers and controls of the loaded
 * vCPU, which FL4 keeps for its VCPU (VGIC_* of seL4_VCPUReg) and we in
 * its `state` (vcpu.c), sent to FL4 on the next entry when they change.
 *
 * GICv3: what VHE hyp code does with ICH_*_EL2 (hyp/vgic-v3-sr.c), here
 * on `state`; arch/arm64/kvm's ICH_* register accesses come here too
 * (init.c).  GICv2: vgic-v2.c reaches GICH through a mapping of
 * L4H_FAKE_GICH (gich.h), whose accesses come here; a VM's GICV is the
 * host's (L4H_SLOT_GICV), which stage2.c maps where KVM maps
 * L4H_FAKE_GICV.  Maintenance interrupts are FL4's VGIC maintenance exits.
 */
#undef pr_fmt
#define pr_fmt(fmt) "l4h-kvm: " fmt

#include <linux/kvm_host.h>
#include <linux/irqchip/arm-gic.h>
#include <linux/irqchip/arm-vgic-info.h>
#include <kvm/arm_vgic.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_hyp.h>
#include <l4h_sys.h>
#include "l4h_kvm_arm64.h"

static u64 *vreg(struct l4h_arm_vcpu *v, int r)
{
	return &v->state->regs[r];
}

/* Writes: what changed goes to FL4 on the next entry, VGIC_HCR and the
 * LRs alone in the VGIC_LR group (vcpu.c ctxt_to_state()). */
static void vset_lr(struct l4h_arm_vcpu *v, int r, u64 val)
{
	if (*vreg(v, r) != val) {
		*vreg(v, r) = val;
		v->vgic_lr_dirty = true;
	}
}

static void vset_vmcr(struct l4h_arm_vcpu *v, int r, u64 val)
{
	if (*vreg(v, r) != val) {
		*vreg(v, r) = val;
		v->vgic_vmcr_dirty = true;
	}
}

/* What ICH_HCR_EL2 traps; its other bits (En, the maintenance interrupt
 * enables) need it only while an LR is in use. */
#define L4H_ICH_HCR_TRAPS	(ICH_HCR_EL2_TC | ICH_HCR_EL2_TALL0 | ICH_HCR_EL2_TALL1 | \
				 ICH_HCR_EL2_TDIR | ICH_HCR_EL2_TSEI)

static bool is_lr_reg(int r)
{
	return r == L4H_ARM_VCPUREG_VGIC_HCR ||
	       (r >= L4H_ARM_VCPUREG_VGIC_LR0 && r <= L4H_ARM_VCPUREG_VGIC_LR15);
}

/*
 * GICv3: VMCR and the active priorities as the guest left them.  FL4
 * keeps them in the CPU, and across vCPU switches and migrations itself:
 * we do not take them back on exits or vcpu_put, but when KVM reads them
 * (vgic-v3.c's VMCR, the APR sysregs, the ICH_* emulation).
 */
static void pull_vmcr(struct l4h_arm_vcpu *v)
{
	const struct l4h_arm_vcpu_state *st;
	int i;

	if (!v->synced || v->vgic_vmcr_dirty || l4h_bootinfo->arm_virt.gic_version != 3)
		return;
	preempt_disable();
	st = (const void *)((const char *)l4h_this_vcpu()->ipcbuf + L4H_VCPU_STATE_OFFSET);
	if (!WARN_ON_ONCE(l4h_arm_vcpu_read_state_self(v->vcpu_obj.cptr, L4H_ARM_VCPU_STATE_VGIC))) {
		*vreg(v, L4H_ARM_VCPUREG_VGIC_VMCR) = st->regs[L4H_ARM_VCPUREG_VGIC_VMCR];
		for (i = 0; i < 4; i++) {
			*vreg(v, L4H_ARM_VCPUREG_VGIC_AP0R0 + i) = st->regs[L4H_ARM_VCPUREG_VGIC_AP0R0 + i];
			*vreg(v, L4H_ARM_VCPUREG_VGIC_AP1R0 + i) = st->regs[L4H_ARM_VCPUREG_VGIC_AP1R0 + i];
		}
	}
	preempt_enable();
}

static struct l4h_arm_vcpu *loaded(void)
{
	return this_cpu_read(l4h_loaded_vcpu);
}

static unsigned int nr_lrs(void)
{
	return min_t(unsigned int, (l4h_bootinfo->arm_virt.vgic_vtr & 0x1f) + 1, 16);
}

/* The empty list registers, from their state bits: FL4's VGIC_ELRSR is
 * the CPU's at the last exit, stale after we write the LRs. */
static u64 elrsr(struct l4h_arm_vcpu *v, bool v3)
{
	u64 mask = v3 ? ICH_LR_STATE : GICH_LR_STATE, r = 0;
	unsigned int i;

	for (i = 0; i < nr_lrs(); i++)
		if (!(*vreg(v, L4H_ARM_VCPUREG_VGIC_LR0 + i) & mask))
			r |= 1ull << i;
	return r;
}

/* ---- GICv3: hyp/vgic-v3-sr.c on `state` */

u64 __gic_v3_get_lr(unsigned int lr)
{
	struct l4h_arm_vcpu *v = loaded();

	return v ? *vreg(v, L4H_ARM_VCPUREG_VGIC_LR0 + (lr & 0xf)) : 0;
}

void __vgic_v3_save_state(struct vgic_v3_cpu_if *cpu_if)
{
	struct l4h_arm_vcpu *v = loaded();
	int i;

	if (!v || !(cpu_if->used_lrs || cpu_if->its_vpe.its_vm))
		return;
	/*
	 * The list registers as FL4 holds them, not ELRSR's shortcut: FL4
	 * leaves ELRSR as the CPU last had it, which is stale when the
	 * guest did not run (an event stopped it first) after we wrote the
	 * LRs.  A consumed LR has its state bits clear anyway.
	 */
	/* vgic-v3.c clears UIE only after this: keep the traps alone, so
	 * that VGIC_HCR is 0 again without them. */
	vset_lr(v, L4H_ARM_VCPUREG_VGIC_HCR, cpu_if->vgic_hcr & L4H_ICH_HCR_TRAPS);
	for (i = 0; i < cpu_if->used_lrs; i++) {
		cpu_if->vgic_lr[i] = *vreg(v, L4H_ARM_VCPUREG_VGIC_LR0 + i);
		vset_lr(v, L4H_ARM_VCPUREG_VGIC_LR0 + i, 0);
	}
}

void __vgic_v3_restore_state(struct vgic_v3_cpu_if *cpu_if)
{
	struct l4h_arm_vcpu *v = loaded();
	int i;

	/* As hyp/vgic-v3-sr.c: with no LR in use, VGIC_HCR stays as
	 * __vgic_v3_activate_traps() left it (0 without traps to set). */
	if (!v || !(cpu_if->used_lrs || cpu_if->its_vpe.its_vm))
		return;
	vset_lr(v, L4H_ARM_VCPUREG_VGIC_HCR, cpu_if->vgic_hcr);
	for (i = 0; i < cpu_if->used_lrs; i++)
		vset_lr(v, L4H_ARM_VCPUREG_VGIC_LR0 + i, cpu_if->vgic_lr[i]);
}

/*
 * As hyp/vgic-v3-sr.c: ICH_HCR_EL2 only when it traps something (the trap
 * bits vgic-v3.c sets in vgic_hcr, L4H_ICH_HCR_TRAPS, or no vgic at all),
 * and otherwise when an LR is in use (__vgic_v3_restore_state()), so that
 * an exit with no interrupt to inject leaves VGIC_HCR 0 and the guest's
 * ICC_* accesses do not trap.
 */
void __vgic_v3_activate_traps(struct vgic_v3_cpu_if *cpu_if)
{
	struct l4h_arm_vcpu *v = loaded();

	if (!v)
		return;
	if ((cpu_if->vgic_hcr & L4H_ICH_HCR_TRAPS) || cpu_if->its_vpe.its_vm ||
	    !cpu_if->vgic_sre || !(cpu_if->vgic_hcr & ICH_HCR_EL2_En))
		vset_lr(v, L4H_ARM_VCPUREG_VGIC_HCR, cpu_if->vgic_hcr);
	else
		vset_lr(v, L4H_ARM_VCPUREG_VGIC_HCR, 0);
}

void __vgic_v3_deactivate_traps(struct vgic_v3_cpu_if *cpu_if)
{
	struct l4h_arm_vcpu *v = loaded();

	if (v)
		vset_lr(v, L4H_ARM_VCPUREG_VGIC_HCR, 0);
}

/* VMCR and the priorities stay in FL4 (pull_vmcr()): nothing to save on
 * vcpu_put or before WFI. */
void __vgic_v3_save_vmcr_aprs(struct vgic_v3_cpu_if *cpu_if)
{
}

void __vgic_v3_restore_vmcr_aprs(struct vgic_v3_cpu_if *cpu_if)
{
	struct l4h_arm_vcpu *v = loaded();
	int i;

	/* Only what goes into FL4 before the first entry: afterwards FL4
	 * has them, and KVM's changes come through l4h_vgic_v3_set_*(). */
	if (!v || v->synced)
		return;
	vset_vmcr(v, L4H_ARM_VCPUREG_VGIC_VMCR, cpu_if->vgic_vmcr);
	for (i = 0; i < 4; i++) {
		vset_vmcr(v, L4H_ARM_VCPUREG_VGIC_AP0R0 + i, cpu_if->vgic_ap0r[i]);
		vset_vmcr(v, L4H_ARM_VCPUREG_VGIC_AP1R0 + i, cpu_if->vgic_ap1r[i]);
	}
}

/*
 * vgic-v3.c and vgic-sys-reg-v3.c reach VMCR and the active priorities in
 * vgic_v3_cpu_if through these (0019).  Only from the vCPU's own thread or
 * with no vCPU loaded (device attributes, with every vCPU locked): another
 * vCPU's thread (a directed yield's runnable check) sees KVM's copy.
 */
static struct l4h_arm_vcpu *vmcr_owner(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu *running = kvm_get_running_vcpu();

	if (l4h_bootinfo->arm_virt.gic_version != 3 || (running && running != vcpu))
		return NULL;
	return vcpu->arch.l4h;
}

void l4h_vgic_v3_pull_vmcr(struct kvm_vcpu *vcpu)
{
	struct vgic_v3_cpu_if *cpu_if = &vcpu->arch.vgic_cpu.vgic_v3;
	struct l4h_arm_vcpu *v = vmcr_owner(vcpu);
	int i;

	if (!v || !v->synced)
		return;
	pull_vmcr(v);
	cpu_if->vgic_vmcr = *vreg(v, L4H_ARM_VCPUREG_VGIC_VMCR);
	for (i = 0; i < 4; i++) {
		cpu_if->vgic_ap0r[i] = *vreg(v, L4H_ARM_VCPUREG_VGIC_AP0R0 + i);
		cpu_if->vgic_ap1r[i] = *vreg(v, L4H_ARM_VCPUREG_VGIC_AP1R0 + i);
	}
}

void l4h_vgic_v3_set_vmcr(struct kvm_vcpu *vcpu, u32 vmcr)
{
	struct l4h_arm_vcpu *v = vmcr_owner(vcpu);

	if (!v)
		return;
	/* The whole group goes to FL4: the priorities as the guest left them. */
	pull_vmcr(v);
	vset_vmcr(v, L4H_ARM_VCPUREG_VGIC_VMCR, vmcr);
}

void l4h_vgic_v3_set_apr(struct kvm_vcpu *vcpu, u8 apr, u8 idx, u32 val)
{
	struct l4h_arm_vcpu *v = vmcr_owner(vcpu);

	if (!v || idx > 3)
		return;
	pull_vmcr(v);
	vset_vmcr(v, (apr ? L4H_ARM_VCPUREG_VGIC_AP1R0 : L4H_ARM_VCPUREG_VGIC_AP0R0) + idx, val);
}

void __vgic_v3_init_lrs(void)
{
}

/* ICH_VTR_EL2; the guest's GIC is always the system register one. */
u64 __vgic_v3_get_gic_config(void)
{
	return l4h_bootinfo->arm_virt.vgic_vtr;
}

bool l4h_sysreg_vgic(u32 enc, u64 *val, bool write)
{
	struct l4h_arm_vcpu *v;
	int r;

	switch (enc) {
	case SYS_ICH_VTR_EL2:
		if (!write)
			*val = l4h_bootinfo->arm_virt.vgic_vtr;
		return true;
	case SYS_ICH_HCR_EL2:
		r = L4H_ARM_VCPUREG_VGIC_HCR;
		break;
	case SYS_ICH_VMCR_EL2:
		r = L4H_ARM_VCPUREG_VGIC_VMCR;
		break;
	case SYS_ICH_MISR_EL2:
		r = L4H_ARM_VCPUREG_VGIC_MISR;
		break;
	case SYS_ICH_EISR_EL2:
		r = L4H_ARM_VCPUREG_VGIC_EISR;
		break;
	case SYS_ICH_ELRSR_EL2:
		if (!write)
			*val = (v = loaded()) ? elrsr(v, true) : 0;
		return true;
	case SYS_ICH_AP0R0_EL2 ... SYS_ICH_AP0R3_EL2:
		r = L4H_ARM_VCPUREG_VGIC_AP0R0 + sys_reg_Op2(enc);
		break;
	case SYS_ICH_AP1R0_EL2 ... SYS_ICH_AP1R3_EL2:
		r = L4H_ARM_VCPUREG_VGIC_AP1R0 + sys_reg_Op2(enc);
		break;
	case SYS_ICH_LR0_EL2 ... SYS_ICH_LR15_EL2:
		r = L4H_ARM_VCPUREG_VGIC_LR0 + ((sys_reg_CRm(enc) & 1) << 3) + sys_reg_Op2(enc);
		break;
	default:
		return false;
	}
	v = loaded();
	if (write) {
		if (v && is_lr_reg(r))
			vset_lr(v, r, *val);
		else if (v)
			vset_vmcr(v, r, *val);
	} else {
		if (v && (r == L4H_ARM_VCPUREG_VGIC_VMCR ||
			  (r >= L4H_ARM_VCPUREG_VGIC_AP0R0 && r <= L4H_ARM_VCPUREG_VGIC_AP1R3)))
			pull_vmcr(v);
		*val = v ? *vreg(v, r) : 0;
	}
	return true;
}

/* ---- GICv2: GICH of the loaded vCPU (gich.h) */

static u64 *gich_reg(struct l4h_arm_vcpu *v, unsigned long off, int *shift)
{
	*shift = 0;
	if (off >= GICH_LR0 && off < GICH_LR0 + 4 * nr_lrs())
		return vreg(v, L4H_ARM_VCPUREG_VGIC_LR0 + (off - GICH_LR0) / 4);
	switch (off) {
	case GICH_HCR:
		return vreg(v, L4H_ARM_VCPUREG_VGIC_HCR);
	case GICH_VMCR:
		return vreg(v, L4H_ARM_VCPUREG_VGIC_VMCR);
	case GICH_MISR:
		return vreg(v, L4H_ARM_VCPUREG_VGIC_MISR);
	case GICH_EISR0:
		return vreg(v, L4H_ARM_VCPUREG_VGIC_EISR);
	case GICH_EISR1:
		*shift = 32;
		return vreg(v, L4H_ARM_VCPUREG_VGIC_EISR);
	case GICH_APR:
		return vreg(v, L4H_ARM_VCPUREG_VGIC_AP0R0);
	}
	return NULL;
}

static bool is_gich(const volatile void __iomem *addr, unsigned long *off)
{
	*off = (unsigned long)addr - (unsigned long)L4H_FAKE_GICH_VA;
	return *off < PAGE_SIZE;
}

u32 l4h_kvm_readl(const volatile void __iomem *addr)
{
	struct l4h_arm_vcpu *v = loaded();
	unsigned long off;
	u64 *r;
	int shift;

	if (!is_gich(addr, &off))
		return readl_relaxed(addr);
	if (off == GICH_VTR)
		return l4h_bootinfo->arm_virt.vgic_vtr;
	if (!v)
		return 0;
	if (off == GICH_ELRSR0)
		return elrsr(v, false);
	if (off == GICH_ELRSR1)
		return elrsr(v, false) >> 32;
	r = gich_reg(v, off, &shift);
	return r ? (u32)(*r >> shift) : 0;
}

void l4h_kvm_writel(u32 val, volatile void __iomem *addr)
{
	struct l4h_arm_vcpu *v = loaded();
	unsigned long off;
	u64 *r;
	int shift;

	if (!is_gich(addr, &off)) {
		writel_relaxed(val, addr);
		return;
	}
	if (!v)
		return;
	r = gich_reg(v, off, &shift);
	/* GICv2 sends the whole VGIC group. */
	if (r)
		vset_vmcr(v, r - v->state->regs, (*r & ~(0xffffffffull << shift)) | ((u64)val << shift));
}

void __iomem *l4h_kvm_ioremap(phys_addr_t phys, size_t size)
{
	if (phys == L4H_FAKE_GICH)
		return L4H_FAKE_GICH_VA;
	return ioremap(phys, size);
}

void l4h_kvm_iounmap(volatile void __iomem *addr)
{
	unsigned long off;

	if (!is_gich(addr, &off))
		iounmap((void __iomem *)addr);
}

/* ---- the GIC KVM finds: FL4's, without a maintenance interrupt */

void __init l4h_vgic_init(void)
{
	static struct gic_kvm_info info = {
		.no_maint_irq_mask = true,
	};

	if (l4h_bootinfo->arm_virt.gic_version == 3) {
		info.type = GIC_V3;
	} else {
		info.type = GIC_V2;
		info.vcpu = (struct resource)DEFINE_RES_MEM(L4H_FAKE_GICV,
							    L4H_GICV_PAGES * PAGE_SIZE);
		info.vctrl = (struct resource)DEFINE_RES_MEM(L4H_FAKE_GICH, PAGE_SIZE);
	}
	vgic_set_kvm_info(&info);
}

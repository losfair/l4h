/* SPDX-License-Identifier: GPL-2.0 */
/* Private definitions of arch/l4h/kvm/arm64. */
#ifndef __L4H_KVM_ARM64_H
#define __L4H_KVM_ARM64_H

#include <linux/xarray.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/kvm_host.h>
#include <l4h_caps.h>

/*
 * A VM's FL4 Stage-2 VSpace: a cache of the leaves of KVM's software
 * Stage-2 table (arch/arm64/kvm/hyp/pgtable.c), which the CPU never walks
 * (stage2.c).  Tables below the root, by the IPA bits each one maps:
 * level 0 the last level (2 MiB of 4 KiB pages), level 1 (1 GiB of
 * 2 MiB blocks), level 2 (512 GiB), when the root is FL4's level 0.
 */
#define L4H_S2_LEVELS	3

struct l4h_s2 {
	struct kvm *kvm;
	unsigned long root;		/* cptr, from the host's pool */
	int levels;			/* tables below the root FL4 uses */
	spinlock_t lock;
	struct list_head tables;	/* newest first */
	struct xarray table_at[L4H_S2_LEVELS];
	struct xarray pages;		/* gfn -> 4 KiB leaf */
	struct xarray large;		/* gfn >> 9 -> 2 MiB leaf */
};

/* The physical addresses KVM is told GICv2's GICV and GICH are at: none
 * that RAM or a device of the guest kernel has.  A Stage-2 mapping of
 * L4H_FAKE_GICV maps the host's GICV frames (L4H_SLOT_GICV); GICH accesses
 * through its "mapping" reach the VCPU's VGIC registers (vgic.c). */
#define L4H_FAKE_GICV		0xfffff0000000ull
#define L4H_FAKE_GICH		0xfffff0010000ull
#define L4H_FAKE_GICH_VA	((void __iomem *)0x7ffff0010000ul)

/*
 * A KVM vCPU on FL4: a VCPU object bound to a TCB of ours whose VSpace is
 * the VM's Stage-2 root, entered from our vCPU's own thread
 * (seL4_ARM_VCPU_Run, guest/provider kvm.c l4h_arm_vcpu_enter()).  `state`
 * is what FL4 holds for it as we last saw it: the registers KVM would find
 * in the CPU while the vCPU is loaded.  Entries transfer only the groups
 * that changed, through our vCPU's IPC buffer (vcpu.c).
 */
struct l4h_arm_vcpu {
	struct kvm_vcpu *vcpu;
	struct l4h_obj vcpu_obj;
	struct l4h_obj tcb_obj;
	struct l4h_uctx uctx;			/* the TCB, for its FP state */
	struct l4h_arm_vcpu_state *state;
	unsigned long s2_root;			/* the TCB's VSpace */
	bool vppi_masked;			/* FL4 holds PPI 27 masked */
	bool synced;		/* FL4's VCPU holds `state` (groups we send) */
	bool timer_dirty;	/* the TIMER group changed since the last entry */
	/* Since the last entry: VMCR or the active priorities changed (the
	 * whole VGIC group goes), or only VGIC_HCR or the LRs (on GICv3,
	 * VGIC_LR goes; FL4 keeps VMCR and the priorities in the CPU). */
	bool vgic_vmcr_dirty;
	bool vgic_lr_dirty;
	int fp_state;		/* L4H_FP_*: where the guest's FP/SIMD state is */
};

static inline struct l4h_s2 *to_s2(struct kvm *kvm)
{
	return kvm->arch.l4h_s2;
}

/* init.c */
extern unsigned int l4h_kvm_ipa_bits;
bool l4h_kvm_available(void);
u64 l4h_kvm_id_reg(u32 enc);

/* stage2.c */
void l4h_s2_pool_init(unsigned int nr);
int l4h_s2_create(struct kvm *kvm);
void l4h_s2_destroy(struct kvm *kvm);

/* vcpu.c */
DECLARE_PER_CPU(struct l4h_arm_vcpu *, l4h_loaded_vcpu);
int l4h_arm_vcpu_create(struct kvm_vcpu *vcpu);
void l4h_arm_vcpu_destroy(struct kvm_vcpu *vcpu);

bool l4h_sysreg_vcpu(u32 enc, u64 *val, bool write);

/* vgic.c */
u32 l4h_kvm_readl(const volatile void __iomem *addr);
void l4h_kvm_writel(u32 val, volatile void __iomem *addr);
void __iomem *l4h_kvm_ioremap(phys_addr_t phys, size_t size);
void l4h_kvm_iounmap(volatile void __iomem *addr);
void l4h_vgic_init(void);
bool l4h_sysreg_vgic(u32 enc, u64 *val, bool write);

#endif

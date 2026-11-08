/* SPDX-License-Identifier: GPL-2.0 */
/* Private definitions of arch/l4h/kvm. */
#ifndef __L4H_KVM_H
#define __L4H_KVM_H

#include <linux/xarray.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <l4h_caps.h>

#define L4H_EPT_LEVELS 3	/* tables below the root */

/* A VM's seL4 EPT, a cache of KVM's software page table (ept.c). */
struct l4h_ept {
	unsigned long root;		/* cptr, from the host's pool */
	spinlock_t lock;
	struct list_head tables;	/* newest first */
	struct xarray table_at[L4H_EPT_LEVELS];
	struct xarray pages;		/* gfn -> 4 KiB leaf */
	struct xarray large;		/* gfn >> 9 -> 2 MiB leaf */
};

struct kvm_l4h {
	struct kvm kvm;
	struct l4h_ept ept;
};

static inline struct l4h_ept *to_ept(struct kvm *kvm)
{
	return &container_of(kvm, struct kvm_l4h, kvm)->ept;
}

int l4h_ept_init(struct l4h_ept *e);
void l4h_ept_destroy(struct l4h_ept *e);
void l4h_ept_pool_init(unsigned int nr);

void l4h_kvm_fpu_init(void);
void l4h_kvm_fpu_load(struct kvm_vcpu *vcpu);

/* What the vCPU structures of both backends start with (common.c). */
struct l4h_vcpu_obj {
	struct kvm_vcpu vcpu;
	struct l4h_obj obj;
	u64 id;
	int bound_cpu;		/* the vCPU whose kTCB it is bound to, or -1 */
	u64 hw_xcr0;		/* what seL4 loads for VM entries */
};

static inline struct l4h_vcpu_obj *to_l4h_obj(struct kvm_vcpu *vcpu)
{
	return container_of(vcpu, struct l4h_vcpu_obj, vcpu);
}

int l4h_kvm_vcpu_alloc(struct l4h_vcpu_obj *v);
void l4h_kvm_vcpu_free(struct kvm_vcpu *vcpu);
void l4h_kvm_vcpu_load(struct kvm_vcpu *vcpu, int cpu);
void l4h_kvm_vcpu_put(struct kvm_vcpu *vcpu);
void l4h_kvm_sync_xcr0(struct kvm_vcpu *vcpu);
int l4h_kvm_internal_error(struct kvm_vcpu *vcpu, u32 reason);
int l4h_kvm_vm_init(struct kvm *kvm);
void l4h_kvm_nop_vm(struct kvm *kvm);
void l4h_kvm_nop_vcpu(struct kvm_vcpu *vcpu);
int l4h_kvm_ok(void);
void l4h_kvm_nop(void);
u64 l4h_kvm_l2_zero(struct kvm_vcpu *vcpu);
bool l4h_kvm_true(void);
int l4h_kvm_check_intercept(struct kvm_vcpu *vcpu, struct x86_instruction_info *info,
			    enum x86_intercept_stage stage, struct x86_exception *exception);
bool l4h_kvm_init_signal_blocked(struct kvm_vcpu *vcpu);
int l4h_kvm_get_feature_msr(u32 msr, u64 *data);
bool l4h_kvm_has_emulated_msr(struct kvm *kvm, u32 index);
void l4h_kvm_set_cpu_caps(void);
extern const struct kvm_x86_nested_ops l4h_nested_ops;
extern struct kvm_pmu_ops l4h_pmu_ops;

/* The vendor backends' module init (vmx.c, svm.c). */
int l4h_vmx_init(void);
int l4h_svm_init(void);

#endif

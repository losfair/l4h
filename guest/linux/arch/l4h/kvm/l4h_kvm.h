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

#endif

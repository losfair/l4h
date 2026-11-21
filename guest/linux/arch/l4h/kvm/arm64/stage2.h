/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Included in arch/arm64/kvm/mmu.c (Makefile): what its KVM_PGT_FN() calls,
 * KVM's Stage-2 table operations followed by FL4's (stage2.c).
 */
#ifndef __L4H_KVM_ARM64_STAGE2_H
#define __L4H_KVM_ARM64_STAGE2_H
#include <asm/kvm_pgtable.h>
#include <l4h_caps.h>

int l4h_kvm_pgtable_stage2_init(struct kvm_pgtable *pgt, struct kvm_s2_mmu *mmu,
				struct kvm_pgtable_mm_ops *mm_ops);
void l4h_kvm_pgtable_stage2_destroy(struct kvm_pgtable *pgt);
void l4h_kvm_pgtable_stage2_free_unlinked(struct kvm_pgtable_mm_ops *mm_ops, void *pgtable,
					  s8 level);
int l4h_kvm_pgtable_stage2_map(struct kvm_pgtable *pgt, u64 addr, u64 size, u64 phys,
			       enum kvm_pgtable_prot prot, void *mc,
			       enum kvm_pgtable_walk_flags flags);
int l4h_kvm_pgtable_stage2_unmap(struct kvm_pgtable *pgt, u64 addr, u64 size);
int l4h_kvm_pgtable_stage2_wrprotect(struct kvm_pgtable *pgt, u64 addr, u64 size);
int l4h_kvm_pgtable_stage2_relax_perms(struct kvm_pgtable *pgt, u64 addr,
				       enum kvm_pgtable_prot prot,
				       enum kvm_pgtable_walk_flags flags);
void l4h_kvm_pgtable_stage2_mkyoung(struct kvm_pgtable *pgt, u64 addr,
				    enum kvm_pgtable_walk_flags flags);
bool l4h_kvm_pgtable_stage2_test_clear_young(struct kvm_pgtable *pgt, u64 addr, u64 size,
					     bool mkold);
int l4h_kvm_pgtable_stage2_flush(struct kvm_pgtable *pgt, u64 addr, u64 size);
int l4h_kvm_pgtable_stage2_split(struct kvm_pgtable *pgt, u64 addr, u64 size,
				 struct kvm_mmu_memory_cache *mc);
#endif

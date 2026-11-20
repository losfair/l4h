// SPDX-License-Identifier: GPL-2.0
/*
 * What the hyp code and the rest of arm64's kernel would give arch/arm64/kvm,
 * and FL4 does instead or never offers here.
 *
 * TLB maintenance: FL4 invalidates a VM's translations whenever it removes
 * a Stage-2 leaf or table (stage2.c), and its VMIDs are its own, so KVM's
 * invalidations have nothing left to do.  Nested virtualization (address
 * translation for a guest hypervisor, EL2 TLBIs), protected mode and
 * GICv4 direct injection are never offered (no ARM64_HAS_NESTED_VIRT,
 * KVM_MODE_PROTECTED or GICv4 here): their entry points are unreachable.
 */
#include <linux/kvm_host.h>
#include <linux/irqchip/arm-gic-v4.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_pkvm.h>
#include <asm/kvm_emulate.h>

void __kvm_flush_vm_context(void)
{
}

void __kvm_flush_cpu_context(struct kvm_s2_mmu *mmu)
{
}

void __kvm_tlb_flush_vmid(struct kvm_s2_mmu *mmu)
{
}

void __kvm_tlb_flush_vmid_ipa(struct kvm_s2_mmu *mmu, phys_addr_t ipa, int level)
{
}

void __kvm_tlb_flush_vmid_ipa_nsh(struct kvm_s2_mmu *mmu, phys_addr_t ipa, int level)
{
}

int __kvm_tlbi_s1e2(struct kvm_s2_mmu *mmu, u64 va, u64 sys_encoding)
{
	return -EINVAL;
}

void __kvm_at_s1e01(struct kvm_vcpu *vcpu, u32 op, u64 vaddr)
{
	WARN_ON_ONCE(1);
}

void __kvm_at_s1e2(struct kvm_vcpu *vcpu, u32 op, u64 vaddr)
{
	WARN_ON_ONCE(1);
}

void __kvm_at_s12(struct kvm_vcpu *vcpu, u32 op, u64 vaddr)
{
	WARN_ON_ONCE(1);
}

int __kvm_translate_va(struct kvm_vcpu *vcpu, struct s1_walk_info *wi,
		       struct s1_walk_result *wr, u64 va)
{
	return -EINVAL;
}

int __kvm_find_s1_desc_level(struct kvm_vcpu *vcpu, u64 va, u64 ipa, int *level)
{
	return -EINVAL;
}

int pkvm_init_host_vm(struct kvm *kvm)
{
	return 0;
}

int pkvm_create_hyp_vm(struct kvm *kvm)
{
	return -EINVAL;
}

void pkvm_destroy_hyp_vm(struct kvm *kvm)
{
}

int pkvm_create_hyp_vcpu(struct kvm_vcpu *vcpu)
{
	return -EINVAL;
}

bool gic_cpuif_has_vsgi(void)
{
	return false;
}

int its_alloc_vcpu_irqs(struct its_vm *vm)
{
	return -ENODEV;
}

void its_free_vcpu_irqs(struct its_vm *vm)
{
}

int its_make_vpe_resident(struct its_vpe *vpe, bool g0en, bool g1en)
{
	return -ENODEV;
}

int its_make_vpe_non_resident(struct its_vpe *vpe, bool db)
{
	return -ENODEV;
}

int its_commit_vpe(struct its_vpe *vpe)
{
	return -ENODEV;
}

int its_invall_vpe(struct its_vpe *vpe)
{
	return -ENODEV;
}

int its_map_vlpi(int irq, struct its_vlpi_map *map)
{
	return -ENODEV;
}

int its_get_vlpi(int irq, struct its_vlpi_map *map)
{
	return -ENODEV;
}

void its_unmap_vlpi(int irq)
{
}

int its_prop_update_vlpi(int irq, u8 config, bool inv)
{
	return -ENODEV;
}

int its_prop_update_vsgi(int irq, u8 priority, bool group)
{
	return -ENODEV;
}

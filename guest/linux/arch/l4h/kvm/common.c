// SPDX-License-Identifier: GPL-2.0
/*
 * What KVM's two vendor backends in the l4h guest kernel share
 * (DESIGN.md §5.10): VCPU objects and their binding to the kTCB of the L4H
 * vCPU that runs them, the parts of kvm_x86_ops that neither VMX nor SVM
 * needs here, and the choice between them at boot.  vmx.c runs seL4 VCPUs
 * on VT-x, svm.c on AMD-V; seL4 picks by the CPU, and the backend follows.
 */
/* compat.h has the one of arch/x86/kvm. */
#undef pr_fmt
#define pr_fmt(fmt) "l4h-kvm: " fmt

#include <linux/kvm_host.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/percpu.h>
#include <l4h_sys.h>
#include "cpuid.h"
#include "pmu.h"
#include "x86.h"
#include "l4h_kvm.h"

/* ---- VCPU objects */

static atomic64_t next_vcpu_id = ATOMIC64_INIT(1);

/* What each kTCB is set up to run. */
static DEFINE_PER_CPU(u64, bound_vcpu);
static DEFINE_PER_CPU(unsigned long, bound_ept);

int l4h_kvm_vcpu_alloc(struct l4h_vcpu_obj *v)
{
	int err;

	for (;;) {
		err = l4h_obj_alloc(L4H_OBJ_VCPU, 0, &v->obj);
		if (err != -ENOMEM || !l4h_objmem_wait())
			break;
	}
	if (err)
		return err;
	v->id = atomic64_inc_return(&next_vcpu_id);
	v->bound_cpu = -1;
	v->hw_xcr0 = l4h_xfeatures;	/* seL4's for a new VCPU */
	return 0;
}

/*
 * As kvm_load_guest_xsave_state(): XCR0 matters to the guest only with
 * CR4.OSXSAVE, and seL4 loads it only around VM entries.  Both XSETBV exits
 * (always on with AMD-V) and KVM_SET_XCRS end up here before the next entry.
 */
void l4h_kvm_sync_xcr0(struct kvm_vcpu *vcpu)
{
	struct l4h_vcpu_obj *v = to_l4h_obj(vcpu);
	u64 xcr0 = kvm_is_cr4_bit_set(vcpu, X86_CR4_OSXSAVE) ? vcpu->arch.xcr0 : l4h_xfeatures;

	if (xcr0 != v->hw_xcr0) {
		WARN_ON_ONCE(l4h_vcpu_write_xcr0(v->obj.cptr, xcr0));
		v->hw_xcr0 = xcr0;
	}
}

void l4h_kvm_vcpu_free(struct kvm_vcpu *vcpu)
{
	l4h_obj_free(&to_l4h_obj(vcpu)->obj);
}

void l4h_kvm_vcpu_load(struct kvm_vcpu *vcpu, int cpu)
{
	struct l4h_vcpu_obj *v = to_l4h_obj(vcpu);
	unsigned long ktcb = l4h_this_vcpu()->ktcb, root = to_ept(vcpu->kvm)->root;

	/* A binding has two ends: binding the VCPU to another kTCB, or
	 * another VCPU to this one, undoes it. */
	if (this_cpu_read(bound_vcpu) != v->id || v->bound_cpu != cpu) {
		WARN_ON_ONCE(l4h_vcpu_set_tcb(v->obj.cptr, ktcb));
		this_cpu_write(bound_vcpu, v->id);
		v->bound_cpu = cpu;
	}
	if (this_cpu_read(bound_ept) != root) {
		WARN_ON_ONCE(l4h_tcb_set_ept(ktcb, root));
		this_cpu_write(bound_ept, root);
	}
}

/*
 * The task may be leaving this vCPU in the middle of KVM_RUN (a preemption,
 * then a migration): its guest's registers must not stay in this kTCB, where
 * the next vCPU would not find them, and from which a later save here would
 * overwrite what the guest did since.
 */
void l4h_kvm_vcpu_put(struct kvm_vcpu *vcpu)
{
	l4h_kvm_fpu_save();
}

int l4h_kvm_internal_error(struct kvm_vcpu *vcpu, u32 reason)
{
	vcpu->run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
	vcpu->run->internal.suberror = KVM_INTERNAL_ERROR_UNEXPECTED_EXIT_REASON;
	vcpu->run->internal.ndata = 2;
	vcpu->run->internal.data[0] = reason;
	vcpu->run->internal.data[1] = vcpu->arch.last_vmentry_cpu;
	return 0;
}

/* ---- VMs and what no backend does here */

int l4h_kvm_vm_init(struct kvm *kvm)
{
	return l4h_ept_init(to_ept(kvm));
}

/* After KVM's last use of the MMU; maybe with no l4h_kvm_vm_init() before it. */
void l4h_kvm_vm_free(struct kvm *kvm)
{
	if (to_ept(kvm)->root)
		l4h_ept_destroy(to_ept(kvm));
}

void l4h_kvm_nop_vm(struct kvm *kvm)
{
}

void l4h_kvm_nop_vcpu(struct kvm_vcpu *vcpu)
{
}

int l4h_kvm_ok(void)
{
	return 0;
}

void l4h_kvm_nop(void)
{
}

u64 l4h_kvm_l2_zero(struct kvm_vcpu *vcpu)
{
	return 0;
}

bool l4h_kvm_true(void)
{
	return true;
}

int l4h_kvm_check_intercept(struct kvm_vcpu *vcpu, struct x86_instruction_info *info,
			    enum x86_intercept_stage stage, struct x86_exception *exception)
{
	return X86EMUL_CONTINUE;
}

bool l4h_kvm_init_signal_blocked(struct kvm_vcpu *vcpu)
{
	return false;
}

int l4h_kvm_get_feature_msr(u32 msr, u64 *data)
{
	return KVM_MSR_RET_UNSUPPORTED;
}

bool l4h_kvm_has_emulated_msr(struct kvm *kvm, u32 index)
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

/* No nested virtualization: a guest never enters guest mode, and none of
 * these runs. */
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

const struct kvm_x86_nested_ops l4h_nested_ops = {
	.leave_nested = l4h_kvm_nop_vcpu,
	.is_exception_vmexit = l4h_is_exception_vmexit,
	.check_events = l4h_nested_check_events,
	.triple_fault = l4h_kvm_nop_vcpu,
	.get_state = l4h_nested_get_state,
	.set_state = l4h_nested_set_state,
	.get_nested_state_pages = l4h_nested_state_pages,
	.hv_inject_synthetic_vmexit_post_tlb_flush = l4h_kvm_nop_vcpu,
};

/* What neither seL4's VCPU interface nor XCR0 lets a guest have, on either
 * vendor. */
void __init l4h_kvm_set_cpu_caps(void)
{
	kvm_set_cpu_caps();
	kvm_cpu_cap_clear(X86_FEATURE_VMX);
	kvm_cpu_cap_clear(X86_FEATURE_SVM);
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
	kvm_cpu_cap_clear(X86_FEATURE_AMD_IBRS);
	kvm_cpu_cap_clear(X86_FEATURE_AMD_STIBP);
	kvm_cpu_cap_clear(X86_FEATURE_AMD_SSBD);
	kvm_cpu_cap_clear(X86_FEATURE_VIRT_SSBD);
	kvm_cpu_cap_clear(X86_FEATURE_AMD_PSFD);
	kvm_caps.supported_xss = 0;
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

struct kvm_pmu_ops l4h_pmu_ops __initdata = {
	.rdpmc_ecx_to_pmc = l4h_pmc_none,
	.msr_idx_to_pmc = l4h_msr_pmc_none,
	.is_valid_msr = l4h_pmu_msr_invalid,
	.get_msr = l4h_pmu_msr_fail,
	.set_msr = l4h_pmu_msr_fail,
	.refresh = l4h_kvm_nop_vcpu,
	.init = l4h_kvm_nop_vcpu,
	.MAX_NR_GP_COUNTERS = 0,
	.MIN_NR_GP_COUNTERS = 0,
};

/* ---- the choice of backend */

static bool l4h_cpu_is_amd;

/* Fill in what x86's boot code would have about the CPU, before KVM's
 * module init reads it (the physical address width, for SPTEs). */
static int __init cpu_setup(void)
{
	struct cpuinfo_um *c = &boot_cpu_data;
	u32 eax, ebx, ecx, edx;

	cpuid(0, &eax, &ebx, &ecx, &edx);
	/* seL4 uses SVM on AMD CPUs (patch 0040) and VT-x on the others. */
	l4h_cpu_is_amd = ebx == 0x68747541;	/* "Auth" */
	c->x86_vendor = l4h_cpu_is_amd ? X86_VENDOR_AMD : X86_VENDOR_INTEL;
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
	if (!l4h_bootinfo->nr_ept_roots) {
		pr_info("no VT-x or AMD-V on this host\n");
		return 0;
	}
	enable_pmu = false;
	l4h_kvm_fpu_init();
	l4h_ept_pool_init(l4h_bootinfo->nr_ept_roots);
	return l4h_cpu_is_amd ? l4h_svm_init() : l4h_vmx_init();
}
late_initcall(l4h_kvm_init);

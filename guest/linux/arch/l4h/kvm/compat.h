/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Included first in every file of arch/x86/kvm when it builds for ARCH=l4h.
 *
 * That code expects to run on bare x86: in ring 0, with x86's FPU, APIC and
 * percpu machinery.  The guest kernel runs in ring 3 on seL4 (DESIGN.md
 * §5.10), so what the common code would do with those goes through the
 * backend (kvm/vmx.c) or does not exist.  This header supplies what x86's
 * headers would have, without changing them or the guest's own.
 */
#ifndef __L4H_KVM_COMPAT_H
#define __L4H_KVM_COMPAT_H

/* What every file in arch/x86/kvm defines, after this. */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/types.h>

struct irq_alloc_info;
struct perf_event;

/* MSI messages as x86 lays them out (asm/msi.h), for KVM's routing.  Before
 * any header that includes linux/msi.h: the guest itself has no MSIs. */
typedef struct x86_msi_data {
	u32	vector			:  8,
		delivery_mode		:  3,
		dest_mode_logical	:  1,
		reserved		:  2,
		active_low		:  1,
		is_level		:  1;
} __attribute__((packed)) arch_msi_msg_data_t;
#define arch_msi_msg_data	x86_msi_data

typedef struct x86_msi_addr_lo {
	u32	reserved_0		:  2,
		dest_mode_logical	:  1,
		redirect_hint		:  1,
		reserved_1		:  1,
		virt_destid_8_14	:  7,
		destid_0_7		:  8,
		base_address		: 12;
} __attribute__((packed)) arch_msi_msg_addr_lo_t;
#define arch_msi_msg_addr_lo	x86_msi_addr_lo

typedef struct x86_msi_addr_hi {
	u32	reserved		:  8,
		destid_8_31		: 24;
} __attribute__((packed)) arch_msi_msg_addr_hi_t;
#define arch_msi_msg_addr_hi	x86_msi_addr_hi

#include <linux/bug.h>
#include <linux/bitops.h>
#include <asm/processor-flags.h>
#include <asm/cpufeatures.h>
#include <asm/cpufeature.h>
#include <asm/cpuid/api.h>
#include <asm/msr-index.h>
#include <asm/fpu/api.h>
/* l4h's asm/fpu/api.h has these from x86's types.h. */
#undef MXCSR_DEFAULT
#undef XFEATURE_MASK_FP
#undef XFEATURE_MASK_SSE
#undef XFEATURE_MASK_YMM
#undef XFEATURE_MASK_OPMASK
#undef XFEATURE_MASK_ZMM_Hi256
#undef XFEATURE_MASK_Hi16_ZMM
#undef XFEATURE_MASK_FPSSE
#undef XFEATURE_MASK_AVX512
/* Types only: keep out x86's page and task-size definitions. */
#define _ASM_X86_PAGE_DEFS_H
#define _ASM_X86_PAGE_TYPES_H
#include <asm/fpu/types.h>
#include <asm/nospec-branch.h>
#include "../../x86/include/asm/perf_event.h"
#undef perf_arch_fetch_caller_regs
#include <asm/desc_defs.h>
#include <asm/ptrace.h>
#include <shared/l4h_sys.h>
/* VMCS fields in asm/vmx.h. */
#undef HOST_FS_BASE
#undef HOST_GS_BASE

/* The hyperv headers, which kvm_host.h includes for its structures, are for
 * CONFIG_X86.  Other headers test it too, for layouts of the guest's. */
#define CONFIG_X86 1
#include <hyperv/hvhdk.h>
#undef CONFIG_X86

enum pg_level {
	PG_LEVEL_NONE,
	PG_LEVEL_4K,
	PG_LEVEL_2M,
	PG_LEVEL_1G,
	PG_LEVEL_512G,
	PG_LEVEL_256T,
	PG_LEVEL_NUM
};

#define NMI_VECTOR 2

/* User addresses are above the guest kernel's PAGE_OFFSET here. */
#define KVM_HVA_ERR_BAD		(-1ul)
#define KVM_HVA_ERR_RO_BAD	(-2ul)
static inline bool kvm_is_error_hva(unsigned long addr)
{
	return addr >= KVM_HVA_ERR_RO_BAD;
}

/* From x86's asm/cpufeature.h, which l4h's hides. */
enum cpuid_leafs {
	CPUID_1_EDX = 0,
	CPUID_8000_0001_EDX,
	CPUID_8086_0001_EDX,
	CPUID_LNX_1,
	CPUID_1_ECX,
	CPUID_C000_0001_EDX,
	CPUID_8000_0001_ECX,
	CPUID_LNX_2,
	CPUID_LNX_3,
	CPUID_7_0_EBX,
	CPUID_D_1_EAX,
	CPUID_LNX_4,
	CPUID_7_1_EAX,
	CPUID_8000_0008_EBX,
	CPUID_6_EAX,
	CPUID_8000_000A_EDX,
	CPUID_7_ECX,
	CPUID_8000_0007_EBX,
	CPUID_7_EDX,
	CPUID_8000_001F_EAX,
	CPUID_8000_0021_EAX,
	CPUID_LNX_5,
	NR_CPUID_WORDS,
};

#define _LINUX_USER_RETURN_NOTIFIER_H
struct user_return_notifier {
	void (*on_user_return)(struct user_return_notifier *urn);
};
static inline void user_return_notifier_register(struct user_return_notifier *urn) { }
static inline void user_return_notifier_unregister(struct user_return_notifier *urn) { }

/* From x86's asm/apic.h and asm/desc.h, which l4h's hide. */
#include <asm/apicdef.h>
#define APIC_VECTORS_PER_REG	32
#define MAX_APIC_VECTOR		256
#define APIC_VECTOR_TO_BIT_NUMBER(v) ((unsigned int)(v) % APIC_VECTORS_PER_REG)
#define APIC_VECTOR_TO_REG_OFFSET(v) ((unsigned int)(v) / APIC_VECTORS_PER_REG * 0x10)

static inline unsigned long get_desc_base(const struct desc_struct *desc)
{
	return (unsigned)(desc->base0 | ((desc->base1) << 16) | ((desc->base2) << 24));
}

static inline void set_desc_base(struct desc_struct *desc, unsigned long base)
{
	desc->base0 = base & 0xffff;
	desc->base1 = (base >> 16) & 0xff;
	desc->base2 = (base >> 24) & 0xff;
}

static inline unsigned long get_desc_limit(const struct desc_struct *desc)
{
	return desc->limit0 | (desc->limit1 << 16);
}

static inline void set_desc_limit(struct desc_struct *desc, unsigned long limit)
{
	desc->limit0 = limit & 0xffff;
	desc->limit1 = (limit >> 16) & 0xf;
}

/*
 * Vector states are maintained by APIC in 32-bit registers that are
 * 16 bytes aligned. The status of each vector is kept in a single
 * bit.
 */
static inline int apic_find_highest_vector(void *bitmap)
{
	int vec;
	u32 *reg;

	for (vec = MAX_APIC_VECTOR - APIC_VECTORS_PER_REG; vec >= 0; vec -= APIC_VECTORS_PER_REG) {
		reg = bitmap + APIC_VECTOR_TO_REG_OFFSET(vec);
		if (*reg)
			return __fls(*reg) + vec;
	}

	return -1;
}

static inline u32 apic_get_reg(void *regs, int reg)
{
	return *((u32 *) (regs + reg));
}

static inline void apic_set_reg(void *regs, int reg, u32 val)
{
	*((u32 *) (regs + reg)) = val;
}

static __always_inline u64 apic_get_reg64(void *regs, int reg)
{
	BUILD_BUG_ON(reg != APIC_ICR);
	return *((u64 *) (regs + reg));
}

static __always_inline void apic_set_reg64(void *regs, int reg, u64 val)
{
	BUILD_BUG_ON(reg != APIC_ICR);
	*((u64 *) (regs + reg)) = val;
}

static inline void apic_clear_vector(int vec, void *bitmap)
{
	clear_bit(APIC_VECTOR_TO_BIT_NUMBER(vec), bitmap + APIC_VECTOR_TO_REG_OFFSET(vec));
}

static inline void apic_set_vector(int vec, void *bitmap)
{
	set_bit(APIC_VECTOR_TO_BIT_NUMBER(vec), bitmap + APIC_VECTOR_TO_REG_OFFSET(vec));
}

static inline int apic_test_vector(int vec, void *bitmap)
{
	return test_bit(APIC_VECTOR_TO_BIT_NUMBER(vec), bitmap + APIC_VECTOR_TO_REG_OFFSET(vec));
}

#define cpuinfo_x86 cpuinfo_um
#define cpu_data(cpu) boot_cpu_data
#define INVPCID_TYPE_INDIV_ADDR		0
#define INVPCID_TYPE_SINGLE_CTXT	1
#define INVPCID_TYPE_ALL_INCL_GLOBAL	2
#define INVPCID_TYPE_ALL_NON_GLOBAL	3

#include <linux/profile.h>

#define SEGMENT_RPL_MASK 3

#define X86_VENDOR_INTEL	0
#define X86_VENDOR_AMD		2
#define X86_VENDOR_CENTAUR	5
#define X86_VENDOR_HYGON	9
#define X86_VENDOR_ZHAOXIN	10

/* Not x86's page tables: spte.h and mmu.c do without them. */
#define _ASM_X86_PGTABLE_DEFS_H
#define _ASM_X86_MEMTYPE_H
#define _ASM_X86_SET_MEMORY_H
#define _ASM_X86_SPECCTRL_H_
#define _ASM_E820_API_H
/* No protection keys for guests. */
static inline unsigned long pte_flags(pte_t pte)
{
	return 0;
}
static inline u16 pte_flags_pkey(unsigned long flags)
{
	return 0;
}
#define e820__mapped_any(start, end, type) false
#define E820_TYPE_RAM 1
#define e820__mapped_raw_any(start, end, type) false
#define pat_enabled() false
#define pat_pfn_immune_to_uc_mtrr(pfn) false
static inline int set_memory_encrypted(unsigned long addr, int n)
{
	return 0;
}
static inline int set_memory_decrypted(unsigned long addr, int n)
{
	return 0;
}
static __maybe_unused bool itlb_multihit_kvm_mitigation;

/* No posted interrupts. */
#define NR_PIR_WORDS 4
#define pi_harvest_pir(pir, regs) false

#define fpu_enable_guest_xfd_features(gfpu, xfeatures) 0
#define kvm_async_pf_task_wait_schedule(token) do { } while (0)

/* From x86's asm/text-patching.h, which needs what l4h does not have. */
static __always_inline bool __emulate_cc(unsigned long flags, u8 cc)
{
	static const unsigned long cc_mask[6] = {
		[0] = X86_EFLAGS_OF,
		[1] = X86_EFLAGS_CF,
		[2] = X86_EFLAGS_ZF,
		[3] = X86_EFLAGS_CF | X86_EFLAGS_ZF,
		[4] = X86_EFLAGS_SF,
		[5] = X86_EFLAGS_PF,
	};
	bool invert = cc & 1;
	bool match;

	if (cc < 0xc) {
		match = flags & cc_mask[cc >> 1];
	} else {
		match = ((flags & X86_EFLAGS_SF) >> X86_EFLAGS_SF_BIT) ^
			((flags & X86_EFLAGS_OF) >> X86_EFLAGS_OF_BIT);
		if (cc >= 0xe)
			match = match || (flags & X86_EFLAGS_ZF);
	}

	return (match && !invert) || (!match && invert);
}
#define _ASM_X86_TEXT_PATCHING_H

#include <linux/msi.h>
static inline u32 x86_msi_msg_get_destid(struct msi_msg *msg, bool extid)
{
	u32 dest = msg->arch_addr_lo.destid_0_7;

	if (extid)
		dest |= msg->arch_addr_hi.destid_8_31 << 8;
	return dest;
}

/*
 * Ring 3: no MSRs, XCR0 stays what seL4 set, and no debug registers.  Reading
 * an MSR tells the common code what seL4 uses or nothing at all: all
 * the MSRs that a guest sees are its own, in the backend or in KVM.
 */
#include <asm/msr.h>
#include <asm/debugreg.h>
#include <asm/fpu/xcr.h>

static inline int l4h_kvm_rdmsr(u32 msr, u64 *p)
{
	switch (msr) {
	case MSR_IA32_CR_PAT:
		*p = 0x0007040600070406ull;
		break;
	case MSR_EFER:
		*p = EFER_SCE | EFER_LME | EFER_LMA | EFER_NX;
		break;
	default:
		*p = 0;
	}
	return 0;
}
#undef rdmsr
#undef rdmsr_safe
#define rdmsr(msr, low, high) do { (low) = 0; (high) = 0; } while (0)
#define rdmsr_safe(msr, low, high) ({ *(low) = 0; *(high) = 0; 0; })
#undef rdmsrq
#define rdmsrq(msr, val) l4h_kvm_rdmsr(msr, (u64 *)&(val))
#define rdmsrq_safe(msr, p) l4h_kvm_rdmsr(msr, p)
#define wrmsrq(msr, val) do { } while (0)
static inline int l4h_kvm_wrmsr(u32 msr, u64 val)
{
	return 0;
}
#define wrmsrq_safe(msr, val) l4h_kvm_wrmsr(msr, val)
#define xsetbv(index, value) do { } while (0)
#undef get_debugreg
#undef set_debugreg
#define get_debugreg(var, reg) ((var) = 0)
#define set_debugreg(val, reg) do { (void)(val); } while (0)
#define get_debugctlmsr() 0ul
#define update_debugctlmsr(val) do { (void)(val); } while (0)

#define gds_ucode_mitigated() false
#define check_tsc_unstable() false
#define mark_tsc_unstable(reason) do { } while (0)
#define tsc_khz ((unsigned int)(l4h_tsc_hz / 1000))
#define cpu_khz tsc_khz
#define rdtsc() l4h_rdtsc()
#define rdtsc_ordered() l4h_rdtsc()

/* Timekeeping on the TSC: what x86's clocksource says, in l4h's terms. */
#define VDSO_CLOCKMODE_TSC VDSO_CLOCKMODE_L4H
#define VDSO_CLOCKMODE_HVCLOCK VDSO_CLOCKMODE_MAX

/* Ring 3: WBINVD exits are emulated as nothing, as for a guest without
 * non-coherent DMA. */
#define wbinvd() do { } while (0)
#define wbinvd_on_cpu(cpu) do { } while (0)
#define wbinvd_on_cpus_mask(mask) do { } while (0)

#define xstate_get_guest_group_perm() 0ull
#define fpu_update_guest_xfd(gfpu, xfd) do { } while (0)
#define fpstate_is_confidential(gfpu) false
#define fpu_sync_guest_vmexit_xfd_state() do { } while (0)

/* The software page table changed at sptep (kvm/ept.c). */
struct kvm;
void l4h_kvm_spte_changed(struct kvm *kvm, u64 *sptep, u64 gfn, int level);
void l4h_kvm_vm_free(struct kvm *kvm);
struct kvm_memory_slot;
void l4h_kvm_memslot_prepare(struct kvm *kvm, struct kvm_memory_slot *slot);
/* Declared for CONFIG_GUEST_PERF_EVENTS only, which l4h has not. */
struct kvm_vcpu;
unsigned long kvm_arch_vcpu_get_ip(struct kvm_vcpu *vcpu);

bool fpu_alloc_guest_fpstate(struct fpu_guest *gfpu);
void fpu_free_guest_fpstate(struct fpu_guest *gfpu);
int fpu_swap_kvm_fpstate(struct fpu_guest *gfpu, bool enter_guest);
void fpstate_clear_xstate_component(struct fpstate *fpstate, unsigned int nr);
void fpu_copy_guest_fpstate_to_uabi(struct fpu_guest *gfpu, void *buf, unsigned int size,
				    u64 xfeatures, u32 pkru);
int fpu_copy_uabi_to_guest_fpstate(struct fpu_guest *gfpu, const void *buf, u64 xcr0, u32 *vpkru);

/* Hardware cmpxchg on user memory, for the emulator (kvm/mem.c). */
int l4h_kvm_cmpxchg_user(void __user *ptr, void *old, const void *new, unsigned int size);
#define __try_cmpxchg_user(ptr, oldp, nval, label) ({			\
	__typeof__(nval) __new = (nval);				\
	l4h_kvm_cmpxchg_user(ptr, oldp, &__new, sizeof(__new));		\
})
#define default_cpu_present_to_apicid(cpu) (cpu)

/* The guest's FPU registers (kvm/fpu.c). */
#define TIF_NEED_FPU_LOAD 31
void l4h_kvm_fpu_lock(void);
void l4h_kvm_fpu_unlock(void);
#define fpregs_lock() l4h_kvm_fpu_lock()
#define fpregs_unlock() l4h_kvm_fpu_unlock()
#define fpregs_assert_state_consistent() do { } while (0)
#define switch_fpu_return() do { } while (0)

static inline u32 rdpkru(void) { return 0; }
static inline void wrpkru(u32 pkru) { }

static __always_inline u64 __canonical_address(u64 vaddr, u8 vaddr_bits)
{
	return ((s64)vaddr << (64 - vaddr_bits)) >> (64 - vaddr_bits);
}

static __always_inline u64 __is_canonical_address(u64 vaddr, u8 vaddr_bits)
{
	return __canonical_address(vaddr, vaddr_bits) == vaddr;
}
#endif

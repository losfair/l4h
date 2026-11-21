/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Included first in every file of arch/arm64/kvm (and arch/l4h/kvm/arm64)
 * when it builds for ARCH=l4h, SUBARCH=aarch64.
 *
 * That code expects to run at EL2 (VHE) or EL1 with arm64's own kernel
 * headers.  The guest kernel runs at EL0 of FL4, which runs the VCPUs at
 * EL2 (DESIGN.md §5.10): what the common code would do on hardware goes
 * through the backend (arch/l4h/kvm/arm64) or does not exist.  This header
 * and the ones in include/ (searched first) supply what arm64's headers
 * would have, without changing them or the guest kernel's own.
 */
#ifndef __L4H_KVM_ARM64_COMPAT_H
#define __L4H_KVM_ARM64_COMPAT_H

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

/* arm64 Kconfig values the shared headers use; the guest kernel's are l4h's. */
#define CONFIG_ARM64_PA_BITS		48
#define CONFIG_ARM64_VA_BITS		48
#define CONFIG_ARM64_CONT_PTE_SHIFT	4
#define CONFIG_ARM64_CONT_PMD_SHIFT	4
#define CONFIG_ARM64_4K_PAGES		1

#include <linux/types.h>

/* EL0 barriers, which l4h's asm/barrier.h leaves to the generic code. */
#define isb()		asm volatile("isb" : : : "memory")
#define dmb(opt)	asm volatile("dmb " #opt : : : "memory")
#define dsb(opt)	asm volatile("dsb " #opt : : : "memory")
#define __nops(n)	".rept	" #n "\nnop\n.endr\n"
#define nops(n)		asm volatile(__nops(n))

/* From arm64's asm/ptrace.h, which l4h's replaces. */
#define CurrentEL_EL1		(1 << 2)
#define CurrentEL_EL2		(2 << 2)

#define INIT_PSTATE_EL1 \
	(PSR_D_BIT | PSR_A_BIT | PSR_I_BIT | PSR_F_BIT | PSR_MODE_EL1h)
#define INIT_PSTATE_EL2 \
	(PSR_D_BIT | PSR_A_BIT | PSR_I_BIT | PSR_F_BIT | PSR_MODE_EL2h)




/* Additional SPSR bits not exposed in the UABI */
#define PSR_MODE_THREAD_BIT	(1 << 0)
#define PSR_IL_BIT		(1 << 20)

/* AArch32-specific ptrace requests */
#define COMPAT_PTRACE_GETREGS		12
#define COMPAT_PTRACE_SETREGS		13
#define COMPAT_PTRACE_GET_THREAD_AREA	22
#define COMPAT_PTRACE_SET_SYSCALL	23
#define COMPAT_PTRACE_GETVFPREGS	27
#define COMPAT_PTRACE_SETVFPREGS	28
#define COMPAT_PTRACE_GETHBPREGS	29
#define COMPAT_PTRACE_SETHBPREGS	30

/* SPSR_ELx bits for exceptions taken from AArch32 */
#define PSR_AA32_MODE_MASK	0x0000001f
#define PSR_AA32_MODE_USR	0x00000010
#define PSR_AA32_MODE_FIQ	0x00000011
#define PSR_AA32_MODE_IRQ	0x00000012
#define PSR_AA32_MODE_SVC	0x00000013
#define PSR_AA32_MODE_ABT	0x00000017
#define PSR_AA32_MODE_HYP	0x0000001a
#define PSR_AA32_MODE_UND	0x0000001b
#define PSR_AA32_MODE_SYS	0x0000001f
#define PSR_AA32_T_BIT		0x00000020
#define PSR_AA32_F_BIT		0x00000040
#define PSR_AA32_I_BIT		0x00000080
#define PSR_AA32_A_BIT		0x00000100
#define PSR_AA32_E_BIT		0x00000200
#define PSR_AA32_PAN_BIT	0x00400000
#define PSR_AA32_SSBS_BIT	0x00800000
#define PSR_AA32_DIT_BIT	0x01000000
#define PSR_AA32_Q_BIT		0x08000000
#define PSR_AA32_V_BIT		0x10000000
#define PSR_AA32_C_BIT		0x20000000
#define PSR_AA32_Z_BIT		0x40000000
#define PSR_AA32_N_BIT		0x80000000
#define PSR_AA32_IT_MASK	0x0600fc00	/* If-Then execution state mask */
#define PSR_AA32_GE_MASK	0x000f0000

#ifdef CONFIG_CPU_BIG_ENDIAN
#define PSR_AA32_ENDSTATE	PSR_AA32_E_BIT
#else
#define PSR_AA32_ENDSTATE	0
#endif

/* AArch32 CPSR bits, as seen in AArch32 */
#define COMPAT_PSR_DIT_BIT	0x00200000

#include <asm/pgtable-hwdef.h>

#define GIC_PRIO_IRQON		0xe0
#define GIC_PRIO_IRQOFF		0x60
#define GIC_PRIO_PSR_I_SET	(1 << 4)

#ifndef __ASSEMBLY__
#include <linux/bits.h>
#include <linux/bitfield.h>
struct alt_instr;
#include <asm/spectre.h>
#include <asm/stacktrace/frame.h>

/* arm64's struct user_pt_regs names for an AArch32 guest's registers. */
#define compat_usr(x)	regs[(x)]
#define compat_fp	regs[11]
#define compat_sp	regs[13]
#define compat_lr	regs[14]
#define compat_sp_hyp	regs[15]
#define compat_lr_irq	regs[16]
#define compat_sp_irq	regs[17]
#define compat_lr_svc	regs[18]
#define compat_sp_svc	regs[19]
#define compat_lr_abt	regs[20]
#define compat_sp_abt	regs[21]
#define compat_lr_und	regs[22]
#define compat_sp_und	regs[23]
#define compat_r8_fiq	regs[24]
#define compat_r9_fiq	regs[25]
#define compat_r10_fiq	regs[26]
#define compat_r11_fiq	regs[27]
#define compat_r12_fiq	regs[28]
#define compat_sp_fiq	regs[29]
#define compat_lr_fiq	regs[30]

/* User addresses are above the guest kernel's PAGE_OFFSET here. */
#define KVM_HVA_ERR_BAD		(-1ul)
#define KVM_HVA_ERR_RO_BAD	(-2ul)
static inline bool kvm_is_error_hva(unsigned long addr)
{
	return addr >= KVM_HVA_ERR_RO_BAD;
}

/* asm/debug-monitors.h */
#define DBG_SPSR_SS	(1 << 21)

/* asm/cache.h */
#define CLIDR_LOUU_SHIFT	27
#define CLIDR_LOC_SHIFT		24
#define CLIDR_LOUIS_SHIFT	21
#define CLIDR_LOUU(clidr)	(((clidr) >> CLIDR_LOUU_SHIFT) & 0x7)
#define CLIDR_LOC(clidr)	(((clidr) >> CLIDR_LOC_SHIFT) & 0x7)
#define CLIDR_LOUIS(clidr)	(((clidr) >> CLIDR_LOUIS_SHIFT) & 0x7)
#define CLIDR_CTYPE_SHIFT(level)	(3 * (level - 1))
#define CLIDR_CTYPE_MASK(level)		(7 << CLIDR_CTYPE_SHIFT(level))
#define CLIDR_CTYPE(clidr, level)	\
	(((clidr) & CLIDR_CTYPE_MASK(level)) >> CLIDR_CTYPE_SHIFT(level))
#define CLIDR_TTYPE_SHIFT(level)	(2 * ((level) - 1) + CLIDR_EL1_Ttypen_SHIFT)

/*
 * Cache maintenance.  The host keeps a VM's Stage-2 mappings coherent
 * (FL4 cleans what it maps non-cacheable; the provider unifies the
 * instruction cache of executable mappings): KVM's own maintenance of
 * the pages it maps has nothing to do (arch/l4h/kvm/arm64/init.c).
 */
void dcache_clean_inval_poc(unsigned long start, unsigned long end);
void dcache_clean_poc(unsigned long start, unsigned long end);
void icache_inval_pou(unsigned long start, unsigned long end);
void icache_inval_all_pou(void);
static inline int icache_is_aliasing(void) { return 0; }

/* asm/tlbflush.h: TLB maintenance is FL4's (a Stage-2 unmap invalidates). */
#define MAX_DVM_OPS		PTRS_PER_PTE
#define TLBI_TTL_UNKNOWN	INT_MAX
#define TLBIR_ASID_MASK		GENMASK_ULL(63, 48)
#define TLBIR_TG_MASK		GENMASK_ULL(47, 46)
#define TLBIR_SCALE_MASK	GENMASK_ULL(45, 44)
#define TLBIR_NUM_MASK		GENMASK_ULL(43, 39)
#define TLBIR_TTL_MASK		GENMASK_ULL(38, 37)
#define TLBIR_BADDR_MASK	GENMASK_ULL(36,  0)
#define __TLBI_RANGE_PAGES(num, scale)	\
	((unsigned long)((num) + 1) << (5 * (scale) + 1))
#define MAX_TLBI_RANGE_PAGES		__TLBI_RANGE_PAGES(31, 3)
#define TLBI_TTL_MASK		GENMASK_ULL(47, 44)
#define TLBI_TTL_TG_4K		1
#define TLBI_TTL_TG_16K		2
#define TLBI_TTL_TG_64K		3
#define __TLBI_VADDR(addr, asid)	((((addr) >> 12) & GENMASK_ULL(43, 0)) | ((unsigned long)(asid) << 48))
#define __tlbi_level(op, addr, level)	do { } while (0)
#define __tlbi(op, ...)			do { } while (0)
#define __tlbi_sync_s1ish_hyp()		do { } while (0)

/* asm/pgtable.h, asm/pgtable-prot.h */
typedef u64 pteval_t;
#define phys_to_ttbr(addr)	(addr)
#define PAGE_S2_MEMATTR(attr, has_fwb)					\
	({								\
		u64 __val;						\
		if (has_fwb)						\
			__val = PTE_S2_MEMATTR(MT_S2_FWB_ ## attr);	\
		else							\
			__val = PTE_S2_MEMATTR(MT_S2_ ## attr);		\
		__val;							\
	 })

/* No MTE for guests (asm/mte.h). */
#define MTE_GRANULES_PER_PAGE	(PAGE_SIZE / 16)
static inline bool page_mte_tagged(struct page *page) { return false; }
static inline void set_page_mte_tagged(struct page *page) { }
static inline bool try_page_mte_tagging(struct page *page) { return false; }
static inline void mte_clear_page_tags(void *addr) { }
static inline unsigned long mte_copy_tags_from_user(void *to, const void __user *from, unsigned long n) { return n; }
static inline unsigned long mte_copy_tags_to_user(void __user *to, void *from, unsigned long n) { return n; }

#define folio_test_hugetlb_mte_tagged(f)	false
#define folio_set_hugetlb_mte_tagged(f)	do { } while (0)
#define folio_try_hugetlb_mte_tagging(f)	({ (void)(f); false; })

/* No hardware breakpoints for guests: ID_AA64DFR0_EL1 says what the host has. */
int get_num_brps(void);
int get_num_wrps(void);

static inline bool lpa2_is_enabled(void) { return false; }
static inline unsigned long kaslr_offset(void) { return 0; }
/* Every pfn KVM maps is the guest kernel's RAM or a device frame. */
bool pfn_is_map_memory(unsigned long pfn);

/* arm64's nVHE hyp layout: never set up here (no hyp code), but named by
 * mmu.c's hyp mappings (arch/l4h/kvm/arm64/init.c has the symbols). */
#define IDMAP_VA_BITS		48
#define NVHE_STACK_SHIFT	PAGE_SHIFT
#define NVHE_STACK_SIZE		(UL(1) << NVHE_STACK_SHIFT)
#define OVERFLOW_STACK_SIZE	SZ_4K
extern char __hyp_idmap_text_start[], __hyp_idmap_text_end[];
#define __phys_to_kimg(x)	((unsigned long)(x))

/* The arch timer: the guest kernel's clock is the virtual counter, which
 * EL0 reads; KVM's timer interrupt is FL4's VPPI event (timer.c). */
#include <clocksource/arm_arch_timer.h>
#define arch_counter_enforce_ordering(val)	do { (void)(val); } while (0)
struct arch_timer_kvm_info *arch_timer_get_kvm_info(void);

/* The backend's hooks in arm.c (arch/l4h/kvm/arm64/vcpu.c). */
struct kvm_vcpu;
int l4h_arm_vcpu_create(struct kvm_vcpu *vcpu);
void l4h_arm_vcpu_destroy(struct kvm_vcpu *vcpu);
void l4h_arm_vcpu_load(struct kvm_vcpu *vcpu);
void l4h_arm_vcpu_put(struct kvm_vcpu *vcpu);
/* vcpu->arch.ctxt.fp_regs made current before KVM reads it (write: and
 * modifies it), or reset (it went into FL4 lazily, vcpu.c). */
void l4h_arm_vcpu_sync_fp(struct kvm_vcpu *vcpu, bool write);
void l4h_arm_vcpu_reset_fp(struct kvm_vcpu *vcpu);
/* GICv3's VMCR and active priorities, which FL4 keeps (vgic.c). */
void l4h_vgic_v3_pull_vmcr(struct kvm_vcpu *vcpu);
void l4h_vgic_v3_set_vmcr(struct kvm_vcpu *vcpu, u32 vmcr);
void l4h_vgic_v3_set_apr(struct kvm_vcpu *vcpu, u8 apr, u8 idx, u32 val);
void l4h_kvm_timer_sync(struct kvm_vcpu *vcpu, bool *level);

/* MPIDR of a guest kernel vCPU: its number (arch/l4h/kvm/arm64/init.c). */
u64 cpu_logical_map(unsigned int cpu);
#endif /* __ASSEMBLY__ */

#ifndef __ASSEMBLY__
#include <asm/brk-imm.h>
#include <asm/kvm_arm.h>
#endif

#endif

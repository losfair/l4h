// SPDX-License-Identifier: GPL-2.0
/*
 * What arm64's kernel proper gives arch/arm64/kvm: the CPU's capabilities
 * and sanitised ID registers, system register access, and the symbols of
 * the hyp code that is not built here.
 *
 * The guest kernel runs at EL0 of FL4, which runs at EL2 (VHE) where the
 * hardware has it: KVM here is a VHE host whose world switch is FL4's
 * (vcpu.c), with the CPU's ID registers from bootinfo (cpu_id, arm_virt).
 * KVM keeps a VM's registers in memory, never in the CPU, so the system
 * registers it would touch on a VHE host are those of the loaded vCPU as
 * FL4 holds them (vcpu.c, vgic.c), and the counter, which EL0 reads.
 */
#undef pr_fmt
#define pr_fmt(fmt) "l4h-kvm: " fmt

#include <linux/kvm_host.h>
#include <linux/init.h>
#include <linux/irqchip/arm-vgic-info.h>
#include <linux/clocksource.h>
#include <clocksource/arm_arch_timer.h>
#include <asm/kvm_mmu.h>
#include <asm/virt.h>
#include <asm/cputype.h>
#include <asm/esr.h>
#include <asm/traps.h>
#include <asm/stacktrace/nvhe.h>
#include <l4h_sys.h>
#include "l4h_kvm_arm64.h"

DECLARE_BITMAP(l4h_kvm_cpucaps, ARM64_NCAPS);
u32 __boot_cpu_mode[2] = { BOOT_CPU_MODE_EL1, BOOT_CPU_MODE_EL1 };
DEFINE_STATIC_KEY_FALSE(kvm_protected_mode_initialized);
DEFINE_STATIC_KEY_FALSE(arm64_mismatched_32bit_el0);
DEFINE_PER_CPU(struct kvm_host_data, kvm_host_data);
unsigned int l4h_kvm_ipa_bits;

/* Hyp symbols that the code built here names but never uses on VHE. */
DEFINE_PER_CPU(struct kvm_host_data, kvm_nvhe_sym(kvm_host_data));
unsigned long kvm_nvhe_sym(kvm_arm_hyp_percpu_base)[NR_CPUS];
unsigned int kvm_nvhe_sym(hyp_gicv3_nr_lr);
char kvm_nvhe_sym(__per_cpu_start)[0];
char kvm_nvhe_sym(__kvm_hyp_init)[0];
char __hyp_idmap_text_start[0], __hyp_idmap_text_end[0];

/* FL4 at EL2 that hands out Stage-2 roots: /dev/kvm. */
bool l4h_kvm_available(void)
{
	return (l4h_bootinfo->arm_virt.flags & L4H_ARM_VIRT_READY) && l4h_bootinfo->nr_ept_roots &&
	       (l4h_bootinfo->arm_virt.gic_version == 3 ||
		(l4h_bootinfo->arm_virt.gic_version == 2 && l4h_bootinfo->arm_virt.gicv_size));
}

/*
 * The ID registers guests may see, from bootinfo, without what FL4 does not
 * switch for them: SVE, SME, MTE, pointer authentication, AArch32, AMU,
 * MPAM, RAS, the PMU, and the EL1 registers of FEAT_TCR2/S1PIE/S1POE/
 * SCTLR2.  KVM further narrows them to what it offers (sys_regs.c).
 */
static u64 l4h_parange(u64 ipa_bits)
{
	switch (ipa_bits) {
	case 48:
		return ID_AA64MMFR0_EL1_PARANGE_48;
	case 44:
		return ID_AA64MMFR0_EL1_PARANGE_44;
	case 42:
		return ID_AA64MMFR0_EL1_PARANGE_42;
	default:
		return ID_AA64MMFR0_EL1_PARANGE_40;
	}
}

u64 l4h_kvm_id_reg(u32 enc)
{
	const struct l4h_bootinfo *bi = l4h_bootinfo;
	const struct l4h_arm_virt_info *av = &bi->arm_virt;
	u64 v;

	switch (enc) {
	case SYS_ID_AA64PFR0_EL1:
		v = bi->cpu_id[3];
		v &= ~(ID_AA64PFR0_EL1_EL0_MASK | ID_AA64PFR0_EL1_EL1_MASK |
		       ID_AA64PFR0_EL1_EL2_MASK | ID_AA64PFR0_EL1_EL3_MASK |
		       ID_AA64PFR0_EL1_SVE_MASK | ID_AA64PFR0_EL1_RAS_MASK |
		       ID_AA64PFR0_EL1_AMU_MASK | ID_AA64PFR0_EL1_MPAM_MASK |
		       ID_AA64PFR0_EL1_SEL2_MASK | ID_AA64PFR0_EL1_RME_MASK);
		v |= FIELD_PREP(ID_AA64PFR0_EL1_EL0_MASK, ID_AA64PFR0_EL1_EL0_IMP) |
		     FIELD_PREP(ID_AA64PFR0_EL1_EL1_MASK, ID_AA64PFR0_EL1_EL1_IMP) |
		     FIELD_PREP(ID_AA64PFR0_EL1_EL2_MASK, ID_AA64PFR0_EL1_EL2_IMP);
		return v;
	case SYS_ID_AA64PFR1_EL1:
		v = bi->cpu_id[4];
		v &= ~(ID_AA64PFR1_EL1_SME_MASK | ID_AA64PFR1_EL1_MTE_MASK |
		       ID_AA64PFR1_EL1_RAS_frac_MASK | ID_AA64PFR1_EL1_MPAM_frac_MASK |
		       ID_AA64PFR1_EL1_NMI_MASK | ID_AA64PFR1_EL1_GCS_MASK |
		       ID_AA64PFR1_EL1_THE_MASK | ID_AA64PFR1_EL1_MTE_frac_MASK |
		       ID_AA64PFR1_EL1_MTEX_MASK | ID_AA64PFR1_EL1_DF2_MASK |
		       ID_AA64PFR1_EL1_PFAR_MASK);
		return v;
	case SYS_ID_AA64ISAR0_EL1:
		return bi->cpu_id[0];
	case SYS_ID_AA64ISAR1_EL1:
		return bi->cpu_id[1] & ~(ID_AA64ISAR1_EL1_APA_MASK | ID_AA64ISAR1_EL1_API_MASK |
					 ID_AA64ISAR1_EL1_GPA_MASK | ID_AA64ISAR1_EL1_GPI_MASK |
					 ID_AA64ISAR1_EL1_LS64_MASK);
	case SYS_ID_AA64ISAR2_EL1:
		/* MOPS needs HCRX_EL2.MSCEn, which FL4 does not set. */
		return bi->cpu_id[2] & ~(ID_AA64ISAR2_EL1_APA3_MASK | ID_AA64ISAR2_EL1_GPA3_MASK |
					 ID_AA64ISAR2_EL1_SYSREG_128_MASK | ID_AA64ISAR2_EL1_MOPS_MASK);
	case SYS_ID_AA64MMFR0_EL1:
		/* No IPA beyond what FL4's Stage-2 roots map; no fine-grained
		 * traps or CNTPOFF, which FL4 does not switch. */
		v = av->id_aa64mmfr0 & ~(ID_AA64MMFR0_EL1_FGT_MASK | ID_AA64MMFR0_EL1_ECV_MASK);
		if (SYS_FIELD_GET(ID_AA64MMFR0_EL1, PARANGE, v) > l4h_parange(av->ipa_bits)) {
			v &= ~ID_AA64MMFR0_EL1_PARANGE_MASK;
			v |= FIELD_PREP(ID_AA64MMFR0_EL1_PARANGE_MASK, l4h_parange(av->ipa_bits));
		}
		return v;
	case SYS_ID_AA64MMFR1_EL1:
		return av->id_aa64mmfr1 & ~(ID_AA64MMFR1_EL1_VH_MASK | ID_AA64MMFR1_EL1_TWED_MASK);
	case SYS_ID_AA64MMFR2_EL1:
		/* FL4 clears HCR_EL2.FWB. */
		return av->id_aa64mmfr2 & ~(ID_AA64MMFR2_EL1_NV_MASK | ID_AA64MMFR2_EL1_EVT_MASK |
					    ID_AA64MMFR2_EL1_FWB_MASK);
	case SYS_ID_AA64DFR0_EL1:
		v = av->id_aa64dfr0;
		v &= ~(ID_AA64DFR0_EL1_PMUVer_MASK | ID_AA64DFR0_EL1_PMSVer_MASK |
		       ID_AA64DFR0_EL1_TraceVer_MASK | ID_AA64DFR0_EL1_TraceFilt_MASK |
		       ID_AA64DFR0_EL1_TraceBuffer_MASK | ID_AA64DFR0_EL1_BRBE_MASK |
		       ID_AA64DFR0_EL1_MTPMU_MASK | ID_AA64DFR0_EL1_DoubleLock_MASK);
		return v;
	case SYS_CTR_EL0:
		return av->ctr_el0;
	case SYS_MIDR_EL1:
		return av->midr_el1;
	default:
		return 0;
	}
}

u64 read_sanitised_ftr_reg(u32 id)
{
	return l4h_kvm_id_reg(id);
}

/* No field may differ from what reset gave: there is no host feature
 * table here (arch/arm64/kernel/cpufeature.c) to say which ones may. */
static const struct arm64_ftr_bits l4h_no_ftr_bits[] = {
	{ .width = 0 },
};
static struct arm64_ftr_reg l4h_ftr_reg = {
	.name = "l4h",
	.ftr_bits = l4h_no_ftr_bits,
};

struct arm64_ftr_reg *get_arm64_ftr_reg(u32 sys_id)
{
	return &l4h_ftr_reg;
}

s64 arm64_ftr_safe_value(const struct arm64_ftr_bits *ftrp, s64 new, s64 cur)
{
	return cur;
}

bool this_cpu_has_cap(unsigned int cap)
{
	return cap < ARM64_NCAPS && test_bit(cap, l4h_kvm_cpucaps);
}

/* No errata list here: the host (FL4) works around what it must. */
bool is_midr_in_range_list(struct midr_range const *ranges)
{
	return false;
}

/* The host's mitigations are FL4's; to KVM the CPU is unaffected. */
enum mitigation_state arm64_get_meltdown_state(void)
{
	return SPECTRE_UNAFFECTED;
}

enum mitigation_state arm64_get_spectre_v2_state(void)
{
	return SPECTRE_UNAFFECTED;
}

enum mitigation_state arm64_get_spectre_v4_state(void)
{
	return SPECTRE_UNAFFECTED;
}

enum mitigation_state arm64_get_spectre_bhb_state(void)
{
	return SPECTRE_UNAFFECTED;
}

bool arm64_is_fatal_ras_serror(struct pt_regs *regs, unsigned long esr)
{
	return true;
}

const char *esr_get_class_string(unsigned long esr)
{
	return "ESR";
}

void dump_kernel_instr(unsigned long kaddr)
{
}

void kvm_nvhe_dump_backtrace(unsigned long hyp_offset)
{
}

int get_num_brps(void)
{
	return SYS_FIELD_GET(ID_AA64DFR0_EL1, BRPs, l4h_bootinfo->arm_virt.id_aa64dfr0) + 1;
}

int get_num_wrps(void)
{
	return SYS_FIELD_GET(ID_AA64DFR0_EL1, WRPs, l4h_bootinfo->arm_virt.id_aa64dfr0) + 1;
}

u64 cpu_logical_map(unsigned int cpu)
{
	return cpu;
}

/* Guest RAM is the guest kernel's; device frames are only GICV's. */
bool pfn_is_map_memory(unsigned long pfn)
{
	return pfn_valid(pfn);
}

/*
 * FL4 keeps a VM's Stage-2 mappings coherent: it cleans what it maps
 * non-cacheable, and the provider makes executable mappings coherent
 * (seL4_ARM_Page_Unify_Instruction).  KVM's maintenance of the pages
 * it maps has nothing left to do.
 */
void dcache_clean_inval_poc(unsigned long start, unsigned long end)
{
}

void dcache_clean_poc(unsigned long start, unsigned long end)
{
}

void icache_inval_pou(unsigned long start, unsigned long end)
{
}

void icache_inval_all_pou(void)
{
}

/* ---- the arch timer's counter */

static u64 l4h_cntvct_read(struct cyclecounter *cc)
{
	u64 v;

	asm volatile("isb; mrs %0, cntvct_el0" : "=r"(v));
	return v;
}

static struct arch_timer_kvm_info l4h_timer_info = {
	.virtual_irq = 27,
	.physical_irq = 30,
};
static struct cyclecounter l4h_cyclecounter = {
	.read = l4h_cntvct_read,
	.mask = CLOCKSOURCE_MASK(56),
};

struct arch_timer_kvm_info *arch_timer_get_kvm_info(void)
{
	return &l4h_timer_info;
}

/* ---- system registers */

static u64 l4h_cntfrq(void)
{
	u64 v;

	asm volatile("mrs %0, cntfrq_el0" : "=r"(v));
	return v;
}

u64 l4h_kvm_read_sysreg(u32 enc)
{
	u64 val = 0;

	if (l4h_sysreg_vcpu(enc, &val, false) || l4h_sysreg_vgic(enc, &val, false))
		return val;
	switch (enc) {
	case SYS_CNTVCT_EL0:
	case SYS_CNTPCT_EL0:
		return l4h_cntvct_read(NULL);
	case SYS_CNTFRQ_EL0:
		return l4h_cntfrq();
	case SYS_MPIDR_EL1:
		return 0x80000000ull | raw_smp_processor_id();
	case SYS_CLIDR_EL1:
		/* One unified cache level: what guests are told unless the
		 * VMM sets its own (sys_regs.c reset_clidr()). */
		return 0x4ull << CLIDR_EL1_Ttypen_SHIFT | 0x1ull << CLIDR_LOC_SHIFT | 0x4;
	case SYS_CCSIDR_EL1:
		return 0;
	case SYS_ICC_SRE_EL1:
		return BIT(0);	/* ICC_SRE_EL1.SRE */
	}
	if (sys_reg_Op0(enc) == 3 && sys_reg_Op1(enc) == 0 && sys_reg_CRn(enc) == 0)
		return l4h_kvm_id_reg(enc);
	return 0;
}

void l4h_kvm_write_sysreg(u32 enc, u64 val)
{
	if (l4h_sysreg_vcpu(enc, &val, true) || l4h_sysreg_vgic(enc, &val, true))
		return;
	/* Host controls (CNTHCTL_EL2, CPTR_EL2, MDCR_EL2, ...) are FL4's. */
}

/* read_sysreg()/write_sysreg() by name: what KVM reads directly. */
u64 l4h_kvm_read_sysreg_name(const char *name)
{
	if (!strcmp(name, "CurrentEL"))
		return CurrentEL_EL2;
	if (!strcmp(name, "cntvct_el0") || !strcmp(name, "cntpct_el0"))
		return l4h_cntvct_read(NULL);
	if (!strcmp(name, "cntfrq_el0"))
		return l4h_cntfrq();
	if (!strcmp(name, "ctr_el0"))
		return l4h_bootinfo->arm_virt.ctr_el0;
	if (!strcmp(name, "midr_el1"))
		return l4h_bootinfo->arm_virt.midr_el1;
	if (!strcmp(name, "mpidr_el1"))
		return 0x80000000ull | raw_smp_processor_id();
	if (!strcmp(name, "cntvoff_el2"))
		return l4h_kvm_read_sysreg(SYS_CNTVOFF_EL2);
	if (!strcmp(name, "cntkctl_el1"))
		return 0;
	return 0;
}

void l4h_kvm_write_sysreg_name(const char *name, u64 val)
{
	if (!strcmp(name, "cntvoff_el2"))
		l4h_kvm_write_sysreg(SYS_CNTVOFF_EL2, val);
}

/* ---- setup */

static void l4h_set_caps(void)
{
	u64 ctr = l4h_bootinfo->arm_virt.ctr_el0;
	u64 pfr0 = l4h_bootinfo->cpu_id[3];

	__set_bit(ARM64_ALWAYS_BOOT, l4h_kvm_cpucaps);
	__set_bit(ARM64_ALWAYS_SYSTEM, l4h_kvm_cpucaps);
	__set_bit(ARM64_HAS_VIRT_HOST_EXTN, l4h_kvm_cpucaps);
	if (SYS_FIELD_GET(ID_AA64PFR0_EL1, FP, pfr0) != 0xf)
		__set_bit(ARM64_HAS_FPSIMD, l4h_kvm_cpucaps);
	if (l4h_bootinfo->arm_virt.gic_version == 3)
		__set_bit(ARM64_HAS_GICV3_CPUIF, l4h_kvm_cpucaps);
	if (ctr & BIT(CTR_EL0_DIC_SHIFT))
		__set_bit(ARM64_HAS_CACHE_DIC, l4h_kvm_cpucaps);
	if (ctr & BIT(CTR_EL0_IDC_SHIFT))
		__set_bit(ARM64_HAS_CACHE_IDC, l4h_kvm_cpucaps);
}

static int __init l4h_kvm_arm64_setup(void)
{
	l4h_set_caps();
	l4h_cyclecounter.mult = clocksource_hz2mult(l4h_cntfrq(), 24);
	l4h_cyclecounter.shift = 24;
	timecounter_init(&l4h_timer_info.timecounter, &l4h_cyclecounter, 0);
	if (!l4h_kvm_available())
		return 0;
	l4h_kvm_ipa_bits = l4h_bootinfo->arm_virt.ipa_bits;
	__boot_cpu_mode[0] = __boot_cpu_mode[1] = BOOT_CPU_MODE_EL2;
	l4h_s2_pool_init(l4h_bootinfo->nr_ept_roots);
	l4h_vgic_init();
	pr_info("FL4 EL2 VCPUs, GICv%llu, %u-bit IPA, %llu Stage-2 roots\n",
		l4h_bootinfo->arm_virt.gic_version, l4h_kvm_ipa_bits, l4h_bootinfo->nr_ept_roots);
	return 0;
}
/* Before KVM's module_init(kvm_arm_init). */
core_initcall(l4h_kvm_arm64_setup);

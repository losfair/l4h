/* SPDX-License-Identifier: GPL-2.0 */
/*
 * What arch/arm64/kvm needs of asm/fpsimd.h in the l4h guest kernel: a
 * guest's FP/SIMD registers live in its TCB (l4h_fpu_read/write); no SVE
 * or SME is offered to guests.
 */
#ifndef __ASM_FP_H
#define __ASM_FP_H
#include <linux/types.h>
#include <linux/bug.h>
#include <linux/bitmap.h>
#include <asm/ptrace.h>
#include <asm/sysreg.h>

#define VFP_FPSCR_STAT_MASK	0xf800009f
#define VFP_FPSCR_CTRL_MASK	0x07f79f00
#define ARCH_SVE_VQ_MAX		((ZCR_ELx_LEN_MASK >> ZCR_ELx_LEN_SHIFT) + 1)
#define SME_VQ_MAX		((SMCR_ELx_LEN_MASK >> SMCR_ELx_LEN_SHIFT) + 1)
#define VL_ARCH_MAX		0x100

enum vec_type {
	ARM64_VEC_SVE = 0,
	ARM64_VEC_SME,
	ARM64_VEC_MAX,
};

enum fp_type {
	FP_STATE_CURRENT,
	FP_STATE_FPSIMD,
	FP_STATE_SVE,
};

struct cpu_fp_state {
	struct user_fpsimd_state *st;
	void *sve_state;
	void *sme_state;
	u64 *svcr;
	u64 *fpmr;
	unsigned int sve_vl;
	unsigned int sme_vl;
	enum fp_type *fp_type;
	enum fp_type to_save;
};

static inline size_t sve_ffr_offset(int vl)
{
	return SVE_SIG_FFR_OFFSET(sve_vq_from_vl(vl)) - SVE_SIG_REGS_OFFSET;
}

static inline int sve_max_vl(void) { return 0; }
static inline int sve_max_virtualisable_vl(void) { return 0; }
static inline bool sve_vq_available(unsigned int vq) { return false; }
static inline void fpsimd_save_and_flush_cpu_state(void) { }
static inline void fpsimd_bind_state_to_cpu(struct cpu_fp_state *fp_state) { }
static inline void sve_cond_update_zcr_vq(u64 val, u32 reg) { }
#endif

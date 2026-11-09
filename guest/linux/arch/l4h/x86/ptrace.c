// SPDX-License-Identifier: GPL-2.0

#include <linux/kemu.h>
#include <linux/sched.h>
#include <l4h_uctx.h>
#include <linux/elf.h>
#include <linux/regset.h>
#include <asm/user32.h>
#include <asm/sigcontext.h>
#include <asm/fpu/api.h>

static int genregs_get(struct task_struct *target,
		       const struct user_regset *regset,
		       struct membuf to)
{
	int reg;

	l4h_sync_regs(target);
	l4h_sync_seg(target);
	for (reg = 0; to.left; reg++)
		membuf_store(&to, getreg(target, reg * sizeof(unsigned long)));
	return 0;
}

static int genregs_set(struct task_struct *target,
		       const struct user_regset *regset,
		       unsigned int pos, unsigned int count,
		       const void *kbuf, const void __user *ubuf)
{
	int ret = 0;

	l4h_sync_regs(target);
	l4h_sync_seg(target);
	l4h_seg_dirty(target);
	if (kbuf) {
		const unsigned long *k = kbuf;

		while (count >= sizeof(*k) && !ret) {
			ret = putreg(target, pos, *k++);
			count -= sizeof(*k);
			pos += sizeof(*k);
		}
	} else {
		const unsigned long  __user *u = ubuf;

		while (count >= sizeof(*u) && !ret) {
			unsigned long word;

			ret = __get_user(word, u++);
			if (ret)
				break;
			ret = putreg(target, pos, word);
			count -= sizeof(*u);
			pos += sizeof(*u);
		}
	}
	return ret;
}

static int generic_fpregs_active(struct task_struct *target, const struct user_regset *regset)
{
	return regset->n;
}

/* The XSAVE image (standard format): the legacy area, its software bytes,
 * the header and the extended components. */
#define XSAVE_MXCSR_OFFSET	24
#define XSAVE_ST_OFFSET		32
#define XSAVE_XMM_OFFSET	160
#define XSAVE_PAD_OFFSET	416
#define XSAVE_SW_OFFSET		464
#define XSAVE_HDR_OFFSET	512
#define XSAVE_EXT_OFFSET	576

/* Extended components (AVX and up) enabled by seL4, by offset. */
static struct { u32 bit, offset, size; } xsave_comps[16];
static unsigned int nr_xsave_comps;

static void write_or_zero(struct membuf *to, const u8 *src, unsigned int len, bool live)
{
	if (live)
		membuf_write(to, src, len);
	else
		membuf_zero(to, len);
}

/*
 * As x86's copy_xstate_to_uabi_buf(): a component in its init state
 * (XSTATE_BV clear, as XSAVEOPT leaves it) is reported with its initial
 * values, not the stale bytes the image still holds there.  A tracer that
 * writes the registers back unchanged would otherwise make that stale
 * state live (generic_fpregs_set()).
 */
static int generic_fpregs_get(struct task_struct *target,
			      const struct user_regset *regset,
			      struct membuf to)
{
	u8 *fpregs = (u8 *)task_pt_regs(target)->regs.fp;
	unsigned int size = regset->size * regset->n, i, off;
	bool xstate = regset->core_note_type == NT_X86_XSTATE;
	/* FCW 0x37f, the rest of the x87 control and status zero. */
	static const u8 fp_init[XSAVE_MXCSR_OFFSET] = { 0x7f, 0x03 };
	const u32 mxcsr_init = 0x1f80;
	/* As x86 reports them (user_xstateregs.i387.xstate_fx_sw[]): XCR0,
	 * then zeros.  gdb reads XCR0 there. */
	u64 sw[(XSAVE_HDR_OFFSET - XSAVE_SW_OFFSET) / 8] = { l4h_xfeatures };
	u64 hdr[(XSAVE_EXT_OFFSET - XSAVE_HDR_OFFSET) / 8] = { 0 };
	u64 bv = ~0ull;

	l4h_fpu_fetch(target);
	if (host_fp_size > XSAVE_HDR_OFFSET)
		bv = *(u64 *)(fpregs + XSAVE_HDR_OFFSET);

	membuf_write(&to, bv & 1 ? fpregs : fp_init, XSAVE_MXCSR_OFFSET);
	membuf_write(&to, bv & 6 ? fpregs + XSAVE_MXCSR_OFFSET : (const u8 *)&mxcsr_init, 4);
	membuf_write(&to, fpregs + XSAVE_MXCSR_OFFSET + 4, 4);	/* MXCSR_MASK */
	write_or_zero(&to, fpregs + XSAVE_ST_OFFSET, XSAVE_XMM_OFFSET - XSAVE_ST_OFFSET, bv & 1);
	write_or_zero(&to, fpregs + XSAVE_XMM_OFFSET, XSAVE_PAD_OFFSET - XSAVE_XMM_OFFSET, bv & 2);
	membuf_zero(&to, XSAVE_SW_OFFSET - XSAVE_PAD_OFFSET);
	if (!xstate || size <= XSAVE_HDR_OFFSET) {
		membuf_zero(&to, XSAVE_HDR_OFFSET - XSAVE_SW_OFFSET);
		return 0;
	}
	membuf_write(&to, sw, sizeof(sw));
	hdr[0] = bv & l4h_xfeatures;
	membuf_write(&to, hdr, sizeof(hdr));
	off = XSAVE_EXT_OFFSET;
	for (i = 0; i < nr_xsave_comps && xsave_comps[i].offset + xsave_comps[i].size <= size; i++) {
		membuf_zero(&to, xsave_comps[i].offset - off);
		write_or_zero(&to, fpregs + xsave_comps[i].offset, xsave_comps[i].size,
			      bv & BIT_ULL(xsave_comps[i].bit));
		off = xsave_comps[i].offset + xsave_comps[i].size;
	}
	membuf_zero(&to, size - off);
	return 0;
}

static int generic_fpregs_set(struct task_struct *target,
			      const struct user_regset *regset,
			      unsigned int pos, unsigned int count,
			      const void *kbuf, const void __user *ubuf)
{
	u8 *fpregs = (u8 *)task_pt_regs(target)->regs.fp;
	int ret;

	l4h_fpu_fetch(target);
	l4h_fpu_dirty(target);
	ret = user_regset_copyin(&pos, &count, &kbuf, &ubuf,
				 fpregs, 0, regset->size * regset->n);
	/* As x86 xfpregs_set(): x87 and SSE state written through the
	 * legacy regset is not in its init state, or XRSTOR ignores it. */
	if (!ret && regset->core_note_type != NT_X86_XSTATE &&
	    host_fp_size > XSAVE_HDR_OFFSET)
		*(u64 *)(fpregs + XSAVE_HDR_OFFSET) |= 3;
	return ret;
}

static struct user_regset uml_regsets[] __ro_after_init = {
	[REGSET_GENERAL] = {
		USER_REGSET_NOTE_TYPE(PRSTATUS),
		.n		= sizeof(struct user_regs_struct) / sizeof(long),
		.size		= sizeof(long),
		.align		= sizeof(long),
		.regset_get	= genregs_get,
		.set		= genregs_set
	},
	[REGSET_FP] = {
		USER_REGSET_NOTE_TYPE(PRFPREG),
		.n		= sizeof(struct user_i387_struct) / sizeof(long),
		.size		= sizeof(long),
		.align		= sizeof(long),
		.active		= generic_fpregs_active,
		.regset_get	= generic_fpregs_get,
		.set		= generic_fpregs_set,
	},
	[REGSET_XSTATE] = {
		USER_REGSET_NOTE_TYPE(X86_XSTATE),
		.size		= sizeof(long),
		.align		= sizeof(long),
		.active		= generic_fpregs_active,
		.regset_get	= generic_fpregs_get,
		.set		= generic_fpregs_set,
	},
	/* TODO: Add TLS regset for 32bit */
};

static const struct user_regset_view user_uml_view = {
	.name = "x86_64", .e_machine = EM_X86_64,
	.regsets = uml_regsets, .n = ARRAY_SIZE(uml_regsets)
};

const struct user_regset_view *
task_user_regset_view(struct task_struct *tsk)
{
#ifdef CONFIG_KEMU
	if (task_is_kemu(tsk))
		return &kemu_regset_view;
#endif
	return &user_uml_view;
}

static int __init init_regset_xstate_info(void)
{
	unsigned int bit, i, a, b, c, d;

	uml_regsets[REGSET_XSTATE].n =
		host_fp_size / uml_regsets[REGSET_XSTATE].size;
	/* Where each extended component is, for generic_fpregs_get().  CPUID
	 * leaf 0xd lists them in the standard format, which seL4 saves. */
	for (bit = 2; bit < 64 && nr_xsave_comps < ARRAY_SIZE(xsave_comps); bit++) {
		if (!(l4h_xfeatures & BIT_ULL(bit)))
			continue;
		asm volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(0xd), "c"(bit));
		if (!a || b < XSAVE_EXT_OFFSET || b + a > host_fp_size)
			continue;
		for (i = nr_xsave_comps; i && xsave_comps[i - 1].offset > b; i--)
			xsave_comps[i] = xsave_comps[i - 1];
		xsave_comps[i].bit = bit;
		xsave_comps[i].offset = b;
		xsave_comps[i].size = a;
		nr_xsave_comps++;
	}

	return 0;
}
arch_initcall(init_regset_xstate_info);

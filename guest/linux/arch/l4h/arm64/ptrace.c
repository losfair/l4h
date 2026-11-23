// SPDX-License-Identifier: GPL-2.0
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/elf.h>
#include <linux/regset.h>
#include <linux/ptrace.h>
#include <linux/uaccess.h>
#include <l4h_uctx.h>
/* Match native arm64: x0 edits at entry must reach dispatch, seccomp and
 * restart, while an exit-stop x0 edit only changes the return value. */
static void update_orig_x0(struct task_struct *t)
{
	struct kernel_siginfo *info = t->last_siginfo;

	if (t->thread.regs.regs.syscall == -1 || !info)
		return;
	if ((info->si_code & ~0x80) == SIGTRAP &&
	    t->ptrace_message == PTRACE_EVENTMSG_SYSCALL_EXIT)
		return;
	t->thread.regs.regs.gp[36] = t->thread.regs.regs.gp[0];
}

unsigned long getreg(struct task_struct *t, int off)
{
	return off >= 0 && off < 34 * 8 && !(off & 7) ?
		       t->thread.regs.regs.gp[off / 8] :
		       0;
}
int putreg(struct task_struct *t, int off, unsigned long value)
{
	if (off < 0 || off >= 34 * 8 || (off & 7))
		return -EIO;
	if (off == 33 * 8) {
		if (value & L4H_PSTATE_BAD)
			return -EINVAL;
		value &= L4H_PSTATE_KEPT;
	}
	t->thread.regs.regs.gp[off / 8] = value;
	l4h_user_mark_dirty(&t->thread.uctx, 0);
	return 0;
}
int poke_user(struct task_struct *t, long addr, long value)
{
	return -EIO;
}
int peek_user(struct task_struct *t, long addr, long value)
{
	return -EIO;
}
long subarch_ptrace(struct task_struct *t, long req, unsigned long addr,
		    unsigned long data)
{
	return -EIO;
}
static int gpr_get(struct task_struct *t, const struct user_regset *r,
		   struct membuf to)
{
	l4h_sync_regs(t);
	return membuf_write(&to, t->thread.regs.regs.gp, 34 * 8);
}
static int gpr_set(struct task_struct *t, const struct user_regset *r,
		   unsigned int pos, unsigned int count, const void *kbuf,
		   const void __user *ubuf)
{
	unsigned long gp[34];
	int err;
	l4h_sync_regs(t);
	memcpy(gp, t->thread.regs.regs.gp, sizeof(gp));
	err = user_regset_copyin(&pos, &count, &kbuf, &ubuf, gp, 0, sizeof(gp));
	if (err)
		return err;
	if (gp[33] & L4H_PSTATE_BAD)
		return -EINVAL;
	gp[33] &= L4H_PSTATE_KEPT;
	memcpy(t->thread.regs.regs.gp, gp, sizeof(gp));
	update_orig_x0(t);
	l4h_user_mark_dirty(&t->thread.uctx, 0);
	return 0;
}
static int tls_get(struct task_struct *t, const struct user_regset *r,
		   struct membuf to)
{
	l4h_sync_seg(t);
	return membuf_store(&to, t->thread.regs.regs.gp[HOST_TLS]);
}
static int tls_set(struct task_struct *t, const struct user_regset *r,
		   unsigned int pos, unsigned int count, const void *kbuf,
		   const void __user *ubuf)
{
	unsigned long tls;
	int err;
	l4h_sync_seg(t);
	/* A copy that faults part way must not leave a torn TPIDR_EL0 in gp[],
	 * which l4h_user_sync_seg trusts once the registers are valid. */
	tls = t->thread.regs.regs.gp[HOST_TLS];
	err = user_regset_copyin(&pos, &count, &kbuf, &ubuf, &tls, 0, sizeof(tls));
	if (!err) {
		t->thread.regs.regs.gp[HOST_TLS] = tls;
		l4h_seg_dirty(t);
	}
	return err;
}
static int fp_get(struct task_struct *t, const struct user_regset *r,
		  struct membuf to)
{
	struct user_fpsimd_state fp = {};
	char *src = (char *)t->thread.regs.regs.fp;
	l4h_fpu_fetch(t);
	memcpy(fp.vregs, src, 512);
	memcpy(&fp.fpsr, src + 512, 4);
	memcpy(&fp.fpcr, src + 516, 4);
	return membuf_write(&to, &fp, sizeof(fp));
}
static int fp_set(struct task_struct *t, const struct user_regset *r,
		  unsigned int pos, unsigned int count, const void *kbuf,
		  const void __user *ubuf)
{
	struct user_fpsimd_state fp = {};
	char *dst = (char *)t->thread.regs.regs.fp;
	int err;
	l4h_fpu_fetch(t);
	memcpy(fp.vregs, dst, 512);
	memcpy(&fp.fpsr, dst + 512, 4);
	memcpy(&fp.fpcr, dst + 516, 4);
	err = user_regset_copyin(&pos, &count, &kbuf, &ubuf, &fp, 0,
				 sizeof(fp));
	if (err)
		return err;
	memcpy(dst, fp.vregs, 512);
	memcpy(dst + 512, &fp.fpsr, 4);
	memcpy(dst + 516, &fp.fpcr, 4);
	l4h_fpu_dirty(t);
	return 0;
}
static int syscallno_get(struct task_struct *t, const struct user_regset *r,
			 struct membuf to)
{
	return membuf_store(&to, (int)t->thread.regs.regs.syscall);
}
static int syscallno_set(struct task_struct *t, const struct user_regset *r,
			 unsigned int pos, unsigned int count, const void *kbuf,
			 const void __user *ubuf)
{
	int nr = t->thread.regs.regs.syscall;
	int err = user_regset_copyin(&pos, &count, &kbuf, &ubuf, &nr, 0,
				     sizeof(nr));

	/* As arm64: x0 is the tracer's (a skipped syscall's return value);
	 * handle_syscall() gives a user-issued syscall(-1) -ENOSYS. */
	if (!err)
		t->thread.regs.regs.syscall = nr;
	return err;
}
static const struct user_regset regsets[] = {
	{ USER_REGSET_NOTE_TYPE(PRSTATUS), .n = 34, .size = 8, .align = 8,
	  .regset_get = gpr_get, .set = gpr_set },
	{ USER_REGSET_NOTE_TYPE(PRFPREG),
	  .n = sizeof(struct user_fpsimd_state) / 4, .size = 4, .align = 16,
	  .regset_get = fp_get, .set = fp_set },
	{ USER_REGSET_NOTE_TYPE(ARM_TLS), .n = 1, .size = 8, .align = 8,
	  .regset_get = tls_get, .set = tls_set },
	{ USER_REGSET_NOTE_TYPE(ARM_SYSTEM_CALL), .n = 1, .size = 4, .align = 4,
	  .regset_get = syscallno_get, .set = syscallno_set },
};
static const struct user_regset_view view = { .name = "aarch64",
					      .e_machine = EM_AARCH64,
					      .regsets = regsets,
					      .n = ARRAY_SIZE(regsets) };
const struct user_regset_view *task_user_regset_view(struct task_struct *t)
{
	return &view;
}

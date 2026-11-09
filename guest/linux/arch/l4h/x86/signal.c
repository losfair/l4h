/*
 * Copyright (C) 2003 PathScale, Inc.
 * Copyright (C) 2003 - 2007 Jeff Dike (jdike@{addtoit,linux.intel}.com)
 * Licensed under the GPL
 */


#include <linux/personality.h>
#include <linux/ptrace.h>
#include <l4h_uctx.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <asm/unistd.h>
#include <linux/uaccess.h>
#include <asm/ucontext.h>
#include <frame_kern.h>
#include <registers.h>
#include <skas.h>

#include <linux/regset.h>
#include <asm/sigframe.h>
#include <uapi/asm/processor-flags.h>
#include <asm/segment.h>
#include <asm/fpu/api.h>

#define _xstate_64 _xstate

static int copy_sc_from_user(struct pt_regs *regs,
			     struct sigcontext __user *from)
{
	struct _xstate_64 __user *from_fp64;
	struct sigcontext sc;
	int err;

	/* Always make any pending restarted system calls return -EINTR */
	current->restart_block.fn = do_no_restart_syscall;

	err = copy_from_user(&sc, from, sizeof(sc));
	if (err)
		return err;

#define GETREG(regno, regname) regs->regs.gp[HOST_##regno] = sc.regname

	GETREG(DI, di);
	GETREG(SI, si);
	GETREG(BP, bp);
	GETREG(SP, sp);
	GETREG(BX, bx);
	GETREG(DX, dx);
	GETREG(CX, cx);
	GETREG(AX, ax);
	GETREG(IP, ip);

#ifdef CONFIG_X86_64
	GETREG(R8, r8);
	GETREG(R9, r9);
	GETREG(R10, r10);
	GETREG(R11, r11);
	GETREG(R12, r12);
	GETREG(R13, r13);
	GETREG(R14, r14);
	GETREG(R15, r15);
#endif

	GETREG(EFLAGS, flags);

#undef GETREG

	from_fp64 = (void __user *)sc.fpstate;

	err = copy_from_user(regs->regs.fp, from_fp64, host_fp_size);
	l4h_fpu_dirty(current);
	if (err)
		return 1;

	return 0;
}

static int copy_sc_to_user(struct sigcontext __user *to,
			   struct _xstate __user *to_fp, struct pt_regs *regs,
			   unsigned long mask)
{
	struct _xstate_64 __user *to_fp64;
	struct sigcontext sc;
	struct faultinfo * fi = &current->thread.arch.faultinfo;
	int err;
	memset(&sc, 0, sizeof(struct sigcontext));

#define PUTREG(regno, regname) sc.regname = regs->regs.gp[HOST_##regno]

	PUTREG(DI, di);
	PUTREG(SI, si);
	PUTREG(BP, bp);
	PUTREG(SP, sp);
	PUTREG(BX, bx);
	PUTREG(DX, dx);
	PUTREG(CX, cx);
	PUTREG(AX, ax);
#ifdef CONFIG_X86_64
	PUTREG(R8, r8);
	PUTREG(R9, r9);
	PUTREG(R10, r10);
	PUTREG(R11, r11);
	PUTREG(R12, r12);
	PUTREG(R13, r13);
	PUTREG(R14, r14);
	PUTREG(R15, r15);
#endif

	sc.cr2 = fi->cr2;
	sc.err = fi->error_code;
	sc.trapno = fi->trap_no;
	PUTREG(IP, ip);
	PUTREG(EFLAGS, flags);
	sc.cs = __USER_CS;
	sc.ss = __USER_DS;
#undef PUTREG
	sc.oldmask = mask;
	sc.fpstate = (unsigned long)to_fp;

	err = copy_to_user(to, &sc, sizeof(struct sigcontext));
	if (err)
		return 1;

	to_fp64 = to_fp;

	l4h_fpu_fetch(current);
	if (copy_to_user(to_fp64, regs->regs.fp, host_fp_size))
		return 1;

	/*
	 * Put magic/size values for userspace. We do not bother to verify them
	 * later on, however, userspace needs them should it try to read the
	 * XSTATE data. And ptrace does not fill in these parts.
	 *
	 * Skip this if we do not have an XSTATE frame.
	 */
	if (host_fp_size <= sizeof(to_fp64->fpstate))
		return 0;

	BUILD_BUG_ON(sizeof(int) != FP_XSTATE_MAGIC2_SIZE);
	__put_user(host_fp_size + FP_XSTATE_MAGIC2_SIZE,
		   &to_fp64->fpstate.sw_reserved.extended_size);
	__put_user(host_fp_size, &to_fp64->fpstate.sw_reserved.xstate_size);
	__put_user(l4h_xfeatures, &to_fp64->fpstate.sw_reserved.xfeatures);

	__put_user(FP_XSTATE_MAGIC1, &to_fp64->fpstate.sw_reserved.magic1);
	__put_user(FP_XSTATE_MAGIC2,
		   (int __user *)((void __user *)to_fp64 + host_fp_size));

	return 0;
}

/* The initial FPU state: XSTATE_BV 0 makes XRSTOR load x87, SSE and AVX
 * in their init state; MXCSR is loaded from the image. */
static void fpu_init_image(struct pt_regs *regs)
{
	struct _fpstate_64 *fp = (struct _fpstate_64 *)regs->regs.fp;

	memset(regs->regs.fp, 0, host_fp_size);
	fp->cwd = 0x37f;
	fp->mxcsr = 0x1f80;
	l4h_fpu_dirty(current);
}

int setup_signal_stack_si(unsigned long stack_top, struct ksignal *ksig,
			  struct pt_regs *regs, sigset_t *set)
{
	unsigned long math_size = host_fp_size + FP_XSTATE_MAGIC2_SIZE;
	struct rt_sigframe __user *frame;
	int err = 0, sig = ksig->sig;
	unsigned long fp_to;

	/*
	 * As x86's get_sigframe(): below the red zone, the math frame on a
	 * 64-byte boundary (user code may xrstor from it), and below that
	 * the frame, its pretcode 8 bytes off a 16-byte boundary as after a
	 * call.
	 */
	fp_to = round_down(stack_top - 128 - math_size, 64);
	frame = (struct rt_sigframe __user *)
		(round_down(fp_to - sizeof(*frame), 16) - 8);

	/* A frame that does not fit on the alternate stack is not written
	 * below it. */
	if (on_sig_stack(stack_top) && !on_sig_stack((unsigned long)frame))
		return -EFAULT;
	if (!access_ok(frame, fp_to + math_size - (unsigned long)frame)) {
		err = -EFAULT;
		goto out;
	}

	if (ksig->ka.sa.sa_flags & SA_SIGINFO) {
		err |= copy_siginfo_to_user(&frame->info, &ksig->info);
		if (err)
			goto out;
	}

	/* Create the ucontext.  */
	err |= __put_user(UC_SIGCONTEXT_SS | UC_STRICT_RESTORE_SS |
			  (host_fp_size > sizeof(struct _fpstate_64) ? UC_FP_XSTATE : 0),
			  &frame->uc.uc_flags);
	err |= __put_user(NULL, &frame->uc.uc_link);
	err |= __save_altstack(&frame->uc.uc_stack, PT_REGS_SP(regs));

	err |= copy_sc_to_user(&frame->uc.uc_mcontext,
			       (struct _xstate __user *)fp_to,
			       regs, set->sig[0]);

	err |= __put_user(fp_to, &frame->uc.uc_mcontext.fpstate);
	if (sizeof(*set) == 16) {
		err |= __put_user(set->sig[0], &frame->uc.uc_sigmask.sig[0]);
		err |= __put_user(set->sig[1], &frame->uc.uc_sigmask.sig[1]);
	}
	else
		err |= __copy_to_user(&frame->uc.uc_sigmask, set,
				      sizeof(*set));

	/*
	 * Set up to return from userspace.  If provided, use a stub
	 * already in userspace.
	 */
	/* x86-64 must use SA_RESTORER: without one the handler could not
	 * return, and x86 fails the delivery (SIGSEGV). */
	if (!(ksig->ka.sa.sa_flags & SA_RESTORER))
		return -EFAULT;
	err |= __put_user((void __user *)ksig->ka.sa.sa_restorer, &frame->pretcode);
	if (err)
		return err;

	/* The handler starts as on x86: DF, TF and RF clear (the ABI says DF
	 * is clear at function entry; rep movs would run backwards) and the
	 * FPU in its initial state, the interrupted one being in the frame. */
	PT_REGS_EFLAGS(regs) &= ~(X86_EFLAGS_DF | X86_EFLAGS_TF | X86_EFLAGS_RF);
	fpu_init_image(regs);

	PT_REGS_SP(regs) = (unsigned long) frame;
	PT_REGS_DI(regs) = sig;
	/* In case the signal handler was declared without prototypes */
	PT_REGS_AX(regs) = 0;

	/*
	 * This also works for non SA_SIGINFO handlers because they expect the
	 * next argument after the signal number on the stack.
	 */
	PT_REGS_SI(regs) = (unsigned long) &frame->info;
	PT_REGS_DX(regs) = (unsigned long) &frame->uc;
	PT_REGS_IP(regs) = (unsigned long) ksig->ka.sa.sa_handler;
 out:
	return err;
}

SYSCALL_DEFINE0(rt_sigreturn)
{
	unsigned long sp = PT_REGS_SP(&current->thread.regs);
	struct rt_sigframe __user *frame =
		(struct rt_sigframe __user *)(sp - sizeof(long));
	struct ucontext __user *uc = &frame->uc;
	sigset_t set;

	if (copy_from_user(&set, &uc->uc_sigmask, sizeof(set)))
		goto segfault;

	set_current_blocked(&set);

	/* Re-arms an SS_AUTODISARM alternate stack. */
	if (restore_altstack(&uc->uc_stack))
		goto segfault;

	if (copy_sc_from_user(&current->thread.regs, &uc->uc_mcontext))
		goto segfault;

	/* Avoid ERESTART handling */
	PT_REGS_SYSCALL_NR(&current->thread.regs) = -1;
	return PT_REGS_SYSCALL_RET(&current->thread.regs);

 segfault:
	force_sig(SIGSEGV);
	return 0;
}

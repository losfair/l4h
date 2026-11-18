// SPDX-License-Identifier: GPL-2.0
/* Native AArch64 rt_sigframe: siginfo, ucontext and FPSIMD records. */
#include <linux/ptrace.h>
#include <linux/syscalls.h>
#include <linux/signal.h>
#include <linux/sched/signal.h>
#include <linux/uaccess.h>
#include <asm/ucontext.h>
#include <asm/elf.h>
#include <l4h_uctx.h>
#include <frame_kern.h>
struct rt_sigframe {
	struct siginfo info;
	struct ucontext uc;
};
/* The reserved context area stays in user memory; avoid a 4 KiB kernel
 * stack allocation on signal delivery and sigreturn. */
struct sigcontext_header {
	u64 fault_address;
	struct user_pt_regs user;
} __aligned(16);

int setup_signal_stack_si(unsigned long top, struct ksignal *ksig,
			  struct pt_regs *regs, sigset_t *set)
{
	struct rt_sigframe __user *frame =
		(void __user *)round_down(top - sizeof(*frame), 16);
	struct sigcontext_header sc = {};
	struct fpsimd_context fp = {};
	int err;
	/* A frame that does not fit on the alternate stack is not written
	 * below it (as x86/signal.c). */
	if (on_sig_stack(top) && !on_sig_stack((unsigned long)frame))
		return -EFAULT;
	if (!access_ok(frame, sizeof(*frame)))
		return -EFAULT;
	memcpy(sc.user.regs, regs->regs.gp, sizeof(sc.user.regs));
	sc.user.sp = PT_REGS_SP(regs);
	sc.user.pc = PT_REGS_IP(regs);
	sc.user.pstate = regs->regs.gp[33];
	sc.fault_address = current->thread.arch.faultinfo.cr2;
	fp.head.magic = FPSIMD_MAGIC;
	fp.head.size = sizeof(fp);
	l4h_fpu_fetch(current);
	/* seL4 stores v0-v31 followed by FPSR and FPCR. */
	memcpy(fp.vregs, regs->regs.fp, sizeof(fp.vregs));
	memcpy(&fp.fpsr, (char *)regs->regs.fp + 512, 4);
	memcpy(&fp.fpcr, (char *)regs->regs.fp + 516, 4);
	err = clear_user(frame, sizeof(*frame));
	err |= copy_siginfo_to_user(&frame->info, &ksig->info);
	err |= __save_altstack(&frame->uc.uc_stack, PT_REGS_SP(regs));
	err |= copy_to_user(&frame->uc.uc_sigmask, set, sizeof(*set));
	err |= copy_to_user(&frame->uc.uc_mcontext, &sc, sizeof(sc));
	err |= copy_to_user(frame->uc.uc_mcontext.__reserved, &fp, sizeof(fp));
	if (err)
		return -EFAULT;
	PT_REGS_SP(regs) = (unsigned long)frame;
	PT_REGS_IP(regs) = (unsigned long)ksig->ka.sa.sa_handler;
	regs->regs.gp[0] = ksig->sig;
	regs->regs.gp[1] = (unsigned long)&frame->info;
	regs->regs.gp[2] = (unsigned long)&frame->uc;
	regs->regs.gp[30] = (ksig->ka.sa.sa_flags & SA_RESTORER) ?
				    (unsigned long)ksig->ka.sa.sa_restorer :
				    um_vdso_addr + 0x100;
	return 0;
}
SYSCALL_DEFINE0(rt_sigreturn)
{
	struct pt_regs *regs = &current->thread.regs;
	struct rt_sigframe __user *frame = (void __user *)PT_REGS_SP(regs);
	struct sigcontext_header sc;
	sigset_t set;
	struct fpsimd_context fp;
	struct _aarch64_ctx head;
	unsigned int off = 0;
	int found = 0;
	if (((unsigned long)frame & 15) || !access_ok(frame, sizeof(*frame)))
		goto bad;
	if (copy_from_user(&set, &frame->uc.uc_sigmask, sizeof(set)) ||
	    copy_from_user(&sc, &frame->uc.uc_mcontext, sizeof(sc)))
		goto bad;
	if ((sc.user.pstate & L4H_PSTATE_BAD) || (sc.user.pc & 3) ||
	    sc.user.pc >= TASK_SIZE || sc.user.sp >= TASK_SIZE)
		goto bad;
	sc.user.pstate &= L4H_PSTATE_KEPT;
	/* Walk the extensible records, requiring a terminator and one FPSIMD record. */
	for (;;) {
		void __user *record = frame->uc.uc_mcontext.__reserved + off;
		if (off > 4096 - sizeof(head) ||
		    copy_from_user(&head, record, sizeof(head)))
			goto bad;
		if (!head.magic && !head.size)
			break;
		if (head.size < 16 || (head.size & 15) ||
		    head.size > 4096 - off)
			goto bad;
		if (head.magic == FPSIMD_MAGIC) {
			if (found++ || head.size != sizeof(fp) ||
			    copy_from_user(&fp, record, sizeof(fp)))
				goto bad;
		} else if (head.magic != ESR_MAGIC) {
			goto bad;
		}
		off += head.size;
	}
	if (!found)
		goto bad;
	if (restore_altstack(&frame->uc.uc_stack))
		goto bad;
	set_current_blocked(&set);
	current->restart_block.fn = do_no_restart_syscall;
	memcpy(regs->regs.gp, sc.user.regs, sizeof(sc.user.regs));
	PT_REGS_SP(regs) = sc.user.sp;
	PT_REGS_IP(regs) = sc.user.pc;
	regs->regs.gp[33] = sc.user.pstate;
	memcpy(regs->regs.fp, fp.vregs, sizeof(fp.vregs));
	memset((char *)regs->regs.fp + 512, 0, host_fp_size - 512);
	memcpy((char *)regs->regs.fp + 512, &fp.fpsr, 4);
	memcpy((char *)regs->regs.fp + 516, &fp.fpcr, 4);
	l4h_fpu_dirty(current);
	PT_REGS_SYSCALL_NR(regs) = -1;
	return PT_REGS_SYSCALL_RET(regs);
bad:
	force_sig(SIGSEGV);
	return 0;
}

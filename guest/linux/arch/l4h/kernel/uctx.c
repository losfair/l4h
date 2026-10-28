// SPDX-License-Identifier: GPL-2.0
/*
 * User execution and kernel threads of the l4h guest.
 *
 * userspace() is the l4h version of UML's main loop for a thread in user
 * mode: run the thread's seL4 user context until it traps (syscall, page
 * fault, exception) or the vCPU receives an event, handle that, repeat.
 *
 * Kernel thread switching keeps UML's setjmp/longjmp scheme.
 */
#include <linux/kernel.h>
#include <linux/kemu.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/sched/signal.h>
#include <linux/sched/task_stack.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/atomic.h>
#include <linux/xarray.h>
#include <asm/current.h>
#include <asm/tlbflush.h>
#include <as-layout.h>
#include <kern_util.h>
#include <arch.h>
#include <os.h>
#include <skas.h>
#include <registers.h>
#include <l4h_sys.h>
#include <l4h_caps.h>
#include <l4h_vspace.h>

#define EMPTY_CNODE	L4H_CPTR2(L4H_SLOT_META, L4H_META_DYN_BASE)

unsigned long host_fp_size;
static atomic64_t uctx_ids = ATOMIC64_INIT(0);
static DEFINE_XARRAY(uctx_by_badge);

/* Debug helper for os-sel4: describe the user context with `badge`. */
void l4h_uctx_describe(unsigned long badge)
{
	struct task_struct *t = xa_load(&uctx_by_badge, badge & ~L4H_EP_BADGE_TASK);

	if (!t) {
		pr_err("l4h: no user context with badge %lx\n", badge);
		return;
	}
	pr_err("l4h: uctx@%lx badge %lx (task's uctx badge %lx tcb %lx): pid %d (%s) state=%d stop=%d fault_ep_vcpu=%d sc_vcpu=%d task_cpu=%d on_cpu=%d\n",
	       (unsigned long)&t->thread.uctx & 0xffffffff, badge, t->thread.uctx.badge, t->thread.uctx.tcb, task_pid_nr(t), t->comm, t->thread.uctx.state, t->thread.uctx.stop,
	       t->thread.uctx.fault_ep_vcpu, t->thread.uctx.sc_vcpu, task_cpu(t), t->on_cpu);
}

/* ---- registers */

/* Initial register state: zero GPRs, native FP/SIMD defaults. */
void get_safe_registers(unsigned long *regs, unsigned long *fp_regs)
{
	memset(regs, 0, sizeof(unsigned long) * MAX_REG_NR);
	if (fp_regs) {
		u8 *fp = (u8 *)fp_regs;

		memset(fp, 0, host_fp_size);
#ifdef CONFIG_UML_X86
		*(u16 *)(fp + 0) = 0x37f;	/* FCW */
		*(u32 *)(fp + 24) = 0x1f80;	/* MXCSR */
#endif
	}
}

/* Make current->thread.regs.regs.fp hold the thread's FPU state. */
void l4h_fpu_fetch(struct task_struct *t)
{
	struct l4h_uctx *u = &t->thread.uctx;

	if (u->fp_state != L4H_FP_IN_TCB)
		return;
	if (u->state == L4H_UCTX_NONE || u->state == L4H_UCTX_FRESH) {
		u->fp_state = L4H_FP_IN_REGS;
		return;
	}
	WARN_ON(l4h_fpu_read(u, t->thread.regs.regs.fp, host_fp_size));
	u->fp_state = L4H_FP_IN_REGS;
}

/* The kernel changed regs.regs.fp; the TCB must be updated before the
 * thread runs again. */
void l4h_fpu_dirty(struct task_struct *t)
{
	t->thread.uctx.fp_state = L4H_FP_DIRTY;
}

/* Make the general registers in thread.regs current (they may only be in
 * the TCB after a page fault, exception or preemption). */
void l4h_sync_regs(struct task_struct *t)
{
	l4h_user_sync_regs(&t->thread.uctx, t->thread.regs.regs.gp);
}

/* fs/gs base were changed by the kernel (arch_prctl, CLONE_SETTLS). */
void l4h_seg_dirty(struct task_struct *t)
{
	l4h_user_mark_dirty(&t->thread.uctx, 1);
}

/* fs/gs base may have been changed by user code; refresh them. */
void l4h_sync_seg(struct task_struct *t)
{
	l4h_user_sync_seg(&t->thread.uctx, t->thread.regs.regs.gp);
}

/* ---- user contexts */

static int uctx_create(struct task_struct *t)
{
	struct thread_struct *th = &t->thread;
	struct l4h_uctx *u = &th->uctx;
	int err;

	err = l4h_obj_alloc(L4H_OBJ_TCB, 0, &th->utcb_obj);
	if (err)
		return err;
	err = l4h_obj_alloc(L4H_OBJ_REPLY, 0, &th->reply_obj);
	if (err)
		goto fail_tcb;
	/* The fault endpoint's slot is taken here, where running out can
	 * wait or go to the OOM killer; prepare_user() only refills it. */
	u->fault_ep = l4h_slot_alloc();
	if (!u->fault_ep) {
		err = -ENOMEM;
		goto fail_reply;
	}
	u->tcb = th->utcb_obj.cptr;
	u->reply = th->reply_obj.cptr;
	u->badge = L4H_EP_BADGE_TASK | atomic64_inc_return(&uctx_ids);
	xa_store(&uctx_by_badge, u->badge & ~L4H_EP_BADGE_TASK, t, GFP_ATOMIC);
	u->fault_ep_vcpu = -1;
	u->sc_vcpu = -1;
	u->vspace = 0;
	/* Missing syscall-trap support is not an allocation failure to retry. */
	if (l4h_tcb_set_flags(u->tcb, 1 /* fpuDisabled */, 2 /* trapSyscalls */))
		panic("l4h: the seL4 kernel cannot trap user syscalls\n");
	u->state = L4H_UCTX_FRESH;
	u->regs_valid = 1;
	if (u->fp_state != L4H_FP_DIRTY) {
		/* The kernel-side copy is authoritative for a new context. */
		u->fp_state = L4H_FP_DIRTY;
	}
	return 0;

fail_reply:
	l4h_obj_free(&th->reply_obj);
fail_tcb:
	l4h_obj_free(&th->utcb_obj);
	u->tcb = 0;
	return -ENOMEM;
}

/*
 * The user context (TCB and reply object) of a task about to run in user
 * mode, made where we may sleep: if there is no memory for the objects,
 * wait for a block to be converted, else it is guest OOM.  The victim may
 * be us.
 */
static void uctx_ensure(struct task_struct *t)
{
	while (t->thread.uctx.state == L4H_UCTX_NONE && uctx_create(t)) {
		if (!l4h_objmem_wait())
			l4h_objmem_oom();
		if (fatal_signal_pending(current))
			do_exit(SIGKILL);
	}
}

void l4h_uctx_destroy(struct task_struct *t)

{
	struct thread_struct *th = &t->thread;
	struct l4h_uctx *u = &th->uctx;

	if (u->state == L4H_UCTX_NONE)
		return;
	l4h_user_deschedule(u);
	xa_erase(&uctx_by_badge, u->badge & ~L4H_EP_BADGE_TASK);
	if (u->fault_ep)
		l4h_slot_delete(u->fault_ep);
	l4h_obj_free(&th->reply_obj);
	l4h_obj_free(&th->utcb_obj);
	u->state = L4H_UCTX_NONE;
	u->tcb = 0;
	u->fault_ep = 0;
	u->fault_ep_vcpu = -1;
}

/*
 * Account `t` as possibly executing user code of `mm`.  The count is kept
 * on the mm it was taken on: exec and exit change t->mm while `t` is
 * counted, and an mm whose count is off is evicted from its VSpace while
 * its threads run, which then share that VSpace with the next owner.
 */
static void mm_running_enter(struct task_struct *t, struct mm_struct *mm)
{
	if (t->thread.running_mm == mm)
		return;
	WARN_ON_ONCE(t->thread.running_mm);
	atomic_inc(&mm->context.l4h.running);
	t->thread.running_mm = mm;
}

static void mm_running_leave(struct task_struct *t)
{
	/* Release even a faulted context before the task can migrate.  Leaving
	 * it bound lets the old vCPU's bind_sc() race with its new vCPU over
	 * sc_owner/sc_vcpu, and retain a pointer to a task that can exit there.
	 * A preempted context must also lose SC_U so it cannot run behind the
	 * kernel's back.  Ownership is consequently local to the current vCPU. */
	l4h_user_deschedule(&t->thread.uctx);
	atomic_dec(&t->thread.running_mm->context.l4h.running);
	t->thread.running_mm = NULL;
}

/* Called when `t` stops being current on its vCPU. */
void l4h_uctx_switch_out(struct task_struct *t)
{
	if (t->thread.running_mm)
		mm_running_leave(t);
}

/* `t` no longer uses `mm` (exec, exit_mm()), which may be freed next. */
void l4h_uctx_mm_gone(struct task_struct *t, struct mm_struct *mm)
{
	unsigned long flags;

	local_irq_save(flags);
	if (t->thread.running_mm == mm)
		mm_running_leave(t);
	local_irq_restore(flags);
}

/* Returns false if it gave the CPU away: the caller starts again. */
static bool prepare_user(struct task_struct *t)
{
	struct thread_struct *th = &t->thread;
	struct l4h_uctx *u = &th->uctx;
	struct mm_struct *mm = t->mm;
	int cpu = smp_processor_id();
	unsigned long root;
	u64 gen;

	/* userspace() created the context (uctx_ensure). */
	if (u->state == L4H_UCTX_NONE && uctx_create(t))
		panic("l4h: out of seL4 objects creating a user context\n");

	if (u->fault_ep_vcpu != cpu) {
		/* The task moved here from another vCPU: the next unmap in
		 * its VSpace flushes it first (vspace.c, mm_flush_moved()). */
		if (u->fault_ep_vcpu >= 0) {
			WRITE_ONCE(mm->context.l4h.moved, true);
			WARN_ON(l4h_cnode_delete(u->fault_ep, 64));
		}
		if (l4h_cnode_mint(u->fault_ep, 64, L4H_SLOT_VCPU(cpu) + L4H_VCPU_EP,
				   L4H_ROOT_DEPTH, L4H_RIGHTS_ALL, u->badge))
			panic("l4h: cannot mint a fault endpoint\n");
		u->fault_ep_vcpu = cpu;
		/* Force SC_U (and with it the fault endpoint) to be rebound. */
		if (u->sc_vcpu >= 0)
			l4h_user_deschedule(u);
	}

	mm_running_enter(t, mm);
	root = l4h_mm_activate(mm, &gen);
	if (!root) {
		/* The vCPU may have changed: redo the above. */
		cond_resched();
		return false;
	}
	if (u->vspace != root || th->vs_gen != gen) {
		int err;

		if (u->state == L4H_UCTX_FRESH && !u->vspace)
			err = l4h_tcb_configure_user(u->tcb, EMPTY_CNODE, root);
		else
			err = l4h_tcb_set_space(u->tcb, u->fault_ep, EMPTY_CNODE, root);
		if (err)
			panic("l4h: binding user context to VSpace failed: %d\n", err);
		u->vspace = root;
		th->vs_gen = gen;
	}

	if (u->fp_state == L4H_FP_DIRTY) {
		if (l4h_fpu_write(u, th->regs.regs.fp, host_fp_size))
			panic("l4h: WriteFPU failed\n");
		u->fp_state = L4H_FP_IN_REGS;
	}
	return true;
}

/* Map an seL4 user exception to the native Linux signal. */
static void handle_exception(struct uml_pt_regs *regs, struct l4h_uctx *u)
{
	struct faultinfo *fi = &current->thread.arch.faultinfo;
	int sig = SIGSEGV, code = SI_KERNEL;
	void __user *addr = (void __user *)u->fault_ip;

	fi->trap_no = u->exc_number;
	fi->error_code = u->fault_code;
	fi->cr2 = 0;
#ifdef CONFIG_UML_ARM64
	/* ESR exception classes: BRK, alignment and undefined instruction. */
	switch (u->exc_number >> 26) {
	case 0x2c: /* trapped floating-point exception */
		sig = SIGFPE;
		code = FPE_FLTUNK;
		if (u->exc_number & (1UL << 23)) {
			if (u->exc_number & 1) code = FPE_FLTINV;
			else if (u->exc_number & 2) code = FPE_FLTDIV;
			else if (u->exc_number & 4) code = FPE_FLTOVF;
			else if (u->exc_number & 8) code = FPE_FLTUND;
			else if (u->exc_number & 16) code = FPE_FLTRES;
		}
		break;
	case 0x3c:
		sig = SIGTRAP;
		code = TRAP_BRKPT;
		break;
	case 0x22: /* PC alignment */
	case 0x26: /* SP alignment */
	case 0x24: /* data abort with alignment FSC */
		sig = SIGBUS;
		code = BUS_ADRALN;
		if ((u->exc_number >> 26) == 0x24)
			addr = (void __user *)u->fault_addr;
		else if ((u->exc_number >> 26) == 0x26)
			addr = (void __user *)UPT_SP(regs);
		break;
	default:
		sig = SIGILL;
		code = ILL_ILLOPC;
		break;
	}
#else
	switch (u->exc_number) {
	case 0:		/* #DE */
		sig = SIGFPE;
		code = FPE_INTDIV;
		break;
	case 1:		/* #DB */
	case 3:		/* #BP */
		sig = SIGTRAP;
		code = (u->exc_number == 3) ? SI_KERNEL : TRAP_BRKPT;
		break;
	case 4:		/* #OF */
		code = SI_KERNEL;
		break;
	case 5:		/* #BR */
		code = SI_KERNEL;
		break;
	case 6:		/* #UD */
		sig = SIGILL;
		code = ILL_ILLOPN;
		break;
	case 16:	/* #MF */
	case 19:	/* #XM */
		sig = SIGFPE;
		code = FPE_FLTINV;
		break;
	case 17:	/* #AC */
		sig = SIGBUS;
		code = BUS_ADRALN;
		break;
	case 13:	/* #GP (also int $0x80 without a gate) */
		/* kemu handles tagged or out-of-range AArch64 data addresses. */
		if (task_is_kemu(current) && kemu_user_gp(&current->thread.regs))
			return;
		fallthrough;
	default:
		sig = SIGSEGV;
		code = SI_KERNEL;
		addr = NULL;
		break;
	}
#endif
	if (code == SI_KERNEL)
		force_sig(sig);
	else
		force_sig_fault(sig, code, addr);
}

static void handle_page_fault_stop(struct uml_pt_regs *regs, struct l4h_uctx *u)
{
	struct faultinfo fi = {
		.error_code = u->fault_code | 4 /* user */,
		.cr2 = u->fault_addr,
		.trap_no = 14,
	};

	regs->faultinfo = fi;
	segv(fi, u->fault_ip, 1, regs, NULL);
}

void userspace(struct uml_pt_regs *regs)
{
	struct task_struct *t = current;
	struct l4h_uctx *u = &t->thread.uctx;
	int stop;

	/* Handle any immediate reschedules or signals */
	interrupt_end();

	while (1) {
		current_mm_sync();
		uctx_ensure(t);
		if (!prepare_user(t))
			continue;
		/* Its locks deliver events, after interrupt_end() looked. */
		if (unlikely(read_thread_flags() & _TIF_WORK_MASK)) {
			interrupt_end();
			continue;
		}

		stop = l4h_user_run(u, regs->gp, 0);
		/* The TCB now owns the FPU state again. */
		if (u->fp_state == L4H_FP_IN_REGS)
			u->fp_state = L4H_FP_IN_TCB;
		regs->is_user = 1;
		UPT_SYSCALL_NR(regs) = -1;

		switch (stop) {
		case L4H_STOP_SYSCALL:
			handle_syscall(regs);
			break;
		case L4H_STOP_PAGEFAULT:
			handle_page_fault_stop(regs, u);
			break;
		case L4H_STOP_EXCEPTION:
			l4h_sync_regs(t);
			handle_exception(regs, u);
			break;
		case L4H_STOP_INTERRUPT:
			l4h_dispatch_user_interrupt();
			break;
		}

		interrupt_end();

		/* Avoid -ERESTARTSYS handling in host */
		if (PT_SYSCALL_NR_OFFSET != PT_SYSCALL_RET_OFFSET)
			PT_SYSCALL_NR(regs->gp) = -1;
	}
}

#ifdef CONFIG_UML_ARM64
#define L4H_STACK_RESERVE 16
#else
#define L4H_STACK_RESERVE sizeof(void *)
#endif

/* ---- kernel threads (UML os-Linux/skas/process.c) */

unsigned long get_thread_reg(int reg, jmp_buf *buf)
{
	switch (reg) {
	case HOST_IP:
		return buf[0]->JB_IP;
	case HOST_SP:
		return buf[0]->JB_SP;
	case HOST_BP:
		return buf[0]->JB_BP;
	default:
		return 0;
	}
}

void new_thread(void *stack, jmp_buf *buf, void (*handler)(void))
{
	(*buf)[0].JB_IP = (unsigned long) handler;
	(*buf)[0].JB_SP = (unsigned long) stack + UM_THREAD_SIZE - L4H_STACK_RESERVE;
}

#define INIT_JMP_NEW_THREAD 0
#define INIT_JMP_CALLBACK 1
#define INIT_JMP_HALT 2
#define INIT_JMP_REBOOT 3

void switch_threads(jmp_buf *me, jmp_buf *you)
{
	if (UML_SETJMP(me) == 0)
		UML_LONGJMP(you, 1);
}

static jmp_buf initial_jmpbuf;

static void (*cb_proc)(void *arg);
static void *cb_arg;
static jmp_buf *cb_back;

int start_idle_thread(void *stack, jmp_buf *switch_buf)
{
	int n;

	n = setjmp(initial_jmpbuf);
	switch (n) {
	case INIT_JMP_NEW_THREAD:
		(*switch_buf)[0].JB_IP = (unsigned long) uml_finishsetup;
		(*switch_buf)[0].JB_SP = (unsigned long) stack +
			UM_THREAD_SIZE - L4H_STACK_RESERVE;
		break;
	case INIT_JMP_CALLBACK:
		(*cb_proc)(cb_arg);
		longjmp(*cb_back, 1);
		break;
	case INIT_JMP_HALT:
		kmalloc_ok = 0;
		return 0;
	case INIT_JMP_REBOOT:
		kmalloc_ok = 0;
		return 1;
	default:
		panic("Bad sigsetjmp return in %s - %d\n", __func__, n);
	}
	longjmp(*switch_buf, 1);

	/* unreachable */
	panic("impossible long jump!");
	return 0;
}

void initial_thread_cb_skas(void (*proc)(void *), void *arg)
{
	jmp_buf here;

	cb_proc = proc;
	cb_arg = arg;
	cb_back = &here;

	block_signals_trace();
	if (UML_SETJMP(&here) == 0)
		UML_LONGJMP(&initial_jmpbuf, INIT_JMP_CALLBACK);
	unblock_signals_trace();

	cb_proc = NULL;
	cb_arg = NULL;
	cb_back = NULL;
}

void halt_skas(void)
{
	block_signals_trace();
	UML_LONGJMP(&initial_jmpbuf, INIT_JMP_HALT);
}

void reboot_skas(void)
{
	block_signals_trace();
	UML_LONGJMP(&initial_jmpbuf, INIT_JMP_REBOOT);
}

void __init l4h_uctx_init(void)
{
	host_fp_size = l4h_fpu_state_size();
}

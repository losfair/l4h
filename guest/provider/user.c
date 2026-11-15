// SPDX-License-Identifier: GPL-2.0
/*
 * Running guest user code.
 *
 * Every Linux thread that enters user mode has its own seL4 TCB (a "user
 * context", struct l4h_uctx) in its process's VSpace, with
 * seL4_TCBFlag_trapSyscalls set and a badged copy of the vCPU endpoint as
 * fault handler.  To run it, the vCPU's kernel thread binds the vCPU's user
 * scheduling context SC_U to it, replies to its pending fault (or resumes
 * it) and blocks in seL4_Recv on the endpoint.  The kernel thread has a
 * higher priority than user contexts, so any event signalled to the vCPU's
 * bound notification preempts user execution immediately.
 *
 * Registers are kept in UML pt_regs order (gp[HOST_*]).
 */
#include "private.h"
#include "registers.h"

#ifdef __aarch64__
#include "user-arm64.h"
#else
/* gp[] indices of FS_BASE/GS_BASE (struct user_regs_struct order). */
#define HOST_FS_BASE 21
#define HOST_GS_BASE 22

/* Number of seL4_UserContext words without / with fs_base and gs_base. */
#define CTX_WORDS_NOSEG 18
#define CTX_WORDS_ALL 20

static void ctx_to_gp(const seL4_UserContext *c, unsigned long *gp, int nwords)
{
	gp[HOST_IP] = c->rip;
	gp[HOST_SP] = c->rsp;
	gp[HOST_EFLAGS] = c->rflags;
	gp[HOST_AX] = c->rax;
	gp[HOST_BX] = c->rbx;
	gp[HOST_CX] = c->rcx;
	gp[HOST_DX] = c->rdx;
	gp[HOST_SI] = c->rsi;
	gp[HOST_DI] = c->rdi;
	gp[HOST_BP] = c->rbp;
	gp[HOST_R8] = c->r8;
	gp[HOST_R9] = c->r9;
	gp[HOST_R10] = c->r10;
	gp[HOST_R11] = c->r11;
	gp[HOST_R12] = c->r12;
	gp[HOST_R13] = c->r13;
	gp[HOST_R14] = c->r14;
	gp[HOST_R15] = c->r15;
	if (nwords >= CTX_WORDS_ALL) {
		gp[HOST_FS_BASE] = c->fs_base;
		gp[HOST_GS_BASE] = c->gs_base;
	}
}

static void gp_to_ctx(const unsigned long *gp, seL4_UserContext *c)
{
	c->rip = gp[HOST_IP];
	c->rsp = gp[HOST_SP];
	c->rflags = gp[HOST_EFLAGS];
	c->rax = gp[HOST_AX];
	c->rbx = gp[HOST_BX];
	c->rcx = gp[HOST_CX];
	c->rdx = gp[HOST_DX];
	c->rsi = gp[HOST_SI];
	c->rdi = gp[HOST_DI];
	c->rbp = gp[HOST_BP];
	c->r8 = gp[HOST_R8];
	c->r9 = gp[HOST_R9];
	c->r10 = gp[HOST_R10];
	c->r11 = gp[HOST_R11];
	c->r12 = gp[HOST_R12];
	c->r13 = gp[HOST_R13];
	c->r14 = gp[HOST_R14];
	c->r15 = gp[HOST_R15];
	c->fs_base = gp[HOST_FS_BASE];
	c->gs_base = gp[HOST_GS_BASE];
}

/* Registers as seen in an UnknownSyscall fault message / reply. */
static void syscall_msg_to_gp(unsigned long *gp)
{
	gp[HOST_AX] = seL4_GetMR(seL4_UnknownSyscall_RAX);
	gp[HOST_BX] = seL4_GetMR(seL4_UnknownSyscall_RBX);
	gp[HOST_CX] = seL4_GetMR(seL4_UnknownSyscall_RCX);
	gp[HOST_DX] = seL4_GetMR(seL4_UnknownSyscall_RDX);
	gp[HOST_SI] = seL4_GetMR(seL4_UnknownSyscall_RSI);
	gp[HOST_DI] = seL4_GetMR(seL4_UnknownSyscall_RDI);
	gp[HOST_BP] = seL4_GetMR(seL4_UnknownSyscall_RBP);
	gp[HOST_R8] = seL4_GetMR(seL4_UnknownSyscall_R8);
	gp[HOST_R9] = seL4_GetMR(seL4_UnknownSyscall_R9);
	gp[HOST_R10] = seL4_GetMR(seL4_UnknownSyscall_R10);
	gp[HOST_R11] = seL4_GetMR(seL4_UnknownSyscall_R11);
	gp[HOST_R12] = seL4_GetMR(seL4_UnknownSyscall_R12);
	gp[HOST_R13] = seL4_GetMR(seL4_UnknownSyscall_R13);
	gp[HOST_R14] = seL4_GetMR(seL4_UnknownSyscall_R14);
	gp[HOST_R15] = seL4_GetMR(seL4_UnknownSyscall_R15);
	/* Linux reports the address after the syscall instruction. */
	gp[HOST_IP] = seL4_GetMR(seL4_UnknownSyscall_FaultIP) + 2;
	gp[HOST_SP] = seL4_GetMR(seL4_UnknownSyscall_SP);
	gp[HOST_EFLAGS] = seL4_GetMR(seL4_UnknownSyscall_FLAGS);
	gp[HOST_ORIG_AX] = gp[HOST_AX];
	/* syscall left rip in rcx and rflags in r11; seL4 saves them only
	 * as NextIP and FLAGS, so its RCX and R11 are stale. */
	gp[HOST_CX] = gp[HOST_IP];
	gp[HOST_R11] = gp[HOST_EFLAGS];
}

static void gp_to_syscall_msg(const unsigned long *gp)
{
	seL4_SetMR(seL4_UnknownSyscall_RAX, gp[HOST_AX]);
	seL4_SetMR(seL4_UnknownSyscall_RBX, gp[HOST_BX]);
	seL4_SetMR(seL4_UnknownSyscall_RCX, gp[HOST_CX]);
	seL4_SetMR(seL4_UnknownSyscall_RDX, gp[HOST_DX]);
	seL4_SetMR(seL4_UnknownSyscall_RSI, gp[HOST_SI]);
	seL4_SetMR(seL4_UnknownSyscall_RDI, gp[HOST_DI]);
	seL4_SetMR(seL4_UnknownSyscall_RBP, gp[HOST_BP]);
	seL4_SetMR(seL4_UnknownSyscall_R8, gp[HOST_R8]);
	seL4_SetMR(seL4_UnknownSyscall_R9, gp[HOST_R9]);
	seL4_SetMR(seL4_UnknownSyscall_R10, gp[HOST_R10]);
	seL4_SetMR(seL4_UnknownSyscall_R11, gp[HOST_R11]);
	seL4_SetMR(seL4_UnknownSyscall_R12, gp[HOST_R12]);
	seL4_SetMR(seL4_UnknownSyscall_R13, gp[HOST_R13]);
	seL4_SetMR(seL4_UnknownSyscall_R14, gp[HOST_R14]);
	seL4_SetMR(seL4_UnknownSyscall_R15, gp[HOST_R15]);
	/* seL4 restarts the thread at FaultIP. */
	seL4_SetMR(seL4_UnknownSyscall_FaultIP, gp[HOST_IP]);
	seL4_SetMR(seL4_UnknownSyscall_SP, gp[HOST_SP]);
	seL4_SetMR(seL4_UnknownSyscall_FLAGS, gp[HOST_EFLAGS]);
}

#endif

/* uctx->regs_dirty values beyond plain "dirty" */
#define DIRTY_GP	1
#define DIRTY_SEG	2	/* fs_base/gs_base changed by the kernel */

static int write_regs(struct l4h_uctx *u, const unsigned long *gp, int resume)
{
	seL4_UserContext c;
	int n = (u->regs_dirty & DIRTY_SEG) ? CTX_WORDS_ALL : CTX_WORDS_NOSEG;

	gp_to_ctx(gp, &c);
	return seL4_TCB_WriteRegisters(u->tcb, resume, 0, n, &c);
}

void l4h_user_sync_regs(struct l4h_uctx *u, unsigned long *gp)
{
	seL4_UserContext c;
	int err;

	if (u->regs_valid || u->state == L4H_UCTX_NONE)
		return;
	err = seL4_TCB_ReadRegisters(u->tcb, 0, 0, CTX_WORDS_ALL, &c);
	l4h_BUG_ON(err);
	ctx_to_gp(&c, gp, CTX_WORDS_ALL);
	u->regs_valid = 1;
}

/* Bind this vCPU's SC_U to u.  Switch-out releases it before migration. */
static void bind_sc(struct l4h_vcpu *v, struct l4h_uctx *u)
{
	int err, waited = 0;

	if (v->sc_owner == u && u->sc_vcpu == v->id)
		return;
	l4h_BUG_ON(v->sc_owner || u->sc_vcpu >= 0);
	/* seL4 refuses to bind a scheduling context without budget available
	 * (capped vCPUs exhaust SC_U) to a blocked thread, which u is: wait
	 * until the budget is refilled, within one period.  Not with
	 * seL4_Yield, which charges SC_K all of its remaining budget: under a
	 * cap, SC_K and SC_U share the vCPU's budget. */
	while ((err = seL4_TCB_SetSchedParams(u->tcb, v->ktcb, L4H_PRIO_USER, L4H_PRIO_USER,
					      v->sc_u, u->fault_ep)) == seL4_IllegalOperation) {
		l4h_wait_briefly();
		waited = 1;
	}
	l4h_BUG_ON(err);
	u->sc_vcpu = v->id;
	v->sc_owner = u;
	/* The waits took their events off the notification: signal it again,
	 * or the Recv that runs u would not return for them. */
	if (waited && __atomic_load_n(&v->ntfn_pending, __ATOMIC_ACQUIRE))
		seL4_Signal(L4H_CPTR(L4H_SLOT_VCPU(v->id) + L4H_VCPU_IPI));
}

void l4h_user_deschedule(struct l4h_uctx *u)
{
	int cpu = u->sc_vcpu;
	struct l4h_vcpu *v;

	if (cpu < 0)
		return;
	l4h_BUG_ON(cpu != l4h_this_vcpu_id());
	v = &l4h_vcpus[cpu];
	l4h_BUG_ON(v->sc_owner != u);
	l4h_BUG_ON(seL4_SchedContext_UnbindObject(v->sc_u, u->tcb));
	v->sc_owner = 0;
	u->sc_vcpu = -1;
}


int l4h_user_run(struct l4h_uctx *u, unsigned long *gp, int read_regs_on_interrupt)
{
	struct l4h_vcpu *v = l4h_this_vcpu();
	seL4_MessageInfo_t info;
	seL4_Word badge;
	int err;

	l4h_BUG_ON(u->fault_ep_vcpu != v->id);
	/* gp[] may have been modified whenever it is valid: write it back. */
	if (u->regs_valid)
		u->regs_dirty |= DIRTY_GP;
	/*
	 * A preempted context is runnable: as soon as it holds SC_U it runs
	 * whenever this kernel thread does not, and that is not only once we
	 * block in Recv below.  Under a CPU cap SC_K runs out of budget while
	 * SC_U still has some, and the context then runs ahead, possibly into
	 * its next fault, between bind_sc() and Recv.  Writing gp[] after
	 * binding would then roll its registers back to the state they had
	 * when it was preempted, and turn a queued fault into one reporting
	 * those stale registers (resuming 2 bytes into an instruction after
	 * a "syscall" stop: SIGILL, SIGSEGV, re-executed code).  Write the
	 * registers while the context has no scheduling context.
	 */
	if (u->state == L4H_UCTX_PREEMPTED && u->regs_dirty) {
		if (u->sc_vcpu >= 0)
			l4h_user_deschedule(u);
		err = write_regs(u, gp, 0);
		l4h_BUG_ON(err);
	}
	bind_sc(v, u);

	switch (u->state) {
	case L4H_UCTX_FRESH:
		/* Inactive until resumed: it cannot run before this write. */
		u->regs_dirty |= DIRTY_GP | DIRTY_SEG;
		err = write_regs(u, gp, 1);
		l4h_BUG_ON(err);
		info = seL4_Recv(v->ep, &badge, u->reply);
		break;
	case L4H_UCTX_PREEMPTED:
		/* Registers written above.  A fault it raises before we block
		 * here is queued on the endpoint and received now. */
		info = seL4_Recv(v->ep, &badge, u->reply);
		break;
	case L4H_UCTX_FAULTED:
		if (!u->regs_dirty) {
			info = seL4_ReplyRecv(v->ep, seL4_MessageInfo_new(0, 0, 0, 0), &badge, u->reply);

#ifndef __aarch64__
		} else if (u->stop == L4H_STOP_SYSCALL && !(u->regs_dirty & DIRTY_SEG) &&
			   gp[HOST_CX] == gp[HOST_IP] && gp[HOST_R11] == gp[HOST_EFLAGS]) {
			/* seL4 resumes a syscall stop with sysretq, which loads rcx
			 * and r11 from rip and rflags: like Linux, only when they
			 * match.  Otherwise (rt_sigreturn, ptrace, signal delivery)
			 * write_regs() below forces a full restore. */
			gp_to_syscall_msg(gp);
			info = seL4_ReplyRecv(v->ep,
					      seL4_MessageInfo_new(0, 0, 0, seL4_UnknownSyscall_Syscall),
					      &badge, u->reply);
#endif
		} else {
			err = write_regs(u, gp, 0);
			l4h_BUG_ON(err);
			info = seL4_ReplyRecv(v->ep, seL4_MessageInfo_new(0, 0, 0, 0), &badge, u->reply);
		}
		break;
	default:
		panic("l4h_user_run: bad uctx state %d\n", u->state);
	}
	u->regs_dirty = 0;

	if (!(badge & L4H_EP_BADGE_TASK)) {
		/* An event on the bound notification preempted user mode.  Take
		 * the scheduling context away right now: otherwise the context
		 * would run again whenever this vCPU's kernel thread blocks. */
		__atomic_or_fetch(&v->ntfn_pending, badge, __ATOMIC_RELEASE);
		l4h_user_deschedule(u);
		/* A signal from another core wakes us before this core switches
		 * away from the user context, which may fault in between; its
		 * fault is then queued on the endpoint.  Collect it now. */
		/* NBRecv prefers the bound notification over queued messages:
		 * keep draining until it reports neither. */
		for (;;) {
			badge = 0;
			info = seL4_NBRecv(v->ep, &badge, u->reply);
			if (!badge || (badge & L4H_EP_BADGE_TASK))
				break;
			__atomic_or_fetch(&v->ntfn_pending, badge, __ATOMIC_RELEASE);
		}
		if (!(badge & L4H_EP_BADGE_TASK)) {
			__atomic_or_fetch(&v->ntfn_pending, badge, __ATOMIC_RELEASE);
			u->state = L4H_UCTX_PREEMPTED;
			u->stop = L4H_STOP_INTERRUPT;
			u->regs_valid = 0;
			if (read_regs_on_interrupt)
				l4h_user_sync_regs(u, gp);
			return u->stop;
		}
		/* Report the fault now; the event stays in ntfn_pending. */
	}

	if (badge != u->badge) {

		if (__atomic_exchange_n(&l4h_provider_state()->stray_once, 1, __ATOMIC_ACQ_REL))
			for (;;)
				seL4_Yield();

		printk("l4h: vCPU %d: stray fault label %lu from %lx while running %lx\n", v->id,
		       (unsigned long)seL4_MessageInfo_get_label(info), (unsigned long)badge, u->badge);
		l4h_uctx_describe(badge);
		l4h_uctx_describe(u->badge);
		for (int c = 0; c < (int)l4h_bootinfo->nr_vcpus; c++)
			printk("vCPU %d sc_owner badge %lx\n", c,
			       l4h_vcpus[c].sc_owner ? l4h_vcpus[c].sc_owner->badge : 0);
	}
	if (badge != u->badge)
		panic("l4h: fault from unexpected user context %lx (running %lx)\n",
		      (unsigned long)badge, u->badge);

	u->state = L4H_UCTX_FAULTED;
	switch (seL4_MessageInfo_get_label(info)) {
	case seL4_Fault_UnknownSyscall:
#ifdef __aarch64__
		syscall_msg_to_gp(u, gp);
#else
		syscall_msg_to_gp(gp);
#endif
		u->regs_valid = 1;
		u->stop = L4H_STOP_SYSCALL;
		/* The syscall reply cannot carry fs/gs base; the TCB keeps them. */
		break;
	case seL4_Fault_VMFault:
		u->fault_ip = seL4_GetMR(seL4_VMFault_IP);
		u->fault_addr = seL4_GetMR(seL4_VMFault_Addr);
		u->fault_code = seL4_GetMR(seL4_VMFault_FSR);
#ifdef __aarch64__
		if ((u->fault_code & 0x3f) == 0x21) {
			/* Alignment aborts cannot be repaired by mapping the page. */
			u->exc_number = u->fault_code;
			u->regs_valid = 0;
			u->stop = L4H_STOP_EXCEPTION;
			break;
		}
		/* Normalize ESR.WnR to the shared faultinfo write bit.  Cache
		 * maintenance (DC CVAU, IC IVAU, ..., which seL4 lets EL0
		 * run) also sets WnR, with CM: it is a read, as on arm64. */
		u->fault_code = (u->fault_code & (1UL << 6)) && !(u->fault_code & (1UL << 8)) ? 2 : 0;
#endif
		if (seL4_GetMR(seL4_VMFault_PrefetchFault))
			u->fault_code |= 0x10;	/* instruction fetch */
		u->regs_valid = 0;
		u->stop = L4H_STOP_PAGEFAULT;
		break;
	case seL4_Fault_UserException:
		u->fault_ip = seL4_GetMR(seL4_UserException_FaultIP);
		u->exc_number = seL4_GetMR(seL4_UserException_Number);
		u->fault_code = seL4_GetMR(seL4_UserException_Code);
		u->regs_valid = 0;
		u->stop = L4H_STOP_EXCEPTION;
		break;
	default:
		panic("l4h: unexpected user fault label %lu\n",
		      (unsigned long)seL4_MessageInfo_get_label(info));
	}

	return u->stop;
}

void l4h_user_sync_seg(struct l4h_uctx *u, unsigned long *gp)
{
	seL4_UserContext c;

	/* gp[] is authoritative until the kernel's own change is written back. */
	if (u->state == L4H_UCTX_NONE || u->state == L4H_UCTX_FRESH ||
	    (u->regs_dirty & DIRTY_SEG))
		return;
	if (seL4_TCB_ReadRegisters(u->tcb, 0, 0, CTX_WORDS_ALL, &c) == 0) {
#ifdef __aarch64__
		gp[HOST_TLS] = c.tpidr_el0;
#else
		gp[HOST_FS_BASE] = c.fs_base;
		gp[HOST_GS_BASE] = c.gs_base;
#endif
	}
}

void l4h_user_mark_dirty(struct l4h_uctx *u, int seg)
{
	u->regs_dirty |= DIRTY_GP | (seg ? DIRTY_SEG : 0);
}

/* ---- FPU state, through the vCPU's FPU scratch area */

_Static_assert(L4H_FPU_SCRATCH_OFFSET >= sizeof(seL4_IPCBuffer), "FPU scratch overlaps IPC buffer");
_Static_assert(L4H_FPU_SCRATCH_OFFSET + seL4_FPUStateSize <= (1ul << seL4_PageBits),
	       "FPU scratch must fit in its frame");

int l4h_fpu_read(struct l4h_uctx *u, void *buf, unsigned long size)
{
	struct l4h_vcpu *v = l4h_this_vcpu();
	int err;

	if (size > seL4_FPUStateSize)
		size = seL4_FPUStateSize;
	err = seL4_TCB_ReadFPU(u->tcb, VCPU_CAP(v->id, L4H_VCPU_IPCBUF), L4H_FPU_SCRATCH_OFFSET);
	if (!err)
		memcpy(buf, (char *)v->ipcbuf + L4H_FPU_SCRATCH_OFFSET, size);
	return err;
}

int l4h_fpu_write(struct l4h_uctx *u, const void *buf, unsigned long size)
{
	struct l4h_vcpu *v = l4h_this_vcpu();

	if (size > seL4_FPUStateSize)
		size = seL4_FPUStateSize;
	memcpy((char *)v->ipcbuf + L4H_FPU_SCRATCH_OFFSET, buf, size);
	return seL4_TCB_WriteFPU(u->tcb, VCPU_CAP(v->id, L4H_VCPU_IPCBUF), L4H_FPU_SCRATCH_OFFSET);
}

unsigned long l4h_fpu_state_size(void)
{
	return seL4_FPUStateSize;
}

/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Interface between the l4h kernel proper (built against kernel headers)
 * and arch/l4h/os-sel4 (built against libsel4, without kernel headers).
 * Only plain C types cross this boundary.
 */
#ifndef __L4H_SYS_H
#define __L4H_SYS_H

#include <l4h/abi.h>

/* seL4 object types used by the guest (values match libsel4). */
enum l4h_obj_type {
	L4H_OBJ_UNTYPED,
	L4H_OBJ_TCB,
	L4H_OBJ_ENDPOINT,
	L4H_OBJ_NOTIFICATION,
	L4H_OBJ_CNODE,
	L4H_OBJ_SCHED_CONTEXT,
	L4H_OBJ_REPLY,
	L4H_OBJ_FRAME,
	L4H_OBJ_PT,	/* last-level page table */
	L4H_OBJ_PD,	/* x86_64: page directory */
	L4H_OBJ_PDPT,	/* x86_64: page directory pointer table */
	L4H_OBJ_LARGE_FRAME,	/* 2 MiB RAM frame */
	L4H_OBJ_NR,
};

/* Byte size (log2) of an object of the given type (size_bits for variable
 * sized ones). */
int l4h_obj_bits(int type, int size_bits);

/* Paging structure levels below the VSpace root, from the leaf upwards. */
#define L4H_NR_PT_LEVELS 3
extern const int l4h_pt_level_obj[L4H_NR_PT_LEVELS];
extern const int l4h_pt_level_shift[L4H_NR_PT_LEVELS]; /* VA bits mapped by one table */

/* Error codes are seL4_Error values; 0 is success. */
#define L4H_ERR_FAILED_LOOKUP	6
#define L4H_ERR_DELETE_FIRST	8

/* ---- capability management (cptrs as in l4h/abi.h) */
int l4h_retype(unsigned long ut, int type, int size_bits, unsigned long node_index,
	       int node_depth, unsigned long offset, unsigned long n);
int l4h_cnode_copy(unsigned long dst, int dst_depth, unsigned long src, int src_depth, int rights);
int l4h_cnode_mint(unsigned long dst, int dst_depth, unsigned long src, int src_depth,
		   int rights, unsigned long badge);
int l4h_cnode_mutate(unsigned long dst, int dst_depth, unsigned long src, int src_depth,
		     unsigned long data);
int l4h_cnode_delete(unsigned long cap, int depth);
int l4h_cnode_revoke(unsigned long cap, int depth);

#define L4H_RIGHT_WRITE		1
#define L4H_RIGHT_READ		2
#define L4H_RIGHT_GRANT		4
#define L4H_RIGHT_GRANT_REPLY	8
#define L4H_RIGHTS_ALL		15

/* ---- address spaces */
#define L4H_PROT_READ		1
#define L4H_PROT_WRITE		2
#define L4H_PROT_EXEC		4
/* With lowered rights for a frame already mapped there: leave the TLBs to
 * l4h_vspace_flush() (x86_64; elsewhere the map flushes them itself). */
#define L4H_PROT_DEFER_FLUSH	8
/* Native 2 MiB leaf; also selects the ARM instruction-cache range. */
#define L4H_PROT_LARGE		16
int l4h_page_map(unsigned long frame, unsigned long vspace, unsigned long va, int prot);
/* `n` 4 KiB aliases of large `frame` from byte `offset`, into slots like
 * l4h_retype()'s. */
int l4h_page_derive_subframes(unsigned long frame, unsigned long offset, unsigned long node_index,
			      int node_depth, unsigned long node_offset, unsigned long n);
int l4h_page_unmap(unsigned long frame);
int l4h_page_test_and_clear_accessed(unsigned long frame, int *accessed);
int l4h_vspace_flush(unsigned long vspace);
int l4h_pt_map(int type, unsigned long table, unsigned long vspace, unsigned long va);

/* ---- threads */
int l4h_tcb_configure_user(unsigned long tcb, unsigned long cspace, unsigned long vspace);
int l4h_tcb_set_space(unsigned long tcb, unsigned long fault_ep, unsigned long cspace,
		      unsigned long vspace);
int l4h_tcb_sched(unsigned long tcb, unsigned long authority, int prio, unsigned long sc,
		  unsigned long fault_ep);
int l4h_tcb_set_flags(unsigned long tcb, unsigned long clear, unsigned long set);
int l4h_tcb_resume(unsigned long tcb);
int l4h_tcb_suspend(unsigned long tcb);
int l4h_tcb_bind_notification(unsigned long tcb, unsigned long ntfn);
int l4h_sc_unbind(unsigned long sc);
void l4h_signal(unsigned long ntfn);
void l4h_yield(void);

/* ---- per-vCPU state shared with os-sel4 */
struct l4h_vcpu {
	int id;
	int online;
	unsigned long ktcb, ep, ntfn, sc_u;
	struct l4h_event_page *evt;
	void *ipcbuf;
	/* Absolute TSC deadline of the armed clockevent, 0 if none. */
	volatile unsigned long long timer_deadline;
	/* Bitmask of pending IPI reasons, set by other vCPUs. */
	volatile unsigned long ipi_pending;
	/* Set (with an atomic OR) when the bound notification may hold bits
	 * we have not yet collected. */
	volatile unsigned long ntfn_pending;
	/* Interrupt masking (UML "signals"): enabled flag and the deferred
	 * delivery flag. */
	int irqs_enabled;
	int irqs_pending;
	int in_irq;
	int in_console;		/* writing its console ring */
	/* The user context currently holding SC_U on this vCPU. */
	struct l4h_uctx *sc_owner;
	/* Stack and entry for secondary vCPU startup. */
	unsigned long start_sp;
	void (*start_fn)(int cpu);
	void *start_task;		/* idle task (struct task_struct *) */
	unsigned long long tsc_last_idle;
};

extern struct l4h_vcpu l4h_vcpus[L4H_MAX_VCPUS];
extern const struct l4h_bootinfo *l4h_bootinfo;
extern unsigned long long l4h_tsc_hz;

struct l4h_vcpu *l4h_this_vcpu(void);
int l4h_this_vcpu_id(void);

/* ---- user contexts (one per Linux thread that runs in user mode) */
enum l4h_uctx_state {
	L4H_UCTX_NONE = 0,	/* no TCB yet */
	L4H_UCTX_FRESH,		/* TCB exists, never started or suspended */
	L4H_UCTX_FAULTED,	/* blocked on a fault, reply pending in `reply` */
	L4H_UCTX_PREEMPTED,	/* runnable but descheduled (SC unbound) */
};

/* Why the user context stopped (struct l4h_uctx.stop). */
enum l4h_stop {
	L4H_STOP_NONE = 0,
	L4H_STOP_SYSCALL,
	L4H_STOP_PAGEFAULT,
	L4H_STOP_EXCEPTION,
	L4H_STOP_INTERRUPT,	/* preempted by an event, not a fault */
};

struct l4h_uctx {
	unsigned long tcb;	/* cptr, 0 if none */
	unsigned long reply;	/* cptr of this context's reply object */
	unsigned long fault_ep;	/* cptr of the badged fault endpoint in use */
	int fault_ep_vcpu;	/* vCPU whose EP fault_ep refers to, -1 none */
	int sc_vcpu;		/* vCPU whose SC_U is bound to the TCB, -1 none */
	int state;		/* enum l4h_uctx_state */
	int stop;		/* enum l4h_stop */
	unsigned long vspace;	/* VSpace the TCB is currently bound to */
	unsigned long badge;	/* L4H_EP_BADGE_TASK | id */
	/* Fault details for L4H_STOP_PAGEFAULT / L4H_STOP_EXCEPTION. */
	unsigned long fault_addr;
	unsigned long fault_ip;
	unsigned long fault_code;	/* seL4 FSR (x86 PF error code) / exception code */
	unsigned long exc_number;
	/* General purpose registers are valid in the caller's gp[] array. */
	int regs_valid;
	int regs_dirty;
	/* FPU state location: see L4H_FP_* */
	int fp_state;
};



#define L4H_FP_IN_TCB		0	/* only the TCB has it */
#define L4H_FP_IN_REGS		1	/* copied into regs.fp, unchanged */
#define L4H_FP_DIRTY		2	/* regs.fp modified, TCB must be updated */

/* Run user context `u` on this vCPU until it stops (fault) or an event
 * arrives.  gp[] holds the registers in UML pt_regs order; they are written
 * to the TCB if marked dirty, and are valid afterwards only if
 * u->regs_valid (syscall stops, or interrupts with read_regs_on_interrupt).
 * The caller must have set u->fault_ep for this vCPU.  Returns u->stop. */
int l4h_user_run(struct l4h_uctx *u, unsigned long *gp, int read_regs_on_interrupt);
/* Make gp[] current if it is not (reads the TCB). */
void l4h_user_sync_regs(struct l4h_uctx *u, unsigned long *gp);
/* gp[] was modified by the kernel; seg != 0 if fs/gs base changed. */
void l4h_user_mark_dirty(struct l4h_uctx *u, int seg);
/* Copy the TCB's fs/gs base into gp[] (they are not part of syscall
 * fault messages, and user code may change them with wrfsbase). */
void l4h_user_sync_seg(struct l4h_uctx *u, unsigned long *gp);
/* Give up the user scheduling context if `u` holds one. */
void l4h_user_deschedule(struct l4h_uctx *u);
int l4h_fpu_read(struct l4h_uctx *u, void *buf, unsigned long size);
int l4h_fpu_write(struct l4h_uctx *u, const void *buf, unsigned long size);
unsigned long l4h_fpu_state_size(void);

/* ---- events, timers, idle */
unsigned long long l4h_rdtsc(void);
void l4h_timer_arm(unsigned long long tsc_deadline);
/* Collect all pending event sources on this vCPU; returns nonzero if any
 * were found and leaves them in *timer, *ipi and events[]. */
int l4h_collect_events(int *timer, unsigned long *ipi, unsigned long *events);
/* Block this vCPU until something happens. */
void l4h_idle_wait(void);
void l4h_wait_briefly(void);
/* Cheap check for undelivered events on this vCPU. */
int l4h_events_pending(void);
/* Deliver pending events (calls l4h_deliver_events). */
void l4h_dispatch_pending(void);
int l4h_irqs_enabled(void);
/* Kick another vCPU (IPI reason bitmask). */
void l4h_send_ipi(int cpu, unsigned long reasons);

/* Implemented by the kernel: deliver collected events (irqs disabled). */
void l4h_deliver_events(int timer, unsigned long ipi, unsigned long *events);
/* Deliver the events that stopped user mode: they interrupted user code. */
void l4h_dispatch_user_interrupt(void);

/* ---- console, power, hypercalls */
/* Console output, which never waits: what does not fit in the vCPU's ring
 * is counted as lost.  try_write returns how much it took instead; the
 * console device's event follows when there is room. */
void l4h_console_write(const char *s, unsigned int n);
unsigned int l4h_console_try_write(const char *s, unsigned int n);
void __attribute__((noreturn)) l4h_power(int how);
unsigned long long l4h_steal_ns(int cpu);
unsigned long l4h_hypercall(unsigned long label, unsigned long *mrs, int n_in, int n_out);

/* ---- SMP */
int l4h_start_vcpu(int cpu, unsigned long sp, void (*fn)(int cpu), void *task);

#endif /* __L4H_SYS_H */

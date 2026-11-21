/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Version 1 guest/provider ABI, for 64-bit x86_64 and AArch64.
 * The provider implements these operations using the selected microkernel.
 * Structure layouts and function signatures are append-only within this version.
 * Only plain C types cross this boundary.
 */
#ifndef L4H_GUEST_H
#define L4H_GUEST_H

#include <l4h/abi.h>

/* Logical object kinds. The provider translates these to microkernel types. */
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
	L4H_OBJ_VCPU,		/* x86_64 with VT-x */
	L4H_OBJ_EPT_PT,
	L4H_OBJ_EPT_PD,
	L4H_OBJ_EPT_PDPT,
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
/* Device memory (non-cacheable), for Stage-2 maps of device frames such
 * as GICv2's GICV (l4h_arm_s2_map_frame). */
#define L4H_PROT_DEVICE		32
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
	/* Times this vCPU blocked waiting for a spinlock (l4h_pv_wait()). */
	unsigned long pv_waits;
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

/* ---- seL4 VCPUs and EPT (x86_64, arch/l4h/kvm) */
enum {
	L4H_VMX_RAX, L4H_VMX_RBX, L4H_VMX_RCX, L4H_VMX_RDX, L4H_VMX_RSI, L4H_VMX_RDI,
	L4H_VMX_RBP, L4H_VMX_R8, L4H_VMX_R9, L4H_VMX_R10, L4H_VMX_R11, L4H_VMX_R12,
	L4H_VMX_R13, L4H_VMX_R14, L4H_VMX_R15, L4H_VMX_NR_GP,
};

/* What a VMEnter returned.  Without `fault` a notification ended it: there
 * was no exit to handle, and intr_info still holds an event not delivered.
 * Fields an exit does not define are 0; RSP and CR3 are for l4h_vcpu_read()
 * on VT-x.  On AMD (patch 0040) the fields have SVM's meaning: reason is the
 * exit code, qualification and gpa EXITINFO1 and 2, interruptibility the
 * interrupt state, and idt_vector_* EXITINTINFO. */
struct l4h_vmexit {
	int fault;
	unsigned int reason, instr_len;
	unsigned int intr_info, exit_intr_info, exit_intr_error;
	unsigned int idt_vector_info, idt_vector_error, interruptibility;
	unsigned long rip, rflags, cr2, qualification, gpa;
	unsigned long cr3;			/* AMD only; 0 on VT-x */
	unsigned long gp[L4H_VMX_NR_GP];	/* L4H_VMX_* */
};

int l4h_vcpu_set_tcb(unsigned long vcpu, unsigned long tcb);
int l4h_tcb_set_ept(unsigned long tcb, unsigned long ept);
unsigned long l4h_vcpu_read(unsigned long vcpu, unsigned long field, int *err);
int l4h_vcpu_write(unsigned long vcpu, unsigned long field, unsigned long value);
int l4h_vcpu_read_msr(unsigned long vcpu, unsigned long msr, unsigned long *value);
int l4h_vcpu_write_msr(unsigned long vcpu, unsigned long msr, unsigned long value);
int l4h_vcpu_write_cr2(unsigned long vcpu, unsigned long value);
int l4h_vcpu_write_xcr0(unsigned long vcpu, unsigned long long value);
int l4h_vcpu_flush_tlb(unsigned long vcpu);
/* AMD: count (at most 32) words of the VMCB from byte offset, and one word. */
int l4h_vcpu_read_vmcb(unsigned long vcpu, unsigned long offset, unsigned long count,
		       unsigned long *words);
int l4h_vcpu_write_vmcb(unsigned long vcpu, unsigned long offset, unsigned long value,
			unsigned long *written);
int l4h_vcpu_write_regs(unsigned long vcpu, const unsigned long *gp);
void l4h_vcpu_enter(struct l4h_vmexit *x, unsigned long rip, unsigned long controls,
		    unsigned long intr_info);
int l4h_ept_map_table(int level, unsigned long table, unsigned long ept, unsigned long gpa);
int l4h_ept_map_frame(unsigned long frame, unsigned long ept, unsigned long gpa, int writable);

/* ---- FL4 VCPUs and Stage-2 (AArch64 at EL2, arch/l4h/kvm on arm64;
 * L4H_PROVIDER_ARM_VIRT).  The provider translates these to FL4's
 * seL4_ARM_VCPU and Stage-2 invocations. */

/* VCPU registers: FL4's seL4_VCPUReg numbering. */
enum {
	L4H_ARM_VCPUREG_SCTLR = 0,
	L4H_ARM_VCPUREG_CPACR = 1,
	L4H_ARM_VCPUREG_TCR = 2,
	L4H_ARM_VCPUREG_TTBR0 = 3,
	L4H_ARM_VCPUREG_TTBR1 = 4,
	L4H_ARM_VCPUREG_MAIR = 5,
	L4H_ARM_VCPUREG_AMAIR = 6,
	L4H_ARM_VCPUREG_CIDR = 7,
	L4H_ARM_VCPUREG_AFSR0 = 8,
	L4H_ARM_VCPUREG_AFSR1 = 9,
	L4H_ARM_VCPUREG_ESR = 10,
	L4H_ARM_VCPUREG_FAR = 11,
	L4H_ARM_VCPUREG_PAR = 12,
	L4H_ARM_VCPUREG_VBAR = 13,
	L4H_ARM_VCPUREG_TPIDR_EL1 = 14,
	L4H_ARM_VCPUREG_VMPIDR_EL2 = 15,
	L4H_ARM_VCPUREG_SP_EL1 = 16,
	L4H_ARM_VCPUREG_ELR_EL1 = 17,
	L4H_ARM_VCPUREG_SPSR_EL1 = 18,
	L4H_ARM_VCPUREG_CSSELR_EL1 = 19,
	L4H_ARM_VCPUREG_VDISR_EL2 = 20,
	L4H_ARM_VCPUREG_CNTV_CTL = 21,
	L4H_ARM_VCPUREG_CNTV_CVAL = 22,
	L4H_ARM_VCPUREG_CNTVOFF = 23,
	L4H_ARM_VCPUREG_CNTKCTL_EL1 = 24,
	L4H_ARM_VCPUREG_VPIDR_EL2 = 25,
	L4H_ARM_VCPUREG_HCR_EL2 = 26,
	L4H_ARM_VCPUREG_VSESR_EL2 = 27,
	L4H_ARM_VCPUREG_ACTLR_EL1 = 28,
	L4H_ARM_VCPUREG_MDSCR_EL1 = 29,
	L4H_ARM_VCPUREG_MDCCINT_EL1 = 30,
	L4H_ARM_VCPUREG_FAR_EL2 = 31,
	L4H_ARM_VCPUREG_HPFAR_EL2 = 32,
	L4H_ARM_VCPUREG_ESR_EL2 = 33,
	L4H_ARM_VCPUREG_VGIC_VTR = 34,
	L4H_ARM_VCPUREG_VGIC_HCR = 35,
	L4H_ARM_VCPUREG_VGIC_VMCR = 36,
	L4H_ARM_VCPUREG_VGIC_MISR = 37,
	L4H_ARM_VCPUREG_VGIC_EISR = 38,
	L4H_ARM_VCPUREG_VGIC_ELRSR = 39,
	L4H_ARM_VCPUREG_VGIC_AP0R0 = 40,
	L4H_ARM_VCPUREG_VGIC_AP0R1 = 41,
	L4H_ARM_VCPUREG_VGIC_AP0R2 = 42,
	L4H_ARM_VCPUREG_VGIC_AP0R3 = 43,
	L4H_ARM_VCPUREG_VGIC_AP1R0 = 44,
	L4H_ARM_VCPUREG_VGIC_AP1R1 = 45,
	L4H_ARM_VCPUREG_VGIC_AP1R2 = 46,
	L4H_ARM_VCPUREG_VGIC_AP1R3 = 47,
	L4H_ARM_VCPUREG_VGIC_LR0 = 48,
	L4H_ARM_VCPUREG_VGIC_LR1 = 49,
	L4H_ARM_VCPUREG_VGIC_LR2 = 50,
	L4H_ARM_VCPUREG_VGIC_LR3 = 51,
	L4H_ARM_VCPUREG_VGIC_LR4 = 52,
	L4H_ARM_VCPUREG_VGIC_LR5 = 53,
	L4H_ARM_VCPUREG_VGIC_LR6 = 54,
	L4H_ARM_VCPUREG_VGIC_LR7 = 55,
	L4H_ARM_VCPUREG_VGIC_LR8 = 56,
	L4H_ARM_VCPUREG_VGIC_LR9 = 57,
	L4H_ARM_VCPUREG_VGIC_LR10 = 58,
	L4H_ARM_VCPUREG_VGIC_LR11 = 59,
	L4H_ARM_VCPUREG_VGIC_LR12 = 60,
	L4H_ARM_VCPUREG_VGIC_LR13 = 61,
	L4H_ARM_VCPUREG_VGIC_LR14 = 62,
	L4H_ARM_VCPUREG_VGIC_LR15 = 63,
	L4H_ARM_VCPUREG_NR = 64,
};

/* l4h_arm_vcpu_read_state/write_state: the groups of struct
 * l4h_arm_vcpu_state they transfer. */
#define L4H_ARM_VCPU_STATE_EL1_SYSREGS	(1ull << 0)
#define L4H_ARM_VCPU_STATE_HYP		(1ull << 1)
#define L4H_ARM_VCPU_STATE_TIMER	(1ull << 2)
#define L4H_ARM_VCPU_STATE_VGIC		(1ull << 3)
#define L4H_ARM_VCPU_STATE_GPRS		(1ull << 4)
#define L4H_ARM_VCPU_STATE_ALL		0x1full

/* A VCPU's state in a RAM frame, at a 64-byte aligned offset: FL4's
 * seL4_ARM_VCPUState.  regs[] by L4H_ARM_VCPUREG_*; gprs[] X0..X30,
 * SP_EL0, ELR_EL1 (PC), SPSR_EL1, FAULT_IP, TPIDR_EL0, TPIDRRO_EL0. */
struct l4h_arm_vcpu_state {
	l4h_u64 regs[64];
	l4h_u64 gprs[37];
	l4h_u64 vppi_masked;
	l4h_u64 reserved[26];
};
_Static_assert(sizeof(struct l4h_arm_vcpu_state) == 1024, "l4h_arm_vcpu_state layout");

/* Why l4h_arm_vcpu_run returned. */
enum l4h_arm_vcpu_stop {
	L4H_ARM_STOP_NONE = 0,
	L4H_ARM_STOP_VMFAULT,		/* Stage-2 abort: ipa, esr, is_prefetch */
	L4H_ARM_STOP_VCPUFAULT,		/* trapped instruction: esr (ESR_EL2) */
	L4H_ARM_STOP_VGIC_MAINT,	/* VGIC maintenance: vgic_idx if valid */
	L4H_ARM_STOP_VPPI,		/* virtual PPI (timer): vppi_irq */
	L4H_ARM_STOP_INTERRUPT,		/* an event of this vCPU stopped the guest */
	L4H_ARM_STOP_OTHER,		/* another fault */
};

struct l4h_arm_vmexit {
	int stop;		/* enum l4h_arm_vcpu_stop */
	int is_prefetch;
	int vgic_idx_valid;
	unsigned int vgic_idx;
	unsigned long esr;
	unsigned long ipa;
	unsigned long fault_ip;
	unsigned long vppi_irq;
	unsigned long far;	/* FAR_EL2 of a Stage-2 abort or trap */
	unsigned long hpfar;	/* HPFAR_EL2 of a trap */
};

int l4h_arm_vcpu_set_tcb(unsigned long vcpu, unsigned long tcb);
int l4h_arm_vcpu_read_reg(unsigned long vcpu, unsigned long field, unsigned long *val);
int l4h_arm_vcpu_write_reg(unsigned long vcpu, unsigned long field, unsigned long val);
int l4h_arm_vcpu_inject_irq(unsigned long vcpu, unsigned int virq, unsigned int prio,
			    unsigned int group, unsigned int index);
int l4h_arm_vcpu_ack_vppi(unsigned long vcpu, unsigned long irq);
/* Bulk state (L4H_ARM_VCPU_STATE_* groups in `mask`) to or from the
 * struct l4h_arm_vcpu_state at `offset` in RAM frame `frame`. */
int l4h_arm_vcpu_read_state(unsigned long vcpu, unsigned long frame, unsigned long offset,
			    unsigned long mask);
int l4h_arm_vcpu_write_state(unsigned long vcpu, unsigned long frame, unsigned long offset,
			     unsigned long mask);
/* A Stage-2 page table (L4H_OBJ_EPT_*) into `s2_root` (an L4H_SLOT_EPT_POOL
 * root) at `ipa`, and a frame with L4H_PROT_* rights. */
int l4h_arm_s2_map_table(unsigned long table, unsigned long s2_root, unsigned long ipa);
int l4h_arm_s2_map_frame(unsigned long frame, unsigned long s2_root, unsigned long ipa, int prot);
/* Run the guest TCB `u` (bound to a VCPU, its VSpace a Stage-2 root) on this
 * vCPU, as l4h_user_run does a user context, until it faults or an event
 * of this vCPU arrives.  Its registers are the VCPU's state
 * (l4h_arm_vcpu_write_state), not gp[].  Returns x->stop. */
int l4h_arm_vcpu_run(struct l4h_uctx *u, struct l4h_arm_vmexit *x);
/* Run VCPU `vcpu` (bound to a TCB of ours on a Stage-2 root) on this
 * vCPU's own thread until an exit or one of its events (FL4's
 * seL4_ARM_VCPU_Run): the state groups in `in_mask` go in from, and those
 * in `out_mask` come back to, the struct l4h_arm_vcpu_state at
 * L4H_VCPU_STATE_OFFSET in this vCPU's IPC buffer.  Returns x->stop. */
int l4h_arm_vcpu_enter(unsigned long vcpu, unsigned long in_mask, unsigned long out_mask,
		       struct l4h_arm_vmexit *x);

/* ---- events, timers, idle */
unsigned long long l4h_rdtsc(void);
/* Host counter ticks (l4h_rdtsc) as nanoseconds. */
unsigned long long l4h_ticks_to_ns(unsigned long long ticks);
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
/* Paravirtual spinlocks: block while *ptr == val; wake a blocked vCPU. */
void l4h_pv_wait(const unsigned char *ptr, unsigned char val);
void l4h_pv_kick(int cpu);

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

#endif /* L4H_GUEST_H */

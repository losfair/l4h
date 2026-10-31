// SPDX-License-Identifier: GPL-2.0
/*
 * The tests of the ABI test module, against libsel4 (see main.c):
 *   - a user thread with seL4_TCBFlag_trapSyscalls in a process VSpace,
 *     whose Linux-style syscalls and page faults arrive as fault IPC, with
 *     every seL4 syscall number (E1),
 *   - seL4_TCB_ReadFPU of the user thread's FPU state (E2),
 *   - seL4 debug syscalls refused to guest threads,
 *   - seL4_X86_ExecuteNever mappings,
 *   - hardware accessed bits, AArch64 access-flag faults, stale mappings,
 *   - seL4_TCB_SetTimer delivering a timer badge (E3),
 *   - the I/O pool: a virtio-blk driver that ignores ACCESS_PLATFORM or
 *     puts rings or buffers outside the pool is refused,
 *   - seL4's semantics of Untyped copies, which guest RAM relies on, and
 *     the RAM blocks the host gives.
 * A module has no thread-local storage: libsel4's IPC buffer pointer is a
 * plain variable, set to the vCPU's buffer, which is fine while interrupts
 * are off on that vCPU.
 */
#include <stdint.h>
#include <stddef.h>
#include <sel4/macros.h>
#undef LIBSEL4_THREAD_LOCAL
#define LIBSEL4_THREAD_LOCAL
#include <sel4/sel4.h>
#include <l4h_sys.h>
#include "abitest.h"

seL4_IPCBuffer *__sel4_ipc_buffer;
char __sel4_print_error;

extern int _printk(const char *fmt, ...);
#define say(fmt, ...) _printk("\0016abitest: " fmt "\n", ##__VA_ARGS__)

static struct abitest *t;
static const struct l4h_bootinfo *bi;
static struct l4h_vcpu *vcpu;
static seL4_CPtr ep, reply, utcb;

#define CHECK(cond, what, v)                                                        \
	do {                                                                         \
		if (!(cond)) {                                                       \
			_printk("\0013ABITEST: FAIL %s %#lx\n", what, (unsigned long)(v)); \
			return -1;                                                   \
		}                                                                    \
	} while (0)
#define TRY(x) do { if (x) return -1; } while (0)

/* The time counter seL4 deadlines are in: TSC / virtual counter. */
static inline uint64_t rdtsc(void)
{
#ifdef __aarch64__
	uint64_t v;
	__asm__ volatile("isb; mrs %0, cntvct_el0" : "=r"(v));
	return v;
#else
	uint32_t lo, hi;
	__asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
	return ((uint64_t)hi << 32) | lo;
#endif
}

/* Architecture differences of the test. */
#ifdef __aarch64__
#define SYS_getpid		172
#define SYS_exit		93
/* Linux syscall number (x8; patch 0007) and the seL4 one (x7). */
#define MR_SP		seL4_UnknownSyscall_SP
#define MR_SYSNO		seL4_UnknownSyscall_Syscall
#define MR_SEL4NO		seL4_UnknownSyscall_X7
#define MR_RET			seL4_UnknownSyscall_X0
#define MR_ARG0			seL4_UnknownSyscall_X0
#define MR_COUNT		seL4_UnknownSyscall_Length
#define SYSCALL_INSN_LEN	4
#define FPU_V0_OFFSET		0
#define FRAME_TYPE		seL4_ARM_SmallPageObject
#define LARGE_FRAME_TYPE	seL4_ARM_LargePageObject
#define frame_derive		seL4_ARM_Page_DeriveSubframe
#define frame_address		seL4_ARM_Page_GetAddress
#define frame_unmap		seL4_ARM_Page_Unmap
#define frame_accessed		seL4_ARM_Page_TestAndClearAccessed
#define accessed_result		seL4_ARM_Page_TestAndClearAccessed_t
#else
#define SYS_getpid		39
#define SYS_exit		60
#define MR_SP		seL4_UnknownSyscall_SP
#define MR_SYSNO		seL4_UnknownSyscall_RAX
#define MR_SEL4NO		seL4_UnknownSyscall_RDX
#define MR_RET			seL4_UnknownSyscall_RAX
#define MR_ARG0			seL4_UnknownSyscall_RDI
#define MR_COUNT		seL4_UnknownSyscall_Syscall
#define SYSCALL_INSN_LEN	2
#define FPU_V0_OFFSET		160
#define FRAME_TYPE		seL4_X86_4K
#define LARGE_FRAME_TYPE	seL4_X86_LargePageObject
#define frame_derive		seL4_X86_Page_DeriveSubframe
#define frame_address		seL4_X86_Page_GetAddress
#define frame_unmap		seL4_X86_Page_Unmap
#define frame_accessed		seL4_X86_Page_TestAndClearAccessed
#define accessed_result		seL4_X86_Page_TestAndClearAccessed_t
#endif

/* ---- capabilities: slots are depth-64 CPtrs into level-2 CNodes */

static seL4_Word node_index(seL4_CPtr slot)
{
	return slot >> L4H_L2_INDEX_BITS;
}

static seL4_Word node_offset(seL4_CPtr slot)
{
	return slot & ((1ul << L4H_L2_INDEX_BITS) - 1);
}

/* Retype one object from `ut` into a new slot; 0 on failure. */
static int retype(seL4_CPtr ut, seL4_Word type, seL4_Word bits, seL4_CPtr *out)
{
	seL4_CPtr s = abitest_slot();

	*out = s;
	return s ? seL4_Untyped_Retype(ut, type, bits, L4H_CNODE_CPTR, node_index(s), L4H_ROOT_DEPTH,
				       node_offset(s), 1)
		 : seL4_NotEnoughMemory;
}

static seL4_CPtr copy_cap(seL4_CPtr src)
{
	seL4_CPtr s = abitest_slot();

	if (s && seL4_CNode_Copy(L4H_CNODE_CPTR, s, 64, L4H_CNODE_CPTR, src, 64, seL4_AllRights))
		return 0;
	return s;
}

static seL4_CPtr mint_cap(seL4_CPtr src, seL4_Word badge)
{
	seL4_CPtr s = abitest_slot();

	if (s && seL4_CNode_Mint(L4H_CNODE_CPTR, s, 64, L4H_CNODE_CPTR, src, 64, seL4_AllRights, badge))
		return 0;
	return s;
}

/* Map paging structure `pt` of `level` (0: last) at `va`. */
static int pt_map(int level, seL4_CPtr pt, seL4_Word va)
{
#ifdef __aarch64__
	(void)level;
	return seL4_ARM_PageTable_Map(pt, t->vspace, va, seL4_ARM_Default_VMAttributes);
#else
	if (level == 0)
		return seL4_X86_PageTable_Map(pt, t->vspace, va, seL4_X86_Default_VMAttributes);
	if (level == 1)
		return seL4_X86_PageDirectory_Map(pt, t->vspace, va, seL4_X86_Default_VMAttributes);
	return seL4_X86_PDPT_Map(pt, t->vspace, va, seL4_X86_Default_VMAttributes);
#endif
}

/* Map `frame` at `va` in the test's VSpace. */
static int map_user_frame(seL4_CPtr frame, seL4_Word va, seL4_CapRights_t rights, int lowest)
{
	static const int levels[L4H_NR_PT_LEVELS] = { L4H_OBJ_PT, L4H_OBJ_PD, L4H_OBJ_PDPT };

	for (int tries = 0; tries < 5; tries++) {
#ifdef __aarch64__
		int err = seL4_ARM_Page_Map(frame, t->vspace, va, rights, seL4_ARM_Default_VMAttributes);
#else
		int err = seL4_X86_Page_Map(frame, t->vspace, va, rights, seL4_X86_Default_VMAttributes);
#endif
		if (err == 0)
			return 0;
		CHECK(err == seL4_FailedLookup, "page map err=", err);
		/* Add the missing paging structure: the lowest level that maps. */
		for (int l = lowest; l < L4H_NR_PT_LEVELS; l++) {
			seL4_CPtr pt = abitest_obj(levels[l], 0);

			CHECK(pt, "no page table", l);
			err = pt_map(l, pt, va);
			if (err != seL4_FailedLookup)
				break;
		}
		CHECK(err == 0, "pt map err=", err);
	}
	CHECK(0, "map_user_page va=", va);
	return -1;
}

static int map_user_page(seL4_CPtr frame, seL4_Word va, seL4_CapRights_t rights)
{
	return map_user_frame(frame, va, rights, 0);
}

/* Receive from the test's endpoint.  The vCPU's notification is bound to
 * this thread, so its signals (Linux's timer, IPIs, device events) arrive
 * here too: they are Linux's, which finds them in ntfn_pending. */
static seL4_MessageInfo_t recv(seL4_Word *badge)
{
	for (;;) {
		seL4_MessageInfo_t info = seL4_Recv(ep, badge, reply);

		if (*badge & L4H_EP_BADGE_TASK)
			return info;
		__atomic_fetch_or(&vcpu->ntfn_pending, *badge, __ATOMIC_SEQ_CST);
	}
}

static int write_pc(seL4_UserContext *regs, seL4_Word pc)
{
#ifdef __aarch64__
	regs->pc = pc;
#else
	regs->rip = pc;
#endif
	return seL4_TCB_WriteRegisters(utcb, 1, 0, sizeof(*regs) / sizeof(seL4_Word), regs);
}

/* ---- a user thread: E1, E2, debug syscalls, execute-never */

static int user_test(void)
{
	seL4_CPtr prog_frame = copy_cap(L4H_FRAME_CPTR(t->user_gpa));
	seL4_CPtr vcpu_caps = L4H_SLOT_VCPU(t->cpu);
	seL4_Word user_debug_va = ABITEST_USER_VA + (user_debug - user_prog);
	seL4_UserContext regs = { 0 };
	seL4_MessageInfo_t info;
	seL4_Word badge;
	/* Deliberately unmapped: entry/return must not touch the user stack. */
	unsigned long user_sp = 0x7f0000000000;
	int err;

	CHECK(prog_frame, "no program frame copy", 0);
	accessed_result ar = frame_accessed(prog_frame);
	CHECK(ar.error == seL4_IllegalOperation, "accessed on unmapped cap=", ar.error);
	TRY(map_user_page(prog_frame, ABITEST_USER_VA, seL4_CanRead));
	ar = frame_accessed(prog_frame);
	CHECK(ar.error == 0, "clear program accessed=", ar.error);
	ar = frame_accessed(prog_frame);
	CHECK(ar.error == 0 && ar.accessed == 0, "program accessed not cleared=", ar.accessed);
	ep = abitest_obj(L4H_OBJ_ENDPOINT, 0);
	reply = abitest_obj(L4H_OBJ_REPLY, 0);
	utcb = abitest_obj(L4H_OBJ_TCB, 0);
	CHECK(ep && reply && utcb, "no objects", 0);
	seL4_CPtr fault_ep = mint_cap(ep, L4H_EP_BADGE_TASK | 1);
	CHECK(fault_ep, "no fault endpoint", 0);
	/* User threads get an empty CSpace; with trapSyscalls it is never used. */
	err = seL4_TCB_Configure(utcb, L4H_CPTR2(L4H_SLOT_META, L4H_META_DYN_BASE), 0, t->vspace, 0, 0,
				 seL4_CapNull);
	CHECK(err == 0, "utcb configure err=", err);
	err = seL4_TCB_SetSchedParams(utcb, vcpu->ktcb, L4H_PRIO_USER, L4H_PRIO_USER, vcpu->sc_u, fault_ep);
	CHECK(err == 0, "utcb sched err=", err);
	seL4_TCB_SetFlags_t fl = seL4_TCB_SetFlags(utcb, seL4_TCBFlag_fpuDisabled, seL4_TCBFlag_trapSyscalls);
	CHECK(fl.error == 0 && fl.flags == seL4_TCBFlag_trapSyscalls, "setflags=", fl.flags);
#ifdef __aarch64__
	regs.sp = user_sp;
#else
	regs.rsp = user_sp;
#endif
	err = write_pc(&regs, ABITEST_USER_VA);
	CHECK(err == 0, "write regs err=", err);

	/* 1: getpid syscall arrives as UnknownSyscall with Linux registers. */
	info = recv(&badge);
	CHECK(badge == (L4H_EP_BADGE_TASK | 1), "badge1=", badge);
	CHECK(seL4_MessageInfo_get_label(info) == seL4_Fault_UnknownSyscall, "label1=",
	      seL4_MessageInfo_get_label(info));
	CHECK(seL4_GetMR(MR_SYSNO) == SYS_getpid, "sysno=", seL4_GetMR(MR_SYSNO));
	CHECK(seL4_GetMR(MR_SEL4NO) == (seL4_Word)-1, "sel4 sysno reg=", seL4_GetMR(MR_SEL4NO));
	seL4_Word sysregs[MR_COUNT];
	for (int i = 0; i < MR_COUNT; i++)
		sysregs[i] = seL4_GetMR(i);
	say("E1 trapped Linux syscall from user thread, at user_prog+%#lx",
	    sysregs[seL4_UnknownSyscall_FaultIP] - ABITEST_USER_VA);
	ar = frame_accessed(prog_frame);
	CHECK(ar.error == 0 && ar.accessed == 1, "instruction fetch not accessed=", ar.accessed);
	ar = frame_accessed(prog_frame);
	CHECK(ar.error == 0 && ar.accessed == 0, "instruction access counted twice=", ar.accessed);

	CHECK(sysregs[MR_SP] == user_sp, "syscall SP=", sysregs[MR_SP]);

	/* E2: the user thread's xmm0 / d0 is visible through ReadFPU. */
	err = seL4_TCB_ReadFPU(utcb, L4H_CPTR(vcpu_caps + L4H_VCPU_IPCBUF), L4H_FPU_SCRATCH_OFFSET);
	CHECK(err == 0, "readfpu err=", err);
	uint64_t v0 = *(volatile uint64_t *)(L4H_VCPU_IPCBUF_VA(t->cpu) + L4H_FPU_SCRATCH_OFFSET + FPU_V0_OFFSET);
	CHECK(v0 == 0x1122334455667788ull, "xmm0=", v0);
	say("E2 read user FPU state");

	/* Return pid 777 and step over the syscall instruction. */
	sysregs[MR_RET] = 777;
	/* Return a different SP, then let user code change it on every call. */
	user_sp -= 128;
	sysregs[MR_SP] = user_sp;
	sysregs[seL4_UnknownSyscall_FaultIP] += SYSCALL_INSN_LEN;
	for (int i = 0; i < MR_COUNT; i++)
		seL4_SetMR(i, sysregs[i]);
	seL4_Send(reply, seL4_MessageInfo_new(0, 0, 0, MR_COUNT));

	/* 2: the load from 0x500000 is a VM fault. */
	info = recv(&badge);
	CHECK(seL4_MessageInfo_get_label(info) == seL4_Fault_VMFault, "label2=",
	      seL4_MessageInfo_get_label(info));
	CHECK(seL4_GetMR(seL4_VMFault_Addr) == 0x500000, "fault addr=", seL4_GetMR(seL4_VMFault_Addr));
	say("user page fault delivered");
	/* Map a zero page there and restart the instruction. */
	seL4_CPtr zero_frame = copy_cap(L4H_FRAME_CPTR(t->zero_gpa));
	CHECK(zero_frame, "no zero frame copy", 0);
	TRY(map_user_page(zero_frame, 0x500000, seL4_CanRead));
	ar = frame_accessed(zero_frame);
	CHECK(ar.error == 0, "clear data accessed=", ar.error);
	ar = frame_accessed(zero_frame);
	CHECK(ar.error == 0 && ar.accessed == 0, "data accessed not cleared=", ar.accessed);
	seL4_Send(reply, seL4_MessageInfo_new(0, 0, 0, 0));

	/* 3: 64 syscalls with rdx = -1 .. -64 (all seL4 syscall numbers,
	 * including non-faulting ones such as Yield, NBSend and SetTLSBase). */
	uint64_t sweep_t0 = rdtsc();
	for (long n = -1; n >= -64; n--) {
		info = recv(&badge);
		CHECK(seL4_MessageInfo_get_label(info) == seL4_Fault_UnknownSyscall, "sweep label=",
		      seL4_MessageInfo_get_label(info));
		CHECK(seL4_GetMR(MR_SEL4NO) == (seL4_Word)n, "sweep sel4 sysno reg=", seL4_GetMR(MR_SEL4NO));
		CHECK(seL4_GetMR(MR_SYSNO) == SYS_getpid, "sweep sysno=", seL4_GetMR(MR_SYSNO));
		seL4_Word r[MR_COUNT];
		for (int i = 0; i < MR_COUNT; i++)
			r[i] = seL4_GetMR(i);
		CHECK(r[MR_SP] == user_sp, "sweep SP=", r[MR_SP]);
		user_sp -= 16;
		if (n == -1) {
			/* On Cortex-A57 AF=0 caused a kernel-only data abort:
			 * the next delivered event must still be this syscall. */
			ar = frame_accessed(zero_frame);
			CHECK(ar.error == 0 && ar.accessed == 1, "load not accessed=", ar.accessed);
			ar = frame_accessed(zero_frame);
			CHECK(ar.error == 0 && ar.accessed == 0, "load counted twice=", ar.accessed);
		}
		r[seL4_UnknownSyscall_FaultIP] += SYSCALL_INSN_LEN;
		for (int i = 0; i < MR_COUNT; i++)
			seL4_SetMR(i, r[i]);
		seL4_Send(reply, seL4_MessageInfo_new(0, 0, 0, MR_COUNT));
	}
	say("E1 traps every seL4 syscall number (seL4 issue #477), %lu ticks per round trip",
	    (unsigned long)(rdtsc() - sweep_t0) / 64);

	/* 4: exit(777). */
	info = recv(&badge);
	CHECK(seL4_MessageInfo_get_label(info) == seL4_Fault_UnknownSyscall, "label3=",
	      seL4_MessageInfo_get_label(info));
	CHECK(seL4_GetMR(MR_SYSNO) == SYS_exit, "sysno3=", seL4_GetMR(MR_SYSNO));
	CHECK(seL4_GetMR(MR_SP) == user_sp, "exit SP=", seL4_GetMR(MR_SP));
	CHECK(seL4_GetMR(MR_ARG0) == 777, "exit code=", seL4_GetMR(MR_ARG0));
	say("syscall return value reached user mode");
	seL4_TCB_Suspend(utcb);

	/* 5: without the trap flag, seL4_DebugHalt (which would stop the whole
	 * host) is an unknown syscall for a guest thread: its MCP is too low. */
	fl = seL4_TCB_SetFlags(utcb, seL4_TCBFlag_trapSyscalls, 0);
	CHECK(fl.error == 0 && fl.flags == 0, "clearflags=", fl.flags);
	err = write_pc(&regs, user_debug_va);
	CHECK(err == 0, "write regs err=", err);
	info = recv(&badge);
	CHECK(seL4_MessageInfo_get_label(info) == seL4_Fault_UnknownSyscall, "debug label=",
	      seL4_MessageInfo_get_label(info));
	CHECK(seL4_GetMR(seL4_UnknownSyscall_Syscall) == (seL4_Word)-14, "debug sysno=",
	      seL4_GetMR(seL4_UnknownSyscall_Syscall));
	say("debug syscalls refused to guest threads");
	seL4_TCB_Suspend(utcb);

	/* 6: Clearing A/AF must preserve execute-never permissions. */
#ifdef __aarch64__
	err = seL4_ARM_Page_Map(prog_frame, t->vspace, ABITEST_USER_VA, seL4_CanRead, seL4_ARM_ExecuteNever);
#else
	err = seL4_X86_Page_Map(prog_frame, t->vspace, ABITEST_USER_VA, seL4_CanRead, seL4_X86_ExecuteNever);
#endif
	CHECK(err == 0, "remap xn err=", err);
	ar = frame_accessed(prog_frame);
	CHECK(ar.error == 0, "clear xn accessed=", ar.error);
	err = write_pc(&regs, ABITEST_USER_VA);
	CHECK(err == 0, "write regs err=", err);
	info = recv(&badge);
	CHECK(seL4_MessageInfo_get_label(info) == seL4_Fault_VMFault, "xn label=",
	      seL4_MessageInfo_get_label(info));
	CHECK(seL4_GetMR(seL4_VMFault_Addr) == ABITEST_USER_VA, "xn addr=", seL4_GetMR(seL4_VMFault_Addr));
	CHECK(seL4_GetMR(seL4_VMFault_PrefetchFault) == 1, "xn prefetch=",
	      seL4_GetMR(seL4_VMFault_PrefetchFault));
	say("execute-never mappings fault on instruction fetch");
	seL4_TCB_Suspend(utcb);
	TRY(map_user_page(prog_frame, ABITEST_USER_VA, seL4_CanRead));
	ar = frame_accessed(prog_frame);
	CHECK(ar.error == 0, "clear executable accessed=", ar.error);
	ar = frame_accessed(zero_frame);
	CHECK(ar.error == 0, "clear read-only accessed=", ar.error);
	err = write_pc(&regs, ABITEST_USER_VA + (user_write - user_prog));
	CHECK(err == 0, "write test regs=", err);
	info = recv(&badge);
	CHECK(seL4_MessageInfo_get_label(info) == seL4_Fault_VMFault, "read-only label=",
	      seL4_MessageInfo_get_label(info));
	CHECK(seL4_GetMR(seL4_VMFault_Addr) == 0x500000, "read-only fault addr=",
	      seL4_GetMR(seL4_VMFault_Addr));
	CHECK(seL4_GetMR(seL4_VMFault_PrefetchFault) == 0, "read-only prefetch=",
	      seL4_GetMR(seL4_VMFault_PrefetchFault));
#ifdef __aarch64__
	CHECK((seL4_GetMR(seL4_VMFault_FSR) & 0x3f) == 0xf, "expected permission fault, FSR=",
	      seL4_GetMR(seL4_VMFault_FSR));
#else
	CHECK((seL4_GetMR(seL4_VMFault_FSR) & 3) == 3, "expected write protection fault, FSR=",
	      seL4_GetMR(seL4_VMFault_FSR));
#endif
	seL4_TCB_Suspend(utcb);
	say("clearing accessed preserves read-only permissions");

	/* A cap can still name an ASID/VA after another frame replaced its
	 * mapping.  It must not clear the replacement frame's accessed bit. */
	seL4_CPtr stale = copy_cap(L4H_FRAME_CPTR(t->zero_gpa));
	seL4_CPtr replacement = copy_cap(L4H_FRAME_CPTR(t->user_gpa));
	CHECK(stale && replacement, "no stale-map test caps", 0);
	TRY(map_user_page(stale, 0x600000, seL4_CanRead));
	TRY(map_user_page(replacement, 0x600000, seL4_CanRead));
	ar = frame_accessed(stale);
	CHECK(ar.error == seL4_InvalidCapability, "accessed on replaced mapping=", ar.error);
	CHECK(frame_unmap(replacement) == 0, "unmap replacement", 0);
	ar = frame_accessed(stale);
	CHECK(ar.error == seL4_InvalidCapability, "accessed on absent mapping=", ar.error);
	ar = frame_accessed(replacement);
	CHECK(ar.error == seL4_IllegalOperation, "accessed after unmap=", ar.error);
	say("accessed bits track reads and instruction fetches without guest faults; invalid mappings rejected");
	return 0;
}

/* `n` aliases of large frame `src` from byte `offset`, into slot `dst` on. */
static int derive(seL4_CPtr src, seL4_CPtr dst, seL4_Word offset, seL4_Word n,
		  seL4_CapRights_t rights)
{
	return frame_derive(src, L4H_CNODE_CPTR, node_index(dst), L4H_ROOT_DEPTH, node_offset(dst),
			    offset, n, rights);
}

/* Copy slot `i` of the radix-9 CNode `window` to `dst`: whether it holds a cap. */
static int window_copy(seL4_CPtr window, seL4_Word i, seL4_CPtr dst)
{
	return seL4_CNode_Copy(L4H_CNODE_CPTR, dst, 64, window, i, 9, seL4_AllRights);
}

/* Native large leaves and subframe aliases, including MDB lifetime. */
static int large_frame_test(void)
{
	const seL4_Word va = 0x1000000, tail = (1ul << 21) - 4096;
	seL4_CPtr large, alias, first = abitest_slot(), last = abitest_slot();
	seL4_CPtr extra = abitest_slot(), ro = abitest_slot(), ro_child = abitest_slot(), x;
	seL4_UserContext regs = { 0 };
	seL4_Word badge;
	int err;

	CHECK(t->large_ut && first && last && extra && ro && ro_child, "large test allocation", 0);
	CHECK(!retype(t->large_ut, LARGE_FRAME_TYPE, 0, &large), "large retype", 0);
	alias = copy_cap(large);
	CHECK(alias, "large copy", 0);
	CHECK(derive(large, first, 1, 1, seL4_AllRights) == seL4_InvalidArgument,
	      "unaligned subframe accepted", 0);
	CHECK(derive(large, first, 1ul << 21, 1, seL4_AllRights) == seL4_InvalidArgument,
	      "out-of-range subframe accepted", 0);
	CHECK(derive(large, first, ~0ul, 1, seL4_AllRights) == seL4_InvalidArgument,
	      "overflow subframe accepted", 0);
	CHECK(frame_derive(large, ep, node_index(first), L4H_ROOT_DEPTH, node_offset(first), 0, 1,
			   seL4_AllRights) != 0, "non-CNode destination accepted", 0);
	CHECK(!derive(large, first, 0, 1, seL4_AllRights), "first subframe", 0);
	CHECK(!derive(alias, last, tail, 1, seL4_AllRights), "last subframe through copy", 0);
	CHECK(derive(large, first, 0, 1, seL4_AllRights) == seL4_DeleteFirst,
	      "occupied subframe slot accepted", 0);
	CHECK(derive(first, extra, 0, 1, seL4_AllRights) == seL4_IllegalOperation,
	      "small source accepted", 0);
	CHECK(frame_address(last).paddr == frame_address(large).paddr + tail, "subframe physical offset", 0);
	/* One call fills a CNode window, as the guest does per RAM block, and
	 * derives nothing unless the whole window is valid and empty. */
	seL4_CPtr window = abitest_obj(L4H_OBJ_CNODE, 9), probe = abitest_slot();
	static const seL4_Word picks[] = { 0, 1, 300, 511 };

	CHECK(window && probe, "alias window allocation", 0);
	CHECK(frame_derive(large, L4H_CNODE_CPTR, window, 64, 0, 0, 0, seL4_AllRights) == seL4_RangeError,
	      "zero aliases accepted", 0);
	CHECK(frame_derive(large, L4H_CNODE_CPTR, window, 64, 0, tail, 2, seL4_AllRights) == seL4_RangeError,
	      "aliases past the large frame accepted", 0);
	CHECK(frame_derive(large, L4H_CNODE_CPTR, window, 64, 1, 0, 512, seL4_AllRights) == seL4_RangeError,
	      "window overrun accepted", 0);
	CHECK(frame_derive(large, L4H_CNODE_CPTR, window, 64, 512, 0, 1, seL4_AllRights) == seL4_RangeError,
	      "window offset past the CNode accepted", 0);
	CHECK(!frame_derive(large, L4H_CNODE_CPTR, window, 64, 300, 0, 1, seL4_AllRights),
	      "one alias in the window", 0);
	CHECK(frame_derive(large, L4H_CNODE_CPTR, window, 64, 0, 0, 512, seL4_AllRights) == seL4_DeleteFirst,
	      "occupied window slot accepted", 0);
	CHECK(window_copy(window, 0, probe) == seL4_FailedLookup, "failed window derived an alias", 0);
	CHECK(!seL4_CNode_Delete(window, 300, 9), "empty the window", 0);
	CHECK(!frame_derive(large, L4H_CNODE_CPTR, window, 64, 0, 0, 512, seL4_AllRights),
	      "512 aliases in one call", 0);
	for (unsigned int i = 0; i < sizeof(picks) / sizeof(picks[0]); i++) {
		CHECK(!window_copy(window, picks[i], probe), "window alias missing", picks[i]);
		CHECK(frame_address(probe).paddr == frame_address(large).paddr + picks[i] * 4096,
		      "window alias physical offset", picks[i]);
		CHECK(!seL4_CNode_Delete(L4H_CNODE_CPTR, probe, 64), "delete window probe", picks[i]);
	}
	CHECK(!seL4_CNode_Copy(L4H_CNODE_CPTR, ro, 64, L4H_CNODE_CPTR, large, 64, seL4_CanRead),
	      "read-only parent", 0);
	CHECK(!derive(ro, ro_child, 0, 1, seL4_AllRights), "derive read-only", 0);
	seL4_CPtr ro_copy = copy_cap(ro_child);
	CHECK(ro_copy, "copy read-only subframe", 0);
	/* Narrowing a read-only large copy must not grant revocation power
	 * over a neighboring, independently derived read-write alias. */
	CHECK(!seL4_CNode_Revoke(L4H_CNODE_CPTR, ro_child, 64), "revoke subframe alias", 0);
	CHECK(!frame_address(first).error && !frame_address(ro_copy).error,
	      "subframe gained revocation authority", 0);
	volatile unsigned char *code = abitest_map(last, 4);
	volatile uint64_t *data = abitest_map(first, 5);
	CHECK(code && data && !*data, "large allocation zeroed", 0);
	*data = 0x12345678;
	for (unsigned long i = 0; i < (unsigned long)(user_end - user_large); i++)
		code[i] = user_large[i];
	CHECK(!map_user_frame(large, va, seL4_CanRead, 1), "large map", 0);
#ifdef __aarch64__
	CHECK(!seL4_ARM_Page_Unify_Instruction(large, 0, 1ul << 21), "large icache", 0);
#endif
	CHECK(!frame_accessed(large).error, "large clear accessed", 0);
	CHECK(!frame_accessed(large).accessed, "large accessed cleared", 0);
	CHECK(!seL4_TCB_SetFlags(utcb, 0, seL4_TCBFlag_trapSyscalls).error, "large trap flag", 0);
	CHECK(!write_pc(&regs, va + tail), "large test PC", 0);
	seL4_MessageInfo_t info = recv(&badge);
	CHECK(seL4_MessageInfo_get_label(info) == seL4_Fault_UnknownSyscall,
	      "large AF fault escaped kernel", seL4_MessageInfo_get_label(info));
	CHECK(seL4_GetMR(MR_ARG0) == *data, "large/small alias data mismatch", seL4_GetMR(MR_ARG0));
	CHECK(frame_accessed(large).accessed == 1, "large access not observed", 0);
	CHECK(!frame_accessed(large).accessed, "large access counted twice", 0);
	seL4_TCB_Suspend(utcb);
	CHECK(!write_pc(&regs, va + tail + (user_large_write - user_large)), "large write PC", 0);
	info = recv(&badge);
	CHECK(seL4_MessageInfo_get_label(info) == seL4_Fault_VMFault &&
	      seL4_GetMR(seL4_VMFault_Addr) == va, "large read-only mapping writable", 0);
	seL4_TCB_Suspend(utcb);
	CHECK(!map_user_page(ro_child, 0x500000, seL4_ReadWrite), "derived RO map", 0);
	CHECK(!write_pc(&regs, ABITEST_USER_VA + (user_write - user_prog)), "subframe write PC", 0);
	info = recv(&badge);
	CHECK(seL4_MessageInfo_get_label(info) == seL4_Fault_VMFault &&
	      seL4_GetMR(seL4_VMFault_Addr) == 0x500000, "subframe escalated rights", 0);
	seL4_TCB_Suspend(utcb);
	CHECK(!map_user_frame(alias, va, seL4_CanRead, 1), "replacement large alias", 0);
	CHECK(!frame_unmap(alias), "unmap replacement large", 0);
	CHECK(frame_accessed(large).error == seL4_InvalidCapability, "stale large mapping accepted", 0);
	CHECK(!map_user_page(first, va, seL4_CanRead), "small leaf after large unmap", 0);
	CHECK(frame_accessed(large).error == seL4_InvalidCapability, "large cap accepted a small leaf", 0);
	CHECK(!seL4_CNode_Revoke(L4H_CNODE_CPTR, large, 64), "revoke large", 0);
	CHECK(frame_address(first).error && frame_address(last).error && frame_address(alias).error &&
	      frame_address(ro_child).error, "large revoke left aliases", 0);
	CHECK(window_copy(window, 511, probe) == seL4_FailedLookup, "large revoke left window aliases", 0);
	CHECK(!derive(large, extra, 0, 1, seL4_AllRights), "derive after revoke", 0);
	seL4_CPtr survivor = copy_cap(extra);
	volatile uint64_t *q = abitest_map(survivor, 6);
	CHECK(q && *q == 0x12345678, "derivation or revoke changed contents", 0);
	CHECK(!seL4_CNode_Delete(L4H_CNODE_CPTR, large, 64), "delete large parent", 0);
	CHECK(*q == 0x12345678 && !frame_address(extra).error, "parent deletion killed alias", 0);
	err = retype(t->large_ut, FRAME_TYPE, 0, &x);
	CHECK(err == seL4_NotEnoughMemory, "untyped reused with surviving subframe", err);
	CHECK(!seL4_CNode_Revoke(L4H_CNODE_CPTR, t->large_ut, 64), "revoke alias backing", 0);
	CHECK(frame_address(extra).error && frame_address(survivor).error, "untyped revoke left alias", 0);
	CHECK(!retype(t->large_ut, LARGE_FRAME_TYPE, 0, &large), "reuse large backing", 0);
	CHECK(!derive(large, extra, 0, 1, seL4_AllRights), "derive reused backing", 0);
	q = abitest_map(extra, 7);
	CHECK(q && !*q, "reused backing not zeroed", 0);
	CHECK(!derive(large, last, tail, 1, seL4_AllRights), "derive reused tail", 0);
	q = abitest_map(last, 6);
	CHECK(q && !*q, "reused tail not zeroed", 0);
	CHECK(!seL4_CNode_Revoke(L4H_CNODE_CPTR, t->large_ut, 64), "final backing revoke", 0);
	say("2 MiB leaves: alias bounds/rights/windows, tail execution, AF, demotion, parent deletion and Untyped revoke: ok");
	return 0;
}

/* ---- E3: the deadline timer signals the vCPU's bound notification */

static int timer_test(void)
{
	seL4_Word badge = 0;

	/* Linux's events so far, and a timer that fired before we took it. */
	seL4_Poll(vcpu->ntfn, &badge);
	__atomic_fetch_or(&vcpu->ntfn_pending, badge, __ATOMIC_SEQ_CST);
	uint64_t deadline = rdtsc() + bi->tsc_hz / 100;
	int err = seL4_TCB_SetTimer(vcpu->ktcb, deadline, L4H_BADGE_TIMER);
	CHECK(err == 0, "settimer err=", err);
	do {
		seL4_Wait(vcpu->ntfn, &badge);
		__atomic_fetch_or(&vcpu->ntfn_pending, badge & ~L4H_BADGE_TIMER, __ATOMIC_SEQ_CST);
	} while (!(badge & L4H_BADGE_TIMER));
	uint64_t t1 = rdtsc();
	CHECK(t1 >= deadline - bi->tsc_hz / 10000, "timer early by=", deadline - t1);
	say("E3 timer fired, latency %lu ticks", (unsigned long)(t1 - deadline));
	return 0;
}

/* ---- the I/O pool, from a hostile driver's point of view
 *
 * Devices may only use the host's I/O pool: l4h-vmm refuses a driver that
 * does not accept VIRTIO_F_ACCESS_PLATFORM, rings outside the pool and
 * requests with any buffer outside it.  Played against a virtio-blk device
 * (sector 0 holds "l4h-pool-test" from the host), in our part of the pool.
 */
#define VIRTIO_F_VERSION_1	(1ull << 32)
#define VIRTIO_F_ACCESS_PLATFORM (1ull << 33)
#define ST_ACK			1
#define ST_DRIVER		2
#define ST_DRIVER_OK		4
#define ST_FEATURES_OK		8
#define ST_NEEDS_RESET		64
#define VQ_NEXT			1
#define VQ_WRITE		2
#define QN			8

static volatile struct l4h_virtio_regs *blk_regs(void)
{
	return (volatile struct l4h_virtio_regs *)bi->devices[t->blk].page_va;
}

static uint64_t dev_write(uint64_t op)
{
	__atomic_thread_fence(__ATOMIC_SEQ_CST);
	seL4_SetMR(0, t->blk);
	seL4_SetMR(1, op);
	seL4_SetMR(2, 0);
	seL4_SetMR(3, 0);
	seL4_Call(L4H_CPTR(L4H_SLOT_HYP_EP), seL4_MessageInfo_new(L4H_HC_DEV_WRITE, 0, 0, 4));
	return seL4_GetMR(0);
}

static uint64_t set_status(uint32_t s)
{
	blk_regs()->status = s;
	return dev_write(L4H_VIRTIO_OP_STATUS);
}

/* Reset, negotiate `features`; returns the status the device left. */
static uint32_t negotiate(uint64_t features)
{
	volatile struct l4h_virtio_regs *r = blk_regs();

	set_status(0);
	set_status(ST_ACK | ST_DRIVER);
	r->driver_features = features;
	dev_write(L4H_VIRTIO_OP_FEATURES);
	set_status(ST_ACK | ST_DRIVER | ST_FEATURES_OK);
	return r->status;
}

/* Queue 0 with its rings at `ring_gpa`: returns the hypercall result. */
static uint64_t setup_queue(uint64_t ring_gpa)
{
	volatile struct l4h_virtq_regs *q = &blk_regs()->queues[0];

	for (int i = 0; i < 0x400; i++)
		t->dma[i] = 0;
	q->num = QN;
	q->desc = ring_gpa;
	q->driver = ring_gpa + 0x100;
	q->device = ring_gpa + 0x200;
	q->ready = 1;
	return dev_write(L4H_VIRTIO_OP_QUEUE);
}

struct vdesc {
	uint64_t addr;
	uint32_t len;
	uint16_t flags, next;
};

/* Read sector 0 with the header, data and status at the given GPAs (the
 * rings are at the start of our part of the pool, the header at 0x400 in
 * it).  Returns the used length, or -1 if the device did not return the
 * chain. */
static int64_t blk_read(uint64_t hdr, uint64_t data, uint64_t status)
{
	static uint16_t avail_idx;
	struct vdesc *d = (struct vdesc *)t->dma;
	volatile uint16_t *avail = (volatile uint16_t *)(t->dma + 0x100);
	volatile uint16_t *used_idx = (volatile uint16_t *)(t->dma + 0x200 + 2);
	volatile uint32_t *used = (volatile uint32_t *)(t->dma + 0x200 + 4);
	volatile uint32_t *h = (volatile uint32_t *)(t->dma + 0x400);
	uint16_t before = *used_idx;

	h[0] = 0;	/* VIRTIO_BLK_T_IN */
	h[1] = 0;
	h[2] = h[3] = 0;	/* sector 0 */
	d[0] = (struct vdesc){ hdr, 16, VQ_NEXT, 1 };
	d[1] = (struct vdesc){ data, 512, VQ_NEXT | VQ_WRITE, 2 };
	d[2] = (struct vdesc){ status, 1, VQ_WRITE, 0 };
	avail[2 + avail_idx % QN] = 0;
	__atomic_thread_fence(__ATOMIC_SEQ_CST);
	avail[1] = ++avail_idx;
	__atomic_thread_fence(__ATOMIC_SEQ_CST);
	__atomic_fetch_or(&blk_regs()->kick, 1ull, __ATOMIC_SEQ_CST);
	seL4_Signal(L4H_CPTR2(L4H_SLOT_DEV_CNODE, bi->devices[t->blk].kick_slot));
	uint64_t end = rdtsc() + bi->tsc_hz;
	while (*used_idx == before) {
		if (rdtsc() > end)
			return -1;
		seL4_Yield();
	}
	__atomic_thread_fence(__ATOMIC_SEQ_CST);
	return used[2 * (before % QN) + 1];
}

static int io_pool_test(void)
{
	uint64_t pool = bi->io_pool_gpa, size = bi->io_pool_size, p = t->dma_gpa;
	uint64_t ram_gpa = t->ram_gpa;
	volatile uint8_t *data = t->dma + 0x1000, *st = t->dma + 0x600, *ram = t->ram;

	CHECK(size >= (1 << 20) && pool >= bi->ram_size && pool % 4096 == 0, "pool=", pool);
	CHECK(p >= pool && p + ABITEST_DMA_SIZE <= pool + size, "DMA buffer outside the pool at ", p);
	if (t->blk < 0) {
		say("no virtio-blk device, I/O pool test skipped");
		return 0;
	}
	volatile struct l4h_virtio_regs *r = blk_regs();
	CHECK(r->device_features & VIRTIO_F_ACCESS_PLATFORM, "features=", r->device_features);

	/* A driver without ACCESS_PLATFORM is refused. */
	uint32_t s = negotiate(VIRTIO_F_VERSION_1);
	CHECK(!(s & ST_FEATURES_OK), "FEATURES_OK without ACCESS_PLATFORM, status=", s);

	/* Rings in guest RAM are refused, and so is DRIVER_OK after that. */
	s = negotiate(VIRTIO_F_VERSION_1 | VIRTIO_F_ACCESS_PLATFORM);
	CHECK(s & ST_FEATURES_OK, "FEATURES_OK refused, status=", s);
	CHECK(setup_queue(ram_gpa) != 0, "queue in RAM accepted, gpa=", ram_gpa);
	CHECK(r->queues[0].ready == 0, "queue in RAM ready=", r->queues[0].ready);
	CHECK(setup_queue(pool + size - 0x100) != 0, "queue across the pool end accepted", 0);
	CHECK(set_status(ST_ACK | ST_DRIVER | ST_FEATURES_OK | ST_DRIVER_OK) != 0, "DRIVER_OK accepted", 0);
	CHECK(!(r->status & ST_DRIVER_OK) && (r->status & ST_NEEDS_RESET), "status=", r->status);

	/* Rings in the pool work. */
	s = negotiate(VIRTIO_F_VERSION_1 | VIRTIO_F_ACCESS_PLATFORM);
	CHECK(s & ST_FEATURES_OK, "FEATURES_OK refused, status=", s);
	CHECK(setup_queue(p) == 0, "queue in the pool refused", p);
	CHECK(set_status(ST_ACK | ST_DRIVER | ST_FEATURES_OK | ST_DRIVER_OK) == 0, "DRIVER_OK refused", 0);

	/* A read into the pool. */
	*st = 0xff;
	int64_t n = blk_read(p + 0x400, p + 0x1000, p + 0x600);
	CHECK(n == 513 && *st == 0, "pool read: used=", n);
	CHECK(data[0] == 'l' && data[1] == '4' && data[2] == 'h', "pool read data=", data[0]);
	/* A read into guest RAM is refused: nothing is written there, and the
	 * status byte is untouched. */
	for (int i = 0; i < 1024; i++)
		ram[i] = 0x5a;
	*st = 0xff;
	n = blk_read(p + 0x400, ram_gpa, p + 0x600);
	CHECK(n == 0 && *st == 0xff && ram[0] == 0x5a && ram[511] == 0x5a, "RAM read: used=", n);
	/* So are a header in RAM, a status byte in RAM, and a buffer that runs
	 * past the end of the pool. */
	n = blk_read(ram_gpa, p + 0x1000, p + 0x600);
	CHECK(n == 0 && *st == 0xff, "header in RAM: used=", n);
	n = blk_read(p + 0x400, p + 0x1000, ram_gpa + 600);
	CHECK(n == 0 && ram[600] == 0x5a, "status in RAM: used=", n);
	n = blk_read(p + 0x400, pool + size - 256, p + 0x600);
	CHECK(n == 0 && *st == 0xff, "buffer past the pool: used=", n);
	/* The device still works. */
	data[0] = 0;
	n = blk_read(p + 0x400, p + 0x1000, p + 0x600);
	CHECK(n == 513 && *st == 0 && data[0] == 'l', "pool read again: used=", n);
	set_status(0);
	say("I/O pool at %#lx: ACCESS_PLATFORM required, rings and buffers outside the pool refused",
	    (unsigned long)pool);
	return 0;
}

/* ---- seL4 semantics of Untyped copies (DESIGN.md §8.2)
 *
 * l4h-root keeps the original Untyped of each 2 MiB block of guest RAM and
 * gives the guest a copy.  Check, on a 64 KiB Untyped `orig` with a copy
 * `copy`, playing l4h-root's and the guest's caps:
 *   - while the copy exists, the original cannot be retyped;
 *   - objects retyped from the copy can be revoked through the copy;
 *   - a retype from a copy without children starts again at its base and
 *     the memory is zeroed (reset), whatever it held before;
 *   - a copy with children cannot be copied again;
 *   - revoking the original deletes the copy and everything retyped from it.
 */
#define UT_BITS		16
#define UT_FRAMES	(1 << (UT_BITS - 12))

static int untyped_copy_test(void)
{
	seL4_CPtr orig = abitest_obj(L4H_OBJ_UNTYPED, UT_BITS), copy, f[UT_FRAMES], cn, x;
	int err;

	CHECK(orig, "no Untyped", 0);
	copy = copy_cap(orig);
	CHECK(copy, "untyped copy", 0);

	/* Frames from the copy, the last one written. */
	for (int i = 0; i < UT_FRAMES; i++) {
		err = retype(copy, FRAME_TYPE, 0, &f[i]);
		CHECK(err == 0, "frames from the copy err=", err);
	}
	volatile uint64_t *p = abitest_map(f[UT_FRAMES - 1], 0);
	volatile uint64_t *q = abitest_map(f[UT_FRAMES - 2], 1);
	CHECK(p && q, "cannot map frames", 0);
	p[0] = 0x1234567890abcdefull;
	/* A page whose only non-zero word is its last: runtime reset must
	 * clear the whole region, including the end of each page. */
	q[511] = 0x5a5a5a5a5a5a5a5aull;

	/* The original is full while the copy exists: it cannot be retyped. */
	err = retype(orig, FRAME_TYPE, 0, &x);
	CHECK(err == seL4_NotEnoughMemory, "retype of the original with a copy err=", err);
	/* A copy that has children cannot be copied again. */
	CHECK(!copy_cap(copy), "copy of a copy with children", 0);

	/* Revoking the copy deletes its frames and their mappings. */
	err = seL4_CNode_Revoke(L4H_CNODE_CPTR, copy, 64);
	CHECK(err == 0, "revoke copy err=", err);
	err = frame_unmap(f[UT_FRAMES - 1]);
	CHECK(err == seL4_InvalidCapability, "frame after revoke err=", err);

	/* The copy has no children: the next retype resets it.  A CNode
	 * that fills the whole Untyped fits again, so the free index went back
	 * to 0; then frames again, which must read as zero. */
	err = retype(copy, seL4_CapTableObject, UT_BITS - seL4_SlotBits, &cn);
	CHECK(err == 0, "CNode filling the reset copy err=", err);
	err = seL4_CNode_Revoke(L4H_CNODE_CPTR, copy, 64);
	CHECK(err == 0, "revoke copy (CNode) err=", err);
	for (int i = 0; i < UT_FRAMES; i++) {
		err = retype(copy, FRAME_TYPE, 0, &f[i]);
		CHECK(err == 0, "frames again err=", err);
	}
	p = abitest_map(f[UT_FRAMES - 1], 2);
	q = abitest_map(f[UT_FRAMES - 2], 3);
	CHECK(p && q, "cannot map frames", 0);
	CHECK(p[0] == 0, "reset memory not zeroed: ", p[0]);
	CHECK(q[511] == 0, "reset memory not zeroed at the end of a page: ", q[511]);

	/* Revoking the original (teardown by l4h-root) deletes the copy and
	 * everything retyped from it. */
	err = seL4_CNode_Revoke(L4H_CNODE_CPTR, orig, 64);
	CHECK(err == 0, "revoke original err=", err);
	err = retype(copy, FRAME_TYPE, 0, &x);
	CHECK(err == seL4_InvalidCapability, "copy after revoke of the original err=", err);
	err = frame_unmap(f[UT_FRAMES - 1]);
	CHECK(err == seL4_InvalidCapability, "frame after revoke of the original err=", err);
	/* And the original is usable again. */
	err = retype(orig, FRAME_TYPE, 0, &x);
	CHECK(err == 0, "original after revoke err=", err);
	say("Untyped copies: retype/revoke through a copy, reset, teardown by the original: ok");
	return 0;
}

/* The RAM the host gives: boot blocks have frames and no Untyped.  Linux
 * itself converts the other blocks between frames and objects. */
static int ram_blocks_test(void)
{
	seL4_CPtr x;
	int err;

	CHECK(bi->nr_blocks * L4H_BLOCK_SIZE == bi->ram_size, "nr_blocks=", bi->nr_blocks);
	CHECK(bi->boot_blocks > 0 && bi->boot_blocks < bi->nr_blocks, "boot_blocks=", bi->boot_blocks);
	err = retype(L4H_BLOCK_CPTR(0), FRAME_TYPE, 0, &x);
	CHECK(err != 0, "boot block has an Untyped", 0);
	say("RAM: %lu blocks, %lu boot blocks without Untyped", (unsigned long)bi->nr_blocks,
	    (unsigned long)bi->boot_blocks);
	return 0;
}

int abitest_run(struct abitest *test)
{
	int err;

	t = test;
	bi = l4h_bootinfo;
	vcpu = &l4h_vcpus[t->cpu];
	__sel4_ipc_buffer = (seL4_IPCBuffer *)L4H_VCPU_IPCBUF_VA(t->cpu);
	say("vCPU %d, ABI version %lu", t->cpu, (unsigned long)bi->abi_version);
	err = user_test();
	err = err ?: large_frame_test();
	/* Give back the user scheduling context before Linux needs it. */
	if (utcb) {
		seL4_TCB_Suspend(utcb);
		seL4_SchedContext_UnbindObject(vcpu->sc_u, utcb);
	}
	err = err ?: timer_test();
	err = err ?: io_pool_test();
	err = err ?: untyped_copy_test();
	err = err ?: ram_blocks_test();
	return err;
}

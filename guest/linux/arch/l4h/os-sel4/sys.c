// SPDX-License-Identifier: GPL-2.0
/*
 * Thin wrappers around seL4 invocations, so that the rest of the kernel does
 * not need libsel4.  All capability arguments are CPtrs in the guest CSpace
 * (see l4h/abi.h).
 */
#include "l4h_os.h"

__thread seL4_IPCBuffer *__sel4_ipc_buffer;

struct l4h_tls_block l4h_tls_blocks[L4H_MAX_VCPUS];
struct l4h_vcpu l4h_vcpus[L4H_MAX_VCPUS];
const struct l4h_bootinfo *l4h_bootinfo;
unsigned long long l4h_tsc_hz;

struct l4h_vcpu *l4h_this_vcpu(void)
{
	return l4h_tls()->vcpu;
}

int l4h_this_vcpu_id(void)
{
	return (int)l4h_tls()->cpu;
}

static const seL4_Word obj_type[L4H_OBJ_NR] = {
	[L4H_OBJ_UNTYPED] = seL4_UntypedObject,
	[L4H_OBJ_TCB] = seL4_TCBObject,
	[L4H_OBJ_ENDPOINT] = seL4_EndpointObject,
	[L4H_OBJ_NOTIFICATION] = seL4_NotificationObject,
	[L4H_OBJ_CNODE] = seL4_CapTableObject,
	[L4H_OBJ_SCHED_CONTEXT] = seL4_SchedContextObject,
	[L4H_OBJ_REPLY] = seL4_ReplyObject,
#ifdef __aarch64__
	[L4H_OBJ_FRAME] = seL4_ARM_SmallPageObject,
	[L4H_OBJ_LARGE_FRAME] = seL4_ARM_LargePageObject,
	[L4H_OBJ_PT] = seL4_ARM_PageTableObject,
	[L4H_OBJ_PD] = seL4_ARM_PageTableObject,
	[L4H_OBJ_PDPT] = seL4_ARM_PageTableObject,
#else
	[L4H_OBJ_FRAME] = seL4_X86_4K,
	[L4H_OBJ_LARGE_FRAME] = seL4_X86_LargePageObject,
	[L4H_OBJ_PT] = seL4_X86_PageTableObject,
	[L4H_OBJ_PD] = seL4_X86_PageDirectoryObject,
	[L4H_OBJ_PDPT] = seL4_X86_PDPTObject,
#endif
};

int l4h_obj_bits(int type, int size_bits)
{
	switch (type) {
	case L4H_OBJ_UNTYPED:
		return size_bits;
	case L4H_OBJ_TCB:
		return seL4_TCBBits;
	case L4H_OBJ_ENDPOINT:
		return seL4_EndpointBits;
	case L4H_OBJ_NOTIFICATION:
		return seL4_NotificationBits;
	case L4H_OBJ_CNODE:
		return size_bits + seL4_SlotBits;
	case L4H_OBJ_SCHED_CONTEXT:
		return size_bits;
	case L4H_OBJ_REPLY:
		return seL4_ReplyBits;
	case L4H_OBJ_LARGE_FRAME:
		return 21;
	case L4H_OBJ_FRAME:
	case L4H_OBJ_PT:
	case L4H_OBJ_PD:
	case L4H_OBJ_PDPT:
		return seL4_PageBits;
	}
	return -1;
}

const int l4h_pt_level_obj[L4H_NR_PT_LEVELS] = { L4H_OBJ_PT, L4H_OBJ_PD, L4H_OBJ_PDPT };
const int l4h_pt_level_shift[L4H_NR_PT_LEVELS] = { 21, 30, 39 };

int l4h_retype(unsigned long ut, int type, int size_bits, unsigned long node_index,
	       int node_depth, unsigned long offset, unsigned long n)
{
	return seL4_Untyped_Retype(ut, obj_type[type], size_bits, L4H_CNODE_CPTR, node_index,
				   node_depth, offset, n);
}

static seL4_CapRights_t rights(int r)
{
	return seL4_CapRights_new(!!(r & L4H_RIGHT_GRANT_REPLY), !!(r & L4H_RIGHT_GRANT),
				  !!(r & L4H_RIGHT_READ), !!(r & L4H_RIGHT_WRITE));
}

int l4h_cnode_copy(unsigned long dst, int dst_depth, unsigned long src, int src_depth, int r)
{
	return seL4_CNode_Copy(L4H_CNODE_CPTR, dst, dst_depth, L4H_CNODE_CPTR, src, src_depth,
			       rights(r));
}

int l4h_cnode_mint(unsigned long dst, int dst_depth, unsigned long src, int src_depth, int r,
		   unsigned long badge)
{
	return seL4_CNode_Mint(L4H_CNODE_CPTR, dst, dst_depth, L4H_CNODE_CPTR, src, src_depth,
			       rights(r), badge);
}

int l4h_cnode_mutate(unsigned long dst, int dst_depth, unsigned long src, int src_depth,
		     unsigned long data)
{
	return seL4_CNode_Mutate(L4H_CNODE_CPTR, dst, dst_depth, L4H_CNODE_CPTR, src, src_depth,
				 data);
}

int l4h_cnode_delete(unsigned long cap, int depth)
{
	return seL4_CNode_Delete(L4H_CNODE_CPTR, cap, depth);
}

int l4h_cnode_revoke(unsigned long cap, int depth)
{
	return seL4_CNode_Revoke(L4H_CNODE_CPTR, cap, depth);
}

int l4h_page_map(unsigned long frame, unsigned long vspace, unsigned long va, int prot)
{
	seL4_CapRights_t r = (prot & L4H_PROT_WRITE) ? seL4_ReadWrite :
			     (prot & (L4H_PROT_READ | L4H_PROT_EXEC)) ? seL4_CanRead : seL4_NoRights;
	/* Readable pages are executable unless marked execute-never (seL4
	 * patch 0009); there is no execute-only. */
#ifdef __aarch64__
	int err = seL4_ARM_Page_Map(frame, vspace, va, r, seL4_ARM_Default_VMAttributes |
		((prot & L4H_PROT_EXEC) ? 0 : seL4_ARM_ExecuteNever));
	if (!err && (prot & L4H_PROT_EXEC))
		err = seL4_ARM_Page_Unify_Instruction(frame, 0, (prot & L4H_PROT_LARGE) ? 1ul << 21 : 4096);
	return err;
#else
	seL4_X86_VMAttributes attr = (prot & L4H_PROT_EXEC) ? seL4_X86_Default_VMAttributes :
				     seL4_X86_ExecuteNever;

	if (prot & L4H_PROT_DEFER_FLUSH)
		attr |= seL4_X86_DeferFlush;
	return seL4_X86_Page_Map(frame, vspace, va, r, attr);
#endif
}

int l4h_page_derive_subframe(unsigned long frame, unsigned long offset, unsigned long dst)
{
#ifdef __aarch64__
	return seL4_ARM_Page_DeriveSubframe(frame, L4H_CNODE_CPTR, dst, 64, offset, seL4_AllRights);
#else
	return seL4_X86_Page_DeriveSubframe(frame, L4H_CNODE_CPTR, dst, 64, offset, seL4_AllRights);
#endif
}

int l4h_page_unmap(unsigned long frame)
{
#ifdef __aarch64__
	return seL4_ARM_Page_Unmap(frame);
#else
	return seL4_X86_Page_Unmap(frame);
#endif
}

int l4h_page_test_and_clear_accessed(unsigned long frame, int *accessed)
{
#ifdef __aarch64__
	seL4_ARM_Page_TestAndClearAccessed_t ret = seL4_ARM_Page_TestAndClearAccessed(frame);
#else
	seL4_X86_Page_TestAndClearAccessed_t ret = seL4_X86_Page_TestAndClearAccessed(frame);
#endif
	*accessed = ret.error ? 0 : ret.accessed;
	return ret.error;
}

/* Complete the maps made with L4H_PROT_DEFER_FLUSH in `vspace`. */
int l4h_vspace_flush(unsigned long vspace)
{
#ifdef __aarch64__
	return 0;
#else
	return seL4_X64_PML4_Flush(vspace);
#endif
}

int l4h_pt_map(int type, unsigned long table, unsigned long vspace, unsigned long va)
{
#ifdef __aarch64__
	return seL4_ARM_PageTable_Map(table, vspace, va, seL4_ARM_Default_VMAttributes);
#else
	switch (type) {
	case L4H_OBJ_PT:
		return seL4_X86_PageTable_Map(table, vspace, va, seL4_X86_Default_VMAttributes);
	case L4H_OBJ_PD:
		return seL4_X86_PageDirectory_Map(table, vspace, va, seL4_X86_Default_VMAttributes);
	case L4H_OBJ_PDPT:
		return seL4_X86_PDPT_Map(table, vspace, va, seL4_X86_Default_VMAttributes);
	}
	return seL4_InvalidArgument;
#endif
}

int l4h_tcb_configure_user(unsigned long tcb, unsigned long cspace, unsigned long vspace)
{
	return seL4_TCB_Configure(tcb, cspace, 0, vspace, 0, 0, seL4_CapNull);
}

/* On MCS kernels SetSpace also (re)installs the fault handler. */
int l4h_tcb_set_space(unsigned long tcb, unsigned long fault_ep, unsigned long cspace,
		      unsigned long vspace)
{
	return seL4_TCB_SetSpace(tcb, fault_ep, cspace, 0, vspace, 0);
}

int l4h_tcb_sched(unsigned long tcb, unsigned long authority, int prio, unsigned long sc,
		  unsigned long fault_ep)
{
	return seL4_TCB_SetSchedParams(tcb, authority, prio, prio, sc, fault_ep);
}

int l4h_tcb_set_flags(unsigned long tcb, unsigned long clear, unsigned long set)
{
	seL4_TCB_SetFlags_t r = seL4_TCB_SetFlags(tcb, clear, set);

	if (r.error)
		return r.error;
	/* The kernel ignores flags it does not support. */
	return (r.flags & set) == set ? 0 : seL4_IllegalOperation;
}

int l4h_tcb_resume(unsigned long tcb)
{
	return seL4_TCB_Resume(tcb);
}

int l4h_tcb_suspend(unsigned long tcb)
{
	return seL4_TCB_Suspend(tcb);
}

int l4h_tcb_bind_notification(unsigned long tcb, unsigned long ntfn)
{
	return seL4_TCB_BindNotification(tcb, ntfn);
}

int l4h_sc_unbind(unsigned long sc)
{
	return seL4_SchedContext_Unbind(sc);
}

void l4h_signal(unsigned long ntfn)
{
	seL4_Signal(ntfn);
}

void l4h_yield(void)
{
	seL4_Yield();
}

unsigned long l4h_hypercall(unsigned long label, unsigned long *mrs, int n_in, int n_out)
{
	seL4_MessageInfo_t info;
	int i;

	for (i = 0; i < n_in; i++)
		seL4_SetMR(i, mrs[i]);
	info = seL4_Call(L4H_CPTR(L4H_SLOT_HYP_EP), seL4_MessageInfo_new(label, 0, 0, n_in));
	for (i = 0; i < n_out && i < (int)seL4_MessageInfo_get_length(info); i++)
		mrs[i] = seL4_GetMR(i);
	return seL4_MessageInfo_get_length(info) ? seL4_GetMR(0) : 0;
}

/* Record sequence numbers, shared by the vCPUs: the host prints the
 * records of all rings in this order. */
static unsigned int console_seq;

static void console_put(struct l4h_console_out *r, unsigned int off, const void *src, unsigned int n)
{
	const unsigned char *b = src;
	unsigned int i;

	for (i = 0; i < n; i++)
		r->data[(off + i) % L4H_CONSOLE_OUT_SIZE] = b[i];
}

/*
 * Write s as one record in this vCPU's console ring, as much of it as fits,
 * and return how much: this never waits.  Only this vCPU writes its ring,
 * and nothing interrupts kernel code here, so it takes no lock.  With
 * retry, the caller sends the rest later, and the host raises the console
 * event when there is room; without, the rest is counted as lost.
 */
static unsigned int console_out(const char *s, unsigned int len, int retry)
{
	struct l4h_vcpu *v = l4h_this_vcpu();
	struct l4h_console_out *r = &v->evt->console;
	struct l4h_console_rec rec;
	unsigned int head = r->head, used, room, n = 0;

	if (!len)
		return 0;
	/* A fault in here would come back (a crash report): drop that. */
	if (!v->in_console) {
		v->in_console = 1;
		/* The host is done with the bytes before tail. */
		used = (head + L4H_CONSOLE_OUT_WRAP - __atomic_load_n(&r->tail, __ATOMIC_ACQUIRE)) % L4H_CONSOLE_OUT_WRAP;
		room = used < L4H_CONSOLE_OUT_SIZE ? L4H_CONSOLE_OUT_SIZE - used : 0;
		if (room > sizeof(rec))
			n = len < room - sizeof(rec) ? len : room - (unsigned int)sizeof(rec);
		if (n) {
			rec.seq = __atomic_fetch_add(&console_seq, 1, __ATOMIC_RELAXED);
			rec.len = n;
			console_put(r, head, &rec, sizeof(rec));
			console_put(r, head + sizeof(rec), s, n);
			__atomic_store_n(&r->head, (head + sizeof(rec) + n) % L4H_CONSOLE_OUT_WRAP, __ATOMIC_RELEASE);
		}
		v->in_console = 0;
	}
	if (n < len) {
		if (retry)
			__atomic_store_n(&r->want_space, 1, __ATOMIC_RELAXED);
		else
			__atomic_store_n(&r->lost, r->lost + (len - n), __ATOMIC_RELAXED);
	}
	/* Kick a host that caught up (one still reading looks at head again
	 * after publishing its tail), or that should tell us about room. */
	__atomic_thread_fence(__ATOMIC_SEQ_CST);
	if (__atomic_load_n(&r->tail, __ATOMIC_RELAXED) == head || (retry && n < len))
		seL4_Signal(L4H_CPTR(L4H_SLOT_CONSOLE_KICK));
	return n;
}

unsigned int l4h_console_try_write(const char *s, unsigned int len)
{
	return console_out(s, len, 1);
}

void l4h_console_write(const char *s, unsigned int len)
{
	console_out(s, len, 0);
}

void l4h_power(int how)
{
	unsigned long mr = how;

	l4h_hypercall(L4H_HC_POWER, &mr, 1, 0);
	for (;;)
		seL4_Yield();
}

/* libsel4 debug assertions */
void __assert_fail(const char *assertion, const char *file, int line, const char *function)
{
	panic("libsel4 assertion failed: %s (%s:%d %s)\n", assertion, file, line, function);
}

#ifdef __aarch64__
void l4h_flush_icache(unsigned long start, unsigned long end)
{
	/* seL4's VSpace flush may not cross a page boundary. Module text
	 * can span many pages, with an unaligned start or end. */
	while (start < end) {
		unsigned long len = (1UL << seL4_PageBits) -
			(start & ((1UL << seL4_PageBits) - 1));

		if (len > end - start)
			len = end - start;
		l4h_BUG_ON(seL4_ARM_VSpace_Unify_Instruction(L4H_CPTR(L4H_SLOT_VSPACE), start, start + len));
		start += len;
	}
}
#endif

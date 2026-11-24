// SPDX-License-Identifier: GPL-2.0
/*
 * FL4 AArch64 through the guest provider, as a module that runs user code of
 * its own would use it (tests/run-highpactest-arm64.sh):
 *
 *  1. boot info and provider say there is an ArmHighVSpace and PAC keys,
 *     and every vCPU's kernel thread has its id in TPIDRRO_EL0;
 *  2. the kernel thread of this vCPU binds the ArmHighVSpace, maps a page
 *     at seL4_ARM_HighVSpaceBase, reads and writes it, calls code there and
 *     unbinds it again;
 *  3. the kernel thread signs and authenticates pointers with its own keys,
 *     then goes back to none;
 *  4. a user context made here (not a Linux thread's) on a pool VSpace and
 *     an empty CSpace, with its own PAC keys, stops at `svc #0x80` with the
 *     registers it computed, then page faults: run as a version-1 caller
 *     (l4h_user_run(), TPIDRRO_EL0 0, nothing written past struct l4h_uctx
 *     or the 37 words of gp[]), then with l4h_user_run_ex() (its own
 *     TPIDRRO_EL0, changed after a fault too, the fault's raw ESR, short
 *     struct l4h_user_ext, alignment faults);
 *  5. l4h_vspace_get() keeps one VSpace per vCPU for Linux.
 *
 * Prints "HIGHPAC: PASS", "HIGHPAC: SKIP ..." without FL4's extensions, or
 * "HIGHPAC: FAIL ...".  Only uses symbols the guest kernel exports.
 */
#include <linux/module.h>
#include <linux/atomic.h>
#include <linux/preempt.h>
#include <linux/smp.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <l4h_sys.h>
#include <l4h_caps.h>
#include <l4h_vspace.h>
#include <l4h/provider-registers.h>

/* seL4_ARM_HighVSpaceBase (FL4 libsel4), which modules do not include. */
#define HIGH_BASE	0xffffffe000000000ul
/* gp[] of a user context (provider-registers.h): version 1's 37 words, as
 * Linux's pt_regs has them, here followed by words the provider must not
 * touch. */
#define GP_WORDS	37
#define GUARD_WORDS	4
#define GUARD		0x5e5e5e5e5e5e5e5eul
#define GP_SP		L4H_GP_SP
#define GP_PC		L4H_GP_IP
#define GP_PSTATE	33
/* The user context's address space. */
#define U_CODE		0x400000ul
#define U_DATA		0x500000ul
#define U_HOLE		0x600008ul
#define U_COUNTER	(U_DATA + 0x100)
#define TLS_RO_VALUE	0x123456789abcdef0ul
#define TLS_RO_VALUE_2	0x0fedcba987654321ul

/* Provider version 1's struct l4h_uctx, which must never grow: a guest
 * built against it hands the provider no more. */
_Static_assert(sizeof(struct l4h_uctx) == 104, "struct l4h_uctx is version 1's");
_Static_assert(offsetof(struct l4h_uctx, badge) == 48, "struct l4h_uctx is version 1's");
_Static_assert(offsetof(struct l4h_uctx, fault_code) == 72, "struct l4h_uctx is version 1's");
_Static_assert(offsetof(struct l4h_uctx, fp_state) == 96, "struct l4h_uctx is version 1's");
_Static_assert(offsetof(struct l4h_user_ext, raw_fsr) == 24, "struct l4h_user_ext layout");

/* seL4_IllegalOperation: FL4 refuses PAC enables without FEAT_PAuth. */
#define ERR_ILLEGAL_OPERATION 3

#define fail(fmt, ...) do { \
	pr_err("HIGHPAC: FAIL " fmt "\n", ##__VA_ARGS__); \
	return -EINVAL; \
} while (0)

/* Code copied to the high window: f(x) = 3x + 0x77. */
extern const u32 hp_kcode[], hp_kcode_end[];
/*
 * User code: TPIDRRO_EL0, PAC (the HINT forms, NOPs without FEAT_PAuth) and
 * a syscall; then a counter in memory (x13) incremented once and a marker
 * in x6 before a page fault at x12; then TPIDRRO_EL0 again and a second
 * syscall; then an alignment fault (an exclusive load from x14), or a BRK
 * if there is none.
 */
extern const u32 hp_ucode[], hp_usvc1[], hp_ufault[], hp_usvc2[], hp_ualign[], hp_ucode_end[];
asm(".pushsection .rodata\n"
    ".arch armv8.3-a\n"
    ".balign 4\n"
    "hp_kcode:\n"
    "	add x1, x0, x0, lsl #1\n"
    "	add x0, x1, #0x77\n"
    "	ret\n"
    "hp_kcode_end:\n"
    ".balign 4\n"
    "hp_ucode:\n"
    "	mrs x0, tpidrro_el0\n"
    "	mov x17, x10\n"
    "	mov x16, x11\n"
    "	pacia1716\n"
    "	mov x1, x17\n"
    "	autia1716\n"
    "	mov x2, x17\n"
    "	mov x17, x10\n"
    "	pacib1716\n"
    "	mov x3, x17\n"
    "	mov x16, #42\n"
    "	svc #0x80\n"
    "hp_usvc1:\n"
    "	ldr x9, [x13]\n"
    "	add x9, x9, #1\n"
    "	str x9, [x13]\n"
    "	mov x6, #0x666\n"
    "hp_ufault:\n"
    "	ldr x5, [x12]\n"
    "	mrs x0, tpidrro_el0\n"
    "	mov x16, #43\n"
    "	svc #0x80\n"
    "hp_usvc2:\n"
    "hp_ualign:\n"
    "	ldxr x0, [x14]\n"
    "	brk #1\n"
    "hp_ucode_end:\n"
    ".arch armv8-a\n"
    ".popsection\n");

static const unsigned long keys_a[L4H_PAC_KEY_WORDS] = {
	0x0123456789abcdef, 0xfedcba9876543210, 0x1111222233334444, 0x5555666677778888,
	0x9999aaaabbbbcccc, 0xddddeeeeffff0000, 0x0f0e0d0c0b0a0908, 0x0706050403020100,
	0xa5a5a5a55a5a5a5a, 0x3c3c3c3cc3c3c3c3,
};
static const unsigned long keys_b[L4H_PAC_KEY_WORDS] = {
	0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa,
};

/* Page tables made for mappings, deleted with them. */
struct tables {
	struct l4h_obj pt[8];
	int n;
};

/* Map `frame` at `va` of `vspace`, with the tables it needs below the
 * existing ones (the ArmHighVSpace has its level 1 built in). */
static int map(unsigned long frame, unsigned long vspace, unsigned long va, int prot,
	       struct tables *t)
{
	int err;

	while ((err = l4h_page_map(frame, vspace, va, prot)) == L4H_ERR_FAILED_LOOKUP) {
		if (t->n == ARRAY_SIZE(t->pt))
			return -ENOSPC;
		if (l4h_obj_alloc(L4H_OBJ_PT, 0, &t->pt[t->n]))
			return -ENOMEM;
		err = l4h_pt_map(L4H_OBJ_PT, t->pt[t->n++].cptr, vspace, va);
		if (err)
			return err;
	}
	return err;
}

static void free_tables(struct tables *t)
{
	while (t->n)
		l4h_obj_free(&t->pt[--t->n]);
}

/* A frame of its own, written through a kernel mapping of a copy. */
struct page_alias {
	struct l4h_obj frame;
	void *va;
	unsigned long slot;
};

static void alias_put(struct page_alias *p)
{
	if (p->slot)
		l4h_slot_delete(p->slot);
	if (p->va)
		l4h_kernel_va_put(p->va);
	l4h_obj_free(&p->frame);
	memset(p, 0, sizeof(*p));
}

/* Nothing held if it fails. */
static int alias_get(struct page_alias *p)
{
	memset(p, 0, sizeof(*p));
	if (l4h_obj_alloc(L4H_OBJ_FRAME, 0, &p->frame))
		return -ENOMEM;
	p->va = l4h_kernel_va_get(PAGE_SIZE);
	if (p->va)
		p->slot = l4h_kernel_map_frame(p->frame.cptr, (unsigned long)p->va);
	if (!p->slot) {
		alias_put(p);
		return -ENOMEM;
	}
	memset(p->va, 0, PAGE_SIZE);
	return 0;
}

/* 2: the high window on this vCPU's kernel thread. */
static int test_high_window(void)
{
	unsigned long high = L4H_CPTR(L4H_SLOT_HIGH_VSPACE);
	volatile unsigned long *hw = (volatile unsigned long *)HIGH_BASE;
	unsigned long (*fn)(unsigned long) = (void *)HIGH_BASE;
	struct tables t = { .n = 0 };
	struct page_alias p;
	unsigned long r, seen;
	int err, ret = -EINVAL;

	err = alias_get(&p);
	if (err)
		goto out;
	memcpy(p.va, hp_kcode, (hp_kcode_end - hp_kcode) * 4);
	((unsigned long *)p.va)[256] = 0x5a5a5a5a12345678;
	/* Executable: the map makes the instruction cache see the code. */
	err = map(p.frame.cptr, high, HIGH_BASE, L4H_PROT_READ | L4H_PROT_WRITE | L4H_PROT_EXEC, &t);
	if (err) {
		pr_err("HIGHPAC: FAIL map in the high window: %d\n", err);
		goto out;
	}
	/* Bound to this vCPU's kernel thread: stay on it. */
	preempt_disable();
	err = l4h_tcb_set_high_vspace(0, high);
	if (err) {
		preempt_enable();
		pr_err("HIGHPAC: FAIL bind the high window: %d\n", err);
		goto out;
	}
	seen = hw[256];
	hw[257] = 0xc0ffee0000c0ffee;
	r = fn(5);
	err = l4h_tcb_set_high_vspace(0, 0);
	preempt_enable();
	pr_info("HIGHPAC: high window read %lx, f(5) = %lx, low alias sees %lx\n",
		seen, r, ((unsigned long *)p.va)[257]);
	if (err)
		pr_err("HIGHPAC: FAIL unbind the high window: %d\n", err);
	else if (seen != 0x5a5a5a5a12345678)
		pr_err("HIGHPAC: FAIL high window read %lx\n", seen);
	else if (((unsigned long *)p.va)[257] != 0xc0ffee0000c0ffee)
		pr_err("HIGHPAC: FAIL high window write not in the frame\n");
	else if (r != 5 * 3 + 0x77)
		pr_err("HIGHPAC: FAIL high window code returned %lx\n", r);
	else
		ret = 0;
	err = l4h_page_unmap(p.frame.cptr);
	if (err && !ret) {
		pr_err("HIGHPAC: FAIL unmap in the high window: %d\n", err);
		ret = -EINVAL;
	}
out:
	free_tables(&t);
	alias_put(&p);
	return ret;
}

static unsigned long pacia(unsigned long p, unsigned long mod)
{
	asm volatile(".arch armv8.3-a\n pacia %0, %1\n .arch armv8-a" : "+r"(p) : "r"(mod));
	return p;
}

static unsigned long autia(unsigned long p, unsigned long mod)
{
	asm volatile(".arch armv8.3-a\n autia %0, %1\n .arch armv8-a" : "+r"(p) : "r"(mod));
	return p;
}

static unsigned long pacga(unsigned long p, unsigned long mod)
{
	unsigned long r;

	asm volatile(".arch armv8.3-a\n pacga %0, %1, %2\n .arch armv8-a" : "=r"(r) : "r"(p), "r"(mod));
	return r;
}

static bool has_pauth;

/* 3: PAC keys on this vCPU's kernel thread. */
static int test_kernel_pac(void)
{
	const unsigned long ptr = 0x0000123456789ab0, m1 = 0x1234, m2 = 0x4321;
	unsigned long a1, a2, b1, ga_a, ga_none, z1, back1, back2;
	int e1, e2, e3;

	preempt_disable();
	e1 = l4h_tcb_set_pac(0, L4H_PAC_EN_IA | L4H_PAC_EN_IB | L4H_PAC_EN_DA | L4H_PAC_EN_DB, keys_a);
	if (e1 == ERR_ILLEGAL_OPERATION) {
		/* No FEAT_PAuth: PACIA would be undefined, keys stay off. */
		e3 = l4h_tcb_set_pac(0, 0, NULL);
		preempt_enable();
		if (e3)
			fail("clear PAC keys without FEAT_PAuth: %d", e3);
		pr_info("HIGHPAC: no FEAT_PAuth: PAC enables refused, PAC tests skipped\n");
		return 0;
	}
	has_pauth = !e1;
	a1 = pacia(ptr, m1);
	a2 = pacia(ptr, m2);
	back1 = autia(a1, m1);
	back2 = autia(a2, m2);
	ga_a = pacga(ptr, m1);
	e2 = l4h_tcb_set_pac(0, L4H_PAC_EN_IA, keys_b);
	b1 = pacia(ptr, m1);
	e3 = l4h_tcb_set_pac(0, 0, NULL);
	z1 = pacia(ptr, m1);
	ga_none = pacga(ptr, m1);
	preempt_enable();
	pr_info("HIGHPAC: kernel PAC: key A %lx %lx, key B %lx, none %lx; GA %lx, without keys %lx\n",
		a1, a2, b1, z1, ga_a, ga_none);
	if (e1 || e2 || e3)
		fail("set PAC keys: %d %d %d", e1, e2, e3);
	if (a1 == ptr && a2 == ptr)
		fail("pacia left the pointer as it was");
	if (back1 != ptr || back2 != ptr)
		fail("autia gave %lx %lx", back1, back2);
	if (b1 == a1)
		fail("another key signs the same");
	if (z1 != ptr)
		fail("pacia without keys changed the pointer: %lx", z1);
	if (ga_a == ga_none)
		fail("pacga with keys and without agree");
	return 0;
}

/* A user context as a version-1 caller lays it out: no room after it. */
struct guarded_uctx {
	struct l4h_uctx u;
	unsigned long guard[GUARD_WORDS];
};

static int guards_intact(const struct guarded_uctx *w, const unsigned long *gp)
{
	int i;

	for (i = 0; i < GUARD_WORDS; i++)
		if (w->guard[i] != GUARD || gp[GP_WORDS + i] != GUARD)
			return 0;
	return 1;
}

/* Run u to its next stop that is not an event's. */
static int run(struct l4h_uctx *u, unsigned long *gp, struct l4h_user_ext *ext)
{
	int stop;

	while ((stop = ext ? l4h_user_run_ex(u, gp, 0, ext) : l4h_user_run(u, gp, 0)) ==
	       L4H_STOP_INTERRUPT)
		l4h_poll_events();
	return stop;
}

#define ucheck(cond, fmt, ...) do { \
	if (!(cond)) { \
		pr_err("HIGHPAC: FAIL %s: " fmt "\n", how, ##__VA_ARGS__); \
		goto stop; \
	} \
} while (0)

/*
 * 4: a user context of the module's own.  As a version-1 caller
 * (!with_ext), with l4h_user_run(): TPIDRRO_EL0 reads 0, and neither run
 * nor l4h_user_sync_seg() nor l4h_user_sync_regs() writes past struct
 * l4h_uctx or gp[GP_WORDS].  With l4h_user_run_ex():
 *  - a struct l4h_user_ext that ends before raw_fsr gives TPIDRRO_EL0 and
 *    has nothing written after it;
 *  - the page fault's raw ESR;
 *  - TPIDRRO_EL0 changed at the page fault, where gp[] was not read
 *    (L4H_USER_EXT_TLS_RO_UPDATE), reaches the context without rolling it
 *    back to the stale gp[] of the first syscall;
 *  - an alignment fault is an exception, without a raw_fsr.
 */
static int test_user_context(int with_ext)
{
	struct l4h_obj tcb = { 0 }, reply = { 0 };
	struct tables t = { .n = 0 };
	struct page_alias code = { 0 }, data = { 0 }, hole = { 0 };
	struct l4h_user_ext ext = { .size = sizeof(ext), .flags = L4H_USER_EXT_TLS_RO,
				    .tls_ro = TLS_RO_VALUE };
	/* The first three words of a struct l4h_user_ext, then a guard. */
	unsigned long short_ext[4] = { offsetof(struct l4h_user_ext, raw_fsr), L4H_USER_EXT_TLS_RO,
				       TLS_RO_VALUE, GUARD };
	const char *how = with_ext ? "l4h_user_run_ex" : "l4h_user_run";
	unsigned long svc1 = U_CODE + (hp_usvc1 - hp_ucode) * 4;
	unsigned long fault_ip = U_CODE + (hp_ufault - hp_ucode) * 4;
	unsigned long svc2 = U_CODE + (hp_usvc2 - hp_ucode) * 4;
	unsigned long align_ip = U_CODE + (hp_ualign - hp_ucode) * 4;
	unsigned long *gp, vs = 0, fault_ep = 0, s1[4];
	struct guarded_uctx *w;
	struct l4h_uctx *u;
	int cpu, stop, err, i, ret = -EINVAL, mapped = 0;

	w = kmalloc(sizeof(*w), GFP_KERNEL);
	gp = kmalloc_array(GP_WORDS + GUARD_WORDS, sizeof(*gp), GFP_KERNEL);
	if (!w || !gp)
		goto out;
	memset(&w->u, 0, sizeof(w->u));
	memset(gp, 0, GP_WORDS * sizeof(*gp));
	for (i = 0; i < GUARD_WORDS; i++)
		w->guard[i] = gp[GP_WORDS + i] = GUARD;
	u = &w->u;
	if (alias_get(&code) || alias_get(&data) || alias_get(&hole))
		goto out;
	memcpy(code.va, hp_ucode, (hp_ucode_end - hp_ucode) * 4);
	if (l4h_obj_alloc(L4H_OBJ_TCB, 0, &tcb) || l4h_obj_alloc(L4H_OBJ_REPLY, 0, &reply))
		goto out;
	fault_ep = l4h_slot_alloc();
	if (!fault_ep)
		goto out;
	vs = l4h_vspace_get();
	if (!vs) {
		pr_err("HIGHPAC: FAIL no VSpace to spare\n");
		goto out;
	}
	err = map(code.frame.cptr, vs, U_CODE, L4H_PROT_READ | L4H_PROT_EXEC, &t);
	if (!err)
		err = map(data.frame.cptr, vs, U_DATA, L4H_PROT_READ | L4H_PROT_WRITE, &t);
	if (err) {
		pr_err("HIGHPAC: FAIL map the user pages: %d\n", err);
		goto out;
	}
	mapped = 1;
	u->tcb = tcb.cptr;
	u->reply = reply.cptr;
	u->badge = l4h_uctx_alloc_badge();
	u->fault_ep_vcpu = -1;
	u->sc_vcpu = -1;
	u->vspace = vs;
	u->fp_state = L4H_FP_IN_TCB;
	err = l4h_tcb_set_flags(u->tcb, 1 /* fpuDisabled */, 2 /* trapSyscalls */);
	if (!err)
		err = l4h_tcb_configure_user(u->tcb, l4h_empty_cnode_cptr(), vs);
	if (!err)
		err = l4h_tcb_set_pac(u->tcb, has_pauth ? L4H_PAC_EN_IA | L4H_PAC_EN_IB : 0, keys_b);
	if (err) {
		pr_err("HIGHPAC: FAIL configure the user context: %d\n", err);
		goto out;
	}
	u->state = L4H_UCTX_FRESH;
	u->regs_valid = 1;
	gp[GP_PC] = U_CODE;
	gp[GP_SP] = U_DATA + PAGE_SIZE;
	gp[GP_PSTATE] = 0;
	gp[10] = U_DATA + 0x40;
	gp[11] = 0x77;	/* the modifier */
	gp[12] = U_HOLE;
	gp[13] = U_COUNTER;
	/* Unaligned across 16 bytes: FEAT_LSE2 lets unaligned exclusives
	 * within a 16-byte block through. */
	gp[14] = U_DATA + 15;
	l4h_user_mark_dirty(u, 1);

	/* Its fault endpoint and the user scheduling context are this vCPU's:
	 * stay on it, and take SC_U from the Linux thread that holds it (it
	 * takes it back when it next runs). */
	preempt_disable();
	cpu = l4h_this_vcpu_id();
	if (l4h_vcpus[cpu].sc_owner)
		l4h_user_deschedule(l4h_vcpus[cpu].sc_owner);
	err = l4h_cnode_mint(fault_ep, 64, L4H_SLOT_VCPU(cpu) + L4H_VCPU_EP, L4H_ROOT_DEPTH,
			     L4H_RIGHTS_ALL, u->badge);
	ucheck(!err, "mint the fault endpoint: %d", err);
	u->fault_ep = fault_ep;
	u->fault_ep_vcpu = cpu;

	stop = run(u, gp, with_ext ? (struct l4h_user_ext *)short_ext : NULL);
	ucheck(stop == L4H_STOP_SYSCALL, "first stop %d (addr %lx ip %lx exc %lx code %lx)", stop,
	       u->fault_addr, u->fault_ip, u->exc_number, u->fault_code);
	pr_info("HIGHPAC: %s syscall: x0 %lx x1 %lx x2 %lx x3 %lx x8 %lx x16 %lx pc %lx\n",
		how, gp[0], gp[1], gp[2], gp[3], gp[8], gp[16], gp[GP_PC]);
	ucheck(gp[0] == (with_ext ? TLS_RO_VALUE : 0), "TPIDRRO_EL0 %lx", gp[0]);
	ucheck(gp[16] == 42 && gp[GP_PC] == svc1, "x16 %lx pc %lx", gp[16], gp[GP_PC]);
	ucheck(short_ext[3] == GUARD, "wrote past a short struct l4h_user_ext: %lx", short_ext[3]);
	for (i = 0; i < 4; i++)
		s1[i] = gp[i];
	ucheck(gp[2] == gp[10], "AUTIA gave %lx", gp[2]);
	ucheck(!has_pauth || (s1[1] != gp[10] || s1[3] != gp[10]), "PACIA/PACIB left the pointer");
	ucheck(!has_pauth || s1[1] != s1[3], "IA and IB keys sign the same");
	l4h_user_sync_seg(u, gp);

	/* l4h_user_run_ex() clears it first; a version-1 run leaves it. */
	ext.raw_fsr = with_ext ? 0xdeadbeef : 0;
	stop = run(u, gp, with_ext ? &ext : NULL);
	ucheck(stop == L4H_STOP_PAGEFAULT, "second stop %d (exc %lx code %lx)", stop,
	       u->exc_number, u->fault_code);
	pr_info("HIGHPAC: %s fault at %lx ip %lx: raw_fsr %lx (EC %lx), fault_code %lx\n",
		how, u->fault_addr, u->fault_ip, ext.raw_fsr, ext.raw_fsr >> 26, u->fault_code);
	ucheck(u->fault_addr == U_HOLE && u->fault_ip == fault_ip, "fault at %lx ip %lx",
	       u->fault_addr, u->fault_ip);
	ucheck(!with_ext || (ext.raw_fsr >> 26) == 0x24, "raw_fsr %lx is no data abort from EL0",
	       ext.raw_fsr);
	if (!with_ext) {
		/* Registers are in the TCB alone after a fault: read them. */
		l4h_user_sync_seg(u, gp);
		l4h_user_sync_regs(u, gp);
		ucheck(gp[GP_PC] == fault_ip && gp[6] == 0x666, "registers read: pc %lx x6 %lx",
		       gp[GP_PC], gp[6]);
		ucheck(guards_intact(w, gp), "wrote past struct l4h_uctx or gp[%d]", GP_WORDS);
		ret = 0;
		goto stop;
	}

	/* Map the page, and change TPIDRRO_EL0 without reading gp[]. */
	err = map(hole.frame.cptr, vs, U_HOLE & PAGE_MASK, L4H_PROT_READ | L4H_PROT_WRITE, &t);
	ucheck(!err, "map the faulting page: %d", err);
	ext.tls_ro = TLS_RO_VALUE_2;
	ext.flags |= L4H_USER_EXT_TLS_RO_UPDATE;
	stop = run(u, gp, &ext);
	ext.flags &= ~L4H_USER_EXT_TLS_RO_UPDATE;
	ucheck(stop == L4H_STOP_SYSCALL, "third stop %d (addr %lx ip %lx exc %lx code %lx)", stop,
	       u->fault_addr, u->fault_ip, u->exc_number, u->fault_code);
	pr_info("HIGHPAC: %s second syscall: x0 %lx x6 %lx x16 %lx pc %lx, counter %lx\n", how,
		gp[0], gp[6], gp[16], gp[GP_PC], ((unsigned long *)data.va)[0x100 / 8]);
	ucheck(gp[0] == TLS_RO_VALUE_2, "updated TPIDRRO_EL0 %lx", gp[0]);
	ucheck(gp[16] == 43 && gp[GP_PC] == svc2 && gp[6] == 0x666, "x16 %lx pc %lx x6 %lx",
	       gp[16], gp[GP_PC], gp[6]);
	ucheck(((unsigned long *)data.va)[0x100 / 8] == 1, "the code after the first syscall ran again");

	/* An alignment fault is an exception: no raw_fsr. */
	ext.raw_fsr = 0xdeadbeef;
	stop = run(u, gp, &ext);
	pr_info("HIGHPAC: %s alignment fault: stop %d ip %lx exc %lx raw_fsr %lx\n", how, stop,
		u->fault_ip, u->exc_number, ext.raw_fsr);
	ucheck(stop == L4H_STOP_EXCEPTION && (u->exc_number & 0x3f) == 0x21 &&
	       (u->exc_number >> 26) == 0x24 && u->fault_ip == align_ip,
	       "alignment fault: stop %d exc %lx ip %lx", stop, u->exc_number, u->fault_ip);
	ucheck(ext.raw_fsr == 0, "alignment fault raw_fsr %lx", ext.raw_fsr);
	ucheck(guards_intact(w, gp), "wrote past struct l4h_uctx or gp[%d]", GP_WORDS);
	ret = 0;
stop:
	l4h_user_deschedule(u);
	preempt_enable();
out:
	if (tcb.cptr) {
		l4h_tcb_suspend(tcb.cptr);
		l4h_obj_free(&tcb);
	}
	l4h_obj_free(&reply);
	if (fault_ep)
		l4h_slot_delete(fault_ep);
	if (mapped) {
		l4h_page_unmap(code.frame.cptr);
		l4h_page_unmap(data.frame.cptr);
		l4h_page_unmap(hole.frame.cptr);
	}
	free_tables(&t);
	if (vs)
		l4h_vspace_put(vs);
	alias_put(&code);
	alias_put(&data);
	alias_put(&hole);
	kfree(gp);
	kfree(w);
	return ret;
}

/* 5: lending pool VSpaces stops one per vCPU short of the pool, and
 * l4h_vspace_put(0) changes nothing. */
static int test_vspace_lending(void)
{
	int want = (int)l4h_bootinfo->nr_vspaces - (int)nr_cpu_ids, n = 0, again = 0, i;
	unsigned long *vs = kcalloc(l4h_bootinfo->nr_vspaces, sizeof(*vs), GFP_KERNEL);
	int ret = -EINVAL;

	if (!vs)
		return -ENOMEM;
	l4h_vspace_put(0);
	while (n < (int)l4h_bootinfo->nr_vspaces && (vs[n] = l4h_vspace_get()))
		n++;
	l4h_vspace_put(0);
	for (i = 0; i < n; i++)
		l4h_vspace_put(vs[i]);
	while (again < (int)l4h_bootinfo->nr_vspaces && (vs[again] = l4h_vspace_get()))
		again++;
	for (i = 0; i < again; i++)
		l4h_vspace_put(vs[i]);
	kfree(vs);
	pr_info("HIGHPAC: lent %d of %llu VSpaces with %u vCPUs, then %d\n", n,
		l4h_bootinfo->nr_vspaces, nr_cpu_ids, again);
	if (n != want || again != want)
		pr_err("HIGHPAC: FAIL VSpace lending: %d then %d, not %d\n", n, again, want);
	else
		ret = 0;
	return ret;
}

static atomic_t tpidrro_bad = ATOMIC_INIT(0);

static void check_tpidrro(void *unused)
{
	unsigned long v;

	asm volatile("mrs %0, tpidrro_el0" : "=r"(v));
	if (v != smp_processor_id()) {
		pr_err("HIGHPAC: vCPU %d has TPIDRRO_EL0 %lx\n", smp_processor_id(), v);
		atomic_inc(&tpidrro_bad);
	}
}

static int __init highpac_init(void)
{
	unsigned long want = L4H_PROVIDER_ARM_PAC | L4H_PROVIDER_ARM_HIGH_VSPACE;
	unsigned long features = l4h_provider_features();

	pr_info("HIGHPAC: boot flags %llx, provider features %lx\n", l4h_bootinfo->flags, features);
	if ((features & want) != want) {
		pr_info("HIGHPAC: SKIP no FL4 PAC keys or high window in this provider\n");
		return 0;
	}
	if (!(l4h_bootinfo->flags & L4H_BOOT_HIGH_VSPACE))
		fail("no L4H_BOOT_HIGH_VSPACE");
	on_each_cpu(check_tpidrro, NULL, 1);
	if (atomic_read(&tpidrro_bad))
		fail("TPIDRRO_EL0 is not the vCPU id");
	pr_info("HIGHPAC: TPIDRRO_EL0 is the vCPU id on %u vCPUs\n", num_online_cpus());
	if (test_high_window())
		return -EINVAL;
	pr_info("HIGHPAC: high window OK\n");
	if (test_kernel_pac())
		return -EINVAL;
	pr_info("HIGHPAC: kernel PAC OK\n");
	if (test_user_context(0))
		return -EINVAL;
	pr_info("HIGHPAC: version-1 user context OK\n");
	if (test_user_context(1))
		return -EINVAL;
	pr_info("HIGHPAC: user context OK\n");
	if (test_vspace_lending())
		return -EINVAL;
	pr_info("HIGHPAC: VSpace lending OK\n");
	pr_info("HIGHPAC: PASS\n");
	return 0;
}

static void __exit highpac_exit(void)
{
}

module_init(highpac_init);
module_exit(highpac_exit);
MODULE_DESCRIPTION("l4h: FL4 AArch64 high window and PAC keys through the provider");
MODULE_LICENSE("GPL");

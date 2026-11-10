// SPDX-License-Identifier: GPL-2.0-only
/*
 * A seL4 root task for tests/run-vcpustress.sh: SMP stress of the VCPU
 * interface (patches 0039 and 0040), below l4h-root.
 *
 * Two runner threads keep a long-mode guest in seL4_VMEnter on cores 1 and 2
 * while the root thread (core 0) and a second attacker (core 3) do to them
 * what any holder of their capabilities can: signal their notifications,
 * read and write their VCPUs, flush them, take guest pages and whole page
 * tables out of their EPT, suspend and resume them, change their priority,
 * scheduling context, core, flags, FPU state and deadline timer, rebind
 * their VCPU, swap it for another, and in the end delete everything under
 * them.  The kernel must survive, and each runner checks what every VMEnter
 * returns: the guest's counter never goes back, its registers keep their
 * values, and exits come where the guest's code makes them.  At the end a
 * thread on each core that ran a guest executes SYSENTER, which must fault:
 * seL4 is entered with SYSCALL, and a VM exit must not leave SYSENTER armed.
 *
 * Built with -DTFSTEP the guests run with RFLAGS.TF set, so every guest
 * instruction is a #DB exit (seL4 always intercepts #DB) and a runner sees
 * the guest's RIP after each one: an exit the kernel drops, or a VMEnter
 * result it discards, shows as an instruction the guest passed without one.
 * Built with -DONECORE every thread runs on core 0, where the guests are
 * preempted in guest mode instead of interrupted from another core.
 *
 * Built freestanding against build/sel4's libsel4, as tests/vtxprobe.c.
 */
#include <sel4/sel4.h>
#include <sel4/arch/vmenter.h>

__thread seL4_IPCBuffer *__sel4_ipc_buffer;
static char tls[5][4096] __attribute__((aligned(64)));
char vcpustress_stack[16384] __attribute__((aligned(16)));
static char stacks[5][16384] __attribute__((aligned(16)));

#ifndef ROUNDS
#define ROUNDS 40
#endif
/* The operations to run, a bit per case of attack(): all of them. */
#ifndef MASK
#define MASK ~0ul
#endif
#ifdef ONECORE
#define CORE(c) 0
/* Priorities are strict: equal ones, or someone starves. */
#define PRIO(p) 100
#else
#define CORE(c) (c)
#define PRIO(p) (p)
#endif

/* AMD-V: VMCB offsets and exit codes (patch 0040). */
#define VMCB_TSC_OFFSET 0x050
#define VMCB_ES         0x400
#define VMCB_CS         0x410
#define VMCB_SS         0x420
#define VMCB_DS         0x430
#define VMCB_EFER       0x4d0
#define VMCB_CR4        0x548
#define VMCB_CR3        0x550
#define VMCB_CR0        0x558
#define VMCB_RFLAGS     0x570
#define VMCB_RIP        0x578
#define VMCB_RSP        0x5d8
#define SVM_EXIT_DB     0x41
#define SVM_EXIT_INTR   0x60
#define SVM_EXIT_IOIO   0x7b
#define SVM_EXIT_NPF    0x400
/* VT-x: VMCS fields and exit reasons (patch 0039). */
#define VMX_TSC_OFFSET  0x2010
#define VMX_ES_SEL      0x0800
#define VMX_ES_LIMIT    0x4800
#define VMX_ES_AR       0x4814
#define VMX_ES_BASE     0x6806
#define VMX_GDTR_LIMIT  0x4810
#define VMX_IDTR_LIMIT  0x4812
#define VMX_GUEST_CR0   0x6800
#define VMX_GUEST_CR3   0x6802
#define VMX_GUEST_CR4   0x6804
#define VMX_GUEST_DR7   0x681a
#define VMX_GUEST_RSP   0x681c
#define VMX_GUEST_RIP   0x681e
#define VMX_GUEST_RFLAGS 0x6820
#define VMX_EXIT_EXCEPTION 0x00
#define VMX_EXIT_EXTINT 0x01
#define VMX_EXIT_IO     0x1e
#define VMX_EXIT_EPT    0x30

#define MSR_KERNEL_GS_BASE 0xc0000102
#define MAGIC 0x5a5a1234deadbeeful
#ifdef TFSTEP
#define GUEST_RFLAGS 0x102
#else
#define GUEST_RFLAGS 0x2
#endif

static volatile int print_lock;
/* Errors are expected once the teardown has started. */
static volatile int tolerate;
static int amd;
static seL4_BootInfo *bi;
static seL4_CPtr ut, next_slot;
static unsigned long va_next = 0x8000000000ul;

static void puts_(const char *s)
{
    while (*s)
        seL4_DebugPutChar(*s++);
}

static void say_(const char *what, unsigned long v)
{
    char b[17];
    int i = 16;

    b[16] = 0;
    do {
        b[--i] = "0123456789abcdef"[v & 15];
        v >>= 4;
    } while (v);
    puts_("vcpustress: ");
    puts_(what);
    puts_(" 0x");
    puts_(b + i);
    puts_("\n");
}

/* The threads print from four cores. */
static void lock_print(void)
{
    while (__sync_lock_test_and_set(&print_lock, 1))
        __asm__ volatile("pause");
}

static void say(const char *what, unsigned long v)
{
    lock_print();
    say_(what, v);
    __sync_lock_release(&print_lock);
}

/* Keeps the print lock: the first failure is the one reported. */
static void fail(void)
{
    puts_("vcpustress: FAIL\n");
    for (;;)
        seL4_Yield();
}

static void die(const char *what, unsigned long v)
{
    lock_print();
    say_(what, v);
    fail();
}

#define CK(e) do { \
        unsigned long e_ = (unsigned long)(e); \
        if (e_ && !tolerate) \
            die(#e, e_); \
    } while (0)

static seL4_CPtr retype(seL4_Word type, seL4_Word bits)
{
    seL4_CPtr s = next_slot++;

    CK(seL4_Untyped_Retype(ut, type, bits, seL4_CapInitThreadCNode, 0, 0, s, 1));
    return s;
}

/* Map a frame into the root's VSpace, and return where. */
static unsigned long map_root(seL4_CPtr frame)
{
    unsigned long va = va_next;

    va_next += 4096;
    CK(seL4_X86_Page_Map(frame, seL4_CapInitThreadVSpace, va, seL4_ReadWrite,
                         seL4_X86_Default_VMAttributes));
    return va;
}

struct guest {
    seL4_CPtr vcpu[2], pml4, pdpt, pd, pt, frames[6], extra;
    seL4_CPtr tcb, sc, ntfn, ipcframe, fpuframe;
    volatile unsigned long *counter;    /* the guest's page at 0x4000 */
    unsigned long ipcbuf;
    volatile unsigned long exits, notifs, npfs;
    int core, cur;
};
static struct guest g[2];

/*
 * The guest, in 64-bit mode at 0: count at 0x4000, read the page at 0x7000
 * (which the attackers take out and put back), and every 1024 rounds make an
 * I/O exit.
 */
static const unsigned char guest_code[] = {
    /* 0x00 */ 0x48, 0xff, 0x04, 0x25, 0x00, 0x40, 0x00, 0x00,  /* incq 0x4000 */
    /* 0x08 */ 0x48, 0x8b, 0x04, 0x25, 0x00, 0x40, 0x00, 0x00,  /* mov 0x4000, %rax */
    /* 0x10 */ 0x48, 0x8b, 0x1c, 0x25, 0x00, 0x70, 0x00, 0x00,  /* mov 0x7000, %rbx */
    /* 0x18 */ 0xa9, 0xff, 0x03, 0x00, 0x00,                    /* test $0x3ff, %eax */
    /* 0x1d */ 0x75, 0xe1,                                      /* jnz 0x00 */
    /* 0x1f */ 0xe6, 0x80,                                      /* out %al, $0x80 */
    /* 0x21 */ 0xeb, 0xdd,                                      /* jmp 0x00 */
};
/* The instruction after each one that falls through or jumps to one place:
 * 0x1d goes to 0x00 or 0x1f, and the runner steps over the OUT at 0x1f. */
static const unsigned char guest_next[sizeof(guest_code)] = {
    [0x00] = 0x08, [0x08] = 0x10, [0x10] = 0x18, [0x18] = 0x1d, [0x1d] = 0x00, [0x21] = 0x00,
};

static void wvmcb(seL4_CPtr vcpu, unsigned long off, unsigned long v)
{
    seL4_X86_VCPU_WriteVMCB_t w = seL4_X86_VCPU_WriteVMCB(vcpu, off, v);

    if (w.error && !tolerate)
        die("WriteVMCB", off);
}

static void wvmcs(seL4_CPtr vcpu, unsigned long field, unsigned long v)
{
    seL4_X86_VCPU_WriteVMCS_t w = seL4_X86_VCPU_WriteVMCS(vcpu, field, v);

    if (w.error && !tolerate)
        die("WriteVMCS", field);
}

/* 64-bit mode at CPL 0, paging on, the page table at 0x1000. */
static void init_vcpu(seL4_CPtr vcpu)
{
    seL4_VCPUContext r = { 0 };

    if (amd) {
        wvmcb(vcpu, VMCB_CS, 8 | 0xa9bul << 16 | 0xfffffffful << 32);
        wvmcb(vcpu, VMCB_CS + 8, 0);
        wvmcb(vcpu, VMCB_SS, 0x10 | 0xc93ul << 16 | 0xfffffffful << 32);
        wvmcb(vcpu, VMCB_DS, 0x10 | 0xc93ul << 16 | 0xfffffffful << 32);
        wvmcb(vcpu, VMCB_ES, 0x10 | 0xc93ul << 16 | 0xfffffffful << 32);
        wvmcb(vcpu, VMCB_EFER, 0x1500);            /* LME, LMA; SVME is forced */
        wvmcb(vcpu, VMCB_CR4, 0x20);               /* PAE */
        wvmcb(vcpu, VMCB_CR3, 0x1000);
        wvmcb(vcpu, VMCB_CR0, 0x80000031ul);       /* PG, NE, ET, PE */
        wvmcb(vcpu, VMCB_RFLAGS, GUEST_RFLAGS);
        wvmcb(vcpu, VMCB_RSP, 0x5ff0);
    } else {
        /* ES, CS, SS, DS, FS, GS, LDTR, TR: selector, limit, rights, base.
         * A new VCPU enters IA-32e mode, and without "load IA32_EFER" the
         * entry sets EFER.LME and LMA from that. */
        static const struct {
            unsigned short sel;
            unsigned int limit, ar;
        } seg[8] = {
            { 0x10, 0xffffffff, 0xc093 }, { 0x08, 0xffffffff, 0xa09b },
            { 0x10, 0xffffffff, 0xc093 }, { 0x10, 0xffffffff, 0xc093 },
            { 0x10, 0xffffffff, 0xc093 }, { 0x10, 0xffffffff, 0xc093 },
            { 0, 0, 0x10000 },            /* LDTR: unusable */
            { 0x18, 0x67, 0x8b },         /* TR: a busy 64-bit TSS */
        };
        for (int i = 0; i < 8; i++) {
            wvmcs(vcpu, VMX_ES_SEL + 2 * i, seg[i].sel);
            wvmcs(vcpu, VMX_ES_LIMIT + 2 * i, seg[i].limit);
            wvmcs(vcpu, VMX_ES_AR + 2 * i, seg[i].ar);
            wvmcs(vcpu, VMX_ES_BASE + 2 * i, 0);
        }
        wvmcs(vcpu, VMX_GDTR_LIMIT, 0xffff);
        wvmcs(vcpu, VMX_IDTR_LIMIT, 0xffff);
        wvmcs(vcpu, VMX_GUEST_CR0, 0x80000031ul);
        wvmcs(vcpu, VMX_GUEST_CR4, 0x20);          /* VMXE is fixed */
        wvmcs(vcpu, VMX_GUEST_CR3, 0x1000);
        wvmcs(vcpu, VMX_GUEST_DR7, 0x400);
        wvmcs(vcpu, VMX_GUEST_RFLAGS, GUEST_RFLAGS);
        wvmcs(vcpu, VMX_GUEST_RSP, 0x5ff0);
    }
    r.r15 = MAGIC;
    CK(seL4_X86_VCPU_WriteRegisters(vcpu, &r));
}

static void map_guest_page(struct guest *gp, seL4_CPtr frame, unsigned long gpa)
{
    CK(seL4_X86_Page_MapEPT(frame, gp->pml4, gpa, seL4_ReadWrite, seL4_X86_EPT_Default_VMAttributes));
}

static void make_guest(struct guest *gp, int core)
{
    unsigned long va[6];

    gp->core = CORE(core);
    gp->pml4 = retype(seL4_X86_EPTPML4Object, 0);
    gp->pdpt = retype(seL4_X86_EPTPDPTObject, 0);
    gp->pd = retype(seL4_X86_EPTPDObject, 0);
    gp->pt = retype(seL4_X86_EPTPTObject, 0);
    CK(seL4_X86_ASIDPool_Assign(seL4_CapInitThreadASIDPool, gp->pml4));
    CK(seL4_X86_EPTPDPT_Map(gp->pdpt, gp->pml4, 0, seL4_X86_EPT_Default_VMAttributes));
    CK(seL4_X86_EPTPD_Map(gp->pd, gp->pml4, 0, seL4_X86_EPT_Default_VMAttributes));
    CK(seL4_X86_EPTPT_Map(gp->pt, gp->pml4, 0, seL4_X86_EPT_Default_VMAttributes));
    /* Code at 0, the guest's page tables at 0x1000 to 0x3000, its counter at
     * 0x4000 and a stack page, each also mapped here through a copy. */
    for (int i = 0; i < 6; i++) {
        seL4_CPtr copy = next_slot++;

        gp->frames[i] = retype(seL4_X86_4K, 0);
        CK(seL4_CNode_Copy(seL4_CapInitThreadCNode, copy, seL4_WordBits, seL4_CapInitThreadCNode,
                           gp->frames[i], seL4_WordBits, seL4_AllRights));
        va[i] = map_root(copy);
        map_guest_page(gp, gp->frames[i], i * 0x1000ul);
    }
    gp->extra = retype(seL4_X86_4K, 0);
    map_guest_page(gp, gp->extra, 0x7000);
    for (unsigned int i = 0; i < sizeof(guest_code); i++)
        ((volatile unsigned char *)va[0])[i] = guest_code[i];
    *(volatile unsigned long *)va[1] = 0x2000 | 3;      /* PML4 */
    *(volatile unsigned long *)va[2] = 0x3000 | 3;      /* PDPT */
    *(volatile unsigned long *)va[3] = 0x83;            /* 2 MiB at 0 */
    gp->counter = (volatile unsigned long *)va[4];

    for (int i = 0; i < 2; i++) {
        gp->vcpu[i] = retype(seL4_X86_VCPUObject, 0);
        init_vcpu(gp->vcpu[i]);
    }
    gp->ntfn = retype(seL4_NotificationObject, 0);
    gp->ipcframe = retype(seL4_X86_4K, 0);
    gp->ipcbuf = map_root(gp->ipcframe);
    gp->fpuframe = retype(seL4_X86_4K, 0);
    gp->tcb = retype(seL4_TCBObject, 0);
    gp->sc = retype(seL4_SchedContextObject, 10);
    CK(seL4_X86_VCPU_SetTCB(gp->vcpu[0], gp->tcb));
    CK(seL4_TCB_SetEPTRoot(gp->tcb, gp->pml4));
}

enum exit_kind { EXIT_NOTIFICATION, EXIT_IO, EXIT_PAGE, EXIT_DB, EXIT_OTHER };

static enum exit_kind exit_kind(seL4_Word fault, seL4_Word reason)
{
    if (!fault) {
        /* Ended by a notification, or by whoever took the VCPU. */
        if (reason != (amd ? SVM_EXIT_INTR : VMX_EXIT_EXTINT))
            die("the reason of a VMEnter that a notification ended", reason);
        return EXIT_NOTIFICATION;
    }
    if (reason == (amd ? SVM_EXIT_IOIO : VMX_EXIT_IO))
        return EXIT_IO;
    if (reason == (amd ? SVM_EXIT_NPF : VMX_EXIT_EPT))
        return EXIT_PAGE;
    if (amd ? reason == SVM_EXIT_DB :
        reason == VMX_EXIT_EXCEPTION && (seL4_GetMR(SEL4_VMENTER_FAULT_EXIT_INTR_INFO) & 0xff) == 1)
        return EXIT_DB;
    return EXIT_OTHER;
}

/* A runner: keep the guest in VMEnter and check what comes back. */
static void runner(struct guest *gp)
{
    seL4_Word badge, rip = 0, prev_rip = 0;
    unsigned long last = 0;

    __sel4_ipc_buffer = (seL4_IPCBuffer *)gp->ipcbuf;
    for (;;) {
        seL4_SetMR(SEL4_VMENTER_CALL_EIP_MR, rip);
        seL4_SetMR(SEL4_VMENTER_CALL_CONTROL_PPC_MR, 0);
        seL4_SetMR(SEL4_VMENTER_CALL_INTERRUPT_INFO_MR, 0);
        seL4_Word fault = seL4_VMEnter(&badge);
        seL4_Word reason = seL4_GetMR(SEL4_VMENTER_FAULT_REASON_MR);
        seL4_Word r15 = seL4_GetMR(SEL4_VMENTER_FAULT_R15);
        unsigned long now = *gp->counter;
        enum exit_kind kind;

        rip = seL4_GetMR(SEL4_VMENTER_CALL_EIP_MR);
        if (tolerate) {
            /* The teardown takes the VCPUs and the guest's memory away. */
            last = 0;
            rip = prev_rip = 0;
            continue;
        }
        kind = exit_kind(fault, reason);
        if (now < last)
            die("the guest's counter went back to", now);
        last = now;
        if (rip >= sizeof(guest_code))
            die("the guest's RIP left its code:", rip);
        if (r15 != MAGIC)
            die("the guest's R15 changed to", r15);
#ifdef TFSTEP
        /* Every instruction traps: the guest passes none without a #DB
         * exit returned here. */
        if (kind == EXIT_DB) {
            if (rip != guest_next[prev_rip] && !(prev_rip == 0x1d && rip == 0x1f)) {
                lock_print();
                say_("a trap was lost: the guest went from", prev_rip);
                say_("to", rip);
                fail();
            }
            gp->exits++;
            prev_rip = rip;
            continue;
        }
        if (rip != prev_rip) {
            lock_print();
            say_("the guest moved without a trap from", prev_rip);
            say_("to", rip);
            say_("on an exit for", reason);
            fail();
        }
#endif
        switch (kind) {
        case EXIT_NOTIFICATION:
            gp->notifs++;
            break;
        case EXIT_IO:
            if (rip != 0x1f)
                die("an I/O exit at", rip);
            rip += 2;
            prev_rip = rip;
            gp->exits++;
            break;
        case EXIT_PAGE:
            /* An attacker has a page or the page table out: it comes back. */
            if (seL4_GetMR(SEL4_VMENTER_FAULT_GUEST_PHYSICAL_MR) >= 0x8000)
                die("a guest page fault at", seL4_GetMR(SEL4_VMENTER_FAULT_GUEST_PHYSICAL_MR));
            gp->npfs++;
            seL4_Yield();
            break;
        default:
            lock_print();
            say_("an unexpected exit for", reason);
            say_("with the qualification", seL4_GetMR(SEL4_VMENTER_FAULT_QUALIFICATION_MR));
            say_("at", rip);
            fail();
        }
    }
}

static void start_thread(seL4_CPtr tcb, seL4_CPtr sc, seL4_CPtr ipcframe, unsigned long ipcbuf,
                         int core, void *fn, unsigned long arg, int idx, seL4_CPtr fault_ep)
{
    seL4_UserContext regs = { 0 };
    unsigned long tp = (unsigned long)(tls[idx] + sizeof(tls[idx]) - 64);

    *(unsigned long *)tp = tp;
    CK(seL4_SchedControl_ConfigureFlags(bi->schedcontrol.start + core, sc, 5000, 5000, 0, 0, 0));
    CK(seL4_TCB_Configure(tcb, seL4_CapInitThreadCNode, 0, seL4_CapInitThreadVSpace, 0, ipcbuf, ipcframe));
    /* An MCP above KernelDebugSyscallMinMCP, to print. */
    CK(seL4_TCB_SetSchedParams(tcb, seL4_CapInitThreadTCB, 255, 100, sc, fault_ep));
    regs.rip = (unsigned long)fn;
    regs.rsp = (unsigned long)(stacks[idx] + sizeof(stacks[idx]) - 8);
    regs.rdi = arg;
    regs.rflags = 0x202;
    regs.fs_base = tp;
    CK(seL4_TCB_WriteRegisters(tcb, 1, 0, sizeof(regs) / sizeof(seL4_Word), &regs));
}

static unsigned long rnd(unsigned long *s)
{
    *s ^= *s << 13;
    *s ^= *s >> 7;
    *s ^= *s << 17;
    return *s;
}

/* One operation on one of the guests.  The root thread (who 0) owns the ones
 * that are a sequence, or that use an object two threads cannot share. */
static void attack(unsigned long *seed, int who, unsigned long mask)
{
    struct guest *gp = &g[rnd(seed) & 1];
    unsigned long op = rnd(seed) % 26;
    seL4_CPtr vcpu = gp->vcpu[rnd(seed) & 1];

    if (!(mask & (1ul << op)) || (who && op >= 10))
        return;
    switch (op) {
    case 0:
    case 1:
        seL4_Signal(gp->ntfn);
        break;
    case 2:
        /* A read takes the VCPU out of guest mode, as every invocation. */
        if (amd)
            (void)seL4_X86_VCPU_ReadVMCB(vcpu, VMCB_ES, 64);
        else
            (void)seL4_X86_VCPU_ReadVMCS(vcpu, VMX_GUEST_RIP);
        break;
    case 3:
        /* The guest never reads the TSC. */
        if (amd)
            wvmcb(vcpu, VMCB_TSC_OFFSET, rnd(seed));
        else
            wvmcs(vcpu, VMX_TSC_OFFSET, rnd(seed));
        break;
    case 4:
        CK(seL4_X86_VCPU_FlushTLB(vcpu));
        break;
    case 5:
        (void)seL4_X86_VCPU_ReadMSR(vcpu, MSR_KERNEL_GS_BASE);
        break;
    case 6: {
        seL4_VCPUContext r = { 0 };

        /* RAX and RBX are the guest's scratch. */
        r.eax = rnd(seed);
        r.r15 = MAGIC;
        CK(seL4_X86_VCPU_WriteRegisters(vcpu, &r));
        break;
    }
    case 7:
        /* Rebinding ends a VMEnter. */
        CK(seL4_X86_VCPU_SetTCB(gp->vcpu[gp->cur], gp->tcb));
        break;
    case 8:
        CK(seL4_TCB_SetEPTRoot(gp->tcb, gp->pml4));
        break;
    case 9:
        (void)seL4_SchedContext_Consumed(gp->sc);
        break;
    case 10:
        /* An unmap invalidates the EPT on every core that ran a VM on it. */
        CK(seL4_X86_Page_Unmap(gp->extra));
        map_guest_page(gp, gp->extra, 0x7000);
        break;
    case 11:
        /* The whole page table: every guest page faults meanwhile. */
        CK(seL4_X86_EPTPT_Unmap(gp->pt));
        CK(seL4_X86_EPTPT_Map(gp->pt, gp->pml4, 0, seL4_X86_EPT_Default_VMAttributes));
        for (int i = 0; i < 6; i++) {
            CK(seL4_X86_Page_Unmap(gp->frames[i]));
            map_guest_page(gp, gp->frames[i], i * 0x1000ul);
        }
        CK(seL4_X86_Page_Unmap(gp->extra));
        map_guest_page(gp, gp->extra, 0x7000);
        break;
    case 12:
        /* The VMEnter starts again, with the RIP the runner gave it. */
        CK(seL4_TCB_Suspend(gp->tcb));
        CK(seL4_TCB_Resume(gp->tcb));
        break;
    case 13:
        CK(seL4_TCB_SetPriority(gp->tcb, seL4_CapInitThreadTCB, PRIO(90 + rnd(seed) % 10)));
        break;
    case 14:
        CK(seL4_TCB_SetMCPriority(gp->tcb, seL4_CapInitThreadTCB, 250 + rnd(seed) % 5));
        CK(seL4_TCB_SetSchedParams(gp->tcb, seL4_CapInitThreadTCB, 255, PRIO(90 + rnd(seed) % 10),
                                   gp->sc, seL4_CapNull));
        break;
    case 15:
        /* Another budget, and maybe the other runner's core. */
        gp->core = CORE(1 + (rnd(seed) & 1));
        CK(seL4_SchedControl_ConfigureFlags(bi->schedcontrol.start + gp->core, gp->sc,
                                            1000 + rnd(seed) % 4000, 5000, 0, 0, 0));
        break;
    case 16:
        CK(seL4_SchedContext_Unbind(gp->sc));
        CK(seL4_SchedContext_Bind(gp->sc, gp->tcb));
        break;
    case 17:
        CK(seL4_TCB_UnbindNotification(gp->tcb));
        CK(seL4_TCB_BindNotification(gp->tcb, gp->ntfn));
        break;
    case 18:
        CK(seL4_TCB_SetFlags(gp->tcb, 0, seL4_TCBFlag_fpuDisabled).error);
        CK(seL4_TCB_SetFlags(gp->tcb, seL4_TCBFlag_fpuDisabled, 0).error);
        break;
    case 19:
        CK(seL4_TCB_ReadFPU(gp->tcb, gp->fpuframe, 0));
        CK(seL4_TCB_WriteFPU(gp->tcb, gp->fpuframe, 0));
        break;
    case 20: {
        seL4_UserContext regs;

        CK(seL4_TCB_ReadRegisters(gp->tcb, 0, 0, sizeof(regs) / sizeof(seL4_Word), &regs));
        break;
    }
    case 21:
        CK(seL4_TCB_SetIPCBuffer(gp->tcb, gp->ipcbuf, gp->ipcframe));
        break;
    case 22: {
        unsigned int lo, hi;

        /* A deadline timer signals the bound notification (patch 0003). */
        __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
        CK(seL4_TCB_SetTimer(gp->tcb, ((unsigned long)hi << 32 | lo) + rnd(seed) % 2000000, 1));
        break;
    }
    case 23:
        /* The thread's other VCPU: its VMEnter ends, and goes on with it. */
        gp->cur ^= 1;
        CK(seL4_X86_VCPU_SetTCB(gp->vcpu[gp->cur], gp->tcb));
        break;
    default:
        seL4_Yield();
        break;
    }
}

static unsigned long attacker_ipcbuf;
static volatile int attack_stop, attack_stopped;

static void attacker(unsigned long seed)
{
    __sel4_ipc_buffer = (seL4_IPCBuffer *)attacker_ipcbuf;
    while (!attack_stop)
        attack(&seed, 1, MASK);
    attack_stopped = 1;
    for (;;)
        seL4_Yield();
}

/*
 * SYSENTER from user level.  seL4 is entered with SYSCALL and leaves
 * IA32_SYSENTER_CS 0, so this is a #GP on an Intel CPU (and a #UD in long
 * mode on an AMD one).  Every VM exit loads the SYSENTER MSRs from the VMCS
 * host state, where seL4 once had the entry point of a kernel built for
 * SYSENTER: a thread on a core that had run a VM then entered the kernel
 * here, as for the system call in RAX, and came back at RDX.
 */
extern char sysenter_insn[];
static volatile int sysenter_returned;

static void sysenter_thread(unsigned long unused)
{
    (void)unused;
    __asm__ volatile("lea 1f(%%rip), %%rdx\n"
                     "mov %%rsp, %%rcx\n"
                     ".global sysenter_insn\n"
                     "sysenter_insn:\n"
                     "sysenter\n"
                     "1:\n"
                     :: "a"((long)seL4_SysYield) : "rcx", "rdx", "r11", "memory", "cc");
    sysenter_returned = 1;
    for (;;)
        __asm__ volatile("ud2");
}

/* The SYSENTER of a thread on the core must be the fault it is on a core
 * that has run no VM. */
static void check_sysenter(int core)
{
    seL4_CPtr ep = retype(seL4_EndpointObject, 0);
    seL4_CPtr tcb = retype(seL4_TCBObject, 0);
    seL4_CPtr sc = retype(seL4_SchedContextObject, 10);
    seL4_CPtr frame = retype(seL4_X86_4K, 0);
    seL4_MessageInfo_t tag;
    seL4_Word number, ip;

    start_thread(tcb, sc, frame, map_root(frame), core, sysenter_thread, 0, 4, ep);
    tag = seL4_Wait(ep, 0);
    number = seL4_GetMR(seL4_UserException_Number);
    ip = seL4_GetMR(seL4_UserException_FaultIP);
    if (sysenter_returned || seL4_MessageInfo_get_label(tag) != seL4_Fault_UserException ||
        ip != (seL4_Word)sysenter_insn || (number != 13 && number != 6)) {
        lock_print();
        say_("SYSENTER entered the kernel on core", core);
        say_("  returned", sysenter_returned);
        say_("  fault", seL4_MessageInfo_get_label(tag));
        say_("  exception", number);
        say_("  at", ip);
        fail();
    }
    CK(seL4_TCB_Suspend(tcb));
}

static void delete(seL4_CPtr cap)
{
    unsigned long seed = cap;

    CK(seL4_CNode_Delete(seL4_CapInitThreadCNode, cap, seL4_WordBits));
    /* The second attacker goes on with every operation; this thread with
     * those that need no more than the capability. */
    for (int i = 0; i < 100; i++)
        attack(&seed, 0, 0x3ff);
}

void vcpustress_main(seL4_BootInfo *bootinfo)
{
    unsigned long tp = (unsigned long)(tls[3] + sizeof(tls[3]) - 64);
    unsigned long seed = 0x9e3779b97f4a7c15ul;
    unsigned int a = 0, b, c, d;
    seL4_CPtr atcb, asc, aframe;

    bi = bootinfo;
    *(unsigned long *)tp = tp;
    seL4_TCB_SetTLSBase(seL4_CapInitThreadTCB, tp);
    __sel4_ipc_buffer = bi->ipcBuffer;
    __asm__ volatile("cpuid" : "+a"(a), "=b"(b), "=c"(c), "=d"(d));
    amd = b == 0x68747541;      /* "Auth" */
    next_slot = bi->empty.start;
    for (seL4_CPtr i = bi->untyped.start; i < bi->untyped.end; i++) {
        seL4_UntypedDesc *desc = &bi->untypedList[i - bi->untyped.start];

        if (!desc->isDevice && desc->sizeBits >= 24) {
            ut = i;
            break;
        }
    }
    if (!ut)
        die("no untyped of 16 MiB", 0);
    if (bi->numNodes < 4)
        die("4 cores needed, not", bi->numNodes);
    if (seL4_Untyped_Retype(ut, seL4_X86_VCPUObject, 0, seL4_CapInitThreadCNode, 0, 0, next_slot, 1)) {
        puts_("vcpustress: no VCPU objects (no VT-x or AMD-V): skipped\n");
        for (;;)
            seL4_Yield();
    }
    next_slot++;

    /* Page tables for the mappings here. */
    CK(seL4_X86_PDPT_Map(retype(seL4_X86_PDPTObject, 0), seL4_CapInitThreadVSpace, va_next,
                         seL4_X86_Default_VMAttributes));
    CK(seL4_X86_PageDirectory_Map(retype(seL4_X86_PageDirectoryObject, 0), seL4_CapInitThreadVSpace,
                                  va_next, seL4_X86_Default_VMAttributes));
    CK(seL4_X86_PageTable_Map(retype(seL4_X86_PageTableObject, 0), seL4_CapInitThreadVSpace, va_next,
                              seL4_X86_Default_VMAttributes));
    for (int i = 0; i < 2; i++)
        make_guest(&g[i], i + 1);
    for (int i = 0; i < 2; i++) {
        start_thread(g[i].tcb, g[i].sc, g[i].ipcframe, g[i].ipcbuf, g[i].core, runner,
                     (unsigned long)&g[i], i, seL4_CapNull);
        CK(seL4_TCB_BindNotification(g[i].tcb, g[i].ntfn));
    }
    atcb = retype(seL4_TCBObject, 0);
    asc = retype(seL4_SchedContextObject, 10);
    aframe = retype(seL4_X86_4K, 0);
    attacker_ipcbuf = map_root(aframe);
    start_thread(atcb, asc, aframe, attacker_ipcbuf, CORE(3), attacker, 0x1234567887654321ul, 2,
                 seL4_CapNull);
#ifdef ONECORE
    CK(seL4_TCB_SetPriority(seL4_CapInitThreadTCB, seL4_CapInitThreadTCB, 100));
#endif
    say("started; AMD-V", amd);

    for (int round = 0; round < ROUNDS; round++) {
        unsigned long before[2] = { *g[0].counter, *g[1].counter };

        for (int i = 0; i < 500; i++)
            attack(&seed, 0, MASK);
        /* Both guests must still make progress. */
        for (int spin = 0; spin < 4000000 && (*g[0].counter == before[0] || *g[1].counter == before[1]); spin++) {
#ifdef ONECORE
            seL4_Yield();
#else
            __asm__ volatile("pause");
#endif
        }
        if (*g[0].counter == before[0] || *g[1].counter == before[1]) {
            lock_print();
            say_("a guest made no progress in round", round);
            say_("guest 0 counted", *g[0].counter);
            say_("guest 1 counted", *g[1].counter);
            fail();
        }
    }
    lock_print();
    for (int i = 0; i < 2; i++) {
        say_("guest: counted", *g[i].counter);
        say_("  exits returned", g[i].exits);
        say_("  notifications", g[i].notifs);
        say_("  page faults", g[i].npfs);
    }
    __sync_lock_release(&print_lock);

    /* Teardown under fire: the guests still run, and the second attacker
     * still invokes what is deleted (and fails, as it should). */
    tolerate = 1;
    CK(seL4_X86_VCPU_SetTCB(g[0].vcpu[g[0].cur], g[1].tcb));    /* both VMEnters end */
    delete(g[1].vcpu[0]);
    delete(g[0].pml4);
    delete(g[1].pml4);
    delete(g[0].vcpu[0]);
    delete(g[0].vcpu[1]);
    delete(g[1].sc);
    delete(g[1].vcpu[1]);
    delete(g[1].tcb);
    delete(g[0].tcb);
    attack_stop = 1;
    while (!attack_stopped)
        seL4_Yield();
    /* The guests ran on cores 1 and 2 (ONECORE: on core 0). */
    tolerate = 0;
    check_sysenter(CORE(1));
    check_sysenter(CORE(2));
    puts_("vcpustress: done\n");
    for (;;)
        seL4_Yield();
}

__asm__(".global _start\n"
        "_start:\n"
        "    lea vcpustress_stack+16384(%rip), %rsp\n"
        "    call vcpustress_main\n"
        "1:  jmp 1b\n");

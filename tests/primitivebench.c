// SPDX-License-Identifier: GPL-2.0-only
/* Direct microkernel timings below Linux, using the release libsel4 ABI.
 * All timings are invariant-TSC ticks; serial output is outside the window.
 * Build against each backend separately, with -mgeneral-regs-only. */
#include <sel4/sel4.h>

__thread seL4_IPCBuffer *__sel4_ipc_buffer;
#ifdef CONFIG_KERNEL_INVOCATION_REPORT_ERROR_IPC
__thread char __sel4_print_error;
#endif
char primitivebench_stack[32768] __attribute__((aligned(16)));
static char client_stack[32768] __attribute__((aligned(16)));
static char tls[2][4096] __attribute__((aligned(64)));
static char client_ipc[4096] __attribute__((aligned(4096)));
extern char __executable_start[];
static seL4_BootInfo *bi;
static seL4_CPtr ut, next_slot, ep, reply, client_tcb, client_sc, client_space;
static seL4_CPtr uart;
static volatile unsigned long client_start, client_end, client_errors;
static volatile unsigned long client_enter, server_exit, reply_ticks;
static unsigned long iterations = 20000, warmup = 1000;
static unsigned message_words;

void *memset(void *dst, int c, __SIZE_TYPE__ n)
{
    volatile unsigned char *p = dst;
    while (n--) *p++ = c;
    return dst;
}

void *memcpy(void *dst, const void *src, __SIZE_TYPE__ n)
{
    unsigned char *d = dst;
    const unsigned char *s = src;
    while (n--) *d++ = *s++;
    return dst;
}

static void putchar_(char c)
{
    /* FL4 release builds omit DebugPutChar. Use the root's I/O authority
     * on both backends; none of this is in a measured interval. */
    while (!(seL4_X86_IOPort_In8(uart, 0x3fd).result & 0x20)) {}
    seL4_X86_IOPort_Out8(uart, 0x3f8, c);
}

static void puts_(const char *s)
{
    while (*s) putchar_(*s++);
}

static void decimal(unsigned long n)
{
    char buf[24];
    unsigned i = 0;
    do { buf[i++] = '0' + n % 10; n /= 10; } while (n);
    while (i) putchar_(buf[--i]);
}

static void fail(const char *s, unsigned long err)
{
    puts_("PRIMITIVE: FAIL "); puts_(s); puts_(" error="); decimal(err); puts_("\n");
    for (;;) seL4_Yield();
}

#define CK(expr) do { unsigned long err_ = (expr); if (err_) fail(#expr, err_); } while (0)

static unsigned long ticks(void)
{
    unsigned lo, hi;
    __asm__ volatile("lfence; rdtsc; lfence" : "=a"(lo), "=d"(hi) :: "memory");
    return (unsigned long)hi << 32 | lo;
}

static void report(const char *name, unsigned trial, unsigned long elapsed, unsigned long count)
{
    puts_("PRIMITIVE: metric="); puts_(name); puts_(" trial="); decimal(trial);
    puts_(" ticks="); decimal(elapsed); puts_(" operations="); decimal(count); puts_("\n");
}

static seL4_CPtr retype(seL4_Word type, seL4_Word bits)
{
    seL4_CPtr cap = next_slot++;
    CK(seL4_Untyped_Retype(ut, type, bits, seL4_CapInitThreadCNode, 0, 0, cap, 1));
    return cap;
}

static void delete_(seL4_CPtr cap)
{
    CK(seL4_CNode_Delete(seL4_CapInitThreadCNode, cap, seL4_WordBits));
}

static void page_tables(seL4_CPtr space, unsigned long va)
{
    CK(seL4_X86_PDPT_Map(retype(seL4_X86_PDPTObject, 0), space, va, seL4_X86_Default_VMAttributes));
    CK(seL4_X86_PageDirectory_Map(retype(seL4_X86_PageDirectoryObject, 0), space, va,
                                 seL4_X86_Default_VMAttributes));
    CK(seL4_X86_PageTable_Map(retype(seL4_X86_PageTableObject, 0), space, va,
                             seL4_X86_Default_VMAttributes));
}

static seL4_CPtr copy_space(void)
{
    seL4_CPtr space = retype(seL4_X64_PML4Object, 0);
    CK(seL4_X86_ASIDPool_Assign(seL4_CapInitThreadASIDPool, space));
    unsigned long base = (unsigned long)__executable_start;
    page_tables(space, base);
    for (seL4_CPtr frame = bi->userImageFrames.start; frame < bi->userImageFrames.end; frame++) {
        unsigned long va = base + (frame - bi->userImageFrames.start) * 4096;
        if ((va >> 21) != (base >> 21)) fail("image spans multiple page tables", va);
        seL4_CPtr copy = next_slot++;
        CK(seL4_CNode_Copy(seL4_CapInitThreadCNode, copy, 64, seL4_CapInitThreadCNode,
                           frame, 64, seL4_AllRights));
        CK(seL4_X86_Page_Map(copy, space, va, seL4_AllRights, seL4_X86_Default_VMAttributes));
    }
    return space;
}

#define MEASURE(name, expression) do { \
    for (unsigned trial = 0; trial <= 5; trial++) { \
        unsigned long n = trial ? iterations : warmup; \
        unsigned long begin = ticks(); \
        for (unsigned long k = 0; k < n; k++) { expression; } \
        report(name, trial, ticks() - begin, n); \
    } \
} while (0)

/* Pair operations that need cleanup, but time their two sides separately.
 * The empty bracket metric records the timestamp overhead; raw times keep it. */
#define PAIR(name_a, op_a, name_b, op_b, between) do { \
    for (unsigned trial = 0; trial <= 5; trial++) { \
        unsigned long n = trial ? iterations : warmup, a = 0, b = 0; \
        for (unsigned long k = 0; k < n; k++) { \
            unsigned long t = ticks(); op_a; unsigned long u = ticks(); \
            a += u - t; between; t = ticks(); op_b; u = ticks(); b += u - t; \
        } \
        report(name_a, trial, a, n); report(name_b, trial, b, n); \
    } \
} while (0)

static void invocation_bench(void)
{
    seL4_CPtr ntfn = retype(seL4_NotificationObject, 0);
    seL4_CPtr target = retype(seL4_TCBObject, 0);
    seL4_CPtr sc = retype(seL4_SchedContextObject, 10);
    seL4_CPtr frame = retype(seL4_X86_4K, 0), copy = next_slot++;
    seL4_CPtr scratch = retype(seL4_X86_4K, 0);
    seL4_CPtr small_ut = retype(seL4_UntypedObject, 16), object = next_slot++;
    seL4_Word badge;
    seL4_UserContext regs = {0};
    unsigned long va = 0x8000000000ul;
    page_tables(seL4_CapInitThreadVSpace, va);
    CK(seL4_SchedControl_ConfigureFlags(bi->schedcontrol.start, sc, 5000, 5000, 0, 0, 0));
    CK(seL4_TCB_Configure(target, seL4_CapInitThreadCNode, 0, seL4_CapInitThreadVSpace,
                          0, 0, seL4_CapNull));
    CK(seL4_TCB_SetSchedParams(target, seL4_CapInitThreadTCB, 100, 100, sc, seL4_CapNull));
    CK(seL4_TCB_BindNotification(seL4_CapInitThreadTCB, ntfn));
    MEASURE("Poll_empty", (void)seL4_Poll(ntfn, &badge));
    MEASURE("Signal_pending", seL4_Signal(ntfn));
    seL4_Poll(ntfn, &badge);
    MEASURE("TCB_SetTimer_cancel", CK(seL4_TCB_SetTimer(seL4_CapInitThreadTCB, 0, 1)));
    unsigned long deadline = ticks() + 1000000000000ul;
    MEASURE("TCB_SetTimer_future", CK(seL4_TCB_SetTimer(seL4_CapInitThreadTCB, deadline + k, 1)));
    CK(seL4_TCB_SetTimer(seL4_CapInitThreadTCB, 0, 1));
    MEASURE("TCB_ReadRegisters_20", CK(seL4_TCB_ReadRegisters(target, 0, 0, 20, &regs)));
    MEASURE("TCB_WriteRegisters_20", CK(seL4_TCB_WriteRegisters(target, 0, 0, 20, &regs)));
    MEASURE("TCB_SetSchedParams_bound", CK(seL4_TCB_SetSchedParams(target,
        seL4_CapInitThreadTCB, 100, 100, sc, seL4_CapNull)));
    PAIR("SchedContext_UnbindObject", CK(seL4_SchedContext_UnbindObject(sc, target)),
         "TCB_SetSchedParams_bind", CK(seL4_TCB_SetSchedParams(target, seL4_CapInitThreadTCB,
             100, 100, sc, seL4_CapNull)), (void)0);
    MEASURE("TCB_ReadFPU_inactive", CK(seL4_TCB_ReadFPU(target, scratch, 0)));
    MEASURE("TCB_WriteFPU_inactive", CK(seL4_TCB_WriteFPU(target, scratch, 0)));
    PAIR("CNode_Copy", CK(seL4_CNode_Copy(seL4_CapInitThreadCNode, copy, 64,
             seL4_CapInitThreadCNode, ntfn, 64, seL4_AllRights)),
         "CNode_Delete_copy", delete_(copy), (void)0);
    PAIR("Page_Map_new_active", CK(seL4_X86_Page_Map(frame, seL4_CapInitThreadVSpace, va,
             seL4_ReadWrite, seL4_X86_Default_VMAttributes)),
         "Page_Unmap_touched_active", CK(seL4_X86_Page_Unmap(frame)),
         *(volatile unsigned long *)va = k);
    CK(seL4_X86_Page_Map(frame, seL4_CapInitThreadVSpace, va,
                        seL4_ReadWrite, seL4_X86_Default_VMAttributes));
    MEASURE("Page_Map_remap_active", CK(seL4_X86_Page_Map(frame, seL4_CapInitThreadVSpace,
        va, seL4_ReadWrite, seL4_X86_Default_VMAttributes)));
    CK(seL4_X86_Page_Unmap(frame));
    PAIR("Untyped_Retype_frame_reset64k", CK(seL4_Untyped_Retype(small_ut, seL4_X86_4K, 0,
             seL4_CapInitThreadCNode, 0, 0, object, 1)),
         "CNode_Delete_frame", delete_(object), (void)0);
    PAIR("Untyped_Retype_tcb_reset64k", CK(seL4_Untyped_Retype(small_ut, seL4_TCBObject, 0,
             seL4_CapInitThreadCNode, 0, 0, object, 1)),
         "CNode_Delete_tcb", delete_(object), (void)0);
    PAIR("timestamp_bracket_a", (void)0, "timestamp_bracket_b", (void)0, (void)0);
    CK(seL4_TCB_UnbindNotification(seL4_CapInitThreadTCB));
}

static void fresh_retype_bench(const char *name, seL4_Word type)
{
    seL4_CPtr arena = retype(seL4_UntypedObject, 21);
    seL4_CPtr anchor = next_slot++, first = next_slot;
    next_slot += 64;
    for (unsigned trial = 0; trial <= 5; trial++) {
        unsigned long elapsed = 0, batches = trial ? 100 : 10;
        for (unsigned long b = 0; b < batches; b++) {
            CK(seL4_CNode_Revoke(seL4_CapInitThreadCNode, arena, 64));
            /* Reset/zero the arena before timing, and retain a child so
             * each measured allocation only advances its free index. */
            CK(seL4_Untyped_Retype(arena, seL4_EndpointObject, 0,
                                   seL4_CapInitThreadCNode, 0, 0, anchor, 1));
            unsigned long start = ticks();
            for (unsigned i = 0; i < 64; i++)
                CK(seL4_Untyped_Retype(arena, type, 0,
                                       seL4_CapInitThreadCNode, 0, 0, first + i, 1));
            elapsed += ticks() - start;
        }
        report(name, trial, elapsed, batches * 64);
    }
    CK(seL4_CNode_Revoke(seL4_CapInitThreadCNode, arena, 64));
}

__attribute__((noreturn)) static void client(unsigned long mode)
{
    __sel4_ipc_buffer = (seL4_IPCBuffer *)client_ipc;
    if (mode & 2)
        __asm__ volatile("pxor %%xmm0, %%xmm0" ::: "memory");
    unsigned long rounds = iterations + warmup;
    for (unsigned long i = 0; i < rounds; i++) {
        if (i == warmup) client_start = ticks();
        if (mode & 1) {
            unsigned long result = 42;
            if (mode & 4) client_enter = ticks();
            __asm__ volatile("syscall" : "+a"(result) :: "rcx", "r11", "memory");
            if (mode & 4) {
                unsigned long returned = ticks();
                if (i >= warmup) reply_ticks += returned - server_exit;
            }
            if (result != 42) client_errors++;
        } else {
            seL4_MessageInfo_t tag = seL4_Call(ep, seL4_MessageInfo_new(0, 0, 0, message_words));
            if (seL4_MessageInfo_get_length(tag) != message_words) client_errors++;
        }
    }
    client_end = ticks();
    if (mode & 1) {
        unsigned long result = 0xdeadbeef;
        __asm__ volatile("syscall" : "+a"(result) :: "rcx", "r11", "memory");
    } else {
        seL4_Call(ep, seL4_MessageInfo_new(1, 0, 0, 0));
    }
    for (;;) __asm__ volatile("pause");
}

static void ipc_bench(const char *name, int separate, unsigned mode, unsigned words)
{
    message_words = words;
    seL4_CPtr ipcframe = bi->userImageFrames.start +
        ((unsigned long)client_ipc - (unsigned long)__executable_start) / 4096;
    for (unsigned trial = 0; trial < 5; trial++) {
        client_start = client_end = client_errors = 0;
        reply_ticks = 0;
        CK(seL4_TCB_Configure(client_tcb, seL4_CapInitThreadCNode, 0,
            separate ? client_space : seL4_CapInitThreadVSpace, 0,
            (unsigned long)client_ipc, ipcframe));
        CK(seL4_TCB_SetSchedParams(client_tcb, seL4_CapInitThreadTCB, 100, 100, client_sc, ep));
        CK(seL4_TCB_SetFlags(client_tcb, 3, (mode & 1 ? 2 : 0) | (mode & 2 ? 0 : 1)).error);
        seL4_UserContext regs = {0};
        regs.rip = (unsigned long)client;
        regs.rsp = (unsigned long)(client_stack + sizeof(client_stack) - 8);
        regs.rdi = mode;
        regs.rflags = 0x202;
        regs.fs_base = (unsigned long)(tls[1] + sizeof(tls[1]) - 64);
        *(unsigned long *)regs.fs_base = regs.fs_base;
        CK(seL4_TCB_WriteRegisters(client_tcb, 1, 0, 20, &regs));
        seL4_Word badge;
        seL4_MessageInfo_t tag = seL4_Recv(ep, &badge, reply);
        unsigned long arrival = mode & 4 ? ticks() : 0;
        unsigned long received = 0, fault_ticks = 0;
        for (;;) {
            if (mode & 1) {
                if (seL4_MessageInfo_get_label(tag) != seL4_Fault_UnknownSyscall)
                    fail("expected syscall fault", seL4_MessageInfo_get_label(tag));
                if (seL4_GetMR(seL4_UnknownSyscall_RAX) == 0xdeadbeef) break;
                if ((mode & 4) && received >= warmup)
                    fault_ticks += arrival - client_enter;
                seL4_SetMR(seL4_UnknownSyscall_FaultIP,
                           seL4_GetMR(seL4_UnknownSyscall_FaultIP) + 2);
            } else if (seL4_MessageInfo_get_label(tag) == 1) {
                break;
            }
            received++;
            if (mode & 4) server_exit = ticks();
            tag = seL4_ReplyRecv(ep, seL4_MessageInfo_new(0, 0, 0,
                mode & 1 ? seL4_UnknownSyscall_Syscall : words), &badge, reply);
            if (mode & 4) arrival = ticks();
        }
        CK(seL4_TCB_Suspend(client_tcb));
        if (received != iterations + warmup || client_errors || client_end <= client_start)
            fail("IPC count/data/timing", received);
        report(name, trial + 1, client_end - client_start, iterations);
        if (mode & 4) {
            report("SyscallFault_delivery_other_as_userfpu", trial + 1, fault_ticks, iterations);
            report("ReplyRecv_resume_other_as_userfpu", trial + 1, reply_ticks, iterations);
        }
        /* A blocked fault/call still owns its reply object. Deleting it
         * cancels that reply before the next iteration resumes the TCB. */
        delete_(reply);
        reply = retype(seL4_ReplyObject, 0);
    }
}

void primitivebench_main(seL4_BootInfo *bootinfo)
{
    bi = bootinfo;
    unsigned long tp = (unsigned long)(tls[0] + sizeof(tls[0]) - 64);
    *(unsigned long *)tp = tp;
    seL4_TCB_SetTLSBase(seL4_CapInitThreadTCB, tp);
    __sel4_ipc_buffer = bi->ipcBuffer;
    next_slot = bi->empty.start;
    uart = next_slot++;
    seL4_X86_IOPortControl_Issue(seL4_CapIOPortControl, 0x3f8, 0x3ff,
                                seL4_CapInitThreadCNode, uart, 64);
    CK(seL4_TCB_SetFlags(seL4_CapInitThreadTCB, 0, 1).error);
    unsigned best = 0;
    for (seL4_CPtr i = bi->untyped.start; i < bi->untyped.end; i++) {
        seL4_UntypedDesc *d = &bi->untypedList[i - bi->untyped.start];
        if (!d->isDevice && d->sizeBits > best) { ut = i; best = d->sizeBits; }
    }
    if (best < 22) fail("no large untyped", best);
    puts_("PRIMITIVE: start cores="); decimal(bi->numNodes); puts_("\n");
    invocation_bench();
    fresh_retype_bench("Untyped_Retype_frame_no_reset", seL4_X86_4K);
    fresh_retype_bench("Untyped_Retype_tcb_no_reset", seL4_TCBObject);
    ep = retype(seL4_EndpointObject, 0);
    reply = retype(seL4_ReplyObject, 0);
    client_tcb = retype(seL4_TCBObject, 0);
    client_sc = retype(seL4_SchedContextObject, 10);
    CK(seL4_SchedControl_ConfigureFlags(bi->schedcontrol.start, client_sc, 5000, 5000, 0, 0, 0));
    client_space = copy_space();
    ipc_bench("Call0_ReplyRecv_same_as", 0, 0, 0);
    ipc_bench("Call0_ReplyRecv_other_as", 1, 0, 0);
    ipc_bench("Call19_ReplyRecv_same_as", 0, 0, 19);
    ipc_bench("Call19_ReplyRecv_other_as", 1, 0, 19);
    ipc_bench("Fault_ReplyRecv_same_as_nofpu", 0, 1, 0);
    ipc_bench("Fault_ReplyRecv_other_as_nofpu", 1, 1, 0);
    ipc_bench("Fault_ReplyRecv_same_as_userfpu", 0, 3, 0);
    ipc_bench("Fault_ReplyRecv_other_as_userfpu", 1, 3, 0);
    ipc_bench("Fault_ReplyRecv_other_as_userfpu_split", 1, 7, 0);
    puts_("PRIMITIVE: PASS\n");
    for (;;) seL4_Yield();
}

__asm__(".global _start\n_start:\n"
        "lea primitivebench_stack+32768(%rip), %rsp\n"
        "call primitivebench_main\n1: jmp 1b\n");

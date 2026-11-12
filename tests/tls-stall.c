// SPDX-License-Identifier: GPL-2.0-only
/* Preserve live FS/GS bases when a remote SC query stalls a thread that
 * is entering the kernel. No l4h host or guest binaries are involved. */
#include <sel4/sel4.h>

__thread seL4_IPCBuffer *__sel4_ipc_buffer;
static char tls[3][4096] __attribute__((aligned(64)));
static char worker_stack[8192] __attribute__((aligned(16)));
char tls_stall_stack[16384] __attribute__((aligned(16)));
static volatile seL4_Word progress, bad, expected_fs, expected_gs, found_fs, found_gs;
static seL4_CPtr untyped, next_slot;

static void say(const char *s) { while (*s) seL4_DebugPutChar(*s++); }
static void hex(seL4_Word n) {
    for (unsigned shift = 64; shift; shift -= 4)
        seL4_DebugPutChar("0123456789abcdef"[(n >> (shift - 4)) & 15]);
}
static void fail(const char *s) {
    say("TLSSTALL: FAIL: "); say(s); say("\n");
    for (;;) seL4_Yield();
}
#define CHECK(x) do { if ((x) != seL4_NoError) fail(#x); } while (0)

static seL4_CPtr object(seL4_Word type, seL4_Word bits) {
    seL4_CPtr cap = next_slot++;
    CHECK(seL4_Untyped_Retype(untyped, type, bits, seL4_CapInitThreadCNode, 0, 0, cap, 1));
    return cap;
}

static void worker(void) {
    for (seL4_Word n = 0;; n++) {
        /* These changes intentionally leave the TCB's saved bases stale
         * until entry saves them. Yield needs no IPC-buffer/TLS lookup,
         * so we can report a lost base instead of taking a page fault. */
        seL4_Word fs = (seL4_Word)(tls[(n + 1) & 1] + sizeof(tls[0]) - 64);
        seL4_Word gs = fs + 16;
        __asm__ volatile("wrfsbase %0; wrgsbase %1" :: "r"(fs), "r"(gs) : "memory");
        seL4_Yield();
        seL4_Word actual_fs, actual_gs;
        __asm__ volatile("rdfsbase %0; rdgsbase %1" : "=r"(actual_fs), "=r"(actual_gs) :: "memory");
        if (actual_fs != fs || actual_gs != gs) {
            expected_fs = fs; expected_gs = gs;
            found_fs = actual_fs; found_gs = actual_gs;
            __atomic_store_n(&bad, 1, __ATOMIC_RELEASE);
            for (;;) __asm__ volatile("pause");
        }
        __atomic_add_fetch(&progress, 1, __ATOMIC_RELAXED);
    }
}

void tls_stall_main(seL4_BootInfo *bi) {
    seL4_Word tp = (seL4_Word)(tls[2] + sizeof(tls[2]) - 64);
    *(seL4_Word *)tp = tp;
    CHECK(seL4_TCB_SetTLSBase(seL4_CapInitThreadTCB, tp));
    __sel4_ipc_buffer = bi->ipcBuffer;
    if (bi->numNodes < 2) fail("two cores required");
    next_slot = bi->empty.start;
    for (seL4_CPtr i = bi->untyped.start; i < bi->untyped.end; i++) {
        seL4_UntypedDesc *d = &bi->untypedList[i - bi->untyped.start];
        if (!d->isDevice && d->sizeBits >= 20) { untyped = i; break; }
    }
    if (!untyped) fail("no untyped");
    const seL4_Word ipc_va = 0x8000000000ul;
    CHECK(seL4_X86_PDPT_Map(object(seL4_X86_PDPTObject, 0), seL4_CapInitThreadVSpace, ipc_va, seL4_X86_Default_VMAttributes));
    CHECK(seL4_X86_PageDirectory_Map(object(seL4_X86_PageDirectoryObject, 0), seL4_CapInitThreadVSpace, ipc_va, seL4_X86_Default_VMAttributes));
    CHECK(seL4_X86_PageTable_Map(object(seL4_X86_PageTableObject, 0), seL4_CapInitThreadVSpace, ipc_va, seL4_X86_Default_VMAttributes));
    seL4_CPtr tcb = object(seL4_TCBObject, 0), cnode = object(seL4_CapTableObject, 4);
    seL4_CPtr frame = object(seL4_X86_4K, 0), sc = object(seL4_SchedContextObject, 9);
    CHECK(seL4_X86_Page_Map(frame, seL4_CapInitThreadVSpace, ipc_va, seL4_ReadWrite, seL4_X86_Default_VMAttributes));
    CHECK(seL4_TCB_Configure(tcb, cnode, seL4_CNode_CapData_new(0, seL4_WordBits - 4).words[0],
                            seL4_CapInitThreadVSpace, 0, ipc_va, frame));
    CHECK(seL4_SchedControl_ConfigureFlags(bi->schedcontrol.start + 1, sc, 5000, 5000, 0, 0, 0));
    CHECK(seL4_TCB_SetSchedParams(tcb, seL4_CapInitThreadTCB, 100, 100, sc, seL4_CapNull));
    seL4_UserContext r = { 0 };
    r.rip = (seL4_Word)worker;
    r.rsp = (seL4_Word)(worker_stack + sizeof(worker_stack) - 8);
    r.rflags = 0x202;
    r.fs_base = (seL4_Word)(tls[0] + sizeof(tls[0]) - 64);
    CHECK(seL4_TCB_WriteRegisters(tcb, 1, 0, sizeof(r) / sizeof(seL4_Word), &r));

    for (unsigned i = 0; i < 100000; i++) {
        seL4_SchedContext_Consumed_t result = seL4_SchedContext_Consumed(sc);
        if (result.error) fail("Consumed");
        if (__atomic_load_n(&bad, __ATOMIC_ACQUIRE)) {
            say("TLSSTALL: FS expected="); hex(expected_fs); say(" actual="); hex(found_fs);
            say(" GS expected="); hex(expected_gs); say(" actual="); hex(found_gs); say("\n");
            fail("remote stall lost live FS/GS bases");
        }
        /* Sampling must leave the target time to complete syscalls;
         * continuously stalling it can otherwise suppress all progress. */
        for (unsigned pause = 0; pause < 512; pause++) __asm__ volatile("pause");
    }
    CHECK(seL4_TCB_Suspend(tcb));
    if (__atomic_load_n(&progress, __ATOMIC_RELAXED) < 100) fail("worker made no progress");
    say("TLSSTALL: PASS (100000 remote SC queries preserve user FS/GS)\n");
    for (;;) seL4_Yield();
}

__asm__(".global _start\n_start:\n lea tls_stall_stack+16384(%rip), %rsp\n call tls_stall_main\n1: jmp 1b\n");

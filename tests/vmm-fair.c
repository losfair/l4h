// SPDX-License-Identifier: GPL-2.0-only
/* Exercise the VMM guard against both guest scheduling bands. The VMM
 * has only its own TCB capability, not root's authority. */
#include <sel4/sel4.h>
#include <stddef.h>
#include "vmm-priorities.h"

__thread seL4_IPCBuffer *__sel4_ipc_buffer;
static char tls[5][4096] __attribute__((aligned(64)));
static char stacks[4][8192] __attribute__((aligned(16)));
char vmm_fair_stack[16384] __attribute__((aligned(16)));
static seL4_BootInfo *bi;
static seL4_CPtr ut, next_slot;
static volatile seL4_Word progress[4] __attribute__((aligned(64)));
static volatile seL4_Word phase, denied, escaped;
static seL4_Word ipc_va[4];

static void say(const char *s) { while (*s) seL4_DebugPutChar(*s++); }
static void fail(const char *s) {
    say("VMMFAIR: FAIL: "); say(s); say("\n");
    for (;;) seL4_Yield();
}
#define CHECK(x) do { if ((x) != seL4_NoError) fail(#x); } while (0)

static seL4_CPtr object(seL4_Word type, seL4_Word bits) {
    seL4_CPtr cap = next_slot++;
    CHECK(seL4_Untyped_Retype(ut, type, bits, seL4_CapInitThreadCNode, 0, 0, cap, 1));
    return cap;
}

static void worker(seL4_Word id) {
    __sel4_ipc_buffer = (seL4_IPCBuffer *)ipc_va[id];
    seL4_Word tested = 0;
    for (;;) {
        __atomic_add_fetch(&progress[id], 1, __ATOMIC_RELAXED);
        seL4_Word current = __atomic_load_n(&phase, __ATOMIC_ACQUIRE);
        if (!id && current != tested) {
            tested = current;
            /* Slot 1 is this thread's TCB, including when used as authority. */
            int a = seL4_TCB_SetPriority(1, 1, VMM_PRIO);
            int b = seL4_TCB_SetMCPriority(1, 1, VMM_PRIO);
            if (a != seL4_RangeError || b != seL4_RangeError)
                __atomic_store_n(&escaped, 1, __ATOMIC_RELEASE);
            else
                __atomic_add_fetch(&denied, 1, __ATOMIC_RELAXED);
        }
    }
}

static seL4_CPtr start(unsigned id, seL4_CPtr sc, seL4_Word priority) {
    enum { BITS = 4 };
    seL4_CPtr tcb = object(seL4_TCBObject, 0);
    seL4_CPtr cnode = object(seL4_CapTableObject, BITS);
    seL4_CPtr frame = object(seL4_X86_4K, 0);
    seL4_UserContext r = { 0 };
    seL4_Word tp = (seL4_Word)(tls[id] + sizeof(tls[id]) - 64);
    ipc_va[id] = 0x8000000000ul + id * 4096;
    CHECK(seL4_X86_Page_Map(frame, seL4_CapInitThreadVSpace, ipc_va[id], seL4_ReadWrite,
                            seL4_X86_Default_VMAttributes));
    CHECK(seL4_CNode_Copy(cnode, 1, BITS, seL4_CapInitThreadCNode, tcb, seL4_WordBits, seL4_AllRights));
    CHECK(seL4_TCB_Configure(tcb, cnode, seL4_CNode_CapData_new(0, seL4_WordBits - BITS).words[0],
                             seL4_CapInitThreadVSpace, 0, ipc_va[id], frame));
    CHECK(seL4_SchedControl_ConfigureFlags(bi->schedcontrol.start + 1, sc, 5000, 5000, 0, 0, 0));
    CHECK(seL4_TCB_SetSchedParams(tcb, seL4_CapInitThreadTCB, priority, priority, sc, seL4_CapNull));
    *(seL4_Word *)tp = tp;
    r.rip = (seL4_Word)worker;
    r.rsp = (seL4_Word)(stacks[id] + sizeof(stacks[id]) - 8);
    r.rdi = id;
    r.rflags = 0x202;
    r.fs_base = tp;
    CHECK(seL4_TCB_WriteRegisters(tcb, 1, 0, sizeof(r) / sizeof(seL4_Word), &r));
    return tcb;
}

static seL4_Word consumed(seL4_CPtr sc) {
    seL4_SchedContext_Consumed_t r = seL4_SchedContext_Consumed(sc);
    if (r.error) fail("Consumed");
    return r.consumed;
}

static void interval(void) {
    seL4_Word elapsed = 0;
    (void)consumed(seL4_CapInitThreadSC);
    while (elapsed < 100000) {
        for (unsigned i = 0; i < 100000; i++) __asm__ volatile("pause");
        elapsed += consumed(seL4_CapInitThreadSC);
    }
}

void vmm_fair_main(seL4_BootInfo *bootinfo) {
    seL4_Word tp = (seL4_Word)(tls[4] + sizeof(tls[4]) - 64);
    *(seL4_Word *)tp = tp;
    seL4_TCB_SetTLSBase(seL4_CapInitThreadTCB, tp);
    __sel4_ipc_buffer = bootinfo->ipcBuffer;
    bi = bootinfo;
    next_slot = bi->empty.start;
    if (bi->numNodes < 2) fail("two cores required");
    if (!(GUEST_KERNEL < VMM_FAIR && VMM_FAIR < LOGD_PRIO && LOGD_PRIO < VMM_PRIO)) fail("host priority bands");
    for (seL4_CPtr i = bi->untyped.start; i < bi->untyped.end; i++) {
        seL4_UntypedDesc *d = &bi->untypedList[i - bi->untyped.start];
        if (!d->isDevice && d->sizeBits >= 20) { ut = i; break; }
    }
    if (!ut) fail("no untyped");
    CHECK(seL4_X86_PDPT_Map(object(seL4_X86_PDPTObject, 0), seL4_CapInitThreadVSpace,
                            0x8000000000ul, seL4_X86_Default_VMAttributes));
    CHECK(seL4_X86_PageDirectory_Map(object(seL4_X86_PageDirectoryObject, 0), seL4_CapInitThreadVSpace,
                                     0x8000000000ul, seL4_X86_Default_VMAttributes));
    CHECK(seL4_X86_PageTable_Map(object(seL4_X86_PageTableObject, 0), seL4_CapInitThreadVSpace,
                                 0x8000000000ul, seL4_X86_Default_VMAttributes));
    seL4_CPtr vs = object(seL4_SchedContextObject, SC_BITS), us = object(seL4_SchedContextObject, SC_BITS);
    seL4_CPtr ks = object(seL4_SchedContextObject, SC_BITS);
    seL4_CPtr ls = object(seL4_SchedContextObject, SC_BITS);
    seL4_CPtr user = start(1, us, GUEST_USER);
    seL4_CPtr kernel = start(2, ks, GUEST_KERNEL);
    seL4_CPtr logger = start(3, ls, LOGD_PRIO);
    CHECK(seL4_SchedControl_ConfigureFlags(bi->schedcontrol.start + 1, ls, 1000, 5000, SC_REFILLS, 0, 0));
    seL4_CPtr vmm = start(0, vs, VMM_PRIO);
    (void)consumed(vs); (void)consumed(us); (void)consumed(ks); (void)consumed(ls);
    interval();
    if (consumed(vs) < 50000 || consumed(us) > 1000 || consumed(ks) > 1000) fail("initial priority boost");
    CHECK(seL4_TCB_SetMCPriority(vmm, seL4_CapInitThreadTCB, VMM_FAIR));
    CHECK(seL4_TCB_SetPriority(vmm, seL4_CapInitThreadTCB, VMM_FAIR));
    CHECK(seL4_SchedControl_ConfigureFlags(bi->schedcontrol.start + 1, vs, BG_BUDGET, BG_PERIOD, SC_REFILLS, 0, 0));
    __atomic_store_n(&phase, 1, __ATOMIC_RELEASE);
    interval();
    if (consumed(vs) < 10000 || consumed(ks) < 10000 || !__atomic_load_n(&progress[2], __ATOMIC_RELAXED)) fail("guest kernel starved VMM");
    if (consumed(ls) < 5000 || !__atomic_load_n(&progress[3], __ATOMIC_RELAXED)) fail("VMM delayed logd");
    /* A kernel spinning for an I/O reply cannot prevent the VMM running.
     * Once that kernel blocks, the VMM must leave time for guest users. */
    CHECK(seL4_TCB_Suspend(kernel));
    (void)consumed(vs); (void)consumed(us);
    interval();
    if (consumed(vs) < 10000 || consumed(us) < 10000 || !__atomic_load_n(&progress[1], __ATOMIC_RELAXED)) fail("guest user progress");
    if (!__atomic_load_n(&denied, __ATOMIC_RELAXED) || __atomic_load_n(&escaped, __ATOMIC_ACQUIRE)) fail("VMM regained authority");
    /* Its parent can restore the boost without restoring the VMM's MCP. */
    CHECK(seL4_TCB_SetPriority(vmm, seL4_CapInitThreadTCB, VMM_PRIO));
    __atomic_store_n(&phase, 2, __ATOMIC_RELEASE);
    interval();
    if (__atomic_load_n(&escaped, __ATOMIC_ACQUIRE) || __atomic_load_n(&denied, __ATOMIC_RELAXED) != 2) fail("restored boost restored authority");
    CHECK(seL4_TCB_Suspend(vmm));
    CHECK(seL4_TCB_Suspend(user));
    CHECK(seL4_TCB_Suspend(logger));
    say("VMMFAIR: PASS (kernel/user/logd progress, authority ceiling)\n");
    for (;;) seL4_Yield();
}

__asm__(".global _start\n_start:\n lea vmm_fair_stack+16384(%rip), %rsp\n call vmm_fair_main\n1: jmp 1b\n");

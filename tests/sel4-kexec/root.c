/* SPDX-License-Identifier: GPL-2.0-only */
/* A minimal root task for patch 0026; no l4h host or guest is involved. */
#include <sel4/config.h>
#undef CONFIG_LIB_SEL4_USE_THREAD_LOCALS
#include <sel4/sel4.h>

seL4_IPCBuffer *__sel4_ipc_buffer;
static seL4_CPtr debug_port;
extern const unsigned char payload[], payload_end[];

static void print(const char *s)
{
    while (*s) {
        seL4_X86_IOPort_Out8(debug_port, 0xe9, *s++);
    }
}

static void check(int ok, const char *what)
{
    if (!ok) {
        print("KEXEC: FAIL ");
        print(what);
        print("\n");
        seL4_TCB_Suspend(seL4_CapInitThreadTCB);
        for (;;) {}
    }
}

static void copy(void *dst, const void *src, unsigned long len)
{
    unsigned char *d = dst;
    const unsigned char *s = src;
    while (len--) {
        *d++ = *s++;
    }
}

static void retype(seL4_CPtr ut, seL4_Word type, seL4_CPtr slot)
{
    check(seL4_Untyped_Retype(ut, type, 0, seL4_CapInitThreadCNode, 0, 0, slot, 1) == 0, "retype");
}

static void migrate(seL4_BootInfo *bi, unsigned int cpu)
{
#ifdef CONFIG_KERNEL_MCS
    check(seL4_SchedControl_ConfigureFlags(bi->schedcontrol.start + cpu,
          seL4_CapInitThreadSC, 10000, 10000, 0, 0, 0) == 0, "migrate");
#elif defined(CONFIG_ENABLE_SMP_SUPPORT)
    (void)bi;
    check(seL4_TCB_SetAffinity(seL4_CapInitThreadTCB, cpu) == 0, "migrate");
#else
    (void)bi;
    (void)cpu;
#endif
}

void test_main(seL4_BootInfo *bi)
{
    seL4_SetIPCBuffer(bi->ipcBuffer);
    seL4_CPtr slot = bi->empty.start;
    debug_port = slot++;
    if (seL4_X86_IOPortControl_Issue(seL4_CapIOPortControl, 0xe9, 0xe9,
            seL4_CapInitThreadCNode, debug_port, seL4_WordBits)) {
        for (;;) {}
    }
    print("KEXEC: start\n");
    check(seL4_X86_Kexec(seL4_CapIRQControl, 0) == seL4_InvalidArgument, "null control");
    check(seL4_X86_Kexec(seL4_CapIRQControl, 0x1001) == seL4_InvalidArgument, "alignment");
    check(seL4_X86_Kexec(seL4_CapIRQControl, 1ul << 32) == seL4_InvalidArgument, "high control");
    check(seL4_X86_Kexec(seL4_CapInitThreadTCB, 0) == seL4_IllegalOperation, "wrong cap");
    seL4_MessageInfo_t reply = seL4_Call(seL4_CapIRQControl,
            seL4_MessageInfo_new(X86IRQControlKexec, 0, 0, 0));
    check(seL4_MessageInfo_get_label(reply) == seL4_TruncatedMessage, "short message");
    if (bi->numNodes > 1) {
        migrate(bi, 1);
        check(seL4_X86_Kexec(seL4_CapIRQControl, 0) == seL4_IllegalOperation, "AP invocation");
        migrate(bi, 0);
    }

    /* One large frame contains all sources/control memory, safely above the
     * entire old kernel. A new PDPT avoids the initial task's existing tables. */
    seL4_CPtr ut = 0;
    seL4_Word pa = 0;
    for (seL4_Word i = 0; i < bi->untyped.end - bi->untyped.start; i++) {
        seL4_UntypedDesc *d = &bi->untypedList[i];
        if (!d->isDevice && d->sizeBits >= 22 && d->paddr >= 0x1000000 &&
                d->paddr < (1ul << 32) - (1ul << 22)) {
            ut = bi->untyped.start + i;
            pa = d->paddr;
            break;
        }
    }
    check(ut != 0, "staging untyped");
    seL4_CPtr frame = slot++, pdpt_cap = slot++, pd_cap = slot++;
    retype(ut, seL4_X86_LargePageObject, frame);
    retype(ut, seL4_X86_PDPTObject, pdpt_cap);
    retype(ut, seL4_X86_PageDirectoryObject, pd_cap);
    const seL4_Word va = 1ul << 39;
    check(seL4_X86_PDPT_Map(pdpt_cap, seL4_CapInitThreadVSpace, va, seL4_X86_Default_VMAttributes) == 0, "PDPT map");
    check(seL4_X86_PageDirectory_Map(pd_cap, seL4_CapInitThreadVSpace, va, seL4_X86_Default_VMAttributes) == 0, "PD map");
    check(seL4_X86_Page_Map(frame, seL4_CapInitThreadVSpace, va, seL4_AllRights,
          seL4_X86_Default_VMAttributes) == 0, "frame map");

    seL4_X86_KexecControl_t *c = (void *)va;
    c->version = SEL4_X86_KEXEC_VERSION;
    c->pml4 = pa + 0x1000;
    c->trampoline = pa + 0x7000;
    c->parking = pa + 0x8000;
    c->stack = pa + 0x9000;
    c->segments = pa + 0xa000;
    c->segment_count = 10;
    c->entry = 0x100000;
    c->multiboot_info = pa + 0xb000;
    c->parked = ~0ul; /* The kernel must initialize this itself. */
    seL4_Word *pml4 = (void *)(va + 0x1000), *pdpt = (void *)(va + 0x2000);
    pml4[0] = (pa + 0x2000) | 3;
    for (unsigned int i = 0; i < 4; i++) {
        pdpt[i] = (pa + 0x3000 + i * 0x1000) | 3;
        seL4_Word *pd = (void *)(va + 0x3000 + i * 0x1000);
        for (unsigned int j = 0; j < 512; j++) {
            pd[j] = ((seL4_Word)(i * 512 + j) << 21) | 0x83;
        }
    }
    copy((void *)(va + 0x7000), seL4_X86_KexecTrampoline,
         seL4_X86_KexecTrampolineEnd - seL4_X86_KexecTrampoline);
    copy((void *)(va + 0x8000), seL4_X86_KexecPark, seL4_X86_KexecParkEnd - seL4_X86_KexecPark);
    copy((void *)(va + 0x10000), payload, payload_end - payload);
    unsigned char *pattern = (void *)(va + 0x20000);
    for (unsigned int i = 0; i < 0x100000; i++) {
        pattern[i] = 0x5a;
    }
    seL4_X86_KexecSegment_t *segments = (void *)(va + 0xa000);
    for (unsigned int i = 0; i < 8; i++) {
        segments[i] = (seL4_X86_KexecSegment_t) { pa + 0x20000, 0x100000ul * (i + 1), 0x100000 };
    }
    segments[8] = (seL4_X86_KexecSegment_t) { SEL4_X86_KEXEC_ZERO, 0x200000, 0x8000 };
    segments[9] = (seL4_X86_KexecSegment_t) { pa + 0x10000, 0x100000, payload_end - payload };
    /* MBI with a private tag carrying the parking mask for the test payload. */
    seL4_Uint32 *mbi = (void *)(va + 0xb000);
    seL4_Word mask = ((1ul << (bi->numNodes - 1)) - 1) << 1;
    mbi[0] = 40; mbi[2] = 0x6c3468; mbi[3] = 24;
    mbi[4] = pa; mbi[5] = mask; mbi[6] = mask >> 32;
#ifdef CONFIG_X2APIC
    mbi[7] = 1 << 10;
#endif
    mbi[9] = 8;

    c->version++;
    check(seL4_X86_Kexec(seL4_CapIRQControl, pa) == seL4_InvalidArgument, "version");
    c->version--;
    c->stack = c->parking;
    check(seL4_X86_Kexec(seL4_CapIRQControl, pa) == seL4_InvalidArgument, "aliased control pages");
    c->stack = pa + 0x9000;
    c->segment_count = ~0ul;
    check(seL4_X86_Kexec(seL4_CapIRQControl, pa) == seL4_InvalidArgument, "list overflow");
    c->segment_count = 10;
    print("KEXEC: validation passed; overwriting old kernel\n");
    seL4_X86_Kexec(seL4_CapIRQControl, pa);
    check(0, "returned from kexec");
}

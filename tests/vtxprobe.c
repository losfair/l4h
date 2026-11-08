// SPDX-License-Identifier: GPL-2.0-only
/*
 * A minimal seL4 root task for tests/run-vtxtest.sh: try to create the
 * objects that need VT-x (patch 0038) and report each result on the
 * kernel's debug console.  With VT-x it also binds the VCPU to a TCB,
 * which loads its VMCS.  Built freestanding against build/sel4's libsel4.
 */
#include <sel4/sel4.h>

__thread seL4_IPCBuffer *__sel4_ipc_buffer;
static char tls[4096] __attribute__((aligned(64)));
char vtxprobe_stack[16384] __attribute__((aligned(16)));

static void puts_(const char *s)
{
    while (*s)
        seL4_DebugPutChar(*s++);
}

static void report(const char *what, seL4_Error err)
{
    char digits[8];
    int i = 0;

    puts_("vtxprobe: ");
    puts_(what);
    if (err == seL4_NoError) {
        puts_(" ok\n");
        return;
    }
    puts_(" err=");
    do {
        digits[i++] = '0' + err % 10;
        err /= 10;
    } while (err);
    while (i)
        seL4_DebugPutChar(digits[--i]);
    puts_("\n");
}

void vtxprobe_main(seL4_BootInfo *bi)
{
    /* libsel4 keeps the IPC buffer pointer in TLS (%fs). */
    unsigned long tp = (unsigned long)(tls + sizeof(tls) - 64);
    *(unsigned long *)tp = tp;
    __asm__ volatile("wrfsbase %0" :: "r"(tp));
    __sel4_ipc_buffer = bi->ipcBuffer;

    seL4_CPtr ut = seL4_CapNull;
    for (seL4_CPtr i = bi->untyped.start; i < bi->untyped.end; i++) {
        seL4_UntypedDesc *d = &bi->untypedList[i - bi->untyped.start];
        if (!d->isDevice && d->sizeBits >= 20) {
            ut = i;
            break;
        }
    }
    if (ut == seL4_CapNull) {
        puts_("vtxprobe: no untyped of 1 MiB\n");
        for (;;)
            seL4_Yield();
    }

    seL4_CPtr vcpu = bi->empty.start, pml4 = vcpu + 1, pt = vcpu + 2, tcb = vcpu + 3;
    seL4_Error vcpu_err = seL4_Untyped_Retype(ut, seL4_X86_VCPUObject, 0,
                                              seL4_CapInitThreadCNode, 0, 0, vcpu, 1);
    report("vcpu", vcpu_err);
    report("ept_pml4", seL4_Untyped_Retype(ut, seL4_X86_EPTPML4Object, 0,
                                           seL4_CapInitThreadCNode, 0, 0, pml4, 1));
    report("ept_pt", seL4_Untyped_Retype(ut, seL4_X86_EPTPTObject, 0,
                                         seL4_CapInitThreadCNode, 0, 0, pt, 1));
    report("tcb", seL4_Untyped_Retype(ut, seL4_TCBObject, 0,
                                      seL4_CapInitThreadCNode, 0, 0, tcb, 1));
    if (vcpu_err == seL4_NoError) {
        report("vcpu_set_tcb", seL4_X86_VCPU_SetTCB(vcpu, tcb));
        /* Loaded with WRMSR before VM entry: only canonical addresses
         * (patch 0039). */
        report("kgs_canonical", seL4_X86_VCPU_WriteMSR(vcpu, 0xC0000102, 0xffff800000001000ul).error);
        report("kgs_noncanonical", seL4_X86_VCPU_WriteMSR(vcpu, 0xC0000102, 0x0100000000000000ul).error);
    }
    puts_("vtxprobe: done\n");
    for (;;)
        seL4_Yield();
}

__asm__(".global _start\n"
        "_start:\n"
        "    lea vtxprobe_stack+16384(%rip), %rsp\n"
        "    call vtxprobe_main\n"
        "1:  jmp 1b\n");

// SPDX-License-Identifier: GPL-2.0-only
/*
 * A minimal seL4 root task for tests/run-vtxtest.sh: try to create the
 * objects that need VT-x (patch 0038) and report each result on the
 * kernel's debug console.  With VT-x it also binds the VCPU to a TCB,
 * which loads its VMCS.  Built freestanding against build/sel4's libsel4.
 */
#include <sel4/sel4.h>
#include <sel4/arch/vmenter.h>

__thread seL4_IPCBuffer *__sel4_ipc_buffer;
static char tls[4096] __attribute__((aligned(64)));
static char tls2[4096] __attribute__((aligned(64)));
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

static int is_amd(void)
{
    unsigned int a = 0, b, c, d;

    __asm__ volatile("cpuid" : "+a"(a), "=b"(b), "=c"(c), "=d"(d));
    return b == 0x68747541;     /* "Auth" */
}

/* Patch 0040's VMCB offsets and exit codes. */
#define VMCB_I_CR       0x000   /* the CR intercepts, then the DR ones */
#define VMCB_I_MISC1    0x008   /* the exception intercepts, then misc1 */
#define VMCB_I_MISC2    0x010
#define VMCB_IOPM       0x040
#define VMCB_CLEAN      0x0c0
#define VMCB_CS         0x410
#define VMCB_IDTR       0x480
#define VMCB_CR4        0x548
#define VMCB_CR0        0x558
#define VMCB_CLEAN_DT   (1u << 7)
#define VMCB_RIP        0x578
#define SVM_I1_INVD     (1u << 22)
#define SVM_I1_HLT      (1u << 24)
#define SVM_CR4_WRITE   (1u << 20)
#define SVM_EXC_UD      (1u << 6)
#define SVM_EXIT_INVD   0x76
#define SVM_EXIT_IOIO   0x7b
#define SVM_EXIT_HLT    0x78
#define SVM_EXIT_NPF    0x400
#define SVM_EXIT_CR4_WRITE 0x14
#define SVM_EXIT_UD     0x46
#define CR4_PKE         (1ul << 22)
/* Patches 0040 and 0042: the CR4 bits a guest may set (VCPU_GUEST_CR4_ALLOWED). */
#define CR4_ALLOWED     (0x1ffful | 1ul << 16 | 1ul << 17 | 1ul << 18 | 1ul << 20 | 1ul << 21)
#define CR4_VMXE        (1ul << 13)
/* The VMCS fields patch 0042 masks on VT-x. */
#define VMX_CR4_MASK    0x6002
#define VMX_GUEST_CR4   0x6804
/* The primary controls patches 0039 and 0043 keep on: CR8-load and
 * CR8-store exiting and MOV-DR exiting. */
#define VMX_PRIMARY_CONTROLS 0x4002
#define VMX_PPC_FORCED  (1ul << 19 | 1ul << 20 | 1ul << 23)

static void check(const char *what, int ok)
{
    report(what, ok ? seL4_NoError : seL4_InvalidArgument);
}

/* Run a real-mode guest on the root thread: an OUT, a read of unmapped
 * guest memory, an INVD that only the kernel intercepts and a HLT, each a
 * VM exit to here.  The kernel must keep its intercepts and refuse the
 * VMCB fields it owns. */
static void svm_probe(seL4_BootInfo *bi, seL4_CPtr ut, seL4_CPtr vcpu, seL4_CPtr pml4,
                      seL4_CPtr pt, seL4_CPtr free)
{
    static const unsigned char code[] = {
        0xb0, 0x42,             /* mov $0x42, %al */
        0xe6, 0x80,             /* out %al, $0x80 */
        0xa0, 0x00, 0x50,       /* mov 0x5000, %al */
        0x0f, 0x08,             /* invd */
        0xf4,                   /* hlt */
    };
    seL4_CPtr pdpt = free, pd = free + 1, frame = free + 2, copy = free + 3;
    seL4_CPtr vpdpt = free + 4, vpd = free + 5, vpt = free + 6;
    unsigned long va = 0x8000000000ul;
    unsigned long tp = (unsigned long)(tls + sizeof(tls) - 64), tp2, fs;
    seL4_X86_VCPU_WriteVMCB_t w;
    seL4_MessageInfo_t tag;
    seL4_Word badge;
    int ok;

    w = seL4_X86_VCPU_WriteVMCB(vcpu, VMCB_I_MISC2, 0);
    check("svm_forced_intercepts", !w.error && (w.written & 0x7d) == 0x7d);
    w = seL4_X86_VCPU_WriteVMCB(vcpu, VMCB_I_MISC1, 0);
    check("svm_forced_invd", !w.error && (w.written >> 32 & SVM_I1_INVD));
    report("svm_owned_field", seL4_X86_VCPU_WriteVMCB(vcpu, VMCB_IOPM, 0).error);

    seL4_Untyped_Retype(ut, seL4_X86_EPTPDPTObject, 0, seL4_CapInitThreadCNode, 0, 0, pdpt, 1);
    seL4_Untyped_Retype(ut, seL4_X86_EPTPDObject, 0, seL4_CapInitThreadCNode, 0, 0, pd, 1);
    seL4_Untyped_Retype(ut, seL4_X86_4K, 0, seL4_CapInitThreadCNode, 0, 0, frame, 1);
    seL4_Untyped_Retype(ut, seL4_X86_PDPTObject, 0, seL4_CapInitThreadCNode, 0, 0, vpdpt, 1);
    seL4_Untyped_Retype(ut, seL4_X86_PageDirectoryObject, 0, seL4_CapInitThreadCNode, 0, 0, vpd, 1);
    seL4_Untyped_Retype(ut, seL4_X86_PageTableObject, 0, seL4_CapInitThreadCNode, 0, 0, vpt, 1);
    seL4_CNode_Copy(seL4_CapInitThreadCNode, copy, seL4_WordBits,
                    seL4_CapInitThreadCNode, frame, seL4_WordBits, seL4_AllRights);
    report("svm_asid", seL4_X86_ASIDPool_Assign(seL4_CapInitThreadASIDPool, pml4));
    report("svm_map", seL4_X86_EPTPDPT_Map(pdpt, pml4, 0, seL4_X86_EPT_Default_VMAttributes) |
           seL4_X86_EPTPD_Map(pd, pml4, 0, seL4_X86_EPT_Default_VMAttributes) |
           seL4_X86_EPTPT_Map(pt, pml4, 0, seL4_X86_EPT_Default_VMAttributes) |
           seL4_X86_Page_MapEPT(frame, pml4, 0, seL4_ReadWrite, seL4_X86_EPT_Default_VMAttributes) |
           seL4_X86_PDPT_Map(vpdpt, seL4_CapInitThreadVSpace, va, seL4_X86_Default_VMAttributes) |
           seL4_X86_PageDirectory_Map(vpd, seL4_CapInitThreadVSpace, va, seL4_X86_Default_VMAttributes) |
           seL4_X86_PageTable_Map(vpt, seL4_CapInitThreadVSpace, va, seL4_X86_Default_VMAttributes) |
           seL4_X86_Page_Map(copy, seL4_CapInitThreadVSpace, va, seL4_ReadWrite,
                             seL4_X86_Default_VMAttributes));
    for (unsigned int i = 0; i < sizeof(code); i++)
        ((volatile unsigned char *)va)[i] = code[i];

    /* CS at 0 for real mode, and the guest on this thread. */
    seL4_X86_VCPU_WriteVMCB(vcpu, VMCB_CS, 0x9bul << 16 | 0xfffful << 32);
    seL4_X86_VCPU_WriteVMCB(vcpu, VMCB_CS + 8, 0);
    report("svm_bind", seL4_X86_VCPU_SetTCB(vcpu, seL4_CapInitThreadTCB) |
           seL4_TCB_SetEPTRoot(seL4_CapInitThreadTCB, pml4));

    seL4_SetMR(SEL4_VMENTER_CALL_EIP_MR, 0);
    seL4_SetMR(SEL4_VMENTER_CALL_CONTROL_PPC_MR, SVM_I1_HLT);
    seL4_SetMR(SEL4_VMENTER_CALL_INTERRUPT_INFO_MR, 0);
    check("svm_io", seL4_VMEnter(&badge) == SEL4_VMENTER_RESULT_FAULT &&
          seL4_GetMR(SEL4_VMENTER_FAULT_REASON_MR) == SVM_EXIT_IOIO &&
          seL4_GetMR(SEL4_VMENTER_FAULT_QUALIFICATION_MR) >> 16 == 0x80 &&
          (seL4_GetMR(SEL4_VMENTER_FAULT_EAX) & 0xff) == 0x42 &&
          seL4_GetMR(SEL4_VMENTER_FAULT_INSTRUCTION_LEN_MR) == 2);

    seL4_SetMR(SEL4_VMENTER_CALL_EIP_MR, seL4_GetMR(SEL4_VMENTER_CALL_EIP_MR) + 2);
    check("svm_npf", seL4_VMEnter(&badge) == SEL4_VMENTER_RESULT_FAULT &&
          seL4_GetMR(SEL4_VMENTER_FAULT_REASON_MR) == SVM_EXIT_NPF &&
          seL4_GetMR(SEL4_VMENTER_FAULT_GUEST_PHYSICAL_MR) == 0x5000 &&
          seL4_GetMR(SEL4_VMENTER_CALL_EIP_MR) == 4);

    /* Only HLT requested: INVD must exit anyway. */
    seL4_SetMR(SEL4_VMENTER_CALL_EIP_MR, 7);
    check("svm_invd", seL4_VMEnter(&badge) == SEL4_VMENTER_RESULT_FAULT &&
          seL4_GetMR(SEL4_VMENTER_FAULT_REASON_MR) == SVM_EXIT_INVD &&
          seL4_GetMR(SEL4_VMENTER_CALL_EIP_MR) == 7);

    seL4_SetMR(SEL4_VMENTER_CALL_EIP_MR, 9);
    check("svm_hlt", seL4_VMEnter(&badge) == SEL4_VMENTER_RESULT_FAULT &&
          seL4_GetMR(SEL4_VMENTER_FAULT_REASON_MR) == SVM_EXIT_HLT);

    /* An exit's VMLOAD restores the FS base the kernel's host area was
     * saved with, at the first VMRUN: a TLS base set since must still be
     * this thread's after an exit (with KernelFSGSBase=msr, the kernel
     * skips the WRMSR of a base it thinks is loaded already). */
    for (unsigned int i = 0; i < sizeof(tls); i++)
        tls2[i] = tls[i];
    tp2 = (unsigned long)(tls2 + sizeof(tls2) - 64);
    *(unsigned long *)tp2 = tp2;
    ok = seL4_TCB_SetTLSBase(seL4_CapInitThreadTCB, tp2) == seL4_NoError;
    seL4_SetMR(SEL4_VMENTER_CALL_EIP_MR, 9);
    ok = ok && seL4_VMEnter(&badge) == SEL4_VMENTER_RESULT_FAULT &&
         seL4_GetMR(SEL4_VMENTER_FAULT_REASON_MR) == SVM_EXIT_HLT;
    __asm__ volatile("mov %%fs:0, %0" : "=r"(fs));
    check("svm_tls_base", ok && fs == tp2);
    seL4_TCB_SetTLSBase(seL4_CapInitThreadTCB, tp);

    /* A VMRUN that fails its checks may load nothing: an IDTR written
     * before it is still not clean for the next VMRUN, which runs. */
    seL4_X86_VCPU_WriteVMCB(vcpu, VMCB_IDTR + 8, 0x1000);
    seL4_X86_VCPU_WriteVMCB(vcpu, VMCB_CR0, 1ul << 63 | 0x10);
    seL4_SetMR(SEL4_VMENTER_CALL_EIP_MR, 9);
    check("svm_invalid", seL4_VMEnter(&badge) == SEL4_VMENTER_RESULT_FAULT &&
          seL4_GetMR(SEL4_VMENTER_FAULT_REASON_MR) == 0xffffffff);
    seL4_X86_VCPU_WriteVMCB(vcpu, VMCB_CR0, 0x10);
    seL4_SetMR(SEL4_VMENTER_CALL_EIP_MR, 9);
    ok = seL4_VMEnter(&badge) == SEL4_VMENTER_RESULT_FAULT &&
         seL4_GetMR(SEL4_VMENTER_FAULT_REASON_MR) == SVM_EXIT_HLT;
    seL4_SetMR(0, VMCB_CLEAN);
    seL4_SetMR(1, 1);
    tag = seL4_Call(vcpu, seL4_MessageInfo_new(X86VCPUReadVMCB, 0, 0, 2));
    check("svm_dirty_kept", ok && !seL4_MessageInfo_get_label(tag) &&
          !(seL4_GetMR(0) & VMCB_CLEAN_DT));

    /* Patch 0040: CR4 writes always exit and CR4 keeps only the allowed
     * bits, so the guest cannot, for one, set a PKRU that the next guest on
     * the core runs with.  The guest sets PKE with a MOV; written back as a
     * VMM would on that exit, CR4 keeps PKE clear and WRPKRU raises #UD. */
    static const unsigned char pke_code[] = {
        0x0f, 0x20, 0xe0,                       /* mov %cr4, %eax */
        0x66, 0x0d, 0x00, 0x00, 0x40, 0x00,     /* or $0x400000, %eax */
        0x0f, 0x22, 0xe0,                       /* mov %eax, %cr4 */
        0x66, 0x31, 0xc9,                       /* xor %ecx, %ecx */
        0x66, 0x31, 0xd2,                       /* xor %edx, %edx */
        0x0f, 0x01, 0xef,                       /* wrpkru */
        0xf4,                                   /* hlt */
    };
    unsigned long cr4;
    w = seL4_X86_VCPU_WriteVMCB(vcpu, VMCB_I_CR, 0);
    check("svm_forced_cr4_write", !w.error && (w.written & SVM_CR4_WRITE));
    w = seL4_X86_VCPU_WriteVMCB(vcpu, VMCB_CR4, ~0ul);
    check("svm_cr4_allowed", !w.error && w.written == CR4_ALLOWED);
    seL4_X86_VCPU_WriteVMCB(vcpu, VMCB_CR4, 0);
    for (unsigned int i = 0; i < sizeof(pke_code); i++)
        ((volatile unsigned char *)va)[0x10 + i] = pke_code[i];
    seL4_X86_VCPU_WriteVMCB(vcpu, VMCB_I_MISC1, (unsigned long)SVM_I1_HLT << 32 | SVM_EXC_UD);
    seL4_SetMR(SEL4_VMENTER_CALL_EIP_MR, 0x10);
    seL4_SetMR(SEL4_VMENTER_CALL_CONTROL_PPC_MR, SVM_I1_HLT);
    seL4_SetMR(SEL4_VMENTER_CALL_INTERRUPT_INFO_MR, 0);
    ok = seL4_VMEnter(&badge) == SEL4_VMENTER_RESULT_FAULT &&
         seL4_GetMR(SEL4_VMENTER_FAULT_REASON_MR) == SVM_EXIT_CR4_WRITE &&
         seL4_GetMR(SEL4_VMENTER_CALL_EIP_MR) == 0x19;
    cr4 = seL4_GetMR(SEL4_VMENTER_FAULT_EAX);
    check("svm_cr4_exit", ok && (cr4 & CR4_PKE));
    seL4_X86_VCPU_WriteVMCB(vcpu, VMCB_CR4, cr4);
    seL4_SetMR(SEL4_VMENTER_CALL_EIP_MR, 0x1c);
    seL4_SetMR(SEL4_VMENTER_CALL_CONTROL_PPC_MR, SVM_I1_HLT);
    seL4_SetMR(SEL4_VMENTER_CALL_INTERRUPT_INFO_MR, 0);
    check("svm_pkru_ud", seL4_VMEnter(&badge) == SEL4_VMENTER_RESULT_FAULT &&
          seL4_GetMR(SEL4_VMENTER_FAULT_REASON_MR) == SVM_EXIT_UD &&
          seL4_GetMR(SEL4_VMENTER_CALL_EIP_MR) == 0x22);

    /* An exit while VMRUN delivers EVENTINJ: interrupt 0x20 pushes its
     * frame below SP 0, to unmapped guest memory.  The guest's interrupt
     * shadow must stay clear (no host STI shadow in INT_STATE). */
    ((volatile unsigned short *)va)[0x80 / 2] = 0x100;
    ((volatile unsigned short *)va)[0x82 / 2] = 0;
    seL4_SetMR(SEL4_VMENTER_CALL_EIP_MR, 9);
    seL4_SetMR(SEL4_VMENTER_CALL_INTERRUPT_INFO_MR, 1u << 31 | 0x20);
    check("svm_inject_exit", seL4_VMEnter(&badge) == SEL4_VMENTER_RESULT_FAULT &&
          seL4_GetMR(SEL4_VMENTER_FAULT_REASON_MR) == SVM_EXIT_NPF &&
          (seL4_GetMR(SEL4_VMENTER_FAULT_IDT_VECTOR_INFO) & (1u << 31 | 0x7ff)) ==
          (1u << 31 | 0x20) &&
          !(seL4_GetMR(SEL4_VMENTER_FAULT_GUEST_INT_MR) & 1));
    (void)bi;
}

void vtxprobe_main(seL4_BootInfo *bi)
{
    /* libsel4 keeps the IPC buffer pointer in TLS (%fs).  Not with
     * WRFSBASE, which a KernelFSGSBase=msr kernel leaves disabled. */
    unsigned long tp = (unsigned long)(tls + sizeof(tls) - 64);
    *(unsigned long *)tp = tp;
    seL4_TCB_SetTLSBase(seL4_CapInitThreadTCB, tp);
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
        if (is_amd()) {
            svm_probe(bi, ut, vcpu, pml4, pt, tcb + 1);
        } else {
            /* Patch 0042: the CR4 bits a guest may not set stay in the
             * mask and out of the guest; VMXE is fixed to 1. */
            seL4_X86_VCPU_WriteVMCS_t w = seL4_X86_VCPU_WriteVMCS(vcpu, VMX_CR4_MASK, 0);
            check("vmx_cr4_mask", !w.error && w.written == ~CR4_ALLOWED);
            w = seL4_X86_VCPU_WriteVMCS(vcpu, VMX_GUEST_CR4, ~0ul);
            check("vmx_guest_cr4", !w.error && !(w.written & ~(CR4_ALLOWED | CR4_VMXE)) &&
                  !(w.written & CR4_PKE));
            /* Patch 0043: guest MOVs to and from CR8 always exit. */
            w = seL4_X86_VCPU_WriteVMCS(vcpu, VMX_PRIMARY_CONTROLS, 0);
            check("vmx_ppc_forced", !w.error && (w.written & VMX_PPC_FORCED) == VMX_PPC_FORCED);
        }
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

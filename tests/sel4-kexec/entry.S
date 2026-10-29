/* SPDX-License-Identifier: GPL-2.0-only */
#include <sel4/sel4_arch/kexec.h>
.text
.code64
.global _start
_start:
    leaq stack_top(%rip), %rsp
    call test_main
    ud2

/* Copied over the old kernel at 1 MiB. No absolute references to the root task. */
.section .rodata.payload,"a",@progbits
.code32
.global payload, payload_end
payload:
    cmpl $0x36d76289, %eax
    jne fail
    testl $7, %ebx
    jnz fail
    cmpl $40, (%ebx)
    jne fail
    cmpl $0x6c3468, 8(%ebx)
    jne fail
    movl %cr0, %eax
    andl $0x80000001, %eax
    cmpl $1, %eax
    jne fail
    movl %cr4, %eax
    testl $((1 << 5) | (1 << 7) | (1 << 17)), %eax
    jnz fail
    testl $(1 << 4), %eax
    jz fail
    testl $((1 << 20) | (1 << 21)), %eax
    jnz fail
    pushfl
    popl %eax
    testl $((1 << 9) | (1 << 10) | (1 << 17)), %eax
    jnz fail
    movl $0xc0000080, %ecx
    rdmsr
    testl $((1 << 8) | (1 << 10)), %eax
    jnz fail
    movl $0x1b, %ecx
    rdmsr
    andl $(1 << 10), %eax
    cmpl 28(%ebx), %eax
    jne fail
    movl 16(%ebx), %ebp
    movl SEL4_X86_KEXEC_PARKED(%ebp), %eax
    cmpl 20(%ebx), %eax
    jne fail
    movl SEL4_X86_KEXEC_PARKED+4(%ebp), %eax
    cmpl 24(%ebx), %eax
    jne fail
    /* Includes the old kernel text, stacks, and page tables. */
    movl $0x300000, %edi
    movl $0x600000, %ecx
    movb $0x5a, %al
    repe scasb
    jne fail
    movl $0x200000, %edi
    movl $0x8000, %ecx
    xorl %eax, %eax
    repe scasb
    jne fail
    /* Check the flat data segments; the old FS/GS bases must not leak. */
    movl %fs:16(%ebx), %eax
    cmpl %ebp, %eax
    jne fail
    movl %gs:16(%ebx), %eax
    cmpl %ebp, %eax
    jne fail
    call 1f
1:  popl %esi
    addl $(pass_text - 1b), %esi
    movl $0x10, %edi
    jmp output
fail:
    call 1f
1:  popl %esi
    addl $(fail_text - 1b), %esi
    movl $0x11, %edi
output:
    movw $0xe9, %dx
1:  lodsb
    testb %al, %al
    jz 2f
    outb %al, %dx
    jmp 1b
2:  movw $0xf4, %dx
    movl %edi, %eax
    outl %eax, %dx
    cli
3:  hlt
    jmp 3b
pass_text: .asciz "KEXEC: PASS handoff, copies, parked APs\n"
fail_text: .asciz "KEXEC: FAIL payload state\n"
payload_end:

.bss
.balign 16
.skip 16384
stack_top:
.section .note.GNU-stack,"",@progbits

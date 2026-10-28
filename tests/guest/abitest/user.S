/* SPDX-License-Identifier: GPL-2.0 */
/* The user program of the ABI test, copied to a page of its own. */
	.section .rodata, "a"
	.balign 16
	.globl user_prog, user_debug, user_write, user_end
#ifdef __aarch64__
user_prog:
	/* d0 = 0x1122334455667788 to check FPU state transfer. */
	movz	x0, #0x7788
	movk	x0, #0x5566, lsl #16
	movk	x0, #0x3344, lsl #32
	movk	x0, #0x1122, lsl #48
	fmov	d0, x0
	/* getpid(); x7 = -1 would be an seL4 syscall number if not trapped */
	mov	x8, #172
	mov	x7, #-1
	svc	#0
	/* touch an unmapped address -> VM fault */
	mov	x1, #0x500000
	ldr	x2, [x1]
	/* seL4 issue #477 on aarch64: every seL4 syscall number in x7 must
	 * still trap. */
	mov	x12, x0
	mov	x13, #-1
3:	mov	x8, #172
	mov	x7, x13
	svc	#0
	sub	sp, sp, #16
	sub	x13, x13, #1
	cmn	x13, #64
	b.ge	3b
	/* exit(saved x0) */
	mov	x0, x12
	mov	x8, #93
	svc	#0
2:	b	2b

/* seL4_DebugHalt from a thread without the trap flag: must fault (patch
 * 0008), not halt the host. */
user_debug:
	mov	x7, #-14
	svc	#0
4:	b	4b
user_write:
	mov	x1, #0x500000
	str	x1, [x1]
	brk	#0
#else
user_prog:
	/* xmm0 = 0x1122334455667788 to check FPU state transfer. */
	movabsq	$0x1122334455667788, %rax
	movq	%rax, %xmm0
	/* getpid(); rdx = -1 would be an seL4 syscall number if not trapped */
	movq	$39, %rax
	movq	$-1, %rdx
	syscall
	/* touch an unmapped address -> VM fault */
	movq	$0x500000, %rbx
	movq	(%rbx), %rcx
	/* seL4 issue #477: with every seL4 syscall number in rdx (and the
	 * aarch64-relevant registers too), each syscall must still trap. */
	movq	%rax, %r12
	movq	$-1, %rbx
3:	movq	$39, %rax
	movq	%rbx, %rdx
	movq	%rbx, %r10
	movq	%rbx, %r8
	movq	%rbx, %r9
	syscall
	subq	$16, %rsp
	decq	%rbx
	cmpq	$-64, %rbx
	jge	3b
	/* exit(saved rax) */
	movq	%r12, %rdi
	movq	$60, %rax
	syscall
2:	jmp	2b

/* seL4_DebugHalt from a thread without the trap flag: must fault (patch
 * 0008), not halt the host. */
user_debug:
	movq	$-14, %rdx
	syscall
4:	jmp	4b
user_write:
	movq	$0x500000, %rbx
	movq	%rbx, (%rbx)
	ud2
#endif
user_end:

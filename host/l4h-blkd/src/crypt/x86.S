// AES-NI, no AVX and no XMM arguments/results. All used vector registers
// and the tweak scratch are cleared before returning to Rust.
.text
.macro clear_vectors
    .irp n,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
        pxor xmm\n, xmm\n
    .endr
.endm

// One pair of AES-256 round keys. xmm0/xmm1 are the previous pair.
.macro expand_pair rc, off, last=0
    aeskeygenassist xmm2, xmm1, \rc
    pshufd xmm2, xmm2, 0xff
    movdqa xmm3, xmm0
    pslldq xmm3, 4
    pxor xmm0, xmm3
    pslldq xmm3, 4
    pxor xmm0, xmm3
    pslldq xmm3, 4
    pxor xmm0, xmm3
    pxor xmm0, xmm2
    movdqu [rsi + \off], xmm0
    .if !\last
        aeskeygenassist xmm2, xmm0, 0
        pshufd xmm2, xmm2, 0xaa
        movdqa xmm3, xmm1
        pslldq xmm3, 4
        pxor xmm1, xmm3
        pslldq xmm3, 4
        pxor xmm1, xmm3
        pslldq xmm3, 4
        pxor xmm1, xmm3
        pxor xmm1, xmm2
        movdqu [rsi + \off + 16], xmm1
    .endif
.endm

.global l4h_aes256_expand
.type l4h_aes256_expand,@function
l4h_aes256_expand:
    movdqu xmm0, [rdi]
    movdqu xmm1, [rdi + 16]
    movdqu [rsi], xmm0
    movdqu [rsi + 16], xmm1
    expand_pair 1,32
    expand_pair 2,64
    expand_pair 4,96
    expand_pair 8,128
    expand_pair 16,160
    expand_pair 32,192
    expand_pair 64,224,1
    test rdx, rdx
    jz 2f
    movdqu xmm0, [rsi + 224]
    movdqu [rdx], xmm0
    mov eax, 16
1:
    mov ecx, 224
    sub rcx, rax
    movdqu xmm0, [rsi + rcx]
    aesimc xmm0, xmm0
    movdqu [rdx + rax], xmm0
    add eax, 16
    cmp eax, 224
    jne 1b
    movdqu xmm0, [rsi]
    movdqu [rdx + 224], xmm0
2:
    clear_vectors
    ret
.size l4h_aes256_expand, .-l4h_aes256_expand

// One complete 4 KiB unit. rdi=K1 schedule, rsi=K2 encryption schedule,
// rdx=source, rcx=destination, r8=unit. Eight blocks share each round-key
// load and their AES instructions are interleaved to hide round latency.
.macro xts name, round, last
.global \name
.type \name,@function
\name:
    sub rsp, 136
    movq xmm8, r8
    pxor xmm8, [rsi]
    .irp off,16,32,48,64,80,96,112,128,144,160,176,192,208
        aesenc xmm8, [rsi + \off]
    .endr
    aesenclast xmm8, [rsi + 224]
    movq r9, xmm8
    psrldq xmm8, 8
    movq r10, xmm8
    mov r8d, 32
1:
    // T *= x in GF(2^128), little endian, reduction polynomial 0x87.
    .irp n,0,1,2,3,4,5,6,7
        mov [rsp + 16*\n], r9
        mov [rsp + 16*\n + 8], r10
        mov r11, r10
        sar r11, 63
        and r11d, 0x87
        shld r10, r9, 1
        shl r9, 1
        xor r9, r11
        movdqu xmm\n, [rdx + 16*\n]
        pxor xmm\n, [rsp + 16*\n]
        pxor xmm\n, [rdi]
    .endr
    mov eax, 16
2:
    movdqu xmm15, [rdi + rax]
    .irp n,0,1,2,3,4,5,6,7
        \round xmm\n, xmm15
    .endr
    add eax, 16
    cmp eax, 224
    jne 2b
    movdqu xmm15, [rdi + 224]
    .irp n,0,1,2,3,4,5,6,7
        \last xmm\n, xmm15
        pxor xmm\n, [rsp + 16*\n]
        movdqu [rcx + 16*\n], xmm\n
    .endr
    add rdx, 128
    add rcx, 128
    dec r8d
    jne 1b
    clear_vectors
    .irp off,0,16,32,48,64,80,96,112
        movdqu [rsp + \off], xmm0
    .endr
    xor r9d, r9d
    xor r10d, r10d
    xor r11d, r11d
    add rsp, 136
    ret
.size \name, .-\name
.endm
xts l4h_xts_encrypt, aesenc, aesenclast
xts l4h_xts_decrypt, aesdec, aesdeclast
.section .note.GNU-stack,"",@progbits

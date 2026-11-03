//! The multiboot headers, the 32-bit entry into long mode, the way back
//! to 32-bit protected mode to enter a kernel, and the real-mode
//! trampoline a partition's first CPU starts in.

core::arch::global_asm!(
    r#"
    .section .multiboot, "a"
    .align 4
mb1_header:
    .long 0x1badb002
    /* page-aligned modules, memory information */
    .long 0x00000003
    .long 0x100000000 - (0x1badb002 + 3)

    .align 8
mb2_header:
    .long 0xe85250d6
    .long 0
    .long mb2_header_end - mb2_header
    .long 0x100000000 - (0xe85250d6 + (mb2_header_end - mb2_header))
    /* page-aligned modules */
    .short 6
    .short 0
    .long 8
    /* a linear framebuffer, if there is one (optional), for partition 0 */
    .short 5
    .short 1
    .long 20
    .long 1024
    .long 768
    .long 32
    .long 0
    .short 0
    .short 0
    .long 8
mb2_header_end:

    .section .text.entry, "ax"
    .code32
    .global _start
_start:
    cli
    cld
    mov %eax, %edi
    mov %ebx, %esi
    mov $boot_stack_top, %esp

    /* The first 4 GiB, identity mapped in 2 MiB pages, to get to 64-bit
     * code (shim_main builds the full map). */
    mov $boot_pd, %ebx
    xor %ecx, %ecx
1:
    mov %ecx, %eax
    shl $21, %eax
    or $0x83, %eax
    mov %eax, (%ebx,%ecx,8)
    movl $0, 4(%ebx,%ecx,8)
    inc %ecx
    cmp $2048, %ecx
    jne 1b

    mov $boot_pdpt, %edx
    mov $boot_pd + 3, %eax
    mov %eax, (%edx)
    add $4096, %eax
    mov %eax, 8(%edx)
    add $4096, %eax
    mov %eax, 16(%edx)
    add $4096, %eax
    mov %eax, 24(%edx)
    mov $boot_pml4, %edx
    mov $boot_pdpt + 3, %eax
    mov %eax, (%edx)
    mov %edx, %cr3

    mov %cr4, %eax
    or $0x20, %eax
    mov %eax, %cr4
    mov $0xc0000080, %ecx
    rdmsr
    or $0x100, %eax
    wrmsr
    mov %cr0, %eax
    or $0x80000001, %eax
    mov %eax, %cr0
    lgdt shim_gdt_ptr
    ljmp $0x08, $start64

    .code64
start64:
    mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss
    mov %ax, %fs
    mov %ax, %gs
    mov $boot_stack_top, %rsp
    /* The upper halves are undefined after the switch. */
    mov %edi, %edi
    mov %esi, %esi
    call shim_main
2:
    hlt
    jmp 2b

    /* enter_kernel(entry, mbi): leave long mode and jump to a multiboot2
     * kernel the way a boot loader does: 32-bit protected mode, paging
     * off, EAX the magic, EBX the information. */
    .global enter_kernel
enter_kernel:
    cli
    pushq $0x18
    mov $enter32, %rax
    pushq %rax
    lretq
    .code32
enter32:
    mov $0x20, %eax
    mov %eax, %ds
    mov %eax, %es
    mov %eax, %ss
    mov %eax, %fs
    mov %eax, %gs
    mov %cr0, %eax
    and $0x7fffffff, %eax
    mov %eax, %cr0
    mov $0xc0000080, %ecx
    rdmsr
    and $0xfffffeff, %eax
    wrmsr
    mov %cr4, %eax
    and $0xffffffdf, %eax
    mov %eax, %cr4
    mov %esi, %ebx
    mov $0x36d76289, %eax
    jmp *%edi

    /* A partition's first CPU, after INIT-SIPI-SIPI: from the page this
     * is copied to, into 32-bit protected mode and on to ap32. */
    .global ap_tramp_start
    .global ap_tramp_end
    .code16
ap_tramp_start:
    cli
    mov %cs, %ax
    mov %ax, %ds
    lgdtl (ap_gdt_ptr - ap_tramp_start)
    mov %cr0, %eax
    or $1, %eax
    mov %eax, %cr0
    ljmpl $0x18, $ap32
    .align 4
ap_gdt_ptr:
    .short shim_gdt_end - shim_gdt - 1
    .long shim_gdt
ap_tramp_end:

    .code32
ap32:
    mov $0x20, %eax
    mov %eax, %ds
    mov %eax, %es
    mov %eax, %ss
    mov %eax, %fs
    mov %eax, %gs
    mov ap_entry, %ecx
    mov ap_mbi, %ebx
    lock incl ap_ack
    mov $0x36d76289, %eax
    jmp *%ecx
    .code64

    .section .data
    .align 16
    .global shim_gdt
shim_gdt:
    .quad 0
    .quad 0x00af9a000000ffff
    .quad 0x00cf92000000ffff
    .quad 0x00cf9a000000ffff
    .quad 0x00cf92000000ffff
shim_gdt_end:
    .align 4
    .short 0
shim_gdt_ptr:
    .short shim_gdt_end - shim_gdt - 1
    .long shim_gdt
    .align 4
    .global ap_entry
    .global ap_mbi
    .global ap_ack
ap_entry:
    .long 0
ap_mbi:
    .long 0
ap_ack:
    .long 0

    .section .bss
    .align 4096
boot_pml4:
    .skip 4096
boot_pdpt:
    .skip 4096
boot_pd:
    .skip 16384
boot_stack:
    .skip 4194304
boot_stack_top:
    "#,
    options(att_syntax)
);

unsafe extern "C" {
    pub fn enter_kernel(entry: u64, mbi: u64) -> !;
    pub static ap_tramp_start: u8;
    pub static ap_tramp_end: u8;
    pub static mut ap_entry: u32;
    pub static mut ap_mbi: u32;
    pub static mut ap_ack: u32;
}

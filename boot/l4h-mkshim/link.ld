/* l4h-mkshim runs where the boot loader puts it: above every kernel slot
 * (1 MiB + 8 * 32 MiB, l4h_partition::SLOT_*), identity mapped. */
ENTRY(_start)
SECTIONS
{
    . = 0x11000000;
    __shim_start = .;
    .multiboot : { KEEP(*(.multiboot)) }
    .text : { *(.text.entry) *(.text .text.*) }
    .rodata : ALIGN(4096) { *(.rodata .rodata.*) }
    .data : ALIGN(4096) { *(.data .data.*) *(.got .got.*) }
    .bss : ALIGN(4096) { *(.bss .bss.*) *(COMMON) }
    . = ALIGN(4096);
    __shim_end = .;
    /DISCARD/ : { *(.eh_frame*) *(.comment) *(.note*) }
}

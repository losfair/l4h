ENTRY(_head)

SECTIONS
{
    . = 0;
    _image_start = .;

    .head : {
        KEEP(*(.head))
    }

    .text : ALIGN(4096) {
        *(.text.entry)
        *(.text .text.*)
    }

    .rodata : ALIGN(4096) {
        *(.rodata .rodata.*)
    }

    .rela.dyn : ALIGN(8) {
        __rela_start = .;
        *(.rela.dyn)
        *(.rela.*)
        __rela_end = .;
    }

    .data : ALIGN(4096) {
        *(.data.rel.ro .data.rel.ro.*)
        *(.got .got.*)
        *(.data .data.*)
    }

    .bss : ALIGN(4096) {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    }

    .stack : ALIGN(4096) {
        KEEP(*(.stack))
    }

    . = ALIGN(4096);
    _stub_end = .;

    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
        *(.dynamic)
        *(.dynsym)
        *(.dynstr)
        *(.hash)
        *(.gnu.hash)
        *(.interp)
    }
}

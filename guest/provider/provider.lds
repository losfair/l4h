/* SPDX-License-Identifier: GPL-2.0 */
ENTRY(l4h_provider_table)
PHDRS {
    code PT_LOAD FLAGS(5);
    tls PT_TLS FLAGS(4);
}
SECTIONS {
    . = 0x00007ff000010000;
    .provider : { KEEP(*(.provider)) } :code
    .text : { *(.text .text.*) } :code
    .rodata : { *(.rodata .rodata.*) } :code
    ASSERT(. <= 0x00007ff000100000, "provider overlaps vCPU area")
    .tbss 0 (NOLOAD) : { *(.tbss .tbss.*) } :tls
    ASSERT(SIZEOF(.tbss) <= 16, "provider TLS exceeds reserved area")
    ASSERT(ALIGNOF(.tbss) <= 16, "provider TLS alignment exceeds reserved area")
    .forbidden (NOLOAD) : {
        *(.data .data.* .bss .bss.* .sdata .sdata.* .sbss .sbss.* COMMON)
        *(.tdata .tdata.* .init_array .init_array.* .fini_array .fini_array.*)
    }
    ASSERT(SIZEOF(.forbidden) == 0, "provider must have no writable globals")
    /DISCARD/ : { *(.comment .note* .eh_frame*) }
}

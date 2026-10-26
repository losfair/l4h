/* SPDX-License-Identifier: GPL-2.0 */
#include <asm-generic/vmlinux.lds.h>

  .fini      : { *(.fini)    } =0x9090
  _etext = .;
  PROVIDE (etext = .);

  /*
   * Text and rodata fill whole pages of their segments, and rodata ends
   * at a RAM block (L4H_BLOCK_SIZE): the host shares only pages that a
   * read-only segment's file data covers, and saves memory only for
   * blocks of them.  Each pad starts with an empty section of contents
   * (physmem.c): of a section of padding alone ld makes writable memory
   * without file data.  A pad already aligned takes nothing.
   */
  .text.l4h_pad : { KEEP(*(.l4h.pad.text)) . = ALIGN(4096); } =0
  _sdata = .;
  PROVIDE (sdata = .);

  RO_DATA(4096)

  .rodata.l4h_pad : { KEEP(*(.l4h.pad.rodata)) . = ALIGN(L4H_LDS_BLOCK_SIZE); } =0

  .unprotected : { *(.unprotected) }
  . = ALIGN(4096);
  PROVIDE (_unprotected_end = .);

  . = ALIGN(4096);

  BUG_TABLE

  .uml.setup.init : {
	__uml_setup_start = .;
	*(.uml.setup.init)
	__uml_setup_end = .;
  }
	
  .uml.help.init : {
	__uml_help_start = .;
	*(.uml.help.init)
	__uml_help_end = .;
  }
	
  .uml.postsetup.init : {
	__uml_postsetup_start = .;
	*(.uml.postsetup.init)
	__uml_postsetup_end = .;
  }
	
  .init.setup : {
	INIT_SETUP(0)
  }

  PERCPU_SECTION(32)
	
  .initcall.init : {
	INIT_CALLS
  }

  .con_initcall.init : {
	CON_INITCALL
  }

  .exitcall : {
	__exitcall_begin = .;
	*(.exitcall.exit)
	__exitcall_end = .;
  }

  .uml.exitcall : {
	__uml_exitcall_begin = .;
	*(.uml.exitcall.exit)
	__uml_exitcall_end = .;
  }

  . = ALIGN(4);
  .altinstructions : {
	__alt_instructions = .;
	*(.altinstructions)
	__alt_instructions_end = .;
  }
  .altinstr_replacement : { *(.altinstr_replacement) }
  /* .exit.text is discard at runtime, not link time, to deal with references
     from .altinstructions and .eh_frame */
  .exit.text : { EXIT_TEXT }
  .exit.data : { *(.exit.data) }

  .preinit_array : {
	__preinit_array_start = .;
	*(.preinit_array)
	__preinit_array_end = .;
  }
  .init_array : {
	__init_array_start = .;
	*(.kasan_init)
	*(.init_array.*)
	*(.init_array)
	__init_array_end = .;
  }
  .fini_array : {
	__fini_array_start = .;
	*(.fini_array)
	__fini_array_end = .;
  }

   . = ALIGN(4096);
  .init.ramfs : {
	INIT_RAM_FS
  }


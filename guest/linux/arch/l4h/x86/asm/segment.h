/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __UM_SEGMENT_H
#define __UM_SEGMENT_H

extern int host_gdt_entry_tls_min;

#define GDT_ENTRY_TLS_ENTRIES 3
#define GDT_ENTRY_TLS_MIN host_gdt_entry_tls_min
#define GDT_ENTRY_TLS_MAX (GDT_ENTRY_TLS_MIN + GDT_ENTRY_TLS_ENTRIES - 1)

/*
 * The user selectors of the x86_64 Linux ABI, which ptrace and sigcontext
 * report (gdb takes CS 0x33 for a 64-bit inferior).  The guest kernel loads
 * none: seL4 does, and its patch 0028 lays out its user segments as Linux
 * does, so these are what user code reading %cs or %ss sees, and what it
 * may reload with iretq.
 */
#define __USER_CS 0x33
#define __USER_DS 0x2b

/*
 * For arch/x86 headers that the BPF JIT includes (nospec-branch.h); the
 * guest kernel loads no selectors.
 */
#define __KERNEL_DS 0

#endif

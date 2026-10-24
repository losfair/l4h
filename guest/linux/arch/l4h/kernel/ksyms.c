// SPDX-License-Identifier: GPL-2.0
/*
 * Symbols of arch/l4h/os-sel4, which is built without kernel headers, for
 * modules that use the l4h ABI and seL4 directly (tests/guest/abitest).
 */
#include <linux/export.h>
#include <asm/processor.h>
#include <os.h>
#include <l4h_sys.h>

EXPORT_SYMBOL_GPL(l4h_bootinfo);
EXPORT_SYMBOL_GPL(l4h_vcpus);
EXPORT_SYMBOL_GPL(l4h_user_deschedule);
EXPORT_SYMBOL_GPL(l4h_timer_arm);
/* Interrupt masking (asm/irqflags.h), which any module may use. */
EXPORT_SYMBOL(um_set_signals);
EXPORT_SYMBOL(um_set_signals_trace);
/* cpu_relax() (asm/processor.h), which any module may use. */
EXPORT_SYMBOL(l4h_poll_events);

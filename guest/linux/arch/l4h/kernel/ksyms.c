// SPDX-License-Identifier: GPL-2.0
/*
 * Symbols of arch/l4h/os-sel4, which is built without kernel headers, for
 * modules that use the l4h ABI and seL4 directly (tests/guest/abitest).
 */
#include <linux/export.h>
#include <asm/cacheflush.h>
#include <asm/processor.h>
#include <os.h>
#include <l4h_sys.h>

EXPORT_SYMBOL_GPL(l4h_bootinfo);
EXPORT_SYMBOL_GPL(l4h_vcpus);
EXPORT_SYMBOL_GPL(l4h_user_deschedule);
EXPORT_SYMBOL_GPL(l4h_timer_arm);
/* Kicks and device writes of host-device drivers (usb-l4h). */
EXPORT_SYMBOL_GPL(l4h_signal);
EXPORT_SYMBOL_GPL(l4h_hypercall);
/* The host kernel's configuration (L4H_PROVIDER_KERNEL_CONFIG). */
EXPORT_SYMBOL_GPL(l4h_kernel_config);
/* Interrupt masking (asm/irqflags.h), which any module may use. */
EXPORT_SYMBOL(um_set_signals);
EXPORT_SYMBOL(um_set_signals_trace);
/* cpu_relax() (asm/processor.h), which any module may use. */
EXPORT_SYMBOL(l4h_poll_events);
/*
 * The provider's generic seL4 operations, for modules that run user code of
 * their own beside Linux's (struct l4h_uctx): its address spaces, threads,
 * capabilities and registers.  Their capability arguments are CPtrs in the
 * guest's CSpace.
 */
EXPORT_SYMBOL_GPL(l4h_provider_features);
EXPORT_SYMBOL_GPL(l4h_this_vcpu_id);
EXPORT_SYMBOL_GPL(l4h_cnode_copy);
EXPORT_SYMBOL_GPL(l4h_cnode_mint);
EXPORT_SYMBOL_GPL(l4h_cnode_delete);
EXPORT_SYMBOL_GPL(l4h_pt_map);
EXPORT_SYMBOL_GPL(l4h_page_map);
EXPORT_SYMBOL_GPL(l4h_page_unmap);
EXPORT_SYMBOL_GPL(l4h_vspace_flush);
EXPORT_SYMBOL_GPL(l4h_tcb_configure_user);
EXPORT_SYMBOL_GPL(l4h_tcb_set_space);
EXPORT_SYMBOL_GPL(l4h_tcb_set_flags);
EXPORT_SYMBOL_GPL(l4h_tcb_suspend);
EXPORT_SYMBOL_GPL(l4h_tcb_resume);
EXPORT_SYMBOL_GPL(l4h_tcb_set_pac);
EXPORT_SYMBOL_GPL(l4h_tcb_set_high_vspace);
EXPORT_SYMBOL_GPL(l4h_user_run);
EXPORT_SYMBOL_GPL(l4h_user_run_ex);
EXPORT_SYMBOL_GPL(l4h_user_sync_regs);
EXPORT_SYMBOL_GPL(l4h_user_sync_seg);
EXPORT_SYMBOL_GPL(l4h_user_mark_dirty);
EXPORT_SYMBOL_GPL(l4h_fpu_read);
EXPORT_SYMBOL_GPL(l4h_fpu_write);
EXPORT_SYMBOL_GPL(l4h_fpu_state_size);
EXPORT_SYMBOL_GPL(l4h_flush_icache);

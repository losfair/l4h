/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Host-layer interface of the l4h guest kernel.
 *
 * In UML this header described the host Linux system; in l4h the "host" is
 * seL4 and most of the interface is in l4h_sys.h.  What remains here are
 * the UML-named entry points that the (mostly unchanged) generic UML code
 * calls, now implemented in arch/l4h/kernel and arch/l4h/os-sel4.
 */
#ifndef __OS_H__
#define __OS_H__

#include <irq_user.h>
#include <longjmp.h>
#include <mm_id.h>
#include <linux/types.h>
#include <l4h_sys.h>

#define OS_LIB_PATH	"/usr/lib64/"

/* interrupt masking (os-sel4/events.c) */
extern int um_set_signals(int enable);
extern int um_set_signals_trace(int enable);
extern void block_signals(void);
extern void unblock_signals(void);
extern void block_signals_trace(void);
extern void unblock_signals_trace(void);
extern void block_signals_hard(void);
extern void unblock_signals_hard(void);

/* threads (kernel/uctx.c) */
extern void userspace(struct uml_pt_regs *regs);
extern void new_thread(void *stack, jmp_buf *buf, void (*handler)(void));
extern void switch_threads(jmp_buf *me, jmp_buf *you);
extern int start_idle_thread(void *stack, jmp_buf *switch_buf);
extern void initial_thread_cb_skas(void (*proc)(void *), void *arg);
extern void halt_skas(void);
extern void reboot_skas(void);

/* memory (kernel/vspace.c) */
extern int os_map_memory(void *virt, unsigned long phys, unsigned long len, int r, int w, int x);
extern int os_protect_memory(void *addr, unsigned long len, int r, int w, int x);
extern int os_unmap_memory(void *addr, int len);
int map(struct mm_id *mm_idp, unsigned long virt, unsigned long len, int prot,
	unsigned long phys);
int unmap(struct mm_id *mm_idp, unsigned long addr, unsigned long len);
void unmap_large(struct mm_id *mm_idp, unsigned long addr);

/* time (kernel/time.c) */
extern long long os_nsecs(void);
extern long long os_persistent_clock_emulation(void);
extern void os_idle_sleep(void);

/* misc (kernel/um_arch.c) */
extern void os_info(const char *fmt, ...)
	__attribute__ ((format (printf, 1, 2)));
extern void os_warn(const char *fmt, ...)
	__attribute__ ((format (printf, 1, 2)));
extern void os_dump_core(void) __attribute__ ((noreturn));
extern void um_early_printk(const char *s, unsigned int n);
extern ssize_t os_getrandom(void *buf, size_t len, unsigned int flags);
extern void setup_machinename(char *machine_out);
extern void setup_hostinfo(char *buf, int len);
extern void os_early_checks(void);
extern void os_check_bugs(void);
extern void get_host_cpu_features(void (*flags_helper_func)(char *line),
				  void (*cache_helper_func)(char *line));

#endif

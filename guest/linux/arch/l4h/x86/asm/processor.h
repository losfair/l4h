/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __UM_PROCESSOR_H
#define __UM_PROCESSOR_H
#include <linux/time-internal.h>

/* include faultinfo structure */
#include <sysdep/faultinfo.h>

# include "processor_64.h"

/* The user IP, as on x86 (seccomp, SIGSYS); KSTK_ESP is the kernel's, for
 * stack walks. */
#define KSTK_EIP(tsk) PT_REGS_IP(task_pt_regs(tsk))
#define KSTK_ESP(tsk) KSTK_REG(tsk, HOST_SP)
#define KSTK_EBP(tsk) KSTK_REG(tsk, HOST_BP)

#define ARCH_IS_STACKGROW(address) \
       (address + 65536 + 32 * sizeof(unsigned long) >= UPT_SP(&current->thread.regs.regs))

#include <asm/user.h>

/* PAUSE is a good thing to insert into busy-wait loops. */
static __always_inline void native_pause(void)
{
	__asm__ __volatile__("pause": : :"memory");
}

/* arch/l4h/os-sel4/events.c: deliver pending events if interrupts are on. */
void l4h_poll_events(void);

/*
 * A vCPU sees interrupts only where it polls for them.  Spinning with
 * interrupts on must poll, as a CPU would take them: two vCPUs in
 * csd_lock_wait() for each other's smp_call_function() (or one waiting for
 * a lock that the other holds while it waits so) would wait for good.
 */
static __always_inline void cpu_relax(void)
{
	if (time_travel_mode == TT_MODE_INFCPU ||
	    time_travel_mode == TT_MODE_EXTERNAL)
		time_travel_ndelay(1);
	else
		native_pause();
	l4h_poll_events();
}

#define task_pt_regs(t) (&(t)->thread.regs)

#include <asm/processor-generic.h>

#endif

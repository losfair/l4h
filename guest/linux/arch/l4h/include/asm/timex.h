/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __UM_TIMEX_H
#define __UM_TIMEX_H

#define CLOCK_TICK_RATE (HZ)

#ifdef CONFIG_UML_ARM64
static inline unsigned long get_cycles(void)
{
	unsigned long val;
	asm volatile("isb; mrs %0, cntvct_el0" : "=r"(val));
	return val;
}
#define get_cycles get_cycles
#endif

#include <asm-generic/timex.h>

#endif

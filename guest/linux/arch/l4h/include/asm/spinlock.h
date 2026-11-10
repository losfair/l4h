/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __L4H_SPINLOCK_H
#define __L4H_SPINLOCK_H

/*
 * How long a paravirtual spinlock's waiter spins before it blocks its vCPU
 * (asm/qspinlock.h), in cpu_relax() iterations.  x86's 1 << 15 was about
 * 100 us of 10-cycle PAUSEs.  An iteration here is a PAUSE of some 40 to
 * 140 cycles, or an arm64 YIELD, and the event poll, with a read of the
 * time counter when interrupts are on: 1 << 11 spins about as long, well
 * beyond a critical section and the cost of blocking (two seL4 calls and
 * an IPI), and well short of the 5 ms a preempted vCPU can stay away.
 */
#define SPIN_THRESHOLD	(1 << 11)

#include <asm/qspinlock.h>
#include <asm/qrwlock.h>

#endif

/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __L4H_SPINLOCK_H
#define __L4H_SPINLOCK_H

/*
 * How long a paravirtual spinlock's waiter spins before it blocks its vCPU
 * (asm/qspinlock.h): about L4H_SPIN_US, beyond a critical section and the
 * cost of blocking (two seL4 calls and an IPI, all under FL4's serial
 * gate), and well short of the 5 ms a preempted vCPU can stay away.  It is
 * bounded by time (kernel/locking/qspinlock_paravirt.h's pv_spin_start()
 * and pv_spin_over(), patch 0022; the time counter, as udelay() and the
 * provider's timer use it), not by a count of cpu_relax() iterations: what one costs
 * depends on the CPU, a PAUSE of some 40 to 140 cycles on x86 or a YIELD
 * of a few on arm64.  The 1 << 11 iterations this replaces were meant as
 * 100 us on x86 and lasted a few microseconds on Axion: from 16 vCPUs
 * faulting at once (smpbench fault_4k on a c4a-standard-64), the waiters
 * for a lock held a fraction of a microsecond blocked, and every handoff
 * waited for a seL4_Signal, a reschedule IPI and a wakeup.  A spin that a
 * preemption interrupts has used its time when it resumes, and blocks.
 *
 * SPIN_THRESHOLD only bounds the iterations, should the counter not move.
 */
#define L4H_SPIN_US	100
#define SPIN_THRESHOLD	(1 << 22)

/* kernel/smp.c */
unsigned long long l4h_spin_start(void);
int l4h_spin_over(unsigned long long start, unsigned int us);
#define pv_spin_start()		l4h_spin_start()
#define pv_spin_over(start)	l4h_spin_over(start, L4H_SPIN_US)

#include <asm/qspinlock.h>
#include <asm/qrwlock.h>

#endif

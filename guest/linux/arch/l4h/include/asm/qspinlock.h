/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __L4H_QSPINLOCK_H
#define __L4H_QSPINLOCK_H

#include <linux/jump_label.h>
#include <linux/atomic.h>
#include <asm-generic/qspinlock_types.h>

#ifdef CONFIG_PARAVIRT_SPINLOCKS
/*
 * Paravirtual queued spinlocks (kernel/locking/qspinlock_paravirt.h): a
 * waiter that has spun for SPIN_THRESHOLD iterations blocks its vCPU
 * instead, and the unlock wakes it.  Spinning on is wasted when the lock's
 * holder, or the waiter ahead in the queue, is not running: its vCPU lost
 * the core to another thread, or ran out of budget under a CPU cap.
 *
 * The unlock is then a compare-and-exchange instead of a store, which a
 * guest that cannot be preempted that way should not pay.  There is no
 * code patching here, so a static key chooses: it is off with one vCPU
 * and with "nopvspin" (l4h_pv_spinlock_init()).
 */
void native_queued_spin_lock_slowpath(struct qspinlock *lock, u32 val);
void __pv_init_lock_hash(void);
void __pv_queued_spin_lock_slowpath(struct qspinlock *lock, u32 val);
void __pv_queued_spin_unlock(struct qspinlock *lock);
extern bool nopvspin;

DECLARE_STATIC_KEY_FALSE(l4h_pv_spinlocks);

/* arch/l4h/os-sel4/events.c */
void l4h_pv_wait(const unsigned char *ptr, unsigned char val);
void l4h_pv_kick(int cpu);

/* Block this vCPU while *ptr == val, until pv_kick() or any event. */
static __always_inline void pv_wait(u8 *ptr, u8 val)
{
	l4h_pv_wait(ptr, val);
}

static __always_inline void pv_kick(int cpu)
{
	l4h_pv_kick(cpu);
}

static __always_inline void queued_spin_lock_slowpath(struct qspinlock *lock, u32 val)
{
	if (static_branch_unlikely(&l4h_pv_spinlocks))
		__pv_queued_spin_lock_slowpath(lock, val);
	else
		native_queued_spin_lock_slowpath(lock, val);
}

#define queued_spin_unlock queued_spin_unlock
static __always_inline void queued_spin_unlock(struct qspinlock *lock)
{
	if (static_branch_unlikely(&l4h_pv_spinlocks))
		__pv_queued_spin_unlock(lock);
	else
		smp_store_release(&lock->locked, 0);
}
#endif /* CONFIG_PARAVIRT_SPINLOCKS */

#include <asm-generic/qspinlock.h>

#endif

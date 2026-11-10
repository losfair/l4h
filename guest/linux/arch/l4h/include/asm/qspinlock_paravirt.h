/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __L4H_QSPINLOCK_PARAVIRT_H
#define __L4H_QSPINLOCK_PARAVIRT_H

/*
 * kernel/locking/qspinlock_paravirt.h includes this for an architecture's
 * own __pv_queued_spin_unlock().  We use the generic one.
 */
void __lockfunc __pv_queued_spin_unlock_slowpath(struct qspinlock *lock, u8 locked);

#endif

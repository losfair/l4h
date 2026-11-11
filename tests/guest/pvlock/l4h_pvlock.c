// SPDX-License-Identifier: GPL-2.0
/*
 * Test-only spinlock contention, loaded by tests/run-pvlocktest.sh.
 *
 * One thread per vCPU takes four locks in turn, and now and then holds one
 * for much longer than a waiter spins, so that with paravirtual spinlocks
 * (arch/l4h/include/asm/qspinlock.h) the waiters block and are woken:
 *   - a spinlock taken with interrupts on;
 *   - one taken with interrupts off, whose waiters must block although
 *     they cannot take the events that arrive meanwhile;
 *   - one that timers take too, in softirq context;
 *   - a rwlock, whose writers queue on a spinlock.
 * Each lock guards a counter that is read, then written back incremented:
 * two vCPUs inside at once lose an increment, and leave their mark in
 * `owner`.  Loading fails unless every increment is there.
 *
 * Two kinds of waiter are counted when they blocked, from their vCPU's
 * own count of waits, which nothing else can raise meanwhile: those with
 * interrupts off, and timers run from an event's delivery, which block
 * with events pending.  And the holder of the first lock,
 * during a long hold, calls a function on every other vCPU and waits for
 * it: a vCPU blocked for that lock with interrupts on must take the IPI,
 * or the test never ends.
 */
#include <linux/atomic.h>
#include <linux/cpumask.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <l4h_sys.h>

static unsigned int secs = 3;
module_param(secs, uint, 0444);
/* A long hold.  Waiters spin for some 100 us before they block, and for
 * longer on an emulated CPU. */
static unsigned int hold_us = 5000;
module_param(hold_us, uint, 0444);

struct guarded {
	unsigned long count;
	int owner;
};

static DEFINE_SPINLOCK(plain_lock);
static DEFINE_SPINLOCK(irq_lock);
static DEFINE_SPINLOCK(bh_lock);
static DEFINE_RWLOCK(rw_lock);
static struct guarded plain, irq, bh, rw;
static atomic_long_t violations;
static atomic_long_t timer_done;
static atomic_long_t timer_blocked;
static atomic_long_t ipis;

struct worker {
	struct task_struct *task;
	struct timer_list timer;
	unsigned long done[4];
	unsigned long irqoff_blocked;
};
static DEFINE_PER_CPU(struct worker, workers);

/* How often this vCPU has waited in seL4 for a spinlock (the PVW row of
 * /proc/interrupts).  Only the vCPU itself counts. */
static unsigned long my_waits(void)
{
	return READ_ONCE(l4h_vcpus[raw_smp_processor_id()].pv_waits);
}

static void pvlock_ipi(void *arg)
{
	atomic_long_inc(&ipis);
}

/* The critical section.  Called with g's lock held. */
static void enter(struct guarded *g, bool hold, bool ipi)
{
	unsigned long n;
	int cpu;

	if (READ_ONCE(g->owner))
		atomic_long_inc(&violations);
	WRITE_ONCE(g->owner, 1 + raw_smp_processor_id());
	n = READ_ONCE(g->count);
	if (hold)
		udelay(hold_us);
	/* By now the lock's waiters have blocked. */
	if (ipi)
		for_each_online_cpu(cpu)
			if (cpu != raw_smp_processor_id())
				smp_call_function_single(cpu, pvlock_ipi, NULL, 1);
	WRITE_ONCE(g->count, n + 1);
	WRITE_ONCE(g->owner, 0);
}

static void pvlock_timer(struct timer_list *t)
{
	/* Run from an event's delivery (in_irq), a timer takes no further
	 * event: a wait is this lock's, and blocks whatever is pending. */
	struct l4h_vcpu *v = &l4h_vcpus[raw_smp_processor_id()];
	unsigned long waits = READ_ONCE(v->pv_waits);

	spin_lock(&bh_lock);
	if (v->in_irq && READ_ONCE(v->pv_waits) != waits)
		atomic_long_inc(&timer_blocked);
	enter(&bh, false, false);
	spin_unlock(&bh_lock);
	atomic_long_inc(&timer_done);
	mod_timer(t, jiffies + 1);
}

static int pvlock_thread(void *arg)
{
	struct worker *w = arg;
	unsigned long flags, waits, i = 0;

	while (!kthread_should_stop()) {
		/* The long holds fall on different iterations of each
		 * thread, and on a different lock each time. */
		unsigned int slow = (i + 16 * raw_smp_processor_id()) % 64;

		if (i % 8 == 7) {
			if (spin_trylock(&plain_lock)) {
				enter(&plain, false, false);
				spin_unlock(&plain_lock);
				w->done[0]++;
			}
		} else {
			spin_lock(&plain_lock);
			enter(&plain, slow == 0, slow == 0);
			spin_unlock(&plain_lock);
			w->done[0]++;
		}

		local_irq_save(flags);
		waits = my_waits();
		spin_lock(&irq_lock);
		if (my_waits() != waits)
			w->irqoff_blocked++;
		enter(&irq, slow == 1, false);
		spin_unlock_irqrestore(&irq_lock, flags);
		w->done[1]++;

		spin_lock_bh(&bh_lock);
		enter(&bh, slow == 2, false);
		spin_unlock_bh(&bh_lock);
		w->done[2]++;

		if (i % 4) {
			read_lock(&rw_lock);
			if (READ_ONCE(rw.owner))
				atomic_long_inc(&violations);
			read_unlock(&rw_lock);
		} else {
			write_lock(&rw_lock);
			enter(&rw, slow == 4, false);
			write_unlock(&rw_lock);
			w->done[3]++;
		}
		i++;
		cond_resched();
	}
	return 0;
}

static int __init pvlock_init(void)
{
	unsigned long done[4] = {}, irqoff_blocked = 0;
	unsigned int cpu, k, threads = 0;
	long bad;
	int err = 0;

	for_each_online_cpu(cpu) {
		struct worker *w = &per_cpu(workers, cpu);

		w->task = kthread_create(pvlock_thread, w, "pvlock/%u", cpu);
		if (IS_ERR(w->task)) {
			err = PTR_ERR(w->task);
			w->task = NULL;
			break;
		}
		kthread_bind(w->task, cpu);
		timer_setup(&w->timer, pvlock_timer, TIMER_PINNED);
		w->timer.expires = jiffies + 1;
		add_timer_on(&w->timer, cpu);
		wake_up_process(w->task);
		threads++;
	}
	if (!err)
		msleep(secs * 1000);
	for_each_online_cpu(cpu) {
		struct worker *w = &per_cpu(workers, cpu);

		if (!w->task)
			continue;
		kthread_stop(w->task);
		timer_shutdown_sync(&w->timer);
		for (k = 0; k < 4; k++)
			done[k] += w->done[k];
		irqoff_blocked += w->irqoff_blocked;
	}
	if (err)
		return err;

	done[2] += atomic_long_read(&timer_done);
	bad = atomic_long_read(&violations);
	if (plain.count != done[0] || irq.count != done[1] || bh.count != done[2] ||
	    rw.count != done[3])
		bad++;
	pr_info("PVLOCK: %s threads=%u plain=%lu/%lu irq=%lu/%lu bh=%lu/%lu rw=%lu/%lu violations=%ld ipis=%ld irqoff_blocked=%lu timer_blocked=%ld\n",
		bad ? "FAIL" : "PASS", threads, plain.count, done[0], irq.count, done[1],
		bh.count, done[2], rw.count, done[3], atomic_long_read(&violations),
		atomic_long_read(&ipis), irqoff_blocked, atomic_long_read(&timer_blocked));
	return bad ? -EIO : 0;
}

static void __exit pvlock_exit(void)
{
}

module_init(pvlock_init);
module_exit(pvlock_exit);
MODULE_DESCRIPTION("l4h spinlock contention test");
MODULE_LICENSE("GPL");

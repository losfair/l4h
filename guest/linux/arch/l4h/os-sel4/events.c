// SPDX-License-Identifier: GPL-2.0
/*
 * Interrupt emulation for the l4h guest kernel.
 *
 * "Interrupts" are events signalled to the vCPU's bound notification:
 *   - the E3 deadline timer (badge L4H_BADGE_TIMER),
 *   - IPIs from other vCPUs (L4H_BADGE_IPI, reasons in vcpu->ipi_pending),
 *   - device events from l4h-vmm (L4H_BADGE_EVENT, bits in the event page).
 * They are delivered when the vCPU blocks (in user execution or idle) or,
 * while running kernel code, at the points where interrupts are re-enabled.
 * Detection there is a few memory reads; only real events cost a syscall.
 */
#include "l4h_os.h"

unsigned long long l4h_rdtsc(void)
{
#ifdef __aarch64__
	unsigned long ticks;
	__asm__ volatile("mrs %0, cntvct_el0" : "=r"(ticks));
	return ticks;
#else
	uint32_t lo, hi;

	__asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
	return ((unsigned long long)hi << 32) | lo;
#endif
}

void l4h_timer_arm(unsigned long long deadline)
{
	struct l4h_vcpu *v = l4h_this_vcpu();

	v->timer_deadline = deadline;
	seL4_TCB_SetTimer(v->ktcb, deadline, L4H_BADGE_TIMER);
}

static int evt_any(struct l4h_vcpu *v)
{
	unsigned int i;

	for (i = 0; i < L4H_NR_EVENTS / 64; i++)
		if (__atomic_load_n(&v->evt->pending[i], __ATOMIC_RELAXED))
			return 1;
	return 0;
}

/* Cheap check used on every interrupt-enable. */
int l4h_events_pending(void)
{
	struct l4h_vcpu *v = l4h_this_vcpu();
	unsigned long long dl = v->timer_deadline;

	return v->ipi_pending || v->ntfn_pending || (dl && l4h_rdtsc() >= dl) || evt_any(v);
}

int l4h_collect_events(int *timer, unsigned long *ipi, unsigned long *events)
{
	struct l4h_vcpu *v = l4h_this_vcpu();
	unsigned long long dl;
	unsigned long word;
	unsigned int i;
	int any = 0;

	/* Drain the notification word so that the next blocking call does not
	 * wake up for events we are handling now. */
	word = __atomic_exchange_n(&v->ntfn_pending, 0, __ATOMIC_ACQ_REL);
	if (!word) {
		seL4_Word badge = 0;

		seL4_Poll(v->ntfn, &badge);
		word = badge;
	}

	*timer = 0;
	dl = v->timer_deadline;
	/* seL4 signals a timer once, when its deadline has passed on the core
	 * holding it; a vCPU that migrated may read a TSC slightly behind
	 * that core's.  So the badge counts as the expiry: the clockevent
	 * handler copes with being early and re-arms. */
	if (dl && ((word & L4H_BADGE_TIMER) || l4h_rdtsc() >= dl)) {
		v->timer_deadline = 0;
		*timer = 1;
		any = 1;
	}
	*ipi = __atomic_exchange_n(&v->ipi_pending, 0, __ATOMIC_ACQ_REL);
	if (*ipi)
		any = 1;
	for (i = 0; i < L4H_NR_EVENTS / 64; i++) {
		events[i] = __atomic_exchange_n(&v->evt->pending[i], 0, __ATOMIC_ACQ_REL);
		if (events[i])
			any = 1;
	}
	return any;
}

void l4h_idle_wait(void)
{
	struct l4h_vcpu *v = l4h_this_vcpu();
	seL4_Word badge = 0;

	if (l4h_events_pending())
		return;
	/* A signal sent between the check above and the wait leaves the
	 * notification active, so the wait returns immediately: no lost
	 * wakeups. */
	unsigned long long t0 = l4h_rdtsc();
	seL4_Wait(v->ntfn, &badge);
	/* Published for the host's steal-time estimate (only we write it). */
	__atomic_store_n(&v->evt->idle_ticks, v->evt->idle_ticks + (l4h_rdtsc() - t0), __ATOMIC_RELAXED);
	__atomic_or_fetch(&v->ntfn_pending, badge, __ATOMIC_RELEASE);
}

/*
 * Block for about 100 us, or until an event arrives, without consuming
 * CPU.  The kernel's own timer deadline is kept: it ends the wait too.
 */
void l4h_wait_briefly(void)
{
	struct l4h_vcpu *v = l4h_this_vcpu();
	unsigned long long now = l4h_rdtsc(), saved = v->timer_deadline;
	unsigned long long dl = now + l4h_tsc_hz / 10000;
	seL4_Word badge = 0;
	int due = saved && saved <= now;

	/* A deadline already past is an expiry the caller's events take.
	 * Arming it would end this wait, and every one after it, at once:
	 * bind_sc() then spun until SC_U's budget came back. */
	if (due)
		__atomic_or_fetch(&v->ntfn_pending, L4H_BADGE_TIMER, __ATOMIC_RELEASE);
	else if (saved && saved < dl)
		dl = saved;
	seL4_TCB_SetTimer(v->ktcb, dl, L4H_BADGE_TIMER);
	seL4_Wait(v->ntfn, &badge);
	/* A timer badge is the short wait's own, not the kernel's expiry:
	 * re-arming `saved` below signals again if that is due. */
	if (dl != saved)
		badge &= ~L4H_BADGE_TIMER;
	__atomic_or_fetch(&v->ntfn_pending, badge, __ATOMIC_RELEASE);
	if (!due)
		seL4_TCB_SetTimer(v->ktcb, saved, L4H_BADGE_TIMER);
}

/* Steal time of vCPU `cpu` in ns, as published by the host. */
unsigned long long l4h_steal_ns(int cpu)
{
	return __atomic_load_n(&l4h_vcpus[cpu].evt->steal_ns, __ATOMIC_RELAXED);
}

void l4h_send_ipi(int cpu, unsigned long reasons)
{
	struct l4h_vcpu *t = &l4h_vcpus[cpu];

	__atomic_or_fetch(&t->ipi_pending, reasons, __ATOMIC_RELEASE);
	seL4_Signal(L4H_CPTR(L4H_SLOT_VCPU(cpu) + L4H_VCPU_IPI));
}

/* ---- interrupt masking ("signals" in UML terms) */

void l4h_dispatch_pending(void);

int um_set_signals(int enable)
{
	struct l4h_vcpu *v = l4h_this_vcpu();
	int old = v->irqs_enabled;

	if (old == enable)
		return old;
	if (!enable) {
		v->irqs_enabled = 0;
		return old;
	}
	v->irqs_enabled = 1;
	if (!v->in_irq && l4h_events_pending())
		l4h_dispatch_pending();
	return old;
}

int um_set_signals_trace(int enable)
{
	return um_set_signals(enable);
}

void block_signals(void)
{
	l4h_this_vcpu()->irqs_enabled = 0;
}

void unblock_signals(void)
{
	um_set_signals(1);
}

int l4h_irqs_enabled(void)
{
	return l4h_this_vcpu()->irqs_enabled;
}

/* Deliver pending events now.  Called with interrupts enabled from
 * um_set_signals, or explicitly from the user loop and idle. */
void l4h_dispatch_pending(void)
{
	struct l4h_vcpu *v = l4h_this_vcpu();
	unsigned long events[L4H_NR_EVENTS / 64];
	unsigned long ipi;
	int timer;

	if (v->in_irq)
		return;
	v->in_irq = 1;
	while (l4h_collect_events(&timer, &ipi, events)) {
		v->irqs_enabled = 0;
		l4h_deliver_events(timer, ipi, events);
		v->irqs_enabled = 1;
	}
	v->in_irq = 0;
}

/* Deliver pending events if interrupts are enabled, as re-enabling them
 * would.  Called from cond_resched(), whose callers may loop waiting for
 * another task without ever re-enabling interrupts. */
void l4h_poll_events(void)
{
	struct l4h_vcpu *v = l4h_this_vcpu();

	if (v->irqs_enabled && !v->in_irq && l4h_events_pending())
		l4h_dispatch_pending();
}

/*
 * Paravirtual spinlocks (asm/qspinlock.h): block this vCPU while
 * *ptr == val.  The vCPU that changes *ptr kicks us afterwards, at once or
 * when it unlocks, and a kick sent between the check and the wait leaves
 * the notification active, so the wait returns at once.  Every other event
 * ends the wait as well; the caller looks at the lock again.
 */
void l4h_pv_wait(const unsigned char *ptr, unsigned char val)
{
	struct l4h_vcpu *v = l4h_this_vcpu();
	unsigned long long t0;
	seL4_Word badge = 0;

	/* With interrupts on, an event already here is delivered first, as
	 * the waiter's cpu_relax() did while it spun (and, like it, not
	 * inside an event's own delivery, softirqs included). */
	if (v->irqs_enabled && !v->in_irq && l4h_events_pending()) {
		l4h_dispatch_pending();
		return;
	}
	/* With interrupts off, events already collected stay pending, as on
	 * a CPU, and do not keep us from blocking: l4h_events_pending() is
	 * not asked.  A new one still ends the wait, and stays pending. */
	if (__atomic_load_n(ptr, __ATOMIC_RELAXED) != val)
		return;
	/* Shown in /proc/interrupts; only we write it.  It counts the
	 * waits, also one that a signal already there ends at once. */
	__atomic_store_n(&v->pv_waits, v->pv_waits + 1, __ATOMIC_RELAXED);
	t0 = l4h_rdtsc();
	seL4_Wait(v->ntfn, &badge);
	/* Blocked, not runnable: not steal time (see l4h_idle_wait()). */
	__atomic_store_n(&v->evt->idle_ticks, v->evt->idle_ticks + (l4h_rdtsc() - t0), __ATOMIC_RELAXED);
	__atomic_or_fetch(&v->ntfn_pending, badge, __ATOMIC_RELEASE);
	l4h_poll_events();
}

/* Wake vCPU `cpu` from l4h_pv_wait(): an IPI without a reason.  A vCPU no
 * longer waiting runs no handler for it, but it ends one user run, VM
 * entry or idle wait like any other event. */
void l4h_pv_kick(int cpu)
{
	seL4_Signal(L4H_CPTR(L4H_SLOT_VCPU(cpu) + L4H_VCPU_IPI));
}

// SPDX-License-Identifier: GPL-2.0
/*
 * Time keeping of the l4h guest.
 *
 * Clock source: the TSC, read directly (it is invariant and synchronised
 * on the hosts l4h targets; seL4 reports its frequency).
 * Clock event: one per vCPU, a one-shot TSC deadline armed with the seL4
 * TCB deadline timer (l4h extension E3), which signals the vCPU.
 */

#include <linux/jump_label.h>
#include <asm/paravirt.h>
#include <linux/clockchips.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/jiffies.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/threads.h>
#include <linux/sched/clock.h>
#include <linux/sched/idle.h>
#include <linux/sched_clock.h>
#include <linux/percpu.h>
#include <linux/delay.h>
#include <asm/irq.h>
#include <asm/param.h>
#include <kern_util.h>
#include <os.h>
#include <l4h_sys.h>

static u32 tsc_to_ns_mult;
static u32 tsc_to_ns_shift;

long long os_nsecs(void)
{
	return mul_u64_u32_shr(l4h_rdtsc(), tsc_to_ns_mult, tsc_to_ns_shift);
}

unsigned long long l4h_ticks_to_ns(unsigned long long ticks)
{
	return mul_u64_u32_shr(ticks, tsc_to_ns_mult, tsc_to_ns_shift);
}

long long os_persistent_clock_emulation(void)
{
	unsigned long mr = 0;

	return l4h_hypercall(L4H_HC_GET_TIME, &mr, 0, 1);
}

void read_persistent_clock64(struct timespec64 *ts)
{
	long long nsecs = os_persistent_clock_emulation();

	set_normalized_timespec64(ts, nsecs / NSEC_PER_SEC, nsecs % NSEC_PER_SEC);
}

/* ---- clocksource */

static u64 l4h_tsc_read(struct clocksource *cs)
{
	return l4h_rdtsc();
}

static struct clocksource l4h_tsc_clocksource = {
	.name		= "l4h-tsc",
	.rating		= 400,
	.read		= l4h_tsc_read,
	.mask		= CLOCKSOURCE_MASK(64),
	.flags		= CLOCK_SOURCE_IS_CONTINUOUS | CLOCK_SOURCE_VALID_FOR_HRES,
#ifdef CONFIG_GENERIC_GETTIMEOFDAY
	/* User code reads the same counter: the vDSO's clock_gettime(). */
	.vdso_clock_mode = VDSO_CLOCKMODE_L4H,
#endif
};

static u64 notrace l4h_sched_clock(void)
{
	return os_nsecs();
}

/* ---- clockevents */

static DEFINE_PER_CPU(struct clock_event_device, l4h_clockevent);

/*
 * Clockevent deltas are in units of 8 TSC ticks, as on x86 (TSC_DIVISOR):
 * the clockevent frequency is a u32, and TSCs run at 4.3 GHz and more.
 */
#define L4H_TIMER_SHIFT 3

static int l4h_timer_next(unsigned long delta, struct clock_event_device *evt)
{
	l4h_timer_arm(l4h_rdtsc() + (delta << L4H_TIMER_SHIFT));
	return 0;
}

static int l4h_timer_shutdown(struct clock_event_device *evt)
{
	l4h_timer_arm(0);
	return 0;
}

void l4h_timer_interrupt(void)
{
	struct clock_event_device *evt = this_cpu_ptr(&l4h_clockevent);

	if (evt->event_handler)
		evt->event_handler(evt);
}

void l4h_timer_setup_cpu(void)
{
	struct clock_event_device *evt = this_cpu_ptr(&l4h_clockevent);

	*evt = (struct clock_event_device) {
		.name			= "l4h-deadline",
		.features		= CLOCK_EVT_FEAT_ONESHOT,
		.set_next_event		= l4h_timer_next,
		.set_state_shutdown	= l4h_timer_shutdown,
		.set_state_oneshot_stopped = l4h_timer_shutdown,
		.rating			= 400,
		.irq			= TIMER_IRQ,
		.cpumask		= cpumask_of(smp_processor_id()),
	};
	/* The seL4 timer has microsecond-ish granularity, so do not ask for
	 * less than ~2 us. */
	clockevents_config_and_register(evt, l4h_tsc_hz >> L4H_TIMER_SHIFT,
					(l4h_tsc_hz / 500000) >> L4H_TIMER_SHIFT,
					~0ul >> (1 + L4H_TIMER_SHIFT));
}

#ifdef CONFIG_PARAVIRT
/* Steal time, from the event pages (see asm/paravirt.h). */
struct static_key paravirt_steal_enabled;
struct static_key paravirt_steal_rq_enabled;
/* x86's qspinlock checks this under CONFIG_PARAVIRT: native spinlocks. */
DEFINE_STATIC_KEY_FALSE(virt_spin_lock_key);
#endif

void __init time_init(void)
{
	u64 hz = l4h_tsc_hz;

	if (hz < 1000)
		panic("l4h: unknown TSC frequency\n");
	/* In kHz, as on x86: rates in Hz are u32 and overflow at 4.3 GHz. */
	clocks_calc_mult_shift(&tsc_to_ns_mult, &tsc_to_ns_shift, hz / 1000, NSEC_PER_MSEC, 600);
	lpj_fine = hz / HZ;
	clocksource_register_khz(&l4h_tsc_clocksource, hz / 1000);
	sched_clock_register(l4h_sched_clock, 64, NSEC_PER_SEC);
	l4h_timer_setup_cpu();
#ifdef CONFIG_PARAVIRT
	static_key_slow_inc(&paravirt_steal_enabled);
	if (IS_ENABLED(CONFIG_PARAVIRT_TIME_ACCOUNTING))
		static_key_slow_inc(&paravirt_steal_rq_enabled);
#endif
	pr_info("l4h: TSC %llu.%03llu MHz, deadline timer clockevent\n",
		hz / 1000000, (hz / 1000) % 1000);
}

/* ---- idle */

/*
 * Before an idle vCPU blocks it polls for a while, as KVM guests' haltpoll
 * and the host's halt polling do.  It polls with TIF_POLLING_NRFLAG set, so
 * a vCPU waking it (a reschedule, or a function call IPI) only sets
 * need_resched and sends no IPI: no seL4_Signal on the sender, no wakeup of
 * a blocked kernel thread on this core.  Host events are seen in the event
 * page.  The window adapts as KVM's halt polling does: it grows while a
 * block ends within l4h_idle_poll_us and drops to zero after a longer one,
 * so a mostly idle vCPU stops polling at once.  Polling time is CPU used,
 * not idle time.  l4h_idle_poll_us=0 turns it off.
 */
static unsigned long l4h_idle_poll_us = 50;
static DEFINE_PER_CPU(u64, l4h_idle_poll_window);

static int __init l4h_idle_poll_setup(char *s)
{
	return kstrtoul(s, 0, &l4h_idle_poll_us) == 0;
}
__setup("l4h_idle_poll_us=", l4h_idle_poll_setup);

/* Poll for up to `window` TSC ticks; true if there is work. */
static bool l4h_idle_poll(u64 window)
{
	u64 t0 = l4h_rdtsc();

	if (!current_set_polling_and_test()) {
		while (!tif_need_resched() && !l4h_events_pending() &&
		       l4h_rdtsc() - t0 < window)
			cpu_relax();
	}
	/* A waker that saw the flag set need_resched instead of signalling:
	 * test again once it is clear. */
	return current_clr_polling_and_test() || l4h_events_pending();
}

void os_idle_sleep(void)
{
	u64 max = l4h_idle_poll_us * (l4h_tsc_hz / USEC_PER_SEC);
	u64 *window = this_cpu_ptr(&l4h_idle_poll_window);
	u64 t0, blocked;

	if (*window && l4h_idle_poll(*window))
		return;
	t0 = l4h_rdtsc();
	l4h_idle_wait();
	blocked = l4h_rdtsc() - t0;
	/* A wakeup a longer poll would have caught grows the window, from
	 * an eighth of the maximum; a long block ends polling. */
	if (blocked <= max)
		*window = min(*window ? *window * 2 : max / 8, max);
	else
		*window = 0;
}

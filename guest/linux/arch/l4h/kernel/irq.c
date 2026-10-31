// SPDX-License-Identifier: GPL-2.0
/*
 * Interrupts of the l4h guest.
 *
 * os-sel4 collects the pending events of a vCPU (timer expiry, IPIs and the
 * device event lines of the event page) and calls l4h_deliver_events(),
 * which runs the corresponding Linux interrupt handlers.  Event lines are
 * exposed as an IRQ domain; drivers get their Linux IRQ number with
 * l4h_event_irq().
 */

#include <linux/cpumask.h>
#include <linux/hardirq.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <asm/irq.h>
#include <irq_kern.h>
#include <kern_util.h>
#include <os.h>
#include <l4h_sys.h>

/*
 * A vCPU sees events only where it polls for them, cond_resched() among
 * them (guest/linux/patches/0005).  CONFIG_PREEMPTION compiles
 * cond_resched() out, and a task that waits there for another one would
 * never be told to reschedule (DESIGN.md §5.4).
 */
#ifdef CONFIG_PREEMPTION
#error "l4h needs PREEMPT_NONE or PREEMPT_VOLUNTARY: cond_resched() polls for events"
#endif

extern void l4h_timer_interrupt(void);
extern void l4h_handle_ipi(unsigned long reasons);

static struct irq_domain *event_domain;

static void l4h_event_noop(struct irq_data *d)
{
}

static int l4h_event_set_affinity(struct irq_data *data,
				  const struct cpumask *mask, bool force)
{
	struct l4h_irq_route *route = irq_data_get_irq_chip_data(data);
	unsigned int cpu = force ? cpumask_first(mask) :
			   cpumask_first_and(mask, cpu_online_mask);
	int err;

	if (!route || !route->set_affinity || cpu >= nr_cpu_ids)
		return -EINVAL;
	err = route->set_affinity(route->data, cpu);
	if (err)
		return err;
	irq_data_update_effective_affinity(data, cpumask_of(cpu));
	return IRQ_SET_MASK_OK;
}

static struct irq_chip l4h_event_chip = {
	.name		= "l4h-event",
	.irq_mask	= l4h_event_noop,
	.irq_unmask	= l4h_event_noop,
	.irq_ack	= l4h_event_noop,
	.irq_set_affinity = l4h_event_set_affinity,
};

static int event_domain_map(struct irq_domain *d, unsigned int virq, irq_hw_number_t hw)
{
	irq_set_chip_and_handler(virq, &l4h_event_chip, handle_simple_irq);
	return 0;
}

static const struct irq_domain_ops event_domain_ops = {
	.map	= event_domain_map,
	.xlate	= irq_domain_xlate_onecell,
};

int l4h_event_irq(unsigned int event)
{
	if (event >= L4H_NR_EVENTS)
		return -EINVAL;
	return irq_create_mapping(event_domain, event);
}
EXPORT_SYMBOL_GPL(l4h_event_irq);

/*
 * The registers an interrupt reports.  current->thread.regs are the user
 * registers of the task, with is_user set, so they stand for the interrupted
 * context only when the event stopped user mode.  Everywhere else the vCPU
 * was running the kernel, and a tick that said "user" would let RCU take a
 * quiescent state inside a read-side critical section.
 */
static DEFINE_PER_CPU(struct pt_regs, kernel_irq_regs);
static DEFINE_PER_CPU(bool, irq_from_user);

/* Deliver the events that stopped the current task's user context. */
void l4h_dispatch_user_interrupt(void)
{
	this_cpu_write(irq_from_user, true);
	l4h_dispatch_pending();
	this_cpu_write(irq_from_user, false);
}

void l4h_deliver_events(int timer, unsigned long ipi, unsigned long *events)
{
	struct pt_regs *regs = this_cpu_read(irq_from_user) ? &current->thread.regs :
			       this_cpu_ptr(&kernel_irq_regs);
	struct pt_regs *old_regs = set_irq_regs(regs);
	unsigned int w;

	irq_enter();
	if (timer)
		l4h_timer_interrupt();
	if (ipi)
		l4h_handle_ipi(ipi);
	for (w = 0; w < L4H_NR_EVENTS / 64; w++) {
		unsigned long bits = events[w];

		while (bits) {
			unsigned int b = __ffs(bits);

			bits &= bits - 1;
			if (generic_handle_domain_irq(event_domain, w * 64 + b))
				pr_warn_ratelimited("l4h: spurious event %u\n", w * 64 + b);
		}
	}
	irq_exit();
	set_irq_regs(old_regs);
}

void __init init_IRQ(void)
{
	irq_set_chip_and_handler(TIMER_IRQ, &dummy_irq_chip, handle_percpu_irq);
	irq_set_chip_and_handler(IPI_IRQ, &dummy_irq_chip, handle_percpu_irq);
	event_domain = irq_domain_create_simple(NULL, L4H_NR_EVENTS, L4H_FIRST_EVENT_IRQ,
						&event_domain_ops, NULL);
	if (!event_domain)
		panic("l4h: cannot create the event IRQ domain\n");
}

int __init arch_probe_nr_irqs(void)
{
	return NR_IRQS;
}

#ifndef CONFIG_SMP
void l4h_handle_ipi(unsigned long reasons)
{
}
#endif

void sigio_run_timetravel_handlers(void)
{
}

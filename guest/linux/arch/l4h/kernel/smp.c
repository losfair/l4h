// SPDX-License-Identifier: GPL-2.0
/*
 * SMP support of the l4h guest.
 *
 * Each vCPU is an seL4 thread (the vCPU's kernel TCB) created by the host;
 * all but vCPU 0 start inactive and are started here by writing their
 * registers.  IPIs are notifications: the reasons are kept in the target's
 * struct l4h_vcpu (see os-sel4/events.c).
 */

#include <linux/cpu.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/irq_work.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/sched/task_stack.h>
#include <linux/smp.h>
#include <linux/mm.h>
#include <asm/current.h>
#include <asm/mmu_context.h>
#include <as-layout.h>
#include <kern_util.h>
#include <os.h>
#include <l4h_sys.h>

#define IPI_RESCHEDULE		(1ul << 0)
#define IPI_CALL_FUNC		(1ul << 1)
#define IPI_STOP		(1ul << 2)
#define IPI_IRQ_WORK		(1ul << 3)

void l4h_timer_setup_cpu(void);

void arch_smp_send_reschedule(int cpu)
{
	l4h_send_ipi(cpu, IPI_RESCHEDULE);
}

void arch_send_call_function_single_ipi(int cpu)
{
	l4h_send_ipi(cpu, IPI_CALL_FUNC);
}

void arch_send_call_function_ipi_mask(const struct cpumask *mask)
{
	int cpu;

	for_each_cpu(cpu, mask)
		l4h_send_ipi(cpu, IPI_CALL_FUNC);
}

#ifdef CONFIG_IRQ_WORK
void arch_irq_work_raise(void)
{
	l4h_send_ipi(smp_processor_id(), IPI_IRQ_WORK);
}
#endif

void smp_send_stop(void)
{
	int cpu, me = smp_processor_id();

	for_each_online_cpu(cpu)
		if (cpu != me)
			l4h_send_ipi(cpu, IPI_STOP);
}

void l4h_handle_ipi(unsigned long reasons)
{
	if (reasons & IPI_STOP) {
		set_cpu_online(smp_processor_id(), false);
		for (;;)
			l4h_idle_wait();
	}
	if (reasons & IPI_RESCHEDULE)
		scheduler_ipi();
	if (reasons & IPI_CALL_FUNC)
		generic_smp_call_function_interrupt();
#ifdef CONFIG_IRQ_WORK
	if (reasons & IPI_IRQ_WORK)
		irq_work_run();
#endif
}

void __init l4h_smp_setup(void)
{
	unsigned int cpu, n = l4h_bootinfo->nr_vcpus;

	if (n > nr_cpu_ids)
		n = nr_cpu_ids;
	for (cpu = 0; cpu < n; cpu++)
		set_cpu_possible(cpu, true);
	set_nr_cpu_ids(n);
}

#ifdef CONFIG_PARAVIRT_SPINLOCKS
/*
 * Paravirtual spinlocks (asm/qspinlock.h).  The key is read by every
 * spin_unlock(), which is inlined, in modules too: it is kept apart from
 * data that is written.
 */
DEFINE_STATIC_KEY_FALSE_RO(l4h_pv_spinlocks);
EXPORT_SYMBOL(l4h_pv_spinlocks);
EXPORT_SYMBOL(__pv_queued_spin_unlock);

/*
 * Switch to them while there is still one vCPU, so no lock is contended:
 * a lock taken before the switch and released after it was not waited for,
 * and is released the same either way.
 */
static void __init l4h_pv_spinlock_init(void)
{
	if (num_possible_cpus() == 1)
		return;
	if (nopvspin) {
		pr_info("l4h: PV spinlocks disabled by \"nopvspin\"\n");
		return;
	}
	static_branch_enable(&l4h_pv_spinlocks);
	pr_info("l4h: PV spinlocks enabled\n");
}
#else
static inline void l4h_pv_spinlock_init(void)
{
}
#endif

void __init smp_prepare_cpus(unsigned int max_cpus)
{
	unsigned int cpu;

	for_each_possible_cpu(cpu)
		set_cpu_present(cpu, true);
	l4h_pv_spinlock_init();
}

void __init smp_prepare_boot_cpu(void)
{
	set_cpu_online(smp_processor_id(), true);
#ifdef CONFIG_PARAVIRT_SPINLOCKS
	/* The table of blocked lock waiters comes from memblock, so it is
	 * allocated here, before "nopvspin" is parsed. */
	if (num_possible_cpus() > 1)
		__pv_init_lock_hash();
#endif
}

static void l4h_secondary_main(int cpu)
{
	struct task_struct *idle = current;

	mmgrab(&init_mm);
	idle->active_mm = &init_mm;

	notify_cpu_starting(cpu);
	l4h_timer_setup_cpu();
	set_cpu_online(cpu, true);

	local_irq_enable();
	cpu_startup_entry(CPUHP_AP_ONLINE_IDLE);
}

int __cpu_up(unsigned int cpu, struct task_struct *tidle)
{
	unsigned long sp = (unsigned long)task_stack_page(tidle) + THREAD_SIZE - 64;
	int timeout = 5000;

	task_thread_info(tidle)->cpu = cpu;
	cpu_tasks[cpu] = tidle;
	if (l4h_start_vcpu(cpu, sp, l4h_secondary_main, tidle))
		return -EIO;
	while (!cpu_online(cpu) && --timeout)
		mdelay(1);
	return cpu_online(cpu) ? 0 : -EIO;
}

void __init smp_cpus_done(unsigned int max_cpus)
{
	pr_info("l4h: %u vCPU(s) online\n", num_online_cpus());
}

int setup_profiling_timer(unsigned int multiplier)
{
	return -EINVAL;
}

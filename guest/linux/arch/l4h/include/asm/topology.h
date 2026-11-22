/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __L4H_ASM_TOPOLOGY_H
#define __L4H_ASM_TOPOLOGY_H

#ifdef CONFIG_SMP
#include <linux/cpumask.h>

/*
 * The vCPUs of one virtual core (L4H_BOOT_TOPOLOGY) share a physical
 * core of the host, which moves them only together: they are SMT
 * siblings, in one package (arch/l4h/kernel/smp.c).
 */
extern unsigned int l4h_core_id[NR_CPUS];
extern struct cpumask l4h_sibling_map[NR_CPUS];

#define topology_physical_package_id(cpu)	((void)(cpu), 0)
#define topology_core_id(cpu)			(l4h_core_id[cpu])
#define topology_sibling_cpumask(cpu)		(&l4h_sibling_map[cpu])
#define topology_core_cpumask(cpu)		((void)(cpu), cpu_online_mask)

/* The capacity other guests take from a vCPU (l4h_event_page.host_cap). */
unsigned long l4h_hw_pressure(int cpu);
#define arch_scale_hw_pressure l4h_hw_pressure
#endif

#include <asm-generic/topology.h>

#endif

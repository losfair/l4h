// SPDX-License-Identifier: GPL-2.0
/*
 * Early boot of the l4h guest kernel: per-vCPU state and TLS, then hand
 * over to the kernel (l4h_linux_main).
 */
#include "l4h_os.h"

static void vcpu_init_struct(int cpu)
{
	struct l4h_vcpu *v = &l4h_vcpus[cpu];

	v->id = cpu;
	v->ktcb = VCPU_CAP(cpu, L4H_VCPU_KTCB);
	v->ep = VCPU_CAP(cpu, L4H_VCPU_EP);
	v->ntfn = VCPU_CAP(cpu, L4H_VCPU_NTFN);
	v->sc_u = VCPU_CAP(cpu, L4H_VCPU_SC_U);
	v->evt = (struct l4h_event_page *)L4H_VCPU_EVENT_VA(cpu);
	v->ipcbuf = (void *)L4H_VCPU_IPCBUF_VA(cpu);
	v->irqs_enabled = 0;
}

/* Called on each vCPU with FS already pointing at its TLS block. */
static void vcpu_enter(int cpu)
{
	struct l4h_tls *t = l4h_tls();

	t->vcpu = &l4h_vcpus[cpu];
	t->cpu = cpu;
	t->provider = &l4h_provider_context;
	l4h_provider_ops->l4h_provider_init_cpu();
	l4h_vcpus[cpu].online = 1;
}

extern char init_task[];

void l4h_boot(const struct l4h_bootinfo *bi)
{
	int cpu;

	l4h_provider_setup(bi);
	l4h_bootinfo = bi;
	for (cpu = 0; cpu < L4H_MAX_VCPUS; cpu++)
		vcpu_init_struct(cpu);
	vcpu_enter(0);
	l4h_tls()->current = init_task;
	if (bi->magic != L4H_BOOTINFO_MAGIC || bi->abi_version != L4H_ABI_VERSION) {
		static const char msg[] = "l4h: bad boot info / ABI version\n";
		l4h_console_write(msg, sizeof(msg) - 1);
		l4h_power(L4H_POWER_CRASH);
	}
	l4h_tsc_hz = bi->tsc_hz;
	l4h_linux_main();
	l4h_power(L4H_POWER_OFF);
}

void l4h_secondary_boot(long cpu)
{
	vcpu_enter((int)cpu);
	l4h_tls()->current = l4h_vcpus[cpu].start_task;
	l4h_vcpus[cpu].start_fn((int)cpu);
	l4h_power(L4H_POWER_CRASH);
}

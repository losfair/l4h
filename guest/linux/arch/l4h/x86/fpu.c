// SPDX-License-Identifier: GPL-2.0
/*
 * Kernel-mode FPU/SIMD for the l4h x86_64 guest (see asm/fpu/api.h).
 *
 * User FPU state lives in each user thread's own seL4 TCB, so unlike x86
 * there is nothing to save here: kernel_fpu_begin() only has to keep the
 * section on its vCPU, free of preemption and of nested use from softirqs
 * and interrupt handlers, and put the control registers in a known state.
 */
#include <linux/bottom_half.h>
#include <linux/export.h>
#include <linux/hardirq.h>
#include <linux/irqflags.h>
#include <linux/percpu.h>
#include <linux/preempt.h>
#include <asm/cpu_device_id.h>
#include <asm/cpufeature.h>
#include <asm/fpu/api.h>

/* False while this vCPU is inside a kernel FPU section. */
static DEFINE_PER_CPU(bool, kernel_fpu_allowed) = true;

u64 l4h_xfeatures;
EXPORT_SYMBOL_GPL(l4h_xfeatures);

bool irq_fpu_usable(void)
{
	if (WARN_ON_ONCE(in_nmi()))
		return false;
	/* The vCPU is already in a section that this context interrupted. */
	if (!this_cpu_read(kernel_fpu_allowed))
		return false;
	if (!in_hardirq())
		return true;
	/* A hardirq is safe if it did not hit a bottom-half-disabled region. */
	return !softirq_count();
}
EXPORT_SYMBOL(irq_fpu_usable);

void kernel_fpu_begin_mask(unsigned int kfpu_mask)
{
	if (!irqs_disabled())
		local_bh_disable();
	else
		preempt_disable();

	WARN_ON_ONCE(!irq_fpu_usable());
	this_cpu_write(kernel_fpu_allowed, false);
#ifdef CONFIG_KVM
	l4h_kvm_fpu_save();
#endif

	if (likely(kfpu_mask & KFPU_MXCSR) && boot_cpu_has(X86_FEATURE_XMM)) {
		u32 mxcsr = MXCSR_DEFAULT;

		asm volatile("ldmxcsr %0" :: "m" (mxcsr));
	}
	if (unlikely(kfpu_mask & KFPU_387) && boot_cpu_has(X86_FEATURE_FPU))
		asm volatile("fninit");
}
EXPORT_SYMBOL_GPL(kernel_fpu_begin_mask);

void kernel_fpu_end(void)
{
	WARN_ON_ONCE(this_cpu_read(kernel_fpu_allowed));
	this_cpu_write(kernel_fpu_allowed, true);

	if (!irqs_disabled())
		local_bh_enable();
	else
		preempt_enable();
}
EXPORT_SYMBOL_GPL(kernel_fpu_end);

/*
 * x86_match_cpu() for drivers such as aesni-intel that match on CPU
 * features.  l4h records only the feature words, so entries that also
 * name a vendor, family, model, stepping or CPU type never match.
 */
const struct x86_cpu_id *x86_match_cpu(const struct x86_cpu_id *match)
{
	const struct x86_cpu_id *m;

	for (m = match; m->flags & X86_CPU_ID_FLAG_ENTRY_VALID; m++) {
		if (m->vendor != X86_VENDOR_ANY || m->family != X86_FAMILY_ANY ||
		    m->model != X86_MODEL_ANY || m->steppings != X86_STEPPING_ANY ||
		    m->type != X86_CPU_TYPE_ANY)
			continue;
		if (m->feature != X86_FEATURE_ANY && !boot_cpu_has(m->feature))
			continue;
		return m;
	}
	return NULL;
}
EXPORT_SYMBOL(x86_match_cpu);

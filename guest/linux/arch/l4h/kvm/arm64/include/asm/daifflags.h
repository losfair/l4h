/* SPDX-License-Identifier: GPL-2.0 */
/* The guest kernel's interrupts are l4h events (asm/irqflags.h), not DAIF. */
#ifndef __ASM_DAIFFLAGS_H
#define __ASM_DAIFFLAGS_H
#include <linux/irqflags.h>
#define DAIF_PROCCTX		0
#define DAIF_PROCCTX_NOIRQ	(PSR_I_BIT | PSR_F_BIT)
#define DAIF_ERRCTX		(PSR_A_BIT | PSR_I_BIT | PSR_F_BIT)
#define DAIF_MASK		(PSR_D_BIT | PSR_A_BIT | PSR_I_BIT | PSR_F_BIT)
static inline unsigned long local_daif_save(void)
{
	unsigned long flags;

	local_irq_save(flags);
	return flags;
}
static inline void local_daif_restore(unsigned long flags)
{
	local_irq_restore(flags);
}
static inline void local_daif_mask(void)
{
	local_irq_disable();
}
#endif

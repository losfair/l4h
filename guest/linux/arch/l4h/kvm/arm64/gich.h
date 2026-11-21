/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Included in arch/arm64/kvm/vgic/vgic-v2.c and mmu.c (Makefile): GICv2's
 * GICH is the loaded vCPU's VGIC registers in FL4 (vgic.c), not MMIO.
 */
#ifndef __L4H_KVM_ARM64_GICH_H
#define __L4H_KVM_ARM64_GICH_H
#include <linux/io.h>

u32 l4h_kvm_readl(const volatile void __iomem *addr);
void l4h_kvm_writel(u32 val, volatile void __iomem *addr);
void __iomem *l4h_kvm_ioremap(phys_addr_t phys, size_t size);
void l4h_kvm_iounmap(volatile void __iomem *addr);

#undef readl_relaxed
#undef writel_relaxed
#undef ioremap
#undef iounmap
#define readl_relaxed(a)	l4h_kvm_readl(a)
#define writel_relaxed(v, a)	l4h_kvm_writel(v, a)
#define ioremap(p, s)		l4h_kvm_ioremap(p, s)
#define iounmap(a)		l4h_kvm_iounmap(a)
#endif

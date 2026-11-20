/* SPDX-License-Identifier: GPL-2.0 */
/*
 * arm64's sysreg.h for arch/arm64/kvm in the l4h guest kernel.  The guest
 * kernel runs at EL0: system register accesses go through
 * arch/l4h/kvm/arm64/init.c, which answers the ID registers from bootinfo
 * and reads the EL0 counter.  KVM keeps a VM's registers in memory
 * (never SYSREGS_ON_CPU), so nothing else reaches the hardware.
 */
#ifndef __L4H_KVM_ASM_SYSREG_H
#define __L4H_KVM_ASM_SYSREG_H
#include <../arch/arm64/include/asm/sysreg.h>

#ifndef __ASSEMBLY__
u64 l4h_kvm_read_sysreg(u32 enc);
void l4h_kvm_write_sysreg(u32 enc, u64 val);
u64 l4h_kvm_read_sysreg_name(const char *name);
void l4h_kvm_write_sysreg_name(const char *name, u64 val);

#undef read_sysreg
#undef write_sysreg
#undef read_sysreg_s
#undef write_sysreg_s
#define read_sysreg(r)		l4h_kvm_read_sysreg_name(#r)
#define write_sysreg(v, r)	l4h_kvm_write_sysreg_name(#r, (u64)(v))
#define read_sysreg_s(r)	l4h_kvm_read_sysreg(r)
#define write_sysreg_s(v, r)	l4h_kvm_write_sysreg(r, (u64)(v))
#endif
#endif

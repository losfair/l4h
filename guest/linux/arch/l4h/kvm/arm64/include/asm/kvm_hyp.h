/* SPDX-License-Identifier: GPL-2.0 */
/*
 * arm64's kvm_hyp.h for arch/arm64/kvm in the l4h guest kernel: its EL1/EL2
 * register accessors (the VHE _EL02/_EL12 views) go through
 * l4h_kvm_read_sysreg() and l4h_kvm_write_sysreg() like the others (sysreg.h).
 */
#ifndef __L4H_KVM_ASM_KVM_HYP_H
#define __L4H_KVM_ASM_KVM_HYP_H
#include <../arch/arm64/include/asm/kvm_hyp.h>

#undef read_sysreg_elx
#undef write_sysreg_elx
#define read_sysreg_elx(r, nvh, vh)	l4h_kvm_read_sysreg(r##vh)
#define write_sysreg_elx(v, r, nvh, vh)	l4h_kvm_write_sysreg(r##vh, (u64)(v))
#endif

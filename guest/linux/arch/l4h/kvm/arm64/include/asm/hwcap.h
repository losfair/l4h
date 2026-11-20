/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __L4H_KVM_ASM_HWCAP_H
#define __L4H_KVM_ASM_HWCAP_H
#include <../arch/arm64/include/asm/hwcap.h>
/* The guest kernel's asm/elf.h has its own. */
#undef ELF_HWCAP
#undef ELF_HWCAP2
#undef ELF_HWCAP3
#endif

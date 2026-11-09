/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __X86_UM_SYSDEP_ARCHSETJMP_H
#define __X86_UM_SYSDEP_ARCHSETJMP_H

#include "archsetjmp_64.h"

unsigned long get_thread_reg(int reg, jmp_buf *buf);

#endif /* __X86_UM_SYSDEP_ARCHSETJMP_H */

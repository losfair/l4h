/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_ALTERNATIVE_H
#define __ASM_ALTERNATIVE_H
#include <asm/alternative-macros.h>
#ifndef __ASSEMBLY__
#include <linux/types.h>
static inline void apply_alternatives_all(void) { }
#endif
#endif

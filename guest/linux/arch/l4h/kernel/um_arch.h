/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __UML_ARCH_H__
#define __UML_ARCH_H__

extern void * __init uml_load_file(const char *filename, unsigned long long *size);

#ifdef CONFIG_OF
extern void __init uml_dtb_init(void);
#else
static inline void uml_dtb_init(void) { }
#endif

#ifdef CONFIG_BLK_DEV_INITRD
extern void __init l4h_initrd_setup(void);
#else
static inline void l4h_initrd_setup(void) { }
#endif

#endif

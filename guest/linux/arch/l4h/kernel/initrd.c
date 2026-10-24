// SPDX-License-Identifier: GPL-2.0
/*
 * The l4h host loads the initramfs into guest RAM and describes it in the
 * boot info.  setup_arch() records it, before start_kernel() looks for a
 * bootconfig at its end.
 */
#include <linux/init.h>
#include <linux/initrd.h>
#include <asm/page.h>
#include <l4h_sys.h>
#include "um_arch.h"

void __init l4h_initrd_setup(void)
{
	const struct l4h_bootinfo *bi = l4h_bootinfo;

	if (bi->initrd_size) {
		initrd_start = (unsigned long)__va(bi->initrd_gpa);
		initrd_end = initrd_start + bi->initrd_size;
	}
}

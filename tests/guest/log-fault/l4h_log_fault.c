// SPDX-License-Identifier: GPL-2.0
/* Intentionally stop an expendable test VM, never dom0. */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/panic.h>

static bool panic_test;
module_param(panic_test, bool, 0400);

static int __init log_fault_init(void)
{
	if (panic_test)
		panic("l4h log test panic");
#ifdef CONFIG_X86_64
	asm volatile("ud2");
#else
	asm volatile("udf #0");
#endif
	return 0;
}

module_init(log_fault_init);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("l4h host log fault and panic injection test");

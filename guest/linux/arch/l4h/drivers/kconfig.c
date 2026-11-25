// SPDX-License-Identifier: GPL-2.0
/*
 * What the host's microkernel found and chose at boot (FL4's
 * seL4_KernelConfig, DESIGN.md §10.1), through the ABI provider
 * (l4h_kernel_config, L4H_PROVIDER_KERNEL_CONFIG): cores, the
 * virtualization backend or why there is none, a confidential VM,
 * mitigations, CPU and platform features, one word per key.
 *
 * /dev/l4h-kconfig: ioctl(L4H_KCONFIG_IOC) reads one key, for tools such
 * as l4hctl, in dom0 and any other guest alike.  The answers never change
 * after the host boots, and are no secret of this guest's: anyone may ask.
 * A key the kernel does not know (or one of the other architecture) is
 * -ENOENT; a host kernel without the call (seL4) -ENOSYS.  HVM guests ask
 * through their kernel configuration port instead (abi.h,
 * L4H_KCONFIG_PORT_*).
 */
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <l4h_sys.h>

struct l4h_kconfig_ioc {
	__u64 key;		/* in: a seL4_KernelConfig_* key */
	__u64 value;		/* out: its value */
};

#define L4H_KCONFIG_IOC _IOWR('L', 3, struct l4h_kconfig_ioc)

/* l4h_kernel_config's answer as an errno. */
static long kconfig_errno(int r)
{
	if (r == 0)
		return 0;
	if (r == 1)	/* seL4_InvalidArgument */
		return -ENOENT;
	if (r < 0 && r >= -MAX_ERRNO)
		return r;
	return -EIO;
}

static long kconfig_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	struct l4h_kconfig_ioc c;
	unsigned long value = 0;
	long ret;

	if (cmd != L4H_KCONFIG_IOC)
		return -ENOTTY;
	if (copy_from_user(&c, (void __user *)arg, sizeof(c)))
		return -EFAULT;
	/* A provider without the call has the slot, but nothing behind it
	 * to answer: never called. */
	if (!(l4h_provider_features() & L4H_PROVIDER_KERNEL_CONFIG))
		return -ENOSYS;
	ret = kconfig_errno(l4h_kernel_config(c.key, &value));
	if (ret)
		return ret;
	c.value = value;
	if (copy_to_user((void __user *)arg, &c, sizeof(c)))
		return -EFAULT;
	return 0;
}

static const struct file_operations kconfig_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = kconfig_ioctl,
};

static struct miscdevice kconfig_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "l4h-kconfig",
	.fops = &kconfig_fops,
	.mode = 0444,
};

static int __init l4h_kconfig_init(void)
{
	return misc_register(&kconfig_dev);
}
device_initcall(l4h_kconfig_init);

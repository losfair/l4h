// SPDX-License-Identifier: GPL-2.0
/*
 * /dev/hw_random on the CPU's random number generator (RDRAND), which
 * also seeds the kernel's (os_getrandom()).  Android's prng_seeder reads
 * it and waits forever without it.  Without RDRAND (AArch64 guests,
 * os_getrandom() returns -ENOSYS) there is no device.
 */
#include <linux/hw_random.h>
#include <linux/init.h>
#include <os.h>

static int l4h_rng_read(struct hwrng *rng, void *buf, size_t max, bool wait)
{
	ssize_t n = os_getrandom(buf, max, 0);

	return n < 0 ? 0 : n;
}

static struct hwrng l4h_rng = {
	.name = "l4h",
	.read = l4h_rng_read,
	/* Of the bits read, all are random. */
	.quality = 1024,
};

static int __init l4h_rng_init(void)
{
	u8 probe;

	if (os_getrandom(&probe, 1, 0) != 1)
		return 0;
	return hwrng_register(&l4h_rng);
}
device_initcall(l4h_rng_init);

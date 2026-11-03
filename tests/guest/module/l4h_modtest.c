// SPDX-License-Identifier: GPL-2.0
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <net/checksum.h>
#include <asm/word-at-a-time.h>

static const unsigned long expected[] = { 0x12345678, 0xabcdef01 };

/*
 * Word-at-a-time loads at the end of a mapped page (issue #76).  The page
 * after a one-page vmalloc() area is an unmapped guard page: csum_partial()
 * of a 1-7 byte tail ending there, and load_unaligned_zeropad() across
 * it, must return what they would for the same bytes elsewhere instead of
 * faulting the guest kernel.  Across two mapped pages they must still read
 * the second one.
 */
static int __init zeropad_test(void)
{
	u8 *guard = vmalloc(PAGE_SIZE), *pair = vmalloc(2 * PAGE_SIZE);
	u8 *ref = kmalloc(2048, GFP_KERNEL);
	int len, i, err = -ENOMEM;

	if (!guard || !pair || !ref)
		goto out;
	for (i = 0; i < 2 * PAGE_SIZE; i++)
		pair[i] = i * 37 + 11;
	memcpy(guard, pair, PAGE_SIZE);
	err = -EINVAL;
	for (len = 1; len <= 1500; len++) {
		const u8 *src = guard + PAGE_SIZE - len;

		memcpy(ref, src, len);
		memset(ref + len, 0xa5, 16);
		if (csum_partial(src, len, 0) != csum_partial(ref, len, 0)) {
			pr_err("MODTEST: csum_partial tail %d at page end\n", len);
			goto out;
		}
	}
#ifdef CONFIG_DCACHE_WORD_ACCESS
	for (i = 1; i < sizeof(long); i++) {
		unsigned long want = 0, got;

		memcpy(&want, guard + PAGE_SIZE - i, i);
		got = load_unaligned_zeropad(guard + PAGE_SIZE - i);
		if (got != want) {
			pr_err("MODTEST: zeropad %d bytes before a guard page: %lx, want %lx\n",
			       i, got, want);
			goto out;
		}
		memcpy(&want, pair + PAGE_SIZE - i, sizeof(long));
		got = load_unaligned_zeropad(pair + PAGE_SIZE - i);
		if (got != want) {
			pr_err("MODTEST: zeropad %d bytes before a mapped page: %lx, want %lx\n",
			       i, got, want);
			goto out;
		}
	}
#endif
	pr_info("MODTEST: page-end word loads ok\n");
	err = 0;
out:
	kfree(ref);
	vfree(pair);
	vfree(guard);
	return err;
}

static int __init modtest_init(void)
{
	unsigned long *p = kmemdup(expected, sizeof(expected), GFP_KERNEL);
	int err;

	if (!p)
		return -ENOMEM;
	if (p[0] != expected[0] || p[1] != expected[1]) {
		kfree(p);
		return -EINVAL;
	}
	kfree(p);
	err = zeropad_test();
	if (err)
		return err;
	pr_info("MODTEST: loaded\n");
	return 0;
}

static void __exit modtest_exit(void)
{
	pr_info("MODTEST: unloaded\n");
}

module_init(modtest_init);
module_exit(modtest_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("l4h native module relocation, lifecycle and page-end load test");

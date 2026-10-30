/* SPDX-License-Identifier: GPL-2.0 */
#ifndef L4H_TEST_PAGE_AGING_H
#define L4H_TEST_PAGE_AGING_H

#include <linux/ioctl.h>
#include <linux/types.h>

struct aging_range {
	__u64 start;
	__u64 size;
};

/* Test and clear young for the caller's range; return the young page count. */
#define L4H_AGING_SAMPLE _IOW('A', 0, struct aging_range)

/* Count actual seL4 2 MiB leaves overlapping the range. */
#define L4H_LARGE_MAPPINGS _IOW('A', 1, struct aging_range)

#endif

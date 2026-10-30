/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef L4H_TEST_THP_H
#define L4H_TEST_THP_H

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define PAGE 4096UL
#define HUGE (2UL << 20)
#ifndef MADV_COLLAPSE
#define MADV_COLLAPSE 25
#endif
#ifndef THP_TAG
#define THP_TAG "THPTEST"
#endif
#define CHECK(cond, ...) do { if (!(cond)) { \
	fprintf(stderr, THP_TAG ": FAIL %s:%d: ", __func__, __LINE__); \
	fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); exit(1); \
} } while (0)

struct area {
	void *base;
	unsigned char *p;
	size_t size;
};

/* Keep guard VMAs on both sides so smaps describes exactly this mapping. */
static struct area area_new(size_t size, int advice)
{
	struct area a = { .size = size };

	a.base = mmap(NULL, size + 2 * HUGE, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHECK(a.base != MAP_FAILED, "mmap: %s", strerror(errno));
	a.p = (void *)(((uintptr_t)a.base + HUGE) & ~(HUGE - 1));
	CHECK(!mprotect(a.p, size, PROT_READ | PROT_WRITE), "mprotect: %s", strerror(errno));
	CHECK(!madvise(a.p, size, advice), "madvise %d: %s", advice, strerror(errno));
	return a;
}

static void area_free(struct area a)
{
	CHECK(!munmap(a.base, a.size + 2 * HUGE), "munmap: %s", strerror(errno));
}

static unsigned long area_kb(struct area a, const char *field)
{
	FILE *f = fopen("/proc/self/smaps", "r");
	char line[512], key[64];
	unsigned long start, end, kb, sum = 0;
	int match = 0;

	CHECK(f, "smaps: %s", strerror(errno));
	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "%lx-%lx", &start, &end) == 2)
			match = start < (uintptr_t)a.p + a.size && end > (uintptr_t)a.p;
		else if (match && sscanf(line, "%63s %lu", key, &kb) == 2 && !strcmp(key, field))
			sum += kb;
	}
	fclose(f);
	return sum;
}

static void require_huge(struct area a)
{
	unsigned long kb = area_kb(a, "AnonHugePages:");

	if (kb != a.size / 1024) {
		FILE *f = fopen("/proc/self/smaps", "r");
		char line[512];
		unsigned long start, end;
		int match = 0;

		while (f && fgets(line, sizeof(line), f)) {
			if (sscanf(line, "%lx-%lx", &start, &end) == 2)
				match = start < (uintptr_t)a.p + a.size && end > (uintptr_t)a.p;
			if (match)
				fputs(line, stderr);
		}
		if (f)
			fclose(f);
	}
	CHECK(kb == a.size / 1024, "expected %zu KiB of THP, got %lu", a.size / 1024, kb);
}

#endif

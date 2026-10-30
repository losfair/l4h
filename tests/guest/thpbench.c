// SPDX-License-Identifier: GPL-2.0-only
/* Paired MADV_NOHUGEPAGE/MADV_HUGEPAGE trials on the same kernel. */
#define _GNU_SOURCE
#define THP_TAG "THPBENCH"
#include "thp.h"
#include "page-aging/page-aging.h"
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>

static double now(void)
{
	struct timespec ts;
	CHECK(!clock_gettime(CLOCK_MONOTONIC, &ts), "clock_gettime");
	return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static void wait_ok(pid_t pid)
{
	int status;
	CHECK(pid > 0 && waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
	      !WEXITSTATUS(status), "fork/wait failed");
}

static unsigned long pgtables_kb(void)
{
	FILE *f = fopen("/proc/self/status", "r");
	char line[256];
	unsigned long kb = 0;

	CHECK(f, "status");
	while (fgets(line, sizeof(line), f))
		if (sscanf(line, "VmPTE: %lu", &kb) == 1)
			break;
	fclose(f);
	return kb;
}

static long native_leaves(struct area a)
{
	struct aging_range r = { .start = (uintptr_t)a.p, .size = a.size };
	int fd = open("/dev/l4h_page_aging", O_RDONLY);
	long n;

	/* Keep the same binary usable as a native Linux comparison. */
	if (fd < 0)
		return -1;
	n = ioctl(fd, L4H_LARGE_MAPPINGS, &r);
	close(fd);
	CHECK(n >= 0, "native leaf query");
	return n;
}

static void dense(int trial, int huge)
{
	const size_t size = 64UL << 20, reads = 1000000;
	struct area a = area_new(size, huge ? MADV_HUGEPAGE : MADV_NOHUGEPAGE);
	struct rusage before, after;
	double t, touch, walk, fork_ms, cow, protect, unmap;
	unsigned long anon, rss, pgtables;
	long native;
	uint32_t state = 1;
	unsigned long sum = 0;
	pid_t pid;

	getrusage(RUSAGE_SELF, &before);
	t = now();
	for (size_t off = 0; off < size; off += PAGE)
		a.p[off] = 1;
	touch = (now() - t) * 1000;
	getrusage(RUSAGE_SELF, &after);
	anon = area_kb(a, "AnonHugePages:");
	rss = area_kb(a, "Rss:");
	pgtables = pgtables_kb();
	native = native_leaves(a);
	CHECK(native < 0 || native == (huge ? (long)(size / HUGE) : 0), "native large leaf coverage %ld", native);
	if (huge)
		require_huge(a);
	else
		CHECK(!anon, "base trial has huge pages");

	t = now();
	for (size_t i = 0; i < reads; i++) {
		state = state * 1664525U + 1013904223U;
		sum += *(volatile unsigned char *)(a.p + (state % (size / PAGE)) * PAGE);
	}
	walk = (now() - t) * 1e9 / reads;
	CHECK(sum == reads, "random read data");
	t = now();
	for (int i = 0; i < 8; i++) {
		pid = fork();
		if (!pid)
			_exit(0);
		wait_ok(pid);
	}
	fork_ms = (now() - t) * 1000 / 8;
	t = now();
	pid = fork();
	if (!pid) {
		for (size_t off = 0; off < size; off += PAGE)
			a.p[off] = 2;
		for (size_t off = 0; off < size; off += PAGE)
			CHECK(a.p[off] == 2, "COW child data");
		_exit(0);
	}
	wait_ok(pid);
	cow = (now() - t) * 1000;
	for (size_t off = 0; off < size; off += PAGE)
		CHECK(a.p[off] == 1, "COW changed parent");
	t = now();
	for (size_t off = 0; off < size; off += HUGE) {
		CHECK(!mprotect(a.p + off + PAGE, PAGE, PROT_READ), "protect");
		CHECK(!mprotect(a.p + off + PAGE, PAGE, PROT_READ | PROT_WRITE), "unprotect");
	}
	protect = (now() - t) * 1000;
	t = now();
	area_free(a);
	unmap = (now() - t) * 1000;
	printf("THPBENCH: trial=%d mode=%s dense_ms=%.3f minflt=%ld anon_huge_kb=%lu rss_kb=%lu "
	       "pgtables_kb=%lu native_2m=%ld random_ns=%.2f fork_ms=%.3f cow_ms=%.3f protect_ms=%.3f unmap_ms=%.3f\n",
	       trial, huge ? "huge" : "base", touch, after.ru_minflt - before.ru_minflt,
	       anon, rss, pgtables, native, walk, fork_ms, cow, protect, unmap);
}

static void sparse(int trial, int huge)
{
	struct area a = area_new(64UL << 20, huge ? MADV_HUGEPAGE : MADV_NOHUGEPAGE);
	struct rusage before, after;
	double t, elapsed;

	getrusage(RUSAGE_SELF, &before);
	t = now();
	for (size_t off = 0; off < a.size; off += HUGE)
		a.p[off] = 1;
	elapsed = (now() - t) * 1000;
	getrusage(RUSAGE_SELF, &after);
	if (huge)
		require_huge(a);
	printf("THPBENCH: trial=%d mode=%s sparse_ms=%.3f minflt=%ld anon_huge_kb=%lu rss_kb=%lu\n",
	       trial, huge ? "huge" : "base", elapsed, after.ru_minflt - before.ru_minflt,
	       area_kb(a, "AnonHugePages:"), area_kb(a, "Rss:"));
	area_free(a);
}

int main(int argc, char **argv)
{
	int trials = argc > 1 ? atoi(argv[1]) : 5;

	setbuf(stdout, NULL);
	CHECK(trials > 0 && trials <= 100, "invalid trial count");
	/* Fresh processes isolate COW and VSpace history. Alternate mode order;
	 * trial zero warms both paths and is excluded from reported medians. */
	for (int trial = 0; trial <= trials; trial++)
		for (int mode = 0; mode < 2; mode++) {
			int huge = mode ^ (trial & 1);
			pid_t pid = fork();

			if (!pid) {
				dense(trial, huge);
				sparse(trial, huge);
				_exit(0);
			}
			wait_ok(pid);
		}
	puts("THPBENCH: PASS");
	return 0;
}

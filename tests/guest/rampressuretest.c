// SPDX-License-Identifier: GPL-2.0-only
// Demand conversion must work with the background initcall blacklisted.
#define _GNU_SOURCE
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define MIB (1ul << 20)
#define PAGE 4096
#define THREADS 4

static void check(int ok, const char *what)
{
	if (!ok) {
		printf("RAMPRESSURE: FAIL: %s\n", what);
		exit(1);
	}
}

struct stats {
	unsigned long total, reclaim, oom;
};

static struct stats stats(void)
{
	struct stats s = {0};
	char line[256];
	FILE *f = fopen("/proc/meminfo", "r");

	check(f != NULL, "open meminfo");
	while (fgets(line, sizeof(line), f))
		sscanf(line, "MemTotal: %lu", &s.total);
	fclose(f);
	/* The baseline kernel has no statistics when its worker initcall is
	 * blacklisted. Still run the allocation, to reproduce the actual OOM. */
	f = fopen("/proc/l4h_objmem", "r");
	if (f) {
		while (fgets(line, sizeof(line), f))
			sscanf(line, "reclaim_blocks %lu oom_blocks %lu", &s.reclaim, &s.oom);
		fclose(f);
	}
	return s;
}

static volatile uint64_t *memory;
static unsigned long span;

static uint64_t pattern(unsigned long off)
{
	return 0xdecafbad12345678ull ^ off;
}

static void *touch(void *arg)
{
	unsigned long start = (uintptr_t)arg * span;

	for (unsigned long off = start; off < start + span; off += PAGE) {
		unsigned long first = off / sizeof(*memory);
		unsigned long last = (off + PAGE) / sizeof(*memory) - 1;

		check(!memory[first] && !memory[last], "new pages are zero");
		memory[first] = pattern(off);
		memory[last] = ~pattern(off);
	}
	return NULL;
}

static void allocate(unsigned long bytes)
{
	pthread_t threads[THREADS];

	memory = mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	check(memory != MAP_FAILED, "overcommitted mapping succeeds");
	check(!madvise((void *)memory, bytes, MADV_NOHUGEPAGE), "use small pages");
	printf("RAMPRESSURE: touching %lu MiB with %u threads\n", bytes / MIB, THREADS);
	span = bytes / THREADS;
	for (uintptr_t i = 0; i < THREADS; i++)
		check(!pthread_create(&threads[i], NULL, touch, (void *)i), "create thread");
	for (unsigned i = 0; i < THREADS; i++)
		check(!pthread_join(threads[i], NULL), "join thread");
	for (unsigned long off = 0; off < bytes; off += PAGE) {
		check(memory[off / sizeof(*memory)] == pattern(off), "page start retained");
		check(memory[(off + PAGE) / sizeof(*memory) - 1] == ~pattern(off), "page end retained");
	}
	check(!munmap((void *)memory, bytes), "free mapping");
}

int main(void)
{
	char mode[32];
	unsigned long mb, pad, bytes;
	struct stats before, after;
	struct stat st;
	FILE *f;
	pid_t pid;
	int status;

	setbuf(stdout, NULL);
	f = fopen("/bin/pressure-config", "r");
	check(f && fscanf(f, "%31s %lu %lu", mode, &mb, &pad) == 3, "read test configuration");
	fclose(f);
	check(!stat("/bin/pressure-pad", &st) && st.st_size == (off_t)(pad * MIB),
	      "initramfs unpacked completely");
	before = stats();
	printf("RAMPRESSURE: %s: initial MemTotal %lu KiB, reclaim %lu, OOM %lu\n",
	       mode, before.total, before.reclaim, before.oom);
	if (!strcmp(mode, "initramfs"))
		check(before.reclaim > 0, "initramfs used demand conversion before the worker");
	check(!unlink("/bin/pressure-pad"), "release initramfs padding");
	bytes = (mb * MIB * 3 / 5) & ~(THREADS * PAGE - 1ul);
	if (strcmp(mode, "initramfs"))
		check(bytes > before.total * 1024, "allocation exceeds all currently managed RAM");
	pid = fork();
	check(pid >= 0, "fork allocator");
	if (!pid) {
		allocate(bytes);
		_exit(0);
	}
	check(waitpid(pid, &status, 0) == pid, "wait for allocator");
	check(WIFEXITED(status) && !WEXITSTATUS(status), "allocator survived pressure");
	after = stats();
	if (!strcmp(mode, "shrinker"))
		check(after.reclaim > before.reclaim, "shrinker converted RAM");
	if (!strcmp(mode, "oom")) {
		check(after.oom > before.oom, "OOM notifier converted RAM");
		check(!after.reclaim, "shrinker was disabled");
	}
	printf("RAMPRESSURE: PASS: %s, verified %lu MiB; reclaim %lu, OOM %lu\n",
	       mode, bytes / MIB, after.reclaim, after.oom);
	return 0;
}

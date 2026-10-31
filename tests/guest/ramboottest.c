// SPDX-License-Identifier: GPL-2.0-only
// Boot with deferred RAM, then use the pages returned by the object worker.
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/klog.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#define MIB (1ul << 20)
#define PAGE 4096

static void check(int ok, const char *what)
{
	if (!ok) {
		printf("RAMBOOT: FAIL: %s\n", what);
		exit(1);
	}
}

struct stats {
	unsigned blocks, boot, objects, reserve, target, spare, watermark;
	unsigned long total, free, to_frames;
};

static struct stats stats(void)
{
	struct stats s = {0};
	char line[256];
	FILE *f = fopen("/proc/l4h_objmem", "r");

	check(f != NULL, "open object statistics");
	check(fscanf(f, "blocks %u boot %u objects %u reserve %u/%u spare %u/%u\n",
		     &s.blocks, &s.boot, &s.objects, &s.reserve, &s.target,
		     &s.spare, &s.watermark) == 7, "read object statistics");
	check(fscanf(f, "to_objects %*u to_frames %lu", &s.to_frames) == 1,
	      "read conversions");
	fclose(f);
	f = fopen("/proc/meminfo", "r");
	check(f != NULL, "open memory statistics");
	while (fgets(line, sizeof(line), f)) {
		sscanf(line, "MemTotal: %lu", &s.total);
		sscanf(line, "MemFree: %lu", &s.free);
	}
	fclose(f);
	check(s.total && s.free, "read memory statistics");
	return s;
}

static uint64_t pattern(unsigned long offset)
{
	return 0x12345678abcdef00ull ^ offset;
}

static volatile uint64_t *allocate(unsigned long bytes)
{
	volatile uint64_t *p = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
				  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	check(p != MAP_FAILED, "allocate RAM");
	check(!madvise((void *)p, bytes, MADV_NOHUGEPAGE), "use small frames");
	for (unsigned long off = 0; off < bytes; off += PAGE) {
		unsigned long first = off / sizeof(*p), last = (off + PAGE) / sizeof(*p) - 1;

		check(!p[first] && !p[last], "new page is zero");
		p[first] = pattern(off);
		p[last] = ~pattern(off);
	}
	return p;
}

static void verify(volatile uint64_t *p, unsigned long bytes)
{
	for (unsigned long off = 0; off < bytes; off += PAGE) {
		check(p[off / sizeof(*p)] == pattern(off), "page start retained");
		check(p[(off + PAGE) / sizeof(*p) - 1] == ~pattern(off), "page end retained");
	}
	check(!munmap((void *)p, bytes), "free RAM");
}

int main(void)
{
	unsigned mb = 0, blocks = 0, boot = 0, objects = 0, frames = 0;
	struct stats first, last;
	volatile uint64_t *early, *bulk;
	unsigned long bytes;
	char *log;
	int size;
	time_t deadline;

	setbuf(stdout, NULL);
	size = klogctl(10, NULL, 0);
	check(size > 0, "size kernel log");
	log = calloc(size + 1, 1);
	check(log != NULL, "allocate kernel log");
	check(klogctl(3, log, size) >= 0, "read kernel log");
	for (char *p = log; *p; p++)
		if (sscanf(p, "l4h: %u MiB of RAM in %u blocks: %u boot, %u object, %u frame;",
			   &mb, &blocks, &boot, &objects, &frames) == 5)
			break;
	free(log);
	check(blocks && boot + objects + frames == blocks, "find boot RAM counts");
	printf("RAMBOOT: boot %u MiB: %u boot, %u object, %u frame blocks\n",
	       mb, boot, objects, frames);
	/* Large guests must reach the page allocator with most RAM still
	 * reserved, independent of the exact early-allocation budget. */
	if (mb >= 1024)
		check(boot + frames < blocks / 2, "most RAM conversion deferred");

	first = stats();
	printf("RAMBOOT: userspace MemTotal %lu KiB, conversions %lu\n",
	       first.total, first.to_frames);
	/* Exercise allocations during conversion and keep them across it. */
	early = allocate(16 * MIB);
	deadline = time(NULL) + 90;
	for (;;) {
		last = stats();
		if (last.reserve >= last.target && last.spare <= last.watermark)
			break;
		check(time(NULL) < deadline, "background conversion completed");
		usleep(100000);
	}
	check(last.total >= mb * 1024ul * (mb >= 1024 ? 9 : 7) / 10,
	      "RAM returned to the page allocator");
	if (mb >= 1024)
		check(last.to_frames > blocks / 2, "background conversions recorded");
	printf("RAMBOOT: settled MemTotal %lu KiB, conversions %lu\n",
	       last.total, last.to_frames);
	bytes = (last.free * 1024 * 3 / 5) & ~(PAGE - 1ul);
	if (mb >= 1024)
		check(bytes > (boot + frames) * 2ul * MIB, "allocation exceeds initial RAM");
	bulk = allocate(bytes);
	verify(early, 16 * MIB);
	verify(bulk, bytes);
	printf("RAMBOOT: PASS: verified %lu MiB of RAM\n", bytes / MIB + 16);
	return 0;
}

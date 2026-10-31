// Guest-owned memory: conversion of RAM blocks between frame mode and
// seL4 object mode (DESIGN.md §8.3), run inside an l4h guest by
// tests/run-objtest.sh.
//  1. Page-table pressure: processes touch one page every 2 MiB of a large
//     sparse mapping, so that each touch needs a page table; object blocks
//     are converted from frame blocks.  When they exit, the blocks return.
//  2. The same while /bin/selftest smp_mm_stress runs, repeatedly.
//  3. OOM: a process maps sparse memory until no 2 MiB block can be found;
//     the guest survives (the OOM killer kills it), and conversions work
//     again afterwards.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MIB (1ul << 20)

static int failures;

#define CHECK(c, ...) do { if (!(c)) { printf("OBJTEST: check failed: " __VA_ARGS__); printf("\n"); failures++; } } while (0)

struct stats {
	unsigned long objects_kb, used_kb, free_kb;
	unsigned long to_objects, to_frames, failures;
	unsigned long contig_attempts, contig_successes;
	unsigned long migrated;
	unsigned blocks, object_blocks, reserve_target, spare_target;
};

static void read_stats(struct stats *s)
{
	char line[256];
	FILE *f;

	memset(s, 0, sizeof(*s));
	f = fopen("/proc/meminfo", "r");
	if (f) {
		while (fgets(line, sizeof(line), f)) {
			sscanf(line, "L4hObjects: %lu", &s->objects_kb);
			sscanf(line, "L4hObjectsUsed: %lu", &s->used_kb);
			sscanf(line, "MemFree: %lu", &s->free_kb);
		}
		fclose(f);
	}
	f = fopen("/proc/l4h_objmem", "r");
	if (f) {
		if (fgets(line, sizeof(line), f))
			sscanf(line, "blocks %u boot %*u objects %u reserve %*u/%u spare %*u/%u", &s->blocks,
			       &s->object_blocks, &s->reserve_target, &s->spare_target);
		if (fgets(line, sizeof(line), f))
			sscanf(line, "to_objects %lu to_frames %lu failures %lu", &s->to_objects,
			       &s->to_frames, &s->failures);
		if (fgets(line, sizeof(line), f))
			sscanf(line, "contig_attempts %lu contig_successes %lu", &s->contig_attempts,
			       &s->contig_successes);
		fclose(f);
	}
	f = fopen("/proc/vmstat", "r");
	if (f) {
		while (fgets(line, sizeof(line), f))
			sscanf(line, "pgmigrate_success %lu", &s->migrated);
		fclose(f);
	}
}

static void show(const char *what)
{
	struct stats s;

	read_stats(&s);
	printf("OBJTEST: %-28s L4hObjects %6lu kB (used %6lu kB), MemFree %7lu kB, "
	       "conversions %lu to objects, %lu to frames, %lu failed\n",
	       what, s.objects_kb, s.used_kb, s.free_kb, s.to_objects, s.to_frames, s.failures);
}

static void msleep(int ms)
{
	struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };

	nanosleep(&ts, NULL);
}

/* Touch one page every 2 MiB of a fresh mapping of `span` bytes: each
 * touch needs a page table (and a mapping slot) in the seL4 mirror. */
static long touch_sparse(unsigned long span)
{
	char *p = mmap(NULL, span, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
		       -1, 0);
	unsigned long off;
	long n = 0;

	if (p == MAP_FAILED)
		return -1;
	for (off = 0; off < span; off += 2 * MIB, n++)
		p[off] = 1;
	return n;
}

/* `nproc` processes, each touching `span` sparsely; they wait on a pipe
 * until told to exit.  Returns the write end. */
static int start_pressure(int nproc, unsigned long span, pid_t *pids)
{
	int go[2], ready[2], i;
	char c;

	if (pipe(go) || pipe(ready))
		return -1;
	for (i = 0; i < nproc; i++) {
		pids[i] = fork();
		if (pids[i] == 0) {
			close(go[1]);
			c = touch_sparse(span) > 0 ? 'y' : 'n';
			write(ready[1], &c, 1);
			read(go[0], &c, 1);
			_exit(0);
		}
	}
	close(go[0]);
	close(ready[1]);
	for (i = 0; i < nproc; i++) {
		CHECK(read(ready[0], &c, 1) == 1 && c == 'y', "pressure process %d failed", i);
	}
	close(ready[0]);
	return go[1];
}

static void stop_pressure(int fd, int nproc, pid_t *pids)
{
	int i, st;

	close(fd);
	for (i = 0; i < nproc; i++) {
		CHECK(waitpid(pids[i], &st, 0) == pids[i] && WIFEXITED(st) && !WEXITSTATUS(st),
		      "pressure process %d status %#x", i, st);
	}
}

/* Wait until L4hObjects is at most `kb` (blocks went back to frames). */
static int wait_objects_below(unsigned long kb, int ms)
{
	struct stats s;

	for (; ms > 0; ms -= 100) {
		read_stats(&s);
		if (s.objects_kb <= kb)
			return 1;
		msleep(100);
	}
	return 0;
}

#define NPROC 8

/* L4hObjects at boot: what object memory returns to when idle, give or
 * take the free blocks kept (reserve and watermark) and fragmentation. */
static unsigned long boot_objects_kb;

/* Leave one movable page in each physical 2 MiB block we touch, then
 * grow object memory with proactive compaction disabled and direct
 * compaction disabled by its fragmentation heuristic.  Synchronous
 * migration must rescue the allocation while most of RAM is free.
 * Check the retained pages after migration as well.
 */
static void test_fragmentation(void)
{
	const char *knobs[] = { "/proc/sys/vm/extfrag_threshold",
				"/proc/sys/vm/compaction_proactiveness" };
	const int values[] = { 1000, 0 };
	struct stats s0, s1;
	unsigned long bytes, pages, i, run, kept = 0;
	unsigned char *seen, *p;
	uint64_t *pfns;
	FILE *f;
	int fd, saved[2], nr_saved = 0, k, st, ret;
	pid_t pid;

	read_stats(&s0);
	bytes = s0.free_kb > 32768 ? (s0.free_kb - 32768) * 1024 : 0;
	pages = bytes / 4096;
	CHECK(pages > 0, "not enough RAM for fragmentation test");
	if (!pages)
		return;
	seen = calloc(s0.blocks, 1);
	pfns = malloc(pages * sizeof(*pfns));
	p = mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHECK(seen && pfns && p != MAP_FAILED, "fragmentation bookkeeping");
	if (!seen || !pfns || p == MAP_FAILED)
		goto out;
	for (k = 0; k < 2; k++) {
		f = fopen(knobs[k], "r");
		ret = f ? fscanf(f, "%d", &saved[k]) : 0;
		if (f)
			fclose(f);
		CHECK(ret == 1, "read %s", knobs[k]);
		if (ret != 1)
			goto restore;
		f = fopen(knobs[k], "w");
		ret = f ? fprintf(f, "%d\n", values[k]) : 0;
		if (f)
			fclose(f);
		CHECK(ret > 0, "set %s", knobs[k]);
		if (ret <= 0)
			goto restore;
		nr_saved++;
	}
	for (i = 0; i < pages; i++)
		p[i * 4096] = 0x5a;
	fd = open("/proc/self/pagemap", O_RDONLY);
	ret = fd >= 0 && pread(fd, pfns, pages * sizeof(*pfns),
			      (uintptr_t)p / 4096 * sizeof(*pfns)) == (ssize_t)(pages * sizeof(*pfns));
	if (fd >= 0)
		close(fd);
	CHECK(ret, "read pagemap");
	if (!ret)
		goto restore;
	/* Mark retained pages; release the rest in contiguous runs. */
	for (i = 0; i < pages; i++) {
		unsigned long b = (pfns[i] & ((1ull << 55) - 1)) / 512;

		pfns[i] = b < s0.blocks && !seen[b];
		if (pfns[i]) {
			seen[b] = 1;
			kept++;
		}
	}
	for (i = 0; i < pages;) {
		if (pfns[i]) {
			i++;
			continue;
		}
		run = i;
		while (i < pages && !pfns[i])
			i++;
		CHECK(!madvise(p + run * 4096, (i - run) * 4096, MADV_DONTNEED),
		      "discard fragmentation pages");
	}
	printf("OBJTEST: fragmented %lu physical blocks\n", kept);
	show("before fragmented pressure:");
	pid = fork();
	if (pid == 0)
		_exit(touch_sparse(16ul * 1024 * MIB) > 0 ? 0 : 1);
	CHECK(pid > 0 && waitpid(pid, &st, 0) == pid && WIFEXITED(st) && !WEXITSTATUS(st),
	      "object growth with fragmented free RAM failed");
	read_stats(&s1);
	CHECK(s1.contig_successes > s0.contig_successes, "synchronous migration was not exercised");
	CHECK(s1.migrated > s0.migrated, "no pages migrated under fragmentation");
	printf("OBJTEST: synchronous migrations %lu, attempts %lu\n",
	       s1.contig_successes - s0.contig_successes, s1.contig_attempts - s0.contig_attempts);
	for (i = 0; i < pages; i++)
		if (pfns[i])
			CHECK(p[i * 4096] == 0x5a, "migrated page contents at %lu", i);
restore:
	while (nr_saved) {
		k = --nr_saved;
		f = fopen(knobs[k], "w");
		CHECK(f != NULL, "restore %s", knobs[k]);
		if (f) {
			fprintf(f, "%d\n", saved[k]);
			fclose(f);
		}
	}
out:
	if (p != MAP_FAILED)
		munmap(p, bytes);
	free(pfns);
	free(seen);
}

static void test_pressure(unsigned long span, const char *label)
{
	struct stats s0, s1, s2;
	unsigned long need_kb = NPROC * (span / (2 * MIB)) * 4, idle_kb;
	pid_t pids[NPROC];
	int fd;

	read_stats(&s0);
	fd = start_pressure(NPROC, span, pids);
	read_stats(&s1);
	printf("OBJTEST: %s: %d processes x %lu page tables\n", label, NPROC, span / (2 * MIB));
	show("under page-table pressure:");
	/* 4 KiB per page table, all live at once: the objects must be there.
	 * Not checked against s0: page tables of an earlier round's
	 * processes may still be freed while this round builds its own. */
	CHECK(s1.used_kb >= need_kb && s1.objects_kb >= s1.used_kb,
	      "L4hObjectsUsed is %lu kB (%lu before), at least %lu expected",
	      s1.used_kb, s0.used_kb, need_kb);
	CHECK(s1.to_objects > 0, "no frame block became an object block");
	stop_pressure(fd, NPROC, pids);
	/* Back to what boot had, plus the free blocks kept and some
	 * fragmentation (chunks that long-lived objects pin). */
	idle_kb = boot_objects_kb + (s1.reserve_target + s1.spare_target) * 2048 + 16384;
	if (!wait_objects_below(idle_kb, 20000)) {
		read_stats(&s2);
		CHECK(0, "object blocks did not return to frame mode (%lu kB, at most %lu expected)",
		      s2.objects_kb, idle_kb);
	}
	show("after the processes exited:");
}

/* Maps sparse memory without end: must be killed by the OOM killer (or
 * see mmap fail), not hang or crash the guest. */
static void test_oom(void)
{
	struct stats before, s;
	pid_t pid;
	int st;

	show("before OOM:");
	read_stats(&before);
	pid = fork();
	if (pid == 0) {
		/* Each 2 MiB of span costs a page table and a page; dense
		 * enough to run out of RAM blocks, sparse enough that page
		 * tables, not pages, are most of it. */
		for (;;)
			if (touch_sparse(512 * MIB) < 0)
				pause();
	}
	CHECK(waitpid(pid, &st, 0) == pid, "waitpid");
	printf("OBJTEST: OOM: the hog %s\n",
	       WIFSIGNALED(st) ? (WTERMSIG(st) == SIGKILL ? "was killed (SIGKILL)" : "died of a signal")
			       : "exited");
	CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL, "hog status %#x", st);
	read_stats(&s);
	show("after OOM:");
	/* waitpid() must release the victim's seL4 page tables even while
	 * idle kernel threads or the OOM reaper still hold its mm.  Allow
	 * room for permanent objects and partially occupied chunks. */
	CHECK(s.used_kb <= before.used_kb + 4096,
	      "OOM victim retained object memory after waitpid (%lu kB used, %lu before)",
	      s.used_kb, before.used_kb);
}

static void test_mm_stress_during_conversions(unsigned long span)
{
	pid_t st_pid;
	int st, i;

	st_pid = fork();
	if (st_pid == 0) {
		for (i = 0; i < 5; i++) {
			pid_t p = fork();
			if (p == 0) {
				execl("/bin/selftest", "selftest", "smp_mm_stress", "smp_unmap_vis",
				      "smp_fork_storm", (char *)NULL);
				_exit(127);
			}
			if (waitpid(p, &st, 0) != p || !WIFEXITED(st) || WEXITSTATUS(st))
				_exit(1);
		}
		_exit(0);
	}
	for (i = 0; i < 3; i++)
		test_pressure(span, "with smp_mm_stress");
	CHECK(waitpid(st_pid, &st, 0) == st_pid && WIFEXITED(st) && !WEXITSTATUS(st),
	      "smp_mm_stress during conversions failed (%#x)", st);
	printf("OBJTEST: smp_mm_stress during conversions: %s\n", st == 0 ? "ok" : "FAILED");
}

int main(int argc, char **argv)
{
	unsigned long span = (argc > 1 ? strtoul(argv[1], NULL, 0) : 1024) * MIB;

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("OBJTEST: start (%ld CPUs)\n", sysconf(_SC_NPROCESSORS_ONLN));
	show("at boot:");
	{
		struct stats s;

		read_stats(&s);
		boot_objects_kb = s.objects_kb;
	}
	test_fragmentation();
	test_pressure(span, "page-table pressure");
	test_mm_stress_during_conversions(span);
	test_oom();
	/* Conversions still work after OOM. */
	test_pressure(span, "after OOM");
	{
		struct stats s;

		read_stats(&s);
		CHECK(s.to_objects > 0 && s.to_frames > 0, "blocks did not convert both ways");
	}

	if (failures)
		printf("OBJTEST: FAIL (%d)\n", failures);
	else
		printf("OBJTEST: PASS\n");
	return failures != 0;
}

// SPDX-License-Identifier: GPL-2.0-only
/* PMD THP with native seL4 large leaves and small-page fallback. Run with run-thptest.sh. */
#define _GNU_SOURCE
#include "thp.h"
#include "page-aging/page-aging.h"
#include <fcntl.h>
#include <linux/futex.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>

static long large_mappings(struct area a)
{
	struct aging_range r = { .start = (uintptr_t)a.p, .size = a.size };
	int fd = open("/dev/l4h_page_aging", O_RDONLY);
	long n;

	CHECK(fd >= 0, "missing mapping query module");
	n = ioctl(fd, L4H_LARGE_MAPPINGS, &r);
	close(fd);
	CHECK(n >= 0, "large mapping query: %s", strerror(errno));
	return n;
}

static void require_native(struct area a)
{
	for (size_t i = 0; i < a.size; i += HUGE)
		(void)*(volatile unsigned char *)(a.p + i);
	CHECK(large_mappings(a) == (long)(a.size / HUGE),
	      "expected %zu native 2 MiB leaves, got %ld", a.size / HUGE, large_mappings(a));
}

static void child_ok(pid_t pid)
{
	int status;

	CHECK(pid > 0 && waitpid(pid, &status, 0) == pid, "waitpid: %s", strerror(errno));
	CHECK(WIFEXITED(status) && !WEXITSTATUS(status), "child status %#x", status);
}

static void fill(struct area a)
{
	for (size_t i = 0; i < a.size / PAGE; i++)
		*(unsigned long *)(a.p + i * PAGE) = i + 1;
}

static void verify(struct area a)
{
	for (size_t i = 0; i < a.size / PAGE; i++)
		CHECK(*(unsigned long *)(a.p + i * PAGE) == i + 1, "page %zu changed", i);
}

static void fault_and_cow(void)
{
	struct area a = area_new(4 * HUGE, MADV_HUGEPAGE);
	struct rusage before, after;
	pid_t pid;

	getrusage(RUSAGE_SELF, &before);
	fill(a);
	getrusage(RUSAGE_SELF, &after);
	require_huge(a);
	require_native(a);
	CHECK(after.ru_minflt - before.ru_minflt < 16, "THP faulted %ld times",
	      after.ru_minflt - before.ru_minflt);
	pid = fork();
	if (!pid) {
		/* Both native writes and kernel user copies must COW tail pages. */
		int fd = open("/dev/zero", O_RDONLY);

		CHECK(fd >= 0, "open zero");
		CHECK(read(fd, a.p + HUGE + 127 * PAGE, PAGE) == PAGE, "read into COW THP");
		CHECK(!*(unsigned long *)(a.p + HUGE + 127 * PAGE), "kernel COW write lost");
		for (size_t i = 0; i < a.size / PAGE; i++)
			*(unsigned long *)(a.p + i * PAGE) = 0xabc000 + i;
		for (size_t i = 0; i < a.size / PAGE; i++)
			CHECK(*(unsigned long *)(a.p + i * PAGE) == 0xabc000 + i, "child page %zu", i);
		_exit(0);
	}
	child_ok(pid);
	verify(a);
	require_native(a);
	area_free(a);
}

static void zero_and_uaccess(void)
{
	struct area a = area_new(2 * HUGE, MADV_HUGEPAGE);
	volatile unsigned char *p = a.p;
	int fds[2];
	char buf[PAGE], copy[PAGE];
	uint32_t *word = (void *)(a.p + HUGE + 301 * PAGE);

	for (size_t i = 0; i < a.size; i += PAGE)
		CHECK(p[i] == 0, "zero page %zu", i / PAGE);
	/* A partial operation also splits the huge zero mapping. */
	CHECK(!mprotect(a.p + PAGE, PAGE, PROT_NONE), "protect zero tail");
	CHECK(!mprotect(a.p + PAGE, PAGE, PROT_READ | PROT_WRITE), "restore zero tail");
	p[PAGE] = 17;
	p[HUGE + 301 * PAGE] = 0;
	CHECK(p[0] == 0 && p[2 * PAGE] == 0 && p[PAGE] == 17, "zero alias changed");
	CHECK(!madvise(a.p, a.size, MADV_COLLAPSE), "collapse zero mapping: %s", strerror(errno));
	require_huge(a);
	require_native(a);
	memset(buf, 0xa5, sizeof(buf));
	CHECK(!pipe(fds), "pipe");
	CHECK(write(fds[1], buf, PAGE) == PAGE, "write pipe");
	/* Cross both a tail-page boundary and a PMD boundary. */
	CHECK(read(fds[0], a.p + HUGE - PAGE / 2, PAGE) == PAGE, "copy to THP");
	CHECK(write(fds[1], a.p + HUGE - PAGE / 2, PAGE) == PAGE, "copy from THP");
	CHECK(read(fds[0], copy, PAGE) == PAGE && !memcmp(copy, buf, PAGE), "user copy data");
	CHECK(syscall(SYS_futex, word, FUTEX_WAKE_OP, 1, 1, word,
		      FUTEX_OP(FUTEX_OP_ADD, 1, FUTEX_OP_CMP_EQ, 0)) >= 0, "futex wake op: %s", strerror(errno));
	CHECK(*word == 1, "futex tail-page write");
	require_huge(a);
	require_native(a);
	/* Pin a tail through the pipe, then split its PMD without moving data. */
	struct iovec iov = { .iov_base = a.p + HUGE - PAGE / 2, .iov_len = PAGE };
	CHECK(vmsplice(fds[1], &iov, 1, 0) == PAGE, "vmsplice: %s", strerror(errno));
	CHECK(!mprotect(a.p + HUGE - PAGE, PAGE, PROT_READ), "split pinned THP");
	CHECK(read(fds[0], copy, PAGE) == PAGE && !memcmp(copy, buf, PAGE), "pinned data changed");
	close(fds[0]);
	close(fds[1]);
	area_free(a);
}

static void vspace_eviction(void)
{
	/* The host's pool has at most 64 VSpaces. Keep more mms alive, then
	 * revisit huge PMDs whose software entries are already up to date. */
	enum { CHILDREN = 80 };
	struct area a = area_new(HUGE, MADV_HUGEPAGE);
	pid_t pids[CHILDREN];
	int ready[2], wake[2];
	char token = 0, tokens[CHILDREN] = { 0 };

	fill(a);
	require_huge(a);
	require_native(a);
	CHECK(!pipe(ready) && !pipe(wake), "eviction pipes");
	for (int i = 0; i < CHILDREN; i++) {
		pids[i] = fork();
		CHECK(pids[i] >= 0, "eviction fork: %s", strerror(errno));
		if (!pids[i]) {
			verify(a);
			require_native(a);
			CHECK(write(ready[1], &token, 1) == 1, "child ready");
			CHECK(read(wake[0], &token, 1) == 1, "child wake");
			verify(a);
			require_native(a);
			_exit(0);
		}
		CHECK(read(ready[0], &token, 1) == 1, "parent ready");
	}
	CHECK(write(wake[1], tokens, sizeof(tokens)) == sizeof(tokens), "wake children");
	for (int i = 0; i < CHILDREN; i++)
		child_ok(pids[i]);
	close(ready[0]);
	close(ready[1]);
	close(wake[0]);
	close(wake[1]);
	verify(a);
	area_free(a);
}

static void split_and_collapse(void)
{
	struct area a = area_new(2 * HUGE, MADV_NOHUGEPAGE);
	pid_t pid;
	int status;

	fill(a);
	CHECK(area_kb(a, "AnonHugePages:") == 0, "base mapping unexpectedly huge");
	CHECK(!madvise(a.p, a.size, MADV_HUGEPAGE), "advise");
	CHECK(!madvise(a.p, a.size, MADV_COLLAPSE), "collapse: %s", strerror(errno));
	require_huge(a);
	require_native(a);
	verify(a);
	CHECK(!mprotect(a.p + 277 * PAGE, PAGE, PROT_NONE), "partial PROT_NONE");
	CHECK(large_mappings(a) == 1, "partial protect failed to demote one leaf");
	pid = fork();
	if (!pid) {
		volatile unsigned char byte = a.p[277 * PAGE];
		(void)byte;
		_exit(1);
	}
	CHECK(pid > 0 && waitpid(pid, &status, 0) == pid && WIFSIGNALED(status) &&
	      WTERMSIG(status) == SIGSEGV, "PROT_NONE left a stale mapping: %#x", status);
	CHECK(!mprotect(a.p + 277 * PAGE, PAGE, PROT_READ | PROT_WRITE), "restore protection");
	verify(a);
	CHECK(!madvise(a.p, HUGE, MADV_COLLAPSE), "recollapse");
	CHECK(!madvise(a.p + 103 * PAGE, PAGE, MADV_DONTNEED), "partial discard");
	CHECK(!*(unsigned long *)(a.p + 103 * PAGE), "discard left a stale mapping");
	*(unsigned long *)(a.p + 103 * PAGE) = 104;
	verify(a);
	CHECK(!munmap(a.p + HUGE + 89 * PAGE, PAGE), "partial unmap");
	CHECK(mmap(a.p + HUGE + 89 * PAGE, PAGE, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == a.p + HUGE + 89 * PAGE, "remap hole");
	CHECK(!*(unsigned long *)(a.p + HUGE + 89 * PAGE), "remapped hole retained data");
	*(unsigned long *)(a.p + HUGE + 89 * PAGE) = HUGE / PAGE + 90;
	verify(a);
	area_free(a);
}

static void move_and_background_collapse(void)
{
	struct area a = area_new(2 * HUGE, MADV_NOHUGEPAGE);
	struct area b = area_new(a.size, MADV_NOHUGEPAGE);

	fill(a);
	CHECK(!madvise(a.p, a.size, MADV_HUGEPAGE), "advise background collapse");
	for (int i = 0; i < 2000 && area_kb(a, "AnonHugePages:") < a.size / 1024; i++)
		usleep(10000);
	require_huge(a);
	require_native(a);
	CHECK(mremap(a.p, a.size, a.size, MREMAP_MAYMOVE | MREMAP_FIXED, b.p) == b.p,
	      "move huge mapping: %s", strerror(errno));
	require_huge(b);
	verify(b);
	area_free(a);
	area_free(b);
}

static void swap_roundtrip(void)
{
	struct area a = area_new(8 * HUGE, MADV_HUGEPAGE);
	struct rusage before, after;

	fill(a);
	require_huge(a);
	require_native(a);
	CHECK(!madvise(a.p, a.size, MADV_PAGEOUT), "pageout: %s", strerror(errno));
	/* Let asynchronous swap writes complete before checking residency. */
	for (int i = 0; i < 200 && !area_kb(a, "Swap:"); i++)
		usleep(10000);
	CHECK(area_kb(a, "Swap:") > 0, "pageout did not swap any THP data");
	getrusage(RUSAGE_SELF, &before);
	verify(a);
	getrusage(RUSAGE_SELF, &after);
	/* Swap-cache hits are minor faults; either path must replace the swap
	 * PTEs rather than reaching stale seL4 mappings. */
	CHECK(after.ru_minflt + after.ru_majflt > before.ru_minflt + before.ru_majflt,
	      "swap-in did not fault");
	CHECK(!area_kb(a, "Swap:"), "swap entries remain after reading every page");
	area_free(a);
}

static void execute_permissions(void)
{
	struct area a = area_new(HUGE, MADV_HUGEPAGE);
	void *code = a.p + HUGE - PAGE;
	int (*fn)(void) = code;
	int status;
	pid_t pid;
#ifdef __aarch64__
	const uint32_t insns[] = { 0x52800540, 0xd65f03c0 }; /* mov w0, #42; ret */
#else
	const unsigned char insns[] = { 0xb8, 42, 0, 0, 0, 0xc3 }; /* mov eax, 42; ret */
#endif

	memcpy(code, insns, sizeof(insns));
	require_huge(a);
	require_native(a);
	pid = fork();
	if (!pid)
		_exit(fn());
	CHECK(pid > 0 && waitpid(pid, &status, 0) == pid && WIFSIGNALED(status) &&
	      WTERMSIG(status) == SIGSEGV, "large NX mapping executable: %#x", status);
	CHECK(!mprotect(a.p, a.size, PROT_READ | PROT_EXEC), "executable PMD");
	CHECK(fn() == 42, "execute from tail page");
	require_native(a);
	CHECK(!mprotect(code, PAGE, PROT_READ), "remove execute from tail");
	pid = fork();
	if (!pid)
		_exit(fn());
	CHECK(pid > 0 && waitpid(pid, &status, 0) == pid && WIFSIGNALED(status) &&
	      WTERMSIG(status) == SIGSEGV, "execute permission survived split: %#x", status);
	area_free(a);
}

static void shared_memory(void)
{
	struct area a = area_new(2 * HUGE, MADV_HUGEPAGE);
	int fd = memfd_create("thptest", 0);
	pid_t pid;

	CHECK(fd >= 0 && !ftruncate(fd, a.size), "memfd");
	CHECK(mmap(a.p, a.size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0) == a.p,
	      "shared mapping");
	CHECK(!madvise(a.p, a.size, MADV_HUGEPAGE), "shared advice");
	fill(a);
	CHECK(!madvise(a.p, a.size, MADV_COLLAPSE), "shared collapse: %s", strerror(errno));
	CHECK(area_kb(a, "ShmemPmdMapped:") == a.size / 1024, "shared PMD mapping missing");
	require_native(a);
	pid = fork();
	if (!pid) {
		*(unsigned long *)(a.p + 271 * PAGE) = 99;
		_exit(0);
	}
	child_ok(pid);
	CHECK(*(unsigned long *)(a.p + 271 * PAGE) == 99, "shared child write lost");
	*(unsigned long *)(a.p + 271 * PAGE) = 272;
	CHECK(!fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 89 * PAGE, PAGE),
	      "punch shared tail: %s", strerror(errno));
	CHECK(!*(unsigned long *)(a.p + 89 * PAGE), "shared hole retained data");
	*(unsigned long *)(a.p + 89 * PAGE) = 90;
	verify(a);
	close(fd);
	area_free(a);
}

struct writer {
	unsigned long *word;
	unsigned long count;
};
static atomic_int stop;

static void *write_worker(void *arg)
{
	struct writer *w = arg;

	while (!atomic_load_explicit(&stop, memory_order_relaxed)) {
		__atomic_fetch_add(w->word, 1, __ATOMIC_RELAXED);
		w->count++;
	}
	return NULL;
}

static void concurrent_split(void)
{
	struct area a = area_new(2 * HUGE, MADV_HUGEPAGE);
	struct writer writers[2] = { { .word = (void *)(a.p + PAGE) },
				     { .word = (void *)(a.p + HUGE + PAGE) } };
	pthread_t threads[2];

	memset(a.p, 0, a.size);
	require_huge(a);
	require_native(a);
	for (int i = 0; i < 2; i++)
		CHECK(!pthread_create(&threads[i], NULL, write_worker, &writers[i]), "pthread_create");
	for (int round = 0; round < 40; round++) {
		CHECK(!mprotect(a.p + 7 * PAGE, PAGE, PROT_READ), "split under writes");
		CHECK(!mprotect(a.p + 7 * PAGE, PAGE, PROT_READ | PROT_WRITE), "restore under writes");
		CHECK(!madvise(a.p, a.size, MADV_COLLAPSE), "collapse under writes: %s", strerror(errno));
	}
	atomic_store(&stop, 1);
	for (int i = 0; i < 2; i++) {
		pthread_join(threads[i], NULL);
		CHECK(writers[i].count && *writers[i].word == writers[i].count,
		      "writer %d lost updates: %lu / %lu", i, *writers[i].word, writers[i].count);
	}
	require_huge(a);
	require_native(a);
	area_free(a);
}

static int sample(int fd, struct area a)
{
	struct aging_range r = { .start = (uintptr_t)a.p, .size = a.size };
	return ioctl(fd, L4H_AGING_SAMPLE, &r);
}

static void aging(void)
{
	struct area a = area_new(HUGE, MADV_HUGEPAGE);
	int fd = open("/dev/l4h_page_aging", O_RDONLY);
	volatile unsigned long sum = 0;
	struct rusage before, after;

	CHECK(fd >= 0, "missing page-aging module");
	fill(a);
	require_huge(a);
	require_native(a);
	CHECK(sample(fd, a) == HUGE / PAGE, "initial PMD young bit");
	CHECK(sample(fd, a) == 0, "PMD access counted twice");
	/* A/AF clearing intentionally permits cached translations to delay
	 * the next sample. Invalidate this translation without accessing it:
	 * churning 4 KiB mappings need not evict a separate huge-page TLB. */
	CHECK(!mprotect(a.p, a.size, PROT_READ), "aging write protect");
	CHECK(!mprotect(a.p, a.size, PROT_READ | PROT_WRITE), "aging restore rights");
	CHECK(sample(fd, a) >= 0 && sample(fd, a) == 0, "aging rearm");
	getrusage(RUSAGE_SELF, &before);
	sum += *(volatile unsigned long *)(a.p + 409 * PAGE);
	getrusage(RUSAGE_SELF, &after);
	CHECK(sample(fd, a) == HUGE / PAGE, "hardware access to tail page not sampled");
	CHECK(sample(fd, a) == 0, "hardware access not cleared");
	CHECK(after.ru_minflt == before.ru_minflt, "aging caused a guest fault");
	/* MADV_FREE clears dirty state. Native and kernel writes must restore it. */
	CHECK(!madvise(a.p, a.size, MADV_FREE), "MADV_FREE");
	a.p[203 * PAGE] = 71;
	int zero = open("/dev/zero", O_RDONLY);
	CHECK(zero >= 0 && read(zero, a.p + 311 * PAGE, PAGE) == PAGE, "write after MADV_FREE");
	CHECK(a.p[203 * PAGE] == 71 && !a.p[311 * PAGE], "dirty tracking lost a write");
	close(zero);
	close(fd);
	area_free(a);
}

int main(int argc, char **argv)
{
	setbuf(stdout, NULL);
	CHECK(sysconf(_SC_PAGESIZE) == PAGE, "requires 4 KiB base pages");
	if (argc > 1 && !strcmp(argv[1], "--fallback")) {
		/* Run in a memcg too small to charge a 2 MiB folio. */
		struct area a = area_new(HUGE, MADV_HUGEPAGE);

		a.p[17 * PAGE] = 42;
		CHECK(a.p[17 * PAGE] == 42 && !area_kb(a, "AnonHugePages:"), "allocation fallback");
		CHECK(!large_mappings(a), "fallback installed a large leaf");
		area_free(a);
		puts("THPTEST: fallback PASS");
		return 0;
	}
#define RUN(fn) do { printf("THPTEST: %s\n", #fn); fn(); } while (0)
	RUN(fault_and_cow);
	RUN(zero_and_uaccess);
	RUN(vspace_eviction);
	RUN(split_and_collapse);
	RUN(move_and_background_collapse);
	RUN(concurrent_split);
	RUN(aging);
	RUN(swap_roundtrip);
	RUN(execute_permissions);
	RUN(shared_memory);
	puts("THPTEST: PASS");
	return 0;
}

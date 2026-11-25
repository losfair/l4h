// Concurrent Linux workloads and pinned IPC latency for run-smpbench.py.
#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/futex.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAX_WORKERS 256
#define PAGE_BYTES 4096

static unsigned workers, divisor = 1;
static int cpus[MAX_WORKERS];
static const char *phase;

static void fail(const char *what)
{
	fprintf(stderr, "SMPBENCH: FAIL %s: %s\n", what, strerror(errno));
	exit(1);
}

static void check(int ok, const char *what)
{
	if (!ok)
		fail(what);
}

static uint64_t now(void)
{
	struct timespec ts;
	check(clock_gettime(CLOCK_MONOTONIC, &ts) == 0, "clock_gettime");
	return (uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

static void pin(unsigned cpu)
{
	cpu_set_t set;
	CPU_ZERO(&set);
	CPU_SET(cpus[cpu], &set);
	check(sched_setaffinity(0, sizeof(set), &set) == 0, "sched_setaffinity");
	check(sched_getcpu() == cpus[cpu], "CPU placement");
}

static void transfer(int fd, void *buf, size_t n, int writing)
{
	while (n) {
		ssize_t done = writing ? write(fd, buf, n) : read(fd, buf, n);
		if (done < 0 && errno == EINTR)
			continue;
		check(done > 0, writing ? "write" : "read");
		buf = (char *)buf + done;
		n -= done;
	}
}

static void reap(pid_t pid)
{
	int status;
	check(waitpid(pid, &status, 0) == pid, "waitpid");
	check(WIFEXITED(status) && WEXITSTATUS(status) == 0, "worker status");
}

/* Results wait for the end of the run: the host writes console output to
 * the serial port slowly (about 23 KB/s) and through the microkernel, and a
 * result line printed between phases is still draining during the next
 * one, slowing every vCPU's syscalls. */
static char results[8192];
static size_t results_len;

static void report(const char *metric, uint64_t elapsed, uint64_t ops,
		   const char *unit, int latency, uint64_t checksum)
{
	check(elapsed > 0, "elapsed time");
	double value = latency ? (double)elapsed / ops / 1000.0 :
		(double)ops * 1e9 / elapsed;
	int n = snprintf(results + results_len, sizeof(results) - results_len,
			 "SMPBENCH: phase=%s metric=%s workers=%u value=%.6f unit=%s "
			 "elapsed_ns=%" PRIu64 " operations=%" PRIu64 " checksum=%" PRIu64 "\n",
			 phase, metric, workers, value, unit, elapsed, ops, checksum);
	check(n > 0 && (size_t)n < sizeof(results) - results_len, "result buffer");
	results_len += n;
}

enum workload { COMPUTE, SYSCALL, FAULT, FORK };

struct result {
	uint64_t start, end, checksum;
};

static void parallel(enum workload work, const char *name, uint64_t count)
{
	struct result *results = mmap(NULL, sizeof(*results) * workers,
		PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	check(results != MAP_FAILED, "results mmap");
	pid_t pids[MAX_WORKERS];
	int gate[MAX_WORKERS][2], ready[2];
	check(pipe(ready) == 0, "ready pipe");
	char token = 1;
	/* Separate address spaces; one worker on each guest CPU. Allocation,
	 * fork, readiness, validation and cleanup are outside the timed work. */
	for (unsigned i = 0; i < workers; i++) {
		check(pipe(gate[i]) == 0, "gate pipe");
		pids[i] = fork();
		check(pids[i] >= 0, "worker fork");
		if (pids[i] != 0) {
			close(gate[i][0]);
			continue;
		}
		pin(i);
		close(gate[i][1]);
		close(ready[0]);
		for (unsigned j = 0; j < i; j++)
			close(gate[j][1]);
		volatile unsigned char *pages = NULL;
		if (work == FAULT) {
			pages = mmap(NULL, count * PAGE_BYTES, PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			check(pages != MAP_FAILED, "fault mmap");
			/* EINVAL: a kernel without THP, so no huge pages anyway. */
			check(madvise((void *)pages, count * PAGE_BYTES, MADV_NOHUGEPAGE) == 0 ||
			      errno == EINVAL, "MADV_NOHUGEPAGE");
		}
		pid_t self = getpid();
		uint64_t checksum = 1;
		transfer(ready[1], &token, 1, 1);
		transfer(gate[i][0], &token, 1, 0);
		results[i].start = now();
		switch (work) {
		case COMPUTE:
			for (uint64_t j = 0; j < count; j++) {
				checksum ^= checksum << 13;
				checksum ^= checksum >> 7;
				checksum ^= checksum << 17;
			}
			break;
		case SYSCALL:
			for (uint64_t j = 0; j < count; j++)
				check(syscall(SYS_getpid) == self, "getpid result");
			checksum = count;
			break;
		case FAULT:
			for (uint64_t j = 0; j < count; j++)
				pages[j * PAGE_BYTES] = (j % 251) + 1;
			checksum = count;
			break;
		case FORK:
			for (uint64_t j = 0; j < count; j++) {
				pid_t child = fork();
				check(child >= 0, "timed fork");
				if (!child)
					_exit(0);
				reap(child);
			}
			checksum = count;
			break;
		}
		results[i].end = now();
		results[i].checksum = checksum;
		if (pages) {
			for (uint64_t j = 0; j < count; j++)
				check(pages[j * PAGE_BYTES] == (j % 251) + 1, "fault data");
			check(munmap((void *)pages, count * PAGE_BYTES) == 0, "fault munmap");
		}
		check(sched_getcpu() == cpus[i], "worker migrated");
		_exit(0);
	}
	close(ready[1]);
	for (unsigned i = 0; i < workers; i++)
		transfer(ready[0], &token, 1, 0);
	for (unsigned i = 0; i < workers; i++) {
		transfer(gate[i][1], &token, 1, 1);
		close(gate[i][1]);
	}
	uint64_t start = UINT64_MAX, end = 0;
	for (unsigned i = 0; i < workers; i++) {
		reap(pids[i]);
		check(results[i].end > results[i].start, "worker timing");
		check(results[i].checksum == results[0].checksum && results[i].checksum,
		      "worker checksum");
		if (results[i].start < start)
			start = results[i].start;
		if (results[i].end > end)
			end = results[i].end;
	}
	report(name, end - start, count * workers, "ops/s", 0, results[0].checksum);
	close(ready[0]);
	munmap(results, sizeof(*results) * workers);
}

static void pipe_pingpong(unsigned peer, uint64_t rounds)
{
	int a[2], b[2];
	check(pipe(a) == 0 && pipe(b) == 0, "pingpong pipes");
	pid_t child = fork();
	check(child >= 0, "pipe fork");
	char token = 1;
	if (!child) {
		pin(peer);
		close(a[1]);
		close(b[0]);
		for (uint64_t i = 0; i < rounds + 100; i++) {
			transfer(a[0], &token, 1, 0);
			transfer(b[1], &token, 1, 1);
		}
		_exit(0);
	}
	close(a[0]);
	close(b[1]);
	uint64_t start = 0;
	for (uint64_t i = 0; i < rounds + 100; i++) {
		if (i == 100)
			start = now();
		transfer(a[1], &token, 1, 1);
		transfer(b[0], &token, 1, 0);
	}
	uint64_t elapsed = now() - start;
	reap(child);
	close(a[1]);
	close(b[0]);
	report(peer ? "pipe_cross" : "pipe_same", elapsed, rounds, "us/roundtrip", 1, token);
}

static void futex_wake(_Atomic uint32_t *word)
{
	check(syscall(SYS_futex, word, FUTEX_WAKE, 1, NULL, NULL, 0) >= 0, "futex wake");
}

static void futex_wait_for(_Atomic uint32_t *word, uint32_t wanted)
{
	while (atomic_load_explicit(word, memory_order_acquire) != wanted) {
		int ret = syscall(SYS_futex, word, FUTEX_WAIT, wanted ^ 1, NULL, NULL, 0);
		check(ret == 0 || errno == EAGAIN || errno == EINTR, "futex wait");
	}
}

static void futex_pingpong(unsigned peer, uint64_t rounds)
{
	_Atomic uint32_t *turn = mmap(NULL, PAGE_BYTES, PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	check(turn != MAP_FAILED, "futex mmap");
	atomic_init(turn, 0);
	pid_t child = fork();
	check(child >= 0, "futex fork");
	if (!child) {
		pin(peer);
		for (uint64_t i = 0; i < rounds + 100; i++) {
			futex_wait_for(turn, 1);
			atomic_store_explicit(turn, 0, memory_order_release);
			futex_wake(turn);
		}
		_exit(0);
	}
	uint64_t start = 0;
	for (uint64_t i = 0; i < rounds + 100; i++) {
		if (i == 100)
			start = now();
		atomic_store_explicit(turn, 1, memory_order_release);
		futex_wake(turn);
		futex_wait_for(turn, 0);
	}
	uint64_t elapsed = now() - start;
	reap(child);
	munmap(turn, PAGE_BYTES);
	report(peer ? "futex_cross" : "futex_same", elapsed, rounds, "us/roundtrip", 1, 1);
}

static unsigned number(const char *s, unsigned maximum)
{
	char *end;
	errno = 0;
	unsigned long n = strtoul(s, &end, 10);
	check(!errno && *s && !*end && n > 0 && n <= maximum, "argument");
	return n;
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	check(argc >= 2 && argc <= 3, "usage: smpbench workers [divisor:1..100]");
	workers = number(argv[1], MAX_WORKERS);
	if (argc == 3)
		divisor = number(argv[2], 100);
	alarm(180);
	cpu_set_t available;
	check(sched_getaffinity(0, sizeof(available), &available) == 0, "getaffinity");
	unsigned found = 0;
	for (int i = 0; i < CPU_SETSIZE && found < workers; i++)
		if (CPU_ISSET(i, &available))
			cpus[found++] = i;
	check(found == workers, "available CPUs");
	printf("SMPBENCH: start workers=%u divisor=%u cpus=", workers, divisor);
	for (unsigned i = 0; i < workers; i++)
		printf("%s%d", i ? "," : "", cpus[i]);
	puts("");
	pin(0);
	for (int pass = 0; pass < 2; pass++) {
		phase = pass ? "measured" : "warmup";
		parallel(COMPUTE, "compute", 200000000 / divisor);
		parallel(SYSCALL, "getpid", 200000 / divisor);
		parallel(FAULT, "fault_4k", 8192 / divisor);
		parallel(FORK, "fork_wait", 200 / divisor);
		pipe_pingpong(0, 10000 / divisor);
		futex_pingpong(0, 10000 / divisor);
		if (workers > 1) {
			pipe_pingpong(1, 10000 / divisor);
			futex_pingpong(1, 10000 / divisor);
		}
	}
	fputs(results, stdout);
	puts("SMPBENCH: done");
	return 0;
}

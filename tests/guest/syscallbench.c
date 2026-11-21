// Guest syscall latency for tests/gce-bench.sh: getpid round trips on 1..N
// pinned threads (one process each), the median of several repetitions.
#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CALLS 200000
#define REPS 7
#define MAX_CPUS 64

static void check(int ok, const char *what)
{
	if (!ok) {
		fprintf(stderr, "SYSCALLBENCH: FAIL %s: %s\n", what, strerror(errno));
		exit(1);
	}
}

static uint64_t now(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

static int cmp(const void *a, const void *b)
{
	double x = *(const double *)a, y = *(const double *)b;
	return (x > y) - (x < y);
}

/* ns per getpid on each of `threads` processes pinned to CPUs 0..threads-1;
 * the slowest process's figure. */
static double run(unsigned threads, volatile uint64_t *slots)
{
	volatile uint64_t *go = &slots[MAX_CPUS];
	*go = 0;
	for (unsigned i = 0; i < threads; i++)
		slots[i] = 0;
	pid_t pids[MAX_CPUS];
	for (unsigned i = 0; i < threads; i++) {
		pids[i] = fork();
		check(pids[i] >= 0, "fork");
		if (pids[i])
			continue;
		cpu_set_t set;
		CPU_ZERO(&set);
		CPU_SET(i, &set);
		check(sched_setaffinity(0, sizeof(set), &set) == 0, "affinity");
		__atomic_fetch_add(go, 1, __ATOMIC_SEQ_CST);
		while (__atomic_load_n(go, __ATOMIC_ACQUIRE) < threads)
			;
		uint64_t t = now();
		for (int j = 0; j < CALLS; j++)
			syscall(SYS_getpid);
		slots[i] = now() - t;
		_exit(0);
	}
	uint64_t worst = 0;
	for (unsigned i = 0; i < threads; i++) {
		int status;
		check(waitpid(pids[i], &status, 0) == pids[i] && WIFEXITED(status) &&
		      !WEXITSTATUS(status), "worker");
		if (slots[i] > worst)
			worst = slots[i];
	}
	return (double)worst / CALLS;
}

int main(void)
{
	setvbuf(stdout, NULL, _IOLBF, 0);
	unsigned cpus = sysconf(_SC_NPROCESSORS_ONLN);
	check(cpus > 0 && cpus <= MAX_CPUS, "CPU count");
	volatile uint64_t *slots = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	check(slots != MAP_FAILED, "mmap");
	char out[4096];
	size_t len = 0;
	run(1, slots); /* warm up */
	for (unsigned threads = 1; threads <= cpus; threads *= 2) {
		double v[REPS];
		for (int r = 0; r < REPS; r++)
			v[r] = run(threads, slots);
		qsort(v, REPS, sizeof(v[0]), cmp);
		len += snprintf(out + len, sizeof(out) - len,
			"SYSCALLBENCH: getpid threads=%u median_ns=%.1f min_ns=%.1f max_ns=%.1f\n",
			threads, v[REPS / 2], v[0], v[REPS - 1]);
		if (threads < cpus && threads * 2 > cpus)
			threads = cpus / 2; /* end on all CPUs */
	}
	fputs(out, stdout);
	return 0;
}

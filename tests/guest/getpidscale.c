// Quick guest syscall scaling probe: for each CPU range argument ("a-b"),
// one process pinned to each CPU in it calls getpid for a fixed time
// (GETPIDSCALE_MS, default 1000 ms); prints the total rate and the
// slowest process's ns per call.  Each range takes about that long, so a
// probe of a handful of ranges stays well under 30 s.
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

#define MAX_CPUS 64

struct slot {
	uint64_t calls, ns;
	char pad[48];
};

static uint64_t now(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

int main(int argc, char **argv)
{
	uint64_t ms = getenv("GETPIDSCALE_MS") ? strtoull(getenv("GETPIDSCALE_MS"), 0, 0) : 1000;
	struct slot *slots = mmap(0, sizeof(struct slot) * (MAX_CPUS + 1), PROT_READ | PROT_WRITE,
				  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (slots == MAP_FAILED)
		return 1;
	volatile uint64_t *go = &slots[MAX_CPUS].calls;
	for (int r = 1; r < argc; r++) {
		unsigned a, b;
		if (sscanf(argv[r], "%u-%u", &a, &b) != 2) {
			if (sscanf(argv[r], "%u", &a) != 1)
				return 2;
			b = a;
		}
		if (b >= MAX_CPUS || a > b)
			return 2;
		unsigned n = b - a + 1;
		*go = 0;
		pid_t pids[MAX_CPUS];
		for (unsigned i = 0; i < n; i++) {
			pids[i] = fork();
			if (pids[i] < 0) {
				perror("fork");
				return 1;
			}
			if (pids[i])
				continue;
			cpu_set_t set;
			CPU_ZERO(&set);
			CPU_SET(a + i, &set);
			if (sched_setaffinity(0, sizeof(set), &set))
				_exit(1);
			__atomic_fetch_add(go, 1, __ATOMIC_SEQ_CST);
			while (__atomic_load_n(go, __ATOMIC_ACQUIRE) < n)
				;
			uint64_t t0 = now(), t = t0, end = t0 + ms * 1000000, c = 0;
			while (t < end) {
				for (int k = 0; k < 256; k++)
					syscall(SYS_getpid);
				c += 256;
				t = now();
			}
			slots[i].calls = c;
			slots[i].ns = t - t0;
			_exit(0);
		}
		int ok = 1;
		for (unsigned i = 0; i < n; i++) {
			int st;
			waitpid(pids[i], &st, 0);
			ok = ok && WIFEXITED(st) && WEXITSTATUS(st) == 0;
		}
		double total = 0, worst = 0;
		for (unsigned i = 0; i < n; i++) {
			double per = (double)slots[i].ns / (double)slots[i].calls;
			total += (double)slots[i].calls * 1e9 / (double)slots[i].ns;
			if (per > worst)
				worst = per;
		}
		printf("GETPIDSCALE: cpus=%u-%u n=%u total_ops=%.0f worst_ns=%.1f%s\n", a, b, n, total, worst,
		       ok ? "" : " FAIL");
		fflush(stdout);
	}
	return 0;
}

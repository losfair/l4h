// Fork scaling probe: for each worker count argument, one process pinned
// to each of CPUs 0..n-1 forks a child that exits at once and waits for
// it, for FORKSCALE_MS (default 2000 ms); prints the total rate.  Long
// enough per count for a hypervisor's once-a-second counters.
#define _GNU_SOURCE
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAX_CPUS 64

static uint64_t now(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

int main(int argc, char **argv)
{
	uint64_t ms = getenv("FORKSCALE_MS") ? strtoull(getenv("FORKSCALE_MS"), 0, 0) : 2000;
	volatile uint64_t *slot = mmap(0, 64 * (MAX_CPUS + 1), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (slot == MAP_FAILED)
		return 1;
	setvbuf(stdout, NULL, _IONBF, 0);
	for (int a = 1; a < argc; a++) {
		int n = atoi(argv[a]);
		if (n < 1 || n > MAX_CPUS)
			return 2;
		for (int i = 0; i <= n; i++)
			slot[i * 8] = 0;
		printf("FORKSCALE: start n=%d\n", n);
		uint64_t t0 = now();
		for (int i = 0; i < n; i++) {
			if (fork() == 0) {
				cpu_set_t set;
				CPU_ZERO(&set);
				CPU_SET(i, &set);
				if (sched_setaffinity(0, sizeof(set), &set))
					_exit(3);
				uint64_t end = t0 + ms * 1000000, c = 0;
				while (now() < end) {
					pid_t p = fork();
					if (p == 0)
						_exit(0);
					if (p < 0 || waitpid(p, 0, 0) != p)
						_exit(4);
					c++;
				}
				slot[i * 8] = c;
				_exit(0);
			}
		}
		int ok = 1, st;
		for (int i = 0; i < n; i++)
			if (wait(&st) < 0 || !WIFEXITED(st) || WEXITSTATUS(st))
				ok = 0;
		uint64_t total = 0;
		for (int i = 0; i < n; i++)
			total += slot[i * 8];
		double secs = (now() - t0) / 1e9;
		printf("FORKSCALE: n=%d forks_per_s=%.0f %s\n", n, total / secs, ok ? "ok" : "FAIL");
		if (!ok)
			return 1;
	}
	return 0;
}

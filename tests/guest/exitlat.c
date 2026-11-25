// VM exit round trip from guest user mode: CPUID (always an exit under
// a hypervisor) on each CPU of a list, in a loop; prints ns per CPUID.
#define _GNU_SOURCE
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static uint64_t now(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

int main(int argc, char **argv)
{
	for (int a = 1; a < argc; a++) {
		int cpu = atoi(argv[a]);
		cpu_set_t set;
		CPU_ZERO(&set);
		CPU_SET(cpu, &set);
		if (sched_setaffinity(0, sizeof(set), &set))
			return 1;
		for (int leaf = 0; leaf <= 1; leaf++) {
			unsigned n = 20000, best = ~0u;
			for (int rep = 0; rep < 5; rep++) {
				uint64_t t0 = now();
				for (unsigned i = 0; i < n; i++) {
					unsigned eax = leaf, ebx, ecx = 0, edx;
					__asm__ volatile("cpuid" : "+a"(eax), "=b"(ebx), "+c"(ecx), "=d"(edx));
				}
				unsigned ns = (now() - t0) / n;
				if (ns < best)
					best = ns;
			}
			printf("EXITLAT: cpu=%d cpuid_leaf=%d ns=%u\n", cpu, leaf, best);
		}
	}
	return 0;
}

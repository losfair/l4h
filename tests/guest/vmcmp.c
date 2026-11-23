// CPU, memory and TLB micro-benchmarks for tests/run-hvmbench.sh, run
// alike in a PV and an HVM guest (with tests/guest/bench.c).
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <sys/syscall.h>
#include <unistd.h>

static double now(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static void report(const char *what, double v, const char *unit)
{
	printf("BENCH: %-22s %10.2f %s\n", what, v, unit);
}

/* Pure ALU work: no exits, no memory traffic. */
static void bench_alu(void)
{
	uint64_t x = 88172645463325252ull, n = 20000000;
	double t = now();
	for (uint64_t i = 0; i < n; i++) {
		x ^= x << 13;
		x ^= x >> 7;
		x ^= x << 17;
	}
	report("alu xorshift", (now() - t) / n * 1e9, "ns/iter");
	if (x == 42)
		puts("");
}

/* Streaming bandwidth over 64 MiB (memcpy). */
static void bench_memcpy(void)
{
	size_t sz = 64 << 20;
	char *a = malloc(sz), *b = malloc(sz);
	memset(a, 1, sz);
	memset(b, 2, sz);
	int reps = 4;
	double t = now();
	for (int i = 0; i < reps; i++) {
		memcpy(i & 1 ? a : b, i & 1 ? b : a, sz);
		/* The copies are otherwise dead stores into freed memory. */
		__asm__ volatile("" : : "r"(a), "r"(b) : "memory");
	}
	report("memcpy 64 MiB", (double)sz * reps / (now() - t) / 1e6, "MB/s");
	free(a);
	free(b);
}

/* Dependent loads, one per 4 KiB page, over `mb` MiB: TLB misses, where
 * a two-dimensional (EPT/NPT) walk costs more than a native one. */
static void bench_chase(size_t mb, int huge)
{
	size_t sz = mb << 20, pages = sz / 4096;
	char *p = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED)
		return;
	madvise(p, sz, huge ? MADV_HUGEPAGE : MADV_NOHUGEPAGE);
	size_t *perm = malloc(pages * sizeof(*perm));
	for (size_t i = 0; i < pages; i++)
		perm[i] = i;
	srand(1);
	for (size_t i = pages - 1; i > 0; i--) {
		size_t j = ((size_t)rand() << 16 ^ rand()) % (i + 1), t = perm[i];
		perm[i] = perm[j];
		perm[j] = t;
	}
	/* A cycle through every page, at a varying line in each. */
	for (size_t i = 0; i < pages; i++) {
		size_t from = perm[i] * 4096 + (perm[i] % 64) * 64;
		size_t to = perm[(i + 1) % pages] * 4096 + (perm[(i + 1) % pages] % 64) * 64;
		*(char **)(p + from) = p + to;
	}
	char **q = (char **)(p + perm[0] * 4096 + (perm[0] % 64) * 64);
	free(perm);
	size_t n = 1000000;
	for (size_t i = 0; i < pages; i++) /* warm */
		q = (char **)*q;
	double t = now();
	for (size_t i = 0; i < n; i++)
		q = (char **)*q;
	char name[40];
	snprintf(name, sizeof(name), "chase %zu MiB %s", mb, huge ? "2M" : "4K");
	report(name, (now() - t) / n * 1e9, "ns/load");
	if (!q)
		puts("");
	munmap(p, sz);
}

/* clock_gettime(CLOCK_MONOTONIC): the vDSO, if the clocksource allows. */
static void bench_clock(void)
{
	int n = 1000000;
	struct timespec ts;
	double t = now();
	for (int i = 0; i < n; i++)
		clock_gettime(CLOCK_MONOTONIC, &ts);
	report("clock_gettime", (now() - t) / n * 1e9, "ns");
}

/* CPUID: always an exit (to L0 under nesting; to the VMM in HVM). */
static void bench_cpuid(void)
{
	int n = 5000;
	unsigned a, b, c, d;
	double t = now();
	for (int i = 0; i < n; i++)
		__asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(0), "c"(0));
	report("cpuid (exit)", (now() - t) / n * 1e9, "ns");
}

/* getpid in the best of 100 chunks of 2000 calls: without interrupts
 * and exits in the background (the mean has them). */
static void bench_getpid_best(void)
{
	double best = 1e9;
	for (int c = 0; c < 100; c++) {
		double t = now();
		for (int i = 0; i < 2000; i++)
			syscall(SYS_getpid);
		double d = (now() - t) / 2000;
		if (d < best)
			best = d;
	}
	report("getpid (best chunk)", best * 1e9, "ns");
}

/* Idle: how long a 10 ms sleep takes (timer precision and wakeup). */
static void bench_sleep(void)
{
	double t = now();
	for (int i = 0; i < 20; i++)
		usleep(10000);
	report("usleep(10 ms)", (now() - t) / 20 * 1e6, "us");
}

/* In-cache stores and loads over 16 KiB: write-back memory does both at
 * cache speed; write-through stores go to memory. */
static void bench_cache_bw(void)
{
	static volatile uint64_t buf[2048];
	int reps = 20000;
	double t = now();
	for (int r = 0; r < reps; r++)
		for (int i = 0; i < 2048; i++)
			buf[i] = i + r;
	report("store 16 KiB in cache", sizeof(buf) * (double)reps / (now() - t) / 1e9, "GB/s");
	uint64_t sum = 0;
	t = now();
	for (int r = 0; r < reps; r++)
		for (int i = 0; i < 2048; i++)
			sum += buf[i];
	report("load 16 KiB in cache", sizeof(buf) * (double)reps / (now() - t) / 1e9, "GB/s");
	/* REP STOSB is microcode, not bound by the op cache: L1 speed on
	 * write-back memory, memory speed on write-through. */
	t = now();
	for (int r = 0; r < reps; r++) {
		void *dst = (void *)buf;
		size_t cnt = sizeof(buf);
		__asm__ volatile("rep stosb" : "+D"(dst), "+c"(cnt) : "a"(r) : "memory");
	}
	report("rep stosb 16 KiB", sizeof(buf) * (double)reps / (now() - t) / 1e9, "GB/s");
	if (sum == 42)
		puts("");
}

/* Time the vCPU did not run: spin on the TSC for 100 ms and sum the gaps
 * over 1 us (exits, interrupts, preemption in the host). */
static void bench_gaps(void)
{
	double t0 = now();
	uint64_t last = __builtin_ia32_rdtsc(), start = last, lost = 0, n = 0, big = 0;
	while (now() - t0 < 0.1) {
		uint64_t t = __builtin_ia32_rdtsc();
		uint64_t d = t - last;
		if (d > 4000) {
			lost += d;
			n++;
			if (d > big)
				big = d;
		}
		last = t;
	}
	double all = (double)(last - start);
	printf("BENCH: gaps over 1 us         %10.2f %% of time, %lu gaps, max %lu cycles\n", 100 * lost / all, n, big);
}

/* Front end and branch throughput: an empty counted loop, eight
 * independent adds per iteration, and 16 unconditional jumps per
 * iteration; in cycles of the TSC per iteration. */
static void bench_frontend(void)
{
	uint64_t n = 20000000, t;
	t = __builtin_ia32_rdtsc();
	for (uint64_t i = 0; i < n; i++)
		__asm__ volatile("");
	printf("BENCH: empty loop             %10.2f tsc/iter\n", (double)(__builtin_ia32_rdtsc() - t) / n);
	uint64_t a = 1, b = 2, c = 3, d = 4, e = 5, f = 6, g = 7, h = 8;
	t = __builtin_ia32_rdtsc();
	for (uint64_t i = 0; i < n; i++)
		__asm__ volatile("add $1,%0; add $1,%1; add $1,%2; add $1,%3; add $1,%4; add $1,%5; add $1,%6; add $1,%7"
				 : "+r"(a), "+r"(b), "+r"(c), "+r"(d), "+r"(e), "+r"(f), "+r"(g), "+r"(h));
	printf("BENCH: 8 independent adds     %10.2f tsc/iter\n", (double)(__builtin_ia32_rdtsc() - t) / n);
	t = __builtin_ia32_rdtsc();
	for (uint64_t i = 0; i < n / 4; i++)
		__asm__ volatile("jmp 1f; 1: jmp 2f; 2: jmp 3f; 3: jmp 4f; 4: jmp 5f; 5: jmp 6f; 6: jmp 7f; 7: jmp 8f; 8:"
				 "jmp 9f; 9: jmp 10f; 10: jmp 11f; 11: jmp 12f; 12: jmp 13f; 13: jmp 14f; 14: jmp 15f; 15: jmp 16f; 16:");
	printf("BENCH: 16 taken jumps         %10.2f tsc/iter\n", (double)(__builtin_ia32_rdtsc() - t) / (n / 4));
	if (a + b + c + d + e + f + g + h == 42)
		puts("");
}

/* `vmcmp spin`: eight independent adds in a loop for 4 s, for counting
 * from the host. */
static int spin(void)
{
	uint64_t a = 1, b = 2, c = 3, d = 4, e = 5, f = 6, g = 7, h = 8;
	double t0 = now();
	while (now() - t0 < 4)
		for (int i = 0; i < 1000000; i++)
			__asm__ volatile("add $1,%0; add $1,%1; add $1,%2; add $1,%3; add $1,%4; add $1,%5; add $1,%6; add $1,%7"
					 : "+r"(a), "+r"(b), "+r"(c), "+r"(d), "+r"(e), "+r"(f), "+r"(g), "+r"(h));
	return a + b + c + d + e + f + g + h == 42;
}

/* The 8-add loop copied into a fresh page: does the code's page matter? */
static void bench_fresh_page(void)
{
	static const unsigned char code[] = {
		0x48, 0x89, 0xf9,                                     /* mov %rdi,%rcx */
		0x48, 0x83, 0xc0, 0x01, 0x48, 0x83, 0xc2, 0x01,       /* add $1,%rax; %rdx */
		0x48, 0x83, 0xc6, 0x01, 0x48, 0x83, 0xc7, 0x01,       /* %rsi; %rdi */
		0x49, 0x83, 0xc0, 0x01, 0x49, 0x83, 0xc1, 0x01,       /* %r8; %r9 */
		0x49, 0x83, 0xc2, 0x01, 0x49, 0x83, 0xc3, 0x01,       /* %r10; %r11 */
		0x48, 0xff, 0xc9,                                     /* dec %rcx */
		0x75, 0xdb,                                           /* jnz -37 */
		0xc3,                                                 /* ret */
	};
	unsigned char *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED)
		return;
	memcpy(p + 64, code, sizeof(code));
	mprotect(p, 4096, PROT_READ | PROT_EXEC);
	void (*f)(uint64_t) = (void (*)(uint64_t))(p + 64);
	uint64_t n = 20000000, t = __builtin_ia32_rdtsc();
	f(n);
	printf("BENCH: 8 adds, fresh page     %10.2f tsc/iter\n", (double)(__builtin_ia32_rdtsc() - t) / n);
	munmap(p, 4096);
}

static void print_xcr0(void)
{
	unsigned lo, hi, lo1, hi1;
	__asm__ volatile("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0));
	__asm__ volatile("xgetbv" : "=a"(lo1), "=d"(hi1) : "c"(1));
	printf("BENCH: xcr0 %#x xinuse %#x\n", lo, lo1);
}

int main(int argc, char **argv)
{
	if (argc > 1 && !strcmp(argv[1], "spin"))
		return spin();
	print_xcr0();
	bench_frontend();
	bench_fresh_page();
	bench_gaps();
	bench_cache_bw();
	bench_getpid_best();
	bench_sleep();
	bench_cpuid();
	bench_clock();
	bench_alu();
	bench_memcpy();
	bench_chase(8, 0);
	bench_chase(64, 0);
	bench_chase(64, 1);
	return 0;
}

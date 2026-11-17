/*
 * l4h guest self-test: exercises the Linux user ABI as implemented by the
 * l4h guest kernel.  Built as a static native-ISA binary and run inside a
 * guest; prints "SELFTEST: PASS" or "SELFTEST: FAIL <test>".
 */
#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#ifdef __x86_64__
#include <asm/prctl.h>
#else
#include <asm/ptrace.h>
#endif
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/futex.h>
#include <linux/seccomp.h>
#include "page-aging/page-aging.h"

static int failures;

#define CHECK(cond, ...) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d: ", __func__, __LINE__); \
		printf(__VA_ARGS__); \
		printf("\n"); \
		failures++; \
		return; \
	} \
} while (0)

static double now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

/* ---- syscalls and registers */
static void test_syscall_regs(void)
{
#ifdef __aarch64__
 register long x0 asm("x0") = -1;
 register long x1 asm("x1") = 0x11111111;
 register long x6 asm("x6") = 0x66666666;
 register long x8 asm("x8") = SYS_getpid;
 register long x19 asm("x19") = 0x19191919;
 asm volatile("svc #0" : "+r"(x0), "+r"(x1), "+r"(x6), "+r"(x8), "+r"(x19) :: "memory", "cc");
 CHECK(x0 == getpid(), "getpid returned %ld", x0);
 CHECK(x1 == 0x11111111 && x6 == 0x66666666 && x19 == 0x19191919, "registers clobbered");
#else
	/* getpid through the raw syscall path with all argument registers
	 * holding sentinel values. */
	long r;
	register long r10 asm("r10") = 0x1010101010101010;
	register long r8 asm("r8") = 0x0808080808080808;
	register long r9 asm("r9") = 0x0909090909090909;
	long rbx_before = 0x5555aaaa5555aaaa, rbx_after;

	asm volatile("movq %[b], %%rbx\n\tsyscall\n\tmovq %%rbx, %[a]"
		     : "=a"(r), [a] "=r"(rbx_after), "+r"(r10), "+r"(r8), "+r"(r9)
		     : "0"((long)SYS_getpid), "D"(-1L), "S"(-2L), "d"(-3L), [b] "r"(rbx_before)
		     : "rcx", "r11", "rbx", "memory");
	CHECK(r == getpid(), "getpid returned %ld", r);
	CHECK(rbx_after == rbx_before, "rbx clobbered");
	CHECK(r10 == 0x1010101010101010 && r8 == 0x0808080808080808 && r9 == 0x0909090909090909,
	      "argument registers clobbered");
#endif
}

#ifdef __aarch64__
static void test_arm_exceptions(void)
{
	const int expected[] = { SIGILL, SIGTRAP, SIGBUS };
	for (int which = 0; which < 3; which++) {
		int status;
		pid_t pid = fork();
		CHECK(pid >= 0, "exception fork");
		if (!pid) {
			if (which == 0)
				asm volatile(".inst 0x00000000");
			else if (which == 1)
				asm volatile("brk #0");
			else
				/* PC alignment faults on every CPU, including CPUs
				 * which support unaligned atomic loads. */
				asm volatile("adr x9, .+2\n\tbr x9" ::: "x9");
			_exit(99);
		}
		CHECK(waitpid(pid, &status, 0) == pid && WIFSIGNALED(status) &&
		      WTERMSIG(status) == expected[which],
		      "exception %d: status %#x, expected signal %d",
		      which, status, expected[which]);
	}
}
#endif

/* ---- memory */
static void test_mmap(void)
{
	size_t len = 16 << 20;
	unsigned char *p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	size_t i;

	CHECK(p != MAP_FAILED, "mmap: %s", strerror(errno));
	for (i = 0; i < len; i += 4096)
		p[i] = (unsigned char)(i >> 12);
	for (i = 0; i < len; i += 4096)
		CHECK(p[i] == (unsigned char)(i >> 12), "mismatch at %zu", i);
	CHECK(mprotect(p, len, PROT_READ) == 0, "mprotect");
	CHECK(p[4096] == 1, "read after mprotect");
	CHECK(munmap(p, len) == 0, "munmap");
}

/* Run after exec without ASLR, so the stack cannot land on the fixed
 * address near the top of user space. */
static void mmap_high_child(void)
{
	const uintptr_t addrs[] = {
		0x7f7ffffff000ul, /* crosses the old limit / PGD boundary */
		0x7ff000000000ul, /* special pages in the separate kernel VSpace */
		0x7fffffe00000ul,
	};
	const size_t len = 2 * 4096;
	int fds[2], status;
	char buf[16];
	pid_t pid;

	CHECK(pipe(fds) == 0, "pipe: %s", strerror(errno));
	for (size_t i = 0; i < sizeof(addrs) / sizeof(addrs[0]); i++) {
		unsigned char *p = mmap((void *)addrs[i], len, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);

		CHECK(p == (void *)addrs[i], "mmap at %#lx: %p (%s)", addrs[i], p,
		      strerror(errno));
		CHECK(p[0] == 0 && p[len - 1] == 0, "anonymous pages not zeroed");
		memset(p, 0x5a, len);
		CHECK(write(fds[1], p, sizeof(buf)) == sizeof(buf), "copy from high address");
		memset(p + 4096, 0, sizeof(buf));
		CHECK(read(fds[0], p + 4096, sizeof(buf)) == sizeof(buf), "copy to high address");
		CHECK(p[4096] == 0x5a, "high address data");

		pid = fork();
		CHECK(pid >= 0, "fork: %s", strerror(errno));
		if (!pid) {
			if (p[0] != 0x5a || p[len - 1] != 0x5a)
				_exit(1);
			memset(p, 0xa5, len);
			_exit(p[0] != 0xa5 || p[len - 1] != 0xa5);
		}
		CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
		      WEXITSTATUS(status) == 0, "high address child: status %#x", status);
		CHECK(p[0] == 0x5a && p[len - 1] == 0x5a, "high address COW");
		CHECK(mprotect(p, len, PROT_NONE) == 0, "mprotect high address");
		CHECK(write(fds[1], p, 1) == -1 && errno == EFAULT, "high address protection");
		CHECK(munmap(p, len) == 0, "munmap high address");
		p = mmap((void *)addrs[i], len, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
		CHECK(p == (void *)addrs[i], "remap high address: %s", strerror(errno));
		CHECK(p[0] == 0 && p[len - 1] == 0, "stale high address mapping");
		CHECK(munmap(p, len) == 0, "munmap high address again");
	}
	close(fds[0]);
	close(fds[1]);

	/* The final page remains reserved, including mappings that
	 * start below it and extend into it. */
	const uintptr_t invalid[] = { 0x7ffffffff000ul, 0x7fffffffe000ul, 0x800000000000ul };
	for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
		void *p = mmap((void *)invalid[i], len, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);

		CHECK(p == MAP_FAILED && errno == ENOMEM, "mmap past user limit at %#lx: %p (%s)",
		      invalid[i], p, strerror(errno));
	}
}

static void test_mmap_high(void)
{
	int status;
	pid_t pid = fork();

	CHECK(pid >= 0, "fork: %s", strerror(errno));
	if (!pid) {
		if (personality(ADDR_NO_RANDOMIZE) != -1)
			execl("/proc/self/exe", "selftest", "--mmap-high-child", NULL);
		_exit(99);
	}
	CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0,
	      "high address test: status %#x", status);
}

/* Kernel copies to and from user memory honour its protection. */
static void test_uaccess_prot(void)
{
	unsigned char *p = mmap(NULL, 2 * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	char buf[16];
	int fds[2];
	ssize_t r;

	CHECK(p != MAP_FAILED, "mmap: %s", strerror(errno));
	CHECK(pipe(fds) == 0, "pipe: %s", strerror(errno));
	memcpy(p, "protected data", 15);
	CHECK(mprotect(p, 4096, PROT_NONE) == 0, "mprotect: %s", strerror(errno));
	errno = 0;
	r = write(fds[1], p, 15);
	CHECK(r == -1 && errno == EFAULT, "write from a PROT_NONE page: %zd (%s)", r, strerror(errno));
	/* Never touched before PROT_NONE. */
	CHECK(mprotect(p + 4096, 4096, PROT_NONE) == 0, "mprotect: %s", strerror(errno));
	errno = 0;
	r = write(fds[1], p + 4096, 15);
	CHECK(r == -1 && errno == EFAULT, "write from an untouched PROT_NONE page: %zd (%s)", r,
	      strerror(errno));
	/* Read-only: the kernel cannot write into it either. */
	CHECK(mprotect(p, 4096, PROT_READ) == 0, "mprotect: %s", strerror(errno));
	CHECK(write(fds[1], "0123456789abcde", 15) == 15, "write: %s", strerror(errno));
	errno = 0;
	r = read(fds[0], p, 15);
	CHECK(r == -1 && errno == EFAULT, "read into a PROT_READ page: %zd (%s)", r, strerror(errno));
	CHECK(memcmp(p, "protected data", 15) == 0, "PROT_READ page changed");
	CHECK(write(fds[1], p, 15) == 15, "write from a PROT_READ page: %s", strerror(errno));
	r = read(fds[0], buf, sizeof(buf));
	CHECK(r == 16, "read back: %zd", r);
	CHECK(memcmp(buf, "0123456789abcde", 15) == 0, "pipe data");
	close(fds[0]);
	close(fds[1]);
	munmap(p, 2 * 4096);
}

/*
 * Kernel copies race with another thread dropping the pages (and other
 * threads reusing freed pages): a copy sees the buffer's data or zeroes
 * (MADV_DONTNEED), never another page's, and does not fail (an unlocked
 * walk losing the race returned EFAULT).
 */
static unsigned char *volatile race_buf;
static atomic_int race_stop;

static void *uaccess_dropper(void *arg)
{
	while (!atomic_load(&race_stop)) {
		memset(race_buf, 0xa5, 4 * 4096);
		madvise(race_buf, 4 * 4096, MADV_DONTNEED);
	}
	return NULL;
}

static void *uaccess_reuser(void *arg)
{
	while (!atomic_load(&race_stop)) {
		unsigned char *q = mmap(NULL, 16 * 4096, PROT_READ | PROT_WRITE,
					MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

		if (q == MAP_FAILED)
			continue;
		memset(q, 0x5a, 16 * 4096);
		munmap(q, 16 * 4096);
	}
	return NULL;
}

static void test_uaccess_race(void)
{
	static unsigned char out[4 * 4096];
	pthread_t dropper, reuser;
	int fds[2], i, bad = 0;
	size_t j;

	race_buf = mmap(NULL, 4 * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHECK(race_buf != MAP_FAILED, "mmap: %s", strerror(errno));
	CHECK(pipe(fds) == 0, "pipe: %s", strerror(errno));
	atomic_store(&race_stop, 0);
	pthread_create(&dropper, NULL, uaccess_dropper, NULL);
	pthread_create(&reuser, NULL, uaccess_reuser, NULL);
	for (i = 0; i < 2000 && !bad; i++) {
		ssize_t n = write(fds[1], race_buf, sizeof(out)), got = 0;

		if (n <= 0) {
			bad = -1;
			break;
		}
		while (got < n) {
			ssize_t m = read(fds[0], out + got, n - got);

			if (m <= 0)
				break;
			got += m;
		}
		for (j = 0; j < (size_t)got; j++)
			if (out[j] != 0xa5 && out[j] != 0)
				bad = out[j];
	}
	atomic_store(&race_stop, 1);
	pthread_join(dropper, NULL);
	pthread_join(reuser, NULL);
	close(fds[0]);
	close(fds[1]);
	munmap(race_buf, 4 * 4096);
	CHECK(bad == 0, "copy from user saw byte %#x (write: %s)", bad, bad < 0 ? strerror(errno) : "ok");
}

static sigjmp_buf segv_jmp;
static volatile void *segv_addr;

static void segv_handler(int sig, siginfo_t *si, void *ctx)
{
	segv_addr = si->si_addr;
	siglongjmp(segv_jmp, 1);
}

static void test_segv(void)
{
	struct sigaction sa = { .sa_sigaction = segv_handler, .sa_flags = SA_SIGINFO };
	unsigned char *p = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	sigaction(SIGSEGV, &sa, NULL);
	if (sigsetjmp(segv_jmp, 1) == 0) {
		*(volatile int *)0x10 = 1;
		CHECK(0, "no fault on NULL write");
	}
	CHECK(segv_addr == (void *)0x10, "si_addr %p", segv_addr);
	if (sigsetjmp(segv_jmp, 1) == 0) {
		p[100] = 1;
		CHECK(0, "no fault on read-only write");
	}
	CHECK(segv_addr == p + 100, "si_addr %p (expected %p)", segv_addr, p + 100);
	signal(SIGSEGV, SIG_DFL);
	munmap(p, 4096);
}

#ifndef __aarch64__
/* int $N is no system call: seL4's user trap vectors raise #GP, as the
 * closed gates do natively, instead of running the call in eax. */
static void test_int_gate(void)
{
	struct sigaction sa = { .sa_sigaction = segv_handler, .sa_flags = SA_SIGINFO };
	long r = SYS_getpid;

	sigaction(SIGSEGV, &sa, NULL);
	if (sigsetjmp(segv_jmp, 1) == 0) {
		asm volatile("int $0xa0" : "+a"(r) : : "rcx", "r11", "memory");
		CHECK(0, "int $0xa0 returned %ld", r);
	}
	signal(SIGSEGV, SIG_DFL);
}
#endif

/* Data pages are not executable; mprotect(PROT_EXEC) makes them so. */
static void test_nx(void)
{
	struct sigaction sa = { .sa_sigaction = segv_handler, .sa_flags = SA_SIGINFO };
	unsigned char *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	int (*fn)(void) = (int (*)(void))p;

	CHECK(p != MAP_FAILED, "mmap: %s", strerror(errno));
#ifdef __aarch64__
 const uint32_t code[] = { 0x52800540, 0xd65f03c0 }; /* mov w0, #42; ret */
 memcpy(p, code, sizeof(code));
 __builtin___clear_cache((char *)p, (char *)p + sizeof(code));
#else
	/* mov $42, %eax; ret */
	memcpy(p, "\xb8\x2a\x00\x00\x00\xc3", 6);
#endif
	sigaction(SIGSEGV, &sa, NULL);
	segv_addr = NULL;
	if (sigsetjmp(segv_jmp, 1) == 0) {
		fn();
		CHECK(0, "executed from a PROT_READ|PROT_WRITE page (personality %#x)", personality(0xffffffff));
	}
	CHECK(segv_addr == p, "si_addr %p (expected %p)", segv_addr, p);
	CHECK(mprotect(p, 4096, PROT_READ | PROT_EXEC) == 0, "mprotect: %s", strerror(errno));
	CHECK(fn() == 42, "PROT_EXEC page did not run");
	CHECK(mprotect(p, 4096, PROT_READ) == 0, "mprotect: %s", strerror(errno));
	segv_addr = NULL;
	if (sigsetjmp(segv_jmp, 1) == 0) {
		fn();
		CHECK(0, "executed after PROT_EXEC was removed");
	}
	CHECK(segv_addr == p, "si_addr %p (expected %p)", segv_addr, p);
	signal(SIGSEGV, SIG_DFL);
	munmap(p, 4096);
}

/* ---- fork, exec, wait, pipes, COW */
static void test_fork(void)
{
	int fds[2], status;
	char buf[64] = { 0 };
	volatile int cow = 1;
	pid_t pid;

	CHECK(pipe(fds) == 0, "pipe");
	pid = fork();
	CHECK(pid >= 0, "fork: %s", strerror(errno));
	if (pid == 0) {
		cow = 2;
		dprintf(fds[1], "child %d cow=%d", getpid(), cow);
		_exit(42);
	}
	CHECK(waitpid(pid, &status, 0) == pid, "waitpid");
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 42, "exit status %x", status);
	CHECK(read(fds[0], buf, sizeof(buf) - 1) > 0, "read");
	CHECK(strstr(buf, "cow=2") != NULL, "child wrote '%s'", buf);
	CHECK(cow == 1, "COW broken: parent sees %d", cow);
	close(fds[0]);
	close(fds[1]);

	pid = fork();
	if (pid == 0) {
		execl("/bin/true", "true", NULL);
		_exit(99);
	}
	CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0,
	      "exec /bin/true: status %x", status);

	/* Without stack randomization the stack starts at STACK_TOP itself.
	 * It must be clear of the vDSO and its data pages: installing them
	 * over the stack failed exec past its point of no return (SIGSEGV),
	 * which randomization made happen for ~0.2 % of execs. */
	pid = fork();
	if (pid == 0) {
		personality(ADDR_NO_RANDOMIZE);
		execl("/bin/true", "true", NULL);
		_exit(99);
	}
	CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0,
	      "exec /bin/true without randomization: status %x", status);
}

/* ---- ptrace */
#ifdef __x86_64__
#define PT_GS1 0x12345000UL
#define PT_GS2 0x6789a000UL
#define PT_GS3 0x2468a000UL

static long get_base(int code)
{
	unsigned long base = ~0UL;

	syscall(SYS_arch_prctl, code, &base);
	return base;
}

static void ptrace_child(void)
{
	ptrace(PTRACE_TRACEME, 0, NULL, NULL);
	/* glibc does not use gs on x86_64: give it a value of our own. */
	syscall(SYS_arch_prctl, ARCH_SET_GS, PT_GS1);
	raise(SIGSTOP);
	if (get_base(ARCH_GET_GS) != PT_GS2)
		_exit(10);
	raise(SIGSTOP);
	if (get_base(ARCH_GET_GS) != PT_GS3)
		_exit(11);
	_exit(0);
}

static long peek_user(pid_t pid, long off, unsigned long *v)
{
	*v = ~0UL;
	return syscall(SYS_ptrace, PTRACE_PEEKUSER, pid, off, v) ? -errno : 0;
}

static long poke_user(pid_t pid, long off, unsigned long v)
{
	return syscall(SYS_ptrace, PTRACE_POKEUSER, pid, off, v) ? -errno : 0;
}

static int ptrace_stopped(pid_t pid)
{
	int status;

	return waitpid(pid, &status, 0) == pid && WIFSTOPPED(status) &&
	       WSTOPSIG(status) == SIGSTOP;
}

static int ptrace_reaped;

static void ptrace_tracer(pid_t pid)
{
	unsigned long v, fs = get_base(ARCH_GET_FS), fs_new = fs + 0x1000;
	int status;

	CHECK(ptrace_stopped(pid), "child did not stop");

	/* PTRACE_ARCH_PRCTL acts on the tracee, not on the tracer. */
	v = 0;
	CHECK(syscall(SYS_ptrace, PTRACE_ARCH_PRCTL, pid, &v, ARCH_GET_GS) == 0,
	      "ARCH_PRCTL GET_GS: %s", strerror(errno));
	CHECK(v == PT_GS1, "ARCH_PRCTL GET_GS read %#lx, tracee has %#lx", v, PT_GS1);
	CHECK(syscall(SYS_ptrace, PTRACE_ARCH_PRCTL, pid, PT_GS2, ARCH_SET_GS) == 0,
	      "ARCH_PRCTL SET_GS: %s", strerror(errno));
	CHECK(get_base(ARCH_GET_GS) == 0, "ARCH_PRCTL SET_GS changed the tracer's gs base");
	CHECK(syscall(SYS_ptrace, PTRACE_ARCH_PRCTL, pid, &v, ARCH_GET_GS) == 0 && v == PT_GS2,
	      "ARCH_PRCTL GET_GS after SET_GS: %#lx", v);
	/* fs base: set the tracee's to another value, then restore it. */
	CHECK(syscall(SYS_ptrace, PTRACE_ARCH_PRCTL, pid, &v, ARCH_GET_FS) == 0 && v == fs,
	      "ARCH_PRCTL GET_FS read %#lx, expected %#lx", v, fs);
	CHECK(syscall(SYS_ptrace, PTRACE_ARCH_PRCTL, pid, fs_new, ARCH_SET_FS) == 0,
	      "ARCH_PRCTL SET_FS: %s", strerror(errno));
	CHECK(get_base(ARCH_GET_FS) == fs, "ARCH_PRCTL SET_FS changed the tracer's fs base");
	CHECK(syscall(SYS_ptrace, PTRACE_ARCH_PRCTL, pid, &v, ARCH_GET_FS) == 0 && v == fs_new,
	      "ARCH_PRCTL GET_FS after SET_FS: %#lx", v);
	CHECK(syscall(SYS_ptrace, PTRACE_ARCH_PRCTL, pid, fs, ARCH_SET_FS) == 0,
	      "ARCH_PRCTL SET_FS (restore): %s", strerror(errno));

	/* User area: only word-aligned offsets inside struct user.  The
	 * kernel's ends with error_code and fault_address, which glibc's lacks. */
#define PT_USER_SIZE (offsetof(struct user, u_debugreg) + 10 * sizeof(long))
	CHECK(peek_user(pid, 4, &v) == -EIO, "PEEKUSER at 4 accepted");
	CHECK(poke_user(pid, 4, 0) == -EIO, "POKEUSER at 4 accepted");
	CHECK(peek_user(pid, offsetof(struct user_regs_struct, rip) + 4, &v) == -EIO,
	      "PEEKUSER at rip + 4 accepted");
	CHECK(peek_user(pid, -8, &v) == -EIO, "PEEKUSER at -8 accepted");
	CHECK(peek_user(pid, PT_USER_SIZE, &v) == -EIO, "PEEKUSER past struct user accepted");
	CHECK(poke_user(pid, PT_USER_SIZE, 0) == -EIO, "POKEUSER past struct user accepted");
	CHECK(peek_user(pid, PT_USER_SIZE - 8, &v) == 0, "PEEKUSER of the last word failed");
	CHECK(peek_user(pid, offsetof(struct user_regs_struct, gs_base), &v) == 0 && v == PT_GS2,
	      "PEEKUSER gs_base: %#lx", v);
	CHECK(peek_user(pid, sizeof(struct user_regs_struct), &v) == 0 && v == 0,
	      "PEEKUSER after the registers: %#lx", v);
	/* Debug registers are eight bytes apart; DR4/DR5 cannot be set, and
	 * enabling a DR7 breakpoint is unsupported (seL4 has no debug API). */
#define PT_DR(n) (offsetof(struct user, u_debugreg) + (n) * sizeof(long))
	CHECK(poke_user(pid, PT_DR(1), 0x1000) == 0, "POKEUSER DR1 failed");
	CHECK(poke_user(pid, PT_DR(7), 0x4) == -EIO, "POKEUSER enabled DR7 accepted");
	CHECK(poke_user(pid, PT_DR(4), 0) == -EIO, "POKEUSER DR4 accepted");
	CHECK(peek_user(pid, PT_DR(1), &v) == 0 && v == 0x1000, "PEEKUSER DR1: %#lx", v);
	CHECK(peek_user(pid, PT_DR(7), &v) == 0 && v == 0, "PEEKUSER DR7: %#lx", v);
	CHECK(peek_user(pid, PT_DR(4), &v) == 0 && v == 0, "PEEKUSER DR4: %#lx", v);
	CHECK(poke_user(pid, PT_DR(7), 0) == 0 && poke_user(pid, PT_DR(1), 0) == 0,
	      "clearing DR7/DR1 failed");
#undef PT_DR
#undef PT_USER_SIZE

	CHECK(ptrace(PTRACE_CONT, pid, NULL, NULL) == 0, "PTRACE_CONT: %s", strerror(errno));
	CHECK(ptrace_stopped(pid), "child did not stop again");

	/* PEEKUSER/POKEUSER of fs/gs base reach the tracee's thread. */
	CHECK(peek_user(pid, offsetof(struct user_regs_struct, fs_base), &v) == 0 && v == fs,
	      "PEEKUSER fs_base: %#lx, expected %#lx", v, fs);
	CHECK(poke_user(pid, offsetof(struct user_regs_struct, gs_base), PT_GS3) == 0,
	      "POKEUSER gs_base failed");
	CHECK(peek_user(pid, offsetof(struct user_regs_struct, gs_base), &v) == 0 && v == PT_GS3,
	      "PEEKUSER gs_base after POKEUSER: %#lx", v);

	CHECK(ptrace(PTRACE_CONT, pid, NULL, NULL) == 0, "PTRACE_CONT: %s", strerror(errno));
	CHECK(waitpid(pid, &status, 0) == pid, "waitpid: %s", strerror(errno));
	ptrace_reaped = 1;
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	      "child saw the wrong gs base: status %x", status);
}

static void test_ptrace(void)
{
	pid_t pid = fork();

	CHECK(pid >= 0, "fork: %s", strerror(errno));
	if (pid == 0)
		ptrace_child();
	ptrace_reaped = 0;
	ptrace_tracer(pid);
	/* On failure the child may still be stopped. */
	if (!ptrace_reaped) {
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
	}
}

/*
 * PTRACE_GETREGS and PTRACE_SETREGS at a page fault's signal stop: what the
 * child had in its registers, an error (not success) for a value the
 * kernel refuses, and a change that the child resumes with.
 */
static void setregs_child(void)
{
	unsigned long out;

	ptrace(PTRACE_TRACEME, 0, NULL, NULL);
	/* movb $0, (%rax): 3 bytes, which the tracer skips. */
	asm volatile("mov $0x1234567, %%r12\n\t"
		     "movb $0, (%%rax)\n\t"
		     "mov %%r12, %[out]\n\t"
		     : [out] "=r"(out) : "a"(0UL) : "r12", "memory");
	_exit(out == 0x7654321 ? 0 : 1);
}

static void test_ptrace_setregs(void)
{
	struct user_regs_struct r, bad;
	unsigned long v;
	int status;
	pid_t pid = fork();

	CHECK(pid >= 0, "fork: %s", strerror(errno));
	if (pid == 0)
		setregs_child();
	if (waitpid(pid, &status, 0) != pid || !WIFSTOPPED(status) || WSTOPSIG(status) != SIGSEGV) {
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		CHECK(0, "no SIGSEGV stop: status %x", status);
	}
	CHECK(ptrace(PTRACE_GETREGS, pid, NULL, &r) == 0, "GETREGS: %s", strerror(errno));
	CHECK(r.r12 == 0x1234567 && r.rax == 0, "GETREGS at the fault: r12 %#llx rax %#llx", r.r12, r.rax);
	CHECK(peek_user(pid, offsetof(struct user_regs_struct, r12), &v) == 0 && v == 0x1234567,
	      "PEEKUSER r12 at the fault: %#lx", v);
	bad = r;
	bad.cs = 0x10;
	errno = 0;
	CHECK(ptrace(PTRACE_SETREGS, pid, NULL, &bad) == -1 && errno == EIO, "SETREGS with cs 0x10: %s", strerror(errno));
	bad = r;
	bad.fs_base = 1UL << 63;
	errno = 0;
	CHECK(ptrace(PTRACE_SETREGS, pid, NULL, &bad) == -1 && errno == EIO,
	      "SETREGS with a kernel fs base: %s", strerror(errno));
	CHECK(peek_user(pid, offsetof(struct user_regs_struct, fs_base), &v) == 0 && v == r.fs_base,
	      "the refused fs base was set: %#lx", v);
	r.rip += 3;
	r.r12 = 0x7654321;
	CHECK(ptrace(PTRACE_SETREGS, pid, NULL, &r) == 0, "SETREGS: %s", strerror(errno));
	CHECK(peek_user(pid, offsetof(struct user_regs_struct, rip), &v) == 0 && v == r.rip,
	      "PEEKUSER rip after SETREGS: %#lx, set %#llx", v, r.rip);
	/* Resume without the signal: past the store, with the new r12. */
	CHECK(ptrace(PTRACE_CONT, pid, NULL, NULL) == 0, "CONT: %s", strerror(errno));
	CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0,
	      "the child did not resume as set: status %x", status);
}

/* CLONE_SETTLS with a base past user space fails, as on x86, with clone
 * and clone3: no child runs with an fs base the kernel would not report. */
struct selftest_clone_args {
	uint64_t flags, pidfd, child_tid, parent_tid, exit_signal, stack, stack_size, tls;
};

static void test_clone_settls(void)
{
	unsigned long tls[] = { 1UL << 63, 1UL << 47, ~0UL };
	unsigned i;
	long r;

	for (i = 0; i < sizeof(tls) / sizeof(tls[0]); i++) {
		struct selftest_clone_args args = { .flags = CLONE_SETTLS, .exit_signal = SIGCHLD, .tls = tls[i] };

		errno = 0;
		r = syscall(SYS_clone, CLONE_SETTLS | SIGCHLD, 0, NULL, NULL, tls[i]);
		if (r == 0)
			syscall(SYS_exit, 0);
		if (r > 0)
			waitpid(r, NULL, 0);
		CHECK(r == -1 && errno == EPERM, "clone with tls %#lx: %ld (%s)", tls[i], r, strerror(errno));
		errno = 0;
		r = syscall(SYS_clone3, &args, sizeof(args));
		if (r == 0)
			syscall(SYS_exit, 0);
		if (r > 0)
			waitpid(r, NULL, 0);
		CHECK(r == -1 && errno == EPERM, "clone3 with tls %#lx: %ld (%s)", tls[i], r, strerror(errno));
	}
}

/* Stop with SIGSTOP without libc, which could touch the vector registers. */
#define FPREGS_STOP \
	"mov $39, %%eax\n\tsyscall\n\t"		/* getpid */ \
	"mov %%eax, %%edi\n\tmov $19, %%esi\n\t"	/* SIGSTOP */ \
	"mov $62, %%eax\n\tsyscall\n\t"		/* kill */

static void fpregs_child(void)
{
	uint64_t v = 0x123456789abcdef0ull, out;

	ptrace(PTRACE_TRACEME, 0, NULL, NULL);
	/* XMM0 live with a value, then in its init state (vzeroall), while
	 * the saved image may still hold the value. */
	asm volatile("movq %[v], %%xmm0\n\t"
		     FPREGS_STOP
		     "vzeroall\n\t"
		     FPREGS_STOP
		     "movq %%xmm0, %[out]\n\t"
		     : [out] "=r"(out) : [v] "r"(v)
		     : "rax", "rcx", "rdx", "rsi", "rdi", "r11", "memory",
		       "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
		       "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15");
	_exit(out == 0 ? 0 : 1);
}

/* A tracer that writes the FP registers back unchanged must not revive
 * state the tracee had reset: an init-state component reads as zeros. */
static void test_ptrace_fpregs(void)
{
	struct user_fpregs_struct f;
	int status, i;
	pid_t pid;

	if (!__builtin_cpu_supports("avx"))
		return;
	pid = fork();
	CHECK(pid >= 0, "fork: %s", strerror(errno));
	if (pid == 0)
		fpregs_child();
	for (i = 0; i < 2; i++) {
		if (waitpid(pid, &status, 0) != pid || !WIFSTOPPED(status)) {
			kill(pid, SIGKILL);
			waitpid(pid, NULL, 0);
			CHECK(0, "stop %d: status %x", i, status);
		}
		if (ptrace(PTRACE_GETFPREGS, pid, NULL, &f) ||
		    ptrace(PTRACE_SETFPREGS, pid, NULL, &f) ||
		    ptrace(PTRACE_CONT, pid, NULL, NULL)) {
			kill(pid, SIGKILL);
			waitpid(pid, NULL, 0);
			CHECK(0, "stop %d: FP registers: %s", i, strerror(errno));
		}
	}
	CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0,
	      "XMM0 not zero after vzeroall and an FP register round trip: %x", status);
}


#else
static void test_ptrace(void)
{
 pid_t pid = fork();
 int status;
 if (!pid) { ptrace(PTRACE_TRACEME, 0, NULL, NULL); raise(SIGSTOP); _exit(0); }
 CHECK(waitpid(pid, &status, 0) == pid && WIFSTOPPED(status), "tracee stop");
 struct user_pt_regs regs;
 struct iovec iov = { &regs, sizeof(regs) };
 CHECK(ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov) == 0 && iov.iov_len == sizeof(regs), "GETREGSET");
 CHECK((regs.pc & 3) == 0 && (regs.sp & 15) == 0, "unaligned user registers");
 unsigned long tls = 0;
 iov = (struct iovec){ &tls, sizeof(tls) };
 CHECK(ptrace(PTRACE_GETREGSET, pid, (void *)NT_ARM_TLS, &iov) == 0 && tls != 0, "GETREGSET TLS");
 unsigned long saved = tls;
 tls += 0x1000;
 CHECK(ptrace(PTRACE_SETREGSET, pid, (void *)NT_ARM_TLS, &iov) == 0, "SETREGSET TLS");
 tls = 0;
 CHECK(ptrace(PTRACE_GETREGSET, pid, (void *)NT_ARM_TLS, &iov) == 0 && tls == saved + 0x1000, "TLS round trip");
 tls = saved;
 CHECK(ptrace(PTRACE_SETREGSET, pid, (void *)NT_ARM_TLS, &iov) == 0, "restore TLS");
 CHECK(ptrace(PTRACE_CONT, pid, NULL, NULL) == 0, "CONT");
 CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0, "tracee exit: %x", status);
}

static void test_ptrace_syscall(void)
{
	int fds[2], status, entering = 1, changed = 0, skipped = 0;
	char c;
	pid_t pid;

	CHECK(pipe(fds) == 0, "trace pipe");
	pid = fork();
	CHECK(pid >= 0, "trace fork");
	if (!pid) {
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		raise(SIGSTOP);
		if (syscall(SYS_write, (long)-1, "R", 1UL) != 1)
			_exit(10);
		if (syscall(SYS_getpid) != 1234)
			_exit(11);
		_exit(0);
	}
	close(fds[1]);
	CHECK(waitpid(pid, &status, 0) == pid && WIFSTOPPED(status), "trace stop");
	CHECK(ptrace(PTRACE_SETOPTIONS, pid, NULL,
		     (void *)(uintptr_t)PTRACE_O_TRACESYSGOOD) == 0, "trace options");
	for (;;) {
		struct user_pt_regs regs;
		struct iovec iov = { &regs, sizeof(regs) };

		CHECK(ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == 0, "trace resume");
		CHECK(waitpid(pid, &status, 0) == pid, "trace wait");
		if (WIFEXITED(status))
			break;
		CHECK(WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80),
		      "syscall stop: %#x", status);
		CHECK(ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov) == 0,
		      "syscall registers");
		if (entering && regs.regs[8] == SYS_write) {
			CHECK(regs.regs[0] == (unsigned long)-1, "entry x0: %#llx",
			      (unsigned long long)regs.regs[0]);
			regs.regs[0] = fds[1];
			iov = (struct iovec){ &regs, sizeof(regs) };
			CHECK(ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &iov) == 0,
			      "change first syscall argument");
			changed++;
		} else if (entering && regs.regs[8] == SYS_getpid) {
			int nr = -1;
			iov = (struct iovec){ &nr, sizeof(nr) };
			CHECK(ptrace(PTRACE_SETREGSET, pid, (void *)NT_ARM_SYSTEM_CALL, &iov) == 0,
			      "skip syscall");
			regs.regs[0] = 1234;
			iov = (struct iovec){ &regs, sizeof(regs) };
			CHECK(ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &iov) == 0,
			      "set skipped return value");
			skipped++;
		}
		entering = !entering;
	}
	CHECK(WEXITSTATUS(status) == 0 && changed == 1 && skipped == 1,
	      "trace result: status %#x, edits %d, skips %d", status, changed, skipped);
	CHECK(read(fds[0], &c, 1) == 1 && c == 'R', "modified write");
	close(fds[0]);
}

#endif

/* ---- ptrace syscall emulation (also used with AArch64 under kemu) */
#ifndef PTRACE_SYSEMU
#define PTRACE_SYSEMU 31
#endif
#ifndef PTRACE_SYSEMU_SINGLESTEP
#define PTRACE_SYSEMU_SINGLESTEP 32
#endif

#ifdef __x86_64__
typedef struct user_regs_struct sysemu_regs;
#define SYSEMU_NR(r) ((r).orig_rax)
#define SYSEMU_RET(r) ((r).rax)
#else
typedef struct user_pt_regs sysemu_regs;
#define SYSEMU_NR(r) ((r).regs[8])
#define SYSEMU_RET(r) ((r).regs[0])
#endif

static volatile sig_atomic_t sysemu_signal;

static void sysemu_signal_handler(int sig)
{
	sysemu_signal = sig;
}

/* SIGUSR1 denotes resuming with SYSEMU while a signal is pending. */
static void sysemu_child(int fd, int resume, int filtered)
{
	struct sigaction sa = { .sa_handler = sysemu_signal_handler };
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_write, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EACCES),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = { .len = sizeof(filter) / sizeof(filter[0]), .filter = filter };
	long ret;

	sysemu_signal = 0;
	if (sigaction(SIGUSR1, &sa, NULL))
		_exit(10);
	if (filtered && (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
			 prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)))
		_exit(11);
	if (ptrace(PTRACE_TRACEME, 0, NULL, NULL))
		_exit(12);
	raise(SIGSTOP);
	if (syscall(SYS_write, fd, "S", 1UL) != 123)
		_exit(13);
	if (resume == PTRACE_SYSEMU) {
		/* The tracer changes this to write(fd, "S", 1), which must
		 * still be skipped even when it resumes with CONT. */
		if (syscall(SYS_getpid, fd, "S", 1UL) != 456)
			_exit(14);
	}
	ret = syscall(SYS_write, fd, "R", 1UL);
	if (filtered ? (ret != -1 || errno != EACCES) : ret != 1)
		_exit(15);
	if (resume == PTRACE_SYSCALL && syscall(SYS_getpid) != 789)
		_exit(17);
	if (sysemu_signal != (resume == SIGUSR1 ? SIGUSR1 : 0))
		_exit(16);
	_exit(0);
}

static int sysemu_stop(pid_t pid, int sig)
{
	int status;

	return waitpid(pid, &status, 0) == pid && WIFSTOPPED(status) &&
	       WSTOPSIG(status) == sig;
}

static int sysemu_emulate(pid_t pid, long nr, long ret, int change_nr)
{
	sysemu_regs regs;
	struct iovec iov = { &regs, sizeof(regs) };

	if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov))
		return -1;
	if (SYSEMU_NR(regs) != nr) {
		errno = EPROTO;
		return -1;
	}
	SYSEMU_RET(regs) = ret;
	if (change_nr) {
#ifdef __x86_64__
		SYSEMU_NR(regs) = SYS_write;
#else
		int replacement = SYS_write;
		struct iovec syscall_iov = { &replacement, sizeof(replacement) };

		if (ptrace(PTRACE_SETREGSET, pid, (void *)NT_ARM_SYSTEM_CALL, &syscall_iov))
			return -1;
#endif
	}
	return ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &iov);
}

static void sysemu_tracer(pid_t pid, int resume, int *reaped)
{
	sysemu_regs regs;
	struct iovec iov = { &regs, sizeof(regs) };
	int status;

	CHECK(sysemu_stop(pid, SIGSTOP), "initial stop");
	CHECK(ptrace(PTRACE_SETOPTIONS, pid, NULL,
		     (void *)(uintptr_t)(PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL)) == 0,
	      "trace options: %s", strerror(errno));
	CHECK(ptrace(PTRACE_SYSEMU, pid, NULL, NULL) == 0, "SYSEMU: %s", strerror(errno));
	CHECK(sysemu_stop(pid, SIGTRAP | 0x80), "SYSEMU entry stop");
	CHECK(sysemu_emulate(pid, SYS_write, 123, 0) == 0, "emulate write: %s", strerror(errno));
	if (resume == SIGUSR1) {
		CHECK(kill(pid, SIGUSR1) == 0, "queue signal");
		CHECK(ptrace(PTRACE_SYSEMU, pid, NULL, NULL) == 0, "resume before signal");
		CHECK(sysemu_stop(pid, SIGUSR1), "signal delivery stop");
		CHECK(ptrace(PTRACE_CONT, pid, NULL, (void *)(uintptr_t)SIGUSR1) == 0,
		      "deliver signal");
	} else {
		CHECK(ptrace(resume, pid, NULL, NULL) == 0, "resume %d: %s", resume, strerror(errno));
		if (resume == PTRACE_SYSEMU) {
			/* No exit stop in SYSEMU mode; the next stop is getpid. */
			CHECK(sysemu_stop(pid, SIGTRAP | 0x80), "second SYSEMU entry");
			CHECK(sysemu_emulate(pid, SYS_getpid, 456, 1) == 0,
			      "emulate changed syscall: %s", strerror(errno));
			CHECK(ptrace(PTRACE_CONT, pid, NULL, NULL) == 0, "CONT after SYSEMU");
		} else if (resume == PTRACE_SYSCALL) {
			/* Switching to SYSCALL produces an exit stop for the skipped
			 * call. Switching back at the next entry must execute that
			 * call and suppress the one after it. */
			CHECK(sysemu_stop(pid, SIGTRAP | 0x80), "skipped syscall exit");
			CHECK(ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov) == 0 &&
			      SYSEMU_RET(regs) == 123, "skipped syscall return value");
			CHECK(ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == 0, "resume to real entry");
			CHECK(sysemu_stop(pid, SIGTRAP | 0x80), "real syscall entry");
			CHECK(ptrace(PTRACE_SYSEMU, pid, NULL, NULL) == 0, "SYSEMU after SYSCALL");
			CHECK(sysemu_stop(pid, SIGTRAP | 0x80), "SYSEMU after real syscall");
			CHECK(sysemu_emulate(pid, SYS_getpid, 789, 0) == 0, "emulate after SYSCALL");
			CHECK(ptrace(PTRACE_CONT, pid, NULL, NULL) == 0, "CONT after emulation");
		}
	}
	CHECK(waitpid(pid, &status, 0) == pid, "wait for exit");
	*reaped = WIFEXITED(status) || WIFSIGNALED(status);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	      "resume %d: child status %#x", resume, status);
}

static void sysemu_test(int filtered)
{
	const int resumes[] = { PTRACE_SYSEMU, PTRACE_CONT, PTRACE_SYSCALL, PTRACE_DETACH, SIGUSR1 };

	for (unsigned i = 0; i < sizeof(resumes) / sizeof(resumes[0]); i++) {
		int fds[2], reaped = 0, before = failures;
		char buf[8];
		ssize_t n;
		pid_t pid;

		CHECK(pipe2(fds, O_NONBLOCK) == 0, "pipe");
		pid = fork();
		if (pid < 0) {
			close(fds[0]);
			close(fds[1]);
			CHECK(0, "fork: %s", strerror(errno));
		}
		if (!pid)
			sysemu_child(fds[1], resumes[i], filtered);
		close(fds[1]);
		sysemu_tracer(pid, resumes[i], &reaped);
		if (!reaped) {
			kill(pid, SIGKILL);
			waitpid(pid, NULL, 0);
		}
		n = read(fds[0], buf, sizeof(buf));
		close(fds[0]);
		if (failures != before)
			return;
		CHECK(filtered ? n == 0 : (n == 1 && buf[0] == 'R'),
		      "resume %d: syscall side effects (%zd bytes)", resumes[i], n);
	}
}

static void test_ptrace_sysemu(void)
{
	sysemu_test(0);
}

static void test_ptrace_sysemu_seccomp(void)
{
	sysemu_test(1);
}

static void test_ptrace_sysemu_nostep(void)
{
	pid_t pid = fork();
	int stopped, ret, err;

	CHECK(pid >= 0, "fork");
	if (!pid) {
		if (ptrace(PTRACE_TRACEME, 0, NULL, NULL))
			_exit(10);
		raise(SIGSTOP);
		_exit(0);
	}
	stopped = sysemu_stop(pid, SIGSTOP);
	ret = ptrace(PTRACE_SYSEMU_SINGLESTEP, pid, NULL, NULL);
	err = errno;
	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);
	CHECK(stopped && ret == -1 && err == EIO, "SYSEMU_SINGLESTEP: %d, errno %d", ret, err);
}

#undef SYSEMU_NR
#undef SYSEMU_RET

static void test_many_forks(void)
{
	int i, status;

	for (i = 0; i < 200; i++) {
		pid_t pid = fork();

		CHECK(pid >= 0, "fork %d: %s", i, strerror(errno));
		if (pid == 0)
			_exit(i & 0x7f);
		CHECK(waitpid(pid, &status, 0) == pid && WEXITSTATUS(status) == (i & 0x7f),
		      "fork %d status", i);
	}
}

/* ---- signals and FPU state */
static volatile int sig_count;
static volatile double sig_fpu;

static void usr1_handler(int sig)
{
	/* Clobber FPU/SSE state in the handler; it must be restored. */
	volatile double x = 3.0;
	int i;

	for (i = 0; i < 100; i++)
		x = x * 1.0001 + 0.5;
	sig_fpu = x;
	sig_count++;
}

static void test_signals_fpu(void)
{
	double acc = 1.0;
	int i;

	signal(SIGUSR1, usr1_handler);
	for (i = 0; i < 1000; i++) {
		acc = acc * 1.000001 + 0.000001;
		if (i % 100 == 0)
			kill(getpid(), SIGUSR1);
	}
	CHECK(sig_count == 10, "handler ran %d times", sig_count);
	{
		double ref = 1.0;

		for (i = 0; i < 1000; i++)
			ref = ref * 1.000001 + 0.000001;
		CHECK(acc == ref, "FPU state corrupted across signals: %.17g vs %.17g", acc, ref);
	}
	signal(SIGUSR1, SIG_DFL);
}

#ifndef __aarch64__
static void count_handler(int sig)
{
	sig_count++;
}

/*
 * Every register survives a signal taken in the middle of user code.  The
 * handler returns through rt_sigreturn, a syscall: resuming it with
 * sysretq would load rcx and r11 from rip and rflags.
 */
static void test_signal_regs(void)
{
	struct itimerval it = { .it_interval = { 0, 1000 }, .it_value = { 0, 1000 } };
	unsigned long rcx = 0x1111222233334444, r11 = 0x5555666677778888;
	double t0 = now();

	sig_count = 0;
	signal(SIGALRM, count_handler);
	setitimer(ITIMER_REAL, &it, NULL);
	while (sig_count < 50 && now() - t0 < 5.0 &&
	       rcx == 0x1111222233334444 && r11 == 0x5555666677778888) {
		/* Spin with the values live; stop early if one changes. */
		asm volatile("movq %[c], %%rcx\n\tmovq %[r], %%r11\n\tmovl $0x100000, %%eax\n"
			     "1:\n\tcmpq %[c], %%rcx\n\tjne 2f\n\tcmpq %[r], %%r11\n\tjne 2f\n"
			     "\tdecl %%eax\n\tjnz 1b\n"
			     "2:\n\tmovq %%rcx, %[oc]\n\tmovq %%r11, %[or]"
			     : [oc] "=m"(rcx), [or] "=m"(r11)
			     : [c] "r"(0x1111222233334444ul), [r] "r"(0x5555666677778888ul)
			     : "rax", "rcx", "r11", "cc");
	}
	memset(&it, 0, sizeof(it));
	setitimer(ITIMER_REAL, &it, NULL);
	signal(SIGALRM, SIG_DFL);
	CHECK(rcx == 0x1111222233334444 && r11 == 0x5555666677778888,
	      "after %d signals: rcx %#lx r11 %#lx", sig_count, rcx, r11);
	CHECK(sig_count >= 50, "only %d signals in 5 s", sig_count);
}
#endif

static void alarm_handler(int sig)
{
	sig_count = 1000;
}

static void test_timers(void)
{
	struct timespec req = { 0, 50 * 1000 * 1000 };
	double t0 = now(), t1;

	nanosleep(&req, NULL);
	t1 = now();
	CHECK(t1 - t0 >= 0.049 && t1 - t0 < 0.5, "nanosleep(50ms) took %.3f s", t1 - t0);

	sig_count = 0;
	signal(SIGALRM, alarm_handler);
	struct itimerval it = { .it_value = { 0, 20000 } };
	setitimer(ITIMER_REAL, &it, NULL);
	t0 = now();
	while (sig_count != 1000 && now() - t0 < 2.0)
		;
	CHECK(sig_count == 1000, "SIGALRM did not interrupt a busy loop");
}

/* A restarted read must restore its original argument in x0 on AArch64. */
static void test_syscall_restart(void)
{
 int fd[2], status;
 char c = 0;
 struct sigaction sa = { .sa_handler = usr1_handler, .sa_flags = SA_RESTART };
 CHECK(pipe(fd) == 0, "pipe");
 sigemptyset(&sa.sa_mask);
 sigaction(SIGUSR1, &sa, NULL);
 sig_count = 0;
 pid_t child = fork();
 CHECK(child >= 0, "fork");
 if (!child) {
  close(fd[0]);
  usleep(20000);
  kill(getppid(), SIGUSR1);
  usleep(20000);
  write(fd[1], "R", 1);
  _exit(0);
 }
 close(fd[1]);
 CHECK(read(fd[0], &c, 1) == 1 && c == 'R', "restarted read: %s", strerror(errno));
 CHECK(sig_count == 1, "restart handler count %d", sig_count);
 CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0, "restart child");
 close(fd[0]);
 signal(SIGUSR1, SIG_DFL);
}

#ifdef __x86_64__
/* read() with bit 63 of its number set: x86 runs the low 32 bits' syscall,
 * and must restart it as that one, not return -ERESTARTSYS. */
static long read_hi(int fd, void *buf, size_t n)
{
	long ret;

	asm volatile("syscall"
		     : "=a"(ret)
		     : "a"(__NR_read | (1ul << 63)), "D"(fd), "S"(buf), "d"(n)
		     : "rcx", "r11", "memory");
	return ret;
}

static void test_syscall_restart_hi(void)
{
	int fd[2], status;
	long n;
	char c = 0;
	struct sigaction sa = { .sa_handler = usr1_handler, .sa_flags = SA_RESTART };

	CHECK(pipe(fd) == 0, "pipe");
	sigemptyset(&sa.sa_mask);
	sigaction(SIGUSR1, &sa, NULL);
	sig_count = 0;
	pid_t child = fork();
	CHECK(child >= 0, "fork");
	if (!child) {
		close(fd[0]);
		usleep(20000);
		kill(getppid(), SIGUSR1);
		usleep(20000);
		if (write(fd[1], "R", 1) != 1)
			_exit(1);
		_exit(0);
	}
	close(fd[1]);
	n = read_hi(fd[0], &c, 1);
	CHECK(n == 1 && c == 'R', "restarted read returned %ld", n);
	CHECK(sig_count == 1, "restart handler count %d", sig_count);
	CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0, "restart child");
	close(fd[0]);
	signal(SIGUSR1, SIG_DFL);
}
#endif

/* ---- seccomp */
/* The address after the syscall instruction of trapped_getppid(). */
extern const char seccomp_trap_ip[];

static __attribute__((noinline)) long trapped_getppid(void)
{
#ifdef __x86_64__
	long ret;

	asm volatile("syscall\n.globl seccomp_trap_ip\nseccomp_trap_ip:"
		     : "=a"(ret) : "a"(__NR_getppid) : "rcx", "r11", "memory");
	return ret;
#else
	register long x8 asm("x8") = __NR_getppid;
	register long x0 asm("x0");

	asm volatile("svc #0\n.globl seccomp_trap_ip\nseccomp_trap_ip:"
		     : "=r"(x0) : "r"(x8) : "memory");
	return x0;
#endif
}

static volatile unsigned long sigsys_addr, sigsys_pc, sigsys_ax;
static volatile int sigsys_nr;

static void sigsys_handler(int sig, siginfo_t *si, void *ctx)
{
	ucontext_t *uc = ctx;

	sigsys_addr = (unsigned long)si->si_call_addr;
	sigsys_nr = si->si_syscall;
#ifdef __x86_64__
	sigsys_pc = uc->uc_mcontext.gregs[REG_RIP];
	sigsys_ax = uc->uc_mcontext.gregs[REG_RAX];
#else
	sigsys_pc = uc->uc_mcontext.pc;
#endif
}

/* Trap getppid() made at seccomp_trap_ip only, as a filter keyed on the
 * caller's address (Chromium's) does.  Returns which check failed. */
static int seccomp_trap_child(void)
{
	unsigned long ip = (unsigned long)seccomp_trap_ip;
	pid_t parent = getppid();
	struct sock_filter f[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getppid, 0, 5),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, instruction_pointer)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)ip, 0, 3),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, instruction_pointer) + 4),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)(ip >> 32), 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = { .len = sizeof(f) / sizeof(f[0]), .filter = f };
	struct sigaction sa = { .sa_sigaction = sigsys_handler, .sa_flags = SA_SIGINFO };

	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGSYS, &sa, NULL) || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
	    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog))
		return 10;
	if (getppid() != parent || sigsys_nr)
		return 11;	/* trapped at another address */
	trapped_getppid();
	if (sigsys_nr != __NR_getppid)
		return 12;	/* not trapped: the filter saw another address */
	if (sigsys_addr != ip || sigsys_pc != ip)
		return 13;
#ifdef __x86_64__
	if (sigsys_ax != __NR_getppid)
		return 14;	/* syscall_rollback() */
#endif
	return 0;
}

static void test_seccomp_trap(void)
{
	int status;
	pid_t child = fork();

	CHECK(child >= 0, "fork");
	if (!child)
		_exit(seccomp_trap_child());
	CHECK(waitpid(child, &status, 0) == child, "waitpid");
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	      "seccomp child status %#x (exit code: which check failed)", status);
}

/* ---- threads, futexes, TLS */
static __thread int tls_value;
static atomic_int counter;
static double thread_results[8];

static void *thread_fn(void *arg)
{
	long id = (long)arg;
	double x = id;
	int i;

	tls_value = (int)id * 10;
	for (i = 0; i < 2000000; i++) {
		x = x * 0.999999 + 1.0;
		if ((i & 1023) == 0)
			atomic_fetch_add(&counter, 1);
	}
	sched_yield();
	thread_results[id] = x + (tls_value == id * 10 ? 0 : 1e9);
	return NULL;
}

static void test_threads(void)
{
	pthread_t th[8];
	long i;
	int n = 8;

	atomic_store(&counter, 0);
	for (i = 0; i < n; i++)
		CHECK(pthread_create(&th[i], NULL, thread_fn, (void *)i) == 0, "pthread_create");
	for (i = 0; i < n; i++)
		pthread_join(th[i], NULL);
	CHECK(atomic_load(&counter) == n * (2000000 / 1024 + 1), "counter %d", atomic_load(&counter));
	for (i = 0; i < n; i++) {
		double ref = i;
		int k;

		for (k = 0; k < 2000000; k++)
			ref = ref * 0.999999 + 1.0;
		CHECK(thread_results[i] == ref, "thread %ld FPU/TLS result %.17g vs %.17g", i,
		      thread_results[i], ref);
	}
}

static atomic_int futex_word;

static void *futex_waker(void *arg)
{
	usleep(10000);
	atomic_store(&futex_word, 1);
	syscall(SYS_futex, &futex_word, FUTEX_WAKE, 1, NULL, NULL, 0);
	return NULL;
}

static void test_futex(void)
{
	pthread_t t;

	atomic_store(&futex_word, 0);
	pthread_create(&t, NULL, futex_waker, NULL);
	while (atomic_load(&futex_word) == 0)
		syscall(SYS_futex, &futex_word, FUTEX_WAIT, 0, NULL, NULL, 0);
	pthread_join(t, NULL);
	CHECK(atomic_load(&futex_word) == 1, "futex");
}

static void test_files(void)
{
	char buf[4096];
	char *path;
	const char *dir = getenv("TMPDIR");
	CHECK(asprintf(&path, "%s/selftest.XXXXXX", dir ? dir : "/tmp") >= 0, "file path");
	int fd = mkstemp(path);
	int i;

	CHECK(fd >= 0, "open: %s", strerror(errno));
	unlink(path);
	free(path);
	memset(buf, 'x', sizeof(buf));
	for (i = 0; i < 256; i++)
		CHECK(write(fd, buf, sizeof(buf)) == sizeof(buf), "write");
	CHECK(lseek(fd, 0, SEEK_SET) == 0, "lseek");
	for (i = 0; i < 256; i++)
		CHECK(read(fd, buf, sizeof(buf)) == sizeof(buf) && buf[17] == 'x', "read");
	close(fd);
}

/* ---- SMP stress: concurrent faults, mmap/munmap and forks */
static atomic_int stress_errors;
/* First wrong value read back, and what was expected there. */
static _Atomic uint64_t stress_got, stress_want;

/* Each page holds its owner thread, round and page index, so a wrong
 * value tells whose page was read instead. */
#define STRESS_TAG(id, round, pg) \
	(0xa5ull << 56 | (uint64_t)(id) << 48 | (uint64_t)(round) << 24 | (pg))

static void *mm_stress_fn(void *arg)
{
	long id = (long)arg;
	int round;

	for (round = 0; round < 200; round++) {
		size_t len = (1 + (round % 7)) * 65536;
		volatile uint64_t *p = mmap(NULL, len, PROT_READ | PROT_WRITE,
					    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		size_t i;

		if (p == MAP_FAILED) {
			atomic_fetch_add(&stress_errors, 1);
			continue;
		}
		for (i = 0; i < len / 4096; i++)
			p[i * 512] = STRESS_TAG(id, round, i);
		for (i = 0; i < len / 4096; i++) {
			uint64_t got = p[i * 512], want = STRESS_TAG(id, round, i);

			if (got != want && atomic_fetch_add(&stress_errors, 1) == 0) {
				atomic_store(&stress_got, got);
				atomic_store(&stress_want, want);
			}
		}
		if (round & 1)
			mprotect((void *)p, len, PROT_READ);
		munmap((void *)p, len);
	}
	return NULL;
}

static void test_smp_mm_stress(void)
{
	pthread_t th[8];
	long i;

	atomic_store(&stress_errors, 0);
	for (i = 0; i < 8; i++)
		pthread_create(&th[i], NULL, mm_stress_fn, (void *)i);
	for (i = 0; i < 8; i++)
		pthread_join(th[i], NULL);
	CHECK(atomic_load(&stress_errors) == 0, "%d errors, first read %016llx for %016llx "
	      "(tags: a5, thread, round, page)", atomic_load(&stress_errors),
	      (unsigned long long)atomic_load(&stress_got), (unsigned long long)atomic_load(&stress_want));
}

/* A use-after-munmap from another thread must fault, not read stale data. */
static volatile unsigned char *shared_page;
static atomic_int phase;

static void *unmap_reader(void *arg)
{
	struct sigaction sa = { .sa_sigaction = segv_handler, .sa_flags = SA_SIGINFO };

	sigaction(SIGSEGV, &sa, NULL);
	while (atomic_load(&phase) == 0)
		(void)shared_page[0];
	atomic_store(&phase, 2);
	while (atomic_load(&phase) != 3)
		;
	if (sigsetjmp(segv_jmp, 1) == 0) {
		(void)shared_page[0];
		atomic_store(&phase, 5);	/* no fault: stale mapping */
	} else {
		atomic_store(&phase, 4);
	}
	return NULL;
}

static void test_smp_unmap_visibility(void)
{
	pthread_t t;

	shared_page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	shared_page[0] = 7;
	atomic_store(&phase, 0);
	pthread_create(&t, NULL, unmap_reader, NULL);
	usleep(10000);
	atomic_store(&phase, 1);
	while (atomic_load(&phase) != 2)
		;
	munmap((void *)shared_page, 4096);
	atomic_store(&phase, 3);
	pthread_join(t, NULL);
	signal(SIGSEGV, SIG_DFL);
	CHECK(atomic_load(&phase) == 4, "reader saw a stale mapping after munmap");
}

static void *fork_storm_fn(void *arg)
{
	int i, status;

	for (i = 0; i < 50; i++) {
		pid_t pid = fork();

		if (pid == 0) {
			volatile char buf[65536];

			buf[0] = 1;
			buf[65535] = buf[0];
			_exit(3);
		}
		if (pid < 0 || waitpid(pid, &status, 0) != pid || WEXITSTATUS(status) != 3)
			atomic_fetch_add(&stress_errors, 1);
	}
	return NULL;
}

static void test_smp_fork_storm(void)
{
	pthread_t th[4];
	long i;

	atomic_store(&stress_errors, 0);
	for (i = 0; i < 4; i++)
		pthread_create(&th[i], NULL, fork_storm_fn, NULL);
	for (i = 0; i < 4; i++)
		pthread_join(th[i], NULL);
	CHECK(atomic_load(&stress_errors) == 0, "%d errors", atomic_load(&stress_errors));
}

#define AGING_PAGES 512

static int clear_refs(void)
{
	int fd = open("/proc/self/clear_refs", O_WRONLY), ok;

	if (fd < 0)
		return -1;
	ok = write(fd, "1", 1) == 1;
	close(fd);
	return ok ? 0 : -1;
}

static volatile unsigned long *aging_mem;
static atomic_int aging_stop, aging_bad;

static void *aging_reader(void *arg)
{
	unsigned long i = 0;

	while (!atomic_load(&aging_stop)) {
		if (aging_mem[i * 512] != i)
			atomic_fetch_add(&aging_bad, 1);
		i = (i + 1) % AGING_PAGES;
	}
	return NULL;
}

static int sample_young(int fd, const volatile void *start, size_t size)
{
	struct aging_range range = { .start = (uintptr_t)start, .size = size };

	return ioctl(fd, L4H_AGING_SAMPLE, &range);
}

/* clear_refs and reclaim must see reads even after the software young bit
 * is clear.  The test module invokes reclaim's hook; smaps' Referenced
 * intentionally only sees the software PTE. */
static void test_page_aging(void)
{
	unsigned long i, sum = 0;
	pthread_t reader;
	struct rusage before, after;
	int fd = open("/dev/l4h_page_aging", O_RDONLY), hot, cold, aging_err = 0;
	const size_t churn_size = 32 * 1024 * 1024;
	volatile unsigned long *churn = mmap(NULL, churn_size, PROT_READ | PROT_WRITE,
					   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	char *area = mmap(NULL, (AGING_PAGES + 2) * 4096, PROT_NONE,
			  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	/* Other runners reuse this binary without the test module.  They
	 * still exercise concurrent aging and data integrity below. */
	if (fd < 0)
		printf("  page_aging: hardware sampling skipped (no test module)\n");
	CHECK(area != MAP_FAILED && churn != MAP_FAILED, "mmap: %s", strerror(errno));
	aging_mem = (volatile unsigned long *)(area + 4096);
	CHECK(mprotect((void *)aging_mem, AGING_PAGES * 4096, PROT_READ | PROT_WRITE) == 0,
	      "mprotect: %s", strerror(errno));
	for (i = 0; i < churn_size / 4096; i++)
		churn[i * 512] = i;
	for (i = 0; i < AGING_PAGES; i++)
		aging_mem[i * 512] = i;
	if (fd >= 0) {
		CHECK(sample_young(fd, aging_mem, AGING_PAGES * 4096) == AGING_PAGES,
		      "initial software young bits missing");
		CHECK(sample_young(fd, aging_mem, AGING_PAGES * 4096) == 0,
		      "test-and-clear did not clear both bits");
	}
	CHECK(mprotect((void *)aging_mem, AGING_PAGES * 4096, PROT_READ) == 0, "read-only");
	CHECK(clear_refs() == 0, "clear_refs: %s", strerror(errno));
	if (fd >= 0)
		CHECK(sample_young(fd, aging_mem, AGING_PAGES * 4096) == 0,
		      "clear_refs did not clear hardware accessed bits");
	/* Aging deliberately does not invalidate TLBs.  Evict cached AF=1/A=1
	 * translations before checking that page walks record new accesses. */
	for (i = 0; i < churn_size / 4096; i++)
		sum += churn[i * 512];
	sum = 0;
	getrusage(RUSAGE_SELF, &before);
	for (i = 0; i < AGING_PAGES / 2; i++)
		sum += aging_mem[i * 512];
	getrusage(RUSAGE_SELF, &after);
	CHECK(sum == (AGING_PAGES / 2) * (AGING_PAGES / 2 - 1) / 2, "data changed");
	if (fd >= 0) {
		hot = sample_young(fd, aging_mem, AGING_PAGES / 2 * 4096);
		cold = sample_young(fd, aging_mem + AGING_PAGES / 2 * 512, AGING_PAGES / 2 * 4096);
		CHECK(hot >= AGING_PAGES / 2 * 3 / 4 && cold >= 0 && cold <= 16,
		      "young pages: hot=%d, cold=%d", hot, cold);
		CHECK(sample_young(fd, aging_mem, AGING_PAGES * 4096) == 0, "access counted twice");
	}
	CHECK(after.ru_minflt - before.ru_minflt < 8 && after.ru_majflt == before.ru_majflt,
	      "aging delivered guest faults: minor=%ld major=%ld",
	      after.ru_minflt - before.ru_minflt, after.ru_majflt - before.ru_majflt);
	munmap((void *)churn, churn_size);
	CHECK(mprotect((void *)aging_mem, AGING_PAGES * 4096, PROT_READ | PROT_WRITE) == 0,
	      "read-write");

	/* Aging while another thread reads and the main thread writes. */
	atomic_store(&aging_stop, 0);
	atomic_store(&aging_bad, 0);
	CHECK(pthread_create(&reader, NULL, aging_reader, NULL) == 0, "pthread_create");
	for (int round = 0; round < 50; round++) {
		if (clear_refs()) {
			aging_err = 1;
			break;
		}
		for (i = round % 2; i < AGING_PAGES; i += 2)
			aging_mem[i * 512 + 1] = round;
	}
	atomic_store(&aging_stop, 1);
	pthread_join(reader, NULL);
	CHECK(!aging_err, "clear_refs during reads");
	CHECK(!atomic_load(&aging_bad), "%d reads saw wrong data", atomic_load(&aging_bad));
	for (i = 0; i < AGING_PAGES; i++)
		CHECK(aging_mem[i * 512] == i && aging_mem[i * 512 + 1] == 48 + i % 2,
		      "page %lu lost data", i);
	munmap(area, (AGING_PAGES + 2) * 4096);
	if (fd >= 0)
		close(fd);
}

/* More live processes than the guest has seL4 VSpaces (64): sleeping ones
 * lose theirs and get one back when they run again. */
static void test_vspace_evict(void)
{
	enum { N = 96 };
	int fds[N][2], i, status, ok = 1;
	pid_t pids[N];

	for (i = 0; i < N; i++) {
		CHECK(pipe(fds[i]) == 0, "pipe: %s", strerror(errno));
		pids[i] = fork();
		CHECK(pids[i] >= 0, "fork %d: %s", i, strerror(errno));
		if (pids[i] == 0) {
			char c;
			volatile int touch[1024];

			touch[i] = i;
			if (read(fds[i][0], &c, 1) != 1)
				_exit(1);
			_exit(touch[i] == i && c == 'x' ? 0 : 2);
		}
	}
	/* Wake them in turn: each one's VSpace was probably given away. */
	for (i = 0; i < N; i++) {
		if (write(fds[i][1], "x", 1) != 1)
			ok = 0;
		if (waitpid(pids[i], &status, 0) != pids[i] || !WIFEXITED(status) || WEXITSTATUS(status))
			ok = 0;
		close(fds[i][0]);
		close(fds[i][1]);
	}
	CHECK(ok, "a child failed");
}

/* FUTEX_WAKE_OP updates the second word atomically, while user threads on
 * other vCPUs update it with atomic instructions. */
static atomic_int wake_op_word;
static atomic_int wake_op_running;

static void *wake_op_fn(void *arg)
{
	int i, dummy = 0;

	for (i = 0; i < 20000; i++)
		syscall(SYS_futex, &dummy, FUTEX_WAKE_OP_PRIVATE, 0, NULL, &wake_op_word,
			FUTEX_OP(FUTEX_OP_ADD, 1, FUTEX_OP_CMP_EQ, 0));
	atomic_fetch_sub(&wake_op_running, 1);
	return NULL;
}

static void *wake_op_user_fn(void *arg)
{
	long n = 0;

	while (atomic_load(&wake_op_running)) {
		atomic_fetch_add(&wake_op_word, 1);
		n++;
	}
	return (void *)n;
}

static void test_futex_wake_op(void)
{
	pthread_t th[4];
	long total = 2 * 20000;
	void *n;
	int i;

	atomic_store(&wake_op_word, 0);
	atomic_store(&wake_op_running, 2);
	for (i = 0; i < 2; i++)
		pthread_create(&th[i], NULL, wake_op_fn, NULL);
	for (i = 2; i < 4; i++)
		pthread_create(&th[i], NULL, wake_op_user_fn, NULL);
	for (i = 0; i < 4; i++) {
		pthread_join(th[i], &n);
		if (i >= 2)
			total += (long)n;
	}
	CHECK(atomic_load(&wake_op_word) == (int)total, "counter %d, expected %ld (updates lost)",
	      atomic_load(&wake_op_word), total);
}

/*
 * A robust futex list entry whose word is unaligned at a page's end
 * (0xffd..0x1000): the kernel must not run an atomic update off the page
 * through its direct map, into whatever physical page follows.  Its exit
 * walk skips the entry, the word and the next page are left alone, and
 * FUTEX_WAIT on that address is refused.
 */
struct robust_test {
	struct robust_list_head head;
	struct robust_list entry;
};

static void *robust_unaligned_fn(void *arg)
{
	struct robust_test *t = arg;

	syscall(SYS_set_robust_list, &t->head, sizeof(t->head));
	return NULL;
}

static void test_futex_unaligned(void)
{
	unsigned char *p = mmap(NULL, 2 * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	unsigned char *word, want[4], next[64];
	struct robust_test *t;
	pthread_t th;
	long r;
	int i;

	CHECK(p != MAP_FAILED, "mmap: %s", strerror(errno));
	word = p + 4096 - 3;
	memset(p + 4096, 0x5c, 4096);
	memcpy(next, p + 4096, sizeof(next));
	t = (struct robust_test *)p;
	t->head.list.next = &t->entry;
	t->entry.next = &t->head.list;
	t->head.futex_offset = (long)(word - (unsigned char *)&t->entry);
	t->head.list_op_pending = NULL;
	for (i = 0; i < 3; i++)
		word[i] = 0;
	CHECK(pthread_create(&th, NULL, robust_unaligned_fn, t) == 0, "pthread_create");
	pthread_join(th, NULL);
	/* What the exit walk would have written had it taken the entry. */
	memset(want, 0, sizeof(want));
	CHECK(memcmp(word, want, 3) == 0, "unaligned robust word changed: %02x %02x %02x",
	      word[0], word[1], word[2]);
	CHECK(memcmp(p + 4096, next, sizeof(next)) == 0, "the page after the robust word changed");
	errno = 0;
	r = syscall(SYS_futex, word, FUTEX_WAIT, 0, NULL, NULL, 0);
	CHECK(r == -1 && errno == EINVAL, "FUTEX_WAIT on an unaligned word: %ld (%s)", r, strerror(errno));
	errno = 0;
	r = syscall(SYS_futex, p + 4096 - 4, FUTEX_WAKE_OP, 1, NULL, word, FUTEX_OP(FUTEX_OP_SET, 1, FUTEX_OP_CMP_EQ, 0));
	CHECK(r == -1 && errno == EINVAL, "FUTEX_WAKE_OP on an unaligned word: %ld (%s)", r, strerror(errno));
	CHECK(memcmp(p + 4096, next, sizeof(next)) == 0, "the page after the futex word changed");
	munmap(p, 2 * 4096);
}

/*
 * A string argument at a kernel address fails at once with EFAULT, both
 * where the kernel copies it (strncpy_from_user: execve, openat) and where
 * it measures it first (strnlen_user via strndup_user: add_key, mount),
 * not with ENOMEM from taking a negative error for a length.
 */
static void test_uaccess_kernel_strings(void)
{
	const char *bad = (const char *)~0UL;
	const char *high = (const char *)(1UL << 63);
	char *argv[] = { NULL };
	long r;
	int i;

	for (i = 0; i < 2; i++) {
		const char *s = i ? high : bad;

		errno = 0;
		r = syscall(SYS_execve, s, argv, argv);
		CHECK(r == -1 && errno == EFAULT, "execve(%p): %ld (%s)", s, r, strerror(errno));
		errno = 0;
		r = syscall(SYS_openat, AT_FDCWD, s, O_RDONLY);
		CHECK(r == -1 && errno == EFAULT, "openat(%p): %ld (%s)", s, r, strerror(errno));
		errno = 0;
		r = syscall(SYS_add_key, "user", s, "x", 1, -2 /* KEY_SPEC_PROCESS_KEYRING */);
		CHECK(r == -1 && errno == EFAULT, "add_key(%p): %ld (%s)", s, r, strerror(errno));
		errno = 0;
		r = syscall(SYS_mount, "none", "/tmp", s, 0, NULL);
		CHECK(r == -1 && errno == EFAULT, "mount type %p: %ld (%s)", s, r, strerror(errno));
	}
	/* A string ending right before an unmapped page still works. */
	{
		char *p = mmap(NULL, 2 * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

		CHECK(p != MAP_FAILED, "mmap: %s", strerror(errno));
		CHECK(munmap(p + 4096, 4096) == 0, "munmap: %s", strerror(errno));
		memcpy(p + 4096 - 8, "/nonexi", 8);
		errno = 0;
		r = syscall(SYS_openat, AT_FDCWD, p + 4096 - 8, O_RDONLY);
		CHECK(r == -1 && errno == ENOENT, "openat at a page's end: %ld (%s)", r, strerror(errno));
		/* No NUL before the unmapped page: a fault. */
		memcpy(p + 4096 - 8, "/nonexis", 8);
		errno = 0;
		r = syscall(SYS_openat, AT_FDCWD, p + 4096 - 8, O_RDONLY);
		CHECK(r == -1 && errno == EFAULT, "openat across into an unmapped page: %ld (%s)", r, strerror(errno));
		munmap(p, 4096);
	}
}

/*
 * /dev/l4h-attest needs CAP_SYS_ADMIN at each ioctl, as /dev/l4hctl: the
 * taint and seal bitmaps are the whole guest's.  A child that drops the
 * capability is refused on a descriptor its root parent opened.
 */
struct attest_ioc {
	uint32_t op, blob_len, secret_len, out_len;
	uint64_t data, out;
};
#define ATTEST_IOC _IOWR('L', 2, struct attest_ioc)

static int attest_read_flags(int fd)
{
	unsigned char zero[32] = { 0 }, out[64];
	struct attest_ioc c = { .op = 4 /* ACT, empty: read */, .blob_len = sizeof(zero),
				.out_len = sizeof(out), .data = (uintptr_t)zero,
				.out = (uintptr_t)out };

	return ioctl(fd, ATTEST_IOC, &c) < 0 ? -errno : 0;
}

/*
 * The exit status of a child that maps `prot` at guest-physical `off`
 * through `fd` (MAP_SHARED, a PFNMAP), reads it, and, with `write`, writes
 * it: first mapped readable and read, then made writable, with
 * `mprotect_first`.
 */
static int pfnmap_access(int fd, unsigned long long off, int prot, int write, int mprotect_first)
{
	int status;
	pid_t pid = fork();

	if (pid < 0)
		return -1;
	if (pid == 0) {
		volatile unsigned char *p = mmap(NULL, 4096, mprotect_first ? PROT_READ : prot,
						 MAP_SHARED, fd, off);

		alarm(10);
		if (p == MAP_FAILED)
			_exit(100);
		(void)p[0];
		if (mprotect_first && mprotect((void *)p, 4096, prot))
			_exit(101);
		if (write)
			p[0] = p[0];
		_exit(0);
	}
	if (waitpid(pid, &status, 0) != pid)
		return -1;
	return status;
}

/*
 * There is no /dev/mem.  A user mapping of physical memory that is no
 * frame of the guest's RAM (a driver's PFNMAP, here the test module's,
 * past the 64 GiB the RAM CNodes cover, where the frame capability's
 * address would name the guest kernel's other root slots and its own
 * CNodes) is a bus error at the first access: never a copy of whatever
 * capability that address names, nor a fault that repeats for ever or
 * calls the OOM killer as if memory were short.  Nor is a write to the
 * kernel's image, whose shared blocks have read-only frames: mapped
 * writable, or readable and then made writable; reading it works.
 */
static void test_pfnmap_unbacked(void)
{
	static const unsigned long long offsets[] = { 64ULL << 30, 65ULL << 30, 448ULL << 30, (448ULL << 30) + (5 << 12) };
	const char *node = "/tmp/selftest-mem";
	unsigned i;
	int fd, status;

	unlink(node);
	CHECK(mknod(node, S_IFCHR | 0600, makedev(1, 1)) == 0, "mknod: %s", strerror(errno));
	fd = open(node, O_RDONLY);
	unlink(node);
	CHECK(fd < 0 && (errno == ENXIO || errno == ENODEV), "/dev/mem: %s", fd < 0 ? strerror(errno) : "opened");

	fd = open("/dev/l4h_page_aging", O_RDWR);
	if (fd < 0) {
		printf("  pfnmap_unbacked: skipped (no test module)\n");
		return;
	}
	for (i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
		status = pfnmap_access(fd, offsets[i], PROT_READ, 0, 0);
		CHECK(status >= 0 && WIFSIGNALED(status) && WTERMSIG(status) == SIGBUS,
		      "PFNMAP at %#llx: status %#x, not SIGBUS", offsets[i], status);
	}
	status = pfnmap_access(fd, 0, PROT_READ, 0, 0);
	CHECK(status >= 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0,
	      "reading the kernel's image: status %#x", status);
	status = pfnmap_access(fd, 0, PROT_READ | PROT_WRITE, 1, 0);
	CHECK(status >= 0 && WIFSIGNALED(status) && WTERMSIG(status) == SIGBUS,
	      "writing the kernel's image: status %#x, not SIGBUS", status);
	status = pfnmap_access(fd, 0, PROT_READ | PROT_WRITE, 1, 1);
	CHECK(status >= 0 && WIFSIGNALED(status) && WTERMSIG(status) == SIGBUS,
	      "writing the kernel's image after mprotect: status %#x, not SIGBUS", status);
	close(fd);
}

static void test_attest_cap(void)
{
	struct __user_cap_header_struct h = { .version = _LINUX_CAPABILITY_VERSION_3 };
	struct __user_cap_data_struct d[2];
	int fd = open("/dev/l4h-attest", O_RDWR), status, r;
	pid_t pid;

	CHECK(fd >= 0, "open /dev/l4h-attest: %s", strerror(errno));
	r = attest_read_flags(fd);
	CHECK(r == 0, "reading the flags as root: %s", strerror(-r));
	pid = fork();
	if (pid == 0) {
		if (syscall(SYS_capget, &h, d) != 0)
			_exit(10);
		d[CAP_SYS_ADMIN / 32].effective &= ~(1u << (CAP_SYS_ADMIN % 32));
		d[CAP_SYS_ADMIN / 32].permitted &= ~(1u << (CAP_SYS_ADMIN % 32));
		if (syscall(SYS_capset, &h, d) != 0)
			_exit(11);
		r = attest_read_flags(fd);
		_exit(r == -EPERM ? 0 : r == 0 ? 12 : 13);
	}
	CHECK(pid > 0, "fork: %s", strerror(errno));
	waitpid(pid, &status, 0);
	close(fd);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	      "without CAP_SYS_ADMIN: exit %d (10, 11: capget/capset; 12: allowed; 13: not EPERM)",
	      WIFEXITED(status) ? WEXITSTATUS(status) : -1);
}

#ifdef __x86_64__
/*
 * rt_sigreturn takes only the flags user code may set (ptrace's
 * FLAG_MASK): a handler that puts IOPL 3 or VIP in the saved context gets
 * neither, while the arithmetic flags it sets come back.
 */
static volatile unsigned long efl_seen;

static void efl_set_handler(int sig, siginfo_t *si, void *ctx)
{
	ucontext_t *uc = ctx;

	uc->uc_mcontext.gregs[REG_EFL] |= 0x3000 /* IOPL 3 */ | 0x100000 /* VIP */ |
					  0x80000 /* VIF */ | 0x1 /* CF */;
}

static void efl_get_handler(int sig, siginfo_t *si, void *ctx)
{
	efl_seen = ((ucontext_t *)ctx)->uc_mcontext.gregs[REG_EFL];
}

static void test_sigreturn_eflags(void)
{
	struct sigaction sa = { .sa_flags = SA_SIGINFO };
	unsigned long after;
	long pid = getpid(), tid = syscall(SYS_gettid);

	sa.sa_sigaction = efl_set_handler;
	sigaction(SIGUSR1, &sa, NULL);
	sa.sa_sigaction = efl_get_handler;
	sigaction(SIGUSR2, &sa, NULL);
	/* The signal comes as tgkill returns; read the flags right after. */
	asm volatile("syscall\n\tpushfq\n\tpopq %[f]"
		     : [f] "=r"(after)
		     : "a"((long)SYS_tgkill), "D"(pid), "S"(tid), "d"((long)SIGUSR1)
		     : "rcx", "r11", "memory", "cc");
	CHECK(after & 0x1, "CF the handler set was lost: %#lx", after);
	CHECK(!(after & (0x3000 | 0x100000 | 0x80000)), "privileged flags after sigreturn: %#lx", after);
	efl_seen = ~0UL;
	syscall(SYS_tgkill, pid, tid, SIGUSR2);
	CHECK(efl_seen != ~0UL, "second signal not delivered");
	CHECK(!(efl_seen & (0x3000 | 0x100000 | 0x80000)), "privileged flags saved: %#lx", efl_seen);
	signal(SIGUSR1, SIG_DFL);
	signal(SIGUSR2, SIG_DFL);
}
#endif

/* sched_getcpu() (the vDSO) agrees with the CPU a thread is pinned to. */
static void test_getcpu(void)
{
	long n = sysconf(_SC_NPROCESSORS_ONLN), cpu;
	cpu_set_t set, old;

	sched_getaffinity(0, sizeof(old), &old);
	for (cpu = 0; cpu < n; cpu++) {
		unsigned int c = ~0u;
		int vdso;

		CPU_ZERO(&set);
		CPU_SET(cpu, &set);
		sched_setaffinity(0, sizeof(set), &set);
		vdso = sched_getcpu();
		syscall(SYS_getcpu, &c, NULL, NULL);
		/* Unpin before checking: later tests must not run pinned. */
		sched_setaffinity(0, sizeof(old), &old);
		CHECK(c == cpu, "getcpu syscall %u on CPU %ld", c, cpu);
		CHECK(vdso == cpu, "sched_getcpu %d on CPU %ld", vdso, cpu);
	}
}

/* A syscall can move a faulted user context to another vCPU.  Its old
 * vCPU must release it before running another task, including when the
 * migrated thread immediately exits and its task_struct is freed. */
static void *migrate_exit_fn(void *arg)
{
	long n = (long)arg;
	cpu_set_t set;

	for (int i = 0; i < 8; i++) {
		unsigned int cpu = ~0u;
		int target = (n + i) % sysconf(_SC_NPROCESSORS_ONLN);

		CPU_ZERO(&set);
		CPU_SET(target, &set);
		if (sched_setaffinity(0, sizeof(set), &set))
			return (void *)1;
		if (syscall(SYS_getcpu, &cpu, NULL, NULL) || cpu != target)
			return (void *)1;
		sched_yield();
	}
	return NULL;
}

static void test_smp_migrate_exit(void)
{
	pthread_t th[8];

	if (sysconf(_SC_NPROCESSORS_ONLN) < 2)
		return;
	for (int round = 0; round < 64; round++) {
		for (long i = 0; i < 8; i++)
			CHECK(!pthread_create(&th[i], NULL, migrate_exit_fn, (void *)i),
			      "pthread_create");
		for (int i = 0; i < 8; i++) {
			void *result;

			CHECK(!pthread_join(th[i], &result) && !result,
			      "migrated thread failed");
		}
	}
}

struct test {
	const char *name;
	void (*fn)(void);
};

static const struct test tests[] = {
	{ "syscall_regs", test_syscall_regs },
#ifdef __aarch64__
	{ "arm_exceptions", test_arm_exceptions },
#endif
	{ "mmap", test_mmap },
	{ "mmap_high", test_mmap_high },
	{ "segv", test_segv },
	{ "nx", test_nx },
#ifndef __aarch64__
	{ "int_gate", test_int_gate },
#endif
	{ "uaccess_prot", test_uaccess_prot },
	{ "fork", test_fork },
	{ "many_forks", test_many_forks },
	{ "ptrace", test_ptrace },
	{ "ptrace_sysemu", test_ptrace_sysemu },
	{ "ptrace_sysemu_seccomp", test_ptrace_sysemu_seccomp },
	{ "ptrace_sysemu_nostep", test_ptrace_sysemu_nostep },
#ifdef __aarch64__
	{ "ptrace_syscall", test_ptrace_syscall },
#endif
	{ "signals_fpu", test_signals_fpu },
#ifndef __aarch64__
	{ "ptrace_fpregs", test_ptrace_fpregs },
	{ "ptrace_setregs", test_ptrace_setregs },
	{ "clone_settls", test_clone_settls },
	{ "signal_regs", test_signal_regs },
#endif
	{ "timers", test_timers },
	{ "syscall_restart", test_syscall_restart },
#ifdef __x86_64__
	{ "syscall_restart_hi", test_syscall_restart_hi },
#endif
	{ "seccomp_trap", test_seccomp_trap },
	{ "threads", test_threads },
	{ "futex", test_futex },
	{ "futex_wake_op", test_futex_wake_op },
	{ "futex_unaligned", test_futex_unaligned },
	{ "uaccess_kstr", test_uaccess_kernel_strings },
	{ "attest_cap", test_attest_cap },
	{ "pfnmap_unbacked", test_pfnmap_unbacked },
#ifdef __x86_64__
	{ "sigreturn_efl", test_sigreturn_eflags },
#endif
	{ "getcpu", test_getcpu },
	{ "smp_migrate_exit", test_smp_migrate_exit },
	{ "files", test_files },
	{ "smp_mm_stress", test_smp_mm_stress },
	{ "smp_unmap_vis", test_smp_unmap_visibility },
	{ "uaccess_race", test_uaccess_race },
	{ "smp_fork_storm", test_smp_fork_storm },
	{ "vspace_evict", test_vspace_evict },
	{ "page_aging", test_page_aging },
};

int main(int argc, char **argv)
{
	unsigned i;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (argc == 2 && !strcmp(argv[1], "--mmap-high-child")) {
		mmap_high_child();
		return failures != 0;
	}
	printf("SELFTEST: start (%ld CPUs online)\n", sysconf(_SC_NPROCESSORS_ONLN));
	for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
		int before = failures, j, want = argc < 2;
		double t0 = now();

		/* selftest NAME...: only those tests. */
		for (j = 1; j < argc; j++)
			want |= !strcmp(argv[j], tests[i].name);
		if (!want)
			continue;

		tests[i].fn();
		printf("  %-14s %s (%.3f s)\n", tests[i].name, failures == before ? "ok" : "FAILED",
		       now() - t0);
	}
	if (failures)
		printf("SELFTEST: FAIL (%d)\n", failures);
	else
		printf("SELFTEST: PASS\n");
	return failures != 0;
}

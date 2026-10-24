/*
 * l4h guest self-test: exercises the Linux user ABI as implemented by the
 * l4h guest kernel.  Built as a static native-ISA binary and run inside a
 * guest; prints "SELFTEST: PASS" or "SELFTEST: FAIL <test>".
 */
#define _GNU_SOURCE
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
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#ifdef __x86_64__
#include <asm/prctl.h>
#else
#include <asm/ptrace.h>
#include <sys/uio.h>
#include <elf.h>
#endif
#include <linux/futex.h>
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
	int fd = open("/tmp/selftest", O_CREAT | O_RDWR | O_TRUNC, 0644);
	int i;

	CHECK(fd >= 0, "open: %s", strerror(errno));
	memset(buf, 'x', sizeof(buf));
	for (i = 0; i < 256; i++)
		CHECK(write(fd, buf, sizeof(buf)) == sizeof(buf), "write");
	CHECK(lseek(fd, 0, SEEK_SET) == 0, "lseek");
	for (i = 0; i < 256; i++)
		CHECK(read(fd, buf, sizeof(buf)) == sizeof(buf) && buf[17] == 'x', "read");
	close(fd);
	unlink("/tmp/selftest");
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
	{ "segv", test_segv },
	{ "nx", test_nx },
#ifndef __aarch64__
	{ "int_gate", test_int_gate },
#endif
	{ "uaccess_prot", test_uaccess_prot },
	{ "fork", test_fork },
	{ "many_forks", test_many_forks },
	{ "ptrace", test_ptrace },
#ifdef __aarch64__
	{ "ptrace_syscall", test_ptrace_syscall },
#endif
	{ "signals_fpu", test_signals_fpu },
#ifndef __aarch64__
	{ "ptrace_fpregs", test_ptrace_fpregs },
	{ "signal_regs", test_signal_regs },
#endif
	{ "timers", test_timers },
	{ "syscall_restart", test_syscall_restart },
	{ "threads", test_threads },
	{ "futex", test_futex },
	{ "futex_wake_op", test_futex_wake_op },
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

// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM micro-benchmarks for tests/run-kvmbench.sh: the same binary runs in
 * l4h's dom0 and in a plain Linux VM, and prints KVMBENCH lines.
 *   cpuid   exits KVM handles in the kernel
 *   pio     exits to userspace (an OUT to an unclaimed port)
 *   mmio    exits to userspace through the instruction emulator
 *   fault   first touches of guest memory: EPT violations (4 KiB pages)
 *   spin    no exits: guest compute
 */
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>

#define MEM_SIZE (512ul << 20)

/* rdi = operation, rsi = count. */
extern const char g_start[], g_end[];
__asm__(".pushsection .rodata\n.code64\n"
	"g_start:\n"
	"  cmp $1, %rdi\n  je 1f\n"
	"  cmp $2, %rdi\n  je 2f\n"
	"  cmp $3, %rdi\n  je 3f\n"
	"  cmp $4, %rdi\n  je 4f\n"
	"  jmp 5f\n"
	"1: mov %rsi, %r12\n"		/* cpuid */
	"11: xor %eax, %eax\n  cpuid\n  dec %r12\n  jnz 11b\n  jmp 9f\n"
	"2: mov %rsi, %rcx\n  mov $0x500, %dx\n"	/* pio */
	"21: out %al, %dx\n  dec %rcx\n  jnz 21b\n  jmp 9f\n"
	"3: mov %rsi, %rcx\n  mov $0xd0000000, %rbx\n"	/* mmio */
	"31: mov %eax, (%rbx)\n  dec %rcx\n  jnz 31b\n  jmp 9f\n"
	"4: mov $0x1000000, %rbx\n  mov %rsi, %rcx\n"	/* fault: rsi pages */
	"41: mov %rbx, (%rbx)\n  add $4096, %rbx\n  dec %rcx\n  jnz 41b\n  jmp 9f\n"
	"5: mov %rsi, %rcx\n"				/* spin */
	"51: dec %rcx\n  jnz 51b\n"
	"9: hlt\n"
	"g_end:\n.popsection\n");

static int kvm, vmfd, vcpu;
static struct kvm_run *run;
static uint8_t *mem;

static void die(const char *what)
{
	perror(what);
	printf("KVMBENCH: FAIL\n");
	exit(1);
}

static void setup(void)
{
	struct kvm_userspace_memory_region r = { .slot = 0, .memory_size = MEM_SIZE };
	struct { struct kvm_cpuid2 c; struct kvm_cpuid_entry2 e[100]; } cpuid = { .c.nent = 100 };
	struct kvm_sregs sregs;
	uint64_t *pml4, *pdpt, *pd;
	int i;

	vmfd = ioctl(kvm, KVM_CREATE_VM, 0);
	if (vmfd < 0)
		die("KVM_CREATE_VM");
	mem = mmap(NULL, MEM_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	/* Base pages: the fault benchmark counts 4 KiB EPT faults. */
	madvise(mem, MEM_SIZE, MADV_NOHUGEPAGE);
	r.userspace_addr = (uintptr_t)mem;
	if (ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &r))
		die("KVM_SET_USER_MEMORY_REGION");
	vcpu = ioctl(vmfd, KVM_CREATE_VCPU, 0);
	if (vcpu < 0)
		die("KVM_CREATE_VCPU");
	if (ioctl(kvm, KVM_GET_SUPPORTED_CPUID, &cpuid) || ioctl(vcpu, KVM_SET_CPUID2, &cpuid))
		die("CPUID");
	run = mmap(NULL, ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, 0), PROT_READ | PROT_WRITE, MAP_SHARED, vcpu, 0);
	memcpy(mem + 0x1000, g_start, g_end - g_start);
	pml4 = (uint64_t *)(mem + 0x10000);
	pdpt = (uint64_t *)(mem + 0x11000);
	pd = (uint64_t *)(mem + 0x12000);
	pml4[0] = 0x11000 | 3;
	pdpt[0] = 0x12000 | 3;
	pdpt[3] = 0x13000 | 3;
	for (i = 0; i < 512; i++) {
		pd[i] = ((uint64_t)i << 21) | 0x83;
		((uint64_t *)(mem + 0x13000))[i] = (0xc0000000ul + ((uint64_t)i << 21)) | 0x83;
	}
	ioctl(vcpu, KVM_GET_SREGS, &sregs);
	sregs.cr3 = 0x10000;
	sregs.cr4 = 1 << 5;
	sregs.cr0 = 0x80000011;
	sregs.efer = 0x500;
	memset(&sregs.cs, 0, sizeof(sregs.cs));
	sregs.cs.selector = 8; sregs.cs.limit = ~0u; sregs.cs.type = 11; sregs.cs.present = 1;
	sregs.cs.s = 1; sregs.cs.l = 1; sregs.cs.g = 1;
	sregs.ds = sregs.cs;
	sregs.ds.selector = 16; sregs.ds.type = 3; sregs.ds.l = 0; sregs.ds.db = 1;
	sregs.es = sregs.fs = sregs.gs = sregs.ss = sregs.ds;
	if (ioctl(vcpu, KVM_SET_SREGS, &sregs))
		die("KVM_SET_SREGS");
}

static double now(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec + t.tv_nsec / 1e9;
}

/* Run operation op with count n; returns seconds. */
static double bench(int op, unsigned long n)
{
	struct kvm_regs regs = { .rip = 0x1000, .rflags = 2, .rdi = op, .rsi = n };
	double t0;

	if (ioctl(vcpu, KVM_SET_REGS, &regs))
		die("KVM_SET_REGS");
	t0 = now();
	for (;;) {
		if (ioctl(vcpu, KVM_RUN, 0))
			die("KVM_RUN");
		if (run->exit_reason == KVM_EXIT_IO || run->exit_reason == KVM_EXIT_MMIO)
			continue;
		if (run->exit_reason == KVM_EXIT_HLT)
			break;
		printf("KVMBENCH: unexpected exit %u\n", run->exit_reason);
		exit(1);
	}
	return now() - t0;
}

/* kvmbench time NAME CMD...: CMD's wall time, its output discarded. */
static int time_cmd(char **argv)
{
	double t0 = now();
	int status;
	pid_t pid = fork();

	if (!pid) {
		int fd = open("/dev/null", O_WRONLY);

		dup2(fd, 1);
		dup2(fd, 2);
		execv(argv[1], argv + 1);
		_exit(127);
	}
	waitpid(pid, &status, 0);
	printf("KVMBENCH: boot-%-6s %8.0f ms%s\n", argv[0], (now() - t0) * 1e3,
	       WIFEXITED(status) && !WEXITSTATUS(status) ? "" : " (failed)");
	return 0;
}

int main(int argc, char **argv)
{
	int rounds = argc > 1 ? atoi(argv[1]) : 3, i;

	if (argc > 3 && !strcmp(argv[1], "time"))
		return time_cmd(argv + 2);
	double best[5] = { 1e9, 1e9, 1e9, 1e9, 1e9 };
	static const char *name[5] = { "spin", "cpuid", "pio", "mmio", "fault" };
	static const unsigned long n[5] = { 1000000000, 40000, 20000, 20000, 16384 };
	static const char *unit[5] = { "ms", "ns/exit", "ns/exit", "ns/exit", "ns/fault" };

	kvm = open("/dev/kvm", O_RDWR);
	if (kvm < 0)
		die("/dev/kvm");
	setup();
	for (i = 0; i < rounds; i++) {
		int op;

		for (op = 0; op < 5; op++) {
			double t;

			if (op == 4) {
				/* Fresh memory for each round. */
				close(vcpu);
				close(vmfd);
				munmap(mem, MEM_SIZE);
				setup();
			}
			t = bench(op, n[op]);
			if (t < best[op])
				best[op] = t;
		}
	}
	for (i = 0; i < 5; i++)
		printf("KVMBENCH: %-6s %10.1f %s\n", name[i],
		       i ? best[i] * 1e9 / n[i] : best[i] * 1e3, unit[i]);
	printf("KVMBENCH: done\n");
	return 0;
}

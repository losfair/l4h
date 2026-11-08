// SPDX-License-Identifier: GPL-2.0-only
/*
 * /dev/kvm in an l4h guest (tests/run-kvmtest.sh, DESIGN.md §5.10): small
 * VMs that run real-mode and long-mode code, with port I/O, MMIO, EPT
 * faults on all their memory, long runs that seL4 preempts, and VMs made
 * and destroyed in a row.  Prints KVMTEST: PASS or KVMTEST: FAIL.
 */
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#define MEM_SIZE (64ul << 20)

/* Guest code, assembled here and copied to guest address 0x1000. */
extern const char rm_start[], rm_end[], lm_start[], lm_end[];
__asm__(".pushsection .rodata\n"
	/* Real mode: "OK" to port 0x3f8, then hlt. */
	".code16\n"
	"rm_start:\n"
	"  mov $0x3f8, %dx\n"
	"  mov $'O', %al\n"
	"  out %al, %dx\n"
	"  mov $'K', %al\n"
	"  out %al, %dx\n"
	"  hlt\n"
	"rm_end:\n"
	".code64\n"
	/* Long mode: rdi = bytes of memory from 2 MiB to fill and sum,
	 * rsi = spin iterations.  The sum goes to port 0x10 and to an MMIO
	 * write to 0xd0000000 (from r8), CPUID's vendor to r9, then hlt. */
	"lm_start:\n"
	"  mov $0x200000, %rbx\n"
	"  mov %rdi, %rcx\n"
	"  shr $3, %rcx\n"
	"  xor %rax, %rax\n"
	"  test %rcx, %rcx\n"
	"  jz 4f\n"
	"1: mov %rbx, (%rbx)\n"
	"  add (%rbx), %rax\n"
	"  add $8, %rbx\n"
	"  dec %rcx\n"
	"  jnz 1b\n"
	"4: mov %rsi, %rcx\n"
	"  test %rcx, %rcx\n"
	"  jz 3f\n"
	"2: dec %rcx\n"
	"  jnz 2b\n"
	"3: mov %eax, %edx\n"
	"  shr $32, %rax\n"
	"  xor %edx, %eax\n"
	"  mov %eax, %r8d\n"
	"  mov $0x10, %dx\n"
	"  out %eax, %dx\n"
	"  xor %eax, %eax\n"
	"  cpuid\n"
	"  mov %ebx, %r9d\n"
	"  mov $0xd0000000, %rbx\n"
	"  mov %r8d, (%rbx)\n"
	"  hlt\n"
	"lm_end:\n"
	".popsection\n");

static int failures;

#define CHECK(cond, ...) do {						\
		if (!(cond)) {						\
			printf("KVMTEST: check failed: " __VA_ARGS__);	\
			printf(" (%s:%d, errno %d)\n", __FILE__, __LINE__, errno); \
			failures++;					\
			return -1;					\
		}							\
	} while (0)

struct vm {
	int kvm, fd, vcpu;
	struct kvm_run *run;
	int run_size;
	uint8_t *mem;
};

static int vm_create(struct vm *vm, int kvm)
{
	struct kvm_userspace_memory_region r = { .slot = 0, .memory_size = MEM_SIZE };
	int size;

	vm->kvm = kvm;
	vm->fd = ioctl(kvm, KVM_CREATE_VM, 0);
	CHECK(vm->fd >= 0, "KVM_CREATE_VM");
	vm->mem = mmap(NULL, MEM_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHECK(vm->mem != MAP_FAILED, "mmap");
	madvise(vm->mem, MEM_SIZE, MADV_HUGEPAGE);
	r.userspace_addr = (uintptr_t)vm->mem;
	CHECK(ioctl(vm->fd, KVM_SET_USER_MEMORY_REGION, &r) == 0, "KVM_SET_USER_MEMORY_REGION");
	vm->vcpu = ioctl(vm->fd, KVM_CREATE_VCPU, 0);
	CHECK(vm->vcpu >= 0, "KVM_CREATE_VCPU");
	/* The guest's CPUID decides which CR4 and EFER bits it may set. */
	{
		struct {
			struct kvm_cpuid2 c;
			struct kvm_cpuid_entry2 e[100];
		} cpuid = { .c.nent = 100 };

		CHECK(ioctl(kvm, KVM_GET_SUPPORTED_CPUID, &cpuid) == 0, "KVM_GET_SUPPORTED_CPUID");
		CHECK(ioctl(vm->vcpu, KVM_SET_CPUID2, &cpuid) == 0, "KVM_SET_CPUID2");
	}
	size = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, 0);
	CHECK(size > 0, "KVM_GET_VCPU_MMAP_SIZE");
	vm->run_size = size;
	vm->run = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, vm->vcpu, 0);
	CHECK(vm->run != MAP_FAILED, "mmap kvm_run");
	return 0;
}

/* The kvm_run mapping holds the vCPU, and the vCPU the VM. */
static void vm_destroy(struct vm *vm)
{
	munmap(vm->run, vm->run_size);
	close(vm->vcpu);
	close(vm->fd);
	munmap(vm->mem, MEM_SIZE);
}

static int real_mode(int kvm)
{
	struct kvm_sregs sregs;
	struct kvm_regs regs = { .rip = 0x1000, .rflags = 2 };
	char out[8];
	int n = 0;
	struct vm vm;

	if (vm_create(&vm, kvm))
		return -1;
	memcpy(vm.mem + 0x1000, rm_start, rm_end - rm_start);
	CHECK(ioctl(vm.vcpu, KVM_GET_SREGS, &sregs) == 0, "KVM_GET_SREGS");
	sregs.cs.selector = 0;
	sregs.cs.base = 0;
	CHECK(ioctl(vm.vcpu, KVM_SET_SREGS, &sregs) == 0, "KVM_SET_SREGS");
	CHECK(ioctl(vm.vcpu, KVM_SET_REGS, &regs) == 0, "KVM_SET_REGS");
	for (;;) {
		CHECK(ioctl(vm.vcpu, KVM_RUN, 0) == 0, "KVM_RUN");
		if (vm.run->exit_reason == KVM_EXIT_IO && vm.run->io.port == 0x3f8 && n < 7) {
			out[n++] = *((char *)vm.run + vm.run->io.data_offset);
			continue;
		}
		break;
	}
	out[n] = 0;
	CHECK(vm.run->exit_reason == KVM_EXIT_HLT, "real mode: exit %u, wanted HLT",
	      vm.run->exit_reason);
	CHECK(!strcmp(out, "OK"), "real mode: wrote \"%s\"", out);
	vm_destroy(&vm);
	printf("KVMTEST: real mode ok\n");
	return 0;
}

static void seg64(struct kvm_segment *s, int code)
{
	memset(s, 0, sizeof(*s));
	s->selector = code ? 8 : 16;
	s->limit = 0xffffffff;
	s->type = code ? 11 : 3;
	s->present = 1;
	s->s = 1;
	s->l = code;
	s->db = !code;
	s->g = 1;
}

/* Fill `fill` bytes and spin `spin` times in long mode. */
static int long_mode(int kvm, uint64_t fill, uint64_t spin, const char *what)
{
	struct kvm_sregs sregs;
	struct kvm_regs regs;
	uint64_t *pml4, *pdpt, *pd, sum = 0, i;
	uint32_t port_val = 0, mmio_val = 0;
	struct timespec t0, t1;
	int got_mmio = 0;
	struct vm vm;

	if (vm_create(&vm, kvm))
		return -1;
	memcpy(vm.mem + 0x1000, lm_start, lm_end - lm_start);
	/* Identity map of the first GiB in 2 MiB pages at 0x10000. */
	pml4 = (uint64_t *)(vm.mem + 0x10000);
	pdpt = (uint64_t *)(vm.mem + 0x11000);
	pd = (uint64_t *)(vm.mem + 0x12000);
	pml4[0] = 0x11000 | 3;
	pdpt[0] = 0x12000 | 3;
	pdpt[3] = 0x13000 | 3;		/* 3-4 GiB, for the MMIO address */
	for (i = 0; i < 512; i++) {
		pd[i] = (i << 21) | 0x83;
		((uint64_t *)(vm.mem + 0x13000))[i] = (0xc0000000ul + (i << 21)) | 0x83;
	}

	CHECK(ioctl(vm.vcpu, KVM_GET_SREGS, &sregs) == 0, "KVM_GET_SREGS");
	sregs.cr3 = 0x10000;
	sregs.cr4 = 1 << 5;		/* PAE */
	sregs.cr0 = 0x80000011;		/* PG, ET, PE */
	sregs.efer = 0x500;		/* LME, LMA */
	seg64(&sregs.cs, 1);
	seg64(&sregs.ds, 0);
	sregs.es = sregs.fs = sregs.gs = sregs.ss = sregs.ds;
	CHECK(ioctl(vm.vcpu, KVM_SET_SREGS, &sregs) == 0, "KVM_SET_SREGS");
	memset(&regs, 0, sizeof(regs));
	regs.rip = 0x1000;
	regs.rflags = 2;
	regs.rdi = fill;
	regs.rsi = spin;
	CHECK(ioctl(vm.vcpu, KVM_SET_REGS, &regs) == 0, "KVM_SET_REGS");

	clock_gettime(CLOCK_MONOTONIC, &t0);
	for (;;) {
		CHECK(ioctl(vm.vcpu, KVM_RUN, 0) == 0, "KVM_RUN");
		if (vm.run->exit_reason == KVM_EXIT_IO && vm.run->io.port == 0x10) {
			port_val = *(uint32_t *)((char *)vm.run + vm.run->io.data_offset);
			continue;
		}
		if (vm.run->exit_reason == KVM_EXIT_MMIO && vm.run->mmio.phys_addr == 0xd0000000 &&
		    vm.run->mmio.is_write) {
			memcpy(&mmio_val, vm.run->mmio.data, 4);
			got_mmio = 1;
			continue;
		}
		break;
	}
	clock_gettime(CLOCK_MONOTONIC, &t1);
	CHECK(vm.run->exit_reason == KVM_EXIT_HLT, "%s: exit %u, wanted HLT", what,
	      vm.run->exit_reason);
	for (i = 0; i < fill / 8; i++) {
		uint64_t a = 0x200000 + i * 8;

		CHECK(((uint64_t *)vm.mem)[a / 8] == a, "%s: memory at %lx", what, a);
		sum += a;
	}
	sum = (uint32_t)sum ^ (uint32_t)(sum >> 32);
	CHECK(port_val == sum, "%s: port sum %x, wanted %lx", what, port_val, sum);
	CHECK(got_mmio && mmio_val == sum, "%s: MMIO write %d %x", what, got_mmio, mmio_val);
	CHECK(ioctl(vm.vcpu, KVM_GET_REGS, &regs) == 0, "KVM_GET_REGS");
	/* rbx of the emulated CPUID went into the guest. */
	CHECK(regs.rbx == 0xd0000000 && regs.r8 == sum && regs.r9 == 0x756e6547,
	      "%s: registers after exit: rbx %llx r8 %llx r9 %llx", what, regs.rbx, regs.r8, regs.r9);
	vm_destroy(&vm);
	printf("KVMTEST: %s ok (%.3f s)\n", what,
	       (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9);
	return 0;
}

struct job {
	int kvm, ret;
};

static void *parallel_vm(void *arg)
{
	struct job *j = arg;

	j->ret = long_mode(j->kvm, 16ul << 20, 50000000, "parallel VM");
	return NULL;
}

int main(void)
{
	int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC), i;
	pthread_t t[2];
	struct job jobs[2];

	printf("KVMTEST: start\n");
	if (kvm < 0) {
		printf("KVMTEST: FAIL (no /dev/kvm: %s)\n", strerror(errno));
		return 1;
	}
	printf("KVMTEST: API version %d\n", ioctl(kvm, KVM_GET_API_VERSION, 0));
	real_mode(kvm);
	long_mode(kvm, 0, 0, "long mode");
	long_mode(kvm, MEM_SIZE - (4ul << 20), 0, "62 MiB of EPT faults");
	long_mode(kvm, 1 << 20, 2000000000, "long run");
	for (i = 0; i < 2; i++) {
		jobs[i].kvm = kvm;
		pthread_create(&t[i], NULL, parallel_vm, &jobs[i]);
	}
	for (i = 0; i < 2; i++)
		pthread_join(t[i], NULL);
	for (i = 0; i < 20 && !failures; i++)
		if (long_mode(kvm, 1 << 20, 0, "VM reuse"))
			break;
	printf(failures ? "KVMTEST: FAIL\n" : "KVMTEST: PASS\n");
	return failures != 0;
}

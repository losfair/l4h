// SPDX-License-Identifier: GPL-2.0
/*
 * /dev/kvm on AArch64 l4h (FL4 at EL2): small EL1 guests that check what
 * QEMU, Firecracker and cloud-hypervisor rely on.  Run in dom0 by
 * tests/run-kvmtest-arm64.sh; prints "KVMTEST: PASS" or "KVMTEST: FAIL ...".
 *
 *   mmio    8/16/32/64-bit MMIO reads and writes (KVM_EXIT_MMIO)
 *   hvc     HVC to KVM's PSCI (PSCI_VERSION)
 *   dirty   Stage-2 faults and dirty logging (KVM_MEM_LOG_DIRTY_PAGES)
 *   onereg  KVM_GET/SET_ONE_REG, core and FP/SIMD registers
 *   smp     PSCI CPU_ON of a second vCPU
 *   gic     the in-kernel vgic (GICv3 or GICv2, as the host has):
 *           an SPI from KVM_IRQ_LINE, and the virtual timer (PPI 27)
 *           firing while the guest spins and while it waits in WFI
 */
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#define RAM		0x40000000ull
#define RAM_SIZE	0x200000ull
#define DIRTY		(RAM + RAM_SIZE)
#define DIRTY_PAGES	16
#define MMIO		0x10000000ull
#define GICD		0x08000000ull
#define GICR		0x080a0000ull	/* GICv3 redistributors */
#define GICC		0x08010000ull	/* GICv2 CPU interface (GICV) */
#define SPI		40

/* MMIO offsets the guest uses. */
#define M_REPORT	0x00	/* a value to check */
#define M_DONE		0x08	/* the test is over */
#define M_PHASE		0x10	/* a step, for the host to act on */
#define M_CPU1		0x18	/* the second vCPU's report */
#define M_IRQ		0x20	/* an interrupt the guest took */
#define M_WRITE		0x100	/* +0, 8, 16, 24: written with 1, 2, 4, 8 bytes */
#define M_READ		0x200	/* +0, 8, 16, 24: read with 1, 2, 4, 8 bytes */

enum { T_MMIO, T_HVC, T_DIRTY, T_ONEREG, T_SMP, T_GICV3, T_GICV2 };

/*
 * The guest: x0 selects the test, x1..x3 its arguments.  The exception
 * vectors take IRQs only: the handler acknowledges the interrupt,
 * reports it, turns the virtual timer off if it was the timer's, and
 * sets x25.  It uses x20..x24, which the tests leave alone.
 */
asm(".pushsection .rodata\n"
    ".balign 4096\n"
    ".global guest_start\n"
    "guest_start:\n"
    "	movz x9, #0x1000, lsl #16\n"			/* MMIO */
    "	cmp x0, #0\n b.eq t_mmio\n"
    "	cmp x0, #1\n b.eq t_hvc\n"
    "	cmp x0, #2\n b.eq t_dirty\n"
    "	cmp x0, #3\n b.eq t_onereg\n"
    "	cmp x0, #4\n b.eq t_smp\n"
    "	cmp x0, #5\n b.eq t_gicv3\n"
    "	cmp x0, #6\n b.eq t_gicv2\n"
    "	b done\n"

    "t_mmio:\n"
    "	mov x1, #0x11\n strb w1, [x9, #0x100]\n"
    "	mov x1, #0x2222\n strh w1, [x9, #0x108]\n"
    "	movz x1, #0x4444\n movk x1, #0x3333, lsl #16\n str w1, [x9, #0x110]\n"
    "	ldr x1, =0x8877665544332211\n str x1, [x9, #0x118]\n"
    "	ldrb w2, [x9, #0x200]\n"
    "	ldrh w3, [x9, #0x208]\n"
    "	ldr w4, [x9, #0x210]\n"
    "	ldr x5, [x9, #0x218]\n"
    "	add x2, x2, x3\n add x2, x2, x4\n add x2, x2, x5\n"
    "	str x2, [x9]\n"
    "	b done\n"

    "t_hvc:\n"
    "	movz x0, #0x8400, lsl #16\n"			/* PSCI_VERSION */
    "	hvc #0\n"
    "	str x0, [x9]\n"
    "	b done\n"

    "t_dirty:\n"
    "	movz x1, #0x4020, lsl #16\n"			/* DIRTY */
    "	mov x2, #0\n"
    "1:	add x3, x1, x2, lsl #12\n str x2, [x3]\n"
    "	add x2, x2, #1\n cmp x2, #16\n b.ne 1b\n"
    "	str xzr, [x9, #0x10]\n"			/* the host clears the log */
    "	mov x3, #2\n add x3, x1, x3, lsl #12\n str x3, [x3, #8]\n"
    "	mov x3, #5\n add x3, x1, x3, lsl #12\n str x3, [x3, #8]\n"
    "	ldr x3, [x1, #4096 * 7]\n"			/* a read only */
    "	b done\n"

    "t_onereg:\n"
    "	mov x4, #(3 << 20)\n msr cpacr_el1, x4\n isb\n"	/* FP on */
    "	fmov x2, d0\n mov x3, v0.d[1]\n"
    "	str x2, [x9]\n str x3, [x9]\n"
    "	add x1, x1, x1\n str x1, [x9]\n"		/* x1 from the host */
    "	ldr x2, =0x0123456789abcdef\n fmov d1, x2\n"
    "	ldr x2, =0xfedcba9876543210\n mov v1.d[1], x2\n"
    "	b done\n"

    "t_smp:\n"
    "	ldr x0, =0xc4000003\n"			/* CPU_ON */
    "	mov x1, #1\n"					/* MPIDR 1 */
    "	adr x2, secondary\n"
    "	ldr x3, =0x5a5a\n"
    "	hvc #0\n"
    "	str x0, [x9]\n"
    "	b done\n"
    "secondary:\n"
    "	movz x9, #0x1000, lsl #16\n"
    "	str x0, [x9, #0x18]\n"
    "	str xzr, [x9, #0x08]\n"
    "1:	wfi\n b 1b\n"

    /* GICv3: the distributor, this vCPU's redistributor, the CPU
     * interface (system registers). */
    "t_gicv3:\n"
    "	adr x1, vectors\n msr vbar_el1, x1\n isb\n"
    "	movz x10, #0x0800, lsl #16\n"		/* GICD */
    "	mov w1, #0x12\n str w1, [x10]\n"		/* ARE_NS | EnableGrp1NS */
    "	movz x11, #0x080a, lsl #16\n"		/* GICR */
    "	str wzr, [x11, #0x14]\n"			/* WAKER */
    "	add x12, x11, #0x10000\n"			/* SGI_base */
    "	mov w1, #-1\n str w1, [x12, #0x80]\n"		/* IGROUPR0 */
    "	mov w1, #(1 << 27)\n str w1, [x12, #0x100]\n"	/* ISENABLER0 */
    "	mov w1, #(1 << 8)\n str w1, [x10, #0x84]\n"	/* IGROUPR1: SPI 40 */
    "	str w1, [x10, #0x104]\n"			/* ISENABLER1 */
    "	add x1, x10, #0x6000\n str xzr, [x1, #8 * 40]\n"	/* IROUTER40 */
    "	mrs x1, s3_0_c12_c12_5\n orr x1, x1, #1\n msr s3_0_c12_c12_5, x1\n isb\n"	/* SRE */
    "	mov x1, #0xff\n msr s3_0_c4_c6_0, x1\n"	/* PMR */
    "	mov x1, #1\n msr s3_0_c12_c12_7, x1\n isb\n"	/* IGRPEN1 */
    "	b gic_tests\n"

    /* GICv2: the distributor, the CPU interface (GICV, FL4's). */
    "t_gicv2:\n"
    "	adr x1, vectors\n msr vbar_el1, x1\n isb\n"
    "	movz x10, #0x0800, lsl #16\n"		/* GICD */
    "	mov w1, #1\n str w1, [x10]\n"		/* CTLR */
    "	mov w1, #(1 << 27)\n str w1, [x10, #0x100]\n"	/* ISENABLER0 */
    "	mov w1, #(1 << 8)\n str w1, [x10, #0x104]\n"	/* ISENABLER1: SPI 40 */
    "	mov w1, #1\n add x2, x10, #0x800\n strb w1, [x2, #40]\n"	/* ITARGETSR */
    "	movz x13, #0x0801, lsl #16\n"		/* GICC */
    "	mov w1, #0xff\n str w1, [x13, #4]\n"	/* PMR */
    "	mov w1, #1\n str w1, [x13]\n"		/* CTLR */
    "	b gic_tests\n"

    "gic_tests:\n"
    "	mov x25, #0\n"
    "	msr daifclr, #2\n"
    "	str xzr, [x9, #0x10]\n"			/* the host raises SPI 40 */
    "1:	cbz x25, 1b\n"
    /* The virtual timer, 1 ms ahead, while we spin. */
    "	mov x25, #0\n"
    "	mrs x1, cntfrq_el0\n mov x2, #1000\n udiv x1, x1, x2\n"
    "	msr cntv_tval_el0, x1\n mov x2, #1\n msr cntv_ctl_el0, x2\n isb\n"
    "1:	cbz x25, 1b\n"
    /* And while we wait for interrupts. */
    "	mov x25, #0\n"
    "	msr cntv_tval_el0, x1\n mov x2, #1\n msr cntv_ctl_el0, x2\n isb\n"
    "1:	wfi\n cbz x25, 1b\n"
    "	b done\n"

    "done:\n"
    "	str xzr, [x9, #0x08]\n"
    "1:	wfi\n b 1b\n"

    ".balign 2048\n"
    "vectors:\n"
    ".rept 5\n b .\n .balign 128\n .endr\n"
    "	b irq\n .balign 128\n"			/* IRQ, EL1h */
    ".rept 10\n b .\n .balign 128\n .endr\n"
    "irq:\n"
    "	movz x21, #0x0801, lsl #16\n"		/* GICC: GICv2? */
    "	cmp x0, #6\n b.eq 1f\n"
    "	mrs x20, s3_0_c12_c12_0\n"			/* IAR1 */
    "	b 2f\n"
    "1:	ldr w20, [x21, #0xc]\n"			/* GICC_IAR */
    "2:	movz x22, #0x1000, lsl #16\n"
    "	and x23, x20, #0x3ff\n"
    "	str x23, [x22, #0x20]\n"
    "	cmp x23, #27\n b.ne 3f\n"
    "	msr cntv_ctl_el0, xzr\n"
    "3:	cmp x0, #6\n b.eq 4f\n"
    "	msr s3_0_c12_c12_1, x20\n"			/* EOIR1 */
    "	b 5f\n"
    "4:	str w20, [x21, #0x10]\n"			/* GICC_EOIR */
    "5:	mov x25, #1\n"
    "	eret\n"
    ".ltorg\n"
    ".global guest_end\n"
    "guest_end:\n"
    ".popsection\n");
extern char guest_start[], guest_end[];

static int kvm, vm, fail;
static void *ram, *dirty;
static struct kvm_run *runs[2];
static int vcpus[2], gic;

#define CORE(r) (KVM_REG_ARM64 | KVM_REG_ARM_CORE | (offsetof(struct kvm_regs, r) / 4))
#define CORE64(r) (CORE(r) | KVM_REG_SIZE_U64)
#define CORE128(r) (CORE(r) | KVM_REG_SIZE_U128)

static void check(const char *what, int ok)
{
	printf("KVMTEST: %s %s\n", what, ok ? "ok" : "FAIL");
	if (!ok)
		fail = 1;
}

static void die(const char *what)
{
	printf("KVMTEST: FAIL %s: %s\n", what, strerror(errno));
	exit(1);
}

static void set_reg(int vcpu, uint64_t id, void *val)
{
	struct kvm_one_reg r = { .id = id, .addr = (uint64_t)val };

	if (ioctl(vcpu, KVM_SET_ONE_REG, &r))
		die("KVM_SET_ONE_REG");
}

static void get_reg(int vcpu, uint64_t id, void *val)
{
	struct kvm_one_reg r = { .id = id, .addr = (uint64_t)val };

	if (ioctl(vcpu, KVM_GET_ONE_REG, &r))
		die("KVM_GET_ONE_REG");
}

static void set64(int vcpu, uint64_t id, uint64_t v)
{
	set_reg(vcpu, id, &v);
}

static void dev_attr(int dev, uint32_t group, uint64_t attr, void *addr)
{
	struct kvm_device_attr a = { .group = group, .attr = attr, .addr = (uint64_t)addr };

	if (ioctl(dev, KVM_SET_DEVICE_ATTR, &a))
		die("KVM_SET_DEVICE_ATTR");
}

/* A fresh VM with RAM, the dirty-logged slot, and n vCPUs. */
static void vm_create(int n, int gic_type)
{
	struct kvm_userspace_memory_region r;
	struct kvm_vcpu_init init;
	int i, sz;

	vm = ioctl(kvm, KVM_CREATE_VM, 0);
	if (vm < 0)
		die("KVM_CREATE_VM");
	ram = mmap(NULL, RAM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	dirty = mmap(NULL, DIRTY_PAGES * 4096, PROT_READ | PROT_WRITE,
		     MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	memcpy(ram, guest_start, guest_end - guest_start);
	r = (struct kvm_userspace_memory_region){ .slot = 0, .guest_phys_addr = RAM,
		.memory_size = RAM_SIZE, .userspace_addr = (uint64_t)ram };
	if (ioctl(vm, KVM_SET_USER_MEMORY_REGION, &r))
		die("KVM_SET_USER_MEMORY_REGION");
	r = (struct kvm_userspace_memory_region){ .slot = 1, .flags = KVM_MEM_LOG_DIRTY_PAGES,
		.guest_phys_addr = DIRTY, .memory_size = DIRTY_PAGES * 4096,
		.userspace_addr = (uint64_t)dirty };
	if (ioctl(vm, KVM_SET_USER_MEMORY_REGION, &r))
		die("KVM_SET_USER_MEMORY_REGION (dirty)");
	if (gic_type >= 0) {
		struct kvm_create_device d = { .type = gic_type };

		if (ioctl(vm, KVM_CREATE_DEVICE, &d))
			die("KVM_CREATE_DEVICE");
		gic = d.fd;
	}
	if (ioctl(vm, KVM_ARM_PREFERRED_TARGET, &init))
		die("KVM_ARM_PREFERRED_TARGET");
	init.features[0] |= 1 << KVM_ARM_VCPU_PSCI_0_2;
	sz = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, 0);
	for (i = 0; i < n; i++) {
		struct kvm_vcpu_init vi = init;

		vcpus[i] = ioctl(vm, KVM_CREATE_VCPU, i);
		if (vcpus[i] < 0)
			die("KVM_CREATE_VCPU");
		if (i)
			vi.features[0] |= 1 << KVM_ARM_VCPU_POWER_OFF;
		if (ioctl(vcpus[i], KVM_ARM_VCPU_INIT, &vi))
			die("KVM_ARM_VCPU_INIT");
		runs[i] = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED, vcpus[i], 0);
	}
	set64(vcpus[0], CORE64(regs.pc), RAM);
	if (gic_type == KVM_DEV_TYPE_ARM_VGIC_V3) {
		uint64_t dist = GICD, redist = GICR;
		uint32_t nr = 96;

		dev_attr(gic, KVM_DEV_ARM_VGIC_GRP_ADDR, KVM_VGIC_V3_ADDR_TYPE_DIST, &dist);
		dev_attr(gic, KVM_DEV_ARM_VGIC_GRP_ADDR, KVM_VGIC_V3_ADDR_TYPE_REDIST, &redist);
		dev_attr(gic, KVM_DEV_ARM_VGIC_GRP_NR_IRQS, 0, &nr);
		dev_attr(gic, KVM_DEV_ARM_VGIC_GRP_CTRL, KVM_DEV_ARM_VGIC_CTRL_INIT, NULL);
	} else if (gic_type == KVM_DEV_TYPE_ARM_VGIC_V2) {
		uint64_t dist = GICD, cpu = GICC;
		uint32_t nr = 96;

		dev_attr(gic, KVM_DEV_ARM_VGIC_GRP_ADDR, KVM_VGIC_V2_ADDR_TYPE_DIST, &dist);
		dev_attr(gic, KVM_DEV_ARM_VGIC_GRP_ADDR, KVM_VGIC_V2_ADDR_TYPE_CPU, &cpu);
		dev_attr(gic, KVM_DEV_ARM_VGIC_GRP_NR_IRQS, 0, &nr);
		dev_attr(gic, KVM_DEV_ARM_VGIC_GRP_CTRL, KVM_DEV_ARM_VGIC_CTRL_INIT, NULL);
	}
}

static void vm_destroy(int n)
{
	int i;

	for (i = 0; i < n; i++) {
		close(vcpus[i]);
		munmap(runs[i], ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, 0));
	}
	if (gic > 0)
		close(gic);
	gic = 0;
	close(vm);
	munmap(ram, RAM_SIZE);
	munmap(dirty, DIRTY_PAGES * 4096);
}

/* The guest's MMIO, until it is done; each call returns the next report. */
struct mmio_log {
	uint64_t reports[8];
	int nreports;
	uint64_t writes[4];
	uint64_t irqs[8];
	int nirqs;
	int phases;
};

static int run_vcpu(int i, struct mmio_log *log, void (*phase)(int))
{
	struct kvm_run *run = runs[i];
	int steps = 0;

	for (;;) {
		if (ioctl(vcpus[i], KVM_RUN, 0)) {
			if (errno == EINTR)
				continue;
			die("KVM_RUN");
		}
		if (++steps > 100000) {
			printf("KVMTEST: FAIL vCPU %d does not finish\n", i);
			return -1;
		}
		if (run->exit_reason != KVM_EXIT_MMIO) {
			printf("KVMTEST: FAIL vCPU %d exit %d\n", i, run->exit_reason);
			return -1;
		}
		uint64_t a = run->mmio.phys_addr - MMIO, v = 0;

		memcpy(&v, run->mmio.data, run->mmio.len);
		if (!run->mmio.is_write) {
			static const uint64_t pattern = 0x0807060504030201ull;

			memcpy(run->mmio.data, &pattern, run->mmio.len);
			continue;
		}
		if (a == M_DONE)
			return 0;
		if (a == M_REPORT && log->nreports < 8)
			log->reports[log->nreports++] = v;
		else if (a == M_CPU1 && log->nreports < 8)
			log->reports[log->nreports++] = v;
		else if (a == M_IRQ && log->nirqs < 8)
			log->irqs[log->nirqs++] = v;
		else if (a == M_PHASE && phase)
			phase(log->phases++);
		else if (a >= M_WRITE && a < M_WRITE + 32 && !(a & 7))
			log->writes[(a - M_WRITE) / 8] = v | (run->mmio.len < 8 ? (uint64_t)run->mmio.len << 56 : 0);
	}
}

static void start(int test, uint64_t x1)
{
	set64(vcpus[0], CORE64(regs.regs[0]), test);
	set64(vcpus[0], CORE64(regs.regs[1]), x1);
}

static void test_mmio(void)
{
	struct mmio_log log = { 0 };

	vm_create(1, -1);
	start(T_MMIO, 0);
	if (!run_vcpu(0, &log, NULL)) {
		check("mmio write8", log.writes[0] == (0x11ull | 1ull << 56));
		check("mmio write16", log.writes[1] == (0x2222ull | 2ull << 56));
		check("mmio write32", log.writes[2] == (0x33334444ull | 4ull << 56));
		check("mmio write64", log.writes[3] == 0x8877665544332211ull);
		check("mmio read8/16/32/64", log.nreports == 1 &&
		      log.reports[0] == 0x01 + 0x0201 + 0x04030201 + 0x0807060504030201ull);
	} else {
		check("mmio", 0);
	}
	vm_destroy(1);
}

static void test_hvc(void)
{
	struct mmio_log log = { 0 };

	vm_create(1, -1);
	start(T_HVC, 0);
	check("hvc PSCI_VERSION", !run_vcpu(0, &log, NULL) && log.nreports == 1 &&
	      log.reports[0] >= 0x10000);
	printf("KVMTEST: PSCI version %#llx\n", (unsigned long long)log.reports[0]);
	vm_destroy(1);
}

static uint64_t dirty_bits(void)
{
	uint64_t bits = 0;
	struct kvm_dirty_log d = { .slot = 1, .dirty_bitmap = &bits };

	if (ioctl(vm, KVM_GET_DIRTY_LOG, &d))
		die("KVM_GET_DIRTY_LOG");
	return bits;
}

static uint64_t first_bits;

static void dirty_phase(int n)
{
	first_bits = dirty_bits();
}

static void test_dirty(void)
{
	struct mmio_log log = { 0 };
	uint64_t *p = dirty;
	int i, ok = 1;

	vm_create(1, -1);
	dirty_bits();
	start(T_DIRTY, 0);
	if (run_vcpu(0, &log, dirty_phase)) {
		check("dirty", 0);
		vm_destroy(1);
		return;
	}
	for (i = 0; i < DIRTY_PAGES; i++)
		ok &= p[i * 512] == (uint64_t)i;
	check("stage-2 faults (guest writes reach memory)", ok);
	check("dirty log after the first writes", first_bits == 0xffff);
	check("dirty log after write protection", dirty_bits() == ((1 << 2) | (1 << 5)));
	check("guest writes after write protection", p[2 * 512 + 1] == DIRTY + 2 * 4096 &&
	      p[5 * 512 + 1] == DIRTY + 5 * 4096);
	vm_destroy(1);
}

static void test_onereg(void)
{
	struct mmio_log log = { 0 };
	__uint128_t v0 = ((__uint128_t)0x1122334455667788ull << 64) | 0x99aabbccddeeff00ull, v1;

	vm_create(1, -1);
	start(T_ONEREG, 21);
	set_reg(vcpus[0], CORE128(fp_regs.vregs[0]), &v0);
	if (run_vcpu(0, &log, NULL) || log.nreports != 3) {
		check("onereg", 0);
		vm_destroy(1);
		return;
	}
	check("SET_ONE_REG V0 seen by the guest", log.reports[0] == 0x99aabbccddeeff00ull &&
	      log.reports[1] == 0x1122334455667788ull);
	check("SET_ONE_REG X1 seen by the guest", log.reports[2] == 42);
	get_reg(vcpus[0], CORE128(fp_regs.vregs[1]), &v1);
	check("GET_ONE_REG V1 from the guest", v1 == (((__uint128_t)0xfedcba9876543210ull << 64) |
						    0x0123456789abcdefull));
	vm_destroy(1);
}

static struct mmio_log cpu1_log;

static void *cpu1_thread(void *arg)
{
	return (void *)(long)run_vcpu(1, &cpu1_log, NULL);
}

static void test_smp(void)
{
	struct mmio_log log = { 0 };
	pthread_t t;
	void *r1;
	int r0;

	vm_create(2, -1);
	start(T_SMP, 0);
	memset(&cpu1_log, 0, sizeof(cpu1_log));
	pthread_create(&t, NULL, cpu1_thread, NULL);
	r0 = run_vcpu(0, &log, NULL);
	pthread_join(t, &r1);
	check("PSCI CPU_ON returns success", !r0 && log.nreports == 1 && log.reports[0] == 0);
	check("second vCPU starts with its context id", !r1 && cpu1_log.nreports == 1 &&
	      cpu1_log.reports[0] == 0x5a5a);
	vm_destroy(2);
}

static void raise_spi(int n)
{
	struct kvm_irq_level irq = { .irq = (KVM_ARM_IRQ_TYPE_SPI << KVM_ARM_IRQ_TYPE_SHIFT) | SPI,
				     .level = 1 };

	if (ioctl(vm, KVM_IRQ_LINE, &irq))
		die("KVM_IRQ_LINE");
	irq.level = 0;
	if (ioctl(vm, KVM_IRQ_LINE, &irq))
		die("KVM_IRQ_LINE");
}

static void test_gic(int type, const char *name)
{
	struct mmio_log log = { 0 };
	char what[64];

	vm_create(1, type);
	start(type == KVM_DEV_TYPE_ARM_VGIC_V3 ? T_GICV3 : T_GICV2, 0);
	if (run_vcpu(0, &log, raise_spi)) {
		snprintf(what, sizeof(what), "%s", name);
		check(what, 0);
		vm_destroy(1);
		return;
	}
	snprintf(what, sizeof(what), "%s SPI %d from KVM_IRQ_LINE", name, SPI);
	check(what, log.nirqs >= 1 && log.irqs[0] == SPI);
	snprintf(what, sizeof(what), "%s virtual timer (PPI 27) while running", name);
	check(what, log.nirqs >= 2 && log.irqs[1] == 27);
	snprintf(what, sizeof(what), "%s virtual timer (PPI 27) in WFI", name);
	check(what, log.nirqs == 3 && log.irqs[2] == 27);
	vm_destroy(1);
}

int main(int argc, char **argv)
{
	struct kvm_create_device d = { .type = KVM_DEV_TYPE_ARM_VGIC_V3,
				       .flags = KVM_CREATE_DEVICE_TEST };

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("KVMTEST: start\n");
	kvm = open("/dev/kvm", O_RDWR);
	if (kvm < 0)
		die("open /dev/kvm");
	test_mmio();
	test_hvc();
	test_dirty();
	test_onereg();
	test_smp();
	vm = ioctl(kvm, KVM_CREATE_VM, 0);
	if (!ioctl(vm, KVM_CREATE_DEVICE, &d)) {
		close(vm);
		test_gic(KVM_DEV_TYPE_ARM_VGIC_V3, "GICv3");
	} else {
		close(vm);
		test_gic(KVM_DEV_TYPE_ARM_VGIC_V2, "GICv2");
	}
	printf(fail ? "KVMTEST: FAIL\n" : "KVMTEST: PASS\n");
	return fail;
}

// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2000 - 2007 Jeff Dike (jdike@{addtoit,linux.intel}.com)
 *
 * Boot of the l4h guest kernel: memory layout and command line come from
 * the l4h boot info instead of the host process.
 */

#include <linux/kemu.h>
#include <linux/cpu.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/ctype.h>
#include <linux/module.h>
#include <linux/panic_notifier.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/string_choices.h>
#include <linux/utsname.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/kmsg_dump.h>
#include <linux/random.h>
#include <linux/memblock.h>

#include <asm/processor.h>
#include <asm/cpufeature.h>
#include <asm/sections.h>
#include <asm/setup.h>
#ifdef CONFIG_UML_X86
#include <asm/text-patching.h>
#endif
#include <as-layout.h>
#include <arch.h>
#include <init.h>
#include <kern.h>
#include <kern_util.h>
#include <mem_user.h>
#include <os.h>
#include <l4h_sys.h>
#include <l4h_caps.h>
#include <l4h_vspace.h>
#include <l4h_uctx.h>

#include "um_arch.h"

void l4h_smp_setup(void);

static char __initdata command_line[COMMAND_LINE_SIZE] = { 0 };

struct cpuinfo_um boot_cpu_data = {
	.loops_per_jiffy	= 0,
	.cache_alignment	= L1_CACHE_BYTES,
	.x86_capability		= { 0 }
};
EXPORT_SYMBOL(boot_cpu_data);

static char host_info[(__NEW_UTS_LEN + 1) * 5];

static int show_cpuinfo(struct seq_file *m, void *v)
{
	int cpu = (struct cpuinfo_um *)v - &boot_cpu_data;
#ifdef CONFIG_UML_X86
	int i;
#endif

#ifdef CONFIG_KEMU
	if (task_is_kemu(current))
		return kemu_show_cpuinfo(m, cpu);
#endif

	seq_printf(m, "processor\t: %d\n", cpu);
	seq_printf(m, "vendor_id\t: l4h\n");
	seq_printf(m, "model name\t: l4h paravirtual vCPU\n");
	seq_printf(m, "host\t\t: %s\n", host_info);
#ifdef CONFIG_UML_X86
	/*
	 * Report the TSC frequency as the clock speed, as x86 does without
	 * cpufreq. Userspace such as cAdvisor (kubelet) requires this field.
	 */
	seq_printf(m, "cpu MHz\t\t: %llu.%03llu\n",
		   l4h_tsc_hz / 1000000, (l4h_tsc_hz / 1000) % 1000);
	seq_printf(m, "fpu\t\t: %s\n", str_yes_no(cpu_has(&boot_cpu_data, X86_FEATURE_FPU)));
	seq_printf(m, "flags\t\t:");
	for (i = 0; i < 32*NCAPINTS; i++)
		if (cpu_has(&boot_cpu_data, i) && (x86_cap_flags[i] != NULL))
			seq_printf(m, " %s", x86_cap_flags[i]);
	seq_printf(m, "\n");
#else
	seq_printf(m, "Features\t: fp asimd\n");
#endif
	seq_printf(m, "cache_alignment\t: %d\n", boot_cpu_data.cache_alignment);
	seq_printf(m, "bogomips\t: %lu.%02lu\n\n",
		   loops_per_jiffy/(500000/HZ),
		   (loops_per_jiffy/(5000/HZ)) % 100);
	return 0;
}

static void *c_start(struct seq_file *m, loff_t *pos)
{
	while (*pos < nr_cpu_ids && !cpu_online(*pos))
		++*pos;
	/* All vCPUs share boot_cpu_data; pass the index through the pointer. */
	return *pos < nr_cpu_ids ? &boot_cpu_data + *pos : NULL;
}

static void *c_next(struct seq_file *m, void *v, loff_t *pos)
{
	++*pos;
	return c_start(m, pos);
}

static void c_stop(struct seq_file *m, void *v)
{
}

const struct seq_operations cpuinfo_op = {
	.start	= c_start,
	.next	= c_next,
	.stop	= c_stop,
	.show	= show_cpuinfo,
};

/* Guest RAM is mapped at uml_physmem: GPA 0 == uml_physmem. */
unsigned long uml_physmem;
EXPORT_SYMBOL(uml_physmem);
unsigned long uml_reserved;
unsigned long start_vm;
unsigned long end_vm;
unsigned long long physmem_size;
EXPORT_SYMBOL(physmem_size);

unsigned long task_size;
EXPORT_SYMBOL(task_size);
long elf_aux_hwcap;
#ifdef CONFIG_UML_X86
long elf_aux_hwcap2;
#endif
unsigned long end_iomem;
EXPORT_SYMBOL(end_iomem);

/* Use seL4's x86_64 limit on both ISAs: x86_64 reserves the final page
 * below 2^47.  Process and kernel VSpaces are separate, so userspace can
 * use the last PGD slot too.  USER_PTRS_PER_PGD rounds up to include it;
 * TASK_SIZE need not be PGDIR aligned. */
#define L4H_TASK_SIZE	0x00007ffffffff000UL

static int panic_exit(struct notifier_block *self, unsigned long unused1,
		      void *unused2)
{
	kmsg_dump(KMSG_DUMP_PANIC);
	bust_spinlocks(1);
	bust_spinlocks(0);
	os_dump_core();
	return NOTIFY_DONE;
}

static struct notifier_block panic_exit_notifier = {
	.notifier_call	= panic_exit,
	.priority	= INT_MAX - 1, /* run as 2nd notifier, won't return */
};

static void uml_postsetup(void)
{
	initcall_t *p;

	p = &__uml_postsetup_start;
	while (p < &__uml_postsetup_end) {
		(*p)();
		p++;
	}
}

void uml_finishsetup(void)
{
	atomic_notifier_chain_register(&panic_notifier_list,
				       &panic_exit_notifier);

	uml_postsetup();

	new_thread_handler();
}

#ifdef CONFIG_UML_X86
#include <asm/fpu/api.h>

static void __init cpuid(u32 leaf, u32 sub, u32 *a, u32 *b, u32 *c, u32 *d)
{
	asm volatile("cpuid" : "=a"(*a), "=b"(*b), "=c"(*c), "=d"(*d) : "a"(leaf), "c"(sub));
}

/* Words of x86_capability[] (as in arch/x86/include/asm/cpufeature.h). */
enum {
	CPUID_1_EDX = 0, CPUID_8000_0001_EDX = 1, CPUID_1_ECX = 4,
	CPUID_8000_0001_ECX = 6, CPUID_7_0_EBX = 9, CPUID_7_ECX = 16, CPUID_7_EDX = 18,
};

/*
 * seL4 enables only some XSAVE state components (KernelXSaveFeatureSet);
 * instructions using the others fault even if CPUID lists them.
 */
static void __init l4h_mask_xsave_features(void)
{
	u32 *cap = boot_cpu_data.x86_capability;
	u32 lo, hi;
	u64 xcr0 = 0;

	if (cap[CPUID_1_ECX] & BIT(27)) {	/* OSXSAVE */
		asm volatile("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0));
		xcr0 = lo | (u64)hi << 32;
	}
	l4h_xfeatures = xcr0;
	if ((xcr0 & 0x6) != 0x6) {		/* SSE + AVX state */
		cap[CPUID_1_ECX] &= ~(BIT(12) | BIT(28) | BIT(29));	/* FMA, AVX, F16C */
		cap[CPUID_7_0_EBX] &= ~BIT(5);				/* AVX2 */
	}
	if ((xcr0 & 0xe6) != 0xe6) {		/* AVX-512 state */
		cap[CPUID_7_0_EBX] &= ~(BIT(16) | BIT(17) | BIT(21) | BIT(26) | BIT(27) |
					BIT(28) | BIT(30) | BIT(31));
		cap[CPUID_7_ECX] &= ~(BIT(1) | BIT(6) | BIT(11) | BIT(12) | BIT(14));
		cap[CPUID_7_EDX] &= ~(BIT(2) | BIT(3) | BIT(8) | BIT(23));
	}
	if ((xcr0 & (BIT(17) | BIT(18))) != (BIT(17) | BIT(18)))	/* AMX state */
		cap[CPUID_7_EDX] &= ~(BIT(22) | BIT(24) | BIT(25));
	if (!(xcr0 & BIT(9)))			/* PKRU */
		cap[CPUID_7_ECX] &= ~(BIT(3) | BIT(4));
}

/*
 * As arch/x86 (intel.c's zmm_exclusion_list): 512-bit vectors lower these
 * cores' clock, so crypto prefers its 256-bit code (X86_FEATURE_PREFER_YMM).
 */
static bool __init l4h_zmm_downclocks(u32 b, u32 c, u32 d, u32 sig)
{
	/* Skylake-X; Ice Lake X, D, client, L, NNPI; Tiger Lake L, client. */
	static const u8 models[] __initconst = {
		0x55, 0x6a, 0x6c, 0x7d, 0x7e, 0x9d, 0x8c, 0x8d,
	};
	unsigned int model = ((sig >> 4) & 0xf) | ((sig >> 12) & 0xf0), i;

	/* "GenuineIntel", family 6 */
	if (b != 0x756e6547 || d != 0x49656e69 || c != 0x6c65746e ||
	    ((sig >> 8) & 0xf) != 6)
		return false;
	for (i = 0; i < ARRAY_SIZE(models); i++)
		if (model == models[i])
			return true;
	return false;
}

/* CPU features as seen by user code: cpuid is not intercepted. */
static void __init l4h_cpu_features(void)
{
	u32 a, b, c, d, max, vendor[3];

	cpuid(0, 0, &max, &vendor[0], &vendor[1], &vendor[2]);
	cpuid(1, 0, &a, &b, &c, &d);
	if (l4h_zmm_downclocks(vendor[0], vendor[1], vendor[2], a))
		set_cpu_cap(&boot_cpu_data, X86_FEATURE_PREFER_YMM);
	elf_aux_hwcap = d;
	boot_cpu_data.x86_capability[CPUID_1_EDX] = d;
	boot_cpu_data.x86_capability[CPUID_1_ECX] = c;
	boot_cpu_data.cache_alignment = ((b >> 8) & 0xff) * 8 ?: L1_CACHE_BYTES;
	if (max >= 7) {
		cpuid(7, 0, &a, &b, &c, &d);
		boot_cpu_data.x86_capability[CPUID_7_0_EBX] = b;
		boot_cpu_data.x86_capability[CPUID_7_ECX] = c;
		boot_cpu_data.x86_capability[CPUID_7_EDX] = d;
		/* seL4 enables wrfsbase and friends (KernelFSGSBase=inst). */
		if (b & BIT(0))
			elf_aux_hwcap2 |= BIT(1);	/* HWCAP2_FSGSBASE */
	}
	cpuid(0x80000000, 0, &max, &b, &c, &d);
	if (max >= 0x80000001) {
		cpuid(0x80000001, 0, &a, &b, &c, &d);
		boot_cpu_data.x86_capability[CPUID_8000_0001_EDX] = d;
		boot_cpu_data.x86_capability[CPUID_8000_0001_ECX] = c;
	}
	l4h_mask_xsave_features();
}

#else
static unsigned int __init id_field(u64 reg, unsigned int shift)
{
	return (reg >> shift) & 0xf;
}

/*
 * AT_HWCAP from the ID registers root passes in bootinfo (EL0 cannot read
 * them).  Only instructions that need no state beyond what seL4 saves per
 * thread (X0-X30, V0-V31, FPSR, FPCR): no SVE, SME, pointer
 * authentication or MTE, and no PSTATE bits such as DIT.
 */
static void __init l4h_cpu_features(void)
{
	const u64 *id = l4h_bootinfo->cpu_id;
	u64 isar0 = id[0], isar1 = id[1], pfr0 = id[3];
	long cap = HWCAP_FP | HWCAP_ASIMD;

	if (id_field(isar0, 4) >= 1)
		cap |= HWCAP_AES;
	if (id_field(isar0, 4) >= 2)
		cap |= HWCAP_PMULL;
	if (id_field(isar0, 8) >= 1)
		cap |= HWCAP_SHA1;
	if (id_field(isar0, 12) >= 1)
		cap |= HWCAP_SHA2;
	if (id_field(isar0, 12) >= 2)
		cap |= HWCAP_SHA512;
	if (id_field(isar0, 16) >= 1)
		cap |= HWCAP_CRC32;
	if (id_field(isar0, 20) >= 2)
		cap |= HWCAP_ATOMICS;
	if (id_field(isar0, 28) >= 1)
		cap |= HWCAP_ASIMDRDM;
	if (id_field(isar0, 32) >= 1)
		cap |= HWCAP_SHA3;
	if (id_field(isar0, 36) >= 1)
		cap |= HWCAP_SM3;
	if (id_field(isar0, 40) >= 1)
		cap |= HWCAP_SM4;
	if (id_field(isar0, 44) >= 1)
		cap |= HWCAP_ASIMDDP;
	if (id_field(isar0, 48) >= 1)
		cap |= HWCAP_ASIMDFHM;
	if (id_field(isar0, 52) >= 1)
		cap |= HWCAP_FLAGM;
	if (id_field(isar1, 0) >= 1)
		cap |= HWCAP_DCPOP;
	if (id_field(isar1, 12) >= 1)
		cap |= HWCAP_JSCVT;
	if (id_field(isar1, 16) >= 1)
		cap |= HWCAP_FCMA;
	if (id_field(isar1, 20) >= 1)
		cap |= HWCAP_LRCPC;
	if (id_field(isar1, 20) >= 2)
		cap |= HWCAP_ILRCPC;
	if (id_field(isar1, 36) >= 1)
		cap |= HWCAP_SB;
	/* FP and AdvSIMD: 0 base, 1 with half precision (0xf: absent). */
	if (id_field(pfr0, 16) == 1)
		cap |= HWCAP_FPHP;
	if (id_field(pfr0, 20) == 1)
		cap |= HWCAP_ASIMDHP;
	elf_aux_hwcap = cap;
}
#endif

void __init setup_machinename(char *machine_out)
{
#ifdef CONFIG_UML_ARM64
	strcpy(machine_out, "aarch64");
#else
	strcpy(machine_out, "x86_64");
#endif
}

void __init setup_hostinfo(char *buf, int len)
{
	snprintf(buf, len, "l4h guest %llu", (unsigned long long)l4h_bootinfo->guest_id);
}

/* Entered from os-sel4/boot.c on vCPU 0. */
void __init l4h_linux_main(void)
{
	const struct l4h_bootinfo *bi = l4h_bootinfo;

	strscpy(command_line, bi->cmdline, sizeof(command_line));

	uml_physmem = bi->ram_base_va;
	physmem_size = bi->ram_size;
	uml_reserved = uml_physmem + bi->kernel_end_gpa;
	high_physmem = uml_physmem + physmem_size;
	/* The direct map ends after the I/O pool, which follows RAM, and the
	 * hotplug region above it: vmalloc starts beyond. */
	end_iomem = max(high_physmem, uml_physmem + bi->io_pool_gpa + bi->io_pool_size);
	if (bi->hp_count)
		end_iomem = max(end_iomem, uml_physmem + bi->hp_gpa + bi->hp_count * L4H_HP_SIZE);

	task_size = L4H_TASK_SIZE;
	start_vm = VMALLOC_START;
	end_vm = VMALLOC_END;

	l4h_cpu_features();
	setup_machinename(init_utsname()->machine);

	l4h_uctx_init();
	arch_task_struct_size = sizeof(struct task_struct) + host_fp_size;

	start_uml();
}

/*
 * Hotplugged memory (drivers/memhp.c) carries its memmap (DESIGN.md §8.5).
 * The option goes first: the command line can override it.
 */
static void __init hotplug_options(void)
{
	static const char opts[] = "memory_hotplug.memmap_on_memory=1 ";
	size_t n = strlen(command_line);

	if (!IS_ENABLED(CONFIG_L4H_MEMHP) || !l4h_bootinfo->hp_count || n + sizeof(opts) > COMMAND_LINE_SIZE)
		return;
	memmove(command_line + sizeof(opts) - 1, command_line, n + 1);
	memcpy(command_line, opts, sizeof(opts) - 1);
}

void __init setup_arch(char **cmdline_p)
{
	u8 rng_seed[32];

	setup_physmem(uml_physmem, uml_reserved, physmem_size);
	l4h_initrd_setup();
#ifdef CONFIG_SMP
	l4h_smp_setup();
#endif
	l4h_caps_init();
	l4h_vspace_init();
	paging_init();
	hotplug_options();
	strscpy(boot_command_line, command_line, COMMAND_LINE_SIZE);
	*cmdline_p = command_line;
	setup_hostinfo(host_info, sizeof host_info);

	if (os_getrandom(rng_seed, sizeof(rng_seed), 0) == sizeof(rng_seed)) {
		add_bootloader_randomness(rng_seed, sizeof(rng_seed));
		memzero_explicit(rng_seed, sizeof(rng_seed));
	}
}

void __init arch_cpu_finalize_init(void)
{
	arch_check_bugs();
}

#ifdef CONFIG_UML_X86
void apply_seal_endbr(s32 *start, s32 *end)
{
}

void apply_retpolines(s32 *start, s32 *end)
{
}

void apply_returns(s32 *start, s32 *end)
{
}

void apply_fineibt(s32 *start_retpoline, s32 *end_retpoline,
		   s32 *start_cfi, s32 *end_cfi)
{
}

void apply_alternatives(struct alt_instr *start, struct alt_instr *end)
{
}

void alternatives_smp_module_add(struct module *mod, char *name, void *locks,
				 void *locks_end, void *text, void *text_end)
{
}

void alternatives_smp_module_del(struct module *mod)
{
}

void *text_poke(void *addr, const void *opcode, size_t len)
{
	WARN_ON(1);
	return memcpy(addr, opcode, len);
}

/* For the BPF JIT's new images: see x86/bpf_jit.c. */
void *text_poke_copy(void *addr, const void *opcode, size_t len)
{
	return memcpy(addr, opcode, len);
}

void smp_text_poke_sync_each_cpu(void)
{
}

#endif

/* ---- misc host services */

static void os_vprint(const char *prefix, const char *fmt, va_list ap)
{
	char buf[256];
	int n = vscnprintf(buf, sizeof(buf), fmt, ap);

	if (prefix)
		l4h_console_write(prefix, strlen(prefix));
	l4h_console_write(buf, n);
}

void os_info(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	os_vprint(NULL, fmt, ap);
	va_end(ap);
}

void os_warn(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	os_vprint("l4h: ", fmt, ap);
	va_end(ap);
}

void os_dump_core(void)
{
	l4h_power(L4H_POWER_CRASH);
}

void um_early_printk(const char *s, unsigned int n)
{
	l4h_console_write(s, n);
}

ssize_t os_getrandom(void *buf, size_t len, unsigned int flags)
{
#ifdef CONFIG_UML_ARM64
	return -ENOSYS;
#else
	size_t i;

	if (!cpu_has(&boot_cpu_data, X86_FEATURE_RDRAND))
		return -ENOSYS;
	for (i = 0; i < len; i += sizeof(unsigned long)) {
		unsigned long v;
		unsigned char ok;
		int tries = 10;

		do {
			asm volatile("rdrand %0; setc %1" : "=r"(v), "=qm"(ok));
		} while (!ok && --tries);
		if (!ok)
			return i;
		memcpy(buf + i, &v, min(sizeof(v), len - i));
	}
	return len;
#endif
}

// SPDX-License-Identifier: GPL-2.0
/*
 * The FPU state of KVM guests, and memory the emulator needs atomically.
 *
 * seL4 runs a VCPU on the FPU state of the thread that enters it (patch
 * 0039), so a nested guest's registers are the kTCB's while it runs.  They
 * stay there across exits: most exits use no vector register, and kernel-
 * mode SIMD (x86/fpu.c), which does, saves them first through
 * l4h_kvm_fpu_save().  They are written back when the vCPU leaves the kTCB.
 *
 * The state is in standard XSAVE format, which is also KVM's UABI, and has
 * only the features seL4 enables in XCR0.
 */
/* compat.h has the one of arch/x86/kvm. */
#undef pr_fmt
#define pr_fmt(fmt) "l4h-kvm: " fmt

#include <linux/kvm_host.h>
#include <linux/mm.h>
#include <linux/percpu.h>
#include <linux/highmem.h>
#include <linux/vmalloc.h>
#include <linux/preempt.h>
#include <linux/bottom_half.h>
#include <linux/uaccess.h>
#include <linux/atomic.h>
#include <asm/fpu/api.h>
#include <asm/intel_pt.h>
#include <asm/reboot.h>
#include <asm/vmx.h>
#include "l4h_kvm.h"

/* For x86 code in arch/x86/kvm, which no guest kernel code feeds. */
DEFINE_PER_CPU(unsigned long, cpu_dr7);
DEFINE_STATIC_KEY_FALSE(switch_vcpu_ibpb);
DEFINE_STATIC_KEY_FALSE(cpu_buf_vm_clear);
enum vmx_l1d_flush_state l1tf_vmx_mitigation = VMENTER_L1D_FLUSH_NOT_REQUIRED;

void write_ibpb(void)
{
}

void hw_breakpoint_restore(void)
{
}

u32 intel_pt_validate_hw_cap(enum pt_capabilities cap)
{
	return 0;
}

void cpu_emergency_register_virt_callback(cpu_emergency_virt_cb *callback)
{
}

void cpu_emergency_unregister_virt_callback(cpu_emergency_virt_cb *callback)
{
}

void perf_get_x86_pmu_capability(struct x86_pmu_capability *cap)
{
	memset(cap, 0, sizeof(*cap));
}

u64 perf_get_hw_event_config(int hw_event)
{
	return 0;
}

/* The state in this kTCB's registers, if it is a guest's. */
static DEFINE_PER_CPU(struct fpstate *, loaded);

static unsigned int xsave_size;
static u32 mxcsr_mask;

static inline void xsave(struct fpstate *f)
{
	u32 lo = l4h_xfeatures, hi = l4h_xfeatures >> 32;

	asm volatile(".byte 0x48, 0x0f, 0xae, 0x27" /* xsave64 (%rdi) */
		     : : "D" (&f->regs.xsave), "a" (lo), "d" (hi) : "memory");
}

static inline void xrstor(struct fpstate *f)
{
	u32 lo = l4h_xfeatures, hi = l4h_xfeatures >> 32;

	asm volatile(".byte 0x48, 0x0f, 0xae, 0x2f" /* xrstor64 (%rdi) */
		     : : "D" (&f->regs.xsave), "a" (lo), "d" (hi) : "memory");
}

void l4h_kvm_fpu_init(void)
{
	union fpregs_state *regs;

	xsave_size = cpuid_ebx(0xd);
	regs = kzalloc(sizeof(*regs), GFP_KERNEL);
	if (regs) {
		kernel_fpu_begin();
		asm volatile("fxsaveq %0" : "=m" (regs->fxsave));
		kernel_fpu_end();
		mxcsr_mask = regs->fxsave.mxcsr_mask ?: 0xffbf;
		kfree(regs);
	}
}

/* Write this kTCB's guest state back, for the next user of the registers. */
void l4h_kvm_fpu_save(void)
{
	struct fpstate *f = this_cpu_read(loaded);

	if (f) {
		xsave(f);
		this_cpu_write(loaded, NULL);
	}
}

/* With preemption off. */
void l4h_kvm_fpu_load(struct kvm_vcpu *vcpu)
{
	struct fpstate *f = vcpu->arch.guest_fpu.fpstate;

	if (this_cpu_read(loaded) == f)
		return;
	l4h_kvm_fpu_save();
	xrstor(f);
	this_cpu_write(loaded, f);
}

/* kvm/fpu.h: the emulator reads and writes the registers directly. */
void l4h_kvm_fpu_lock(void)
{
	struct kvm_vcpu *vcpu;

	local_bh_disable();
	vcpu = kvm_get_running_vcpu();
	if (vcpu)
		l4h_kvm_fpu_load(vcpu);
}

void l4h_kvm_fpu_unlock(void)
{
	local_bh_enable();
}

bool fpu_alloc_guest_fpstate(struct fpu_guest *gfpu)
{
	struct fpstate *f = vzalloc(ALIGN(offsetof(struct fpstate, regs) + xsave_size, 64));

	if (!f)
		return false;
	f->size = xsave_size;
	f->user_size = xsave_size;
	f->xfeatures = l4h_xfeatures;
	f->user_xfeatures = l4h_xfeatures;
	f->is_guest = true;
	f->regs.xsave.i387.mxcsr = MXCSR_DEFAULT;
	f->regs.xsave.i387.cwd = 0x37f;
	f->regs.xsave.i387.twd = 0;
	f->regs.xsave.header.xfeatures = XFEATURE_MASK_FPSSE;
	gfpu->fpstate = f;
	gfpu->xfeatures = l4h_xfeatures;
	/* KVM_GET_XSAVE's struct kvm_xsave, which holds all of ours. */
	gfpu->uabi_size = sizeof(struct kvm_xsave);
	return true;
}

void fpu_free_guest_fpstate(struct fpu_guest *gfpu)
{
	vfree(gfpu->fpstate);
	gfpu->fpstate = NULL;
}

/* Leaving KVM_RUN is the time to write them back; entering it, loading can
 * wait for the VM entry.  The saving side may run on any vCPU's stack, but
 * not before the task has this vCPU. */
int fpu_swap_kvm_fpstate(struct fpu_guest *gfpu, bool enter_guest)
{
	gfpu->fpstate->in_use = enter_guest;
	if (!enter_guest) {
		preempt_disable();
		if (this_cpu_read(loaded) == gfpu->fpstate)
			l4h_kvm_fpu_save();
		preempt_enable();
	}
	return 0;
}

void fpu_copy_guest_fpstate_to_uabi(struct fpu_guest *gfpu, void *buf, unsigned int size,
				    u64 xfeatures, u32 pkru)
{
	memset(buf, 0, size);
	memcpy(buf, &gfpu->fpstate->regs.xsave, min(size, gfpu->fpstate->size));
}

/*
 * A state XRSTOR would fault on must not get here: the fault would be the
 * guest kernel's.
 */
int fpu_copy_uabi_to_guest_fpstate(struct fpu_guest *gfpu, const void *buf, u64 xcr0, u32 *vpkru)
{
	const struct xregs_state *x = buf;
	int i;

	if (x->header.xfeatures & ~l4h_xfeatures || x->header.xcomp_bv)
		return -EINVAL;
	for (i = 0; i < ARRAY_SIZE(x->header.reserved); i++)
		if (x->header.reserved[i])
			return -EINVAL;
	if (x->i387.mxcsr & ~mxcsr_mask)
		return -EINVAL;
	memcpy(&gfpu->fpstate->regs.xsave, buf, gfpu->fpstate->size);
	return 0;
}

void fpstate_clear_xstate_component(struct fpstate *fpstate, unsigned int nr)
{
	fpstate->regs.xsave.header.xfeatures &= ~BIT_ULL(nr);
}

/*
 * cmpxchg on a guest page of user memory.  Returns <0 if it cannot be
 * reached, 0 on success, 1 with *old updated if it held something else.
 */
int l4h_kvm_cmpxchg_user(void __user *ptr, void *old, const void *new, unsigned int size)
{
	unsigned long addr = (unsigned long)ptr;
	struct page *page;
	void *kaddr;
	int ret = 0;

	if ((addr & ~PAGE_MASK) + size > PAGE_SIZE)
		return -EFAULT;
	if (get_user_pages_fast(addr, 1, FOLL_WRITE, &page) != 1)
		return -EFAULT;
	kaddr = kmap_local_page(page) + (addr & ~PAGE_MASK);
#define CMPXCHG(t) do {							\
		t o = *(t *)old;					\
		if (!try_cmpxchg((t *)kaddr, &o, *(const t *)new)) {	\
			*(t *)old = o;					\
			ret = 1;					\
		}							\
	} while (0)
	switch (size) {
	case 1:
		CMPXCHG(u8);
		break;
	case 2:
		CMPXCHG(u16);
		break;
	case 4:
		CMPXCHG(u32);
		break;
	case 8:
		CMPXCHG(u64);
		break;
	default:
		ret = -EINVAL;
	}
#undef CMPXCHG
	kunmap_local(kaddr);
	set_page_dirty_lock(page);
	put_page(page);
	return ret;
}

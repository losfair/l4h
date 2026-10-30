// SPDX-License-Identifier: GPL-2.0
/*
 * l4h ABI test: a module that exercises the l4h guest ABI and the seL4
 * extensions E1-E3 directly, below Linux (tests/run-abitest.sh).  This half
 * gathers what the tests need from Linux; sel4.c runs them against libsel4,
 * on one vCPU with interrupts off.  Prints "ABITEST: PASS" or
 * "ABITEST: FAIL ...".
 */
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/gfp.h>
#include <linux/irqflags.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/preempt.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <l4h_sys.h>
#include <l4h_caps.h>
#include <l4h_vspace.h>
#include "abitest.h"

#define MAX_OBJS	64
#define MAX_SLOTS	128

static struct l4h_obj objs[MAX_OBJS];
static unsigned long slots[MAX_SLOTS];
static int nr_objs, nr_slots;
static void *kva;

unsigned long abitest_obj(int type, int size_bits)
{
	if (nr_objs == MAX_OBJS || l4h_obj_alloc(type, size_bits, &objs[nr_objs]))
		return 0;
	return objs[nr_objs++].cptr;
}

unsigned long abitest_slot(void)
{
	unsigned long s;

	if (nr_slots == MAX_SLOTS || !(s = l4h_slot_alloc()))
		return 0;
	return slots[nr_slots++] = s;
}

volatile void *abitest_map(unsigned long frame, int i)
{
	unsigned long va = (unsigned long)kva + i * PAGE_SIZE, s;

	if (nr_slots == MAX_SLOTS || i >= ABITEST_KPAGES || !(s = l4h_kernel_map_frame(frame, va)))
		return NULL;
	slots[nr_slots++] = s;
	return (volatile void *)va;
}

/* Guest-physical address of a page of the direct map. */
static unsigned long gpa(const void *va)
{
	return (unsigned long)va - l4h_bootinfo->ram_base_va;
}

/* The first virtio-blk device, which the test drives badly on purpose:
 * boot with initcall_blacklist=virtio_blk_init so that no driver has it. */
static int find_blk(void)
{
	const struct l4h_bootinfo *bi = l4h_bootinfo;
	int i;

	for (i = 0; i < bi->nr_devices; i++)
		if (bi->devices[i].type == L4H_DEV_VIRTIO && bi->devices[i].virtio_id == 2)
			return i;
	return -1;
}

static int __init abitest_init(void)
{
	struct abitest t = { .blk = find_blk() };
	struct page *user = alloc_page(GFP_KERNEL | __GFP_ZERO);
	struct page *zero = alloc_page(GFP_KERNEL | __GFP_ZERO);
	void *ram = (void *)get_zeroed_page(GFP_KERNEL);
	struct device *pool = bus_find_device_by_name(&platform_bus_type, NULL, "virtio-l4h");
	dma_addr_t dma_gpa = 0;
	void *dma = NULL;
	unsigned long flags;
	int err = -ENOMEM;

	if (pool)
		dma = dma_alloc_coherent(pool, ABITEST_DMA_SIZE, &dma_gpa, GFP_KERNEL);
	kva = l4h_kernel_va_get(ABITEST_KPAGES * PAGE_SIZE);
	if (!user || !zero || !ram || !dma || !kva)
		goto out;
	memcpy(page_address(user), user_prog, user_end - user_prog);
	t.user_gpa = gpa(page_address(user));
	t.zero_gpa = gpa(page_address(zero));
	t.ram = ram;
	t.ram_gpa = gpa(ram);
	t.dma = dma;
	t.dma_gpa = dma_gpa;
	t.vspace = l4h_vspace_get();
	t.large_ut = abitest_obj(L4H_OBJ_UNTYPED, L4H_BLOCK_SHIFT);

	preempt_disable();
	local_irq_save(flags);
	t.cpu = smp_processor_id();
	/* The tests' user thread takes this vCPU's user scheduling context. */
	if (l4h_vcpus[t.cpu].sc_owner)
		l4h_user_deschedule(l4h_vcpus[t.cpu].sc_owner);
	err = abitest_run(&t) ? -EIO : 0;
	/* The E3 test took the vCPU's timer. */
	if (l4h_vcpus[t.cpu].timer_deadline)
		l4h_timer_arm(l4h_vcpus[t.cpu].timer_deadline);
	local_irq_restore(flags);
	preempt_enable();

	/* Copies first: deleting them unmaps what the tests mapped. */
	while (nr_slots)
		l4h_slot_delete(slots[--nr_slots]);
	while (nr_objs)
		l4h_obj_free(&objs[--nr_objs]);
	l4h_vspace_put(t.vspace);
	pr_info("ABITEST: %s\n", err ? "FAIL" : "PASS");
out:
	if (kva)
		l4h_kernel_va_put(kva);
	if (dma)
		dma_free_coherent(pool, ABITEST_DMA_SIZE, dma, dma_gpa);
	put_device(pool);
	free_page((unsigned long)ram);
	if (zero)
		__free_page(zero);
	if (user)
		__free_page(user);
	return err;
}

static void __exit abitest_exit(void)
{
}

module_init(abitest_init);
module_exit(abitest_exit);
MODULE_DESCRIPTION("l4h guest ABI and seL4 extension tests");
MODULE_LICENSE("GPL");

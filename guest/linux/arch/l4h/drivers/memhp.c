// SPDX-License-Identifier: GPL-2.0
/*
 * Memory hotplug from the l4h host (DESIGN.md §8.5), through the memory
 * device (L4H_DEV_MEM, struct l4h_mem_page).  dom0 sets a target; we plug
 * and unplug hotplug blocks of 128 MiB (one Linux memory block each) until
 * we have that many.  A plugged block brings its own metadata:
 *
 *   block 0       its memmap (memmap_on_memory)
 *   blocks 1-62   RAM, onlined to ZONE_MOVABLE
 *   block 63      the seL4 objects that map blocks 0-62 (l4h_hp_map()),
 *                 kept PageOffline: never in the page allocator
 *
 * Plug: the CNodes the host copies the Untypeds into, a plug request, map
 * the frames, add_memory.  Unplug: offline_and_remove_memory, unmap, then
 * an unplug request, which revokes the Untypeds.  Memory that cannot be offlined
 * (pinned or unmovable pages) stays: the host then sees plugged > target.
 */
#include <linux/bitmap.h>
#include <linux/device.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/memory.h>
#include <linux/memory_hotplug.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/page_ref.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <irq_kern.h>
#include <l4h_sys.h>
#include <l4h_caps.h>

#define HP_OBJ_BLOCK	(L4H_HP_BLOCKS - 1)
/* Retry after the host was busy, or Linux could not offline enough. */
#define RETRY_BUSY	HZ
#define RETRY_STUCK	(10 * HZ)
/* Available memory an unplug leaves, at least (can_spare_block()). */
#define HEADROOM_MIN	(64ul << 20)
#define HEADROOM_SHIFT	4

static_assert(L4H_HP_SHIFT == SECTION_SIZE_BITS);

static struct l4h_mem_page *page;
static u64 region_gpa;
static unsigned int region_count;
/* Hotplug blocks in Linux, and those out of Linux and unmapped that the
 * host has not taken back yet. */
static DECLARE_BITMAP(added, L4H_HP_MAX);
static DECLARE_BITMAP(pending, L4H_HP_MAX);
static DEFINE_MUTEX(memhp_mutex);

static void memhp_work_fn(struct work_struct *w);
static DECLARE_DELAYED_WORK(memhp_work, memhp_work_fn);

static u64 block_gpa(unsigned int m)
{
	return region_gpa + (u64)m * L4H_HP_SIZE;
}

/* Requests go through the device page and are answered with its event,
 * so the vCPU runs other tasks meanwhile. */
static unsigned long mem_kick;
static u32 mem_seq;
/* The target the worker is currently reconciling, not the last IRQ. */
static u32 mem_target;
static DECLARE_WAIT_QUEUE_HEAD(mem_wq);

/* Callers hold memhp_mutex: one request at a time. */
static long mem_call(unsigned long op, unsigned int m)
{
	WRITE_ONCE(page->req_op, op);
	WRITE_ONCE(page->req_block, m);
	smp_store_release(&page->req_seq, ++mem_seq);
	l4h_signal(mem_kick);
	wait_event(mem_wq, smp_load_acquire(&page->done_seq) == mem_seq);
	return READ_ONCE(page->result);
}

/* Is `pfn` in the object block of a hotplug block? */
static bool in_obj_block(unsigned long pfn)
{
	u64 gpa = PFN_PHYS(pfn);

	if (gpa < region_gpa || gpa >= block_gpa(region_count))
		return false;
	return ((gpa - region_gpa) >> L4H_BLOCK_SHIFT) % L4H_HP_BLOCKS == HP_OBJ_BLOCK;
}

/* Onlining hands out chunks of at most a block, aligned: the object block's
 * stay PageOffline (as initialized), with a reference. */
static void memhp_online_page(struct page *p, unsigned int order)
{
	if (!in_obj_block(page_to_pfn(p)))
		generic_online_page(p, order);
}

/* Offlining skips PageOffline pages without references: drop ours while it
 * runs, as virtio-mem does for its unplugged ranges. */
static int memhp_notify(struct notifier_block *nb, unsigned long action, void *arg)
{
	const struct memory_notify *mn = arg;
	unsigned long pfn, end = mn->start_pfn + mn->nr_pages;

	if (action != MEM_GOING_OFFLINE && action != MEM_CANCEL_OFFLINE)
		return NOTIFY_OK;
	for (pfn = mn->start_pfn; pfn < end; pfn++) {
		if (!in_obj_block(pfn))
			continue;
		if (action == MEM_GOING_OFFLINE)
			page_ref_dec(pfn_to_page(pfn));
		else
			page_ref_inc(pfn_to_page(pfn));
	}
	return NOTIFY_OK;
}

static struct notifier_block memhp_nb = {
	.notifier_call = memhp_notify,
};

/* Did hotplug block m go to ZONE_MOVABLE?  (Its block 0 is its memmap.) */
static bool is_movable(unsigned int m)
{
	struct page *p = pfn_to_online_page(PFN_DOWN(block_gpa(m) + L4H_BLOCK_SIZE));

	return p && page_zonenum(p) == ZONE_MOVABLE;
}

/*
 * Linux may have onlined the block already: when memory is onlined as it is
 * added (auto_online_blocks, memhp_default_state=) or by a udev rule, maybe
 * to a kernel zone.  Such a block is moved to ZONE_MOVABLE if it can be
 * offlined; if not, it stays where it is.
 */
static int online_block(struct memory_block *mem, void *arg)
{
	unsigned int m = *(unsigned int *)arg;
	int ret;

	if (!mem->dev.offline) {
		if (is_movable(m))
			return 0;
		ret = device_offline(&mem->dev);
		if (ret) {
			pr_warn("l4h-memhp: block %u: onlined to a kernel zone, and stays there: %d\n", m, ret);
			return 0;
		}
	}
	mem->online_type = MMOP_ONLINE_MOVABLE;
	ret = device_online(&mem->dev);
	/* 1: onlined meanwhile by someone else. */
	return ret == 1 ? 0 : ret;
}

/*
 * Online hotplug block m, always to ZONE_MOVABLE, which can always be
 * offlined again.  A block in a kernel zone collects unmovable kernel pages
 * and may never go back.  The kernel memory a bigger VM needs most, its
 * processes' seL4 page tables and slots, comes from boot RAM in any case
 * (hotplug blocks are never object blocks, kernel/caps.c); what remains,
 * Linux's own page tables and slabs, is small next to the memory it serves.
 */
static int online(unsigned int m)
{
	int ret;

	lock_device_hotplug();
	ret = walk_memory_blocks(block_gpa(m), L4H_HP_SIZE, &m, online_block);
	unlock_device_hotplug();
	return ret;
}

static int plug(unsigned int m)
{
	long ret = l4h_hp_prepare(m);

	if (ret)
		return ret;
	ret = mem_call(L4H_MEM_PLUG, m);
	if (ret)
		return ret;
	ret = l4h_hp_map(m);
	if (!ret) {
		/* Normally added offline (CONFIG_MHP_DEFAULT_ONLINE_TYPE_OFFLINE),
		 * and we choose its zone. */
		ret = add_memory_driver_managed(0, block_gpa(m), L4H_HP_SIZE, "System RAM (l4h)",
						MHP_MEMMAP_ON_MEMORY);
		if (!ret) {
			ret = online(m);
			/* Nothing Linux may be using goes back: if it will not
			 * let go of the block, it keeps it. */
			if (ret && offline_and_remove_memory(block_gpa(m), L4H_HP_SIZE)) {
				pr_warn("l4h-memhp: block %u: cannot online it as asked, nor remove it: kept as it is: %ld\n",
					m, ret);
				__set_bit(m, added);
				return 0;
			}
		}
		if (ret) {
			pr_err("l4h-memhp: block %u: cannot add it: %ld\n", m, ret);
			l4h_hp_unmap(m);
		}
	}
	if (ret) {
		/* The host takes it back; if it is too busy now, later. */
		if (mem_call(L4H_MEM_UNPLUG, m))
			__set_bit(m, pending);
		return ret;
	}
	__set_bit(m, added);
	return 0;
}

/*
 * Would the guest still have room to run without a hotplug block?
 * Offlining moves whatever it can elsewhere, and memory that cannot be
 * reclaimed (tmpfs without swap) then fills what is left: keep available
 * memory for HEADROOM_SHIFT-th of RAM, at least HEADROOM_MIN.
 */
static bool can_spare_block(void)
{
	unsigned long headroom = max(HEADROOM_MIN >> PAGE_SHIFT, totalram_pages() >> HEADROOM_SHIFT);

	return si_mem_available() >= (long)((L4H_HP_SIZE >> PAGE_SHIFT) + headroom);
}

static int unplug(unsigned int m)
{
	int ret;

	if (!can_spare_block())
		return -ENOMEM;
	ret = offline_and_remove_memory(block_gpa(m), L4H_HP_SIZE);
	if (ret)
		return ret;
	__clear_bit(m, added);
	l4h_hp_unmap(m);
	if (mem_call(L4H_MEM_UNPLUG, m))
		__set_bit(m, pending);
	return 0;
}

/* Bring the plugged hotplug blocks to the host's target. */
static void memhp_work_fn(struct work_struct *w)
{
	unsigned long delay = 0;
	unsigned int m, n, target;

	mutex_lock(&memhp_mutex);
	target = min(READ_ONCE(page->target), region_count);
	WRITE_ONCE(mem_target, target);
	/* First what the host has yet to take back. */
	for_each_set_bit(m, pending, region_count) {
		if (mem_call(L4H_MEM_UNPLUG, m)) {
			delay = RETRY_BUSY;
			goto out;
		}
		__clear_bit(m, pending);
	}
	n = bitmap_weight(added, region_count);
	while (n < target) {
		long ret;

		m = find_first_zero_bit(added, region_count);
		ret = m < region_count ? plug(m) : -ENOSPC;
		if (ret) {
			/* -ENOSPC: the target has just gone down. */
			if (ret != -ENOSPC) {
				pr_info_ratelimited("l4h-memhp: block %u: cannot plug: %ld\n", m, ret);
				delay = ret == -EBUSY ? RETRY_BUSY : RETRY_STUCK;
			}
			goto out;
		}
		n++;
	}
	while (n > target) {
		int ret = -ENOENT;

		if (!can_spare_block()) {
			pr_info_ratelimited("l4h-memhp: %u blocks plugged, target %u: too little memory available to give one back\n",
					    n, target);
			delay = RETRY_STUCK;
			goto out;
		}
		/* Highest first; another if one has pages that will not move. */
		for (m = region_count; m-- > 0 && ret;) {
			if (test_bit(m, added))
				ret = unplug(m);
		}
		if (ret) {
			pr_info_ratelimited("l4h-memhp: %u blocks plugged, target %u: cannot offline more: %d\n",
					    n, target, ret);
			delay = RETRY_STUCK;
			goto out;
		}
		n--;
	}
out:
	/* Blocks out of Linux that the host was too busy to take back:
	 * retry, even with the target met and no event to come. */
	if (!delay && !bitmap_empty(pending, region_count))
		delay = RETRY_BUSY;
	mutex_unlock(&memhp_mutex);
	/* Catch a target changed before the worker published mem_target,
	 * even if its interrupt already ran. */
	if (min(READ_ONCE(page->target), region_count) != target)
		mod_delayed_work(system_wq, &memhp_work, 0);
	else if (delay)
		schedule_delayed_work(&memhp_work, delay);
}

/* A new target, or a request answered. */
static irqreturn_t memhp_interrupt(int irq, void *data)
{
	wake_up(&mem_wq);
	/* A completion alone must not override the worker's retry delay. */
	if (min(READ_ONCE(page->target), region_count) != READ_ONCE(mem_target))
		mod_delayed_work(system_wq, &memhp_work, 0);
	return IRQ_HANDLED;
}

static int __init l4h_memhp_init(void)
{
	const struct l4h_bootinfo *bi = l4h_bootinfo;
	unsigned int i;
	int irq, ret;

	for (i = 0; i < bi->nr_devices && i < L4H_MAX_DEVICES; i++) {
		if (bi->devices[i].type == L4H_DEV_MEM)
			break;
	}
	if (i == bi->nr_devices || i == L4H_MAX_DEVICES || !bi->hp_count)
		return 0;
	page = (struct l4h_mem_page *)bi->devices[i].page_va;
	mem_seq = READ_ONCE(page->req_seq);
	mem_kick = L4H_CPTR2(L4H_SLOT_DEV_CNODE, bi->devices[i].kick_slot);
	region_gpa = bi->hp_gpa;
	region_count = min_t(u64, bi->hp_count, L4H_HP_MAX);
	mem_target = min(READ_ONCE(page->target), region_count);
	if (!mhp_supports_memmap_on_memory())
		pr_warn("l4h-memhp: no memmap_on_memory: plugged memory takes its memmap from boot RAM\n");
	ret = set_online_page_callback(memhp_online_page);
	if (ret)
		return ret;
	ret = register_memory_notifier(&memhp_nb);
	if (ret)
		return ret;
	irq = l4h_event_irq(bi->devices[i].event);
	if (irq < 0)
		return irq;
	ret = request_irq(irq, memhp_interrupt, 0, "l4h-memhp", NULL);
	if (ret)
		return ret;
	pr_info("l4h-memhp: %u hotplug blocks of %llu MiB from %#llx\n", region_count,
		L4H_HP_SIZE >> 20, region_gpa);
	schedule_delayed_work(&memhp_work, 0);
	return 0;
}
late_initcall(l4h_memhp_init);

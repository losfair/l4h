// SPDX-License-Identifier: GPL-2.0
/*
 * seL4 address spaces of the l4h guest.
 *
 * The kernel keeps ordinary Linux page tables; the seL4 VSpaces are caches
 * of them, filled by the UML TLB-sync machinery (tlb.c, through map() and
 * unmap()) and by the page fault path (l4h_map_fault()).
 *
 * Process VSpaces come from a fixed pool of pre-assigned VSpace roots
 * (seL4 ASIDs are scarce, see DESIGN.md).  An mm gets a pool entry when one
 * of its threads first runs; when the pool is exhausted the least recently
 * activated mm without running threads loses its entry, and simply refaults
 * its pages when it runs again.
 *
 * Every mapping needs its own frame capability: the slot is recorded in a
 * per-address-space xarray (virtual page -> slot | rights | pfn) so that it
 * can be deleted again on unmap, and a remap with unchanged rights skipped.
 */
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/xarray.h>
#include <linux/memblock.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/export.h>
#include <linux/vmalloc.h>
#include <asm/tlbflush.h>
#include <asm/pgtable.h>
#include <as-layout.h>
#include <os.h>
#include <l4h_sys.h>
#include <l4h_caps.h>
#include <l4h_vspace.h>

#define SLOT_BITS	30
#define SLOT_MASK	((1ul << SLOT_BITS) - 1)
#define PROT_SHIFT	SLOT_BITS
#define PROT_MASK	7ul
#define PFN_SHIFT	(SLOT_BITS + 3)

/* The rights a mapping with L4H_PROT_* `prot` gets (seL4 has no
 * write-only mappings). */
static inline unsigned long eff_prot(int prot)
{
	prot &= PROT_MASK;
	return (prot & L4H_PROT_WRITE) ? prot | L4H_PROT_READ : prot;
}

static inline void *mk_entry(unsigned long slot, unsigned long pfn, int prot)
{
	return xa_mk_value((pfn << PFN_SHIFT) | (eff_prot(prot) << PROT_SHIFT) | slot);
}

static inline unsigned long entry_slot(void *e)
{
	return xa_to_value(e) & SLOT_MASK;
}

static inline unsigned long entry_pfn(void *e)
{
	return xa_to_value(e) >> PFN_SHIFT;
}

static inline unsigned long entry_prot(void *e)
{
	return (xa_to_value(e) >> PROT_SHIFT) & PROT_MASK;
}

struct table {
	struct list_head link;
	struct l4h_obj obj;
	int level;		/* index into l4h_pt_level_obj[] */
	unsigned long base;	/* virtual coverage of this table */
};

/* One seL4 address space: a VSpace root plus the page tables we added. */
struct l4h_as {
	unsigned long root;
	struct list_head tables;
	struct xarray pages;	/* 4 KiB leaves, indexed by VPN */
	struct xarray large;	/* 2 MiB leaves, indexed by PMD number */
	unsigned long nr_pages, nr_tables;
	long charged;		/* as_cost() last added to the owner mm */
	bool flush_pending;	/* rights lowered with L4H_PROT_DEFER_FLUSH */
};

static void as_init(struct l4h_as *as, unsigned long root)
{
	as->root = root;
	INIT_LIST_HEAD(&as->tables);
	xa_init(&as->pages);
	xa_init(&as->large);
	as->nr_pages = as->nr_tables = 0;
	as->charged = 0;
	as->flush_pending = false;
}

/*
 * Guest memory an address space takes beyond its pages: per mapping a slot
 * (32 bytes of slot CNode) and its xarray entry, and the seL4 page tables.
 * A process with many mappings of few pages (the zero page) has almost no
 * RSS, so this goes into its page-table bytes, which the OOM killer counts.
 */
#define MAPPING_COST	48

static long as_cost(struct l4h_as *as)
{
	return as->nr_pages * MAPPING_COST + as->nr_tables * PAGE_SIZE;
}

/* Bring mm's charge for `as` up to date.  Must hold the mm's lock. */
static void as_charge(struct l4h_as *as, struct mm_struct *mm)
{
	long cost = as_cost(as);

	atomic_long_add(cost - as->charged, &mm->pgtables_bytes);
	as->charged = cost;
}

static int as_add_table(struct l4h_as *as, int level, unsigned long va)
{
	struct table *t;
	int err;

	if (level >= L4H_NR_PT_LEVELS)
		return -EFAULT;
	/* User roots start empty. Install top down so ARM's first-missing-
	 * level API also gives us exact coverage for promotion. The kernel
	 * root has pre-existing boot/direct-map tables and uses lazy lookup. */
	if (as->root != L4H_CPTR(L4H_SLOT_VSPACE)) {
		unsigned long base = va & ~((1ul << l4h_pt_level_shift[level]) - 1);

		list_for_each_entry(t, &as->tables, link)
			if (t->level == level && t->base == base)
				return 0;
		if (level + 1 < L4H_NR_PT_LEVELS) {
			err = as_add_table(as, level + 1, va);
			if (err)
				return err;
		}
	}
	t = kzalloc(sizeof(*t), GFP_ATOMIC);
	if (!t)
		return -ENOMEM;
	err = l4h_obj_alloc(l4h_pt_level_obj[level], 0, &t->obj);
	if (err) {
		kfree(t);
		return err;
	}
	for (;;) {
		err = l4h_pt_map(l4h_pt_level_obj[level], t->obj.cptr, as->root, va);
		if (err != L4H_ERR_FAILED_LOOKUP)
			break;
		err = as_add_table(as, level + 1, va);
		if (err)
			break;
	}
	if (err) {
		l4h_obj_free(&t->obj);
		kfree(t);
		/* A parent's -ENOMEM must reach the callers that wait for memory. */
		if (err < 0)
			return err;
		return err == L4H_ERR_DELETE_FIRST ? 0 : -EFAULT;
	}
	t->level = level;
	t->base = va & ~((1ul << l4h_pt_level_shift[level]) - 1);
	list_add(&t->link, &as->tables);
	as->nr_tables++;
	return 0;
}

/* A partial update drops the whole hardware large leaf. The unchanged
 * neighbors remain valid Linux mappings and refault as small pages. This
 * also makes demotion allocation-free when a TLB sync runs out of memory. */
static void as_drop_large(struct l4h_as *as, unsigned long va)
{
	void *e = xa_load(&as->large, va >> PMD_SHIFT);

	if (e) {
		xa_erase(&as->large, va >> PMD_SHIFT);
		l4h_slot_delete(entry_slot(e));
		as->nr_pages--;
	}
}

/*
 * Map `phys` at `va`.  With `defer`, a remap that lowers the rights of the
 * frame leaves the TLBs to as_flush_deferred(): a TLB sync lowers many in a
 * row (fork write-protects every private page), and each flush is an IPI
 * round trip to every core the address space ran on.
 */
static int as_map_page(struct l4h_as *as, unsigned long va, unsigned long phys, int prot,
		       bool defer)
{
	unsigned long vpn = va >> PAGE_SHIFT, pfn = phys >> PAGE_SHIFT;
	void *e;
	unsigned long slot;
	int err;

	as_drop_large(as, va);
	e = xa_load(&as->pages, vpn);
	if (e && entry_pfn(e) == pfn) {
		/* Same frame.  The entry mirrors the VSpace: a mapping with the
		 * same rights is already there (the sync and the fault path
		 * both install it after a fault), so skip it. */
		unsigned long lowered = entry_prot(e) & ~eff_prot(prot);

		if (entry_prot(e) == eff_prot(prot))
			return 0;
		err = l4h_page_map(entry_slot(e), as->root, va,
				   prot | (defer && lowered ? L4H_PROT_DEFER_FLUSH : 0));
		if (err)
			return -EFAULT;
		if (defer && lowered)
			as->flush_pending = true;
		xa_store(&as->pages, vpn, mk_entry(entry_slot(e), pfn, prot), GFP_ATOMIC);
		return 0;
	}
	if (e) {
		xa_erase(&as->pages, vpn);
		l4h_slot_delete(entry_slot(e));
		as->nr_pages--;
	}
	slot = l4h_cap_copy(L4H_FRAME_CPTR(phys), L4H_RIGHTS_ALL);
	if (!slot)
		return -ENOMEM;
	for (;;) {
		err = l4h_page_map(slot, as->root, va, prot);
		if (err != L4H_ERR_FAILED_LOOKUP)
			break;
		err = as_add_table(as, 0, va);
		if (err)
			break;
	}
	if (err) {
		l4h_slot_delete(slot);
		return err < 0 ? err : -EFAULT;
	}
	err = xa_err(xa_store(&as->pages, vpn, mk_entry(slot, pfn, prot), GFP_ATOMIC));
	if (err) {
		l4h_slot_delete(slot);
		return err;
	}
	as->nr_pages++;
	return 0;
}

static void as_unmap_range(struct l4h_as *as, unsigned long start, unsigned long end)
{
	unsigned long vpn;
	void *e;

	xa_for_each_range(&as->large, vpn, e, start >> PMD_SHIFT, (end - 1) >> PMD_SHIFT) {
		xa_erase(&as->large, vpn);
		l4h_slot_delete(entry_slot(e));
		as->nr_pages--;
	}
	xa_for_each_range(&as->pages, vpn, e, start >> PAGE_SHIFT, (end - 1) >> PAGE_SHIFT) {
		xa_erase(&as->pages, vpn);
		/* Deleting the frame capability removes the mapping. */
		l4h_slot_delete(entry_slot(e));
		as->nr_pages--;
	}
}

/* Promote only a Linux huge PMD backed by a canonical large frame. */
static int as_map_large(struct l4h_as *as, unsigned long va, unsigned long phys,
			int prot, unsigned long frame)
{
	unsigned long index = va >> PMD_SHIFT, pfn = phys >> PAGE_SHIFT, slot;
	void *e = xa_load(&as->large, index);
	struct table *t, *n;
	int err;

	if (e && entry_pfn(e) == pfn) {
		if (entry_prot(e) == eff_prot(prot))
			return 0;
		/* One flush per PMD is cheap; no deferred large-page remaps. */
		err = l4h_page_map(entry_slot(e), as->root, va, prot | L4H_PROT_LARGE);
		if (err)
			return -EFAULT;
		xa_store(&as->large, index, mk_entry(entry_slot(e), pfn, prot), GFP_ATOMIC);
		return 0;
	}
	/* Removing the leaf table first flushes its 512 translations once.
	 * seL4 rejects a large leaf while that table remains installed. */
	list_for_each_entry_safe(t, n, &as->tables, link) {
		if (t->level == 0 && t->base == va) {
			list_del(&t->link);
			l4h_obj_free(&t->obj);
			kfree(t);
			as->nr_tables--;
		}
	}
	as_unmap_range(as, va, va + PMD_SIZE);
	slot = l4h_cap_copy(frame, L4H_RIGHTS_ALL);
	if (!slot)
		return -ENOMEM;
	for (;;) {
		err = l4h_page_map(slot, as->root, va, prot | L4H_PROT_LARGE);
		if (err != L4H_ERR_FAILED_LOOKUP)
			break;
		err = as_add_table(as, 1, va);
		if (err)
			break;
	}
	if (!err)
		err = xa_err(xa_store(&as->large, index, mk_entry(slot, pfn, prot), GFP_ATOMIC));
	if (err) {
		l4h_slot_delete(slot);
		return err < 0 ? err : -EFAULT;
	}
	as->nr_pages++;
	return 0;
}

/*
 * Remove every mapping and page table, leaving an empty VSpace root.
 *
 * The tables go first, the highest level first: oldest first, as a table is
 * always mapped after the ones above it (as_add_table() maps the missing
 * parents first for user roots on both ISAs).  Unmapping one invalidates
 * the whole ASID once (x86_64 flushPDPT()/flushPD(), aarch64
 * unmapPageTable()) and takes everything below it out of the VSpace; the
 * lower tables and the frames then find no mapping from the root and are
 * deleted without a flush.  Deleting the frames first was a TLB shootdown,
 * to every core the address space ran on, per mapping.
 *
 * With `may_sleep`, gives the CPU away now and then: there can be a million
 * frame capabilities to delete.
 */
static void as_reset(struct l4h_as *as, bool may_sleep)
{
	struct table *t, *n;
	unsigned long vpn;
	void *e;

	list_for_each_entry_safe_reverse(t, n, &as->tables, link) {
		list_del(&t->link);
		l4h_obj_free(&t->obj);
		kfree(t);
	}
	as->nr_tables = 0;
	/* Covered by those invalidations too. */
	as->flush_pending = false;
	xa_for_each(&as->large, vpn, e) {
		xa_erase(&as->large, vpn);
		l4h_slot_delete(entry_slot(e));
		if (!(--as->nr_pages % 1024) && may_sleep)
			cond_resched();
	}
	xa_for_each(&as->pages, vpn, e) {
		xa_erase(&as->pages, vpn);
		l4h_slot_delete(entry_slot(e));
		if (!(--as->nr_pages % 1024) && may_sleep)
			cond_resched();
	}
}

/* ---- the guest-kernel VSpace (vmalloc, modules, ...) */

static struct l4h_as kernel_as;
static DEFINE_RAW_SPINLOCK(kernel_as_lock);

int os_map_memory(void *virt, unsigned long phys, unsigned long len, int r, int w, int x)
{
	int prot = (r ? L4H_PROT_READ : 0) | (w ? L4H_PROT_WRITE : 0) | (x ? L4H_PROT_EXEC : 0);
	unsigned long va = (unsigned long)virt, off, flags;
	int err = 0;

	raw_spin_lock_irqsave(&kernel_as_lock, flags);
	for (off = 0; off < len && !err; off += PAGE_SIZE)
		err = as_map_page(&kernel_as, va + off, phys + off, prot, false);
	raw_spin_unlock_irqrestore(&kernel_as_lock, flags);
	return err;
}

int os_unmap_memory(void *virt, int len)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&kernel_as_lock, flags);
	as_unmap_range(&kernel_as, (unsigned long)virt, (unsigned long)virt + len);
	raw_spin_unlock_irqrestore(&kernel_as_lock, flags);
	return 0;
}

int os_protect_memory(void *addr, unsigned long len, int r, int w, int x)
{
	/* The kernel image lives in the direct map, which the host set up;
	 * we do not change its protection. */
	return 0;
}

/*
 * Frames the kernel did not make, for raw seL4 users such as
 * tests/guest/abitest: l4h_kernel_va_get() reserves address space (it may
 * sleep), l4h_kernel_map_frame() maps a copy of `frame` at a page of it
 * and returns the copy's slot, and deleting that (l4h_slot_delete())
 * unmaps it again.
 */
void *l4h_kernel_va_get(unsigned long size)
{
	struct vm_struct *area = get_vm_area(size, VM_IOREMAP);

	return area ? area->addr : NULL;
}
EXPORT_SYMBOL_GPL(l4h_kernel_va_get);

void l4h_kernel_va_put(void *va)
{
	free_vm_area(find_vm_area(va));
}
EXPORT_SYMBOL_GPL(l4h_kernel_va_put);

unsigned long l4h_kernel_map_frame(unsigned long frame, unsigned long va)
{
	unsigned long flags, slot = l4h_cap_copy(frame, L4H_RIGHTS_ALL);
	int err;

	if (!slot)
		return 0;
	raw_spin_lock_irqsave(&kernel_as_lock, flags);
	while ((err = l4h_page_map(slot, kernel_as.root, va, L4H_PROT_READ | L4H_PROT_WRITE)) ==
	       L4H_ERR_FAILED_LOOKUP) {
		err = as_add_table(&kernel_as, 0, va);
		if (err)
			break;
	}
	raw_spin_unlock_irqrestore(&kernel_as_lock, flags);
	if (err) {
		l4h_slot_delete(slot);
		return 0;
	}
	return slot;
}
EXPORT_SYMBOL_GPL(l4h_kernel_map_frame);

/* Is [addr, addr+size) mapped in the guest-kernel VSpace? */
bool l4h_kernel_range_ok(unsigned long addr, unsigned long size)
{
	unsigned long end = addr + size;

	if (end < addr)
		return false;
	/* Blocks converted to seL4 objects left holes in the direct map. */
	if (addr >= uml_physmem && end <= high_physmem)
		return l4h_ram_mapped(addr - uml_physmem, size);
	if (addr >= l4h_io_pool_start && end <= l4h_io_pool_end)
		return true;
	/* Hotplug blocks that are plugged and mapped. */
	if (addr >= uml_physmem && l4h_hp_contains(addr - uml_physmem, size))
		return l4h_ram_mapped(addr - uml_physmem, size);
	if (addr >= L4H_SPECIAL_BASE && end <= L4H_SPECIAL_BASE + L4H_BOOTINFO_SIZE)
		return true;
	for (addr &= PAGE_MASK; addr < end; addr += PAGE_SIZE) {
		if (!xa_load(&kernel_as.pages, addr >> PAGE_SHIFT))
			return false;
	}
	return true;
}
EXPORT_SYMBOL(l4h_kernel_range_ok);

/* ---- process VSpaces */

struct vs_slot {
	struct l4h_as as;
	struct mm_struct *owner;	/* NULL if free */
	struct list_head lru;
};

static struct vs_slot *vs_pool;
static int nr_vs;
static LIST_HEAD(vs_lru);		/* owned entries, least recently used first */
static LIST_HEAD(vs_free);
static DEFINE_RAW_SPINLOCK(vs_lock);
static int nr_resetting;		/* detached entries not yet emptied */
static atomic64_t vs_generation = ATOMIC64_INIT(1);

static struct l4h_mm *mm_l4h(struct mm_struct *mm)
{
	return &mm->context.l4h;
}

void l4h_mm_init(struct mm_struct *mm)
{
	struct l4h_mm *m = mm_l4h(mm);

	raw_spin_lock_init(&m->lock);
	m->vs = -1;
	m->gen = 0;
	atomic_set(&m->running, 0);
	m->moved = false;
}

/*
 * Take `s` from its owner.  Must hold vs_lock and the owner's lock.  The
 * entry is then on no list and its mappings are out of everyone's reach:
 * the caller empties it with vs_reset_free(), without vs_lock.
 */
static void vs_detach(struct vs_slot *s)
{
	struct l4h_mm *m = mm_l4h(s->owner);

	atomic_long_sub(s->as.charged, &s->owner->pgtables_bytes);
	s->as.charged = 0;
	m->vs = -1;
	m->gen = 0;
	m->moved = false;
	s->owner = NULL;
	list_del_init(&s->lru);
	nr_resetting++;
}

/*
 * Empty a detached entry and free it.  That is one seL4 delete per mapping
 * and page table, so it runs without vs_lock and with interrupts as the
 * caller has them: every vCPU that returns to user mode takes vs_lock.
 */
static void vs_reset_free(struct vs_slot *s, bool may_sleep)
{
	unsigned long flags;

	as_reset(&s->as, may_sleep);
	raw_spin_lock_irqsave(&vs_lock, flags);
	nr_resetting--;
	list_add(&s->lru, &vs_free);
	raw_spin_unlock_irqrestore(&vs_lock, flags);
}

/*
 * A free pool entry.  Must hold vs_lock.  If there is none, returns NULL
 * and detaches the entry of the least recently activated mm without running
 * threads into *victim, for the caller to empty with vs_reset_free() before
 * it retries; *victim stays NULL if only entries being emptied could be
 * freed.
 */
static struct vs_slot *vs_take(struct vs_slot **victim)
{
	struct vs_slot *it;
	struct l4h_mm *vm;

	*victim = NULL;
	if (!list_empty(&vs_free))
		return list_first_entry(&vs_free, struct vs_slot, lru);
	list_for_each_entry(it, &vs_lru, lru) {
		if (!atomic_read(&mm_l4h(it->owner)->running)) {
			*victim = it;
			break;
		}
	}
	if (!*victim) {
		if (!nr_resetting)
			panic("l4h: all %d process VSpaces are in use by running threads\n", nr_vs);
		return NULL;
	}
	/* vs_detach() clears the owner: unlock the lock we took. */
	vm = mm_l4h((*victim)->owner);
	raw_spin_lock(&vm->lock);
	vs_detach(*victim);
	raw_spin_unlock(&vm->lock);
	return NULL;
}

/*
 * Wait for vs_take() to succeed.  Takes vs_lock, and returns with it held.
 * May sleep: the entries being emptied may belong to tasks that sleep in
 * as_reset(), and need this vCPU to finish.
 */
static struct vs_slot *vs_take_wait(unsigned long *flags)
{
	struct vs_slot *s, *victim;

	for (;;) {
		raw_spin_lock_irqsave(&vs_lock, *flags);
		s = vs_take(&victim);
		if (s)
			return s;
		raw_spin_unlock_irqrestore(&vs_lock, *flags);
		if (victim)
			vs_reset_free(victim, false);
		else
			cond_resched();
	}
}

/*
 * Make sure `mm` has a VSpace and return it (and its generation).  Called
 * before running one of its threads, with the mm marked running so that it
 * is not evicted meanwhile.  Returns 0 if only entries being emptied could
 * be freed: their tasks may sleep in as_reset() (on this vCPU, too), so the
 * caller gives the CPU away and retries.
 */
unsigned long l4h_mm_activate(struct mm_struct *mm, u64 *gen)
{
	struct l4h_mm *m = mm_l4h(mm);
	struct vs_slot *s, *victim;
	unsigned long flags;

	for (;;) {
		raw_spin_lock_irqsave(&vs_lock, flags);
		if (m->vs >= 0) {
			s = &vs_pool[m->vs];
			list_move_tail(&s->lru, &vs_lru);
			goto out;
		}
		s = vs_take(&victim);
		if (s)
			break;
		raw_spin_unlock_irqrestore(&vs_lock, flags);
		if (!victim)
			return 0;
		vs_reset_free(victim, false);
	}
	raw_spin_lock(&m->lock);
	s->owner = mm;
	m->vs = s - vs_pool;
	m->gen = atomic64_inc_return(&vs_generation);
	/* An emptied entry: as_reset() cleared its TLB bitmap. */
	m->moved = false;
	raw_spin_unlock(&m->lock);
	list_move_tail(&s->lru, &vs_lru);
out:
	*gen = m->gen;
	raw_spin_unlock_irqrestore(&vs_lock, flags);
	return s->as.root;
}

void l4h_mm_release(struct mm_struct *mm, bool may_sleep)
{
	struct l4h_mm *m = mm_l4h(mm);
	struct vs_slot *s = NULL;
	unsigned long flags;

	raw_spin_lock_irqsave(&vs_lock, flags);
	if (m->vs >= 0) {
		s = &vs_pool[m->vs];
		raw_spin_lock(&m->lock);
		vs_detach(s);
		raw_spin_unlock(&m->lock);
	}
	raw_spin_unlock_irqrestore(&vs_lock, flags);
	/* The mm's pages are freed after this returns: empty it now. */
	if (s)
		vs_reset_free(s, may_sleep);
}

/*
 * A process VSpace for raw seL4 use, such as the tests of the host's ABI
 * (tests/guest/abitest): out of the pool, and empty, until
 * l4h_vspace_put().  The caller deletes what it mapped there before it
 * gives the VSpace back.
 */
unsigned long l4h_vspace_get(void)
{
	unsigned long flags, root;
	struct vs_slot *s;

	s = vs_take_wait(&flags);
	list_del_init(&s->lru);
	root = s->as.root;
	raw_spin_unlock_irqrestore(&vs_lock, flags);
	return root;
}
EXPORT_SYMBOL_GPL(l4h_vspace_get);

void l4h_vspace_put(unsigned long root)
{
	struct vs_slot *s = &vs_pool[root & ((1ul << L4H_L2_INDEX_BITS) - 1)];
	unsigned long flags;

	raw_spin_lock_irqsave(&vs_lock, flags);
	list_add(&s->lru, &vs_free);
	raw_spin_unlock_irqrestore(&vs_lock, flags);
}
EXPORT_SYMBOL_GPL(l4h_vspace_put);

static struct mm_struct *idp_mm(struct mm_id *mm_idp)
{
	return container_of(mm_idp, struct mm_struct, context.id);
}

/*
 * Before removing or replacing mappings of `m` (its lock held, a VSpace
 * assigned), after one of its threads moved to another vCPU: flush the
 * VSpace.  seL4 keeps every core the VSpace ran on in its TLB bitmap, and
 * each page unmap interrupts them all and waits, holding the kernel lock;
 * only a flush of the whole VSpace drops the cores that are not running
 * it, here the core of the vCPU a thread left (unless another of the
 * mm's threads runs there).  Doing it here rather than at the move costs
 * nothing to processes that move and do not unmap, and once per move to
 * those that do.  The host does the same for every VSpace of the guest
 * when it moves a vCPU between cores.
 */
static void mm_flush_moved(struct l4h_mm *m)
{
	/* Set without the lock by the vCPU the task moved to (uctx.c). */
	if (!READ_ONCE(m->moved))
		return;
	WARN_ON(l4h_vspace_flush(vs_pool[m->vs].as.root));
	m->moved = false;
}

/*
 * Map [virt, virt+len) to physical `phys` with UM_PROT_* `prot`.  For a TLB
 * sync (`from_sync`), a page that cannot be mapped, for lack of seL4 objects
 * or otherwise, is left unmapped (any old mapping of it is removed) and the
 * others are still done: its next access faults, and the fault path waits
 * for memory.  The sync also defers the TLB flush of lowered rights to its
 * end (l4h_mm_flush_deferred()).
 */
static int map_pages(struct mm_id *mm_idp, unsigned long virt, unsigned long len, int prot,
		     unsigned long phys, bool from_sync)
{
	struct mm_struct *mm = idp_mm(mm_idp);
	struct l4h_mm *m = mm_l4h(mm);
	unsigned long flags, off, frame = 0;
	int err = 0;

	if ((prot & L4H_PROT_LARGE) && len == PMD_SIZE && IS_ALIGNED(virt, PMD_SIZE))
		frame = l4h_large_frame(phys);
	prot &= ~L4H_PROT_LARGE;
	raw_spin_lock_irqsave(&m->lock, flags);
	if (m->vs >= 0) {
		struct l4h_as *as = &vs_pool[m->vs].as;

		/* Size changes can remove mappings on the fault path too. */
		if (!prot || from_sync || frame || xa_load(&as->large, virt >> PMD_SHIFT))
			mm_flush_moved(m);
		if (!prot) {
			as_unmap_range(as, virt, virt + len);
		} else if (frame) {
			err = as_map_large(as, virt, phys, prot, frame);
			if (err && from_sync) {
				as_unmap_range(as, virt, virt + len);
				err = 0;
			}
		} else {
			for (off = 0; off < len && !err; off += PAGE_SIZE) {
				err = as_map_page(as, virt + off, phys + off, prot, from_sync);
				if (err && from_sync) {
					/* A failed remap keeps the old rights. */
					as_unmap_range(as, virt + off, virt + off + PAGE_SIZE);
					err = 0;
				}
			}
		}
		as_charge(as, mm);
	}
	raw_spin_unlock_irqrestore(&m->lock, flags);
	return err;
}

/* tlb.c: a TLB sync must apply every unmap in its range, so pages it
 * cannot map do not stop it. */
int map(struct mm_id *mm_idp, unsigned long virt, unsigned long len, int prot, unsigned long phys)
{
	return map_pages(mm_idp, virt, len, prot, phys, true);
}

/* tlb.c: at the end of a sync of `mm`, before anyone relies on it. */
void l4h_mm_flush_deferred(struct mm_struct *mm)
{
	struct l4h_mm *m = mm_l4h(mm);
	unsigned long flags;

	raw_spin_lock_irqsave(&m->lock, flags);
	if (m->vs >= 0 && vs_pool[m->vs].as.flush_pending) {
		struct l4h_as *as = &vs_pool[m->vs].as;

		WARN_ON(l4h_vspace_flush(as->root));
		as->flush_pending = false;
		/* That flush dropped the cores of vCPUs threads left, too. */
		m->moved = false;
	}
	raw_spin_unlock_irqrestore(&m->lock, flags);
}

int unmap(struct mm_id *mm_idp, unsigned long addr, unsigned long len)
{
	struct mm_struct *mm = idp_mm(mm_idp);
	struct l4h_mm *m = mm_l4h(mm);
	unsigned long flags;

	raw_spin_lock_irqsave(&m->lock, flags);
	if (m->vs >= 0) {
		mm_flush_moved(m);
		as_unmap_range(&vs_pool[m->vs].as, addr, addr + len);
		as_charge(&vs_pool[m->vs].as, mm);
	}
	raw_spin_unlock_irqrestore(&m->lock, flags);
	return 0;
}

/*
 * The caller holds the PTE lock.  m->lock keeps the VSpace and frame cap
 * alive against mapping changes and pool eviction.  Clear both bits even
 * if the software one was set: short-circuiting would count an access
 * twice.  This changes no permissions, so needs neither a sync nor a
 * flush.  Atomic bit operations preserve a concurrent sync's NEEDSYNC.
 */
int ptep_test_and_clear_young(struct vm_area_struct *vma, unsigned long addr,
			    pte_t *ptep)
{
	struct l4h_mm *m = mm_l4h(vma->vm_mm);
	unsigned long flags;
	int young = test_and_clear_bit(7, &pte_val(*ptep));
	int accessed = 0;

	raw_spin_lock_irqsave(&m->lock, flags);
	if (m->vs >= 0) {
		void *e = xa_load(&vs_pool[m->vs].as.pages, addr >> PAGE_SHIFT);

		/* A pending sync may still name the old frame. */
		if (e && entry_pfn(e) == pte_pfn(READ_ONCE(*ptep)))
			WARN_ON_ONCE(l4h_page_test_and_clear_accessed(entry_slot(e), &accessed));
	}
	raw_spin_unlock_irqrestore(&m->lock, flags);
	return young | accessed;
}
EXPORT_SYMBOL_GPL(ptep_test_and_clear_young);

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
/* Sample a native large leaf, or all small aliases in the boot-block
 * fallback, including when the software bit was already set.
 * The caller holds the PMD lock; m->lock also excludes VSpace eviction. */
int pmdp_test_and_clear_young(struct vm_area_struct *vma, unsigned long addr,
			    pmd_t *pmdp)
{
	struct l4h_mm *m = mm_l4h(vma->vm_mm);
	unsigned long flags, off, pfn = pmd_pfn(READ_ONCE(*pmdp));
	int young = test_and_clear_bit(7, &pmd_val(*pmdp));

	addr &= PMD_MASK;
	raw_spin_lock_irqsave(&m->lock, flags);
	if (m->vs >= 0) {
		void *large = xa_load(&vs_pool[m->vs].as.large, addr >> PMD_SHIFT);
		int accessed = 0;

		if (large && entry_pfn(large) == pfn) {
			WARN_ON_ONCE(l4h_page_test_and_clear_accessed(entry_slot(large), &accessed));
			young |= accessed;
		}
		for (off = 0; !large && off < PMD_SIZE; off += PAGE_SIZE) {
			void *e = xa_load(&vs_pool[m->vs].as.pages, (addr + off) >> PAGE_SHIFT);
			int accessed = 0;

			if (e && entry_pfn(e) == pfn + (off >> PAGE_SHIFT))
				WARN_ON_ONCE(l4h_page_test_and_clear_accessed(entry_slot(e), &accessed));
			young |= accessed;
		}
	}
	raw_spin_unlock_irqrestore(&m->lock, flags);
	return young;
}
EXPORT_SYMBOL_GPL(pmdp_test_and_clear_young);
#endif

/* Used by the regression module to distinguish hardware large leaves
 * from Linux's software AnonHugePages accounting. */
unsigned long l4h_mm_large_mappings(struct mm_struct *mm, unsigned long start, unsigned long end)
{
	struct l4h_mm *m = mm_l4h(mm);
	unsigned long flags, index, count = 0;
	void *e;

	if (end <= start)
		return 0;
	raw_spin_lock_irqsave(&m->lock, flags);
	if (m->vs >= 0)
		xa_for_each_range(&vs_pool[m->vs].as.large, index, e,
				  start >> PMD_SHIFT, (end - 1) >> PMD_SHIFT)
			count++;
	raw_spin_unlock_irqrestore(&m->lock, flags);
	return count;
}
EXPORT_SYMBOL_GPL(l4h_mm_large_mappings);

static int map_fault_entry(struct mm_struct *mm, unsigned long va,
			   unsigned long len, pte_t entry)
{
	int prot = UM_PROT_READ;

	if (!(pte_val(entry) & _PAGE_PRESENT) || !pte_read(entry))
		return 0;
	if (pte_exec(entry))
		prot |= UM_PROT_EXEC;
	if (pte_write(entry) && pte_dirty(entry))
		prot |= UM_PROT_WRITE;
	if (len == PMD_SIZE)
		prot |= L4H_PROT_LARGE;
	return map_pages(&mm->context.id, va, len, prot, pte_val(entry) & PAGE_MASK, false);
}

/*
 * After a successful page fault, install the leaf for `address` directly,
 * with the protection the TLB sync uses: clean pages are read-only to
 * emulate the dirty bit.  Returns -ENOMEM if there was no memory for the
 * seL4 objects the mapping needs.
 */
int l4h_map_fault(struct mm_struct *mm, unsigned long address)
{
	unsigned long va = address & PAGE_MASK;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	struct vm_area_struct *vma;
	spinlock_t *ptl;
	int err = 0;

	/* handle_page_fault() releases mmap_lock before returning to segv(),
	 * so a concurrent munmap() may be freeing the page tables of `va`.
	 * It frees them under a read lock (after downgrading mmap_lock), but
	 * only once their VMAs are detached, and never the tables a remaining
	 * VMA spans: holding the read lock and finding `va`'s VMA still there
	 * keeps the hierarchy stable while we walk it.  (The PTE lock below
	 * protects only the leaf entry.)
	 */
	mmap_read_lock(mm);
	vma = vma_lookup(mm, va);
	if (!vma)
		goto out_unlock;
	pgd = pgd_offset(mm, va);
	if (!pgd_present(*pgd))
		goto out_unlock;
	p4d = p4d_offset(pgd, va);
	if (!p4d_present(*p4d))
		goto out_unlock;
	pud = pud_offset(p4d, va);
	if (!pud_present(*pud))
		goto out_unlock;
	pmd = pmd_offset(pud, va);
	if (!pmd_present(*pmd))
		goto out_unlock;
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	ptl = pmd_trans_huge_lock(pmd, vma);
	if (ptl) {
		err = map_fault_entry(mm, va & PMD_MASK, PMD_SIZE, __pte(pmd_val(*pmd)));
		spin_unlock(ptl);
		goto out_unlock;
	}
#endif
	/* Hold the PTE lock so that a concurrent unmap on another vCPU cannot
	 * complete (and sync) between reading the PTE and installing it. */
	pte = pte_offset_map_lock(mm, pmd, va, &ptl);
	if (!pte)
		goto out_unlock;
	err = map_fault_entry(mm, va, PAGE_SIZE, *pte);
	pte_unmap_unlock(pte, ptl);
out_unlock:
	mmap_read_unlock(mm);
	return err == -ENOMEM ? err : 0;
}


void __init l4h_vspace_init(void)
{
	int i;

	as_init(&kernel_as, L4H_CPTR(L4H_SLOT_VSPACE));
	nr_vs = l4h_bootinfo->nr_vspaces;
	if (nr_vs < 1)
		panic("l4h: no process VSpaces in boot info\n");
	vs_pool = memblock_alloc(nr_vs * sizeof(*vs_pool), SMP_CACHE_BYTES);
	if (!vs_pool)
		panic("l4h: cannot allocate VSpace pool\n");
	for (i = 0; i < nr_vs; i++) {
		as_init(&vs_pool[i].as, L4H_CPTR2(L4H_SLOT_VSPACE_POOL, i));
		list_add_tail(&vs_pool[i].lru, &vs_free);
	}
}

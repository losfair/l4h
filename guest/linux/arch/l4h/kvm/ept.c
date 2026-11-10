// SPDX-License-Identifier: GPL-2.0
/*
 * The EPT of a VM.
 *
 * KVM keeps its own TDP page table, which the CPU never sees.  What the CPU
 * walks is a seL4 EPT, a cache of the leaves of that table, as process
 * VSpaces cache Linux page tables (kernel/vspace.c).  Every change of a leaf
 * reaches l4h_kvm_spte_changed() (guest/linux/patches), which makes the EPT
 * agree with what the SPTE holds *now*:
 *
 *  - The TDP MMU changes SPTEs under the read side of mmu_lock, and calls
 *    us after the change.  Two threads can come here in any order, but
 *    `lock` serializes them and whichever comes last reads the final value,
 *    so a mapping cannot outlive its SPTE.
 *  - The EPT may hold less than the table: a failed allocation, a table
 *    being replaced, a block the balloon converted (its revocation takes
 *    our frame capabilities with it).  The guest then faults on a page KVM
 *    thinks is mapped, KVM calls it spurious, and calls us again.  That is
 *    the one path that repairs the EPT, and all that is needed.
 *
 * seL4 invalidates the EPT on every core that may hold its translations
 * (those that entered a VM on it since it was last invalidated) whenever it
 * removes a leaf or a table (patch 0039), and adding one needs no
 * invalidation, so KVM's TLB flushes for page table changes have nothing
 * left to do.
 *
 * Every mapping needs its own copy of the frame capability, in a slot we
 * record to delete it again; deleting the copy removes the mapping.
 */
/* compat.h has the one of arch/x86/kvm. */
#undef pr_fmt
#define pr_fmt(fmt) "l4h-kvm: " fmt

#include <linux/kvm_host.h>
#include <linux/slab.h>
#include <linux/xarray.h>
#include <linux/bitmap.h>
#include <linux/mman.h>
#include <linux/sched/mm.h>
#include <l4h_sys.h>
#include "mmu.h"
#include "mmu/mmu_internal.h"
#include "mmu/spte.h"
#include "l4h_kvm.h"

#define PAGES_2M	(1ul << 9)

struct ept_table {
	struct list_head link;
	struct l4h_obj obj;
	int level;
};

static const int table_type[L4H_EPT_LEVELS] = {
	L4H_OBJ_EPT_PT, L4H_OBJ_EPT_PD, L4H_OBJ_EPT_PDPT
};
static const int table_shift[L4H_EPT_LEVELS] = { 21, 30, 39 };

/* The host's roots (abi.h, L4H_SLOT_EPT_POOL). */
static DEFINE_SPINLOCK(pool_lock);
static unsigned long pool_free;

void l4h_ept_pool_init(unsigned int nr)
{
	pool_free = nr >= BITS_PER_LONG ? ~0ul : (1ul << nr) - 1;
}

/* Slot and rights in a value entry. */
static inline void *mk_entry(unsigned long slot, unsigned long pfn, bool writable)
{
	return xa_mk_value((pfn << 31) | ((unsigned long)writable << 30) | slot);
}

static inline unsigned long entry_slot(void *e)
{
	return xa_to_value(e) & ((1ul << 30) - 1);
}

static inline bool entry_writable(void *e)
{
	return xa_to_value(e) & (1ul << 30);
}

static inline unsigned long entry_pfn(void *e)
{
	return xa_to_value(e) >> 31;
}

int l4h_ept_init(struct l4h_ept *e)
{
	int i, bit;

	spin_lock(&pool_lock);
	bit = ffs(pool_free) - 1;
	if (bit >= 0)
		pool_free &= ~(1ul << bit);
	spin_unlock(&pool_lock);
	if (bit < 0)
		return -EBUSY;
	e->root = L4H_CPTR2(L4H_SLOT_EPT_POOL, bit);
	spin_lock_init(&e->lock);
	INIT_LIST_HEAD(&e->tables);
	for (i = 0; i < L4H_EPT_LEVELS; i++)
		xa_init(&e->table_at[i]);
	xa_init(&e->pages);
	xa_init(&e->large);
	return 0;
}

/* Everything goes; the root stays in the pool, empty. */
void l4h_ept_destroy(struct l4h_ept *e)
{
	struct ept_table *t, *n;
	unsigned long i;
	int level;
	void *entry;

	/* Oldest first: a table goes before the tables below it, so the
	 * rest is deleted without a TLB shootdown each. */
	list_for_each_entry_safe_reverse(t, n, &e->tables, link) {
		list_del(&t->link);
		l4h_obj_free(&t->obj);
		kfree(t);
	}
	for (level = 0; level < L4H_EPT_LEVELS; level++)
		xa_destroy(&e->table_at[level]);
	xa_for_each(&e->large, i, entry)
		l4h_slot_delete(entry_slot(entry));
	xa_destroy(&e->large);
	xa_for_each(&e->pages, i, entry) {
		l4h_slot_delete(entry_slot(entry));
		cond_resched();
	}
	xa_destroy(&e->pages);

	spin_lock(&pool_lock);
	pool_free |= 1ul << (((e->root) & ((1ul << L4H_L2_INDEX_BITS) - 1)));
	spin_unlock(&pool_lock);
}

static int add_table(struct l4h_ept *e, int level, unsigned long gpa)
{
	unsigned long index = gpa >> table_shift[level];
	struct ept_table *t;
	int err;

	if (level >= L4H_EPT_LEVELS)
		return -EFAULT;
	/* Reserved, so that storing it cannot fail. */
	err = xa_reserve(&e->table_at[level], index, GFP_ATOMIC);
	if (err)
		return err;
	t = kzalloc(sizeof(*t), GFP_ATOMIC);
	if (!t) {
		err = -ENOMEM;
		goto release;
	}
	err = l4h_obj_alloc(table_type[level], 0, &t->obj);
	if (err) {
		kfree(t);
		goto release;
	}
	for (;;) {
		err = l4h_ept_map_table(level, t->obj.cptr, e->root, gpa);
		if (err != L4H_ERR_FAILED_LOOKUP)
			break;
		err = add_table(e, level + 1, gpa);
		if (err)
			break;
	}
	if (err) {
		l4h_obj_free(&t->obj);
		kfree(t);
		err = err < 0 ? err : -EFAULT;
		goto release;
	}
	t->level = level;
	list_add(&t->link, &e->tables);
	xa_store(&e->table_at[level], index, t, GFP_ATOMIC);
	return 0;
release:
	xa_release(&e->table_at[level], index);
	return err;
}

static void unmap_small(struct l4h_ept *e, unsigned long gfn)
{
	void *entry = xa_erase(&e->pages, gfn);

	if (entry)
		l4h_slot_delete(entry_slot(entry));
}

static void unmap_large(struct l4h_ept *e, unsigned long gfn)
{
	void *entry = xa_erase(&e->large, gfn >> 9);

	if (entry)
		l4h_slot_delete(entry_slot(entry));
}

static void unmap_range_2m(struct l4h_ept *e, unsigned long gfn)
{
	unsigned long i;
	void *entry;

	unmap_large(e, gfn);
	xa_for_each_range(&e->pages, i, entry, gfn, gfn + PAGES_2M - 1) {
		xa_erase(&e->pages, i);
		l4h_slot_delete(entry_slot(entry));
	}
}

static int map_small(struct l4h_ept *e, unsigned long gfn, unsigned long pfn, bool writable)
{
	void *entry = xa_load(&e->pages, gfn);
	unsigned long gpa = gfn << PAGE_SHIFT, slot;
	int err;

	if (entry) {
		if (entry_pfn(entry) == pfn && entry_writable(entry) == writable)
			return 0;
		unmap_small(e, gfn);
	}
	unmap_large(e, gfn & ~(PAGES_2M - 1));
	slot = l4h_cap_copy(L4H_FRAME_CPTR(pfn << PAGE_SHIFT), L4H_RIGHTS_ALL);
	if (!slot)
		return -ENOMEM;
	for (;;) {
		err = l4h_ept_map_frame(slot, e->root, gpa, writable);
		if (err != L4H_ERR_FAILED_LOOKUP)
			break;
		err = add_table(e, 0, gpa);
		if (err)
			break;
	}
	if (!err)
		err = xa_err(xa_store(&e->pages, gfn, mk_entry(slot, pfn, writable), GFP_ATOMIC));
	if (err) {
		l4h_slot_delete(slot);
		return err < 0 ? err : -EFAULT;
	}
	return 0;
}

/* A 2 MiB SPTE.  Without a large frame (boot-image blocks), 512 small ones. */
static int map_large(struct l4h_ept *e, unsigned long gfn, unsigned long pfn, bool writable)
{
	unsigned long gpa = gfn << PAGE_SHIFT, frame = l4h_large_frame(pfn << PAGE_SHIFT);
	unsigned long index = gfn >> 9, slot, i;
	struct ept_table *t;
	void *entry;
	int err;

	if (!frame) {
		for (i = 0; i < PAGES_2M; i++) {
			err = map_small(e, gfn + i, pfn + i, writable);
			if (err)
				return err;
		}
		return 0;
	}
	entry = xa_load(&e->large, index);
	if (entry && entry_pfn(entry) == pfn && entry_writable(entry) == writable)
		return 0;
	unmap_range_2m(e, gfn);
	/* seL4 refuses a leaf while a page table is there. */
	t = xa_erase(&e->table_at[0], gpa >> table_shift[0]);
	if (t) {
		list_del(&t->link);
		l4h_obj_free(&t->obj);
		kfree(t);
	}
	slot = l4h_cap_copy(frame, L4H_RIGHTS_ALL);
	if (!slot)
		return -ENOMEM;
	for (;;) {
		err = l4h_ept_map_frame(slot, e->root, gpa, writable);
		if (err != L4H_ERR_FAILED_LOOKUP)
			break;
		err = add_table(e, 1, gpa);
		if (err)
			break;
	}
	if (!err)
		err = xa_err(xa_store(&e->large, index, mk_entry(slot, pfn, writable), GFP_ATOMIC));
	if (err) {
		l4h_slot_delete(slot);
		return err < 0 ? err : -EFAULT;
	}
	return 0;
}

static void sync_leaf(struct l4h_ept *e, u64 spte, unsigned long gfn, int level)
{
	bool leaf = is_shadow_present_pte(spte) && is_last_spte(spte, level) &&
		    !is_access_track_spte(spte);
	int err = 0;

	if (level == PG_LEVEL_2M) {
		if (leaf)
			err = map_large(e, gfn, spte_to_pfn(spte), is_writable_pte(spte));
		else
			unmap_range_2m(e, gfn);
	} else if (leaf) {
		err = map_small(e, gfn, spte_to_pfn(spte), is_writable_pte(spte));
	} else {
		unmap_small(e, gfn);
	}
	/* The guest faults on it, which brings it back here. */
	if (err)
		pr_warn_ratelimited("no EPT mapping of gfn %lx: %d\n", gfn, err);
}

/*
 * Guest RAM wants 2 MiB EPT leaves, which need THP behind the memslot.  The
 * guest kernel's THP is "madvise" (DESIGN.md §5.3), and not every VMM asks
 * for it as QEMU does: Firecracker's guests took 2.5 times as long to boot.
 * So the memslot asks, for the mappings whose owner has not said no
 * (MADV_NOHUGEPAGE).  Memory that cannot have THP stays as it is.
 */
void l4h_kvm_memslot_prepare(struct kvm *kvm, struct kvm_memory_slot *slot)
{
	unsigned long start = slot->userspace_addr, end = start + (slot->npages << PAGE_SHIFT);
	struct mm_struct *mm = current->mm;
	struct { unsigned long start, end; } ranges[8];
	VMA_ITERATOR(vmi, mm, start);
	struct vm_area_struct *vma;
	int i, n = 0;

	if (mm != kvm->mm || (slot->flags & KVM_MEM_GUEST_MEMFD))
		return;
	mmap_read_lock(mm);
	for_each_vma_range(vmi, vma, end) {
		if (vma->vm_flags & (VM_HUGEPAGE | VM_NOHUGEPAGE))
			continue;
		if (n == ARRAY_SIZE(ranges))
			break;
		ranges[n].start = max(vma->vm_start, start);
		ranges[n].end = min(vma->vm_end, end);
		n++;
	}
	mmap_read_unlock(mm);
	for (i = 0; i < n; i++)
		do_madvise(mm, ranges[i].start, ranges[i].end - ranges[i].start, MADV_HUGEPAGE);
}

void l4h_kvm_spte_changed(struct kvm *kvm, u64 *sptep, u64 gfn, int level)
{
	struct l4h_ept *e = to_ept(kvm);
	u64 spte;
	int i;

	if (WARN_ON_ONCE(level > PG_LEVEL_2M))
		return;
	spin_lock(&e->lock);
	spte = READ_ONCE(*sptep);
	sync_leaf(e, spte, gfn, level);
	/* A large page split: the 512 SPTEs below it are filled in already. */
	if (level == PG_LEVEL_2M && is_shadow_present_pte(spte) && !is_last_spte(spte, level)) {
		u64 *child = spte_to_child_sp(spte)->spt;

		for (i = 0; i < SPTE_ENT_PER_PAGE; i++)
			sync_leaf(e, READ_ONCE(child[i]), gfn + i, PG_LEVEL_4K);
	}
	spin_unlock(&e->lock);
}

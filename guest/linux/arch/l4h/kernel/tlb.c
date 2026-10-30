// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2000 - 2007 Jeff Dike (jdike@{addtoit,linux.intel}.com)
 */

#include <linux/mm.h>
#include <linux/module.h>
#include <linux/sched/signal.h>

#include <asm/tlbflush.h>
#include <asm/mmu_context.h>
#include <as-layout.h>
#include <mem_user.h>
#include <os.h>
#include <skas.h>
#include <kern_util.h>
#include <l4h_vspace.h>
#include <l4h_caps.h>
#include <l4h_sys.h>

struct vm_ops {
	struct mm_id *mm_idp;

	int (*mmap)(struct mm_id *mm_idp,
		    unsigned long virt, unsigned long len, int prot,
		    unsigned long phys);
	int (*unmap)(struct mm_id *mm_idp,
		     unsigned long virt, unsigned long len);
	/* Kernel syncs: a map ran out of seL4 objects (see um_tlb_sync()). */
	bool enomem;
};

static int kern_map(struct mm_id *mm_idp,
		    unsigned long virt, unsigned long len, int prot,
		    unsigned long phys)
{
	return os_map_memory((void *)virt, phys, len,
			     prot & UM_PROT_READ, prot & UM_PROT_WRITE, 1);
}

static int kern_unmap(struct mm_id *mm_idp,
		      unsigned long virt, unsigned long len)
{
	return os_unmap_memory((void *)virt, len);
}

static int sync_one_pte(pte_t *pte, unsigned long addr, struct vm_ops *ops)
{
	for (;;) {
		pte_t v = READ_ONCE(*pte);
		int ret;

		if (!pte_needsync(v))
			return 0;

		if (pte_present(v)) {
			unsigned long phys = pte_val(v) & PAGE_MASK;
			int r, w, x, prot;

			r = pte_read(v);
			w = pte_write(v);
			x = pte_exec(v);
			/* Accesses are tracked in seL4's page tables.  Clean pages
			 * stay read-only so the first write marks them dirty. */
			if (!pte_dirty(v))
				w = 0;

			prot = (r ? UM_PROT_READ : 0) |
			       (w ? UM_PROT_WRITE : 0) |
			       (x ? UM_PROT_EXEC : 0);

			ret = ops->mmap(ops->mm_idp, addr, PAGE_SIZE, prot, phys);
			if (ret == -ENOMEM && ops->mmap == kern_map) {
				/* Left to sync again; the walk goes on, since
				 * its unmaps must all happen. */
				ops->enomem = true;
				return 0;
			}
		} else
			ret = ops->unmap(ops->mm_idp, addr, PAGE_SIZE);
		if (ret)
			return ret;
		/* Only mark the PTE synced if nobody changed it meanwhile;
		 * otherwise apply the new value too. */
		if (try_cmpxchg(&pte_val(*pte), &pte_val(v), pte_val(pte_mkuptodate(v))))
			return 0;
	}
}

/*
 * The walk runs without mmap_lock: munmap's free_pgtables() may clear an
 * entry meanwhile (its tables are freed only after the flush, which waits
 * for this walk).  Each entry is read once, and the table below it found
 * from that value: a second read could find it cleared, and the walk
 * would go on in the kernel's memory at __va(0).
 */
static inline int update_pte_range(pmd_t pmdv, unsigned long addr,
				   unsigned long end,
				   struct vm_ops *ops)
{
	pte_t *pte;
	int ret = 0;

	pte = (pte_t *)pmd_page_vaddr(pmdv) + pte_index(addr);
	do {
		ret = sync_one_pte(pte, addr, ops);
	} while (pte++, addr += PAGE_SIZE, ((addr < end) && !ret));
	return ret;
}

static int sync_one_pmd(pmd_t *pmd, unsigned long addr, unsigned long end,
			struct vm_ops *ops)
{
	for (;;) {
		pmd_t v = READ_ONCE(*pmd);
		int ret;

		if (pmd_trans_huge(v)) {
			pte_t leaf = __pte(pmd_val(v));
			int prot = 0;

			if (!pmd_needsync(v))
				return 0;
			/* NEEDSYNC describes the whole leaf, even when the flush
			 * covers only part of it.  Retry this whole range if the
			 * PMD changes to a PTE table while we map it. */
			addr &= PMD_MASK;
			end = addr + PMD_SIZE;
			/* pmd_present() also accepts the temporarily invalid leaf
			 * used by splitting.  It must have no seL4 mappings. */
			if (pmd_val(v) & _PAGE_PRESENT) {
				if (pte_read(leaf))
					prot |= UM_PROT_READ;
				if (pte_write(leaf) && pte_dirty(leaf))
					prot |= UM_PROT_WRITE;
				if (pte_exec(leaf))
					prot |= UM_PROT_EXEC;
			}
			if (prot)
				ret = ops->mmap(ops->mm_idp, addr, PMD_SIZE, prot | L4H_PROT_LARGE,
						pmd_val(v) & PAGE_MASK);
			else
				ret = ops->unmap(ops->mm_idp, addr, PMD_SIZE);
		} else if (!pmd_present(v)) {
			if (!pmd_needsync(v))
				return 0;
			ret = ops->unmap(ops->mm_idp, addr, end - addr);
		} else {
			return update_pte_range(v, addr, end, ops);
		}
		if (ret)
			return ret;
		/* As for PTEs, do not acknowledge a concurrent replacement.
		 * In particular, a split/collapse flush must wait until every
		 * old base-page mapping is gone before it can free memory. */
		if (try_cmpxchg(&pmd_val(*pmd), &pmd_val(v), pmd_val(v) & ~_PAGE_NEEDSYNC))
			return 0;
	}
}

static inline int update_pmd_range(pud_t pudv, unsigned long addr,
				   unsigned long end,
				   struct vm_ops *ops)
{
	pmd_t *pmd;
	unsigned long next;
	int ret = 0;

	pmd = pud_pgtable(pudv) + pmd_index(addr);
	do {
		next = pmd_addr_end(addr, end);
		ret = sync_one_pmd(pmd, addr, next, ops);
	} while (pmd++, addr = next, ((addr < end) && !ret));
	return ret;
}

static inline int update_pud_range(p4d_t p4dv, unsigned long addr,
				   unsigned long end,
				   struct vm_ops *ops)
{
	pud_t *pud;
	unsigned long next;
	int ret = 0;

	pud = p4d_pgtable(p4dv) + pud_index(addr);
	do {
		pud_t v = READ_ONCE(*pud);

		next = pud_addr_end(addr, end);
		if (!pud_present(v)) {
			if (pud_needsync(v)) {
				ret = ops->unmap(ops->mm_idp, addr,
						 next - addr);
				pud_mkuptodate(*pud);
			}
		}
		else ret = update_pmd_range(v, addr, next, ops);
	} while (pud++, addr = next, ((addr < end) && !ret));
	return ret;
}

static inline int update_p4d_range(pgd_t *pgd, unsigned long addr,
				   unsigned long end,
				   struct vm_ops *ops)
{
	p4d_t *p4d;
	unsigned long next;
	int ret = 0;

	p4d = p4d_offset(pgd, addr);
	do {
		p4d_t v = READ_ONCE(*p4d);

		next = p4d_addr_end(addr, end);
		if (!p4d_present(v)) {
			if (p4d_needsync(v)) {
				ret = ops->unmap(ops->mm_idp, addr,
						 next - addr);
				p4d_mkuptodate(*p4d);
			}
		} else
			ret = update_pud_range(v, addr, next, ops);
	} while (p4d++, addr = next, ((addr < end) && !ret));
	return ret;
}

/*
 * Apply the pending range of `mm` to its seL4 address space.
 *
 * Every vCPU syncs current->mm before returning to user, so the range a
 * flush has just marked may be taken by another vCPU's sync.  The flush
 * must not return before that sync is complete: its caller goes on to free
 * the pages (or page tables), and a thread of the mm on a third vCPU could
 * still write to them through the old mapping.  Two concurrent syncs would
 * also race on a PTE: one maps the value it read, after the other has
 * unmapped the newer value and marked it synced.  Syncs of an mm therefore
 * hold sync_walk_lock from taking the range until it is applied.
 *
 * Callers include flushes under a PTE lock, so this must not sleep.  Kernel
 * syncs are rare and short and also keep interrupts off; user syncs may be
 * long and leave them on (no interrupt handler syncs a user mm).
 *
 * User maps that find no memory for seL4 objects are dropped: the page
 * faults again.  Kernel maps cannot be: a fault of the guest kernel stops
 * the guest.  Their PTEs stay unsynced, the range is marked again, and the
 * sync returns -ENOMEM for l4h_kernel_map_sync() to retry.
 */
int um_tlb_sync(struct mm_struct *mm)
{
	pgd_t *pgd;
	struct vm_ops ops = {};
	unsigned long start, addr, end, next, flags, wflags = 0;
	int ret = 0;

	if (mm == &init_mm)
		raw_spin_lock_irqsave(&mm->context.sync_walk_lock, wflags);
	else
		raw_spin_lock(&mm->context.sync_walk_lock);

	/* Take the pending range; marks made from now on go to the next sync. */
	raw_spin_lock_irqsave(&mm->context.sync_lock, flags);
	addr = mm->context.sync_tlb_range_from;
	end = mm->context.sync_tlb_range_to;
	mm->context.sync_tlb_range_from = 0;
	mm->context.sync_tlb_range_to = 0;
	raw_spin_unlock_irqrestore(&mm->context.sync_lock, flags);
	if (end == 0)
		goto out;
	start = addr;

	ops.mm_idp = &mm->context.id;
	if (mm == &init_mm) {
		ops.mmap = kern_map;
		ops.unmap = kern_unmap;
	} else {
		ops.mmap = map;
		ops.unmap = unmap;
	}

	pgd = pgd_offset(mm, addr);
	do {
		next = pgd_addr_end(addr, end);
		if (!pgd_present(*pgd)) {
			if (pgd_needsync(*pgd)) {
				ret = ops.unmap(ops.mm_idp, addr,
						next - addr);
				pgd_mkuptodate(*pgd);
			}
		} else
			ret = update_p4d_range(pgd, addr, next, &ops);
	} while (pgd++, addr = next, ((addr < end) && !ret));
	if (mm != &init_mm)
		l4h_mm_flush_deferred(mm);
	if (ops.enomem) {
		um_tlb_mark_sync(mm, start, end);
		if (!ret)
			ret = -ENOMEM;
	}

out:
	if (mm == &init_mm)
		raw_spin_unlock_irqrestore(&mm->context.sync_walk_lock, wflags);
	else
		raw_spin_unlock(&mm->context.sync_walk_lock);

	return ret;
}

/*
 * A kernel map found no memory.  It may have lacked seL4 objects or an
 * atomic allocation (a slot CNode, the mapping's xarray node): make room
 * for both, and sleep, so that the retry neither spins with the vCPU taken
 * nor waits for memory nobody frees.
 */
static void kernel_map_wait(void)
{
	unsigned long page;

	if (!l4h_objmem_wait())
		l4h_objmem_oom();
	/* Reclaims, or calls the OOM killer, below the watermarks. */
	page = __get_free_page(GFP_KERNEL | __GFP_NOWARN);
	if (page)
		free_page(page);
	schedule_timeout_uninterruptible(1);
}

/*
 * Make new kernel mappings (vmap, vmalloc, percpu) reachable before the
 * caller uses them.  Every caller may sleep: wait for memory and retry, as
 * the page fault path does.
 */
void l4h_kernel_map_sync(unsigned long start, unsigned long end)
{
	um_tlb_mark_sync(&init_mm, start, end);
	while (um_tlb_sync(&init_mm) == -ENOMEM)
		kernel_map_wait();
}

void flush_tlb_all(void)
{
	/*
	 * Don't bother flushing if this address space is about to be
	 * destroyed.
	 */
	if (atomic_read(&current->mm->mm_users) == 0)
		return;

	flush_tlb_mm(current->mm);
}

void flush_tlb_mm(struct mm_struct *mm)
{
	/*
	 * All of user space, not the VMAs: when mmu_gathers nest (munmap
	 * against MADV_DONTNEED), tlb_finish_mmu() ends with this full flush
	 * after munmap took its VMAs out of the tree, and the PTEs it cleared
	 * must still be synced before their pages are freed.  The mm may also
	 * not be ours to walk (unmap_mapping_range() holds no mmap_lock).  The
	 * walk skips empty upper levels.
	 */
	um_tlb_mark_sync(mm, 0, TASK_SIZE);
	l4h_tlb_flush_sync(mm);
}

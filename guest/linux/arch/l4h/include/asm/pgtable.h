/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2000 - 2007 Jeff Dike (jdike@{addtoit,linux.intel}.com)
 * Copyright 2003 PathScale, Inc.
 * Derived from include/asm-i386/pgtable.h
 */

#ifndef __UM_PGTABLE_H
#define __UM_PGTABLE_H

#include <asm/page.h>
#include <linux/mm_types.h>

#define _PAGE_PRESENT	0x001
#define _PAGE_NEEDSYNC	0x002
#define _PAGE_EXEC	0x004	/* user code may execute from the page */
#define _PAGE_RW	0x020
#define _PAGE_USER	0x040
#define _PAGE_ACCESSED	0x080
#define _PAGE_DIRTY	0x100
#define _PAGE_HUGE	0x200	/* a software PMD leaf; seL4 still maps 4 KiB */
/* If _PAGE_PRESENT is clear, we use these: */
#define _PAGE_PROTNONE	0x010	/* if the user mapped it with PROT_NONE;
				   pte_present gives true */

/* We borrow bit 10 to store the exclusive marker in swap PTEs. */
#define _PAGE_SWP_EXCLUSIVE	0x400

#if CONFIG_PGTABLE_LEVELS == 4
#include <asm/pgtable-4level.h>
#elif CONFIG_PGTABLE_LEVELS == 2
#include <asm/pgtable-2level.h>
#else
#error "Unsupported number of page table levels"
#endif

extern pgd_t swapper_pg_dir[PTRS_PER_PGD];

/* zero page used for uninitialized stuff */
extern unsigned long *empty_zero_page;

/* Just any arbitrary offset to the start of the vmalloc VM area: the
 * current 8MB value just means that there will be a 8MB "hole" after the
 * physical memory until the kernel virtual memory starts.  That means that
 * any out-of-bounds memory accesses will hopefully be caught.
 * The vmalloc() routines leaves a hole of 4kB between each vmalloced
 * area for the same reason. ;)
 */

extern unsigned long end_iomem;

#define VMALLOC_OFFSET	(__va_space)
#define VMALLOC_START ((end_iomem + VMALLOC_OFFSET) & ~(VMALLOC_OFFSET-1))
/* Keep kernel allocations below the last PGD slot, which contains the
 * host-provided special pages, independently of the process limit.  The
 * vmemmap (the struct pages of all of guest-physical space, populated
 * where there is memory) is just below it, then vmalloc. */
#define VMEMMAP_SIZE	(2UL << 30)
#define VMEMMAP_START	(0x00007f8000000000UL - VMEMMAP_SIZE)
#define vmemmap		((struct page *)VMEMMAP_START)
#define VMALLOC_END	(VMEMMAP_START - 2*PAGE_SIZE)
#define MODULES_VADDR	VMALLOC_START
#define MODULES_END	VMALLOC_END

#define _PAGE_TABLE	(_PAGE_PRESENT | _PAGE_RW | _PAGE_USER | _PAGE_ACCESSED | _PAGE_DIRTY)
#define _KERNPG_TABLE	(_PAGE_PRESENT | _PAGE_RW | _PAGE_ACCESSED | _PAGE_DIRTY)
#define _PAGE_CHG_MASK	(PAGE_MASK | _PAGE_ACCESSED | _PAGE_DIRTY)
#define __PAGE_KERNEL_EXEC                                              \
	 (_PAGE_PRESENT | _PAGE_RW | _PAGE_DIRTY | _PAGE_ACCESSED)
#define PAGE_NONE	__pgprot(_PAGE_PROTNONE | _PAGE_ACCESSED)
#define PAGE_SHARED	__pgprot(_PAGE_PRESENT | _PAGE_RW | _PAGE_USER | _PAGE_ACCESSED)
#define PAGE_COPY	__pgprot(_PAGE_PRESENT | _PAGE_USER | _PAGE_ACCESSED)
#define PAGE_READONLY	__pgprot(_PAGE_PRESENT | _PAGE_USER | _PAGE_ACCESSED)
#define PAGE_SHARED_EXEC	__pgprot(_PAGE_PRESENT | _PAGE_RW | _PAGE_USER | _PAGE_ACCESSED | _PAGE_EXEC)
#define PAGE_COPY_EXEC		__pgprot(_PAGE_PRESENT | _PAGE_USER | _PAGE_ACCESSED | _PAGE_EXEC)
#define PAGE_READONLY_EXEC	__pgprot(_PAGE_PRESENT | _PAGE_USER | _PAGE_ACCESSED | _PAGE_EXEC)
#define PAGE_KERNEL	__pgprot(_PAGE_PRESENT | _PAGE_RW | _PAGE_DIRTY | _PAGE_ACCESSED)
#define PAGE_KERNEL_EXEC	__pgprot(__PAGE_KERNEL_EXEC)

/*
 * The i386 can't do page protection for execute, and considers that the same
 * are read.
 * Also, write permissions imply read permissions. This is the closest we can
 * get..
 */

/*
 * ZERO_PAGE is a global shared page that is always zero: used
 * for zero-mapped memory areas etc..
 */
#define ZERO_PAGE(vaddr) virt_to_page(empty_zero_page)

#define pte_clear(mm, addr, xp) pte_set_val(*(xp), (phys_t) 0, __pgprot(_PAGE_NEEDSYNC))

#define pmd_none(x)	(!((unsigned long)pmd_val(x) & ~_PAGE_NEEDSYNC))
#define	pmd_bad(x)	((pmd_val(x) & (~PAGE_MASK & ~(_PAGE_USER | _PAGE_NEEDSYNC))) != _KERNPG_TABLE)

/* An invalidated huge PMD remains a leaf while split_huge_pmd() fills PTEs. */
#define pmd_present(x)	(pmd_val(x) & (_PAGE_PRESENT | _PAGE_PROTNONE | _PAGE_HUGE))
#define pmd_clear(xp)	do { WRITE_ONCE(pmd_val(*(xp)), _PAGE_NEEDSYNC); } while (0)

#define pmd_needsync(x)   (pmd_val(x) & _PAGE_NEEDSYNC)
/* Atomic: other vCPUs may update the entry concurrently (bit 1 == _PAGE_NEEDSYNC). */
#define pmd_mkuptodate(x) clear_bit(1, (unsigned long *)&pmd_val(x))

#define pud_needsync(x)   (pud_val(x) & _PAGE_NEEDSYNC)
#define pud_mkuptodate(x) clear_bit(1, (unsigned long *)&pud_val(x))

#define p4d_needsync(x)   (p4d_val(x) & _PAGE_NEEDSYNC)
#define p4d_mkuptodate(x) clear_bit(1, (unsigned long *)&p4d_val(x))

#define pmd_pfn(pmd) (pmd_val(pmd) >> PAGE_SHIFT)
#define pmd_page(pmd) phys_to_page(pmd_val(pmd) & PAGE_MASK)

#define pte_page(x) pfn_to_page(pte_pfn(x))

#define pte_present(x)	pte_get_bits(x, (_PAGE_PRESENT | _PAGE_PROTNONE))

/*
 * =================================
 * Flags checking section.
 * =================================
 */

static inline int pte_none(pte_t pte)
{
	return pte_is_zero(pte);
}

/*
 * The following only work if pte_present() is true.
 * Undefined behaviour if not..
 */
static inline int pte_read(pte_t pte)
{
	return((pte_get_bits(pte, _PAGE_USER)) &&
	       !(pte_get_bits(pte, _PAGE_PROTNONE)));
}

static inline int pte_exec(pte_t pte){
	return((pte_get_bits(pte, _PAGE_EXEC)) &&
	       !(pte_get_bits(pte, _PAGE_PROTNONE)));
}

static inline int pte_write(pte_t pte)
{
	return((pte_get_bits(pte, _PAGE_RW)) &&
	       !(pte_get_bits(pte, _PAGE_PROTNONE)));
}

static inline int pte_dirty(pte_t pte)
{
	return pte_get_bits(pte, _PAGE_DIRTY);
}

static inline int pte_young(pte_t pte)
{
	return pte_get_bits(pte, _PAGE_ACCESSED);
}

#define __HAVE_ARCH_PTEP_TEST_AND_CLEAR_YOUNG
int ptep_test_and_clear_young(struct vm_area_struct *vma, unsigned long addr,
			    pte_t *ptep);

/* Aging needs no TLB flush; cached translations may delay the next sample. */
#define __HAVE_ARCH_PTEP_CLEAR_YOUNG_FLUSH
#define ptep_clear_flush_young ptep_test_and_clear_young

static inline int pte_needsync(pte_t pte)
{
	return pte_get_bits(pte, _PAGE_NEEDSYNC);
}

/*
 * =================================
 * Flags setting section.
 * =================================
 */

static inline pte_t pte_mkclean(pte_t pte)
{
	pte_clear_bits(pte, _PAGE_DIRTY);
	return(pte);
}

static inline pte_t pte_mkold(pte_t pte)
{
	pte_clear_bits(pte, _PAGE_ACCESSED);
	return(pte);
}

static inline pte_t pte_wrprotect(pte_t pte)
{
	pte_clear_bits(pte, _PAGE_RW);
	return pte;
}

static inline pte_t pte_mkread(pte_t pte)
{
	pte_set_bits(pte, _PAGE_USER);
	return pte;
}

static inline pte_t pte_mkdirty(pte_t pte)
{
	pte_set_bits(pte, _PAGE_DIRTY);
	return(pte);
}

static inline pte_t pte_mkyoung(pte_t pte)
{
	pte_set_bits(pte, _PAGE_ACCESSED);
	return(pte);
}

static inline pte_t pte_mkwrite_novma(pte_t pte)
{
	pte_set_bits(pte, _PAGE_RW);
	return pte;
}

static inline pte_t pte_mkuptodate(pte_t pte)
{
	pte_clear_bits(pte, _PAGE_NEEDSYNC);
	return pte;
}

static inline pte_t pte_mkneedsync(pte_t pte)
{
	pte_set_bits(pte, _PAGE_NEEDSYNC);
	return(pte);
}

static inline void set_pte(pte_t *pteptr, pte_t pteval)
{
	pte_copy(*pteptr, pteval);

	/* If it's a swap entry, it needs to be marked _PAGE_NEEDSYNC so
	 * update_pte_range knows to unmap it.
	 */

	*pteptr = pte_mkneedsync(*pteptr);
}

#define PFN_PTE_SHIFT		PAGE_SHIFT

static inline void um_tlb_mark_sync(struct mm_struct *mm, unsigned long start,
				    unsigned long end)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&mm->context.sync_lock, flags);
	if (!mm->context.sync_tlb_range_to) {
		mm->context.sync_tlb_range_from = start;
		mm->context.sync_tlb_range_to = end;
	} else {
		if (start < mm->context.sync_tlb_range_from)
			mm->context.sync_tlb_range_from = start;
		if (end > mm->context.sync_tlb_range_to)
			mm->context.sync_tlb_range_to = end;
	}
	raw_spin_unlock_irqrestore(&mm->context.sync_lock, flags);
}

#define set_ptes set_ptes
static inline void set_ptes(struct mm_struct *mm, unsigned long addr,
			    pte_t *ptep, pte_t pte, int nr)
{
	/* Basically the default implementation */
	size_t length = nr * PAGE_SIZE;

	for (;;) {
		set_pte(ptep, pte);
		if (--nr == 0)
			break;
		ptep++;
		/* Consecutive pages: one PFN further for every entry. */
		pte = __pte(pte_val(pte) + (1UL << PFN_PTE_SHIFT));
	}

	um_tlb_mark_sync(mm, addr, addr + length);
}

#define __HAVE_ARCH_PTE_SAME
static inline int pte_same(pte_t pte_a, pte_t pte_b)
{
	return !((pte_val(pte_a) ^ pte_val(pte_b)) & ~_PAGE_NEEDSYNC);
}

#define __virt_to_page(virt) phys_to_page(__pa(virt))
#define virt_to_page(addr) __virt_to_page((const unsigned long) addr)

static inline pte_t pfn_pte(unsigned long pfn, pgprot_t pgprot)
{
	pte_t pte;

	pte_set_val(pte, pfn_to_phys(pfn), pgprot);

	return pte;
}

static inline pte_t pte_modify(pte_t pte, pgprot_t newprot)
{
	pte_set_val(pte, (pte_val(pte) & _PAGE_CHG_MASK), newprot);
	return pte;
}

/* Linux's THP page tables are software-only.  The TLB sync expands each
 * huge leaf into base-page mappings, including permission downgrades. */
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
static inline int pmd_trans_huge(pmd_t pmd)
{
	return !!(pmd_val(pmd) & _PAGE_HUGE);
}

#define pmd_leaf pmd_trans_huge
#define pmd_write(pmd) pte_write(__pte(pmd_val(pmd)))
#define pmd_dirty(pmd) pte_dirty(__pte(pmd_val(pmd)))
#define pmd_young(pmd) pte_young(__pte(pmd_val(pmd)))

static inline pmd_t pmd_mkhuge(pmd_t pmd)
{
	return __pmd(pmd_val(pmd) | _PAGE_HUGE);
}

static inline pmd_t pmd_mkinvalid(pmd_t pmd)
{
	return __pmd(pmd_val(pmd) & ~(_PAGE_PRESENT | _PAGE_PROTNONE));
}

static inline pmd_t pmd_modify(pmd_t pmd, pgprot_t prot)
{
	return __pmd((pmd_val(pmd) & (_PAGE_CHG_MASK | _PAGE_HUGE)) | pgprot_val(prot));
}

#define pmd_mkold(pmd) __pmd(pte_val(pte_mkold(__pte(pmd_val(pmd)))))
#define pmd_mkyoung(pmd) __pmd(pte_val(pte_mkyoung(__pte(pmd_val(pmd)))))
#define pmd_mkclean(pmd) __pmd(pte_val(pte_mkclean(__pte(pmd_val(pmd)))))
#define pmd_mkdirty(pmd) __pmd(pte_val(pte_mkdirty(__pte(pmd_val(pmd)))))
#define pmd_wrprotect(pmd) __pmd(pte_val(pte_wrprotect(__pte(pmd_val(pmd)))))
#define pmd_mkwrite_novma(pmd) __pmd(pte_val(pte_mkwrite_novma(__pte(pmd_val(pmd)))))

#define __HAVE_ARCH_PMD_SAME
static inline int pmd_same(pmd_t a, pmd_t b)
{
	return !((pmd_val(a) ^ pmd_val(b)) & ~_PAGE_NEEDSYNC);
}

static inline void set_pmd_at(struct mm_struct *mm, unsigned long addr,
			      pmd_t *pmdp, pmd_t pmd)
{
	WRITE_ONCE(pmd_val(*pmdp), pmd_val(pmd) | _PAGE_NEEDSYNC);
	um_tlb_mark_sync(mm, addr & PMD_MASK, (addr & PMD_MASK) + PMD_SIZE);
}

#define __HAVE_ARCH_PMDP_HUGE_GET_AND_CLEAR
static inline pmd_t pmdp_huge_get_and_clear(struct mm_struct *mm,
					  unsigned long addr, pmd_t *pmdp)
{
	pmd_t old = __pmd(xchg(&pmd_val(*pmdp), _PAGE_NEEDSYNC));

	/* Once cleared, the sync walker cannot tell this was a huge leaf. */
	um_tlb_mark_sync(mm, addr & PMD_MASK, (addr & PMD_MASK) + PMD_SIZE);
	return old;
}

#define pmdp_establish pmdp_establish
static inline pmd_t pmdp_establish(struct vm_area_struct *vma,
				 unsigned long addr, pmd_t *pmdp, pmd_t pmd)
{
	pmd_t old = __pmd(xchg(&pmd_val(*pmdp), pmd_val(pmd) | _PAGE_NEEDSYNC));
	um_tlb_mark_sync(vma->vm_mm, addr & PMD_MASK, (addr & PMD_MASK) + PMD_SIZE);
	return old;
}

#define __HAVE_ARCH_PMDP_TEST_AND_CLEAR_YOUNG
int pmdp_test_and_clear_young(struct vm_area_struct *vma, unsigned long addr,
			    pmd_t *pmdp);
#define __HAVE_ARCH_PMDP_CLEAR_YOUNG_FLUSH
#define pmdp_clear_flush_young pmdp_test_and_clear_young
#define update_mmu_cache_pmd(vma, address, pmdp) do {} while (0)
#endif

/*
 * the pmd page can be thought of an array like this: pmd_t[PTRS_PER_PMD]
 *
 * this macro returns the index of the entry in the pmd page which would
 * control the given virtual address
 */
#define pmd_page_vaddr(pmd) ((unsigned long) __va(pmd_val(pmd) & PAGE_MASK))

struct mm_struct;

#define update_mmu_cache(vma,address,ptep) do {} while (0)
#define update_mmu_cache_range(vmf, vma, address, ptep, nr) do {} while (0)

/*
 * Encode/decode swap entries and swap PTEs. Swap PTEs are all PTEs that
 * are !pte_none() && !pte_present().
 *
 * Format of swap PTEs:
 *
 *   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
 *   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 *   <--------------- offset ----------------> E < type -> 0 0 0 1 0
 *
 *   E is the exclusive marker that is not stored in swap entries.
 *   _PAGE_NEEDSYNC (bit 1) is always set to 1 in set_pte().
 */
#define __swp_type(x)			(((x).val >> 5) & 0x1f)
#define __swp_offset(x)			((x).val >> 11)

#define __swp_entry(type, offset) \
	((swp_entry_t) { (((type) & 0x1f) << 5) | ((offset) << 11) })
#define __pte_to_swp_entry(pte) \
	((swp_entry_t) { pte_val(pte_mkuptodate(pte)) })
#define __swp_entry_to_pte(x)		((pte_t) { (x).val })

static inline bool pte_swp_exclusive(pte_t pte)
{
	return pte_get_bits(pte, _PAGE_SWP_EXCLUSIVE);
}

static inline pte_t pte_swp_mkexclusive(pte_t pte)
{
	pte_set_bits(pte, _PAGE_SWP_EXCLUSIVE);
	return pte;
}

static inline pte_t pte_swp_clear_exclusive(pte_t pte)
{
	pte_clear_bits(pte, _PAGE_SWP_EXCLUSIVE);
	return pte;
}

#endif

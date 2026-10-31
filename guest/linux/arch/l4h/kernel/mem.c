// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2000 - 2007 Jeff Dike (jdike@{addtoit,linux.intel}.com)
 */

#include <linux/stddef.h>
#include <linux/module.h>
#include <linux/memblock.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/bootmem_info.h>
#include <linux/memory_hotplug.h>
#include <linux/pgtable.h>
#include <asm/sections.h>
#include <asm/page.h>
#include <asm/pgalloc.h>
#include <as-layout.h>
#include <init.h>
#include <kern.h>
#include <kern_util.h>
#include <mem_user.h>
#include <os.h>
#include <um_malloc.h>
#include <linux/sched/task.h>
#include <asm/tlbflush.h>
#include <l4h_sys.h>
#include <l4h_caps.h>

/* allocated in paging_init, zeroed in mem_init, and unchanged thereafter */
unsigned long *empty_zero_page = NULL;
EXPORT_SYMBOL(empty_zero_page);

/*
 * Initialized during boot, and readonly for initializing page tables
 * afterwards
 */
pgd_t swapper_pg_dir[PTRS_PER_PGD];

/* Initialized at boot time, and readonly after that */
int kmalloc_ok = 0;

void __init arch_mm_preinit(void)
{
	/* clear the zero-page */
	memset(empty_zero_page, 0, PAGE_SIZE);
}

void __init mem_init(void)
{
	kmalloc_ok = 1;
}

void __init paging_init(void)
{
	unsigned long max_zone_pfn[MAX_NR_ZONES] = { 0 };

	empty_zero_page = (unsigned long *) memblock_alloc_low(PAGE_SIZE,
							       PAGE_SIZE);
	if (!empty_zero_page)
		panic("%s: Failed to allocate %lu bytes align=%lx\n",
		      __func__, PAGE_SIZE, PAGE_SIZE);

	max_zone_pfn[ZONE_NORMAL] = end_iomem >> PAGE_SHIFT;
	sparse_init();
	free_area_init(max_zone_pfn);

}

/*
 * The vmemmap: struct pages at VMEMMAP_START + pfn, in kernel page tables
 * that the kernel TLB sync mirrors into seL4 like vmalloc's.  The memmap
 * of a hotplug block lives in the block itself (the altmap, DESIGN.md
 * §8.5); that of boot RAM comes from memblock.
 */
static_assert((1UL << (MAX_PHYSMEM_BITS - PAGE_SHIFT)) * sizeof(struct page) <= VMEMMAP_SIZE);

/* The kernel PTE of `addr` if it is present, else NULL. */
static pte_t *kernel_pte(unsigned long addr)
{
	pgd_t *pgd = pgd_offset_k(addr);
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	if (pgd_none(*pgd))
		return NULL;
	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d))
		return NULL;
	pud = pud_offset(p4d, addr);
	if (pud_none(*pud))
		return NULL;
	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd))
		return NULL;
	pte = pte_offset_kernel(pmd, addr);
	return pte_present(*pte) ? pte : NULL;
}

int __meminit vmemmap_populate(unsigned long start, unsigned long end, int node,
			       struct vmem_altmap *altmap)
{
	unsigned long addr;
	int ret = vmemmap_populate_basepages(start, end, node, altmap);

	if (ret)
		return ret;
	/* Struct pages are written right away: map them in seL4 now. */
	if (slab_is_available()) {
		l4h_kernel_map_sync(start, end);
		return 0;
	}
	/* The boot memmap, for good, before the TLB sync can map anything:
	 * its PTEs are then up to date, and later syncs leave them alone. */
	for (addr = start; addr < end; addr += PAGE_SIZE) {
		pte_t *pte = kernel_pte(addr);

		if (pte && pte_needsync(*pte)) {
			l4h_map_kernel_early(L4H_FRAME_CPTR(pte_val(*pte) & PAGE_MASK), addr);
			*pte = pte_mkuptodate(*pte);
		}
	}
	return 0;
}

#ifdef CONFIG_MEMORY_HOTPLUG
/* Unmap [start, end) of the vmemmap and free its pages; the page tables
 * stay, for the next hotplug block there.  Only hotplugged memory is ever
 * removed, whose memmap the TLB sync mapped. */
void vmemmap_free(unsigned long start, unsigned long end, struct vmem_altmap *altmap)
{
	unsigned long addr;

	for (addr = start; addr < end; addr += PAGE_SIZE) {
		pte_t *pte = kernel_pte(addr);
		struct page *page;

		if (!pte)
			continue;
		page = pte_page(*pte);
		pte_clear(&init_mm, addr, pte);
		if (altmap)
			vmem_altmap_free(altmap, 1);
		else if (PageReserved(page))
			free_reserved_page(page);
		else
			__free_page(page);
	}
	/* Before the pages are used again (altmap pages are the hotplug
	 * block's own, which is unplugged next). */
	l4h_kernel_map_sync(start, end);
}

/*
 * Hotplug blocks arrive with their frames already mapped in the direct map
 * (drivers/memhp.c): only their memmap is added here.
 */
int arch_add_memory(int nid, u64 start, u64 size, struct mhp_params *params)
{
	unsigned long start_pfn = PFN_DOWN(start), nr_pages = size >> PAGE_SHIFT;
	int ret;

	ret = __add_pages(nid, start_pfn, nr_pages, params);
	if (!ret && start_pfn + nr_pages > max_pfn) {
		max_pfn = max_low_pfn = start_pfn + nr_pages;
		high_memory = __va(max_pfn << PAGE_SHIFT);
	}
	return ret;
}

void arch_remove_memory(u64 start, u64 size, struct vmem_altmap *altmap)
{
	__remove_pages(PFN_DOWN(start), size >> PAGE_SHIFT, altmap);
}
#endif

#ifdef CONFIG_HAVE_BOOTMEM_INFO_NODE
/* Boot RAM is never removed: nothing to register. */
void register_page_bootmem_memmap(unsigned long section_nr, struct page *start_page,
				  unsigned long nr_pages)
{
}
#endif

/*
 * This can't do anything because nothing in the kernel image can be freed
 * since it's not in kernel physical memory.
 */

void free_initmem(void)
{
}

/* Allocate and free page tables. */

pgd_t *pgd_alloc(struct mm_struct *mm)
{
	pgd_t *pgd = __pgd_alloc(mm, 0);

	if (pgd)
		memcpy(pgd + USER_PTRS_PER_PGD,
		       swapper_pg_dir + USER_PTRS_PER_PGD,
		       (PTRS_PER_PGD - USER_PTRS_PER_PGD) * sizeof(pgd_t));

	return pgd;
}

void *uml_kmalloc(int size, int flags)
{
	return kmalloc(size, flags);
}

static const pgprot_t protection_map[16] = {
	[VM_NONE]					= PAGE_NONE,
	[VM_READ]					= PAGE_READONLY,
	[VM_WRITE]					= PAGE_COPY,
	[VM_WRITE | VM_READ]				= PAGE_COPY,
	[VM_EXEC]					= PAGE_READONLY_EXEC,
	[VM_EXEC | VM_READ]				= PAGE_READONLY_EXEC,
	[VM_EXEC | VM_WRITE]				= PAGE_COPY_EXEC,
	[VM_EXEC | VM_WRITE | VM_READ]			= PAGE_COPY_EXEC,
	[VM_SHARED]					= PAGE_NONE,
	[VM_SHARED | VM_READ]				= PAGE_READONLY,
	[VM_SHARED | VM_WRITE]				= PAGE_SHARED,
	[VM_SHARED | VM_WRITE | VM_READ]		= PAGE_SHARED,
	[VM_SHARED | VM_EXEC]				= PAGE_READONLY_EXEC,
	[VM_SHARED | VM_EXEC | VM_READ]			= PAGE_READONLY_EXEC,
	[VM_SHARED | VM_EXEC | VM_WRITE]		= PAGE_SHARED_EXEC,
	[VM_SHARED | VM_EXEC | VM_WRITE | VM_READ]	= PAGE_SHARED_EXEC
};
DECLARE_VM_GET_PAGE_PROT

void mark_rodata_ro(void)
{
	/*
	 * The host maps text and rodata read-only, shared by all guests
	 * (vmlinux.lds.S); __ro_after_init data is with the data, writable.
	 */
}

/*
 * set_ptes() with nr > 1 must map consecutive pages (large folios and
 * splitting huge PMDs). Check the stride at boot, including builds without
 * THP. A scratch mm takes the sync mark.
 */
static struct mm_struct set_ptes_mm __initdata;

static int __init set_ptes_check(void)
{
	pte_t ptes[4];
	unsigned long pfn = 0x1234;
	int i;

	raw_spin_lock_init(&set_ptes_mm.context.sync_lock);
	set_ptes(&set_ptes_mm, 0, ptes, pfn_pte(pfn, PAGE_READONLY), ARRAY_SIZE(ptes));
	for (i = 0; i < ARRAY_SIZE(ptes); i++)
		if (pte_pfn(ptes[i]) != pfn + i)
			panic("l4h: set_ptes() entry %d maps pfn %lx, not %lx\n",
			      i, pte_pfn(ptes[i]), pfn + i);
	return 0;
}
early_initcall(set_ptes_check);

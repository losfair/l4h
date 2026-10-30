/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2002 - 2007 Jeff Dike (jdike@{addtoit,linux.intel}.com)
 */

#ifndef __UM_TLBFLUSH_H
#define __UM_TLBFLUSH_H

#include <linux/mm.h>

/*
 * In UML, we need to sync the TLB over by using mmap/munmap syscalls from
 * the process handling the MM (which can be the kernel itself).
 *
 * To track updates, we hook into set_ptes, set_pmd_at and flush_tlb_*.
 * The setters catch leaf transitions where unusable memory becomes usable.
 * While with flush_tlb_* we can track any memory that becomes unusable and
 * even if a higher layer of the page table was modified.
 *
 * So, we simply track updates using both methods and mark the memory area to
 * be synced later on. The only special case is that flush_tlb_kern_* needs to
 * be executed immediately as there is no good synchronization point in that
 * case. In contrast, in the set_ptes case we can wait for the next kernel
 * segfault before we do the synchornization.
 *
 *  - flush_tlb_all() flushes all processes TLBs
 *  - flush_tlb_mm(mm) flushes the specified mm context TLB's
 *  - flush_tlb_page(vma, vmaddr) flushes one page
 *  - flush_tlb_range(vma, start, end) flushes a range of pages
 *  - flush_tlb_kernel_range(start, end) flushes a range of kernel pages
 */

extern int um_tlb_sync(struct mm_struct *mm);
extern void l4h_kernel_map_sync(unsigned long start, unsigned long end);

/*
 * With several vCPUs, threads of `mm` may be running elsewhere: removed or
 * downgraded mappings must be gone from the seL4 VSpace before the caller
 * proceeds (e.g. frees the page), so sync immediately.
 */
static inline void l4h_tlb_flush_sync(struct mm_struct *mm)
{
	if (IS_ENABLED(CONFIG_SMP))
		um_tlb_sync(mm);
}

extern void flush_tlb_all(void);
extern void flush_tlb_mm(struct mm_struct *mm);

static inline void flush_tlb_page(struct vm_area_struct *vma,
				  unsigned long address)
{
	um_tlb_mark_sync(vma->vm_mm, address, address + PAGE_SIZE);
	l4h_tlb_flush_sync(vma->vm_mm);
}

static inline void flush_tlb_range(struct vm_area_struct *vma,
				   unsigned long start, unsigned long end)
{
	um_tlb_mark_sync(vma->vm_mm, start, end);
	l4h_tlb_flush_sync(vma->vm_mm);
}

static inline void flush_tlb_kernel_range(unsigned long start,
					  unsigned long end)
{
	um_tlb_mark_sync(&init_mm, start, end);

	/* Kernel needs to be synced immediately */
	um_tlb_sync(&init_mm);
}

#endif

// SPDX-License-Identifier: GPL-2.0
/* Test-only access to the reclaim hook: smaps reads the software PTE and
 * cannot observe a hardware access. Loaded only by the test runners. */
#include <linux/mm.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/sizes.h>
#include <linux/uaccess.h>
#include <l4h_vspace.h>
#include "page-aging.h"

static long aging_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	struct aging_range range;
	unsigned long addr, end;
	long young = 0;

	if (cmd != L4H_AGING_SAMPLE && cmd != L4H_LARGE_MAPPINGS)
		return -ENOTTY;
	if (copy_from_user(&range, (void __user *)arg, sizeof(range)))
		return -EFAULT;
	addr = range.start;
	end = addr + range.size;
	if (!range.size || range.size > SZ_64M || end < addr ||
	    !PAGE_ALIGNED(addr) || !PAGE_ALIGNED(end))
		return -EINVAL;
	if (cmd == L4H_LARGE_MAPPINGS)
		return l4h_mm_large_mappings(mm, addr, end);
	/* The write lock excludes collapse and keeps the hierarchy alive.
	 * Leaf locks also exclude splitting and reclaim. */
	mmap_write_lock(mm);
	vma = vma_lookup(mm, addr);
	if (!vma || end > vma->vm_end) {
		young = -EINVAL;
		goto out;
	}
	for (; addr < end; addr += PAGE_SIZE) {
		pgd_t *pgd = pgd_offset(mm, addr);
		p4d_t *p4d;
		pud_t *pud;
		pmd_t *pmd;
		pte_t *pte;
		spinlock_t *ptl;

		if (pgd_none(*pgd) || pgd_bad(*pgd))
			continue;
		p4d = p4d_offset(pgd, addr);
		if (p4d_none(*p4d) || p4d_bad(*p4d))
			continue;
		pud = pud_offset(p4d, addr);
		if (pud_none(*pud) || pud_bad(*pud))
			continue;
		pmd = pmd_offset(pud, addr);
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
		ptl = pmd_lock(mm, pmd);
		if (pmd_trans_huge(*pmd)) {
			unsigned long next = pmd_addr_end(addr, end);

			if (pmdp_clear_flush_young(vma, addr & PMD_MASK, pmd))
				young += (next - addr) >> PAGE_SHIFT;
			spin_unlock(ptl);
			addr = next - PAGE_SIZE;
			continue;
		}
		spin_unlock(ptl);
#endif
		if (pmd_none(*pmd) || pmd_bad(*pmd))
			continue;
		pte = pte_offset_kernel(pmd, addr);
		ptl = pte_lockptr(mm, pmd);
		spin_lock(ptl);
		if (pte_present(*pte))
			young += !!ptep_clear_flush_young(vma, addr, pte);
		spin_unlock(ptl);
	}
out:
	mmap_write_unlock(mm);
	return young;
}

static const struct file_operations aging_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = aging_ioctl,
};

static struct miscdevice aging_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "l4h_page_aging",
	.fops = &aging_fops,
	.mode = 0600,
};

static int __init aging_init(void)
{
	return misc_register(&aging_device);
}

static void __exit aging_exit(void)
{
	misc_deregister(&aging_device);
}

module_init(aging_init);
module_exit(aging_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("l4h page-aging selftest sampler");

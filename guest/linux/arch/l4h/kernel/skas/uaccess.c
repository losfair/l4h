// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2002 - 2007 Jeff Dike (jdike@{addtoit,linux.intel}.com)
 */

#include <linux/err.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <asm/current.h>
#include <asm/page.h>
#include <kern_util.h>
#include <asm/futex.h>
#include <os.h>

pte_t *virt_to_pte(struct mm_struct *mm, unsigned long addr)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	if (mm == NULL)
		return NULL;

	pgd = pgd_offset(mm, addr);
	if (!pgd_present(*pgd))
		return NULL;

	p4d = p4d_offset(pgd, addr);
	if (!p4d_present(*p4d))
		return NULL;

	pud = pud_offset(p4d, addr);
	if (!pud_present(*pud))
		return NULL;

	pmd = pmd_offset(pud, addr);
	if (!pmd_present(*pmd))
		return NULL;

	return pte_offset_kernel(pmd, addr);
}

/*
 * The page mapped at user address @virt, with a reference, if its PTE allows
 * the access: present, readable (not PROT_NONE) or writable.  The caller
 * holds mmap_lock and has checked that a VMA covers @virt, so the page
 * tables stay in place (munmap frees them only after removing the VMA); the
 * PTE lock keeps the entry stable while we check it, take the reference and
 * mark it accessed (and dirty).
 */
static struct page *get_mapped_page(struct mm_struct *mm, unsigned long virt,
				    int is_write)
{
	struct page *page = NULL;
	spinlock_t *ptl;
	pte_t *ptep, pte;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	pgd = pgd_offset(mm, virt);
	if (!pgd_present(*pgd))
		return NULL;
	p4d = p4d_offset(pgd, virt);
	if (!p4d_present(*p4d))
		return NULL;
	pud = pud_offset(p4d, virt);
	if (!pud_present(*pud))
		return NULL;
	pmd = pmd_offset(pud, virt);
	if (!pmd_present(*pmd))
		return NULL;
	ptep = pte_offset_map_lock(mm, pmd, virt, &ptl);
	if (!ptep)
		return NULL;
	pte = ptep_get(ptep);
	if (pte_present(pte) && (is_write ? pte_write(pte) : pte_read(pte)) &&
	    pfn_valid(pte_pfn(pte))) {
		page = pte_page(pte);
		get_page(page);
		/*
		 * The access goes through the direct map, which no MMU
		 * watches: mark the PTE as the CPU would.  Reclaim drops a
		 * clean page instead of writing it back (MADV_FREE).
		 */
		if (is_write ? !pte_dirty(pte) || !pte_young(pte) : !pte_young(pte))
			set_pte_at(mm, virt, ptep, is_write ? pte_mkdirty(pte_mkyoung(pte)) :
							      pte_mkyoung(pte));
	}
	pte_unmap_unlock(ptep, ptl);
	return page;
}

/*
 * Pin the page that backs user address @virt for an access through the
 * direct map, faulting it in if needed; NULL if the access must fail.
 *
 * Another vCPU may unmap the page meanwhile (munmap, madvise, reclaim) and
 * free it: the reference keeps it from being reused until the caller's
 * put_page(), as get_user_pages() does.  In atomic context (futex
 * operations, *_nofault copies) the walk only tries mmap_lock and never
 * faults; callers then fault the page in themselves and retry.
 */
static struct page *pin_user_page(unsigned long virt, int is_write)
{
	struct mm_struct *mm = current->mm;
	bool atomic = faulthandler_disabled();
	int tries;

	/* Interrupts can arrive with this vCPU holding the PTE lock. */
	if (mm == NULL || in_interrupt())
		return NULL;
	for (tries = 0; tries < 4; tries++) {
		struct page *page = NULL;

		if (atomic) {
			if (!mmap_read_trylock(mm))
				return NULL;
		} else {
			mmap_read_lock(mm);
		}
		if (vma_lookup(mm, virt))
			page = get_mapped_page(mm, virt, is_write);
		mmap_read_unlock(mm);
		if (page)
			return page;
		/* Checks the VMA's permissions; fails when atomic. */
		if (handle_uaccess_fault(virt, is_write))
			return NULL;
	}
	/* Unmapped again after every fault: give up. */
	return NULL;
}

static int do_op_one_page(unsigned long addr, int len, int is_write,
		 int (*op)(unsigned long addr, int len, void *arg), void *arg)
{
	struct page *page;
	int n;

	page = pin_user_page(addr, is_write);
	if (page == NULL)
		return -1;

#ifdef CONFIG_64BIT
	pagefault_disable();
	addr = (unsigned long) page_address(page) +
		(addr & ~PAGE_MASK);
#else
	addr = (unsigned long) kmap_atomic(page) +
		(addr & ~PAGE_MASK);
#endif
	n = (*op)(addr, len, arg);

#ifdef CONFIG_64BIT
	pagefault_enable();
#else
	kunmap_atomic((void *)addr);
#endif
	put_page(page);

	return n;
}

static long buffer_op(unsigned long addr, int len, int is_write,
		      int (*op)(unsigned long, int, void *), void *arg)
{
	long size, remain, n;

	size = min(PAGE_ALIGN(addr) - addr, (unsigned long) len);
	remain = len;

	n = do_op_one_page(addr, size, is_write, op, arg);
	if (n != 0) {
		remain = (n < 0 ? remain : 0);
		goto out;
	}

	addr += size;
	remain -= size;
	if (remain == 0)
		goto out;

	while (addr < ((addr + remain) & PAGE_MASK)) {
		n = do_op_one_page(addr, PAGE_SIZE, is_write, op, arg);
		if (n != 0) {
			remain = (n < 0 ? remain : 0);
			goto out;
		}

		addr += PAGE_SIZE;
		remain -= PAGE_SIZE;
	}
	if (remain == 0)
		goto out;

	n = do_op_one_page(addr, remain, is_write, op, arg);
	if (n != 0) {
		remain = (n < 0 ? remain : 0);
		goto out;
	}

	return 0;
 out:
	return remain;
}

static int copy_chunk_from_user(unsigned long from, int len, void *arg)
{
	unsigned long *to_ptr = arg, to = *to_ptr;

	memcpy((void *) to, (void *) from, len);
	*to_ptr += len;
	return 0;
}

unsigned long raw_copy_from_user(void *to, const void __user *from, unsigned long n)
{
	return buffer_op((unsigned long) from, n, 0, copy_chunk_from_user, &to);
}
EXPORT_SYMBOL(raw_copy_from_user);

static int copy_chunk_to_user(unsigned long to, int len, void *arg)
{
	unsigned long *from_ptr = arg, from = *from_ptr;

	memcpy((void *) to, (void *) from, len);
	*from_ptr += len;
	return 0;
}

unsigned long raw_copy_to_user(void __user *to, const void *from, unsigned long n)
{
	return buffer_op((unsigned long) to, n, 1, copy_chunk_to_user, &from);
}
EXPORT_SYMBOL(raw_copy_to_user);

static int strncpy_chunk_from_user(unsigned long from, int len, void *arg)
{
	char **to_ptr = arg, *to = *to_ptr;
	int n;

	strncpy(to, (void *) from, len);
	n = strnlen(to, len);
	*to_ptr += n;

	if (n < len)
	        return 1;
	return 0;
}

long strncpy_from_user(char *dst, const char __user *src, long count)
{
	long n;
	char *ptr = dst;

	if (!access_ok(src, 1))
		return -EFAULT;
	n = buffer_op((unsigned long) src, count, 0, strncpy_chunk_from_user,
		      &ptr);
	if (n != 0)
		return -EFAULT;
	return strnlen(dst, count);
}
EXPORT_SYMBOL(strncpy_from_user);

static int clear_chunk(unsigned long addr, int len, void *unused)
{
	memset((void *) addr, 0, len);
	return 0;
}

unsigned long __clear_user(void __user *mem, unsigned long len)
{
	return buffer_op((unsigned long) mem, len, 1, clear_chunk, NULL);
}
EXPORT_SYMBOL(__clear_user);

static int strnlen_chunk(unsigned long str, int len, void *arg)
{
	int *len_ptr = arg, n;

	n = strnlen((void *) str, len);
	*len_ptr += n;

	if (n < len)
		return 1;
	return 0;
}

long strnlen_user(const char __user *str, long len)
{
	int count = 0, n;

	if (!access_ok(str, 1))
		return -EFAULT;
	n = buffer_op((unsigned long) str, len, 0, strnlen_chunk, &count);
	if (n == 0)
		return count + 1;
	return 0;
}
EXPORT_SYMBOL(strnlen_user);

/**
 * arch_futex_atomic_op_inuser() - Atomic arithmetic operation with constant
 *			  argument and comparison of the previous
 *			  futex value with another constant.
 *
 * @op:		operation to execute
 * @oparg:	argument to operation
 * @oval:	old value at uaddr
 * @uaddr:	pointer to user space address
 *
 * Return:
 * 0 - On success
 * -EFAULT - User access resulted in a page fault
 * -EAGAIN - Atomic operation was unable to complete due to contention
 * -ENOSYS - Operation not supported
 */

int arch_futex_atomic_op_inuser(int op, u32 oparg, int *oval, u32 __user *uaddr)
{
	int oldval, ret;
	struct page *page;
	unsigned long addr = (unsigned long) uaddr;

	ret = -EFAULT;
	if (!access_ok(uaddr, sizeof(*uaddr)))
		return -EFAULT;
	preempt_disable();
	page = pin_user_page(addr, 1);
	if (page == NULL)
		goto out_inuser;

#ifdef CONFIG_64BIT
	pagefault_disable();
	addr = (unsigned long) page_address(page) +
			(((unsigned long) addr) & ~PAGE_MASK);
#else
	addr = (unsigned long) kmap_atomic(page) +
		((unsigned long) addr & ~PAGE_MASK);
#endif
	uaddr = (u32 *) addr;

	/*
	 * Other vCPUs (and user threads on them) update the word
	 * concurrently: the update must be one atomic operation, and oldval
	 * the value it replaced.
	 */
	ret = 0;
	switch (op) {
	case FUTEX_OP_SET:
		oldval = xchg(uaddr, oparg);
		break;
	case FUTEX_OP_ADD:
	case FUTEX_OP_OR:
	case FUTEX_OP_ANDN:
	case FUTEX_OP_XOR: {
		u32 old = READ_ONCE(*uaddr), new, seen;

		for (;;) {
			switch (op) {
			case FUTEX_OP_ADD:
				new = old + oparg;
				break;
			case FUTEX_OP_OR:
				new = old | oparg;
				break;
			case FUTEX_OP_ANDN:
				new = old & ~oparg;
				break;
			default:
				new = old ^ oparg;
				break;
			}
			seen = cmpxchg(uaddr, old, new);
			if (seen == old)
				break;
			old = seen;
		}
		oldval = old;
		break;
	}
	default:
		ret = -ENOSYS;
	}
#ifdef CONFIG_64BIT
	pagefault_enable();
#else
	kunmap_atomic((void *)addr);
#endif
	put_page(page);

out_inuser:
	preempt_enable();

	if (ret == 0)
		*oval = oldval;

	return ret;
}
EXPORT_SYMBOL(arch_futex_atomic_op_inuser);

/**
 * futex_atomic_cmpxchg_inatomic() - Compare and exchange the content of the
 *				uaddr with newval if the current value is
 *				oldval.
 * @uval:	pointer to store content of @uaddr
 * @uaddr:	pointer to user space address
 * @oldval:	old value
 * @newval:	new value to store to @uaddr
 *
 * Return:
 * 0 - On success
 * -EFAULT - User access resulted in a page fault
 * -EAGAIN - Atomic operation was unable to complete due to contention
 */

int futex_atomic_cmpxchg_inatomic(u32 *uval, u32 __user *uaddr,
			      u32 oldval, u32 newval)
{
	struct page *page;
	int ret = -EFAULT;

	if (!access_ok(uaddr, sizeof(*uaddr)))
		return -EFAULT;

	preempt_disable();
	page = pin_user_page((unsigned long) uaddr, 1);
	if (page == NULL)
		goto out_inatomic;

#ifdef CONFIG_64BIT
	pagefault_disable();
	uaddr = page_address(page) + (((unsigned long) uaddr) & ~PAGE_MASK);
#else
	uaddr = kmap_atomic(page) + ((unsigned long) uaddr & ~PAGE_MASK);
#endif

	/* The value the compare-and-exchange saw, not an earlier read. */
	*uval = cmpxchg(uaddr, oldval, newval);

#ifdef CONFIG_64BIT
	pagefault_enable();
#else
	kunmap_atomic(uaddr);
#endif
	put_page(page);
	ret = 0;

out_inatomic:
	preempt_enable();
	return ret;
}
EXPORT_SYMBOL(futex_atomic_cmpxchg_inatomic);

// SPDX-License-Identifier: GPL-2.0
/*
 * The Stage-2 VSpace of a VM.
 *
 * KVM keeps its own Stage-2 page table (arch/arm64/kvm/hyp/pgtable.c),
 * which the CPU never walks.  What the CPU walks is an FL4 Stage-2 VSpace,
 * a cache of the leaves of that table, as arch/l4h/kvm/ept.c is of the TDP
 * MMU's on x86_64.  Every change KVM makes to its table goes through the
 * l4h_kvm_pgtable_stage2_*() wrappers below (KVM_PGT_FN in
 * arch/arm64/kvm/mmu.c, guest/linux/patches), which make FL4's agree with
 * what KVM's leaves hold *after* the change, in the range it touched:
 *
 *  - KVM changes leaves under the read side of mmu_lock: two threads can
 *    come here in any order, but `lock` serializes them and whichever
 *    comes last reads the final value, so a mapping cannot outlive its
 *    leaf.
 *  - FL4's may hold less than KVM's (a failed allocation, a block whose
 *    frames went away): the guest then faults on a page KVM finds mapped,
 *    KVM maps it again (-EAGAIN, a spurious fault), and the wrapper of
 *    that map brings FL4's back in step.
 *
 * FL4 invalidates the TLBs when it removes a leaf or a table, and adding
 * one needs no invalidation, so KVM's TLB maintenance has nothing to do.
 * Every mapping needs its own copy of the frame capability, in a slot we
 * record to delete it again; deleting the copy removes the mapping.
 *
 * FL4's Stage-2 roots start at level 0 for a 44- or 48-bit IPA space
 * (three tables below the root) and at level 1 (concatenated) for 40 bits
 * (two): ../fl4/crates/fl4-core/src/arch/aarch64/ept.rs, geom().  A page
 * table seL4_ARM_PageTable_Map()s goes to the first level the walk finds
 * empty, so tables are added top-down.
 */
#undef pr_fmt
#define pr_fmt(fmt) "l4h-kvm: " fmt

#include <linux/kvm_host.h>
#include <linux/slab.h>
#include <linux/xarray.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_pgtable.h>
#include <l4h_sys.h>
#include "l4h_kvm_arm64.h"
#include "stage2.h"

#define PAGES_2M	(1ul << 9)
#define SZ_2M_MASK	(~(SZ_2M - 1))

struct s2_table {
	struct list_head link;
	struct l4h_obj obj;
	int level;
};

static const int table_shift[L4H_S2_LEVELS] = { 21, 30, 39 };

/* The host's roots (abi.h, L4H_SLOT_EPT_POOL). */
static DEFINE_SPINLOCK(pool_lock);
static unsigned long pool_free;

void l4h_s2_pool_init(unsigned int nr)
{
	pool_free = nr >= BITS_PER_LONG ? ~0ul : (1ul << nr) - 1;
}

/*
 * Leaf entries: the slot of the mapping's frame copy, the frame (its pfn,
 * or a GICV page) and the rights it was mapped with.
 */
#define E_SLOT_BITS	30
#define E_PROT_SHIFT	E_SLOT_BITS
#define E_PROT_BITS	6
#define E_PFN_SHIFT	(E_PROT_SHIFT + E_PROT_BITS)
#define E_PFN_BITS	(BITS_PER_XA_VALUE - E_PFN_SHIFT)
/* The pfn recorded for GICV page i. */
#define E_PFN_GICV(i)	((1ul << E_PFN_BITS) - 1 - (i))

static inline void *mk_entry(unsigned long slot, unsigned long pfn, int prot)
{
	return xa_mk_value((pfn << E_PFN_SHIFT) | ((unsigned long)prot << E_PROT_SHIFT) | slot);
}

static inline unsigned long entry_slot(void *e)
{
	return xa_to_value(e) & ((1ul << E_SLOT_BITS) - 1);
}

static inline int entry_prot(void *e)
{
	return (xa_to_value(e) >> E_PROT_SHIFT) & ((1ul << E_PROT_BITS) - 1);
}

static inline unsigned long entry_pfn(void *e)
{
	return xa_to_value(e) >> E_PFN_SHIFT;
}

int l4h_s2_create(struct kvm *kvm)
{
	struct l4h_s2 *s;
	int i, bit;

	s = kzalloc(sizeof(*s), GFP_KERNEL_ACCOUNT);
	if (!s)
		return -ENOMEM;
	spin_lock(&pool_lock);
	bit = ffs(pool_free) - 1;
	if (bit >= 0)
		pool_free &= ~(1ul << bit);
	spin_unlock(&pool_lock);
	if (bit < 0) {
		kfree(s);
		return -EBUSY;
	}
	s->kvm = kvm;
	s->root = L4H_CPTR2(L4H_SLOT_EPT_POOL, bit);
	s->levels = l4h_kvm_ipa_bits <= 42 ? 2 : 3;
	spin_lock_init(&s->lock);
	INIT_LIST_HEAD(&s->tables);
	for (i = 0; i < L4H_S2_LEVELS; i++)
		xa_init(&s->table_at[i]);
	xa_init(&s->pages);
	xa_init(&s->large);
	kvm->arch.l4h_s2 = s;
	return 0;
}

/* Everything goes; the root goes back to the pool, empty. */
void l4h_s2_destroy(struct kvm *kvm)
{
	struct l4h_s2 *s = to_s2(kvm);
	struct s2_table *t, *n;
	unsigned long i;
	int level;
	void *entry;

	if (!s)
		return;
	kvm->arch.l4h_s2 = NULL;
	/* Oldest first: a table goes before the tables below it, so the
	 * rest is deleted without a TLB invalidation each. */
	list_for_each_entry_safe_reverse(t, n, &s->tables, link) {
		list_del(&t->link);
		l4h_obj_free(&t->obj);
		kfree(t);
	}
	for (level = 0; level < L4H_S2_LEVELS; level++)
		xa_destroy(&s->table_at[level]);
	xa_for_each(&s->large, i, entry)
		l4h_slot_delete(entry_slot(entry));
	xa_destroy(&s->large);
	xa_for_each(&s->pages, i, entry) {
		l4h_slot_delete(entry_slot(entry));
		cond_resched();
	}
	xa_destroy(&s->pages);

	spin_lock(&pool_lock);
	pool_free |= 1ul << (s->root & ((1ul << L4H_L2_INDEX_BITS) - 1));
	spin_unlock(&pool_lock);
	kfree(s);
}

static void free_table(struct l4h_s2 *s, struct s2_table *t)
{
	list_del(&t->link);
	l4h_obj_free(&t->obj);
	kfree(t);
}

/* A table at `level` covering `ipa`, and the ones above it. */
static int add_table(struct l4h_s2 *s, int level, unsigned long ipa)
{
	unsigned long index = ipa >> table_shift[level];
	struct s2_table *t;
	int err;

	if (xa_load(&s->table_at[level], index))
		return 0;
	if (level + 1 < s->levels) {
		err = add_table(s, level + 1, ipa);
		if (err)
			return err;
	}
	/* Reserved, so that storing it cannot fail. */
	err = xa_reserve(&s->table_at[level], index, GFP_ATOMIC);
	if (err)
		return err;
	t = kzalloc(sizeof(*t), GFP_ATOMIC);
	if (!t) {
		err = -ENOMEM;
		goto release;
	}
	err = l4h_obj_alloc(L4H_OBJ_EPT_PT, 0, &t->obj);
	if (err) {
		kfree(t);
		goto release;
	}
	err = l4h_arm_s2_map_table(t->obj.cptr, s->root, ipa);
	if (err) {
		l4h_obj_free(&t->obj);
		kfree(t);
		err = -EFAULT;
		goto release;
	}
	t->level = level;
	list_add(&t->link, &s->tables);
	xa_store(&s->table_at[level], index, t, GFP_ATOMIC);
	return 0;
release:
	xa_release(&s->table_at[level], index);
	return err;
}

static void unmap_small(struct l4h_s2 *s, unsigned long gfn)
{
	void *entry = xa_erase(&s->pages, gfn);

	if (entry)
		l4h_slot_delete(entry_slot(entry));
}

static void unmap_large(struct l4h_s2 *s, unsigned long gfn)
{
	void *entry = xa_erase(&s->large, gfn >> 9);

	if (entry)
		l4h_slot_delete(entry_slot(entry));
}

static void unmap_range_2m(struct l4h_s2 *s, unsigned long gfn)
{
	unsigned long i;
	void *entry;

	unmap_large(s, gfn);
	xa_for_each_range(&s->pages, i, entry, gfn, gfn + PAGES_2M - 1) {
		xa_erase(&s->pages, i);
		l4h_slot_delete(entry_slot(entry));
	}
}

/* The frame capability of `phys` that a leaf names: guest kernel RAM, or
 * a page of GICv2's GICV (L4H_FAKE_GICV, vgic.c). */
static unsigned long frame_of(unsigned long phys, bool writable, unsigned long *pfn)
{
	if (phys >= L4H_FAKE_GICV && phys < L4H_FAKE_GICV + L4H_GICV_PAGES * PAGE_SIZE) {
		unsigned long i = (phys - L4H_FAKE_GICV) >> PAGE_SHIFT;

		*pfn = E_PFN_GICV(i);
		return L4H_GICV_CPTR(i);
	}
	*pfn = phys >> PAGE_SHIFT;
	if (*pfn >= E_PFN_GICV(L4H_GICV_PAGES) || !l4h_frame_mappable(phys, writable))
		return 0;
	return L4H_FRAME_CPTR(phys);
}

static int map_small(struct l4h_s2 *s, unsigned long gfn, unsigned long phys, int prot)
{
	unsigned long ipa = gfn << PAGE_SHIFT, slot, pfn, frame;
	void *entry;
	int err;

	frame = frame_of(phys, prot & L4H_PROT_WRITE, &pfn);
	if (!frame)
		return -ENXIO;
	entry = xa_load(&s->pages, gfn);
	if (entry) {
		if (entry_pfn(entry) == pfn && entry_prot(entry) == prot)
			return 0;
		unmap_small(s, gfn);
	}
	unmap_large(s, gfn & ~(PAGES_2M - 1));
	slot = l4h_cap_copy(frame, L4H_RIGHTS_ALL);
	if (!slot)
		return -ENOMEM;
	err = add_table(s, 0, ipa);
	if (!err)
		err = l4h_arm_s2_map_frame(slot, s->root, ipa, prot) ? -EFAULT : 0;
	if (!err)
		err = xa_err(xa_store(&s->pages, gfn, mk_entry(slot, pfn, prot), GFP_ATOMIC));
	if (err)
		l4h_slot_delete(slot);
	return err;
}

/* A 2 MiB leaf.  Without a large frame (boot-image blocks), 512 small ones. */
static int map_large(struct l4h_s2 *s, unsigned long gfn, unsigned long phys, int prot)
{
	unsigned long ipa = gfn << PAGE_SHIFT, frame, index = gfn >> 9, slot, i;
	struct s2_table *t;
	void *entry;
	int err;

	frame = (phys >> PAGE_SHIFT) < E_PFN_GICV(L4H_GICV_PAGES) ? l4h_large_frame(phys) : 0;
	if (!frame) {
		for (i = 0; i < PAGES_2M; i++) {
			err = map_small(s, gfn + i, phys + i * PAGE_SIZE, prot);
			if (err)
				return err;
		}
		return 0;
	}
	entry = xa_load(&s->large, index);
	if (entry && entry_pfn(entry) == (phys >> PAGE_SHIFT) && entry_prot(entry) == prot)
		return 0;
	unmap_range_2m(s, gfn);
	/* FL4 refuses a block where a page table is. */
	t = xa_erase(&s->table_at[0], ipa >> table_shift[0]);
	if (t)
		free_table(s, t);
	slot = l4h_cap_copy(frame, L4H_RIGHTS_ALL);
	if (!slot)
		return -ENOMEM;
	err = s->levels > 1 ? add_table(s, 1, ipa) : 0;
	if (!err)
		err = l4h_arm_s2_map_frame(slot, s->root, ipa, prot | L4H_PROT_LARGE) ? -EFAULT : 0;
	if (!err)
		err = xa_err(xa_store(&s->large, index, mk_entry(slot, phys >> PAGE_SHIFT, prot),
				      GFP_ATOMIC));
	if (err)
		l4h_slot_delete(slot);
	return err;
}

/* The rights a valid leaf of KVM's table gives. */
static int leaf_prot(kvm_pte_t pte)
{
	u64 memattr = FIELD_GET(KVM_PTE_LEAF_ATTR_LO_S2_MEMATTR, pte);
	int prot = 0;

	if (pte & KVM_PTE_LEAF_ATTR_LO_S2_S2AP_R)
		prot |= L4H_PROT_READ;
	if (pte & KVM_PTE_LEAF_ATTR_LO_S2_S2AP_W)
		prot |= L4H_PROT_WRITE;
	if (!(pte & KVM_PTE_LEAF_ATTR_HI_S2_XN))
		prot |= L4H_PROT_EXEC;
	if (memattr == MT_S2_DEVICE_nGnRE || memattr == MT_S2_NORMAL_NC)
		prot = (prot & ~L4H_PROT_EXEC) | L4H_PROT_DEVICE;
	return prot;
}

/*
 * Make FL4's mapping of the 4 KiB page (`level` 3) or 2 MiB block
 * (`level` 2) at `ipa` agree with KVM's table.  Returns the size synced.
 */
static unsigned long sync_at(struct kvm_pgtable *pgt, struct l4h_s2 *s, u64 ipa)
{
	unsigned long gfn = ipa >> PAGE_SHIFT, step;
	kvm_pte_t pte = 0;
	s8 level = KVM_PGTABLE_LAST_LEVEL;
	int err = 0, prot;

	if (kvm_pgtable_get_leaf(pgt, ipa, &pte, &level))
		pte = 0;
	if (!kvm_pte_valid(pte) || level < 1 || !(leaf_prot(pte) & (L4H_PROT_READ | L4H_PROT_WRITE))) {
		/* Nothing mapped (or no access): neither a page nor a block. */
		if (xa_load(&s->large, gfn >> 9))
			unmap_range_2m(s, gfn & ~(PAGES_2M - 1));
		unmap_small(s, gfn);
		return PAGE_SIZE;
	}
	prot = leaf_prot(pte);
	if (level == KVM_PGTABLE_LAST_LEVEL) {
		err = map_small(s, gfn, kvm_pte_to_phys(pte), prot);
		if (err)
			pr_warn_ratelimited("no Stage-2 mapping of IPA %llx: %d\n", ipa, err);
		return PAGE_SIZE;
	}
	/* A block of 2 MiB, or a 2 MiB part of a 1 GiB one. */
	step = SZ_2M - (ipa & (SZ_2M - 1));
	ipa &= SZ_2M_MASK;
	err = map_large(s, ipa >> PAGE_SHIFT,
			kvm_pte_to_phys(pte) + (ipa & (kvm_granule_size(level) - 1)), prot);
	if (err)
		pr_warn_ratelimited("no Stage-2 mapping of IPA %llx: %d\n", ipa, err);
	return step;
}

/* After KVM mapped [addr, addr + size). */
static void sync_range(struct kvm_pgtable *pgt, u64 addr, u64 size)
{
	struct l4h_s2 *s = to_s2(kvm_s2_mmu_to_kvm(pgt->mmu));
	u64 end = addr + size;

	if (!s)
		return;
	spin_lock(&s->lock);
	while (addr < end)
		addr += sync_at(pgt, s, addr);
	spin_unlock(&s->lock);
}

/* After KVM unmapped or write-protected [addr, addr + size): only what
 * FL4 has mapped there can change. */
static void sync_mapped(struct kvm_pgtable *pgt, u64 addr, u64 size)
{
	struct l4h_s2 *s = to_s2(kvm_s2_mmu_to_kvm(pgt->mmu));
	unsigned long first = addr >> PAGE_SHIFT, last = (addr + size - 1) >> PAGE_SHIFT, i;
	void *entry;

	if (!s || !size)
		return;
	spin_lock(&s->lock);
	xa_for_each_range(&s->large, i, entry, first >> 9, last >> 9)
		sync_at(pgt, s, (u64)i << (PAGE_SHIFT + 9));
	xa_for_each_range(&s->pages, i, entry, first, last)
		sync_at(pgt, s, (u64)i << PAGE_SHIFT);
	spin_unlock(&s->lock);
}

/* ---- KVM_PGT_FN (arch/arm64/kvm/mmu.c) */

int l4h_kvm_pgtable_stage2_init(struct kvm_pgtable *pgt, struct kvm_s2_mmu *mmu,
				struct kvm_pgtable_mm_ops *mm_ops)
{
	struct kvm *kvm = kvm_s2_mmu_to_kvm(mmu);
	int err;

	/* Nested MMUs (no NV here) never get one. */
	if (mmu != &kvm->arch.mmu)
		return -EINVAL;
	err = kvm_pgtable_stage2_init(pgt, mmu, mm_ops);
	if (err)
		return err;
	err = l4h_s2_create(kvm);
	if (err)
		kvm_pgtable_stage2_destroy(pgt);
	return err;
}

void l4h_kvm_pgtable_stage2_destroy(struct kvm_pgtable *pgt)
{
	l4h_s2_destroy(kvm_s2_mmu_to_kvm(pgt->mmu));
	kvm_pgtable_stage2_destroy(pgt);
}

void l4h_kvm_pgtable_stage2_free_unlinked(struct kvm_pgtable_mm_ops *mm_ops, void *pgtable,
					  s8 level)
{
	kvm_pgtable_stage2_free_unlinked(mm_ops, pgtable, level);
}

int l4h_kvm_pgtable_stage2_map(struct kvm_pgtable *pgt, u64 addr, u64 size, u64 phys,
			       enum kvm_pgtable_prot prot, void *mc,
			       enum kvm_pgtable_walk_flags flags)
{
	int ret = kvm_pgtable_stage2_map(pgt, addr, size, phys, prot, mc, flags);

	/* Also when KVM found it mapped already (-EAGAIN): FL4 may not. */
	sync_range(pgt, addr, size);
	return ret;
}

int l4h_kvm_pgtable_stage2_unmap(struct kvm_pgtable *pgt, u64 addr, u64 size)
{
	int ret = kvm_pgtable_stage2_unmap(pgt, addr, size);

	sync_mapped(pgt, addr, size);
	return ret;
}

int l4h_kvm_pgtable_stage2_wrprotect(struct kvm_pgtable *pgt, u64 addr, u64 size)
{
	int ret = kvm_pgtable_stage2_wrprotect(pgt, addr, size);

	sync_mapped(pgt, addr, size);
	return ret;
}

int l4h_kvm_pgtable_stage2_relax_perms(struct kvm_pgtable *pgt, u64 addr,
				       enum kvm_pgtable_prot prot,
				       enum kvm_pgtable_walk_flags flags)
{
	int ret = kvm_pgtable_stage2_relax_perms(pgt, addr, prot, flags);

	sync_range(pgt, addr, PAGE_SIZE);
	return ret;
}

/* The access flag is KVM's alone: FL4 maps with it set. */
void l4h_kvm_pgtable_stage2_mkyoung(struct kvm_pgtable *pgt, u64 addr,
				    enum kvm_pgtable_walk_flags flags)
{
	kvm_pgtable_stage2_mkyoung(pgt, addr, flags);
	sync_range(pgt, addr, PAGE_SIZE);
}

bool l4h_kvm_pgtable_stage2_test_clear_young(struct kvm_pgtable *pgt, u64 addr, u64 size,
					     bool mkold)
{
	return kvm_pgtable_stage2_test_clear_young(pgt, addr, size, mkold);
}

int l4h_kvm_pgtable_stage2_flush(struct kvm_pgtable *pgt, u64 addr, u64 size)
{
	return kvm_pgtable_stage2_flush(pgt, addr, size);
}

int l4h_kvm_pgtable_stage2_split(struct kvm_pgtable *pgt, u64 addr, u64 size,
				 struct kvm_mmu_memory_cache *mc)
{
	int ret = kvm_pgtable_stage2_split(pgt, addr, size, mc);

	sync_mapped(pgt, addr, size);
	return ret;
}

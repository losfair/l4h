/* SPDX-License-Identifier: GPL-2.0 */
/* Capability slots, seL4 objects and RAM blocks of the l4h guest kernel. */
#ifndef __L4H_CAPS_H
#define __L4H_CAPS_H

struct l4h_obj {
	unsigned long cptr;	/* 0 if none */
	void *chunk;		/* the Untyped chunk it was retyped from */
};

unsigned long l4h_slot_alloc(void);
void l4h_slot_free(unsigned long cptr);
void l4h_slot_delete(unsigned long cptr);
int l4h_obj_alloc(int type, int size_bits, struct l4h_obj *out);
void l4h_obj_free(struct l4h_obj *o);
unsigned long l4h_cap_copy(unsigned long src, int rights);
unsigned long l4h_cap_mint_root(unsigned long root_slot, int rights, unsigned long badge);
void l4h_caps_init(void);
/* Make room for seL4 objects (may sleep); true if there is room. */
bool l4h_objmem_wait(void);
/* No memory for seL4 objects: the OOM killer. */
void l4h_objmem_oom(void);
/* Is guest RAM [gpa, gpa+size) in the direct map (not an object block)? */
bool l4h_ram_mapped(unsigned long gpa, unsigned long size);
/* Caller pins the whole aligned RAM block. Zero for boot-image blocks. */
unsigned long l4h_large_frame(unsigned long gpa);
void l4h_map_kernel_early(unsigned long frame, unsigned long va);
/* Hotplug blocks (DESIGN.md §8.5, drivers/memhp.c). */
bool l4h_hp_contains(unsigned long gpa, unsigned long size);
int l4h_hp_prepare(unsigned int m);
int l4h_hp_map(unsigned int m);
void l4h_hp_unmap(unsigned int m);

#endif

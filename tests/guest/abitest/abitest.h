/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Between the two halves of the ABI test module: main.c (kernel headers)
 * and sel4.c (libsel4).  Plain C types only.
 */
#ifndef ABITEST_H
#define ABITEST_H

#define ABITEST_DMA_SIZE	0x10000
/* Where the user program runs in the test's VSpace. */
#define ABITEST_USER_VA		0x400000ul

struct abitest {
	int cpu;		/* the vCPU the tests run on, interrupts off */
	unsigned long large_ut;	/* independent 2 MiB allocation for alias lifetime tests */
	unsigned long vspace;	/* an empty process VSpace */
	unsigned long user_gpa;	/* a page with a copy of user_prog */
	unsigned long zero_gpa;	/* a zeroed page */
	/* A page of guest RAM, and ABITEST_DMA_SIZE bytes of the I/O pool. */
	volatile unsigned char *ram, *dma;
	unsigned long ram_gpa, dma_gpa;
	int blk;		/* a virtio-blk device no driver uses, or -1 */
};

/* The user program (user.S) and its position-independent fault helpers. */
extern char user_prog[], user_debug[], user_write[], user_large[], user_large_write[], user_end[];

/* main.c: objects, slots and mappings, deleted when the tests are done. */
unsigned long abitest_obj(int type, int size_bits);	/* L4H_OBJ_*; 0 if none */
unsigned long abitest_slot(void);			/* an empty slot, or 0 */
/* Map `frame` at page `i` (< ABITEST_KPAGES) of a range of the kernel's
 * VSpace; NULL on failure. */
#define ABITEST_KPAGES		8
volatile void *abitest_map(unsigned long frame, int i);

/* sel4.c: 0 if every test passed. */
int abitest_run(struct abitest *t);

#endif

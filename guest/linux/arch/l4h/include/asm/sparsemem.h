/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __L4H_SPARSEMEM_H
#define __L4H_SPARSEMEM_H

/*
 * A section is a hotplug block (L4H_HP_SHIFT, 128 MiB, DESIGN.md §8.5), and
 * guest-physical space ends at L4H_GPA_END (64 GiB).  Plain numbers: this
 * is included before anything else (memhp.c checks them against l4h/abi.h).
 */
#define SECTION_SIZE_BITS	27
#define MAX_PHYSMEM_BITS	36

#endif

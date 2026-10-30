/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __L4H_VSPACE_H
#define __L4H_VSPACE_H

struct mm_struct;

void l4h_mm_init(struct mm_struct *mm);
unsigned long l4h_mm_activate(struct mm_struct *mm, u64 *gen);
/* Give up mm's VSpace; `may_sleep` if the caller can schedule. */
void l4h_mm_release(struct mm_struct *mm, bool may_sleep);
int l4h_map_fault(struct mm_struct *mm, unsigned long address);
void l4h_mm_flush_deferred(struct mm_struct *mm);
unsigned long l4h_mm_large_mappings(struct mm_struct *mm, unsigned long start, unsigned long end);
void l4h_vspace_init(void);
unsigned long l4h_vspace_get(void);
void l4h_vspace_put(unsigned long root);
void *l4h_kernel_va_get(unsigned long size);
void l4h_kernel_va_put(void *va);
unsigned long l4h_kernel_map_frame(unsigned long frame, unsigned long va);

#endif

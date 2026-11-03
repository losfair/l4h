// SPDX-License-Identifier: GPL-2.0
/*
 * load_unaligned_zeropad() for a word that crosses a page boundary
 * (x86's asm/word-at-a-time.h, guest/linux/patches/0015).
 */
#include <linux/export.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <asm/word-at-a-time.h>

static __always_inline unsigned long load_word(unsigned long addr)
{
	unsigned long ret;

	/* As x86's: an asm load is not instrumented, as the tail is not real data. */
	asm volatile("mov %[mem], %[ret]"
		     : [ret] "=r" (ret)
		     : [mem] "m" (*(unsigned long *)addr));
	return ret;
}

unsigned long l4h_load_unaligned_zeropad_cross(const void *addr)
{
	unsigned long a = (unsigned long)addr, next = PAGE_ALIGN(a);
	unsigned long ret;

	/* The bytes in the next page, when it is mapped. */
	if (l4h_nofault_begin(next, a + sizeof(long) - next)) {
		ret = load_word(a);
		l4h_nofault_end();
		return ret;
	}
	/*
	 * Otherwise the aligned word that ends the page, shifted down to
	 * addr: its bytes past the page end are zeroes, as x86's exception
	 * fixup returns them (ex_handler_zeropad()).
	 */
	return load_word(a & ~(sizeof(long) - 1)) >> (8 * (a & (sizeof(long) - 1)));
}
EXPORT_SYMBOL(l4h_load_unaligned_zeropad_cross);

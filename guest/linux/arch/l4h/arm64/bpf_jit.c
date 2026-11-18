// SPDX-License-Identifier: GPL-2.0-only
/*
 * Code patching for the arm64 BPF JIT (arch/arm64/net/bpf_jit_comp.c).
 * arm64 writes through a fixmap alias of read-only text; guest-kernel
 * memory is mapped writable and executable, so l4h writes in place and
 * makes the instruction cache coherent through seL4 (flush_icache_range).
 */

#include <linux/string.h>
#include <linux/uaccess.h>
#include <asm/byteorder.h>
#include <asm/cacheflush.h>
#include <asm/text-patching.h>

int aarch64_insn_read(void *addr, u32 *insnp)
{
	__le32 val;
	int ret = copy_from_kernel_nofault(&val, addr, sizeof(__le32));

	if (!ret)
		*insnp = le32_to_cpu(val);
	return ret;
}

/* One single-copy-atomic store: other vCPUs may run the instruction. */
int aarch64_insn_write(void *addr, u32 insn)
{
	if (!l4h_kernel_range_ok((unsigned long)addr, sizeof(__le32), true))
		return -EFAULT;
	WRITE_ONCE(*(__le32 *)addr, cpu_to_le32(insn));
	return 0;
}

/* New code, or the unused part of an image: no vCPU runs it yet. */
void *aarch64_insn_copy(void *dst, void *src, size_t len)
{
	if ((uintptr_t)dst & 0x3)
		return NULL;
	memcpy(dst, src, len);
	flush_icache_range((uintptr_t)dst, (uintptr_t)dst + len);
	return dst;
}

void *aarch64_insn_set(void *dst, u32 insn, size_t len)
{
	if ((uintptr_t)dst & 0x3)
		return NULL;
	memset32(dst, insn, len / 4);
	flush_icache_range((uintptr_t)dst, (uintptr_t)dst + len);
	return dst;
}

/*
 * The JIT only patches branches and NOPs, which the architecture lets one
 * CPU change while others run them, given the cache maintenance after.
 */
int aarch64_insn_patch_text_nosync(void *addr, u32 insn)
{
	int ret;

	if ((uintptr_t)addr & 0x3)
		return -EINVAL;
	ret = aarch64_insn_write(addr, insn);
	if (!ret)
		flush_icache_range((uintptr_t)addr, (uintptr_t)addr + sizeof(__le32));
	return ret;
}

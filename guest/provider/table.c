/* SPDX-License-Identifier: GPL-2.0 */
#include "private.h"

__attribute__((section(".provider"), used))
const struct l4h_provider l4h_provider_table = {
	.magic = L4H_PROVIDER_MAGIC,
	.version = L4H_PROVIDER_VERSION,
	.size = sizeof(struct l4h_provider),
#if defined(__x86_64__) && defined(CONFIG_VTX)
	.features = L4H_PROVIDER_VTX,
#endif
#define L4H_PROVIDER_OP(ret, name, args, call) .name = name,
#define L4H_PROVIDER_NORETURN(name, args, call) .name = name,
#include <l4h/provider-ops.h>
#undef L4H_PROVIDER_NORETURN
#undef L4H_PROVIDER_OP
};

void *memcpy(void *dst, const void *src, size_t size)
{
	unsigned char *d = dst;
	const unsigned char *s = src;
	while (size--)
		*d++ = *s++;
	return dst;
}

void *memset(void *dst, int value, size_t size)
{
	unsigned char *d = dst;
	while (size--)
		*d++ = value;
	return dst;
}

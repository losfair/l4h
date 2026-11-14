/* SPDX-License-Identifier: GPL-2.0 */
#ifndef L4H_PROVIDER_PRIVATE_H
#define L4H_PROVIDER_PRIVATE_H
#include <stdint.h>
#include <stddef.h>
#include <sel4/sel4.h>
#include <l4h/provider.h>

#define l4h_vcpus (l4h_provider_state()->vcpus)
#define l4h_bootinfo (l4h_provider_state()->bootinfo)
#define l4h_tsc_hz (l4h_provider_state()->tsc_hz)
#define printk (l4h_provider_state()->printk)
#define panic (l4h_provider_state()->panic)
#define l4h_deliver_events (l4h_provider_state()->deliver_events)
#define l4h_uctx_describe (l4h_provider_state()->describe_context)
#define VCPU_CAP(v, which) L4H_CPTR(L4H_SLOT_VCPU(v) + (which))
#define l4h_BUG_ON(c) do { \
	if (__builtin_expect(!!(c), 0)) \
		panic("l4h provider: %s:%d: %s\n", __FILE__, __LINE__, #c); \
} while (0)

void *memcpy(void *, const void *, size_t);
void *memset(void *, int, size_t);
#define L4H_PROVIDER_OP(ret, name, args, call) ret name args;
#define L4H_PROVIDER_NORETURN(name, args, call) void name args __attribute__((noreturn));
#include <l4h/provider-ops.h>
#undef L4H_PROVIDER_NORETURN
#undef L4H_PROVIDER_OP
#endif

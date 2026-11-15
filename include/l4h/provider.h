/* SPDX-License-Identifier: GPL-2.0 */
#ifndef L4H_PROVIDER_H
#define L4H_PROVIDER_H

#include <l4h/guest.h>

#define L4H_PROVIDER_MAGIC 0x315244565048344cull /* L4HPVDR1 */
#define L4H_PROVIDER_VERSION 1
#define L4H_PROVIDER_VTX (1ull << 0)

/* Native 64-bit C ABI. Slots are append-only and shared layouts are fixed
 * within a version; gp[] uses Linux's native register-array order. The host maps this
 * immutable code/table only in the guest kernel's VSpace. Microkernel types
 * and numbering never cross this boundary. */
struct l4h_provider {
	l4h_u64 magic, version, size, features;
#define L4H_PROVIDER_OP(ret, name, args, call) ret (*name) args;
#define L4H_PROVIDER_NORETURN(name, args, call) void (*name) args __attribute__((noreturn));
#include <l4h/provider-ops.h>
#undef L4H_PROVIDER_NORETURN
#undef L4H_PROVIDER_OP
};

/* Validate before the first indirect call. Unknown trailing slots are allowed;
 * every required entry must point into code after the complete descriptor. */
static inline int l4h_provider_valid(const struct l4h_provider *p, l4h_u64 size)
{
	if (size < sizeof(*p) || size > L4H_PROVIDER_MAX ||
	    p->magic != L4H_PROVIDER_MAGIC || p->version != L4H_PROVIDER_VERSION ||
	    p->size < sizeof(*p) || p->size > size)
		return 0;
#define L4H_PROVIDER_OP(ret, name, args, call) \
	if ((unsigned long)p->name < L4H_PROVIDER_VA + p->size || \
	    (unsigned long)p->name >= L4H_PROVIDER_VA + size) return 0;
#define L4H_PROVIDER_NORETURN(name, args, call) L4H_PROVIDER_OP(void, name, args, call)
#include <l4h/provider-ops.h>
#undef L4H_PROVIDER_NORETURN
#undef L4H_PROVIDER_OP
	return 1;
}

/* Private to one guest, shared by its vCPUs. The provider has no writable
 * global state. Callbacks run on the calling guest's stack and capabilities. */
struct l4h_provider_context {
	const struct l4h_bootinfo *bootinfo;
	struct l4h_vcpu *vcpus;
	unsigned long long tsc_hz;
	int (*printk)(const char *, ...);
	void (*panic)(const char *, ...) __attribute__((noreturn));
	void (*deliver_events)(int, unsigned long, unsigned long *);
	void (*describe_context)(unsigned long);
	void *secondary_entry;
	unsigned int console_seq, stray_once;
};

/* Reserve libsel4's TLS independently of its configured layout. x86 TLS
 * precedes TP; arm64 TLS follows a 16-byte TCB. The provider linker checks
 * that its TLS fits. Linux only uses the metadata after the reserved area. */
#define L4H_TLS_SIZE 128
struct l4h_tls {
#ifdef __aarch64__
	char tcb[16];
	char provider_tls[16];
#endif
	struct l4h_tls *self;
	struct l4h_vcpu *vcpu;
	long cpu;
	void *current;
	struct l4h_provider_context *provider;
	char pad[L4H_TLS_SIZE - 40
#ifdef __aarch64__
		 - 32
#endif
	];
};
struct l4h_tls_block {
#ifdef __aarch64__
	struct l4h_tls tls;
	char tbss[L4H_TLS_SIZE];
#else
	char tbss[L4H_TLS_SIZE];
	struct l4h_tls tls;
#endif
} __attribute__((aligned(64)));

static inline struct l4h_tls *l4h_tls(void)
{
	struct l4h_tls *t;
#ifdef __aarch64__
	__asm__ volatile("mrs %0, tpidr_el0" : "=r"(t));
#else
	__asm__("movq %%fs:0, %0" : "=r"(t));
#endif
	return t;
}

static inline struct l4h_provider_context *l4h_provider_state(void)
{
	return l4h_tls()->provider;
}

#endif

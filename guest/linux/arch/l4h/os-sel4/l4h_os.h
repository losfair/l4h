/* SPDX-License-Identifier: GPL-2.0 */
#ifndef L4H_OS_H
#define L4H_OS_H
#include <l4h/provider.h>
extern struct l4h_tls_block l4h_tls_blocks[L4H_MAX_VCPUS];
extern struct l4h_provider_context l4h_provider_context;
extern const struct l4h_provider *l4h_provider_ops;
void l4h_provider_setup(const struct l4h_bootinfo *bi);
void l4h_linux_main(void);
void l4h_secondary_main(int cpu);
void l4h_boot(const struct l4h_bootinfo *bi);
void l4h_secondary_boot(long cpu);
int _printk(const char *, ...);
void panic(const char *, ...) __attribute__((noreturn));
#define L4H_PROVIDER_OP(ret, name, args, call) ret name args;
#define L4H_PROVIDER_NORETURN(name, args, call) void name args __attribute__((noreturn));
#include <l4h/provider-ops.h>
#undef L4H_PROVIDER_NORETURN
#undef L4H_PROVIDER_OP
#define VCPU_CAP(v, which) L4H_CPTR(L4H_SLOT_VCPU(v) + (which))
#endif

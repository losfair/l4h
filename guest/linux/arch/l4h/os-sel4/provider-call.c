/* SPDX-License-Identifier: GPL-2.0 */
#include "l4h_os.h"
#include <generated/user_constants.h>
#include <l4h/provider-registers.h>
#ifdef L4H_GP_IP
_Static_assert(HOST_IP == L4H_GP_IP, "provider register ABI: IP");
#endif
#ifdef L4H_GP_SP
_Static_assert(HOST_SP == L4H_GP_SP, "provider register ABI: SP");
#endif
#ifdef L4H_GP_ORIG_AX
_Static_assert(HOST_ORIG_AX == L4H_GP_ORIG_AX, "provider register ABI: ORIG_AX");
#endif
#ifdef L4H_GP_TLS
_Static_assert(HOST_TLS == L4H_GP_TLS, "provider register ABI: TLS");
#endif
#ifdef L4H_GP_R15
_Static_assert(HOST_R15 == L4H_GP_R15, "provider register ABI: R15");
#endif
#ifdef L4H_GP_R14
_Static_assert(HOST_R14 == L4H_GP_R14, "provider register ABI: R14");
#endif
#ifdef L4H_GP_R13
_Static_assert(HOST_R13 == L4H_GP_R13, "provider register ABI: R13");
#endif
#ifdef L4H_GP_R12
_Static_assert(HOST_R12 == L4H_GP_R12, "provider register ABI: R12");
#endif
#ifdef L4H_GP_BP
_Static_assert(HOST_BP == L4H_GP_BP, "provider register ABI: BP");
#endif
#ifdef L4H_GP_BX
_Static_assert(HOST_BX == L4H_GP_BX, "provider register ABI: BX");
#endif
#ifdef L4H_GP_R11
_Static_assert(HOST_R11 == L4H_GP_R11, "provider register ABI: R11");
#endif
#ifdef L4H_GP_R10
_Static_assert(HOST_R10 == L4H_GP_R10, "provider register ABI: R10");
#endif
#ifdef L4H_GP_R9
_Static_assert(HOST_R9 == L4H_GP_R9, "provider register ABI: R9");
#endif
#ifdef L4H_GP_R8
_Static_assert(HOST_R8 == L4H_GP_R8, "provider register ABI: R8");
#endif
#ifdef L4H_GP_AX
_Static_assert(HOST_AX == L4H_GP_AX, "provider register ABI: AX");
#endif
#ifdef L4H_GP_CX
_Static_assert(HOST_CX == L4H_GP_CX, "provider register ABI: CX");
#endif
#ifdef L4H_GP_DX
_Static_assert(HOST_DX == L4H_GP_DX, "provider register ABI: DX");
#endif
#ifdef L4H_GP_SI
_Static_assert(HOST_SI == L4H_GP_SI, "provider register ABI: SI");
#endif
#ifdef L4H_GP_DI
_Static_assert(HOST_DI == L4H_GP_DI, "provider register ABI: DI");
#endif
#ifdef L4H_GP_EFLAGS
_Static_assert(HOST_EFLAGS == L4H_GP_EFLAGS, "provider register ABI: EFLAGS");
#endif


int l4h_debug_user;
struct l4h_tls_block l4h_tls_blocks[L4H_MAX_VCPUS];
struct l4h_vcpu l4h_vcpus[L4H_MAX_VCPUS];
const struct l4h_bootinfo *l4h_bootinfo;
unsigned long long l4h_tsc_hz;
const struct l4h_provider *l4h_provider_ops;
struct l4h_provider_context l4h_provider_context;

extern char l4h_secondary_entry[];
extern void l4h_uctx_describe(unsigned long);

void l4h_provider_setup(const struct l4h_bootinfo *bi)
{
	const struct l4h_provider *p = (const void *)L4H_PROVIDER_VA;
	/* Logging is unavailable until the immutable bootstrap table is checked. */
	if (bi->magic != L4H_BOOTINFO_MAGIC || bi->abi_version != L4H_ABI_VERSION ||
	    bi->provider_va != L4H_PROVIDER_VA || !l4h_provider_valid(p, bi->provider_size))
		__builtin_trap();
	if (bi->nr_ept_roots && !(p->features & L4H_PROVIDER_VTX))
		__builtin_trap();
	l4h_provider_ops = p;
	l4h_provider_context = (struct l4h_provider_context) {
		.bootinfo = bi, .vcpus = l4h_vcpus, .tsc_hz = bi->tsc_hz,
		.printk = _printk, .panic = panic, .deliver_events = l4h_deliver_events,
		.describe_context = l4h_uctx_describe, .secondary_entry = l4h_secondary_entry,
	};
}

/* Preserve the Linux/module symbols and their calling convention. */
#define L4H_PROVIDER_OP(ret, name, args, call) \
	ret name args { return l4h_provider_ops->name call; }
#define L4H_PROVIDER_NORETURN(name, args, call) void name args { l4h_provider_ops->name call; __builtin_unreachable(); }
#include <l4h/provider-ops.h>
#undef L4H_PROVIDER_NORETURN
#undef L4H_PROVIDER_OP

const int l4h_pt_level_obj[L4H_NR_PT_LEVELS] = { L4H_OBJ_PT, L4H_OBJ_PD, L4H_OBJ_PDPT };
const int l4h_pt_level_shift[L4H_NR_PT_LEVELS] = { 21, 30, 39 };

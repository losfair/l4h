/* SPDX-License-Identifier: GPL-2.0 */
/* The native Linux register-array ABI (sys/user.h on x86_64, pt_regs on arm64). */
#ifdef __aarch64__
#define L4H_GP_IP 32
#define L4H_GP_SP 31
#define L4H_GP_ORIG_AX 34
#define L4H_GP_TLS 35
#else
#define L4H_GP_R15 0
#define L4H_GP_R14 1
#define L4H_GP_R13 2
#define L4H_GP_R12 3
#define L4H_GP_BP 4
#define L4H_GP_BX 5
#define L4H_GP_R11 6
#define L4H_GP_R10 7
#define L4H_GP_R9 8
#define L4H_GP_R8 9
#define L4H_GP_AX 10
#define L4H_GP_CX 11
#define L4H_GP_DX 12
#define L4H_GP_SI 13
#define L4H_GP_DI 14
#define L4H_GP_ORIG_AX 15
#define L4H_GP_IP 16
#define L4H_GP_EFLAGS 18
#define L4H_GP_SP 19
#endif

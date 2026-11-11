/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __L4H_VERMAGIC_H
#define __L4H_VERMAGIC_H

/*
 * spin_unlock() is inlined into modules (asm/qspinlock.h).  One built for
 * the plain unlock would release a paravirtual lock without waking its
 * waiter or taking it out of the table of blocked waiters, and the kernel's
 * release string does not tell the two apart: the version magic does.
 */
#ifdef CONFIG_UML_ARM64
#define L4H_VERMAGIC_ISA	"aarch64 "
#else
#define L4H_VERMAGIC_ISA	""
#endif

#ifdef CONFIG_PARAVIRT_SPINLOCKS
#define MODULE_ARCH_VERMAGIC	L4H_VERMAGIC_ISA "pvspinlocks"
#else
#define MODULE_ARCH_VERMAGIC	L4H_VERMAGIC_ISA
#endif

#endif

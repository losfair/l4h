# SPDX-License-Identifier: GPL-2.0

ccflags-y += -I $(srctree)/arch/x86/kvm -I $(srctree)/arch/l4h/kvm \
	     -include $(srctree)/arch/l4h/kvm/compat.h

obj-y += vmx.o ept.o fpu.o

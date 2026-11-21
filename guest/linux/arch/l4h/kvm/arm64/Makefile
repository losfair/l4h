# SPDX-License-Identifier: GPL-2.0

LINUXINCLUDE := -I$(srctree)/arch/l4h/kvm/arm64/include $(LINUXINCLUDE)
ccflags-y += -I $(srctree)/arch/arm64/kvm -I $(srctree)/arch/arm64/kvm/hyp/include \
	     -I $(srctree)/arch/arm64/include -I $(srctree)/arch/l4h/kvm/arm64 \
	     -include $(srctree)/arch/l4h/kvm/arm64/compat.h

obj-y += init.o stage2.o vcpu.o vgic.o stubs.o

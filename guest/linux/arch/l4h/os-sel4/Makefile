# SPDX-License-Identifier: GPL-2.0
#
# os-sel4: the lowest layer of the l4h guest kernel, which talks to seL4.

obj-y := head.o sys.o boot.o events.o user.o

ifeq ($(SUBARCH),aarch64)
obj-y := head-arm64.o sys.o boot.o events.o user.o
endif

obj-$(CONFIG_KVM) += kvm.o
SEL4_OBJS := sys.o boot.o events.o user.o kvm.o

include $(srctree)/arch/l4h/scripts/Makefile.rules

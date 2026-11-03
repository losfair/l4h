# SPDX-License-Identifier: GPL-2.0
# Pieces of arch/x86 used by the l4h guest kernel.

ccflags-y += -I$(srctree)/arch
asflags-y += -I$(srctree)/arch

obj-y := csum-partial_64.o memcpy_64.o memmove_64.o memset_64.o word-at-a-time.o
obj-$(CONFIG_MODULES) += module.o

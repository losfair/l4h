# SPDX-License-Identifier: GPL-2.0
#
# os-sel4: the lowest layer of the l4h guest kernel, which talks to seL4.

obj-y := head.o boot.o provider-call.o
ifeq ($(SUBARCH),aarch64)
obj-y := head-arm64.o boot.o provider-call.o
endif

# SPDX-License-Identifier: GPL-2.0
# The l4h ABI test (main.c), a module built against the guest kernel's tree.
obj-m += l4h_abitest.o
l4h_abitest-y := main.o sel4.o user.o

# This diagnostic deliberately exercises raw microkernel invocations. Its
# private headers are supplied by the test runner, outside the common SDK.
sel4_flags := -O2 -g -std=gnu11 -ffreestanding -fno-common -fno-strict-aliasing \
    -fno-stack-protector -fno-pic -fno-pie -mcmodel=large \
    -fno-asynchronous-unwind-tables -fno-delete-null-pointer-checks \
    -Wall -Wno-unused-function -nostdinc -isystem $(shell $(CC) -print-file-name=include) \
    -I$(L4H_SEL4_INCLUDE) -I$(srctree)/l4h/abi -I$(srctree)/arch/l4h/include/shared \
    -I$(objtree)/include -D__L4H_OS__
ifeq ($(SUBARCH),aarch64)
sel4_flags += -mgeneral-regs-only -mno-outline-atomics
else
sel4_flags += -m64 -mno-red-zone -mno-sse -mno-mmx -mno-sse2 -mno-avx
endif
$(obj)/sel4.%: c_flags = -Wp,-MD,$(depfile) $(sel4_flags)

# SPDX-License-Identifier: GPL-2.0
#
# ARCH=l4h: Linux guest kernel for the l4h hypervisor (derived from ARCH=um).
#
# The kernel only needs the versioned l4h ABI; microkernel headers are
# confined to guest/provider and never affect Linux's configuration.
L4H_ABI_INCLUDE ?= $(wildcard $(srctree)/l4h/abi)

SUBARCH ?= x86_64
ifeq ($(SUBARCH),aarch64)
include $(srctree)/arch/l4h/arm64/Makefile.arch
else
KBUILD_DEFCONFIG := defconfig

ARCH_DIR := arch/l4h
HOST_DIR := arch/x86
HEADER_ARCH := x86

ifeq ($(L4H_ABI_INCLUDE),)
$(error L4H_ABI_INCLUDE must point at the directory containing l4h/abi.h)
endif

SHELL := bash

SHARED_HEADERS	:= $(ARCH_DIR)/include/shared
ARCH_INCLUDE	:= -I$(srctree)/$(SHARED_HEADERS) -I$(srctree)/$(SHARED_HEADERS)/skas
ARCH_INCLUDE	+= -I$(srctree)/$(ARCH_DIR)/x86/shared
ARCH_INCLUDE	+= -I$(L4H_ABI_INCLUDE)
KBUILD_CPPFLAGS += -I$(srctree)/$(ARCH_DIR)/x86

# The guest kernel lives in ring 3 at 0x60000000; modules are loaded far
# above it, so use the large code model like UML.
KBUILD_CFLAGS += -mcmodel=large -fno-builtin -m64 -mno-red-zone \
		 -mno-sse -mno-mmx -mno-sse2 -mno-3dnow -mno-avx \
		 -D__arch_um__ -D__arch_l4h__ $(ARCH_INCLUDE) \
		 -Dlongjmp=kernel_longjmp -Dsetjmp=kernel_setjmp
KBUILD_AFLAGS += -m64 $(ARCH_INCLUDE)
KBUILD_CPPFLAGS += -m64
KBUILD_LDFLAGS += -m elf_x86_64
KBUILD_RUSTFLAGS += --target=$(objtree)/scripts/target.json
KBUILD_RUSTFLAGS += -Ccode-model=large -Crelocation-model=static -Cno-redzone=y
KBUILD_RUSTFLAGS += -Ctarget-feature=-sse,-sse2
CHECKFLAGS += -m64 -D__x86_64__

START := 0x60000000
ELF_ARCH := i386:x86-64
ELF_FORMAT := elf64-x86-64

KBUILD_CPPFLAGS += -I$(srctree)/$(HOST_DIR)/include \
		   -I$(srctree)/$(HOST_DIR)/include/uapi \
		   -I$(objtree)/$(HOST_DIR)/include/generated \
		   -I$(objtree)/$(HOST_DIR)/include/generated/uapi

# Host-libc flags, only for the build-time generator x86/user-offsets.c.
USER_CFLAGS = $(patsubst -I%,,$(filter-out -mcmodel=large -nostdinc -fno-builtin \
		-D__arch_um__ -D__arch_l4h__,$(KBUILD_CFLAGS))) \
		-D_FILE_OFFSET_BITS=64 -idirafter $(srctree)/include \
		-idirafter $(objtree)/include -D__KERNEL__ -D__UM_HOST__

core-y += $(ARCH_DIR)/x86/
core-$(CONFIG_KVM) += $(HOST_DIR)/kvm/ $(ARCH_DIR)/kvm/
# x86 SIMD crypto (AES-NI, ...): needs CONFIG_L4H_X86_SIMD, selected per algorithm.
core-$(CONFIG_CRYPTO) += $(HOST_DIR)/crypto/
# The x86-64 BPF JIT, with x86/bpf_jit.c.
core-$(CONFIG_BPF_JIT) += $(HOST_DIR)/net/

PHONY += linux

all: vmlinux

archheaders:
	$(Q)$(MAKE) -f $(srctree)/Makefile ARCH=$(HEADER_ARCH) asm-generic archheaders

archprepare:
	$(Q)$(MAKE) $(build)=$(ARCH_DIR)/x86 include/generated/user_constants.h

export LDS_START      := $(START)
export LDS_ELF_ARCH   := $(ELF_ARCH)
export LDS_ELF_FORMAT := $(ELF_FORMAT)

LDFLAGS_vmlinux := -z noexecstack -z max-page-size=4096 --no-warn-rwx-segments

archclean:
	$(Q)$(MAKE) -f $(srctree)/Makefile ARCH=$(HEADER_ARCH) clean

endif
export HEADER_ARCH SUBARCH USER_CFLAGS

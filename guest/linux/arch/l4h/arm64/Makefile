# SPDX-License-Identifier: GPL-2.0
obj-y := setjmp.o core.o syscalls.o syscall_table.o ptrace.o signal.o vdso.o vma.o neon.o
$(obj)/user-offsets.s: c_flags = -Wp,-MD,$(depfile) -O2 -ffreestanding -mgeneral-regs-only -I$(srctree)/include
targets += user-offsets.s
include/generated/user_constants.h: $(obj)/user-offsets.s FORCE
	$(call filechk,offsets,__USER_CONSTANT_H__)
include $(srctree)/arch/l4h/scripts/Makefile.rules

$(obj)/vdso.o: $(obj)/vdso.so
quiet_cmd_vdso = VDSO    $@
      cmd_vdso = $(CC) -nostdlib -shared -Wl,--hash-style=both -Wl,-soname=linux-vdso.so.1 -Wl,-z,max-page-size=4096 -Wl,-T,$(src)/vdso.lds -o $@ $(src)/sigreturn.S
targets += vdso.so
$(obj)/vdso.so: $(src)/sigreturn.S $(src)/vdso.lds FORCE
	$(call if_changed,vdso)

obj-$(CONFIG_MODULES) += module.o
obj-$(CONFIG_BPF_JIT) += bpf_jit.o

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Regenerate include/asm/pgtable-hwdef.h from arm64's.

Usage: gen-pgtable-hwdef.py <linux>/arch/arm64/include/asm/pgtable-hwdef.h > include/asm/pgtable-hwdef.h

Every definition is wrapped in #ifndef, and the page table geometry names
the guest kernel's own asm/pgtable.h defines are left out: arch/arm64/kvm
sees arm64's hardware page table definitions without redefining the
guest kernel's.
"""
import re
import sys

OWN = {"PUD_SIZE", "PUD_SHIFT", "PUD_MASK", "PTRS_PER_PUD", "PTRS_PER_PTE", "PTRS_PER_PMD",
       "PTRS_PER_PGD", "PMD_SIZE", "PMD_SHIFT", "PMD_MASK", "PGDIR_SIZE", "PGDIR_SHIFT",
       "PGDIR_MASK"}

src = open(sys.argv[1]).read().split("\n")
out = ["/* SPDX-License-Identifier: GPL-2.0-only */",
       "/*",
       " * arm64's pgtable-hwdef.h for arch/arm64/kvm in the l4h guest kernel,",
       " * generated from it by wrapping every definition in #ifndef: the guest",
       " * kernel's own page table macros (asm/pgtable.h) win.  Regenerate with",
       " * arch/l4h/kvm/arm64/gen-pgtable-hwdef.py when Linux is updated.",
       " */",
       "#ifndef __L4H_KVM_ASM_PGTABLE_HWDEF_H",
       "#define __L4H_KVM_ASM_PGTABLE_HWDEF_H"]
i = 0
while i < len(src):
    line = src[i]
    if line.startswith("#ifndef __ASM_PGTABLE_HWDEF_H") or line.startswith("#define __ASM_PGTABLE_HWDEF_H"):
        i += 1
        continue
    m = re.match(r"#define\s+([A-Za-z0-9_]+)", line)
    if m:
        block = [line]
        while block[-1].endswith("\\"):
            i += 1
            block.append(src[i])
        if m.group(1) not in OWN:
            out += ["#ifndef " + m.group(1)] + block + ["#endif"]
    else:
        out.append(line)
    i += 1
for j in range(len(out) - 1, -1, -1):
    if out[j].startswith("#endif"):
        out[j] = "#endif /* __L4H_KVM_ASM_PGTABLE_HWDEF_H */"
        break
sys.stdout.write("\n".join(out))

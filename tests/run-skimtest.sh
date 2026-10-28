#!/usr/bin/env bash
# Exercise the shipped SKIM variant with a CPU lacking RDCL_NO, PCID,
# INVPCID and x2APIC. Host/guest binaries use the ordinary libsel4 build.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
export L4H_KERNEL_VARIANT=skim-xapic-nopcid
export L4H_RELEASE=0
L4H_SKIM_WINDOW=ON L4H_LAPIC_MODE=XAPIC L4H_PCID=OFF "$root/tools/build-kernel.sh"
export L4H_QEMU_CPU=host,vendor=GenuineIntel,-vmx,+invtsc,-arch-capabilities,-pcid,-invpcid,-x2apic
python3 "$root/tests/skim-qemu.py"
"$root/tests/run-abitest.sh"
"$root/tests/run-selftest.sh" 1
"$root/tests/run-selftest.sh" 4
"$root/tests/run-uefitest.sh"
"$root/tests/run-biostest.sh"
# Cover a CPU enumerating ARCH_CAPABILITIES but explicitly lacking RDCL_NO.
L4H_QEMU_CPU=host,vendor=GenuineIntel,-vmx,+invtsc,+arch-capabilities,-rdctl-no,-pcid,-invpcid,-x2apic \
    python3 "$root/tests/skim-qemu.py"
# Release binaries suppress guest serial output. This test records its
# result on disk and exercises guest creation, faults and shutdown too.
L4H_RELEASE=1 L4H_SKIM_WINDOW=ON L4H_LAPIC_MODE=XAPIC L4H_PCID=OFF "$root/tools/build-kernel.sh"
L4H_RELEASE=1 "$root/tests/run-logtest.sh"

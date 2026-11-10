# SPDX-License-Identifier: GPL-2.0-only
# shellcheck shell=bash
# Source after setting root. Shared architecture selection for guest tests.
# $l4h_profile is the cargo profile directory the host builds to.
source "$root/tools/host-profile.sh"
l4h_test_slow=1
case "${L4H_ARCH:-x86_64}" in
    x86_64)
        l4h_linux_out=$root/build/linux-l4h
        l4h_ctl=$root/tools/l4hctl/target/release/l4hctl
        l4h_cc=gcc
        l4h_objcopy=objcopy
        l4h_host_build=$root/tools/build-host.sh
        l4h_qemu=$root/tools/run-qemu.sh
        l4h_target=x86_64-sel4-roottask
        ;;
    aarch64)
        l4h_test_slow=3
        l4h_linux_out=$root/build/linux-l4h-aarch64
        l4h_ctl=$root/tools/l4hctl/target/aarch64-unknown-linux-gnu/release/l4hctl
        l4h_cc=aarch64-linux-gnu-gcc
        l4h_objcopy=aarch64-linux-gnu-objcopy
        l4h_host_build=$root/tools/build-host-aarch64.sh
        l4h_qemu=$root/tools/run-qemu-aarch64.sh
        l4h_target=aarch64-sel4-roottask
        ;;
    *) echo "unsupported L4H_ARCH: $L4H_ARCH" >&2; exit 1 ;;
esac

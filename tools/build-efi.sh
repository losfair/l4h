#!/usr/bin/env bash
# Build the shipped l4h UEFI applications, one per seL4 variant plus FL4, into
# build/efi/l4h-VARIANT.efi. The seL4 variants share their host components
# and ABI provider. Linux and its SDK are separate release artifacts; this
# script never builds them. The seL4 kernels
# differ in options that seL4 fixes at build time:
#   generic       x2APIC, PCID: QEMU/KVM and GCE
#   xapic-nopcid  xAPIC, no PCID: machines whose firmware leaves x2APIC off
#                 and CPUs without PCID (Latitude.sh m4.metal.small)
#   skim-xapic-nopcid  SKIM, xAPIC, no PCID: Meltdown-affected CPUs
# Each application also holds the multikernel shim and the variant's
# kernels for its 8 slots (tools/build-mkshim.sh), which GRUB boots when
# the EFI system partition has /l4h/l4h-mk.conf (DESIGN.md §11.4).
# L4H_RELEASE=1 builds release kernels and host components.
# build/efi/l4h-bios-x86_64.tar.xz holds l4h's files for BIOS machines
# (tools/mkbios.sh), with each variant's kernel as kernel-VARIANT.elf; the
# Linux installer installs one as kernel.elf.
# build/efi/l4h-debug-x86_64.tar.xz holds the same build unstripped (root,
# the components, each variant's kernel, its slot kernels as
# kernel-VARIANT-sK.elf, the shim and ABI provider), to
# decode host fault addresses. Guest symbols come from build-guest.sh.
# FL4 has its own microkernel, host and ABI provider (build-fl4-efi.sh),
# accepting the same independently released guest package,
# packaged as l4h-fl4.efi and l4h-debug-fl4-x86_64.tar.xz, without a shim.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/reproducible-env.sh"
export L4H_ARCH=x86_64 L4H_GUEST_EXTERNAL=1
export L4H_VERSION=$("$root/tools/version.sh")
export L4H_GUEST_RELEASE=${L4H_GUEST_RELEASE:-$L4H_VERSION}
out=$root/build/efi
mkdir -p "$out"
# The host components build to the cargo profile's directory.
source "$root/tools/host-profile.sh"
variants=(
    "generic X2APIC ON OFF"
    "xapic-nopcid XAPIC OFF OFF"
    "skim-xapic-nopcid XAPIC OFF ON"
)
for v in "${variants[@]}"; do
    read -r name lapic pcid skim <<<"$v"
    L4H_VTX=ON L4H_KERNEL_VARIANT=$name L4H_LAPIC_MODE=$lapic L4H_PCID=$pcid L4H_SKIM_WINDOW=$skim \
        "$root/tools/build-kernel.sh" >"$out/kernel-$name.log" 2>&1 \
        || { tail -20 "$out/kernel-$name.log"; exit 1; }
    L4H_VTX=ON L4H_KERNEL_VARIANT=$name L4H_LAPIC_MODE=$lapic L4H_PCID=$pcid L4H_SKIM_WINDOW=$skim \
        "$root/tools/build-mkshim.sh" 8 >"$out/mkshim-$name.log" 2>&1 \
        || { tail -20 "$out/mkshim-$name.log"; exit 1; }
done
# libsel4 does not depend on these options: build the host against the
# default kernel build, as the other scripts do.
L4H_KERNEL_VARIANT= L4H_VTX=ON "$root/tools/build-kernel.sh" >"$out/kernel.log" 2>&1
export SEL4_PREFIX=$root/build/sel4
"$root/tools/build-host.sh"
debug=$(mktemp -d)
trap 'rm -rf "$debug"' EXIT
mkdir "$debug/l4h-debug-x86_64"
cp "$root/host/target/x86_64-sel4-roottask/$l4h_profile/l4h-root.elf" \
    "$root"/host/target/x86_64-sel4/$l4h_profile/l4h-{vmmgr,vmm,blkd,netd,trustd,memd,logd,usbd}.elf \
    "$debug/l4h-debug-x86_64/"
cp "$SEL4_PREFIX/guest-provider/provider.bin" "$debug/l4h-debug-x86_64/guest-provider.bin"
cp "$SEL4_PREFIX/guest-provider/provider.elf" "$debug/l4h-debug-x86_64/guest-provider.elf"
for v in "${variants[@]}"; do
    read -r name _ <<<"$v"
    # mkefi.sh leaves multikernel boot out when the shim is missing: every
    # shipped application has it, with all 8 slots.
    mk=$root/build/mkshim-$name
    for f in l4h-mkshim.elf kernel-s{0..7}.elf; do
        [ -f "$mk/$f" ] || { echo "$mk/$f: missing" >&2; exit 1; }
    done
    L4H_MKSHIM=$mk "$root/tools/mkefi.sh" "$out/l4h-$name.efi" \
        "$root/host/target/x86_64-sel4-roottask/$l4h_profile/l4h-root.elf" \
        "$root/build/sel4-$name/bin/kernel.elf"
    cp "$root/build/sel4-$name/bin/kernel.elf" "$debug/l4h-debug-x86_64/kernel-$name.elf"
    for k in {0..7}; do
        cp "$mk/kernel-s$k.elf" "$debug/l4h-debug-x86_64/kernel-$name-s$k.elf"
    done
done
# The shim does not depend on the variant.
cp "$root/build/mkshim-generic/l4h-mkshim.elf" "$debug/l4h-debug-x86_64/"
l4h_tar -C "$debug" -cJf "$out/l4h-debug-x86_64.tar.xz" l4h-debug-x86_64
bios=$debug/l4h-bios-x86_64
# Multikernel boot is UEFI-only in the release (the installer's BIOS
# package has one kernel per variant).
L4H_MKSHIM= "$root/tools/mkbios.sh" "$bios" "$root/host/target/x86_64-sel4-roottask/$l4h_profile/l4h-root.elf" >/dev/null
rm "$bios/kernel.elf"
for v in "${variants[@]}"; do
    read -r name _ <<<"$v"
    cp "$root/build/sel4-$name/bin/kernel.elf" "$bios/kernel-$name.elf"
done
l4h_tar -C "$debug" -cJf "$out/l4h-bios-x86_64.tar.xz" l4h-bios-x86_64
for f in l4h-debug-x86_64.tar.xz l4h-bios-x86_64.tar.xz; do
    echo "$out/$f: $(( $(stat -c %s "$out/$f") >> 10 )) KiB"
done
# Host manifests bind the payloads to their provider ABI. The default guest
# release is a recommendation; installers may select another compatible one.
for name in generic xapic-nopcid skim-xapic-nopcid; do
    python3 "$root/tools/install/artifacts.py" host "$out/l4h-host-$name.json" \
        --release "$L4H_VERSION" --guest-release "$L4H_GUEST_RELEASE" \
        --provider "$SEL4_PREFIX/guest-provider/provider.bin" --abi-header "$root/include/l4h/abi.h" \
        --payload "$out/l4h-$name.efi" --payload "$out/l4h-bios-x86_64.tar.xz"
done
"$root/tools/build-fl4-efi.sh"

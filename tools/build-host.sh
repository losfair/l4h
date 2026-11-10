#!/usr/bin/env bash
# Build the host components and the root task that embeds them, without
# their debug information, which only takes memory there; the unstripped
# ELFs stay in host/target/x86_64-sel4/{debug,release}.  dom0 is not
# built in (see host/l4h-root/build.rs).  Extra arguments go to the root
# task's cargo build.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
export L4H_VERSION=$("$root/tools/version.sh")
cd "$root/host"
# L4H_RELEASE=1 builds the shipped, optimised components (the cargo release
# profile); otherwise the dev profile (tools/host-profile.sh).
source "$root/tools/host-profile.sh"
out=$root/host/target/x86_64-sel4/$l4h_profile
mkdir -p "$out/stripped"
strip() {
    for c in "$@"; do
        # Replace the copy only when it changes: whatever embeds it rebuilds
        # when it does.
        objcopy --strip-debug "$out/l4h-$c.elf" "$out/stripped/l4h-$c.elf.new"
        cmp -s "$out/stripped/l4h-$c.elf.new" "$out/stripped/l4h-$c.elf" \
            && rm "$out/stripped/l4h-$c.elf.new" || mv "$out/stripped/l4h-$c.elf.new" "$out/stripped/l4h-$c.elf"
        export "L4H_$(echo $c | tr a-z A-Z)_ELF=$out/stripped/l4h-$c.elf"
    done
}
cargo build -q "${l4h_cargo_profile[@]}" --target x86_64-sel4 -p l4h-vmm -p l4h-blkd -p l4h-netd -p l4h-trustd -p l4h-memd -p l4h-logd -p l4h-usbd
strip vmm blkd netd trustd memd logd usbd
# vmmgr embeds l4h-vmm, root embeds vmmgr.
cargo build -q "${l4h_cargo_profile[@]}" --target x86_64-sel4 -p l4h-vmmgr
strip vmmgr
cargo build -q "${l4h_cargo_profile[@]}" -p l4h-root "$@"

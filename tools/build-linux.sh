#!/usr/bin/env bash
# Build the l4h guest kernel (Linux 6.18 + arch/l4h).
# Usage: build-linux.sh [make targets...]   (default: vmlinux)
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
src=$root/build/linux-6.18
kemu=$root/third_party/kemu
arch=${L4H_ARCH:-x86_64}
case "$arch" in
    x86_64) out=$root/build/linux-l4h; sel4=$root/build/sel4 ;;
    aarch64) out=$root/build/linux-l4h-aarch64; sel4=$root/build/sel4-aarch64 ;;
    *) echo "unsupported L4H_ARCH: $arch" >&2; exit 1 ;;
esac
if [ ! -d "$src" ]; then
    echo "missing $src: extract linux-6.18.y there (see DESIGN.md §14)" >&2
    exit 1
fi
if [ ! -f "$kemu/overlay/kernel/kemu/Kconfig" ]; then
    echo "missing kemu: run git submodule update --init third_party/kemu" >&2
    exit 1
fi
ln -sfn "$root/guest/linux/arch/l4h" "$src/arch/l4h"
# Out-of-tree patches outside arch/l4h.  $src/.l4h-patches keeps a copy of
# each patch applied: from the first one that changed or went away, the
# applied patches are reverted (last first) and the current ones applied.
# Each patch is tried with --dry-run first, so one that does not apply
# leaves the tree as the copies describe instead of half patched, and
# without fuzz, so a stable update cannot move a hunk unnoticed.  The
# x86_64 and aarch64 builds share the tree: one patches it at a time.
shopt -s nullglob
applied=$src/.l4h-patches
mkdir -p "$applied"
exec 9>"$src/.l4h-patches.lock"
flock 9
# Trees patched before the copies were kept have only stamps.
for s in "$src"/.l4h-applied-*.patch; do
    n=${s##*/.l4h-applied-}
    p=$root/guest/linux/patches/$n
    if [ ! -e "$p" ] || ! patch -d "$src" -p1 -R --dry-run -s -f < "$p" >/dev/null; then
        echo "$src: $n changed since it was applied: extract linux-6.18.y there again" >&2
        exit 1
    fi
    cp "$p" "$applied/$n"
    rm "$s"
done
# Refresh upstream patch context for the stable Linux version we build.
# Keep the imported submodule untouched.
mkdir -p "$src/.l4h-kemu-patches"
rsync -a --checksum --delete "$kemu/patches/" "$src/.l4h-kemu-patches/"
patch -d "$src/.l4h-kemu-patches" -p1 -F0 -s < "$root/guest/linux/kemu-patches.patch"
have=("$applied"/*.patch)
want=("$src"/.l4h-kemu-patches/*.patch "$root"/guest/linux/patches/*.patch)
# Number the combined series so upstream and l4h patches have unique,
# ordered snapshot names. Old, unnumbered snapshots are reverted once.
names=()
for ((i = 0; i < ${#want[@]}; i++)); do
    printf -v name '%04d-%s' "$i" "${want[$i]##*/}"
    names+=("$name")
done
overlay_hash=$(cd "$kemu" && git ls-files -z overlay | xargs -0 sha256sum | sha256sum)
keep=0
while [ $keep -lt ${#have[@]} ] && [ $keep -lt ${#want[@]} ] &&
      cmp -s "${have[$keep]}" "${want[$keep]}" &&
      [ "${have[$keep]##*/}" = "${names[$keep]}" ]; do
    keep=$((keep + 1))
done
# A tree extracted again over the old one keeps the copies: a kept patch
# that applies again is not in the tree.
for ((i = 0; i < keep; i++)); do
    if patch -d "$src" -p1 --forward -F0 --dry-run -s -f < "${have[$i]}" >/dev/null 2>&1; then
        echo "$src: $(basename "${have[$i]}") is recorded as applied but is not:" \
            "remove $applied or extract linux-6.18.y afresh" >&2
        exit 1
    fi
done
for ((i = ${#have[@]} - 1; i >= keep; i--)); do
    patch -d "$src" -p1 -R -F0 -f -s --dry-run < "${have[$i]}"
    patch -d "$src" -p1 -R -F0 -f -s < "${have[$i]}"
    rm "${have[$i]}"
done
# The overlay consists of new files; architecture adaptations live in
# arch/l4h, so refreshing it does not require reapplying the kernel patches.
if [ "$keep" = 0 ] || [ ! -f "$src/.l4h-kemu-overlay" ] ||
   [ "$(cat "$src/.l4h-kemu-overlay")" != "$overlay_hash" ]; then
    for dir in kernel/kemu arch/x86/kemu rust/kemu_core; do
        mkdir -p "$src/$dir"
        rsync -a --checksum --delete --exclude target/ --exclude Cargo.lock \
            "$kemu/overlay/$dir/" "$src/$dir/"
    done
    rsync -a --checksum "$kemu"/overlay/include/linux/kemu*.h "$src/include/linux/"
    rsync -a --checksum "$kemu/overlay/arch/x86/include/asm/kemu.h" "$src/arch/x86/include/asm/"
    echo "$overlay_hash" >"$src/.l4h-kemu-overlay"
fi
for ((i = keep; i < ${#want[@]}; i++)); do
    p=${want[$i]}
    patch -d "$src" -p1 --forward -F0 -s --dry-run < "$p"
    patch -d "$src" -p1 --forward -F0 -s < "$p"
    cp "$p" "$applied/${names[$i]}"
done
exec 9>&-
mkdir -p "$out"
mk=(make -C "$src" O="$out" ARCH=l4h SUBARCH="$arch"
    L4H_SEL4_INCLUDE="$sel4/libsel4/include"
    L4H_ABI_INCLUDE="$root/include")
if [ "$arch" = aarch64 ]; then
    mk+=(CROSS_COMPILE="${CROSS_COMPILE:-aarch64-linux-gnu-}")
fi
# L4H_LINUX_CC overrides the compiler, e.g. "ccache gcc" in CI.
if [ -n "${L4H_LINUX_CC:-}" ]; then
    mk+=(CC="$L4H_LINUX_CC")
fi
# Regenerate the config when the defconfig changed.
if [ ! -f "$out/.config" ] || [ "$root/guest/linux/arch/l4h/configs/defconfig" -nt "$out/.config" ]; then
    if [ "$arch" = x86_64 ]; then
        "${mk[@]}" rustavailable
    fi
    "${mk[@]}" defconfig
    if [ "$arch" = x86_64 ] && ! grep -q '^CONFIG_KEMU=y' "$out/.config"; then
        echo "the default x86_64 guest kernel requires CONFIG_KEMU=y (check the Rust toolchain)" >&2
        exit 1
    fi
fi
"${mk[@]}" -j"${L4H_JOBS:-$(nproc)}" "${@:-vmlinux}"

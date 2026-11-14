#!/usr/bin/env bash
# Build a frozen FL4 worktree for l4h development, without changing seL4's
# default build or the release variants. L4H_FL4_SOURCE names that worktree.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/prepare-fl4.sh"
out=$root/build/kernel-fl4
prefix=$root/build/sel4-fl4
export PATH=$root/.venv/bin:$PATH
debug=ON
[ "${L4H_RELEASE:-0}" = 1 ] && debug=OFF
cmake -G Ninja -S "$root/kernel/fl4" -B "$out" \
    -DFL4_SOURCE="$src" \
    -C "$root/kernel/configs/l4h-x86_64.cmake" \
    -DKernelVTX=OFF -DKernelDebugBuild="$debug" \
    -DKernelRetypeFanOutLimit=256 \
    -DLibSel4PrintInvocationErrors=0
ninja -C "$out"
mkdir -p "$prefix/bin" "$prefix/libsel4/include"
cp "$out/kernel/kernel.elf" "$prefix/bin/kernel.elf"
# Resolve FL4's relative interface/header symlinks into the installed tree.
for d in \
    "$src/libsel4/include" \
    "$src/libsel4/arch_include/x86" \
    "$src/libsel4/sel4_arch_include/x86_64" \
    "$src/libsel4/sel4_plat_include/pc99" \
    "$src/libsel4/mode_include/64" \
    "$out/libsel4/include" \
    "$out/libsel4/arch_include/x86" \
    "$out/libsel4/sel4_arch_include/x86_64" \
    "$out/kernel/gen_config" \
    "$out/libsel4/gen_config" \
    "$out/libsel4/autoconf"; do
    cp -rL "$d/." "$prefix/libsel4/include/"
done
# rust-sel4 parses both API sections even in an MCS-only build. FL4 prunes
# the unused master section; an empty one preserves every generated ID.
python3 - "$prefix/libsel4/include/api/syscall.xml" <<'PY'
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

path = Path(sys.argv[1])
text = path.read_text()
if ET.fromstring(text).find("api-master") is None:
    path.write_text(text.replace("<syscalls>", "<syscalls>\n    <api-master/>"))
PY
printf '%s\n' "$base" >"$prefix/fl4-revision"
echo "FL4 installed to $prefix (debug build: $debug)"

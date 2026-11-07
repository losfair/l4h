#!/usr/bin/env bash
# Run a supplied Linux x86_64 Node binary and its shared libraries in l4h.
# Usage: run-nodetest.sh /path/to/node [vcpus]
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
node=$(realpath "${1:?usage: run-nodetest.sh /path/to/node [vcpus]}")
out=$root/build/guest
mkdir -p "$out"
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
mkdir -p "$dir/bin"
cp "$node" "$dir/bin/node"
# Keep the interpreter and library paths reported by the host loader.
ldd "$node" >"$dir/ldd.txt" 2>&1 || {
    grep -q 'not a dynamic executable\|statically linked' "$dir/ldd.txt" || { cat "$dir/ldd.txt"; exit 1; }
}
! grep -q 'not found' "$dir/ldd.txt" || { cat "$dir/ldd.txt"; exit 1; }
while read -r lib; do
    mkdir -p "$dir$(dirname "$lib")"
    cp -L "$lib" "$dir$lib"
done < <(awk '{ for (i=1; i<=NF; i++) if ($i ~ /^\//) print $i }' "$dir/ldd.txt")
rm "$dir/ldd.txt"
"$root/tools/mkinitramfs.sh" "$out/nodetest-base.cpio.gz" "$root/tests/guest/init-nodetest" \
    "$root/tests/guest/nodetest.js" >/dev/null
# Compress the large Node binary separately at level 1 for fast rebuilds.
(cd "$dir" && find . | cpio -o -H newc --quiet | gzip -1) >"$out/nodetest-node.cpio.gz"
cat "$out/nodetest-base.cpio.gz" "$out/nodetest-node.cpio.gz" >"$out/nodetest.cpio.gz"
L4H_DOM0_MEM_MB=${L4H_DOM0_MEM_MB:-2048} L4H_DOM0_VCPUS=${2:-4} \
    "$root/tools/run-dom0.sh" "$out/nodetest.cpio.gz" "console=hvc0" "${NODETEST_TIMEOUT:-300}" \
    | grep -E 'NODETEST|segfault|panic|SC failed|object not bound' || true
grep -q 'NODETEST: PASS' "$root/build/qemu.log"
! grep -q 'NODETEST: FAIL\|deschedule .* SC failed\|SchedContext UnbindObject: object not bound' "$root/build/qemu.log" || exit 1

#!/usr/bin/env bash
# Rebuild every shipped artifact from scratch in a different checkout path.
# First run tools/build-release.sh; an optional argument names its artifact dir.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/reproducible-env.sh"
source "$root/tools/source-pins.sh"
reference=$(realpath "${1:-$root/build/efi}")
export L4H_VERSION=$("$root/tools/version.sh")
revision=$(git -C "$root" rev-parse HEAD)
git -C "$root" diff --quiet HEAD -- ':!kernel/seL4' ':!third_party' || {
    echo 'Commit source changes before checking reproducibility' >&2; exit 1;
}
work=$(mktemp -d "$root/build/reproducibility.XXXXXX")
# Keep a failed rebuild for diagnosis, including its logs and changed files.
trap 'status=$?; if [ "$status" = 0 ]; then rm -rf "$work"; else echo "Rebuild retained at $work" >&2; fi' EXIT
rebuild=$work/source
git clone -q --shared --no-checkout "$root" "$rebuild"
git -C "$rebuild" checkout -q --detach "$revision"
for sub in kernel/seL4 third_party/rust-sel4 third_party/sddf third_party/kemu; do
    git -c protocol.file.allow=always -C "$rebuild" submodule update --init --reference "$root/$sub" -- "$sub"
done
ln -s "$root/.venv" "$rebuild/.venv"
mkdir -p "$rebuild/build/tmp"
tarball=$root/build/dl/linux-$LINUX_VERSION.tar.xz
echo "$LINUX_SHA256  $tarball" | sha256sum -c --quiet
tar -C "$rebuild/build" -xJf "$tarball"
mv "$rebuild/build/linux-$LINUX_VERSION" "$rebuild/build/linux-6.18"
export TMPDIR=$rebuild/build/tmp
umask 077
"$rebuild/tools/build-release.sh" >"$work/rebuild.log" 2>&1 || {
    tail -60 "$work/rebuild.log" >&2; exit 1;
}
diff -u "$reference/SHA256SUMS" "$rebuild/build/efi/SHA256SUMS"
echo 'REPRODUCIBLE: all published artifacts match the independent rebuild'

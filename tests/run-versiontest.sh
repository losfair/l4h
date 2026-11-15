#!/usr/bin/env bash
# Build metadata checks, without seL4 or QEMU. Use a disposable repository
# so release tags and worktrees never change the developer's checkout.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
unset L4H_VERSION
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
# TMPDIR may be inside a checkout. The uninitialized fixture must not
# discover that parent repository when testing the "unknown" version.
export GIT_CEILING_DIRECTORIES="$tmp"
mkdir -p "$tmp/source/tools"
cp "$root/tools/version.sh" "$tmp/source/tools/"
cd "$tmp/source"
version=$PWD/tools/version.sh
check() {
    local actual
    actual=$("$version")
    [ "$actual" = "$1" ] || { echo "VERSIONTEST: expected $1, got $actual" >&2; exit 1; }
}

check unknown
L4H_VERSION=v2026.10.1 check v2026.10.1
git init -q
git config user.name 'Version test'
git config user.email 'version-test@example.invalid'
git add tools/version.sh
git commit -qm initial
check "$(git rev-parse --short HEAD)"
git tag v2026.10.1
check v2026.10.1
printf 'development\n' > source
git add source
git commit -qm development
check "v2026.10.1-1-g$(git rev-parse --short HEAD)"
git tag -am release v2026.10.2
check v2026.10.2
git tag unrelated
check v2026.10.2
printf 'changed\n' >> source
check v2026.10.2-dirty
L4H_VERSION=v2026.10.1 check v2026.10.1

# The helper locates its own checkout, even when invoked from elsewhere.
git worktree add -q --detach "$tmp/worktree" HEAD
version=$tmp/worktree/tools/version.sh
check v2026.10.2

# The control API adds the kernel from the selected installed prefix,
# independently of the release tag or checkout location.
mkdir -p "$tmp/host-out" "$tmp/prefix/libsel4/include/sel4"
touch "$tmp/prefix/libsel4/include/sel4/config.h"
# Exercise the actual build script with Cargo's environment, while keeping
# this metadata test independent of the real provider compiler and libsel4.
# Provider compilation is covered by the host builds and provider checks.
mkdir -p "$tmp/provider-project/host/l4h-vmmgr" "$tmp/provider-project/tools"
cat > "$tmp/provider-project/tools/build-guest-provider.sh" <<'PROVIDER'
#!/bin/sh
set -eu
[ "$L4H_ARCH" = x86_64 ]
[ -f "$SEL4_PREFIX/libsel4/include/sel4/config.h" ]
mkdir -p "$SEL4_PREFIX/guest-provider"
printf 'metadata test provider\n' > "$SEL4_PREFIX/guest-provider/provider.bin"
PROVIDER
chmod +x "$tmp/provider-project/tools/build-guest-provider.sh"
rustc +stable --edition=2024 "$root/host/l4h-vmmgr/build.rs" -o "$tmp/host-build"
check_host_version() {
    local actual
    actual=$(env -u L4H_VMM_ELF OUT_DIR="$tmp/host-out" SEL4_PREFIX="$tmp/prefix" \
        CARGO_MANIFEST_DIR="$tmp/provider-project/host/l4h-vmmgr" CARGO_CFG_TARGET_ARCH=x86_64 \
        "$tmp/host-build")
    grep -Fxq "cargo:rustc-env=L4H_HOST_VERSION=$1" <<<"$actual" \
        || { echo "VERSIONTEST: missing host version $1 in $actual" >&2; exit 1; }
    grep -Fxq "cargo:rustc-env=L4H_GUEST_PROVIDER=$tmp/prefix/guest-provider/provider.bin" <<<"$actual"
    grep -Fxq 'metadata test provider' "$tmp/prefix/guest-provider/provider.bin"
}
check_host_version 'unknown (seL4)'
L4H_VERSION=v2026.10.1 check_host_version 'v2026.10.1 (seL4)'
printf '%s\n' frozen-fl4-revision >"$tmp/prefix/fl4-revision"
check_host_version 'unknown (FL4)'
L4H_VERSION= check_host_version 'unknown (FL4)'
L4H_VERSION=v2026.10.1 check_host_version 'v2026.10.1 (FL4)'
L4H_VERSION=v2026.10.2-dirty check_host_version 'v2026.10.2-dirty (FL4)'
echo 'VERSIONTEST: PASS'

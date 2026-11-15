#!/usr/bin/env bash
# Shared build metadata and archive policy. Source after setting root.
export LC_ALL=C TZ=UTC
umask 022
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
    SOURCE_DATE_EPOCH=$(git -C "$root" show -s --format=%ct HEAD)
fi
case "$SOURCE_DATE_EPOCH" in
    ''|*[!0-9]*) echo 'SOURCE_DATE_EPOCH must be a nonnegative Unix timestamp' >&2; exit 1 ;;
esac
export SOURCE_DATE_EPOCH
KBUILD_BUILD_TIMESTAMP=$(date -u -d "@$SOURCE_DATE_EPOCH" '+%a %b %d %T %Y')
export KBUILD_BUILD_TIMESTAMP
export KBUILD_BUILD_USER=l4h KBUILD_BUILD_HOST=build KBUILD_BUILD_VERSION=1
# Keep scratch files with the checkout unless the caller chooses another directory.
export TMPDIR=${TMPDIR:-$root/build/tmp}
mkdir -p "$TMPDIR"
l4h_prefix_map="-ffile-prefix-map=$root=/l4h"
case " ${CFLAGS:-} " in
    *" $l4h_prefix_map "*) ;;
    *) export CFLAGS="${CFLAGS:+$CFLAGS }$l4h_prefix_map" ;;
esac
# Command-line config arrays extend the crate's flags (in particular the
# shim's linker script and the host's -Zunstable-options).
l4h_cargo=(--locked --config "build.rustflags=$(python3 - "$root" "${CARGO_HOME:-$HOME/.cargo}" "${RUSTUP_HOME:-$HOME/.rustup}" <<'PY'
import json, sys
print(json.dumps([f"--remap-path-prefix={path}={dest}" for path, dest in
                  zip(sys.argv[1:], ("/l4h", "/cargo", "/rustup"))]))
PY
)")

l4h_tar() {
    tar --sort=name --format=gnu --mtime="@$SOURCE_DATE_EPOCH" \
        --owner=0 --group=0 --numeric-owner --mode='a=rX,u+w' "$@"
}

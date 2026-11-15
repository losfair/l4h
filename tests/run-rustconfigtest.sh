#!/usr/bin/env bash
# A config change must refresh bindgen's constants, even when its C inputs
# do not use the option. Restoring the config must restore the kernel bytes.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/reproducible-env.sh"
source "$root/tools/guest-env.sh"
log=$root/build/rustconfigtest.log
: > "$log"
linux() {
    "$root/tools/build-linux.sh" "$@" >>"$log" 2>&1 || { tail -50 "$log"; exit 1; }
}
linux vmlinux modules
config=$l4h_linux_out/.config
bindings=$l4h_linux_out/rust/bindings/bindings_generated.rs
grep -qx '# CONFIG_MODULE_SIG_ALL is not set' "$config"
expected=$(sha256sum < "$l4h_linux_out/vmlinux")
saved=$(mktemp)
cp "$config" "$saved"
trap 'cp "$saved" "$config"; rm "$saved"' EXIT
# This option is unused by the binding generators' C inputs. Building
# only rust/ exercises the dependency without installing/signing modules.
"$root/build/linux-6.18/scripts/config" --file "$config" --enable MODULE_SIG_ALL
linux olddefconfig
linux rust/
if ! grep -qE 'CONFIG_MODULE_SIG_ALL[[:space:]]*:[[:space:]]*u32[[:space:]]*=[[:space:]]*1[[:space:]]*;' "$bindings"; then
    echo 'RUSTCONFIGTEST: FAIL missing enabled configuration constant' >&2
    exit 1
fi
cp "$saved" "$config"
linux vmlinux modules
if grep -qE 'CONFIG_MODULE_SIG_ALL[[:space:]]*:' "$bindings"; then
    echo 'RUSTCONFIGTEST: FAIL stale configuration constant' >&2
    exit 1
fi
if [ "$(sha256sum < "$l4h_linux_out/vmlinux")" != "$expected" ]; then
    echo 'RUSTCONFIGTEST: FAIL kernel changed after restoring its configuration' >&2
    exit 1
fi
echo 'RUSTCONFIGTEST: PASS'

#!/usr/bin/env bash
# Build a small busybox initramfs for l4h guests.
# Usage: mkinitramfs.sh <out.cpio.gz> [init-script] [extra binaries for /bin...]
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/reproducible-env.sh"
out=$1
init=${2:-}
shift 2 || shift $#
busybox=${L4H_BUSYBOX:-$(command -v busybox)}
if [ "${L4H_ARCH:-x86_64}" = aarch64 ] && [ -z "${L4H_BUSYBOX:-}" ]; then
    busybox=$root/build/busybox-aarch64/usr/bin/busybox
    [ -f "$busybox" ] || { echo "Set L4H_BUSYBOX to a static AArch64 busybox, or run tools/ci-setup.sh aarch64" >&2; exit 1; }
fi
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
mkdir -p "$dir"/{bin,sbin,etc,proc,sys,dev,tmp,root,mnt,usr/bin,usr/sbin,var/run}
cp "$busybox" "$dir/bin/busybox"
for app in $(busybox --list); do
    [ "$app" = busybox ] || ln -sf busybox "$dir/bin/$app"
done
# The kernel runs /sbin/poweroff and /sbin/reboot for host shutdown requests.
for app in poweroff reboot halt; do
    ln -sf ../bin/busybox "$dir/sbin/$app"
done
if [ -n "$init" ]; then
    cp "$init" "$dir/init"
else
    cat > "$dir/init" <<'INIT'
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev 2>/dev/null
echo "l4h: init running, kernel $(uname -r) on $(nproc) vCPU(s)"
exec /bin/sh
INIT
fi
chmod +x "$dir/init"
for extra in "$@"; do
    cp "$extra" "$dir/bin/"
done
chmod 755 "$dir"
find "$dir" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
(cd "$dir" && find . -print0 | sort -z | cpio --null -o -H newc --reproducible --owner=0:0 --quiet | gzip -n -9) > "$out"
echo "initramfs: $out ($(stat -c %s "$out") bytes)"

#!/usr/bin/env bash
# Build Xen and a minimal Linux dom0 that partition a large machine into l4h
# instances, each an HVM guest with its own passed-through NIC (DESIGN.md
# §11.2).  Everything comes from Debian 13 packages, downloaded into
# build/xen/debs; libraries the packages need but do not ship are taken from
# this machine, which must therefore run Debian 13 too.  Outputs, in
# build/xen:
#   xen           the hypervisor, a multiboot image
#   vmlinuz       dom0's kernel (Debian's, which supports dom0)
#   dom0.cpio.gz  dom0's initramfs: busybox, the xl toolstack, QEMU as the
#                 device model, OvmfXen (tools/build-ovmf-xen.sh) as
#                 /usr/lib/xen/boot/ovmf.fd, the Xen driver modules and
#                 tools/xen/dom0-init as /init
# Usage: build-xen-dom0.sh [file...]
#   files to put in dom0's /etc/l4h-xen: xl configurations (*.cfg), which
#   dom0 starts at boot, and an optional script "run" it then executes.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
out=$root/build/xen
export PATH=$PATH:/usr/sbin:/sbin   # depmod
xenver=4.20
mkdir -p "$out/debs"
kver=$(apt-cache depends linux-image-amd64 | sed -n 's/.*Depends: linux-image-//p' | head -1)
[ -n "$kver" ] || { echo "no linux-image-amd64 in the apt cache" >&2; exit 1; }
pkgs=(xen-hypervisor-$xenver-amd64 xen-utils-$xenver xen-utils-common xenstore-utils
    libxenmisc$xenver libxencall1 libxendevicemodel1 libxenevtchn1 libxenforeignmemory1
    libxengnttab1 libxenstore4 libxentoollog1 libxentoolcore1 libxenhypfs1 libyajl2
    qemu-system-xen qemu-system-data seabios busybox-static "linux-image-$kver")
missing=()
for p in "${pkgs[@]}"; do
    compgen -G "$out/debs/${p}_*.deb" >/dev/null || missing+=("$p")
done
[ ${#missing[@]} -eq 0 ] || (cd "$out/debs" && apt-get download "${missing[@]}")
[ -e "$out/OvmfXen.fd" ] || "$root/tools/build-ovmf-xen.sh" >/dev/null

dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
pkgroot=$dir/pkg
mkdir -p "$pkgroot"
for p in "${pkgs[@]}"; do
    dpkg-deb -x "$(compgen -G "$out/debs/${p}_*.deb" | tail -1)" "$pkgroot"
done
zcat "$pkgroot/boot/xen-$xenver-amd64.gz" > "$out/xen"
cp "$pkgroot/boot/vmlinuz-$kver" "$out/vmlinuz"

# The initramfs: usr-merged like Debian, with busybox in /bin.
fs=$dir/fs
mkdir -p "$fs"/{bin,sbin,etc,proc,sys,dev,tmp,run,var/lib/xen,var/log/xen,usr/lib/x86_64-linux-gnu,usr/lib64,usr/libexec,usr/share,etc/l4h-xen}
ln -s usr/lib "$fs/lib"
ln -s usr/lib64 "$fs/lib64"
cp "$pkgroot/usr/bin/busybox" "$fs/bin/busybox"
for app in $("$fs/bin/busybox" --list); do
    [ -e "$fs/bin/$app" ] || ln -s busybox "$fs/bin/$app"
done
ln -s ../bin/busybox "$fs/sbin/modprobe"
cp -a "$pkgroot/usr/lib/xen-$xenver" "$fs/usr/lib/"
cp -a "$pkgroot"/usr/lib/x86_64-linux-gnu/lib{xen,xl,yajl}* "$fs/usr/lib/x86_64-linux-gnu/"
cp -a "$pkgroot/usr/bin/xenstore"* "$fs/bin/"
cp -a "$pkgroot/usr/libexec/xen-qemu-system-i386" "$fs/usr/libexec/"
cp -a "$pkgroot/usr/share/qemu" "$pkgroot/usr/share/seabios" "$fs/usr/share/"
mkdir -p "$fs/usr/lib/xen/boot"
cp "$out/OvmfXen.fd" "$fs/usr/lib/xen/boot/ovmf.fd"
cp -a "$pkgroot/etc/xen" "$fs/etc/"
# The rest of the libraries, from this machine: the closure of the binaries'
# dependencies that the packages above do not provide.
for bin in "$fs/usr/lib/xen-$xenver/bin/"{xl,xenstored,xenconsoled,xen-init-dom0,libxl-save-helper} \
           "$fs/bin/xenstore" "$fs/usr/libexec/xen-qemu-system-i386"; do
    LD_LIBRARY_PATH=$fs/usr/lib/x86_64-linux-gnu ldd "$bin" \
        | awk '/=> \// { print $3 } /^\t\/.*ld-linux/ { print $1 }'
done | sort -u | while read -r lib; do
    [ -e "$fs/usr/lib/x86_64-linux-gnu/$(basename "$lib")" ] && continue
    case $lib in
        */ld-linux-x86-64.so.2) mkdir -p "$fs/usr/lib64"; cp -L "$lib" "$fs/usr/lib64/" ;;
        *) cp -L "$lib" "$fs/usr/lib/x86_64-linux-gnu/" ;;
    esac
done
[ -e "$fs/usr/lib64/ld-linux-x86-64.so.2" ] || { echo "no dynamic loader found" >&2; exit 1; }

# The Xen driver modules dom0 needs, and their dependencies, uncompressed
# for busybox's modprobe.
mods=$pkgroot/usr/lib/modules/$kver
[ -d "$mods" ] || { echo "no modules in linux-image-$kver" >&2; exit 1; }
# The package leaves modules.dep to its postinst.
depmod -b "$pkgroot/usr" "$kver"
want="xen-evtchn xen-gntdev xen-gntalloc xen-privcmd xenfs xen-pciback virtio_blk"
need=$(for m in $want; do
    awk -v m="$m" -F: '{ n = $1; sub(/.*\//, "", n); sub(/\.ko.*/, "", n); gsub(/-/, "_", n)
        t = m; gsub(/-/, "_", t)
        if (n == t) { print $1; s = $2; gsub(/^ +/, "", s); if (s != "") print s } }' \
        "$mods/modules.dep" | tr ' ' '\n'
done | sort -u)
[ -n "$need" ] || { echo "no modules found in $mods" >&2; exit 1; }
for m in $need; do
    mkdir -p "$fs/usr/lib/modules/$kver/$(dirname "$m")"
    case $m in
        *.xz) xz -dc "$mods/$m" > "$fs/usr/lib/modules/$kver/${m%.xz}" ;;
        *) cp "$mods/$m" "$fs/usr/lib/modules/$kver/$m" ;;
    esac
done
cp "$mods"/modules.{order,builtin,builtin.modinfo} "$fs/usr/lib/modules/$kver/"
depmod -b "$fs/usr" "$kver"

cp "$root/tools/xen/dom0-init" "$fs/init"
chmod +x "$fs/init"
for f in "$@"; do
    cp "$f" "$fs/etc/l4h-xen/"
done
(cd "$fs" && find . | cpio -o -H newc --quiet | gzip -6) > "$out/dom0.cpio.gz"
echo "$out/dom0.cpio.gz: $(( $(stat -c %s "$out/dom0.cpio.gz") >> 20 )) MiB, kernel $kver"

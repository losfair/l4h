#!/usr/bin/env bash
# Turn the images of an x86_64 Cuttlefish build of Android (the
# aosp_cf_x86_64_only_phone-img-*.zip of ci.android.com, unpacked) into
# what an l4h guest boots: an initramfs and one disk, a GPT with
#   misc      the bootloader message
#   frp       the persistent data block (factory reset protection), which
#             system_server keeps OEM unlocking in
#   metadata  ext4, for vold's metadata encryption keys
#   odm       l4h's ODM partition: Cuttlefish's, and an init script that
#             puts Android's errors on the console and leaves out the
#             sensors of Cuttlefish's host (l4h.rc)
#   super     super.img: system, system_ext, product, vendor and their
#             _dlkm partitions, of slot _a (and an odm, which this one
#             replaces)
#   userdata  ext4, mapped by vold through dm-default-key
# which first-stage init finds by name (androidboot.boot_devices).  The
# disk of an earlier run is kept, but for its odm, unless super.img has
# changed: DATA=0 makes a new one.
#
# The initramfs is what a bootloader loads: the vendor ramdisk
# (vendor_boot.img), the generic one (init_boot.img), then an archive of
# l4h's that replaces in the vendor ramdisk
#   - the first-stage fstab: the same partitions, without AVB (nothing is
#     verified: the device is unlocked);
#   - the modules first-stage init loads, built for another kernel, with
#     those of the kernel in <modules dir> (lib/modules/<release>) that
#     the display needs: virtio_gpu (l4h-vmm's) and what it depends on;
# and a bootconfig with the vendor's androidboot.* and what Cuttlefish's
# launcher adds for a guest that renders in software (SwiftShader).
# Usage: mkandroid.sh <image dir> <modules dir> <out dir>
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
img=$(realpath "$1")
mods=$(realpath "$2")
out=$3
for f in super.img init_boot.img vendor_boot.img; do
    [ -f "$img/$f" ] || { echo "$img/$f: not a Cuttlefish image" >&2; exit 1; }
done
mkdir -p "$out"
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
"$root/tools/android-image.py" vendor-boot "$img/vendor_boot.img" "$dir/vendor"
"$root/tools/android-image.py" ramdisk "$img/init_boot.img" "$dir/generic.ramdisk"

fstab=cf.ext4.cts
mkdir -p "$dir/l4h/first_stage_ramdisk/system/etc" "$dir/l4h/lib/modules"
cat > "$dir/l4h/first_stage_ramdisk/system/etc/fstab.$fstab" <<'EOF'
system      /system      erofs ro wait,logical,first_stage_mount,slotselect
system      /system      ext4  ro wait,logical,first_stage_mount,slotselect
/dev/block/by-name/metadata /metadata ext4 nodev,noatime,nosuid wait,first_stage_mount
/dev/block/by-name/odm /odm erofs ro wait,first_stage_mount
product     /product     erofs ro wait,logical,first_stage_mount,slotselect
system_ext  /system_ext  erofs ro wait,logical,first_stage_mount,slotselect
vendor      /vendor      erofs ro wait,logical,first_stage_mount,slotselect
vendor_dlkm /vendor_dlkm erofs ro wait,logical,first_stage_mount,slotselect
odm_dlkm    /odm_dlkm    erofs ro wait,logical,first_stage_mount,slotselect
system_dlkm /system_dlkm erofs ro wait,logical,first_stage_mount,slotselect
EOF
# virtio_gpu and its dependencies, in the order modprobe would load them.
python3 - "$mods" "$dir/l4h/lib/modules" virtio_gpu <<'PY'
import os, shutil, sys
src, dst, want = sys.argv[1], sys.argv[2], sys.argv[3:]
deps = {}
for line in open(os.path.join(src, 'modules.dep')):
    mod, _, rest = line.partition(':')
    deps[mod] = rest.split()
byname = {os.path.basename(m)[:-3].replace('-', '_'): m for m in deps}
order = []
def visit(m):
    if m in order:
        return
    for d in deps[m]:
        visit(d)
    order.append(m)
for w in want:
    visit(byname[w])
with open(os.path.join(dst, 'modules.dep'), 'w') as f:
    for m in order:
        shutil.copy(os.path.join(src, m), dst)
        f.write(os.path.basename(m) + ':' + ''.join(' ' + os.path.basename(d) for d in deps[m]) + '\n')
with open(os.path.join(dst, 'modules.load'), 'w') as f:
    f.write(''.join(os.path.basename(m) + '\n' for m in order))
for name in ('modules.alias', 'modules.softdep', 'modules.options', 'modules.blocklist'):
    open(os.path.join(dst, name), 'w').close()
PY
# Owned by root, as the ramdisks it overlays are: the kernel applies the
# owner and mode of a directory that is already there too.
chmod -R u=rwX,go=rX "$dir/l4h"
(cd "$dir/l4h" && find . -mindepth 1 | cpio -o -H newc -R 0:0 --quiet | gzip -9) > "$dir/l4h.cpio.gz"

# androidboot.* in a bootconfig: its text, size and checksum
# (little-endian), then the magic, at the end of the initramfs.
python3 - "$dir/vendor/bootconfig" "$dir/bootconfig" "$fstab" <<'PY'
import struct, sys
props = {
    # virtio-l4h is the platform device all virtio-l4h disks hang off.
    'boot_devices': 'virtio-l4h',
    'slot_suffix': '_a',
    'force_normal_boot': '1',
    'fstab_suffix': sys.argv[3],
    'dynamic_partitions': 'true',
    'verifiedbootstate': 'orange',
    'vbmeta.device_state': 'unlocked',
    'selinux': 'permissive',
    'console': 'hvc0',
    'serialno': 'l4h0',
    # Rendering in the guest: ANGLE on SwiftShader (pastel), buffers from
    # minigbm, shown on the virtio-gpu (DRM), as Cuttlefish's
    # guest_swiftshader mode does; its framebuffers are BGRA, all that
    # virtio-gpu takes.
    'hardware.gralloc': 'minigbm',
    'hardware.hwcomposer': 'ranchu',
    'hardware.hwcomposer.display_finder_mode': 'drm',
    'hardware.hwcomposer.display_framebuffer_format': 'bgra',
    'hardware.egl': 'angle',
    'hardware.vulkan': 'pastel',
    'hardware.guest_hwui_renderer': 'skiagl',
    'opengles.version': '196609',
    'cpuvulkan.version': '4202496',
    'lcd_density': '320',
    'vendor.apex.com.android.hardware.graphics.composer':
        'com.android.hardware.graphics.composer.ranchu',
    # KeyMint and Gatekeeper in the guest: there is no host to keep keys.
    'vendor.apex.com.android.hardware.keymint': 'com.android.hardware.keymint.rust_nonsecure',
    'vendor.apex.com.android.hardware.gatekeeper': 'com.android.hardware.gatekeeper.nonsecure',
    # The camera HAL with emulated cameras, not V4L2 ones.
    'vendor.apex.com.google.emulated.camera.provider.hal':
        'com.google.emulated.camera.provider.hal',
    # Not the HALs that talk to Cuttlefish's host over serial ports, which
    # stop without one, and whose services system_server would wait for:
    # an APEX named here is not activated, no file being "none".
    'vendor.apex.com.google.cf.oemlock': 'none',
    'vendor.apex.com.android.hardware.uwb': 'none',
    'vendor.apex.com.google.cf.nfc': 'none',
    'vendor.apex.com.google.cf.bt': 'none',
    'vendor.apex.com.google.cf.rild': 'none',
    'vendor.apex.com.android.hardware.threadnetwork': 'none',
    # What Cuttlefish's launcher gives HALs that would serve its host: a
    # vsock port for the lights HAL's (below 1024 it may not bind).
    'vsock_lights_port': '6900',
    'setupwizard_mode': 'DISABLED',
    'enable_bootanimation': '0',
    'hw_timeout_multiplier': '3',
}
vendor = open(sys.argv[1], 'rb').read().rstrip(b'\0').decode()
lines = [l for l in vendor.splitlines()
         if l.strip() and l.split('=')[0].strip().removeprefix('androidboot.') not in props]
lines += [f'androidboot.{k} = "{v}"' for k, v in props.items()]
bc = ('\n'.join(lines) + '\n').encode() + b'\0'
bc += b'\0' * (-len(bc) % 4)
open(sys.argv[2], 'wb').write(bc + struct.pack('<II', len(bc), sum(bc)) + b'#BOOTCONFIG\n')
PY
# The ramdisks are legacy LZ4, whose frames end with the data or a zero
# frame length: without one, the kernel would read the next archive as
# LZ4 frames.
{ cat "$dir/vendor/ramdisk" "$dir/generic.ramdisk"; printf '\0\0\0\0'
  cat "$dir/l4h.cpio.gz" "$dir/bootconfig"; } > "$out/initrd.img"

# A new disk is made under another name and renamed once complete, so an
# interrupted run does not leave half a disk to be kept; and made again
# when super.img is not the one it was made from.
disk=$out/disk.img
src=$(stat -c '%s %Y' "$img/super.img")
if [ "${DATA:-1}" = 0 ] || [ ! -f "$disk" ] || [ "$(cat "$disk.src" 2>/dev/null)" != "$src" ]; then
    rm -f "$disk" "$disk.src"
    new=$disk.new
    rm -f "$new"
    super=$(( $("$root/tools/android-image.py" size "$img/super.img") / 512 ))
    data=$(( $(numfmt --from=iec "${L4H_ANDROID_DATA:-8G}") / 512 ))
    # 1 MiB of misc and of frp, 16 MiB of metadata and of odm, from 1 MiB;
    # 1 MiB at the end for the backup GPT.
    misc=2048 frp=$((misc + 2048)) meta=$((frp + 2048)) odm=$((meta + 32768)) sup=$((odm + 32768))
    ud=$((sup + super))
    truncate -s $(( (ud + data + 2048) * 512 )) "$new"
    sfdisk -q -X gpt "$new" <<EOF
start=$misc, size=2048, name="misc"
start=$frp, size=2048, name="frp"
start=$meta, size=32768, name="metadata"
start=$odm, size=32768, name="odm"
start=$sup, size=$super, name="super"
start=$ud, size=$data, name="userdata"
EOF
    mkfs.ext4 -q -L metadata -E offset=$((meta * 512)) "$new" 16M
    "$root/tools/android-image.py" unsparse "$img/super.img" "$new" $((sup * 512))
    mkfs.ext4 -q -L userdata -O encrypt,quota,verity -E offset=$((ud * 512)) "$new" $((data / 2))k
    mv "$new" "$disk"
    echo "$src" > "$disk.src"
fi

# l4h's odm: Cuttlefish's files, labelled as the platform's policy labels
# /odm, and l4h.rc.
part() {
    sfdisk -J "$disk" | python3 -c 'import json, sys
t = json.load(sys.stdin)["partitiontable"]
print(next(p["start"] for p in t["partitions"] if p["name"] == sys.argv[1]) * 512)' "$1"
}
super=$(part super)
system=$("$root/tools/android-image.py" lp-offset "$disk" "$super" system_a)
dump.erofs --offset="$system" --path=/system/etc/selinux/plat_file_contexts --cat "$disk" \
    > "$dir/file_contexts"
fsck.erofs --offset="$("$root/tools/android-image.py" lp-offset "$disk" "$super" odm_a)" \
    --extract="$dir/odm" --preserve-perms "$disk" >/dev/null
mkdir -p "$dir/odm/etc/init"
cat > "$dir/odm/etc/init/l4h.rc" <<'EOF'
# Android's errors and boot progress on the console, with the kernel's
# messages: Cuttlefish logs everything to /dev/hvc2, which l4h guests do
# not have.  Not the crash dumps, which are long and repeat with the HALs
# that look for the Cuttlefish host.
service l4h_logcat /system/bin/logcat -b main,system,crash,events -v brief *:E DEBUG:S libc:S crash_dump64:S tombstoned:S Watchdog:W boot_progress_start:I boot_progress_preload_start:I boot_progress_preload_end:I boot_progress_system_run:I boot_progress_pms_start:I boot_progress_pms_ready:I boot_progress_ams_ready:I boot_progress_enable_screen:I
    class main
    user logd
    group root logd
    seclabel u:r:logpersist:s0
    console

# No sensors: Cuttlefish's sensors HAL simulates those of its host, and
# stops without one; with no sub-HAL to load, the multi-HAL has none.
on init
    mount none /odm/etc/l4h/no-sensors /vendor/etc/sensors/hals.conf bind

# Cuttlefish's logcat to /dev/hvc2, which an l4h guest does not have: it
# would stop at once, and start again, for good.
service seriallogging /system/bin/logcat -b all -v threadtime -f /dev/hvc2 *:V
    override
    disabled
    user logd
    group root logd
    seclabel u:r:logpersist:s0

# Of each crash dump, what crashed and why.
service l4h_crashes /system/bin/logcat -b crash -v brief -e "Cmdline:|Abort message:|panicked at|signal [0-9]|#0[0-5] pc|Cause:" *:V
    class main
    user logd
    group root logd
    seclabel u:r:logpersist:s0
    console
EOF
# init skips scripts that others than their owner may write.
chmod 0644 "$dir/odm/etc/init/l4h.rc"
# SELinux denials, which a permissive guest has thousands of, go to
# logcat only, not to the kernel's log too.
echo "ro.logd.auditd.dmesg=false" >> "$dir/odm/etc/build.prop"
mkdir -p "$dir/odm/etc/l4h"
install -m 0644 /dev/null "$dir/odm/etc/l4h/no-sensors"
mkfs.erofs -zlz4hc -T0 --all-root --mount-point=/odm --file-contexts="$dir/file_contexts" \
    "$dir/odm.img" "$dir/odm" >/dev/null 2>&1
[ "$(stat -c %s "$dir/odm.img")" -le $((16 << 20)) ] || { echo "odm: over 16 MiB" >&2; exit 1; }
dd if="$dir/odm.img" of="$disk" bs=1M seek="$(part odm)" oflag=seek_bytes conv=notrunc status=none
echo "android: $out (initrd.img, disk.img)"

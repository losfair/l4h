#!/usr/bin/env bash
# Install a tagged x86_64 release under an existing Linux installation.
# Keep execution inside one function: a truncated curl must not run half an installer.
l4h_install() {
    set -euo pipefail
    export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
    local release=latest check=0 arg work url
    local -a args=()
    while (($#)); do
        arg=$1; shift
        case "$arg" in
            --help|-h)
                cat <<'HELP'
Usage: curl -fsSL https://raw.githubusercontent.com/losfair/l4h/main/tools/install.sh | bash -s -- [options]
  --check                 Check compatibility only; do not install packages or change boot
  --release TAG           Install a specific GitHub release (default: latest)
  --esp PATH              Mounted EFI system partition (UEFI; otherwise auto-detect)
  --memory MiB            dom0 RAM (default: half of physical RAM, capped at 8192 MiB)
  --vcpus N               dom0 CPUs (default: up to 4)
  --variant NAME          generic or xapic-nopcid (otherwise select from CPU features)
  --make-default          Make L4H the default boot entry (default: one-time
                          BootNext on UEFI, GRUB next_entry on BIOS)
  --help                  Show this help

Requires x86_64 Linux booted with 64-bit UEFI and Secure Boot disabled, or
booted by BIOS GRUB (grub-pc) from /boot on ext2/3/4 or XFS.
Supports a plain ext4/XFS root, supported PCI disks and one supported physical NIC.
The existing userspace boots with L4H's kernel. No automatic reboot.
Run --check first; see the README and docs/manual/l4h-manual.tex for limits and recovery.
HELP
                return ;;
            --check) check=1; args+=("$arg") ;;
            --make-default) args+=("$arg") ;;
            --release|--esp|--memory|--vcpus|--variant)
                (($#)) || { echo "l4h: $arg needs a value" >&2; return 2; }
                if [[ $arg == --release ]]; then release=$1; else args+=("$arg" "$1"); fi
                shift ;;
            *) echo "l4h: unknown option: $arg" >&2; return 2 ;;
        esac
    done
    [[ $release == latest || $release =~ ^v[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || {
        echo 'l4h: --release must be a v-prefixed release tag' >&2; return 2;
    }
    if ((EUID != 0)); then
        command -v sudo >/dev/null || { echo 'l4h: run as root or install sudo' >&2; return 1; }
        sudo bash -c "$(declare -f l4h_install); l4h_install \"\$@\"" -- \
            --release "$release" "${args[@]}" </dev/null
        return
    fi
    [[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || {
        echo 'l4h: requires x86_64 Linux' >&2; return 1;
    }
    # UEFI selects L4H through an NVRAM entry, BIOS through GRUB's environment.
    local boot_tool=efibootmgr
    if [[ -d /sys/firmware/efi ]]; then
        [[ $(cat /sys/firmware/efi/fw_platform_size) == 64 ]] || {
            echo 'l4h: requires 64-bit UEFI' >&2; return 1;
        }
    elif [[ -f /boot/grub2/grub.cfg ]]; then
        boot_tool=grub2-editenv
    else
        boot_tool=grub-editenv
    fi
    local missing=0 tool
    local -a packages=(ca-certificates)
    for tool in curl python3 "$boot_tool" lsblk findmnt blkid ip; do
        if ! command -v "$tool" >/dev/null; then
            echo "l4h: dependency needed: $tool" >&2; missing=1
            case "$tool" in
                lsblk|findmnt|blkid) packages+=(util-linux) ;;
                ip)
                    if command -v apt-get >/dev/null; then packages+=(iproute2); else packages+=(iproute); fi ;;
                grub-editenv) packages+=(grub-common) ;;
                grub2-editenv) packages+=(grub2-tools-minimal) ;;
                *) packages+=("$tool") ;;
            esac
        fi
    done
    if ((missing)); then
        ((check == 0)) || { echo 'l4h: --check does not install dependencies; install the listed tools first' >&2; return 1; }
        if command -v apt-get >/dev/null; then
            apt-get update
            DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${packages[@]}"
        elif command -v dnf >/dev/null; then
            dnf install -y "${packages[@]}"
        elif command -v yum >/dev/null; then
            yum install -y "${packages[@]}"
        else
            echo 'l4h: automatic dependencies require apt-get, dnf or yum' >&2; return 1
        fi
    fi
    python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else "l4h: Python 3.9 or later is required")'
    work=$(mktemp -d)
    # The trap belongs to this shell, including when invoked through sudo.
    # Capture and shell-quote the pathname now: function locals are gone
    # when an EXIT trap runs after an error returns from the function.
    # shellcheck disable=SC2064
    trap "$(printf 'rm -rf -- %q' "$work")" EXIT
    if [[ $release == latest ]]; then
        curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
            --retry 3 -o "$work/release.json" https://api.github.com/repos/losfair/l4h/releases/latest
        release=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tag_name"])' "$work/release.json")
        [[ $release =~ ^v[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || { echo 'l4h: invalid release tag' >&2; return 1; }
    fi
    url=https://github.com/losfair/l4h/releases/download/$release
    for arg in SHA256SUMS l4h-dom0-x86_64.tar.xz; do
        curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
            --retry 3 -o "$work/$arg" "$url/$arg"
    done
    # Verify before executing anything from the release. Extract only regular
    # files/directories beneath the package prefix; never trust archive paths.
    python3 - "$work" <<'PY'
import hashlib
from pathlib import Path, PurePosixPath
import shutil
import sys
import tarfile

work = Path(sys.argv[1])
name = 'l4h-dom0-x86_64.tar.xz'
lines = [line.split() for line in (work / 'SHA256SUMS').read_text().splitlines()]
hashes = [parts[0] for parts in lines if len(parts) == 2 and parts[1] == name]
with (work / name).open('rb') as stream:
    digest = hashlib.sha256()
    for block in iter(lambda: stream.read(1024 * 1024), b''):
        digest.update(block)
if hashes != [digest.hexdigest()]:
    sys.exit('l4h: dom0 package checksum missing, duplicated or mismatched')
with tarfile.open(work / name, 'r:xz') as archive:
    seen = set()
    for item in archive:
        path = PurePosixPath(item.name)
        if (path.is_absolute() or '..' in path.parts or not path.parts
                or path.parts[0] != 'l4h-dom0-x86_64'
                or not (item.isfile() or item.isdir()) or path in seen):
            sys.exit('l4h: unsafe dom0 package member: ' + item.name)
        seen.add(path)
        dest = work / path
        if item.isdir():
            dest.mkdir(parents=True, exist_ok=True)
        else:
            dest.parent.mkdir(parents=True, exist_ok=True)
            with archive.extractfile(item) as src, dest.open('xb') as out:
                shutil.copyfileobj(src, out)
            dest.chmod(0o755 if item.mode & 0o111 else 0o644)
PY
    [[ -f $work/l4h-dom0-x86_64/install/install.py ]] || {
        echo "l4h: $release predates the Linux installer; choose a newer release" >&2; return 1;
    }
    python3 "$work/l4h-dom0-x86_64/install/install.py" \
        --release "$release" --checksums "$work/SHA256SUMS" "${args[@]}"
    rm -rf -- "$work"
    trap - EXIT
}
l4h_install "$@"

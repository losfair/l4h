#!/usr/bin/env python3
"""Release manifests and the guest/provider compatibility contract.

Shared by the package builders and installer; only Python's standard library
is required. The installer verifies manifests against the selected release SHA256SUMS.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import struct
import tarfile

GUEST_PACKAGE = "l4h-guest-x86_64"
GUEST_FILES = ("vmlinux", "sdk.erofs", "kernel.release")
ABI_FIELDS = ("guest_abi", "provider_abi", "provider_size", "features")


def need(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def release_tag(value):
    return isinstance(value, str) and re.fullmatch(r"(?:guest-)?v[A-Za-z0-9][A-Za-z0-9._-]*", value)


def kernel_release(value):
    need(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}", value),
         "invalid kernel release in guest package")
    return value


def elf_abi(path):
    """Read the fixed, allocated .l4h.abi section, retained by strip-debug."""
    data = Path(path).read_bytes()
    need(len(data) >= 64 and data[:6] == b"\x7fELF\x02\x01", "guest is not a little-endian ELF64 image")
    machine, = struct.unpack_from("<H", data, 18)
    need(machine in (62, 183), "unsupported guest architecture")
    shoff, = struct.unpack_from("<Q", data, 40)
    stride, count, names_index = struct.unpack_from("<HHH", data, 58)
    need(stride >= 64 and names_index < count and shoff + stride * count <= len(data), "bad guest section table")

    def section(index):
        name, kind, flags, addr, offset, size = struct.unpack_from("<IIQQQQ", data, shoff + stride * index)
        need(kind != 8 and offset + size <= len(data), "bad guest section")
        return name, data[offset:offset + size]

    _, names = section(names_index)
    descriptors = []
    for i in range(count):
        name, = struct.unpack_from("<I", data, shoff + stride * i)
        need(name < len(names), "bad guest section name")
        if names[name:].split(b"\0", 1)[0] == b".l4h.abi":
            descriptors.append(section(i)[1])
    need(len(descriptors) == 1 and len(descriptors[0]) == 40 and descriptors[0][:8] == b"L4HGABI1",
         "guest kernel lacks valid .l4h.abi metadata; rebuild it with a current ARCH=l4h")
    return ("x86_64" if machine == 62 else "aarch64",
            dict(zip(ABI_FIELDS, struct.unpack_from("<4Q", descriptors[0], 8))))


def read_manifest(path, kind):
    value = json.loads(Path(path).read_text())
    need(isinstance(value, dict) and value.get("format") == 1 and value.get("kind") == kind,
         "unsupported " + kind + " manifest")
    need(value.get("architecture") in ("x86_64", "aarch64"), "invalid manifest architecture")
    need(isinstance(value.get("release"), str) and bool(value["release"]), "missing release identity")
    for field in ABI_FIELDS:
        need(type(value.get(field)) is int and 0 <= value[field] < 2**64, "invalid manifest " + field)
    need(value["provider_size"] >= 32 and value["provider_size"] % 8 == 0, "invalid provider table size")
    files = value.get("files")
    need(isinstance(files, dict) and bool(files), "missing artifact checksums")
    for name, checksum in files.items():
        need(isinstance(name, str) and name not in ("", ".", "..") and PurePosixPath(name).name == name
             and isinstance(checksum, str) and re.fullmatch(r"[a-f0-9]{64}", checksum), "invalid artifact checksum")
    if kind == "guest":
        need(set(files) == set(GUEST_FILES), "invalid guest file list")
        kernel_release(value.get("kernel_release"))
    else:
        need(isinstance(value.get("guest_release"), str) and bool(value["guest_release"]), "missing default guest release")
    return value


def compatible(host, guest):
    need(host["architecture"] == guest["architecture"], "guest architecture does not match host")
    for field in ("guest_abi", "provider_abi"):
        need(host[field] == guest[field],
             "incompatible {}: guest requires {}, host provides {}".format(field, guest[field], host[field]))
    need(guest["provider_size"] <= host["provider_size"],
         "guest requires a newer provider table ({} bytes; host has {})".format(guest["provider_size"], host["provider_size"]))
    need(guest["features"] & ~host["features"] == 0, "host lacks required guest provider features")


def verify_guest(directory):
    directory = Path(directory)
    manifest = read_manifest(directory / "guest.json", "guest")
    for name, checksum in manifest["files"].items():
        path = directory / name
        need(path.is_file() and not path.is_symlink() and digest(path) == checksum, "guest checksum mismatch: " + name)
    architecture, abi = elf_abi(directory / "vmlinux")
    need(architecture == manifest["architecture"] and all(manifest[k] == v for k, v in abi.items()),
         "guest manifest does not match kernel ABI metadata")
    need((directory / "kernel.release").read_text().strip() == manifest["kernel_release"],
         "guest kernel.release does not match manifest")
    return manifest


def unpack_guest(archive, work):
    """Extract only the four regular files of a guest package; never links."""
    seen = set()
    with tarfile.open(archive, "r:xz") as tar:
        for item in tar:
            path = PurePosixPath(item.name)
            need(not path.is_absolute() and ".." not in path.parts and path not in seen and
                 (path.parts == (GUEST_PACKAGE,) and item.isdir() or
                  len(path.parts) == 2 and path.parts[0] == GUEST_PACKAGE and
                  path.parts[1] in (*GUEST_FILES, "guest.json") and item.isfile()),
                 "unsafe guest package member: " + item.name)
            seen.add(path)
            dest = Path(work) / path
            if item.isdir():
                dest.mkdir(parents=True, exist_ok=True)
            else:
                dest.parent.mkdir(parents=True, exist_ok=True)
                with tar.extractfile(item) as src, dest.open("xb") as out:
                    shutil.copyfileobj(src, out)
    directory = Path(work) / GUEST_PACKAGE
    verify_guest(directory)
    return directory


def write_manifest(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    guest = sub.add_parser("guest")
    guest.add_argument("directory", type=Path)
    guest.add_argument("--release", required=True)
    host = sub.add_parser("host")
    host.add_argument("manifest", type=Path)
    host.add_argument("--release", required=True)
    host.add_argument("--guest-release", required=True)
    host.add_argument("--provider", type=Path, required=True)
    host.add_argument("--abi-header", type=Path, required=True)
    host.add_argument("--payload", type=Path, action="append", required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("directory", type=Path)
    verify.add_argument("--host", type=Path)
    unpack = sub.add_parser("unpack")
    unpack.add_argument("archive", type=Path)
    unpack.add_argument("directory", type=Path)
    args = parser.parse_args()
    if args.command == "guest":
        architecture, abi = elf_abi(args.directory / "vmlinux")
        value = dict(format=1, kind="guest", release=args.release, architecture=architecture, **abi,
                     kernel_release=kernel_release((args.directory / "kernel.release").read_text().strip()),
                     files={name: digest(args.directory / name) for name in GUEST_FILES})
        write_manifest(args.directory / "guest.json", value)
        verify_guest(args.directory)
    elif args.command == "host":
        provider = args.provider.read_bytes()
        need(len(provider) >= 32, "truncated provider")
        magic, version, size, features = struct.unpack_from("<4Q", provider)
        need(magic == 0x315244565048344c and 32 <= size <= len(provider), "invalid provider")
        abi = re.search(r"^#define L4H_ABI_VERSION\s+(\d+)$", args.abi_header.read_text(), re.M)
        need(abi is not None, "missing guest ABI version")
        write_manifest(args.manifest, dict(format=1, kind="host", release=args.release, architecture="x86_64",
                       guest_abi=int(abi[1]), provider_abi=version, provider_size=size, features=features,
                       guest_release=args.guest_release, provider_sha256=digest(args.provider),
                       files={p.name: digest(p) for p in args.payload}))
        read_manifest(args.manifest, "host")
    elif args.command == "unpack":
        print(unpack_guest(args.archive, args.directory))
    else:
        value = verify_guest(args.directory)
        if args.host:
            compatible(read_manifest(args.host, "host"), value)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, struct.error, tarfile.TarError) as error:
        raise SystemExit("l4h: " + str(error)) from error

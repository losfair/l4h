#!/usr/bin/env python3
"""Independent guest releases: ABI skew, package integrity and rollback."""
from functools import lru_cache
import io
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import test_installer
from test_installer import Harness, ROOT, installer

artifacts = installer.artifacts


@lru_cache(maxsize=8)
def kernel_image(guest_abi=10, provider_abi=1, features=0):
    # A real ELF with the same declaration as Linux; no libsel4 dependency.
    with tempfile.TemporaryDirectory() as work:
        out = Path(work) / "vmlinux"
        source = """#include <l4h/provider.h>
__attribute__((section(".l4h.abi"), used))
const struct { char magic[8]; l4h_u64 abi, version, size, features; } requirements = {
    "L4HGABI1", %d, %d, sizeof(struct l4h_provider), %d
};
int main(void) { return 0; }
""" % (guest_abi, provider_abi, features)
        subprocess.run(["cc", "-x", "c", "-", "-I" + str(ROOT / "include"), "-o", str(out)],
                       input=source, text=True, check=True)
        subprocess.run(["objcopy", "--strip-debug", str(out)], check=True)
        return out.read_bytes()


def guest_package(directory, release="guest-v1", linux="6.18.63-l4h", **requirements):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "vmlinux").write_bytes(kernel_image(**requirements))
    (directory / "sdk.erofs").write_bytes(b"SDK for " + linux.encode())
    (directory / "kernel.release").write_text(linux + "\n")
    subprocess.run(["python3", str(ROOT / "tools/install/artifacts.py"), "guest", str(directory),
                    "--release", release], check=True)
    return artifacts.verify_guest(directory)


def host_manifest(guest, payload=None, release="vhost", features=1):
    value = dict(format=1, kind="host", release=release, architecture="x86_64",
                 guest_release=guest["release"], **{k: guest[k] for k in artifacts.ABI_FIELDS})
    value["features"] = features
    value["files"] = {"l4h-generic.efi": artifacts.digest(payload)} if payload else {"l4h-generic.efi": "0" * 64}
    return value


def efi_image():
    data = bytearray(256)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 60, 64)
    data[64:70] = b"PE\0\0\x64\x86"
    data[88:90] = b"\x0b\x02"
    struct.pack_into("<H", data, 156, 10)
    return bytes(data)


class GuestReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.directory = self.work / artifacts.GUEST_PACKAGE
        self.guest = guest_package(self.directory)
        self.host = host_manifest(self.guest)

    def test_independent_versions_and_microkernels(self):
        # Release labels and microkernel identities do not determine ABI compatibility.
        for release, backend in (("v2", "seL4"), ("v9", "FL4")):
            host = dict(self.host, release=release, backend=backend)
            artifacts.compatible(host, self.guest)

    def test_old_guest_with_newer_table_and_new_guest_with_older_table(self):
        artifacts.compatible(dict(self.host, provider_size=self.host["provider_size"] + 8), self.guest)
        with self.assertRaisesRegex(ValueError, "newer provider table"):
            artifacts.compatible(dict(self.host, provider_size=self.host["provider_size"] - 8), self.guest)

    def test_versions_architecture_and_required_features(self):
        for change, message in ((dict(guest_abi=11), "guest_abi"), (dict(provider_abi=2), "provider_abi"),
                                (dict(architecture="aarch64"), "architecture"), (dict(features=2), "features")):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, message):
                artifacts.compatible(self.host, dict(self.guest, **change))
        # KVM is optional: a guest requiring no features works without VTX.
        artifacts.compatible(dict(self.host, features=0), self.guest)

    def test_kernel_sdk_and_linux_release_are_bound_together(self):
        for name in artifacts.GUEST_FILES:
            with self.subTest(name=name):
                path = self.directory / name
                saved = path.read_bytes()
                path.write_bytes(saved + b"changed")
                with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                    artifacts.verify_guest(self.directory)
                path.write_bytes(saved)

    def test_manifest_cannot_understate_kernel_requirements(self):
        self.guest["provider_size"] -= 8
        artifacts.write_manifest(self.directory / "guest.json", self.guest)
        with self.assertRaisesRegex(ValueError, "does not match kernel ABI"):
            artifacts.verify_guest(self.directory)

    def test_bad_elf_section_table_is_rejected(self):
        data = bytearray(kernel_image())
        struct.pack_into("<Q", data, 40, 2**64 - 1)
        path = self.work / "bad.elf"
        path.write_bytes(data)
        with self.assertRaisesRegex(ValueError, "section table"):
            artifacts.elf_abi(path)

    def archive(self):
        path = self.work / "guest.tar.xz"
        with installer.tarfile.open(path, "w:xz") as tar:
            tar.add(self.directory, arcname=artifacts.GUEST_PACKAGE)
        return path

    def test_package_round_trip(self):
        dest = artifacts.unpack_guest(self.archive(), self.work / "out")
        self.assertEqual(artifacts.verify_guest(dest), self.guest)

    def test_archive_rejects_links_paths_duplicate_and_missing_files(self):
        for name, kind in (("../escape", installer.tarfile.REGTYPE),
                           (artifacts.GUEST_PACKAGE + "/vmlinux", installer.tarfile.SYMTYPE),
                           (artifacts.GUEST_PACKAGE + "/vmlinux", installer.tarfile.LNKTYPE),
                           (artifacts.GUEST_PACKAGE + "/unexpected", installer.tarfile.REGTYPE)):
            archive = self.work / "bad.tar.xz"
            with installer.tarfile.open(archive, "w:xz") as tar:
                item = installer.tarfile.TarInfo(name)
                item.type = kind
                item.linkname = "/outside"
                tar.addfile(item, io.BytesIO())
            with self.subTest(name=name, kind=kind), self.assertRaisesRegex(ValueError, "unsafe guest"):
                artifacts.unpack_guest(archive, self.work / "out")
        archive = self.work / "duplicate.tar.xz"
        with installer.tarfile.open(archive, "w:xz") as tar:
            for _ in range(2):
                tar.add(self.directory / "vmlinux", arcname=artifacts.GUEST_PACKAGE + "/vmlinux")
        with self.assertRaisesRegex(ValueError, "unsafe guest"):
            artifacts.unpack_guest(archive, self.work / "duplicate")


class SplitInstallerTests(Harness):
    def setUp(self):
        super().setUp()
        self.package()  # Legacy dom0 kernel.release deliberately differs below.
        self.guest_dir = self.root / artifacts.GUEST_PACKAGE
        self.guest = guest_package(self.guest_dir, linux="6.19-l4h")
        self.host = host_manifest(self.guest, self.root / "new.efi")
        self.payload = self.root / "new.efi"
        self.guest_install = "/boot/efi/l4h/guest/"
        self.host_install = "/boot/efi/EFI/L4H/l4h.efi"

    def commit_split(self, guest=None, host=None):
        installer.commit(self.check(), self.root / "package", self.payload, "vhost", False,
                         root=self.root, command=self.machine.command,
                         host=host or self.host, guest=guest or self.guest_dir)

    def test_records_both_versions_and_prepares_selected_guest_sdk(self):
        self.commit_split()
        state = json.loads(self.machine.path(installer.STATE).read_text())
        self.assertEqual((state["version"], state["release"], state["guest_release"]), (3, "vhost", "guest-v1"))
        self.assertEqual(state["guest"]["files"], self.guest["files"])
        self.assertTrue(self.machine.path("/lib/modules/6.19-l4h/build").is_dir())
        self.assertFalse(self.machine.path("/lib/modules/6.18.63-l4h").exists())
        self.assertEqual(self.check()["guest_release"], "guest-v1")
        for name in artifacts.GUEST_FILES:
            self.assertEqual(self.machine.path(self.guest_install + name).read_bytes(), (self.guest_dir / name).read_bytes())

    def test_incompatible_pair_is_rejected_before_any_write(self):
        before = sorted(self.root.rglob("*"))
        with self.assertRaisesRegex(ValueError, "guest_abi"):
            self.commit_split(host=dict(self.host, guest_abi=11))
        self.assertEqual(before, sorted(self.root.rglob("*")))

    def test_failed_update_restores_kernel_sdk_host_and_version_record(self):
        self.commit_split()
        paths = [self.machine.path(self.guest_install + n) for n in (*artifacts.GUEST_FILES, "guest.json")]
        paths += [self.machine.path(installer.STATE), self.machine.path(self.host_install)]
        before = {p: p.read_bytes() for p in paths}
        next_guest = self.root / "next-guest"
        guest_package(next_guest, release="guest-v2", linux="6.20-l4h")
        real_copy = installer.atomic_copy

        failed = False

        def fail_initrd(source, dest, mode):
            nonlocal failed
            if dest.name == "initrd" and not failed:
                failed = True
                raise OSError("injected disk failure")
            real_copy(source, dest, mode)

        with patch.object(installer, "atomic_copy", side_effect=fail_initrd):
            with self.assertRaisesRegex(OSError, "injected disk failure"):
                self.commit_split(guest=next_guest)
        self.assertEqual(before, {p: p.read_bytes() for p in paths})
        self.assertFalse(self.machine.path("/lib/modules/6.20-l4h").exists())

    def test_guest_change_during_download_is_detected(self):
        self.commit_split()
        plan = self.check()
        self.machine.path(self.guest_install + "vmlinux").write_bytes(b"changed by another installer")
        with self.assertRaisesRegex(installer.Incompatible, "files changed"):
            installer.commit(plan, self.root / "package", self.payload, "vhost", False,
                             root=self.root, command=self.machine.command, host=self.host, guest=self.guest_dir)

    def releases(self):
        host_dir, guest_dir = self.root / "host-release", self.root / "guest-release"
        host_dir.mkdir()
        guest_dir.mkdir()
        efi = host_dir / "l4h-generic.efi"
        efi.write_bytes(efi_image())
        self.host = host_manifest(self.guest, efi)
        if self.check()["firmware"] == "bios":
            archive = host_dir / (installer.BIOS_PACKAGE + ".tar.xz")
            with installer.tarfile.open(archive, "w:xz") as tar:
                tar.add(self.payload, arcname=installer.BIOS_PACKAGE)
            self.host["files"][archive.name] = artifacts.digest(archive)
        artifacts.write_manifest(host_dir / "l4h-host-generic.json", self.host)
        with installer.tarfile.open(guest_dir / (artifacts.GUEST_PACKAGE + ".tar.xz"), "w:xz") as tar:
            tar.add(self.guest_dir, arcname=artifacts.GUEST_PACKAGE)
        for directory in (host_dir, guest_dir):
            (directory / "SHA256SUMS").write_text("".join(artifacts.digest(p) + "  " + p.name + "\n"
                                                        for p in sorted(directory.iterdir())))
        return installer.arguments(["--release", "vhost", "--checksums", str(host_dir / "SHA256SUMS"),
                                    "--artifacts", str(host_dir), "--guest-artifacts", str(guest_dir)])

    def test_downloads_independently_versioned_verified_pair(self):
        args = self.releases()
        work = self.root / "download"
        work.mkdir()
        _, host, guest = installer.download_pair(args, self.check(), work)
        self.assertEqual(host["release"], "vhost")
        self.assertEqual(artifacts.verify_guest(guest)["release"], "guest-v1")

    def test_update_keeps_guest_when_new_host_recommends_another(self):
        self.commit_split()
        args = self.releases()
        self.host["guest_release"] = "guest-v9"
        path = args.artifacts / "l4h-host-generic.json"
        artifacts.write_manifest(path, self.host)
        args.checksums.write_text("".join(artifacts.digest(p) + "  " + p.name + "\n"
                                         for p in sorted(args.artifacts.iterdir()) if p.name != "SHA256SUMS"))
        work = self.root / "download"
        work.mkdir()
        _, _, guest = installer.download_pair(args, self.check(), work)
        self.assertEqual(artifacts.verify_guest(guest)["release"], "guest-v1")

    def test_explicit_guest_release_overrides_installed_guest(self):
        self.commit_split()
        self.guest = guest_package(self.guest_dir, release="guest-v2", linux="6.20-l4h")
        args = self.releases()
        args.guest_release = "guest-v2"
        work = self.root / "download"
        work.mkdir()
        _, _, guest = installer.download_pair(args, self.check(), work)
        self.assertEqual(artifacts.verify_guest(guest)["release"], "guest-v2")

    def test_guest_download_checksum_failure(self):
        args = self.releases()
        (args.guest_artifacts / (artifacts.GUEST_PACKAGE + ".tar.xz")).write_bytes(b"corrupt")
        work = self.root / "download"
        work.mkdir()
        with self.assertRaisesRegex(installer.Incompatible, "checksum mismatch"):
            installer.download_pair(args, self.check(), work)

    def test_guest_release_identity_cannot_be_substituted(self):
        args = self.releases()
        args.guest_release = "guest-v2"
        work = self.root / "download"
        work.mkdir()
        with self.assertRaisesRegex(installer.Incompatible, "release identity"):
            installer.download_pair(args, self.check(), work)


class SplitBiosInstallerTests(SplitInstallerTests):
    def setUp(self):
        super().setUp()
        self.machine.bios()
        self.payload = test_installer.BiosInstallerTests.bios_package(self)
        (self.payload / "vmlinux").unlink()
        (self.payload / "sdk.erofs").unlink()
        self.guest_install = "/boot/l4h/guest/"
        self.host_install = "/boot/l4h/bios/kernel.elf"


if __name__ == "__main__":
    unittest.main()

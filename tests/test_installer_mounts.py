#!/usr/bin/env python3
"""Installer directory preparation and SDK mounts in a private Linux mount namespace."""
import errno
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from test_installer import Harness, installer


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "requires root on Linux")
class InstallerMountTests(Harness):
    def setUp(self):
        super().setUp()
        self.release = "6.18.63-l4h"
        self.mount("--bind", str(self.root), str(self.root))
        self.addCleanup(installer.run, "umount", str(self.root))

    def mount(self, *args):
        return installer.run("mount", *map(str, args))

    def command(self, *args):
        if args[0] in ("mount", "umount"):
            return installer.run(*args)
        return self.machine.command(*args)

    def package(self):
        package = super().package()
        (package / "install/kernel.release").write_text(self.release + "\n")
        return package

    def commit(self):
        installer.commit(self.check(), self.package(), self.root / "new.efi", "vtest", False,
                         root=self.root, command=self.command)

    def image_directory(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        return Path(directory.name)

    def boot_sdk(self):
        sdk = self.image_directory()
        (sdk / "kernel.release").write_text(self.release)
        self.mount("-o", "remount,bind,ro", self.root)
        with self.assertRaises(OSError) as error:
            (self.root / "boot-write").write_text("must fail")
        self.assertEqual(error.exception.errno, errno.EROFS)
        build = self.root / "lib/modules" / self.release / "build"
        self.mount("--bind", sdk, build)
        self.addCleanup(installer.run, "umount", str(build))
        self.mount("-o", "remount,bind,ro", build)
        self.assertEqual((build / "kernel.release").read_text(), self.release)
        with self.assertRaises(OSError) as error:
            (build / "sdk-write").write_text("must fail")
        self.assertEqual(error.exception.errno, errno.EROFS)

    def test_install_then_mount_sdk_on_read_only_root(self):
        self.machine.write("/lib/modules/native/user.ko", b"native module")
        self.commit()
        self.boot_sdk()
        self.assertEqual(self.machine.path("/lib/modules/native/user.ko").read_bytes(), b"native module")

    def test_update_below_old_read_only_module_mount_with_usrmerge(self):
        self.machine.write("/usr/lib/modules/native/user.ko", b"native module")
        self.machine.link("/lib", Path("usr/lib"))
        self.release = "6.17-l4h"
        self.commit()
        self.machine.dom0()
        old = self.image_directory()
        (old / "running.ko").write_bytes(b"running module")
        modules = self.root / "lib/modules"
        self.mount("--bind", old, modules)
        self.mount("-o", "remount,bind,ro", modules)
        mounted = True
        try:
            self.release = "6.18.63-l4h"
            self.commit()
            self.assertEqual((modules / "running.ko").read_bytes(), b"running module")
            self.assertFalse((modules / self.release).exists())
            with self.assertRaises(OSError) as error:
                (modules / "running-write").write_text("must fail")
            self.assertEqual(error.exception.errno, errno.EROFS)
            installer.run("umount", str(modules))
            mounted = False
            self.boot_sdk()
            self.assertEqual((modules / "native/user.ko").read_bytes(), b"native module")
        finally:
            if mounted:
                installer.run("umount", str(modules))

    def test_unmount_failure_keeps_root_and_mountpoint(self):
        self.machine.write("/lib/modules/native/user.ko", b"native module")
        views = []

        def fail_unmount(*args):
            if args[0] == "umount":
                raise installer.Incompatible("injected unmount failure: " + args[1])
            views.append(Path(args[-1]))
            return installer.run(*args)

        try:
            with self.assertRaisesRegex(installer.Incompatible, "injected unmount failure"):
                with installer.root_filesystem(self.root, fail_unmount):
                    pass
            view = views[0]
            self.assertEqual(installer.run("findmnt", "--noheadings", "--mountpoint", str(view),
                                           "--output", "TARGET"), str(view))
            self.assertEqual((view / "lib/modules/native/user.ko").read_bytes(), b"native module")
            self.assertEqual(self.machine.path("/lib/modules/native/user.ko").read_bytes(), b"native module")
        finally:
            for view in views:
                installer.run("umount", str(view))
                view.rmdir()


if __name__ == "__main__":
    if sys.platform == "linux" and os.geteuid() == 0:
        if "--mount-namespace" not in sys.argv:
            sys.exit(subprocess.call(["unshare", "--mount", "--fork", "--", sys.executable,
                                      __file__, "--mount-namespace", *sys.argv[1:]]))
        sys.argv.remove("--mount-namespace")
        installer.run("mount", "--make-rprivate", "/")
    unittest.main()

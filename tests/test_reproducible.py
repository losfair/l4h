#!/usr/bin/env python3
"""Exercise deterministic packaging and public module signing input replay."""
import gzip
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("module_signing", ROOT / "tools/module-signing.py")
signing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(signing)


class ReproducibleTest(unittest.TestCase):
    def setUp(self):
        (ROOT / "build").mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / "build")
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.env = dict(os.environ, SOURCE_DATE_EPOCH="1700000000", TMPDIR=str(self.work))

    def test_archive_ignores_creation_order_mtime_and_umask(self):
        archives = []
        for i, names in enumerate((("a", "b"), ("b", "a"))):
            tree = self.work / str(i)
            tree.mkdir(mode=0o700 if i else 0o755)
            for name in names:
                path = tree / name
                path.write_text(name)
                path.chmod(0o600 if i else 0o644)
                os.utime(path, (100 + i, 100 + i))
            archive = self.work / f"{i}.tar.xz"
            subprocess.run(["bash", "-eu", "-c",
                            'root=$1; source "$root/tools/reproducible-env.sh"; '
                            'l4h_tar -cJf "$2" -C "$3" .', "bash", str(ROOT), str(archive), str(tree)],
                           check=True, env=self.env)
            archives.append(archive.read_bytes())
            with tarfile.open(archive) as tar:
                self.assertTrue(all(m.uid == m.gid == 0 for m in tar.getmembers()))
        self.assertEqual(*archives)

    @unittest.skipUnless(shutil.which("busybox") and shutil.which("cpio"), "needs BusyBox and cpio")
    def test_initramfs_ignores_inode_numbers_and_timestamps(self):
        images = []
        for i in range(2):
            init = self.work / f"init-{i}"
            init.write_text("#!/bin/sh\nexec /bin/sh\n")
            os.utime(init, (100 + i, 100 + i))
            image = self.work / f"initrd-{i}"
            subprocess.run([str(ROOT / "tools/mkinitramfs.sh"), str(image), str(init)],
                           check=True, env=self.env, stdout=subprocess.DEVNULL)
            images.append(image.read_bytes())
        self.assertEqual(*images)
        self.assertEqual(gzip.decompress(images[0])[:6], b"070701")

    @unittest.skipUnless(shutil.which("cargo"), "needs Cargo")
    def test_rust_crate_hashes_and_debug_info_ignore_checkout_path(self):
        pin = tomllib.loads((ROOT / "host/rust-toolchain.toml").read_text())["toolchain"]["channel"]
        compiler = subprocess.run(["rustup", "which", "--toolchain", pin, "rustc"], capture_output=True, text=True)
        if compiler.returncode:
            self.skipTest("needs the pinned nightly (installed by ci-setup.sh)")
        binaries = []
        for name in ("first", "a-longer-second-checkout"):
            checkout = self.work / name
            app, shared = checkout / "app", checkout / "shared"
            for path in (app / "src", shared / "src"):
                path.mkdir(parents=True)
            (app / "Cargo.toml").write_text(
                '[package]\nname="app"\nversion="0.1.0"\nedition="2021"\n'
                '[workspace]\n[dependencies]\nshared={path="../shared"}\n'
                '[profile.release]\ndebug=true\n')
            (shared / "Cargo.toml").write_text('[package]\nname="shared"\nversion="0.1.0"\nedition="2021"\n')
            (shared / "src/lib.rs").write_text('pub fn marker() -> &\'static str { file!() }\n')
            (app / "src/main.rs").write_text('fn main() { println!("{}", shared::marker()); }\n')
            env = dict(self.env, RUSTC=compiler.stdout.strip())
            for args in (("generate-lockfile", "--offline"), ("build", "--offline", "--locked", "--release")):
                subprocess.run([str(ROOT / "tools/cargo.sh"), *args], cwd=app, env=env,
                               check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            binaries.append((app / "target/release/app").read_bytes())
        self.assertTrue(binaries[0] == binaries[1], "Rust output differs between checkout paths")

    @unittest.skipUnless(shutil.which("openssl"), "needs OpenSSL")
    def test_replay_prepares_only_a_public_certificate(self):
        original, replay = self.work / "original", self.work / "replay"
        saved = os.environ.pop("L4H_BUILD_INPUTS", None)
        if saved is not None:
            self.addCleanup(os.environ.__setitem__, "L4H_BUILD_INPUTS", saved)
        self.addCleanup(lambda: os.environ.pop("L4H_BUILD_INPUTS", None))
        signing.prepare(original)
        public = signing.certificate(original).read_bytes()
        self.assertNotIn(b"PRIVATE KEY", public)
        self.assertIn(b"CERTIFICATE", public)
        bundle = self.work / "inputs"
        bundle.mkdir()
        (bundle / "module-signing.pem").write_bytes(public)
        os.environ["L4H_BUILD_INPUTS"] = str(bundle)
        signing.prepare(replay)
        self.assertEqual(signing.certificate(replay).read_bytes(), public)
        self.assertFalse((replay / "certs/l4h-signing-private.pem").exists())

    def test_replay_rejects_changed_or_missing_modules_before_signing(self):
        bundle, tree = self.work / "inputs", self.work / "modules"
        bundle.mkdir()
        tree.mkdir()
        (bundle / "modules.json").write_text(json.dumps({"module.ko": "wrong hash"}))
        saved = os.environ.get("L4H_BUILD_INPUTS")
        os.environ["L4H_BUILD_INPUTS"] = str(bundle)
        if saved is not None:
            self.addCleanup(os.environ.__setitem__, "L4H_BUILD_INPUTS", saved)
        self.addCleanup(lambda: os.environ.pop("L4H_BUILD_INPUTS", None))
        for present in (False, True):
            if present:
                (tree / "module.ko").write_bytes(b"changed module")
            with self.assertRaisesRegex(SystemExit, "do not match.*module.ko"):
                signing.install(self.work / "no-build", tree, self.work / "output")

    @unittest.skipUnless((ROOT / "build/linux-l4h/scripts/sign-file").exists(), "needs a built Linux sign-file")
    def test_signed_module_replay_and_tampered_signature(self):
        saved = os.environ.pop("L4H_BUILD_INPUTS", None)
        if saved is not None:
            self.addCleanup(os.environ.__setitem__, "L4H_BUILD_INPUTS", saved)
        self.addCleanup(lambda: os.environ.pop("L4H_BUILD_INPUTS", None))
        original = self.work / "original"
        signing.prepare(original)
        (original / "scripts").mkdir()
        shutil.copy2(ROOT / "build/linux-l4h/scripts/sign-file", original / "scripts/sign-file")
        tree = self.work / "modules"
        tree.mkdir()
        module = tree / "module.ko"
        unsigned = b"module bytes to authenticate\n"
        module.write_bytes(unsigned)
        bundle = self.work / "inputs"
        signing.install(original, tree, bundle)
        signed = module.read_bytes()
        self.assertTrue(signed.endswith(b"~Module signature appended~\n"))
        self.assertFalse(any(b"PRIVATE KEY" in p.read_bytes() for p in bundle.rglob("*") if p.is_file()))
        os.environ["L4H_BUILD_INPUTS"] = str(bundle)
        replay = self.work / "replay"
        signing.prepare(replay)
        shutil.copytree(original / "scripts", replay / "scripts")
        module.write_bytes(unsigned)
        signing.install(replay, tree, self.work / "replayed-inputs")
        self.assertEqual(module.read_bytes(), signed)
        signature = bundle / "signatures/module.ko.p7s"
        signature.write_bytes(b"corrupted signature")
        module.write_bytes(unsigned)
        with self.assertRaises(subprocess.CalledProcessError):
            signing.install(replay, tree, self.work / "bad-replay")
        self.assertEqual(module.read_bytes(), unsigned)


if __name__ == "__main__":
    unittest.main()

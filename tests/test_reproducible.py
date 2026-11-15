#!/usr/bin/env python3
"""Exercise deterministic archives, initramfs and Rust builds."""
import gzip
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
            (shared / "build.rs").write_text(
                'fn main() { std::fs::write(std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("generated.rs"), '
                '"pub fn marker() -> &\'static str { file!() }").unwrap(); }\n')
            (shared / "src/lib.rs").write_text('include!(concat!(env!("OUT_DIR"), "/generated.rs"));\n')
            (app / "src/main.rs").write_text('fn main() { println!("{}", shared::marker()); }\n')
            env = dict(self.env, RUSTC=compiler.stdout.strip())
            for args in (("generate-lockfile", "--offline"), ("build", "--offline", "--locked", "--release")):
                maps = json.dumps([f"--remap-path-prefix={checkout}=/l4h"])
                subprocess.run([str(ROOT / "tools/cargo.sh"), *args, "--config", f"build.rustflags={maps}"], cwd=app, env=env,
                               check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            binaries.append((app / "target/release/app").read_bytes())
        self.assertTrue(binaries[0] == binaries[1], "Rust output differs between checkout paths")

    @unittest.skipUnless(shutil.which("rustc") and shutil.which("gcc"), "needs Rust and GCC")
    def test_rust_host_linker_accepts_a_multiword_compiler(self):
        cache = self.work / "ccache"
        cache.write_text('#!/bin/sh\nexec "$@"\n')
        cache.chmod(0o755)
        source, binary = self.work / "host.rs", self.work / "host"
        source.write_text('fn main() {}\n')
        env = dict(self.env, PATH=f"{self.work}:{self.env['PATH']}", L4H_LINUX_CC="ccache gcc")
        subprocess.run(["rustc", "+stable", str(source), "-C", f"linker={ROOT / 'tools/linux-cc.sh'}",
                        "-o", str(binary)], check=True, env=env, capture_output=True)
        subprocess.run([str(binary)], check=True)

if __name__ == "__main__":
    unittest.main()

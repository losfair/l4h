#!/usr/bin/env python3
"""Keep random signing keys private; publish public inputs for release replay."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def run(*args):
    result = subprocess.run([str(a) for a in args], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    if result.returncode:
        sys.stderr.buffer.write(result.stderr)
        result.check_returncode()


def certificate(out):
    return out / "certs/l4h-signing.pem"


def inputs():
    value = os.environ.get("L4H_BUILD_INPUTS")
    return Path(value).resolve() if value else None


def prepare(out):
    cert = certificate(out)
    cert.parent.mkdir(parents=True, exist_ok=True)
    replay = inputs()
    if replay:
        public = subprocess.check_output(["openssl", "x509", "-in", str(replay / "module-signing.pem")])
    else:
        key = out / "certs/l4h-signing-private.pem"
        if not key.exists():
            with tempfile.TemporaryDirectory(dir=cert.parent) as temp:
                private, public_cert = Path(temp) / "key.pem", Path(temp) / "cert.pem"
                run("openssl", "req", "-new", "-nodes", "-newkey", "rsa:4096", "-x509",
                    "-sha512", "-days", "36500", "-subj", "/CN=L4H module signing/",
                    "-keyout", private, "-out", public_cert)
                key.write_bytes(private.read_bytes() + public_cert.read_bytes())
                key.chmod(0o600)
        public = subprocess.check_output(["openssl", "x509", "-in", str(key)])
    # Never put the private key in the kernel's configured input, SDK or bundle.
    if not cert.exists() or cert.read_bytes() != public:
        cert.write_bytes(public)


def install(out, tree, bundle):
    modules = sorted(tree.rglob("*.ko"))
    hashes = {str(p.relative_to(tree)): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in modules}
    replay = inputs()
    if replay:
        expected = json.loads((replay / "modules.json").read_text())
        if hashes != expected:
            changed = sorted(k for k in hashes.keys() | expected.keys()
                             if hashes.get(k) != expected.get(k))
            raise SystemExit("module signing inputs do not match rebuilt modules: " + ", ".join(changed))
    bundle.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=bundle.parent) as temp:
        stage = Path(temp) / bundle.name
        stage.mkdir()
        shutil.copyfile(certificate(out), stage / "module-signing.pem")
        (stage / "modules.json").write_text(json.dumps(hashes, indent=2, sort_keys=True) + "\n")
        for module in modules:
            relative = module.relative_to(tree)
            signature = stage / "signatures" / relative.with_suffix(".ko.p7s")
            signature.parent.mkdir(parents=True, exist_ok=True)
            if replay:
                shutil.copyfile(replay / "signatures" / relative.with_suffix(".ko.p7s"), signature)
                # A matching module hash alone does not authenticate its signature.
                run("openssl", "cms", "-verify", "-binary", "-inform", "DER", "-in", signature,
                    "-content", module, "-certfile", certificate(out), "-noverify", "-out", os.devnull)
            else:
                run(out / "scripts/sign-file", "-d", "sha512", out / "certs/l4h-signing-private.pem",
                    certificate(out), module)
                generated = Path(str(module) + ".p7s")
                generated.replace(signature)
            run(out / "scripts/sign-file", "-s", signature, "sha512", certificate(out), module)
        if bundle.exists():
            shutil.rmtree(bundle)
        stage.replace(bundle)


def verify_image(tree, image):
    # Check the packed bytes as well as the signatures before compression.
    for module in sorted(tree.rglob("*.ko")):
        relative = module.relative_to(tree)
        packed = subprocess.check_output(["dump.erofs", "--cat", f"--path=/{relative}", str(image)])
        if packed != module.read_bytes():
            raise SystemExit(f"module image corrupted {relative}")


if __name__ == "__main__":
    command, output, *args = sys.argv[1:]
    if command == "prepare":
        prepare(Path(output))
    elif command == "install":
        install(Path(output), *(Path(a) for a in args))
    elif command == "verify-image":
        verify_image(Path(output), Path(args[0]))
    else:
        raise SystemExit(f"unknown command: {command}")

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run the same disposable block test image under local QEMU."""
import argparse
import json
import os
from pathlib import Path
import re
import socket
import shlex
import shutil
import subprocess
import tempfile
import time

parser = argparse.ArgumentParser()
parser.add_argument("image", type=Path)
parser.add_argument("--log", type=Path, required=True)
parser.add_argument("--baseline", action="store_true")
parser.add_argument("--guest-queues", type=int, choices=(1, 4), default=4)
parser.add_argument("--scsi-queues", type=int, choices=(1, 4), default=4)
parser.add_argument("--legacy", action="store_true")
parser.add_argument("--suite", choices=("blkmq", "fsync"), default="blkmq")
parser.add_argument("--io-threads", type=int, choices=(0, 1, 4), default=0)
parser.add_argument("--cache", choices=("writeback", "none"), default="writeback")
parser.add_argument("--trace", type=Path)
parser.add_argument("--profile", action="store_true")
parser.add_argument("--fsync-hook", type=Path, help="macOS diagnostic interposer; do not use for performance comparisons")
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
args.log.parent.mkdir(parents=True, exist_ok=True)
env = dict(os.environ, L4H_MEM="2048", L4H_SMP="4", L4H_BALLOON="1")
if args.fsync_hook:
    env["L4H_FSYNC_TRACE_LIBRARY"] = str(args.fsync_hook.resolve())
    env["L4H_FSYNC_TRACE_PATH"] = str(args.log.with_suffix(".host-fsync.jsonl").resolve())
marker = "BLKMQ" if args.suite == "blkmq" else "FSYNC"
observations = []
profile = None

def qmp_call(stream, command):
    stream.write(json.dumps({"execute": command}).encode() + b"\n")
    stream.flush()
    while True:
        reply = json.loads(stream.readline())
        if "return" in reply:
            return reply["return"]
        if "error" in reply:
            raise RuntimeError(reply["error"])

with tempfile.TemporaryDirectory(prefix="l4h-blkmq-") as temp:
    if args.fsync_hook:
        qemu_binary = shutil.which("qemu-system-aarch64")
        if qemu_binary is None:
            raise SystemExit("QEMU is missing")
        shim = Path(temp) / "qemu-system-aarch64"
        # Set DYLD after the system shell starts; macOS clears it on entry.
        shim.write_text('#!/bin/bash\nexport DYLD_INSERT_LIBRARIES="$L4H_FSYNC_TRACE_LIBRARY"\nexec '
                        + shlex.quote(qemu_binary) + ' "$@"\n')
        shim.chmod(0o700)
        env["PATH"] = temp + os.pathsep + env["PATH"]
    disk = Path(temp) / "disk.raw"
    with disk.open("wb") as f:
        f.truncate(128 << 20)
    controller = {"driver": "virtio-scsi-pci", "id": "s0", "num_queues": args.scsi_queues,
                  "disable-modern": args.legacy, "disable-legacy": "off" if args.legacy else "on"}
    extra = []
    for i in range(args.io_threads):
        extra += ["-object", f"iothread,id=io{i},poll-max-ns=0"]
    if args.io_threads == 1:
        controller["iothread"] = "io0"
    elif args.io_threads == 4:
        # SCSI request queues are numbered from zero in this property.
        mapping = [{"iothread": f"io{i}", "vqs": [i]} for i in range(args.scsi_queues)]
        controller["iothread-vq-mapping"] = mapping
    if args.trace:
        extra += ["-trace", f"enable=virtio_queue_notify,file={args.trace.resolve()}"]
    qmp = Path(temp) / "qmp.sock"
    command = [str(root / "tools/run-image-aarch64.sh"), str(args.image.resolve()),
               "-nic", "none", "-drive", f"file={disk},if=none,id=d0,format=raw,cache=writeback",
               "-device", json.dumps(controller),
               "-device", json.dumps({"driver": "scsi-hd", "drive": "d0", "bus": "s0.0", "scsi-id": 0}),
               "-qmp", f"unix:{qmp},server=on,wait=off", "-S", *extra]
    command[command.index("-drive") + 1] = f"file={disk},if=none,id=d0,format=raw,cache={args.cache}"
    with args.log.open("w") as log:
        vm = subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT,
                              stdin=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + (420 if args.suite == "fsync" else 240)
            client = socket.socket(socket.AF_UNIX)
            while True:
                try:
                    client.connect(str(qmp))
                    break
                except (FileNotFoundError, ConnectionRefusedError):
                    if vm.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError(f"QEMU did not start: {args.log}")
                    time.sleep(0.05)
            client.settimeout(10)
            stream = client.makefile("rwb")
            json.loads(stream.readline())
            qmp_call(stream, "qmp_capabilities")
            observations.append({"kind": "threads", "threads": qmp_call(stream, "query-iothreads")})
            qmp_call(stream, "cont")
            last_phase = ""
            while vm.poll() is None and time.monotonic() < deadline:
                text = args.log.read_text(errors="replace")
                phases = re.findall(r"BLKPHASE: ([^\n\r]+)", text)
                phase = phases[-1] if phases else "boot"
                if phase != last_phase:
                    observations.append({"kind": "phase", "phase": phase, "time": time.time(),
                                         "host_loadavg": os.getloadavg(),
                                         "blockstats": qmp_call(stream, "query-blockstats"),
                                         "trace_bytes": args.trace.stat().st_size if args.trace and args.trace.exists() else None})
                    last_phase = phase
                    if args.profile and phase == "BEGIN read 4 16" and profile is None:
                        profile = subprocess.Popen(["sample", str(vm.pid), "2", "5", "-file",
                                                    str(args.log.with_suffix(".sample.txt"))],
                                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if re.search(rf"{marker}: (PASS|FAIL)|panicked at|Caught cap fault|Kernel panic", text):
                    break
                time.sleep(0.1)
        finally:
            if vm.poll() is None:
                vm.terminate()
            try:
                vm.wait(timeout=5)
            except subprocess.TimeoutExpired:
                vm.kill()
                vm.wait()
            if profile is not None:
                profile.wait(timeout=10)
            args.log.with_suffix(".qmp.json").write_text(json.dumps({"command": command, "observations": observations}, indent=2) + "\n")
text = args.log.read_text(errors="replace")
if f"{marker}: PASS" not in text or f"{marker}: FAIL" in text:
    raise SystemExit(f"block VM test failed: {args.log}")
if args.baseline and ("BLKMQ: IRQ affinity accepted" in text or "1/0/0 default/read/poll queues" not in text):
    raise SystemExit("baseline image does not have the original single-queue behavior")
if args.suite == "blkmq" and not args.baseline and "BLKMQ: IRQ affinity accepted" not in text:
    raise SystemExit("IRQ affinity regression")
if args.suite == "fsync":
    affinity = "FSYNC: CPU1 IRQ affinity accepted" in text
    if affinity == args.baseline:
        raise SystemExit("unexpected fsync IRQ affinity behavior")
if not args.baseline:
    if f"{args.guest_queues}/0/0 default/read/poll queues" not in text:
        raise SystemExit("guest queue count regression")
    if args.guest_queues == 4 and f"virtio-scsi {args.scsi_queues} request queues" not in text:
        raise SystemExit("physical queue count regression")
results = [json.loads(x) for x in re.findall(r"BLKBENCH: (\{[^\n]+\})", text)]
args.log.with_suffix(".json").write_text(json.dumps(results, indent=2) + "\n")
print(json.dumps({"pass": True, "suite": args.suite,
                  "affinity": any(x in text for x in ("BLKMQ: IRQ affinity accepted", "FSYNC: CPU1 IRQ affinity accepted")),
                  "results": results, "temporary_disk_removed": True}))

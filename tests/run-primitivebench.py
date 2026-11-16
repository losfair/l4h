#!/usr/bin/env python3
"""Measure individual APIs and fault/IPC round trips on both release kernels.

Uses the same six physical CPUs and QEMU configuration as run-smpbench.py.
Requires build/sel4 and build/sel4-fl4. Output uses a UART I/O capability.
"""
import argparse
import csv
import importlib.util
import json
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("smpbench", ROOT / "tests/run-smpbench.py")
smp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smp)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--nice", type=int, help="Runner/QEMU nice value; negative values use sudo -n renice if needed")
    parser.add_argument("--output", type=Path, default=ROOT / "build/primitivebench/results")
    parser.add_argument("--host-cpus", type=smp.cpu_list, default=[2, 3, 4, 5, 6, 7])
    parser.add_argument("--emulator-cpus", type=smp.cpu_list, default=[0, 1])
    parser.add_argument("--kernel-fl4", type=Path, default=ROOT / "build/sel4-fl4/bin/kernel.elf")
    parser.add_argument("--source", type=Path, default=ROOT / "tests/primitivebench.c")
    args = parser.parse_args()
    nice = smp.configure_nice(args.nice)
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    scratch = ROOT / "build/scratch"
    scratch.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, TMPDIR=str(scratch))
    source = args.source.resolve()
    shutil.copy2(source, args.output / source.name)
    if source.name != "primitivebench.c":
        shutil.copy2(ROOT / "tests/primitivebench.c", args.output / "primitivebench.c")
    images = {}
    for backend in ("sel4", "fl4"):
        dest = args.output / backend
        dest.mkdir()
        prefix = ROOT / ("build/sel4-fl4" if backend == "fl4" else "build/sel4")
        include = prefix / "libsel4/include"
        command = ["gcc", "-O2", "-DNDEBUG", "-static", "-nostdlib", "-ffreestanding", "-fno-builtin",
                   "-fno-pic", "-no-pie", "-fno-stack-protector", "-fcf-protection=none",
                   "-mno-red-zone", "-mgeneral-regs-only", "-Wall", "-Wextra", "-Werror",
                   f"-I{include}", f"-I{include / 'sel4'}", "-Wl,-z,max-page-size=4096",
                   "-Wl,-e,_start", "-Wl,--build-id=none", "-o", str(dest / "probe.elf"), str(source)]
        smp.run(command, env=env, log=dest / "build.log")
        kernel = args.kernel_fl4 if backend == "fl4" else prefix / "bin/kernel.elf"
        smp.run(["objcopy", "-O", "elf32-i386", str(kernel), str(dest / "kernel32.elf")], env=env)
        images[backend] = {"build_command": command, "probe_sha256": smp.digest(dest / "probe.elf"),
                           "kernel_sha256": smp.digest(kernel)}
    metadata = {"images": images, "host_cpus": args.host_cpus, "emulator_cpus": args.emulator_cpus, "nice": nice,
                "scheduler": smp.scheduler_context(),
                "fl4_kernel": str(args.kernel_fl4.resolve()),
                "l4h_revision": smp.run(["git", "rev-parse", "HEAD"]),
                "fl4_revision": (ROOT / "build/sel4-fl4/fl4-revision").read_text().strip(),
                "uname": smp.run(["uname", "-a"]), "qemu": smp.run(["qemu-system-x86_64", "--version"])}
    (args.output / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    rows = []
    for repetition in range(1, args.runs + 1):
        for backend in (("sel4", "fl4") if repetition % 2 else ("fl4", "sel4")):
            print(f"Primitive boot {repetition}/{args.runs}: {backend}", flush=True)
            dest = args.output / f"r{repetition:02d}-{backend}"
            dest.mkdir()
            qmp_path = ROOT / "build/primitivebench-qmp.sock"
            qmp_path.unlink(missing_ok=True)
            command = ["taskset", "-c", ",".join(map(str, args.emulator_cpus)), "qemu-system-x86_64",
                       "-enable-kvm", "-cpu", "host,-vmx,-svm,+invtsc", "-smp",
                       f"{len(args.host_cpus)},sockets=1,cores={len(args.host_cpus)},threads=1",
                       "-m", "4G", "-nographic", "-serial", "mon:stdio", "-no-reboot", "-nic", "none",
                       "-kernel", str(args.output / backend / "kernel32.elf"),
                       "-initrd", str(args.output / backend / "probe.elf"),
                       "-S", "-qmp", f"unix:{qmp_path},server=on,wait=off"]
            logfile = dest / "serial.log"
            info = {"command": command, "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
            qmp = None
            with logfile.open("w") as stream:
                process = subprocess.Popen(command, cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
                                           stdout=stream, stderr=subprocess.STDOUT)
                try:
                    qmp = smp.QMP(qmp_path, process)
                    threads = sorted(qmp.execute("query-cpus-fast"), key=lambda cpu: cpu["cpu-index"])
                    if len(threads) != len(args.host_cpus):
                        raise RuntimeError("unexpected QEMU CPU count")
                    for cpu, physical in zip(threads, args.host_cpus):
                        os.sched_setaffinity(cpu["thread-id"], {physical})
                        cpu["host_affinity"] = sorted(os.sched_getaffinity(cpu["thread-id"]))
                        cpu["host_stats"] = smp.thread_stats(cpu["thread-id"])
                        assert cpu["host_stats"]["nice"] == nice
                    info["cpu_threads"] = threads
                    qmp.execute("cont")
                    deadline = time.monotonic() + 240
                    while process.poll() is None:
                        text = logfile.read_text(errors="replace")
                        if "PRIMITIVE: PASS" in text or "PRIMITIVE: FAIL" in text:
                            break
                        if time.monotonic() > deadline:
                            raise TimeoutError(dest.name)
                        time.sleep(0.1)
                finally:
                    if process.poll() is None and "cpu_threads" in info:
                        info["final_thread_stats"] = {str(c["thread-id"]): smp.thread_stats(c["thread-id"])
                                                      for c in info["cpu_threads"]}
                    if qmp: qmp.close()
                    process.terminate()
                    try: process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                    qmp_path.unlink(missing_ok=True)
                    (dest / "run.json").write_text(json.dumps(info, indent=2) + "\n")
            text = logfile.read_text(errors="replace")
            if "PRIMITIVE: PASS" not in text or "PRIMITIVE: FAIL" in text:
                raise RuntimeError(f"primitive benchmark failed: {logfile}")
            for line in text.splitlines():
                if line.startswith("PRIMITIVE: metric="):
                    row = dict(item.split("=", 1) for item in line.split()[1:])
                    for key in ("trial", "ticks", "operations"): row[key] = int(row[key])
                    row.update(backend=backend, repetition=repetition)
                    row["ticks_per_op"] = row["ticks"] / row["operations"]
                    rows.append(row)
            with (args.output / "raw.csv").open("w") as stream:
                writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
                writer.writeheader()
                writer.writerows(rows)
    summary = []
    for metric in sorted({row["metric"] for row in rows}):
        entry = {"metric": metric}
        for backend in ("sel4", "fl4"):
            values = [row["ticks_per_op"] for row in rows if row["metric"] == metric
                      and row["backend"] == backend and row["trial"] > 0]
            entry[backend] = {"n": len(values), "median": statistics.median(values),
                              "min": min(values), "max": max(values)}
        entry["fl4_over_sel4"] = entry["fl4"]["median"] / entry["sel4"]["median"]
        summary.append(entry)
        print(f"{metric:40s} seL4={entry['sel4']['median']:9.1f} FL4={entry['fl4']['median']:9.1f} "
              f"ticks/op ratio={entry['fl4_over_sel4']:.2f}", flush=True)
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")


if __name__ == "__main__":
    main()

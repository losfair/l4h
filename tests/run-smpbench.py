#!/usr/bin/env python3
"""Compare seL4/FL4 with identical Linux/payload images and pinned QEMU CPUs.

Requires the usual x86_64 build prerequisites and build/linux-6.18 sources.
Example: tests/run-smpbench.py --host-cpus 2,3,4,5,6,7 --emulator-cpus 0,1
Use --skip-build only with images prepared by this script (or equivalent
release builds). --divisor 100 is a smoke check, not a performance result.
"""

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import statistics
import subprocess
import time


ROOT = Path(__file__).resolve().parents[1]
METRICS = {"compute", "getpid", "fault_4k", "fork_wait", "pipe_same", "futex_same"}


def run(command, *, env=None, log=None):
    if log:
        with open(log, "w") as stream:
            subprocess.run(command, cwd=ROOT, env=env, stdout=stream,
                           stderr=subprocess.STDOUT, check=True)
    else:
        return subprocess.check_output(command, cwd=ROOT, env=env, text=True).strip()


def digest(path):
    with open(path, "rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def configure_nice(value):
    """Set only this runner's priority; its QEMU children inherit it."""
    if value is not None:
        if not -20 <= value <= 19:
            raise ValueError("nice value must be between -20 and 19")
        try:
            os.setpriority(os.PRIO_PROCESS, 0, value)
        except PermissionError:
            run(["sudo", "-n", "renice", "-n", str(value), "-p", str(os.getpid())])
        if os.getpriority(os.PRIO_PROCESS, 0) != value:
            raise RuntimeError("benchmark priority was not applied")
    return os.getpriority(os.PRIO_PROCESS, 0)


def thread_stats(tid):
    values = [int(v) for v in Path(f"/proc/{tid}/schedstat").read_text().split()]
    return {"nice": os.getpriority(os.PRIO_PROCESS, tid),
            "affinity": sorted(os.sched_getaffinity(tid)),
            "runtime_ns": values[0], "runqueue_wait_ns": values[1], "timeslices": values[2]}


def scheduler_context():
    raw = Path("/proc/self/cgroup").read_text().strip()
    group = next((line[3:] for line in raw.splitlines() if line.startswith("0::")), None)
    if group is None:
        return {"cgroup": raw, "nice": os.getpriority(os.PRIO_PROCESS, 0)}
    base = Path("/sys/fs/cgroup") / group.lstrip("/")
    return {"cgroup": group, "nice": os.getpriority(os.PRIO_PROCESS, 0),
            **{name: (base / name).read_text().strip()
               for name in ("cpu.weight", "cpu.weight.nice", "cpu.max") if (base / name).exists()}}


def cpu_list(value):
    cpus = [int(cpu) for cpu in value.split(",")]
    if not cpus or min(cpus) < 0 or len(set(cpus)) != len(cpus):
        raise argparse.ArgumentTypeError("expected distinct, nonnegative comma-separated CPUs")
    return cpus


def physical_core(cpu):
    base = Path(f"/sys/devices/system/cpu/cpu{cpu}/topology")
    return tuple((base / name).read_text().strip()
                 for name in ("physical_package_id", "core_id"))


def default_cpus():
    cores = {}
    for cpu in sorted(os.sched_getaffinity(0)):
        cores.setdefault(physical_core(cpu), cpu)
    cpus = list(cores.values())
    reserved = 2 if len(cpus) >= 6 else 1
    return cpus[reserved:], cpus[:reserved]


def prepare(args, env):
    images = args.images
    images.mkdir(parents=True, exist_ok=True)
    print("Building shared Linux and benchmark payload", flush=True)
    run([str(ROOT / "tools/build-linux.sh"), "vmlinux"], env=env,
        log=images / "build-linux.log")
    run(["objcopy", "--strip-debug", str(ROOT / "build/linux-l4h/vmlinux"),
         str(images / "linux.elf")], env=env)
    run(["gcc", "-O2", "-static", "-Wall", "-Wextra", "-Werror", "-o",
         str(images / "smpbench"), str(ROOT / "tests/guest/smpbench.c")], env=env)
    run([str(ROOT / "tools/mkinitramfs.sh"), str(images / "initrd.cpio.gz"),
         str(ROOT / "tests/guest/init-smpbench"), str(images / "smpbench")], env=env)
    for backend in ("sel4", "fl4"):
        dest = images / backend
        dest.mkdir(exist_ok=True)
        prefix = ROOT / ("build/sel4-fl4" if backend == "fl4" else "build/sel4")
        current = dict(env, SEL4_PREFIX=str(prefix))
        print(f"Building {backend} release kernel and host", flush=True)
        script = "build-fl4.sh" if backend == "fl4" else "build-kernel.sh"
        run([str(ROOT / "tools" / script)], env=current, log=dest / "build-kernel.log")
        run([str(ROOT / "tools/build-host.sh")], env=current, log=dest / "build-host.log")
        shutil.copy2(ROOT / "host/target/x86_64-sel4-roottask/release/l4h-root.elf",
                     dest / "root.elf")
        run(["objcopy", "-O", "elf32-i386", str(prefix / "bin/kernel.elf"),
             str(dest / "kernel32.elf")], env=env)


class QMP:
    def __init__(self, path, process):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        deadline = time.monotonic() + 10
        while True:
            try:
                self.sock.connect(str(path))
                break
            except (FileNotFoundError, ConnectionRefusedError):
                if process.poll() is not None or time.monotonic() > deadline:
                    self.sock.close()
                    raise RuntimeError("QEMU did not open its QMP socket; see serial log")
                time.sleep(0.05)
        self.stream = self.sock.makefile("rwb", buffering=0)
        if "QMP" not in json.loads(self.stream.readline()):
            raise RuntimeError("missing QMP greeting")
        self.execute("qmp_capabilities")

    def execute(self, command):
        self.stream.write(json.dumps({"execute": command}).encode() + b"\n")
        while True:
            response = json.loads(self.stream.readline())
            if "error" in response:
                raise RuntimeError(response["error"])
            if "return" in response:
                return response["return"]

    def close(self):
        self.stream.close()
        self.sock.close()


def parse_log(text, backend, vcpus, repetition):
    if "SMPBENCH: FAIL" in text or "SMPBENCH: PASS" not in text:
        raise RuntimeError("benchmark did not pass; see serial log")
    if ("FL4: seL4" in text) != (backend == "fl4"):
        raise RuntimeError("booted microkernel does not match requested backend")
    if f"SMPBENCH: start workers={vcpus} " not in text:
        raise RuntimeError("guest CPU count does not match requested count")
    rows = []
    for line in text.splitlines():
        if not line.startswith("SMPBENCH: phase="):
            continue
        values = dict(part.split("=", 1) for part in line.split()[1:])
        values.update(backend=backend, vcpus=vcpus, repetition=repetition)
        for key in ("workers", "elapsed_ns", "operations", "checksum"):
            values[key] = int(values[key])
        values["value"] = float(values["value"])
        if (values["workers"] != vcpus or values["elapsed_ns"] <= 0 or
                values["operations"] <= 0 or values["value"] <= 0):
            raise RuntimeError("invalid measurement")
        latency = values["metric"].startswith(("pipe_", "futex_"))
        unit = "us/roundtrip" if latency else "ops/s"
        expected_value = (values["elapsed_ns"] / values["operations"] / 1000
                          if latency else values["operations"] * 1e9 / values["elapsed_ns"])
        if values["unit"] != unit or abs(values["value"] - expected_value) > 0.00001:
            raise RuntimeError("inconsistent measurement units or value")
        rows.append(values)
    expected = METRICS | ({"pipe_cross", "futex_cross"} if vcpus > 1 else set())
    for phase in ("warmup", "measured"):
        metrics = [row["metric"] for row in rows if row["phase"] == phase]
        if len(metrics) != len(expected) or set(metrics) != expected:
            raise RuntimeError(f"missing or duplicate {phase} measurements")
    return rows


def boot(args, env, backend, vcpus, repetition):
    dest = args.output / f"r{repetition:02d}-{backend}-{vcpus}vcpu"
    dest.mkdir()
    config = dest / "l4h.conf"
    config.write_text(f"dom0_vcpus={vcpus}\ndom0_mem_mb=512\nwatchdog_secs=0\n"
                      # quiet: logd drains the guest's boot log during the
                      # first measurements otherwise (smpbench.c).
                      f"dom0_cmdline=console=hvc0 quiet SMPBENCH_DIVISOR={args.divisor}\n")
    image = dest / "root-dom0.elf"
    run([str(ROOT / "tools/add-modules.py"), str(args.images / backend / "root.elf"),
         str(image), f"guest-kernel={args.images / 'linux.elf'}",
         f"dom0-initrd={args.images / 'initrd.cpio.gz'}", f"l4h-config={config}"],
        env=env, log=dest / "modules.log")
    # This short path avoids UNIX's 108-byte socket pathname limit. Only one
    # VM runs at a time, and the harness holds an exclusive lock on scratch.
    qmp_path = ROOT / "build/smpbench-qmp.sock"
    qmp_path.unlink(missing_ok=True)
    command = ["taskset", "-c", ",".join(map(str, args.emulator_cpus)),
               "qemu-system-x86_64", "-enable-kvm", "-cpu", "host,-vmx,-svm,+invtsc",
               "-smp", f"{len(args.host_cpus)},sockets=1,cores={len(args.host_cpus)},threads=1",
               "-m", "4G", "-nographic", "-serial", "mon:stdio", "-no-reboot", "-nic", "none",
               "-kernel", str(args.images / backend / "kernel32.elf"),
               "-initrd", str(image), "-S", "-qmp", f"unix:{qmp_path},server=on,wait=off"]
    info = {"command": command, "loadavg_before": os.getloadavg(),
            "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    logfile = dest / "serial.log"
    qmp = None
    with logfile.open("w") as serial:
        process = subprocess.Popen(command, cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
                                   stdout=serial, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            qmp = QMP(qmp_path, process)
            threads = sorted(qmp.execute("query-cpus-fast"), key=lambda cpu: cpu["cpu-index"])
            if len(threads) != len(args.host_cpus):
                raise RuntimeError("unexpected QEMU CPU count")
            info["cpu_threads"] = []
            for cpu, physical in zip(threads, args.host_cpus):
                tid = cpu["thread-id"]
                os.sched_setaffinity(tid, {physical})
                affinity = sorted(os.sched_getaffinity(tid))
                if affinity != [physical]:
                    raise RuntimeError("QEMU CPU affinity did not take effect")
                info["cpu_threads"].append(dict(cpu, host_affinity=affinity))
            (dest / "run.json").write_text(json.dumps(info, indent=2) + "\n")
            qmp.execute("cont")
            deadline = time.monotonic() + args.timeout
            while process.poll() is None:
                text = logfile.read_text(errors="replace")
                if "SMPBENCH: FAIL" in text or "SMPBENCH: PASS" in text:
                    break
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"{dest.name} exceeded {args.timeout}s")
                time.sleep(0.25)
        finally:
            if qmp:
                qmp.close()
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            qmp_path.unlink(missing_ok=True)
            info["loadavg_after"] = os.getloadavg()
            (dest / "run.json").write_text(json.dumps(info, indent=2) + "\n")
    rows = parse_log(logfile.read_text(errors="replace"), backend, vcpus, repetition)
    # Appended ELFs are fully reconstructible from the immutable input images
    # and the retained per-run config; avoid keeping a copy for every boot.
    image.unlink()
    return rows


def summarize(args, rows):
    with (args.output / "raw.csv").open("w") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    summary = []
    for vcpus in args.vcpus:
        for metric in sorted({row["metric"] for row in rows if row["vcpus"] == vcpus}):
            entry = {"vcpus": vcpus, "metric": metric}
            for backend in ("sel4", "fl4"):
                selected = [row for row in rows if row["phase"] == "measured"
                            and row["vcpus"] == vcpus and row["metric"] == metric
                            and row["backend"] == backend]
                if not selected:
                    break
                values = [row["value"] for row in selected]
                entry["unit"] = selected[0]["unit"]
                entry[f"{backend}_n"] = len(values)
                entry[f"{backend}_median"] = statistics.median(values)
                entry[f"{backend}_min"] = min(values)
                entry[f"{backend}_max"] = max(values)
            else:
                ratio = entry["fl4_median"] / entry["sel4_median"]
                entry["fl4_speedup"] = 1 / ratio if entry["unit"] == "us/roundtrip" else ratio
                summary.append(entry)
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def main():
    host_cpus, emulator_cpus = default_cpus()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host-cpus", type=cpu_list, default=host_cpus)
    parser.add_argument("--emulator-cpus", type=cpu_list, default=emulator_cpus)
    parser.add_argument("--vcpus", type=cpu_list, default=[1, 2, 4])
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--divisor", type=int, default=1)
    parser.add_argument("--timeout", type=int, default=240)
    parser.add_argument("--images", type=Path, default=ROOT / "build/smpbench/images")
    parser.add_argument("--fl4-cmake-cache", type=Path, default=ROOT / "build/kernel-fl4/CMakeCache.txt")
    parser.add_argument("--output", type=Path, default=ROOT / "build/smpbench/results")
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args()
    if (min(args.vcpus) < 1 or max(args.vcpus) > min(64, len(args.host_cpus)) or
            args.runs < 1 or not 1 <= args.divisor <= 100 or args.timeout < 1):
        parser.error("invalid vCPU count, runs, divisor or timeout")
    selected_cpus = args.host_cpus + args.emulator_cpus
    if (not set(selected_cpus) <= os.sched_getaffinity(0) or
            len({physical_core(cpu) for cpu in selected_cpus}) != len(selected_cpus)):
        parser.error("host/emulator CPUs must be available and on distinct physical cores")
    args.images = args.images.resolve()
    args.output = args.output.resolve()
    scratch = ROOT / "build/scratch"
    scratch.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, TMPDIR=str(scratch), L4H_RELEASE="1", L4H_ARCH="x86_64")
    for key in ("L4H_KERNEL_VARIANT", "L4H_KERNEL_SLOT", "SEL4_PREFIX"):
        env.pop(key, None)
    flags = re.search(r"^flags\s*:\s*(.*)$", Path("/proc/cpuinfo").read_text(), re.M)
    env.setdefault("L4H_PCID", "ON" if flags and "pcid" in flags[1].split() else "OFF")
    import fcntl
    with (scratch / "smpbench.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if not args.skip_build:
            prepare(args, env)
        if args.prepare_only:
            return
        # Refuse to mix old results with a new experiment.
        args.output.mkdir(parents=True, exist_ok=False)
        files = [args.images / "linux.elf", args.images / "initrd.cpio.gz", args.images / "smpbench"]
        files += [args.images / backend / name for backend in ("sel4", "fl4")
                  for name in ("root.elf", "kernel32.elf")]
        metadata = {"l4h_revision": run(["git", "rev-parse", "HEAD"]),
                    "sel4_revision": run(["git", "-C", "kernel/seL4", "rev-parse", "HEAD"]),
                    "sel4_patchset": (ROOT / "build/seL4-src/.git/l4h-patches").read_text().strip(),
                    "fl4_revision": (ROOT / "build/sel4-fl4/fl4-revision").read_text().strip(),
                    "qemu": run(["qemu-system-x86_64", "--version"]),
                    "lscpu": run(["lscpu"]), "uname": run(["uname", "-a"]),
                    "args": {key: str(value) if isinstance(value, Path) else value
                             for key, value in vars(args).items()},
                    "sha256": {str(path.relative_to(args.images)): digest(path) for path in files},
                    "governors": {cpu: Path(f"/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_governor").read_text().strip()
                                  if Path(f"/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_governor").exists() else "unknown"
                                  for cpu in args.host_cpus}}
        for backend in ("sel4", "fl4"):
            cache = args.fl4_cmake_cache if backend == "fl4" else ROOT / "build/kernel/CMakeCache.txt"
            shutil.copy2(cache,
                         args.output / f"{backend}-CMakeCache.txt")
        for name in ("smpbench.c", "init-smpbench"):
            shutil.copy2(ROOT / "tests/guest" / name, args.output / name)
        shutil.copy2(__file__, args.output / "run-smpbench.py")
        (args.output / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
        rows = []
        for repetition in range(1, args.runs + 1):
            for index, vcpus in enumerate(args.vcpus):
                order = ("sel4", "fl4") if (repetition + index) % 2 else ("fl4", "sel4")
                for backend in order:
                    print(f"Run {repetition}/{args.runs}: {backend}, {vcpus} guest vCPU(s)", flush=True)
                    rows.extend(boot(args, env, backend, vcpus, repetition))
                    summarize(args, rows)
        for entry in summarize(args, rows):
            print(f"{entry['vcpus']} vCPU {entry['metric']:12s} "
                  f"seL4={entry['sel4_median']:.3f} FL4={entry['fl4_median']:.3f} "
                  f"{entry['unit']} FL4 speedup={entry['fl4_speedup']:.2f}x")
        print(f"Results: {args.output}", flush=True)


if __name__ == "__main__":
    main()

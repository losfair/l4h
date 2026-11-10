#!/usr/bin/env python3
"""Verify dom0 RTC writes by reading QEMU's hardware through qtest.

Run via tests/run-rtctest.sh --qemu. qtest accesses only the emulated RTC.
"""
import calendar
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
from host_profile import root_elf  # noqa: E402
ARM = os.environ.get("L4H_ARCH", "x86_64") == "aarch64"
RUNNER = ROOT / "tools" / ("run-qemu-aarch64.sh" if ARM else "run-qemu.sh")


def connect(path, proc):
    end = time.monotonic() + 30
    while time.monotonic() < end:
        try:
            sock = socket.socket(socket.AF_UNIX)
            sock.settimeout(10)
            sock.connect(str(path))
            return sock.makefile("rwb", buffering=0)
        except (FileNotFoundError, ConnectionRefusedError):
            sock.close()
            assert proc.poll() is None, "QEMU exited before opening its sockets"
            time.sleep(0.1)
    raise TimeoutError(f"QEMU socket {path}")


def qmp(stream, command):
    stream.write(json.dumps({"execute": command}).encode() + b"\n")
    while True:
        line = stream.readline()
        if not line:
            raise RuntimeError("QMP connection closed")
        response = json.loads(line)
        assert "error" not in response, response
        if "return" in response:
            return response["return"]


def qt(stream, command):
    stream.write(command.encode() + b"\n")
    while True:
        response = stream.readline().decode().strip()
        if response.startswith("IRQ"):
            continue
        assert response.startswith("OK"), (command, response)
        return int(response.split()[1], 0) if " " in response else None


def reg(stream, index, value=None):
    qt(stream, f"outb 0x70 {index}")
    if value is None:
        return qt(stream, "inb 0x71")
    qt(stream, f"outb 0x71 {value}")


def run_case(directory, mode, control):
    name = f"{mode}-{control:02x}"
    config = directory / "l4h.conf"
    invalid = 4294967296 if ARM else 4102444800
    config.write_text(f'dom0_cmdline="console=hvc0 L4H_RTC_TEST={mode} L4H_RTC_INVALID={invalid}"\n'
                      'dom0_disks=0\ndom0_nics=0\ndom0_vcpus=1\n')
    arch = "aarch64" if ARM else "x86_64"
    log = ROOT / "build" / f"rtc-qemu-{arch}-{name}.log"
    env = dict(os.environ, L4H_CONFIG=str(config), L4H_BALLOON="0",
               L4H_SMP=os.environ.get("L4H_SMP", "4" if ARM else "2"))
    with log.open("wb") as output:
        proc = subprocess.Popen([str(RUNNER), str(root_elf(arch)),
                                 "-S", "-rtc", "base=2030-01-01T00:00:00,clock=vm",
                                 "-qmp", f"unix:{directory}/qmp,server=on,wait=off",
                                 "-qtest", f"unix:{directory}/qtest,server=on,wait=off",
                                 "-qtest-log", "/dev/null"],
                                env=env, stdin=subprocess.DEVNULL, stdout=output, stderr=output)
        monitor = None
        try:
            monitor = connect(directory / "qmp", proc)
            assert "QMP" in json.loads(monitor.readline())
            qmp(monitor, "qmp_capabilities")
            with connect(directory / "qtest", proc) as hardware:
                qmp(monitor, "cont")
                configured = ARM
                end = time.monotonic() + 360
                while time.monotonic() < end:
                    text = log.read_text(errors="replace")
                    assert "RTCTEST: FAIL" not in text, text[-4000:]
                    assert "bad boot info / ABI version" not in text, text[-4000:]
                    assert "Kernel panic" not in text, text[-4000:]
                    assert "panicked at" not in text, text[-4000:]
                    assert proc.poll() is None, text[-4000:]
                    if not configured and "RTCTEST: ready" in text:
                        # SeaBIOS forces BCD/24h at boot. Change the mode
                        # after firmware has finished, while init sleeps.
                        qmp(monitor, "stop")
                        enc = lambda v: v if control & 4 else (v // 10) * 16 + v % 10
                        reg(hardware, 0x0b, control | 0x80)
                        for index, value in [(0, 0), (2, 0), (4, 0 if control & 2 else 12),
                                             (6, 3), (7, 1), (8, 1), (9, 30), (0x32, 20)]:
                            reg(hardware, index, enc(value))
                        reg(hardware, 0x0b, control)
                        assert reg(hardware, 0x0b) == control
                        configured = True
                        qmp(monitor, "cont")
                    if "l4h-vmmgr: all guests stopped" in text:
                        break
                    time.sleep(0.1)
                else:
                    raise TimeoutError(f"guest did not finish; see {log}")
                match = re.search(r"RTCTEST: PASS target=(\d+)", text)
                assert match, text[-4000:]
                assert configured, "CMOS mode was not set before the guest finished"
                target = int(match[1])
                qmp(monitor, "stop")
                if ARM:
                    seconds = qt(hardware, "readl 0x09010000")
                else:
                    assert reg(hardware, 0x0b) == control, "RTC mode changed or SET left on"
                    dec = lambda v: v if control & 4 else (v // 16) * 10 + v % 16
                    sec, minute, hour, day, month, year, century = [
                        reg(hardware, index) for index in [0, 2, 4, 7, 8, 9, 0x32]]
                    pm = hour & 0x80
                    hour = dec(hour & 0x7f)
                    if not control & 2:
                        hour = hour % 12 + (12 if pm else 0)
                    seconds = calendar.timegm((dec(century) * 100 + dec(year), dec(month), dec(day),
                                                hour, dec(minute), dec(sec)))
                assert target <= seconds <= target + 120, (name, seconds, target)
                print(f"RTCTEST: QEMU {name}: hardware RTC verified ({seconds})", flush=True)
        finally:
            if monitor is not None:
                try:
                    qmp(monitor, "quit")
                except (OSError, RuntimeError):
                    pass
                finally:
                    monitor.close()
            else:
                proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


with tempfile.TemporaryDirectory(prefix="l4h-rtc-") as temporary:
    directory = Path(temporary)
    for control in ([2] if ARM else [2, 0, 6, 4]):
        run_case(directory, "explicit", control)
    run_case(directory, "default", 2)

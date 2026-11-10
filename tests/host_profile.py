# SPDX-License-Identifier: GPL-2.0-only
"""Where the host build put l4h-root, for the Python tests: the cargo
profile directory comes from tools/host-profile.sh, its one definition
(debug, or release with L4H_RELEASE=1)."""
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def profile() -> str:
    return subprocess.run(
        ["bash", "-c", 'root=$1; source "$root/tools/host-profile.sh"; printf %s "$l4h_profile"', "-", str(ROOT)],
        check=True, capture_output=True, text=True,
    ).stdout


def root_elf(arch: str = "x86_64") -> Path:
    return ROOT / f"host/target/{arch}-sel4-roottask/{profile()}/l4h-root.elf"

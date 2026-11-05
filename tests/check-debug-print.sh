#!/usr/bin/env bash
# Only l4h-logd writes the serial port (DESIGN.md §10.4): host code never
# prints through the kernel.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
found=$(grep -rnE '\bdebug_put_char\b|\bdebug_print(ln)?!' "$root/host" --include='*.rs' --exclude-dir=target || true)
if [ -n "$found" ]; then
    echo "$found"
    echo "host code prints through the kernel: use log! or info!"
    exit 1
fi

#!/usr/bin/env bash
# Only l4h-logd writes the serial port (DESIGN.md §10.4): host code never
# prints through the kernel. aarch64, which has no logd yet, still does, on
# lines marked "no logd here yet".
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
found=$(grep -rnE '\bdebug_put_char\b|\bdebug_print(ln)?!' "$root/host" --include='*.rs' --exclude-dir=target \
    | grep -v 'no logd here yet' || true)
if [ -n "$found" ]; then
    echo "$found"
    echo "host code prints through the kernel: use log! or info!"
    exit 1
fi

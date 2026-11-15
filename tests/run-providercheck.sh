#!/usr/bin/env bash
# Pure bootstrap checks; intentionally compile without libsel4 or Linux headers.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$root/build/provider-check"
gcc -O2 -Wall -Wextra -Werror -I"$root/include" "$root/tests/provider-table.c" \
    -o "$root/build/provider-check/provider-table"
"$root/build/provider-check/provider-table" "$@"
if command -v aarch64-linux-gnu-gcc >/dev/null; then
    aarch64-linux-gnu-gcc -Wall -Wextra -Werror -I"$root/include" \
        -c "$root/tests/provider-table.c" -o "$root/build/provider-check/table-aarch64.o"
fi

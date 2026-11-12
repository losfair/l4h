#!/usr/bin/env bash
# Pure host-side tests of CPU topology, migration policy and CPU budgets.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$root/build"
cd "$root/host"
rustc --edition=2024 --test "$root/tests/sched.rs" -o "$root/build/schedtest"
"$root/build/schedtest"

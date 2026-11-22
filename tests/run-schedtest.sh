#!/usr/bin/env bash
# Pure host-side tests of CPU topology, placement, migration policy and CPU
# budgets, then the closed-loop scheduling simulation (tests/dst-sched.rs).
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$root/build"
cd "$root/host"
rustc --edition=2024 --test "$root/tests/sched.rs" -o "$root/build/schedtest"
"$root/build/schedtest"
rustc --edition=2024 -O --test "$root/tests/dst-sched.rs" -o "$root/build/dst-schedtest"
"$root/build/dst-schedtest" "$@"

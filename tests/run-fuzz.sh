#!/usr/bin/env bash
# Host-side randomised tests of guest-facing parsers.  Debug build: like
# the host components, it checks overflow and pointer preconditions.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
(cd "$root/tests/fuzz-virtq" && cargo +stable test -q && cargo +stable run -q -- "${1:-200000}")

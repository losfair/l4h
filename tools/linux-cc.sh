#!/usr/bin/env bash
# Kbuild's Rust host tools require -Clinker to name one executable, even
# when L4H_LINUX_CC is a compiler command such as "ccache gcc".
set -euo pipefail
read -r -a compiler <<<"${L4H_LINUX_CC:-gcc}"
exec "${compiler[@]}" "$@"

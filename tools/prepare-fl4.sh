#!/usr/bin/env bash
# Make a private build tree from a frozen FL4 checkout. Neither
# that worktree nor FL4's actively developed main checkout is edited.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
frozen=$(realpath "${L4H_FL4_SOURCE:?set L4H_FL4_SOURCE to a frozen FL4 worktree}")
if git -C "$frozen" symbolic-ref -q HEAD >/dev/null; then
    echo "$frozen is on a branch; use a detached FL4 worktree" >&2
    exit 1
fi
src=$root/build/FL4-src
base=$(git -C "$frozen" rev-parse HEAD)
stamp=$src/.git/l4h-source
if [ ! -d "$src/.git" ]; then
    git clone -q --shared "$frozen" "$src"
fi
if [ -n "$(git -C "$src" status --porcelain --untracked-files=no)" ]; then
    echo "$src has uncommitted changes; cannot build unmodified FL4 source" >&2
    exit 1
fi
if [ "$(cat "$stamp" 2>/dev/null)" != "$base" ] ||
   [ "$(git -C "$src" rev-parse HEAD)" != "$base" ]; then
    git -C "$src" fetch -q "$frozen" "$base"
    git -C "$src" checkout -q -B l4h "$base"
    ref=()
    if [ -e "$frozen/vendor/seL4/.git" ]; then
        ref=(--reference "$frozen/vendor/seL4")
    fi
    git -c protocol.file.allow=always -C "$src" submodule update --init "${ref[@]}" -- vendor/seL4
    echo "$base" >"$stamp"
fi

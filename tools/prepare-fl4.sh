#!/usr/bin/env bash
# Make a private build tree from the pinned public FL4 revision, or from
# L4H_FL4_SOURCE, a frozen checkout. The source worktree is never edited.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
clone_args=(--no-checkout)
if [ -n "${L4H_FL4_SOURCE:-}" ]; then
    frozen=$(realpath "$L4H_FL4_SOURCE")
    if git -C "$frozen" symbolic-ref -q HEAD >/dev/null; then
        echo "$frozen is on a branch; use a detached FL4 worktree" >&2
        exit 1
    fi
    base=$(git -C "$frozen" rev-parse HEAD)
    clone_args+=(--shared)
else
    frozen=https://github.com/losfair/FL4.git
    base=$(cat "$root/kernel/fl4/REVISION")
fi
src=$root/build/FL4-src
stamp=$src/.git/l4h-source
if [ ! -d "$src/.git" ]; then
    git clone -q "${clone_args[@]}" "$frozen" "$src"
    git -C "$src" checkout -q -B l4h "$base"
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
    if [ -n "${L4H_FL4_SOURCE:-}" ] && [ -e "$frozen/vendor/seL4/.git" ]; then
        ref=(--reference "$frozen/vendor/seL4")
    fi
    git -c protocol.file.allow=always -C "$src" submodule update --init "${ref[@]}" -- vendor/seL4
    echo "$base" >"$stamp"
fi

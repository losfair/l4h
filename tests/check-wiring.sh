#!/usr/bin/env bash
# Every IPC capability is minted from its edge (l4h_host::wiring, through
# l4h_task::edge): the only other mints are of a CNode's guard (and the
# give_badged that does them).
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
found=$(find "$root/host" -name '*.rs' -not -path '*/target/*' \
    -not -path '*/l4h-task/src/edge.rs' -not -path '*/l4h-host/src/*' -print0 |
    xargs -0 perl -0777 -ne '
        while (/(\.mint|give_badged)\s*\(([^;]*?);/sg) {
            my ($call, $args, $start) = ($1, $2, $-[0]);
            if ($args !~ /guard|CNodeCapData|\brights, badge\)/) {
                my $line = 1 + (substr($_, 0, $start) =~ tr/\n//);
                print "$ARGV:$line: $call(" . ($args =~ s/\s+/ /gr) . "\n";
            }
        }' || true)
if [ -n "$found" ]; then
    echo "$found"
    echo "an IPC capability minted without its edge: declare it in l4h_host::wiring and mint it with l4h_task::edge"
    exit 1
fi

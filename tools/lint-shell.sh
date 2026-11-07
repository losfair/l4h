#!/usr/bin/env bash
# Lint every shell script in the repository with ShellCheck, failing on the
# checks that find real bugs here; CI runs this (.github/workflows/test.yml).
# The scripts are the tracked *.sh files and the extensionless files whose
# first line is a sh or bash shebang (guest init scripts, tools/install/init).
#
# Failing checks:
#  - every error-severity finding (syntax errors, unknown shell);
#  - SC2251: a bare "! cmd" is not a condition, so set -e ignores it and a
#    check like "! grep -q FAIL log" stops a test only as its last command.
# Pass -a (all) to also print warnings and style notes, without failing.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
scripts=()
while IFS= read -r -d '' f; do
    [ -f "$f" ] || continue
    case "$f" in
        *.sh) scripts+=("$f") ;;
        */*.*|*.*) ;;
        *) head -n1 "$f" | grep -qE '^#!.*[/ ](ba|da)?sh( |$)' && scripts+=("$f") ;;
    esac
done < <(git ls-files -z -- ':!third_party' ':!guest/linux')
echo "shellcheck: ${#scripts[@]} scripts"
if [ "${1:-}" = -a ]; then
    shellcheck -f gcc "${scripts[@]}" || true
fi
status=0
shellcheck -S error "${scripts[@]}" || status=1
shellcheck -i SC2251 "${scripts[@]}" || status=1
exit $status

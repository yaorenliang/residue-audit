#!/bin/sh
# L3: recompute alignment with stat(1) and the shell, and compare with residue.
#
# Identification comes from residue (which files count as ours is a judgement
# call, and duplicating it here would just duplicate the bug). Measurement does
# not: every number below is produced by stat(1), not by residue's Python.
#
# Two rules keep this honest:
#   1. A residue run that cannot produce a report is a failure, not a zero.
#      The previous version appended `|| true` and then compared 0 with 0,
#      which turned a crashed checker into a green cross-check.
#   2. The numbers are read as JSON, not scraped out of the pretty printer.
#      Indentation is a presentation detail; a gate must not depend on it.
#
# Usage: tests/cross_check.sh ROOT

set -eu

root=${1:?usage: cross_check.sh ROOT}

stat_ms() {
    if stat -c %Y "$1" >/dev/null 2>&1; then
        echo $(( $(stat -c %Y "$1") * 1000 ))
    else
        echo $(( $(stat -f %m "$1") * 1000 ))
    fi
}

# residue exits 0..3 for its verdicts; 4 means the tool itself failed. Only the
# second kind is fatal here, and the docs for that code path live in README.
json=""
status=0
json=$(python3 -m residue.cli trace "$root" --json) || status=$?
if [ "$status" -ge 4 ]; then
    echo "CROSS_FAIL=residue exited $status" >&2
    exit 1
fi
if [ -z "$json" ]; then
    echo "CROSS_FAIL=residue produced no report" >&2
    exit 1
fi

paths=$(printf '%s' "$json" | python3 -c '
import json, sys
report = json.load(sys.stdin)
for check in report.get("checks", []):
    for item in check.get("evidence", []):
        if item.get("field") == "marker":
            print(item["path"].replace("<root>", sys.argv[1]))
' "$root")

read_fact() {
    printf '%s' "$json" | python3 -c '
import json, sys
report = json.load(sys.stdin)
value = report.get("facts", {}).get(sys.argv[1])
print("" if value is None else value)
' "$1"
}

# membership tests below compare against a space-padded list: a newline
# separated one would let every artifact be its own sibling
members=" $(printf '%s' "$paths" | tr '\n' ' ') "

# A sibling is a regular file in the same directory. Directories are not
# siblings: their mtime moves whenever anything inside them is created, which
# would let one new subdirectory vouch for every artifact next to it.
aligned=0
leaks=0
for artifact in $paths; do
    mtime=$(stat_ms "$artifact")
    dir=$(dirname "$artifact")
    cap=0
    while IFS= read -r sibling; do
        [ -n "$sibling" ] || continue
        case "$members" in
            *" $sibling "*) continue ;;
        esac
        value=$(stat_ms "$sibling")
        if [ "$value" -gt "$cap" ]; then
            cap=$value
        fi
    done <<EOF
$(find "$dir" -mindepth 1 -maxdepth 1 -type f ! -type l | sort)
EOF
    if [ "$cap" -eq 0 ]; then
        continue  # no sibling to compare against; alignment is unmeasurable here
    fi
    if [ "$mtime" -gt "$cap" ]; then
        leaks=$((leaks + 1))
    else
        aligned=$((aligned + 1))
    fi
done

their_aligned=$(read_fact aligned)
their_leaks=$(read_fact leaks)

echo "CROSS_ALIGNED=$aligned"
echo "CROSS_LEAKS=$leaks"
echo "RESIDUE_ALIGNED=${their_aligned:--}"
echo "RESIDUE_LEAKS=${their_leaks:--}"

if [ -z "$their_aligned" ] || [ -z "$their_leaks" ]; then
    echo "CROSS_FAIL=residue report has no counts" >&2
    exit 1
fi

if [ "$aligned" = "$their_aligned" ] && [ "$leaks" = "$their_leaks" ]; then
    echo "CROSS_MATCH=1"
    exit 0
fi

echo "CROSS_MATCH=0"
exit 1

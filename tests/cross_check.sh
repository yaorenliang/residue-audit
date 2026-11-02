#!/bin/sh
# L3: recompute alignment with stat(1) and the shell, and compare with residue.
#
# Identification comes from residue (which files count as ours is a judgement
# call, and duplicating it here would just duplicate the bug). Measurement does
# not: every number below is produced by stat(1), not by residue's Python.
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

# residue exits non-zero when a check fails, which is exactly when we still
# want its output, so the status is ignored on purpose
json=$(python3 -m residue.cli trace "$root" --json || true)

paths=$(printf '%s\n' "$json" \
    | sed -n '/"field": "marker"/{n;p;}' \
    | sed -n 's/.*"path": "\(.*\)",*/\1/p' \
    | sed "s#<root>#${root}#")

# membership tests below compare against a space-padded list: a newline
# separated one would let every artifact be its own sibling
members=" $(printf '%s' "$paths" | tr '\n' ' ') "

aligned=0
leaks=0
for artifact in $paths; do
    mtime=$(stat_ms "$artifact")
    dir=$(dirname "$artifact")
    cap=0
    for sibling in "$dir"/*; do
        [ -f "$sibling" ] || continue
        case "$members" in
            *" $sibling "*) continue ;;
        esac
        value=$(stat_ms "$sibling")
        if [ "$value" -gt "$cap" ]; then
            cap=$value
        fi
    done
    if [ "$cap" -eq 0 ]; then
        continue  # no sibling to compare against; alignment is unmeasurable here
    fi
    if [ "$mtime" -gt "$cap" ]; then
        leaks=$((leaks + 1))
    else
        aligned=$((aligned + 1))
    fi
done

their_aligned=$(printf '%s\n' "$json" | sed -n 's/.*"aligned": \([0-9]*\).*/\1/p' | head -1)
their_leaks=$(printf '%s\n' "$json" | sed -n 's/.*"leaks": \([0-9]*\).*/\1/p' | head -1)

echo "CROSS_ALIGNED=$aligned"
echo "CROSS_LEAKS=$leaks"
echo "RESIDUE_ALIGNED=${their_aligned:-0}"
echo "RESIDUE_LEAKS=${their_leaks:-0}"

if [ "$aligned" = "${their_aligned:-0}" ] && [ "$leaks" = "${their_leaks:-0}" ]; then
    echo "CROSS_MATCH=1"
    exit 0
fi

echo "CROSS_MATCH=0"
exit 1
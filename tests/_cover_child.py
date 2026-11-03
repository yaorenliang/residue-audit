"""Run one residue entry point under the stdlib tracer, for tests/coverage.py.

A tracer cannot follow a subprocess, so the lines "python3 -m residue" executes
were invisible to the suite's tracer and the coverage table printed 0/4 for a
module that tests/test_entrypoints.py proves is tested. This child installs the
same tracer in its own process and writes the hit lines to the file it is given.

Usage: python3 tests/_cover_child.py OUT.json [entry-point args...]
"""

from __future__ import annotations

import json
import os
import runpy
import sys
import trace

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main(argv) -> int:
    if not argv:
        sys.stderr.write("usage: _cover_child.py OUT.json [args...]" + "\n")
        return 2
    out = argv[0]
    rest = list(argv[1:])
    sys.path.insert(0, REPO)
    tracer = trace.Trace(count=1, trace=0, ignoredirs=[sys.prefix, sys.exec_prefix])

    def go() -> None:
        sys.argv = ["residue"] + rest
        try:
            runpy.run_module("residue", run_name="__main__")
        except SystemExit:
            pass

    tracer.runfunc(go)
    root = os.path.realpath(REPO) + os.sep
    hits = {}
    for (filename, lineno), seen in tracer.results().counts.items():
        if not seen:
            continue
        path = os.path.realpath(filename)
        if path.startswith(root):
            hits.setdefault(path, []).append(lineno)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(hits, fh, sort_keys=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

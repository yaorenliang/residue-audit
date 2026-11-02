"""Line coverage for residue/*.py, using only the standard library.

No coverage package, no dependency, on purpose: the project advertises "pip
install into a restricted host", and adding a dev-only dependency to measure it
would be the same promise broken from the other side. ``trace`` from the stdlib
is slow and crude, and for a 1.1 kLOC package that is the right trade.

Usage: python3 tests/coverage.py [--min 85] [--quiet]
"""

from __future__ import annotations

import argparse
import ast
import io
import os
import sys
import trace
import unittest
from collections import defaultdict

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKAGE = os.path.join(REPO, "residue")


def _measurable_lines(path: str) -> set:
    """Statement lines that could execute. Docstrings and blanks are not code."""
    with open(path, encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    lines = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.stmt):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                for sub in ast.walk(node):
                    if isinstance(sub, ast.stmt):
                        lines.add(sub.lineno)
                continue
            lines.add(node.lineno)
    return lines


def measure() -> list:
    """Run the suite under trace and return [(name, hit, total, percent)]."""
    cwd = os.getcwd()
    sys.path.insert(0, REPO)
    os.chdir(REPO)
    tracer = trace.Trace(count=1, trace=0, ignoredirs=[sys.prefix, sys.exec_prefix])

    def run() -> unittest.TestResult:
        suite = unittest.TestLoader().discover("tests", top_level_dir=".")
        runner = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0)
        return runner.run(suite)

    try:
        result = tracer.runfunc(run)
        if not result.wasSuccessful():
            raise SystemExit("coverage: the suite is not green, so the numbers mean nothing")
        counts = tracer.results().counts
    finally:
        os.chdir(cwd)

    executed = defaultdict(set)
    for (filename, lineno), _hits in counts.items():
        executed[os.path.realpath(filename)].add(lineno)

    rows = []
    for name in sorted(os.listdir(PACKAGE)):
        if not name.endswith(".py"):
            continue
        path = os.path.join(PACKAGE, name)
        lines = _measurable_lines(path)
        hit = lines & executed[os.path.realpath(path)]
        rows.append((name, len(hit), len(lines), 100.0 * len(hit) / len(lines) if lines else 100.0))
    return rows


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="line coverage for residue/*.py")
    parser.add_argument("--min", type=float, default=None, help="fail below this percentage")
    parser.add_argument("--quiet", action="store_true", help="only print the total")
    args = parser.parse_args(argv)

    rows = measure()
    total_hit = sum(row[1] for row in rows)
    total_lines = sum(row[2] for row in rows)
    total = 100.0 * total_hit / total_lines if total_lines else 100.0
    if not args.quiet:
        for name, hit, lines, pct in rows:
            print("COV %-14s %4d/%-4d %5.1f%%" % (name, hit, lines, pct))
    print("COVERAGE_TOTAL %d/%d = %.1f%%" % (total_hit, total_lines, total))
    if args.min is not None and total < args.min:
        print("COVERAGE_FLOOR %.1f%% not met (need %.1f%%)" % (total, args.min))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

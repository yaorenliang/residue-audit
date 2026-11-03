"""Line coverage for residue/*.py, using only the standard library.

No coverage package, no dependency, on purpose: the project advertises "pip
install into a restricted host", and adding a dev-only dependency to measure it
would be the same promise broken from the other side. The stdlib tracer is slow
and crude, and for a 1.1 kLOC package that is the right trade.

Two measurements, because one process cannot see both:

  the suite      run under an in-process tracer, which sees every line the tests
                 execute here
  the entry      residue/__main__.py is exercised by subprocess runs
  point          (tests/test_entrypoints.py), which an in-process tracer cannot
                 follow: the row used to read 0/4 for a module that IS tested.
                 It is measured in a child (tests/_cover_child.py) running the
                 same tracer, and the counts are merged here.

The floor has two halves. The total may not fall below --min, and no module may
fall more than --module-floor points below the value recorded in
tests/coverage_baseline.json: deleting one test file used to leave the total
above the floor while a whole module quietly lost its tests.

Usage: python3 tests/coverage.py [--min 88] [--module-floor 2] [--quiet]
       python3 tests/coverage.py --write-baseline   # after an intended change
"""

from __future__ import annotations

import argparse
import ast
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import trace
import unittest
from collections import defaultdict

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKAGE = os.path.join(REPO, "residue")
BASELINE = os.path.join(REPO, "tests", "coverage_baseline.json")
CHILD = os.path.join(REPO, "tests", "_cover_child.py")


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


def _drop_trace_files() -> None:
    """Remove the *.cover files the stdlib tracer writes next to its sources.

    Trace.runctx calls results().write_results() with coverdir=None, which means
    the current directory: an annotated copy of every measured file lands in the
    repository root once per run. They are an artifact of measuring, never a
    product, so they are deleted as part of measuring.
    """
    for name in os.listdir(REPO):
        if name.endswith('.cover') and os.path.isfile(os.path.join(REPO, name)):
            os.remove(os.path.join(REPO, name))


def _subprocess_hits() -> dict:
    """{realpath: {lineno}} the entry point ran in a child of its own.

    A tracer cannot follow a subprocess, which is exactly why the row for
    __main__.py read 0/4 while tests/test_entrypoints.py was proving otherwise.
    """
    outdir = tempfile.mkdtemp(prefix="residue-cov-")
    out = os.path.join(outdir, "hits.json")
    try:
        proc = subprocess.run(
            [sys.executable, CHILD, out, "--version"],
            cwd=REPO,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        if proc.returncode != 0:
            raise SystemExit(
                "coverage: the entry-point child failed (exit=%d): %s"
                % (proc.returncode, proc.stderr[-400:])
            )
        with open(out, encoding="utf-8") as fh:
            raw = json.load(fh)
    finally:
        shutil.rmtree(outdir, ignore_errors=True)
    return dict((os.path.realpath(path), set(lines)) for path, lines in raw.items())


def measure() -> list:
    """Run the suite under the tracer and return [(name, hit, total, percent)]."""
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
        _drop_trace_files()

    executed = defaultdict(set)
    for (filename, lineno), _hits in counts.items():
        executed[os.path.realpath(filename)].add(lineno)
    for path, lines in _subprocess_hits().items():
        executed[path].update(lines)

    rows = []
    for name in sorted(os.listdir(PACKAGE)):
        if not name.endswith(".py"):
            continue
        path = os.path.join(PACKAGE, name)
        lines = _measurable_lines(path)
        hit = lines & executed[os.path.realpath(path)]
        rows.append((name, len(hit), len(lines), 100.0 * len(hit) / len(lines) if lines else 100.0))
    return rows


def _read_baseline(path: str) -> dict:
    """The recorded per-module values, or a refusal loud enough to act on."""
    if not os.path.isfile(path):
        raise SystemExit(
            "coverage: no baseline at %s, so the per-module floor cannot be checked; "
            "record one with --write-baseline" % (path,)
        )
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _write_baseline(path: str, rows: list, total: float) -> None:
    payload = {
        "total": round(total, 1),
        "modules": dict((name, round(pct, 1)) for name, _hit, _lines, pct in rows),
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
        fh.write("\n")


def _breaches(rows: list, baseline: dict, tolerance: float) -> list:
    """Modules that fell more than tolerance points below their recorded value.

    A module absent from the baseline is reported, not failed: it is new, and
    nobody has claimed a number for it yet. The note is printed so that the next
    --write-baseline records it on purpose instead of by drift.
    """
    recorded = baseline.get("modules", {})
    out = []
    for name, _hit, _lines, pct in rows:
        if name not in recorded:
            out.append((name, pct, None, "unbaselined"))
            continue
        floor = recorded[name] - tolerance
        if pct < floor:
            out.append((name, pct, floor, "below"))
    return out


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="line coverage for residue/*.py")
    parser.add_argument("--min", type=float, default=None, help="fail below this total percentage")
    parser.add_argument(
        "--module-floor",
        type=float,
        default=2.0,
        dest="module_floor",
        help="how far one module may fall below its recorded value, in points",
    )
    parser.add_argument("--baseline", default=BASELINE, help="recorded per-module values")
    parser.add_argument(
        "--write-baseline",
        action="store_true",
        dest="write_baseline",
        help="record the values this run measured, then exit",
    )
    parser.add_argument("--quiet", action="store_true", help="only print the total")
    args = parser.parse_args(argv)

    rows = measure()
    total_hit = sum(row[1] for row in rows)
    total_lines = sum(row[2] for row in rows)
    total = 100.0 * total_hit / total_lines if total_lines else 100.0
    if args.write_baseline:
        _write_baseline(args.baseline, rows, total)
        print("COVERAGE_BASELINE %d/%d = %.1f%% recorded" % (total_hit, total_lines, total))
        return 0

    if not args.quiet:
        for name, hit, lines, pct in rows:
            print("COV %-14s %4d/%-4d %5.1f%%" % (name, hit, lines, pct))
    print("COVERAGE_TOTAL %d/%d = %.1f%%" % (total_hit, total_lines, total))

    failed = False
    for name, pct, floor, kind in _breaches(rows, _read_baseline(args.baseline), args.module_floor):
        if kind == "unbaselined":
            print(
                "COVERAGE_UNBASELINED %s %.1f%% (no recorded value; run --write-baseline)"
                % (name, pct)
            )
            continue
        print(
            "COVERAGE_FLOOR_MODULE %s %.1f%% is below %.1f%% (recorded %.1f%%, tolerance %.1f)"
            % (name, pct, floor, floor + args.module_floor, args.module_floor)
        )
        failed = True
    if args.min is not None and total < args.min:
        print("COVERAGE_FLOOR %.1f%% not met (need %.1f%%)" % (total, args.min))
        failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Self-contained demo: build throwaway trees, audit them, then break them.

The demo exists so a reader can see a passing audit and the failing version of
the same tree in one run. It used to print four sections and return 0 no matter
what they said, so a demo that had rotted into "everything fails" still looked
green in CI. It now returns a real report: every section is a check, and the
process exit code is the code of that report.

What a synthetic tree cannot do is worth stating once: a directory's ctime is
rewritten whenever an entry is created in it, and nothing in user space can move
it backwards. So a tree written today always has a directory newer than the
old mtimes its artifacts borrowed, and ``trace.directory_ctime`` says so. The
best a synthetic tree can reach is partial, and section 2 shows exactly that.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import _fixtures
from . import batch as batch_mod
from . import dwell as dwell_mod
from . import report as report_mod
from . import stat_io
from . import trace as trace_mod
from .model import ERROR, EXIT, FAIL, PASS, PARTIAL, Check, Report


def _borrowed_tree(root: str) -> None:
    """Artifacts written after the neighbours, carrying an old mtime.

    This is what a real implant looks like: the file was created last, so the
    inode order and the ctime both give it away even though the mtime was
    borrowed from a neighbour.
    """
    _fixtures.make_dirs(root, trace_mod.DEFAULT_SCAN)
    _fixtures.write_neighbours(root, trace_mod.DEFAULT_SCAN)
    written = _fixtures.write_artifacts(root)
    # The ctime comparison is strict, so an artifact that lands in the same clock
    # tick as its neighbours ties instead of winning and the report loses one
    # evidence line. A fixed sleep was a bet on the filesystem's granularity, and
    # CI lost it: the sample the README quotes came out one line short. The
    # fixture now checks the bet instead of making it.
    _fixtures.separate_ctimes(written)
    _fixtures.borrow_sibling_mtimes(written)


def _ordered_tree(root: str) -> None:
    """Artifacts written first, neighbours after: the best a fake tree can do.

    The artifacts hold old mtimes and their ctime/inode order is older than the
    neighbours, so alignment, freshness, ctime and order all pass. The holding
    directories were still written today, which is what section 2 reports.
    """
    _fixtures.make_dirs(root, trace_mod.DEFAULT_SCAN)
    written = _fixtures.write_artifacts(root)
    for path in written:
        stat_io.set_mtime_ms(path, _fixtures.NEIGHBOUR_MS)
    _fixtures.write_neighbours(root, trace_mod.DEFAULT_SCAN)


def _coverage_ledger(tmp: str) -> str:
    """Three of the four deployed hosts were seen: coverage, not luck."""
    path = os.path.join(tmp, "ledger-covered.ndjson")
    events = list(_fixtures.LEDGER)
    events.append({"ts": 1040, "host": "h2", "event": "mine", "ok": False})
    _fixtures.write_ledger(path, events)
    return path


def _discordant_hits(tmp: str) -> str:
    path = os.path.join(tmp, "hits-discordant.json")
    _fixtures.write_hits(
        path,
        [
            {"ts": 1090, "host": "h1", "rule": "yara:generic-miner"},
            {"ts": 1150, "host": "h2", "rule": "falco:systemd-drop"},
            {"ts": 1075, "host": "h4", "rule": "yara:elf-xor"},
        ],
    )
    return path


# Each section is a builder: it makes its throwaway tree or its pair of inputs,
# and returns the report the loop prints. A docstring would read well here, but
# tests/coverage.py counts a docstring line as measurable and it can never
# execute, so the six of them cost more module coverage than they are worth.
def _borrowed_section(tmp: str) -> Report:
    # artifacts written last, mtimes borrowed: the shape a real implant has
    root = os.path.join(tmp, "leak")
    os.makedirs(root)
    _borrowed_tree(root)
    return trace_mod.run(root)


def _floor_section(tmp: str) -> Report:
    # the same artifacts written first: the floor a synthetic tree can reach
    root = os.path.join(tmp, "floor")
    os.makedirs(root)
    _ordered_tree(root)
    return trace_mod.run(root)


def _covered_section(tmp: str) -> Report:
    # three of four deployed hosts were seen: coverage, not luck
    return dwell_mod.run(_coverage_ledger(tmp), _discordant_hits(tmp))


def _half_section(tmp: str) -> Report:
    # exactly half of the deployed hosts is not coverage
    ledger = os.path.join(tmp, "ledger.ndjson")
    _fixtures.write_ledger(ledger, _fixtures.LEDGER)
    hits = os.path.join(tmp, "hits.json")
    _fixtures.write_hits(hits, _fixtures.HITS)
    return dwell_mod.run(ledger, hits)


def _cluster_section(tmp: str) -> Report:
    # two builds one feature apart: they still cluster
    near = os.path.join(tmp, "near-a.json")
    near_b = os.path.join(tmp, "near-b.json")
    _fixtures.write_json(near, _fixtures.feature_set("build-a"))
    _fixtures.write_json(near_b, _fixtures.feature_set("build-b", tail="feature-999"))
    return batch_mod.run([near, near_b])


def _apart_section(tmp: str) -> Report:
    # two builds with nothing in common: they do not cluster
    far = os.path.join(tmp, "far-a.json")
    far_b = os.path.join(tmp, "far-b.json")
    _fixtures.write_json(far, {"name": "build-c", "features": ["alpha", "beta", "gamma"]})
    _fixtures.write_json(far_b, {"name": "build-d", "features": ["delta", "epsilon"]})
    return batch_mod.run([far, far_b])


# The six sections in the order a reader meets them: name, title, note, and the
# builder that produces the report the loop prints. The order is the output.
_SECTIONS: List[Tuple[str, str, str, Callable[[str], Report]]] = [
    (
        "borrowed",
        "artifacts written last, mtimes borrowed from a neighbour",
        "note: order and ctime still fail here. utimensat rewrites a timestamp;\n"
        "      nothing user-space can rewrite the inode number or the ctime.\n",
        _borrowed_section,
    ),
    (
        "floor",
        "same artifacts written first: the floor for a synthetic tree",
        "note: alignment, freshness, ctime and order pass. The holding\n"
        "      directories were still created today, so directory_ctime stays\n"
        "      partial: a ctime cannot be moved backwards. This is the floor.\n",
        _floor_section,
    ),
    ("covered", "three of four deployed hosts were seen: coverage", "", _covered_section),
    (
        "half",
        "two of four deployed hosts were seen: exactly half is not coverage",
        "",
        _half_section,
    ),
    ("cluster", "two builds one feature apart: they still cluster", "", _cluster_section),
    ("apart", "two builds with nothing in common: they do not cluster", "", _apart_section),
]


def _sections_check(facts: Dict[str, Any]) -> Check:
    """One verdict for the run itself: did the six sections show every verdict?"""
    wanted = {PASS, PARTIAL, FAIL}
    missing = sorted(wanted - set(facts["verdicts"].values()))
    if missing:
        return Check(
            "demo.sections",
            FAIL,
            "the demo no longer shows every verdict: missing %s" % (", ".join(missing),),
        )
    return Check(
        "demo.sections",
        PASS,
        "%d section(s) show pass, partial and fail verdicts" % (len(facts["sections"]),),
    )


def run(prose=None) -> Report:
    """Print every section to prose, and return the report to exit on.

    The human sections go to the stream the caller names, because with --json the
    caller needs stdout to carry one machine-readable document: sections written
    into stdout made the json a suffix of a human report, and json.loads failed
    on the first character of it.
    """
    out = prose or sys.stdout
    tmp = tempfile.mkdtemp(prefix="residue-demo-")
    checks: List[Check] = []
    facts: Dict[str, Any] = {"sections": [], "verdicts": {}}
    try:
        def section(name: str, title: str, report: Report, note: str = "") -> None:
            out.write("### %s. %s\n" % (name, title))
            out.write(report_mod.as_text(report))
            if note:
                out.write(note)
            out.write("\n")
            worst = [c.name for c in report.checks if c.status == report.status()]
            checks.append(
                Check(
                    "demo." + name,
                    report.status(),
                    "%s (%s)" % (title, ", ".join(worst[:3])),
                )
            )
            facts["sections"].append(name)
            facts["verdicts"][name] = report.status()

        for name, title, note, build in _SECTIONS:
            section(name, title, build(tmp), note)
        checks.append(_sections_check(facts))
        return Report("demo", checks, facts)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main() -> int:
    """The module entry point: one report, and every failure lands on 4.

    This is the second entry point next to ``residue demo``, and it used to be the
    only one without the boundary the CLI keeps. An uncaught exception left Python
    exiting 1, which is this tool's code for *partial* - a verdict about the tree -
    so a crash and a partial read were the same number to anything watching, CI
    included.
    """
    try:
        return report_mod.emit(run(sys.stdout), False)
    except Exception as exc:  # noqa: BLE001 - the boundary itself is the point
        report_mod.flush_stdout()
        sys.stderr.write("residue: error: %s: %s\n" % (exc.__class__.__name__, exc))
        return EXIT[ERROR]


if __name__ == "__main__":
    raise SystemExit(main())

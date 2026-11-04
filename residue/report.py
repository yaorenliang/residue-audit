"""Rendering only. No judgement happens here."""

from __future__ import annotations

import json
import os
import sys
from typing import Any, List

from .model import ERROR, EXIT, Report


def flush_stdout() -> bool:
    """Deliver the buffered report; False means the reader left first.

    stdout is block-buffered when piped, so a report smaller than the buffer is
    written successfully and only fails at interpreter shutdown - where the
    failure is not ours to catch and Python exits 120, outside the 0..4 range
    README.md promises. Flushing here moves the failure inside main(), and the
    fd is pointed at devnull so the shutdown flush has somewhere harmless to go.
    A report that could not be delivered is a tool failure (4), never a verdict.
    """
    try:
        sys.stdout.flush()
        return True
    except BrokenPipeError:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        return False


def _ordered(items: List[Any]) -> List[Any]:
    """Sorted; by repr when the values cannot be compared, so a diff stays stable."""
    try:
        return sorted(items)
    except TypeError:
        return sorted(items, key=repr)


def _jsonable(value: Any) -> Any:
    """Turn a fact into the shapes json can carry.

    Facts are measurements, and a measurement can be a set: "these two runs
    touched the same paths" is a set of names. The conversion lives here and
    nowhere else, so the text form and the json form cannot disagree about what
    a fact is - they used to: as_text printed a set happily while as_json raised
    TypeError, which meant --json failed only after every check had already run,
    and a caller who relied on text output never saw the problem.

    Ordering is fixed for sets and frozensets, because a report that reorders
    itself is a report nobody can diff. A value with no json shape at all is
    rendered with repr: the number is lost, but the fact stays visible instead
    of aborting the report.
    """
    if isinstance(value, dict):
        return dict(
            (str(name), _jsonable(item))
            for name, item in value.items()
        )
    if isinstance(value, (set, frozenset)):
        return _ordered([_jsonable(item) for item in value])
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if value is None or isinstance(value, (str, int, float)):
        return value
    if isinstance(value, os.PathLike):
        return os.fspath(value)
    return repr(value)


def as_json(report: Report) -> str:
    return json.dumps(_jsonable(report.to_dict()), indent=2, sort_keys=True) + "\n"


def as_text(report: Report) -> str:
    lines = []
    width = max([len(c.name) for c in report.checks] + [7])
    for check in report.checks:
        lines.append("%-*s  %-7s  %s" % (width, check.name, check.status, check.why))
        for item in check.evidence:
            lines.append(
                "%-*s  %-7s    %s %s=%s"
                % (width, "", "", item.path, item.field, item.value)
            )
    if report.facts:
        lines.append("")
        for key in sorted(report.facts):
            value = _jsonable(report.facts[key])
            if isinstance(value, (list, dict)):
                value = json.dumps(value, sort_keys=True)
            lines.append("%s=%s" % (key, value))
    lines.append("")
    lines.append(
        "summary command=%s status=%s exit=%d"
        % (report.command, report.status(), report.exit_code())
    )
    return "\n".join(lines) + "\n"


def render(report: Report, want_json: bool) -> str:
    return as_json(report) if want_json else as_text(report)


_UNDELIVERED = "residue: error: stdout closed before the report was written\n"


def emit(report: Report, want_json: bool) -> int:
    # Both entry points end here: the document goes out, the buffer is flushed
    # inside the boundary, and a reader who left before the last byte becomes
    # the tool's own failure (4) instead of a verdict about the tree. One write
    # carries the diagnostic: it is the message when nothing was delivered and
    # an empty string when everything was, so the boundary reads as one path.
    sys.stdout.write(render(report, want_json))
    undelivered = not flush_stdout()
    sys.stderr.write(_UNDELIVERED if undelivered else "")
    return EXIT[ERROR] if undelivered else report.exit_code()

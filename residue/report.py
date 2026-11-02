"""Rendering only. No judgement happens here."""

from __future__ import annotations

import json
import os
from typing import Any, Dict

from .model import Report


def _jsonable(value: Any, key: str = "") -> Any:
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
            (str(name), _jsonable(item, "%s.%s" % (key, name) if key else str(name)))
            for name, item in value.items()
        )
    if isinstance(value, (set, frozenset)):
        items = [_jsonable(item, key) for item in value]
        try:
            return sorted(items)
        except TypeError:
            return sorted(items, key=repr)
    if isinstance(value, (list, tuple)):
        return [_jsonable(item, key) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
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
            value = _jsonable(report.facts[key], key)
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


def facts_line(facts: Dict[str, Any]) -> str:
    return " ".join("%s=%s" % (k, facts[k]) for k in sorted(facts))

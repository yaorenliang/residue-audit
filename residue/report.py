"""Rendering only. No judgement happens here."""

from __future__ import annotations

import json
from typing import Any, Dict

from .model import Report


def as_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n"


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
            value = report.facts[key]
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

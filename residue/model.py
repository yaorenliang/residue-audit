"""Verdict model: checks carry their own reason and evidence.

A check is not a print statement. It is an object that states what it claims,
why it claims it, and which observations support it. Rendering happens elsewhere,
so a second implementation can compare objects instead of scraping text.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

PASS = "pass"
PARTIAL = "partial"
FAIL = "fail"
SKIP = "skip"
ERROR = "error"

# aggregate severity, used to fold a list of checks into one status
SEVERITY = {PASS: 0, SKIP: 1, PARTIAL: 2, FAIL: 3}

# Exit codes are a process interface: a gate reads the number and decides whether
# a host is compromised. So every meaning gets its own code, and "the tool could
# not judge" gets one that no verdict can reach - a crash or a mistyped flag must
# never be readable as partial or fail. ERROR is a code, not a verdict: it is
# deliberately absent from SEVERITY, so no Check can claim it.
EXIT = {PASS: 0, PARTIAL: 1, FAIL: 2, SKIP: 3, ERROR: 4}


@dataclass(frozen=True)
class Evidence:
    """One observation. Values are strings so the JSON stays stable."""

    path: str
    field: str
    value: str

    def to_dict(self) -> Dict[str, str]:
        return {"path": self.path, "field": self.field, "value": self.value}


@dataclass
class Check:
    name: str
    status: str
    why: str
    evidence: List[Evidence] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.status not in SEVERITY:
            raise ValueError("unknown status: %r" % (self.status,))
        if not self.why:
            # a check that cannot say why is a print statement with extra steps
            raise ValueError("check %r has no reason" % (self.name,))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "why": self.why,
            "evidence": [e.to_dict() for e in self.evidence],
        }


@dataclass
class Report:
    command: str
    checks: List[Check]
    facts: Dict[str, Any] = field(default_factory=dict)

    def status(self) -> str:
        if not self.checks:
            return SKIP
        return max((c.status for c in self.checks), key=lambda s: SEVERITY[s])

    def exit_code(self) -> int:
        return EXIT[self.status()]

    def failed(self) -> List[str]:
        return [c.name for c in self.checks if c.status == FAIL]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "command": self.command,
            "status": self.status(),
            "exit_code": self.exit_code(),
            "facts": self.facts,
            "checks": [c.to_dict() for c in self.checks],
        }

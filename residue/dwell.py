"""Dwell: how long did it live, and how much of that was actually covered.

Two traps this module refuses to fall into:

  * the denominator is every host in the ledger, not every host that was hit,
    otherwise "coverage" silently becomes "of the things we found, we found them";
  * a hit before deploy and a hit after deploy are different events, so they are
    counted separately instead of being folded into one rate.

"Exactly half" is not a majority. 50.0 percent is partial coverage.
"""

from __future__ import annotations

import json
from typing import Dict, List, Optional

from .model import FAIL, PASS, PARTIAL, SKIP, Check, Evidence, Report


def load_ledger(path: str) -> List[dict]:
    events: List[dict] = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            events.append(json.loads(line))
    return events


def load_hits(path: Optional[str]) -> List[dict]:
    if not path:
        return []
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict):
        data = data.get("hits", [])
    return list(data)


def _median(values: List[int]) -> int:
    ordered = sorted(values)
    return ordered[len(ordered) // 2]


def _p90(values: List[int]) -> int:
    ordered = sorted(values)
    return ordered[round(0.9 * (len(ordered) - 1))]


def run(ledger_path: str, hits_path: Optional[str] = None) -> Report:
    events = load_ledger(ledger_path)
    hits = load_hits(hits_path)

    if not events:
        return Report(
            "dwell",
            [Check("dwell.data", SKIP, "ledger holds no events; nothing to measure")],
            {"ledger": ledger_path},
        )

    first: Dict[str, int] = {}
    last: Dict[str, int] = {}
    deployed: Dict[str, int] = {}
    mined = set()
    failed = set()

    for event in events:
        host = str(event["host"])
        ts = int(event["ts"])
        first.setdefault(host, ts)
        last[host] = max(last.get(host, ts), ts)
        kind = event.get("event") or event.get("phase") or "scan"
        if kind == "deploy":
            deployed[host] = min(deployed.get(host, ts), ts)
        elif kind == "mine":
            if event.get("ok", True):
                mined.add(host)
            else:
                failed.add(host)

    hosts = sorted(first)
    checks: List[Check] = [
        Check(
            "dwell.data",
            PASS,
            "%d event(s) across %d host(s)" % (len(events), len(hosts)),
        )
    ]

    checks.append(
        Check(
            "dwell.hosts",
            PASS,
            "%d deployed, %d mined, %d failed of %d observed"
            % (len(deployed), len(mined), len(failed), len(hosts)),
            [Evidence("<ledger>", h, "deployed") for h in sorted(deployed)],
        )
    )

    spans = [last[h] - first[h] for h in hosts if last[h] > first[h]]
    if spans:
        checks.append(
            Check(
                "dwell.span",
                PASS,
                "min=%d median=%d p90=%d max=%d over %d host(s)"
                % (min(spans), _median(spans), _p90(spans), max(spans), len(spans)),
            )
        )
    else:
        checks.append(Check("dwell.span", SKIP, "no host has two distinct timestamps"))

    if not deployed:
        checks.append(
            Check("dwell.coverage", SKIP, "no host reached deploy, so coverage is undefined")
        )
        return Report(
            "dwell",
            checks,
            {"ledger": ledger_path, "hosts": len(hosts), "verdict": "no-deployment"},
        )

    pre = post = covered = 0
    per_rule: Dict[str, int] = {}
    hit_hosts = set()
    for hit in hits:
        host = str(hit["host"])
        rule = str(hit.get("rule", "unknown"))
        per_rule[rule] = per_rule.get(rule, 0) + 1
        if host in deployed:
            hit_hosts.add(host)
            if int(hit["ts"]) < deployed[host]:
                pre += 1
            else:
                post += 1
    covered = len(hit_hosts)
    # the denominator is the hosts that actually hosted the implant: a host that
    # was only scanned had nothing to detect, and counting it would let an
    # operator flatter the rate by scanning more than it infected
    denominator = len(deployed)
    rate = 100.0 * covered / denominator if denominator else 0.0
    none = denominator - covered

    if not hits:
        checks.append(
            Check(
                "dwell.coverage",
                SKIP,
                "no detection hits supplied; coverage is unknown, not zero",
            )
        )
    elif rate > 50.0:
        checks.append(
            Check(
                "dwell.coverage",
                PASS,
                "%d of %d host(s) hit by at least one rule (%.1f%%), above half"
                % (covered, denominator, rate),
                [Evidence("<hits>", r, str(per_rule[r])) for r in sorted(per_rule)],
            )
        )
    else:
        checks.append(
            Check(
                "dwell.coverage",
                PARTIAL,
                "%d of %d host(s) hit (%.1f%%); exactly half or less is not coverage"
                % (covered, denominator, rate),
                [Evidence("<hits>", r, str(per_rule[r])) for r in sorted(per_rule)],
            )
        )

    verdict = "covered" if rate > 50.0 else "partial-coverage"
    if not hits:
        verdict = "unknown"

    return Report(
        "dwell",
        checks,
        {
            "ledger": ledger_path,
            "hosts": len(hosts),
            "deployed": len(deployed),
            "not_deployed": len(hosts) - len(deployed),
            "mined": len(mined),
            "failed": len(failed),
            "hits_pre_deploy": pre,
            "hits_post_deploy": post,
            "hit_rate": round(rate, 1),
            "hosts_without_hits": none,
            "verdict": verdict,
        },
    )
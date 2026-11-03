"""Dwell: how long did it live, and how much of that was actually covered.

Two traps this module refuses to fall into:

  * the denominator is the hosts that reached deploy, not every host observed.
    A host that was only scanned had nothing to detect, and counting it would
    let an operator flatter the rate by scanning more than it infected. The
    other reading is still reported, as ``hit_rate_all_hosts``, so a reader can
    see how far the two diverge instead of being handed one of them;
  * a hit before deploy and a hit after deploy are different events, so they are
    counted separately instead of being folded into one rate. A rule that fires
    before the implant exists is a false positive, and a false positive is not
    coverage.

"Exactly half" is not a majority. 50.0 percent is partial coverage.

Event kinds outside {deploy, mine, scan} do not silently become scans: they are
listed in ``unknown_events`` and downgrade ``dwell.schema`` to partial, because a
vocabulary that drifted upstream shrinks the denominator quietly, and every rate
computed from a shrinking denominator goes up.
"""

from __future__ import annotations

import json
from typing import Dict, List, Optional

from .model import FAIL, PASS, PARTIAL, SKIP, Check, Evidence, Report

# the only kinds this module can interpret; anything else is reported, not guessed
KINDS = frozenset(("deploy", "mine", "scan"))


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


def _median(values: List[int]) -> float:
    """The median, which for an even count is the mean of the two middle values.

    Taking ``ordered[len // 2]`` is the upper median: it reports one of the two
    middle readings and biases every even-sized distribution upward. On the demo
    ledger that reads 180 where the honest answer is 125.
    """
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return float(ordered[middle])
    return (ordered[middle - 1] + ordered[middle]) / 2.0


def _p90(values: List[int]) -> int:
    """Nearest-rank 90th percentile: the ceil(0.9 * n)-th smallest value.

    Nearest-rank never interpolates, so the answer is always a value that was
    actually observed rather than a number between two of them.
    """
    ordered = sorted(values)
    rank = (9 * len(ordered) + 9) // 10  # ceil(0.9 * n), integer arithmetic
    return ordered[max(rank, 1) - 1]


def _number(value: float) -> str:
    """Print 125.0 as 125 and 122.5 as 122.5, so the span line stays readable."""
    if float(value).is_integer():
        return str(int(value))
    return str(value)


def run(ledger_path: str, hits_path: Optional[str] = None) -> Report:
    events = load_ledger(ledger_path)
    hits = load_hits(hits_path)

    if not events:
        return Report(
            "dwell",
            [Check("dwell.data", SKIP, "ledger holds no events; nothing to measure")],
            {"ledger": ledger_path},
        )

    deploys: Dict[str, int] = {}
    last: Dict[str, int] = {}
    mined = set()
    failed = set()
    unknown: Dict[str, int] = {}

    for event in events:
        host = str(event["host"])
        ts = int(event["ts"])
        last[host] = max(last.get(host, ts), ts)
        kind = str(event.get("event") or event.get("phase") or "scan")
        if kind not in KINDS:
            unknown[kind] = unknown.get(kind, 0) + 1
            continue
        if kind == "deploy":
            # a host that deployed twice counts once, from its earliest deploy:
            # the window opens when the implant first existed
            deploys[host] = min(deploys.get(host, ts), ts)
        elif kind == "mine":
            if event.get("ok", True):
                mined.add(host)
            else:
                failed.add(host)

    hosts = sorted(last)
    unknown_events = sorted(unknown)
    hosts_not_deployed = [host for host in hosts if host not in deploys]

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
            % (len(deploys), len(mined), len(failed), len(hosts)),
            [Evidence("<ledger>", h, "deployed") for h in sorted(deploys)],
        )
    )

    if unknown:
        checks.append(
            Check(
                "dwell.schema",
                PARTIAL,
                "%d event(s) have unrecognized kind; denominator may be wrong: %s"
                % (sum(unknown.values()), ", ".join(sorted(unknown))),
            )
        )
    else:
        checks.append(
            Check(
                "dwell.schema",
                PASS,
                "every event carries one of the %d known kinds" % len(KINDS),
            )
        )

    # a span runs from deploy to the last event seen for that host, whatever
    # order the lines arrived in. A host whose last event is its deploy has no
    # measured end, so it contributes no span rather than a fabricated zero
    spans = [last[host] - start for host, start in deploys.items() if last[host] > start]
    if spans:
        checks.append(
            Check(
                "dwell.span",
                PASS,
                "min=%s median=%s p90=%d max=%d over %d host(s)"
                % (
                    _number(min(spans)),
                    _number(_median(spans)),
                    _p90(spans),
                    max(spans),
                    len(spans),
                ),
            )
        )
    else:
        checks.append(Check("dwell.span", SKIP, "no host has two distinct timestamps"))

    pre = post = covered = 0
    per_rule: Dict[str, int] = {}
    hit_hosts = set()
    unmatched: List[str] = []
    for hit in hits:
        host = str(hit["host"])
        rule = str(hit.get("rule", "unknown"))
        start = deploys.get(host)
        if start is None:
            # a hit on a host the ledger never deployed to cannot answer "of the
            # hosts we deployed to, how many were seen". Naming it keeps the
            # report from listing a rule count next to a zero.
            if host not in unmatched:
                unmatched.append(host)
            continue
        per_rule[rule] = per_rule.get(rule, 0) + 1
        if int(hit["ts"]) < start:
            # before the implant existed: this is a false positive and must not
            # be allowed to raise the rate for the hosts that were really there
            pre += 1
            continue
        post += 1
        hit_hosts.add(host)
    covered = len(hit_hosts)
    denominator = len(deploys)
    rate = 100.0 * covered / denominator if denominator else 0.0
    all_hosts_rate = 100.0 * covered / len(hosts) if hosts and hits else None
    none = denominator - covered

    # A ledger that never reached deploy answers nothing, but it still describes
    # what it saw. Returning early meant writing the same twelve facts a second
    # time by hand, so the one place that could drift was the place nobody read.
    defined = bool(deploys)

    if not defined:
        checks.append(
            Check("dwell.coverage", SKIP, "no host reached deploy, so coverage is undefined")
        )
    elif not hits:
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

    if not defined:
        verdict = "no-deployment"
    elif not hits:
        verdict = "unknown"
    else:
        verdict = "covered" if rate > 50.0 else "partial-coverage"

    return Report(
        "dwell",
        checks,
        {
            "ledger": ledger_path,
            "hosts": len(hosts),
            "deployed": denominator,
            "not_deployed": len(hosts) - denominator,
            "hosts_not_deployed": hosts_not_deployed,
            "mined": len(mined),
            "failed": len(failed),
            "hits_pre_deploy": pre,
            "hits_post_deploy": post,
            # two denominators, printed side by side: the hosts that reached deploy
            # and every host the ledger mentions. Neither is the right one alone.
            "hit_rate": round(rate, 1) if defined else None,
            "hit_rate_all_hosts": (
                round(all_hosts_rate, 1) if all_hosts_rate is not None else None
            ),
            "hosts_without_hits": none if defined else None,
            "unknown_events": unknown_events,
            "hits_unmatched": sorted(unmatched),
            "verdict": verdict,
        },
    )
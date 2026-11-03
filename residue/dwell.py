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
from dataclasses import dataclass
from typing import Dict, List, Optional, Set

from .model import PASS, PARTIAL, SKIP, Check, Evidence, Report

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


def load_hits(path: Optional[str]) -> Optional[List[dict]]:
    """The hits file, or None when no hits file was named.

    None and [] are different answers: no file means coverage was not measured, an
    empty list means it was measured and nothing was hit. Returning [] for both is
    how a report ends up printing 0.0% coverage for an audit that never looked.
    """
    if not path:
        return None
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict):
        if "hits" not in data:
            raise ValueError(
                "%s is an object without a hits key; coverage cannot be read from it" % path
            )
        data = data["hits"]
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


@dataclass(frozen=True)
class _Tally:
    """What the ledger says, counted once."""

    deploys: Dict[str, int]
    last: Dict[str, int]
    mined: Set[str]
    failed: Set[str]
    unknown: Dict[str, int]
    unknown_hosts: List[str]


@dataclass(frozen=True)
class _Coverage:
    """What the hits say about the hosts that reached deploy.

    Two questions decide whether a rate exists at all, and they are different
    questions: did anything reach deploy (otherwise there is no denominator), and
    were hits supplied at all (otherwise there is no numerator). A rate of 0.0
    answers neither - it says "measured, and nothing was hit" about a report that
    measured nothing.
    """

    defined: bool
    hits_provided: bool
    pre: int
    post: int
    per_rule: Dict[str, int]
    covered: int
    denominator: int
    rate: Optional[float]
    all_hosts_rate: Optional[float]
    unmatched: List[str]

    @property
    def without_hits(self) -> Optional[int]:
        if self.rate is None:
            return None
        return self.denominator - self.covered


MISSING_KIND = "<missing>"


def _kind(event: dict) -> Optional[str]:
    """The kind of one event, or None when the line does not carry one.

    Defaulting a missing kind to "scan" invented evidence twice over: the schema
    check reported a clean vocabulary because every line had a kind, and a deploy
    whose key was misspelled left the denominator without leaving a trace.
    """
    for key in ("event", "phase"):
        value = event.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None


def _tally(events: List[dict]) -> _Tally:
    deploys: Dict[str, int] = {}
    last: Dict[str, int] = {}
    mined: Set[str] = set()
    failed: Set[str] = set()
    unknown: Dict[str, int] = {}
    unknown_hosts: List[str] = []

    for event in events:
        host = str(event["host"])
        ts = int(event["ts"])
        last[host] = max(last.get(host, ts), ts)
        kind = _kind(event)
        if kind is None or kind not in KINDS:
            name = MISSING_KIND if kind is None else kind
            unknown[name] = unknown.get(name, 0) + 1
            if host not in unknown_hosts:
                unknown_hosts.append(host)
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
    return _Tally(deploys, last, mined, failed, unknown, sorted(unknown_hosts))


def _coverage(
    hits: Optional[List[dict]], deploys: Dict[str, int], hosts: List[str]
) -> _Coverage:
    provided = hits is not None
    pre = post = 0
    per_rule: Dict[str, int] = {}
    hit_hosts: Set[str] = set()
    unmatched: List[str] = []
    for hit in hits or []:
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
    defined = bool(denominator)
    measurable = defined and provided
    rate = 100.0 * covered / denominator if measurable else None
    all_hosts_rate = 100.0 * covered / len(hosts) if measurable and hosts else None
    return _Coverage(
        defined,
        provided,
        pre,
        post,
        per_rule,
        covered,
        denominator,
        rate,
        all_hosts_rate,
        unmatched,
    )


def _data_check(events: List[dict], hosts: List[str]) -> Check:
    return Check(
        "dwell.data",
        PASS,
        "%d event(s) across %d host(s)" % (len(events), len(hosts)),
    )


def _hosts_check(tally: _Tally, hosts: List[str]) -> Check:
    return Check(
        "dwell.hosts",
        PASS,
        "%d deployed, %d mined, %d failed of %d observed"
        % (len(tally.deploys), len(tally.mined), len(tally.failed), len(hosts)),
        [Evidence("<ledger>", h, "deployed") for h in sorted(tally.deploys)],
    )


def _schema_check(unknown: Dict[str, int]) -> Check:
    if unknown:
        named = ", ".join("%s x%d" % (name, unknown[name]) for name in sorted(unknown))
        return Check(
            "dwell.schema",
            PARTIAL,
            "%d event(s) have unrecognized kind; the denominator may be wrong: %s"
            % (sum(unknown.values()), named),
        )
    return Check(
        "dwell.schema",
        PASS,
        "every event carries one of the %d known kinds" % len(KINDS),
    )


def _span_check(spans: List[int]) -> Check:
    if not spans:
        return Check("dwell.span", SKIP, "no host has two distinct timestamps")
    return Check(
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


def _coverage_check(cov: _Coverage) -> Check:
    evidence = [Evidence("<hits>", r, str(cov.per_rule[r])) for r in sorted(cov.per_rule)]
    if not cov.defined:
        return Check("dwell.coverage", SKIP, "no host reached deploy, so coverage is undefined")
    if not cov.hits_provided:
        return Check(
            "dwell.coverage",
            SKIP,
            "no detection hits supplied; coverage is unknown, not zero",
        )
    rate = cov.rate or 0.0
    if rate > 50.0:
        return Check(
            "dwell.coverage",
            PASS,
            "%d of %d host(s) hit by at least one rule (%.1f%%), above half"
            % (cov.covered, cov.denominator, rate),
            evidence,
        )
    return Check(
        "dwell.coverage",
        PARTIAL,
        "%d of %d host(s) hit (%.1f%%); exactly half or less is not coverage"
        % (cov.covered, cov.denominator, rate),
        evidence,
    )


def _verdict(cov: _Coverage) -> str:
    if not cov.defined:
        return "no-deployment"
    if cov.rate is None:
        return "unknown"
    return "covered" if cov.rate > 50.0 else "partial-coverage"


def _facts(
    ledger_path: str, tally: _Tally, hosts: List[str], cov: _Coverage
) -> dict:
    # A host whose ledger row could not be read did not "never deploy": its
    # deployment is unknown, and listing it here would turn an unread key into a
    # measurement. It is named in hosts_unknown_kind instead.
    not_deployed = [
        host
        for host in hosts
        if host not in tally.deploys and host not in tally.unknown_hosts
    ]
    return {
        "ledger": ledger_path,
        "hosts": len(hosts),
        "deployed": cov.denominator,
        "not_deployed": len(not_deployed),
        "hosts_not_deployed": not_deployed,
        "mined": len(tally.mined),
        "failed": len(tally.failed),
        "hits_pre_deploy": cov.pre,
        "hits_post_deploy": cov.post,
        # two denominators, printed side by side: the hosts that reached deploy
        # and every host the ledger mentions. Neither is the right one alone.
        "hit_rate": round(cov.rate, 1) if cov.rate is not None else None,
        "hit_rate_all_hosts": (
            round(cov.all_hosts_rate, 1) if cov.all_hosts_rate is not None else None
        ),
        "hosts_without_hits": cov.without_hits,
        "unknown_events": sorted(tally.unknown),
        "hosts_unknown_kind": tally.unknown_hosts,
        "hits_unmatched": sorted(cov.unmatched),
        "verdict": _verdict(cov),
    }


def run(ledger_path: str, hits_path: Optional[str] = None) -> Report:
    events = load_ledger(ledger_path)
    hits = load_hits(hits_path)

    if not events:
        return Report(
            "dwell",
            [Check("dwell.data", SKIP, "ledger holds no events; nothing to measure")],
            {"ledger": ledger_path},
        )

    tally = _tally(events)
    hosts = sorted(tally.last)
    # a span runs from deploy to the last event seen for that host, whatever
    # order the lines arrived in. A host whose last event is its deploy has no
    # measured end, so it contributes no span rather than a fabricated zero
    spans = [
        tally.last[host] - start
        for host, start in tally.deploys.items()
        if tally.last[host] > start
    ]
    coverage = _coverage(hits, tally.deploys, hosts)
    checks = [
        _data_check(events, hosts),
        _hosts_check(tally, hosts),
        _schema_check(tally.unknown),
        _span_check(spans),
        _coverage_check(coverage),
    ]
    return Report("dwell", checks, _facts(ledger_path, tally, hosts, coverage),
                  primary="dwell.coverage")

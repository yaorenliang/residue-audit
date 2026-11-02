"""Batch: can one signature cluster two builds of the same family?

Same source code compiled twice should not share a feature set. This module
scores that claim with Jaccard similarity over feature sets (strings, symbol
lists, whatever the caller extracted) and states the threshold it used.

The interesting case is not "different" but "almost the same": a pair at 0.99
looks distinct to a human reading two file lists, and identical to a clusterer.

Two empty feature sets are not a third case. They carry no evidence either way,
so their similarity is undefined and the pair is skipped: scoring them as 1.0
would let "we extracted nothing" read as "these builds are the same".
"""

from __future__ import annotations

import json
from itertools import combinations
from typing import Dict, List, Optional

from .model import FAIL, PASS, PARTIAL, SKIP, Check, Report

DEFAULT_THRESHOLD = 0.98


def load_features(path: str) -> Dict[str, object]:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if "features" not in data:
        raise ValueError("%s has no 'features' key" % path)
    name = str(data.get("name") or path)
    return {"name": name, "features": set(str(f) for f in data["features"])}


def jaccard(a: set, b: set) -> Optional[float]:
    """Jaccard similarity, or None when both sets are empty.

    None is not 0.0: 0.0 says "we compared two sets and they share nothing",
    None says "there was nothing to compare". Only the first is a measurement.
    """
    if not a and not b:
        return None
    union = a | b
    return len(a & b) / len(union) if union else 0.0


def run(paths: List[str], threshold: float = DEFAULT_THRESHOLD) -> Report:
    sets = [load_features(p) for p in paths]
    checks: List[Check] = []

    for left, right in combinations(sets, 2):
        score = jaccard(left["features"], right["features"])
        name = "batch.%s_vs_%s" % (left["name"], right["name"])
        if score is None:
            checks.append(
                Check(
                    name,
                    SKIP,
                    "similarity is undefined: both feature sets are empty",
                )
            )
        elif score >= threshold:
            checks.append(
                Check(
                    name,
                    FAIL,
                    "similarity %.4f is at or above the %.2f threshold: one signature can cluster both builds"
                    % (score, threshold),
                )
            )
        elif score >= threshold - 0.02:
            checks.append(
                Check(
                    name,
                    PARTIAL,
                    "similarity %.4f sits just under the %.2f threshold; the margin is too small to trust"
                    % (score, threshold),
                )
            )
        else:
            checks.append(
                Check(
                    name,
                    PASS,
                    "similarity %.4f is below the %.2f threshold" % (score, threshold),
                )
            )

    return Report(
        "batch",
        checks,
        {
            "pairs": len(checks),
            "threshold": threshold,
            "sizes": {s["name"]: len(s["features"]) for s in sets},
            "min_similarity": _bounds(sets),
        },
    )


def _bounds(sets: List[Dict[str, object]]) -> Optional[float]:
    """Lowest defined similarity, or None when no pair could be defined."""
    scores = [
        jaccard(a["features"], b["features"]) for a, b in combinations(sets, 2)
    ]
    defined = [score for score in scores if score is not None]
    return round(min(defined), 4) if defined else None

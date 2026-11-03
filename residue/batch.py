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
from typing import Dict, List, Optional, Tuple

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


def _pairs(sets: List[Dict[str, object]]) -> List[Tuple[str, Optional[float]]]:
    """Every pair once, with the similarity it carries - None when undefined.

    Computed once and handed to both the checks and the summary. The summary used
    to recompute every pair to find its minimum, so the number printed as
    min_similarity and the numbers the checks judged were two separate walks of
    the same data.
    """
    return [
        (
            "batch.%s_vs_%s" % (left["name"], right["name"]),
            jaccard(left["features"], right["features"]),
        )
        for left, right in combinations(sets, 2)
    ]


def _verdict(score: Optional[float], threshold: float) -> Tuple[str, str]:
    """Status and message for one pair; the bands are stated here and nowhere else."""
    if score is None:
        return SKIP, "similarity is undefined: both feature sets are empty"
    if score >= threshold:
        return (
            FAIL,
            "similarity %.4f is at or above the %.2f threshold: one signature can cluster both builds"
            % (score, threshold),
        )
    if score >= threshold - 0.02:
        return (
            PARTIAL,
            "similarity %.4f sits just under the %.2f threshold; the margin is too small to trust"
            % (score, threshold),
        )
    return PASS, "similarity %.4f is below the %.2f threshold" % (score, threshold)


def run(paths: List[str], threshold: float = DEFAULT_THRESHOLD) -> Report:
    sets = [load_features(p) for p in paths]
    pairs = _pairs(sets)
    checks = [Check(name, *_verdict(score, threshold)) for name, score in pairs]

    defined = [score for _, score in pairs if score is not None]
    return Report(
        "batch",
        checks,
        {
            "pairs": len(pairs),
            "threshold": threshold,
            "sizes": {s["name"]: len(s["features"]) for s in sets},
            "min_similarity": round(min(defined), 4) if defined else None,
        },
    )
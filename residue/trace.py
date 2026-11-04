"""Trace: did the artifacts blend in, or do they stand out on ls -lt?

Three questions, deliberately separated:

  artifacts      which files are ours: claims anchored on a marker-bearing unit
  aligned        artifact mtime is not newer than the newest non-ours sibling
  corroborated   the directory actually has such a sibling to borrow from
  ctime          status-change time outruns every sibling (cannot be rewritten)
  order          inode allocation does not preserve creation order
  directory_ctime
                 the holding directory changed after the artifact claims to exist
  readable       every scanned path could actually be read

They are separate because they can disagree. A tree can be aligned and still
uncorroborated (empty directory), which is neither a pass nor a failure. The last
two describe the measurement rather than the tree: a check that could not read
its input must say so instead of returning the verdict of the part it managed to
see.
"""

from __future__ import annotations

import os
import time
from typing import Dict, List, Optional, Sequence

from .model import Check, Report
from .trace_obs import Observations, _Scratch
from .trace_claims import DEFAULT_SCAN, _claim, _stamp, scan_entry
from .trace_dirs import _dir_observations, _hits
from .trace_checks import JUDGES, _weak_evidence


DEFAULT_MARKERS = ("KillSignal=SIGCONT", "SendSIGKILL=no")


def observe(
    root: str,
    scan: Optional[Sequence[str]] = None,
    markers: Optional[Sequence[str]] = None,
    fresh_window_s: int = 120,
    now_ms: Optional[int] = None,
    broad: bool = False,
) -> Observations:
    """One pass: discover claims, read their stamps, and sort them by question."""
    scratch = _Scratch(
        os.path.abspath(root),
        tuple(scan_entry(one) for one in (scan or DEFAULT_SCAN)),
        tuple(markers or DEFAULT_MARKERS),
        broad,
    )
    _claim(scratch)
    artifacts = _stamp(scratch)
    dirs = _dir_observations(scratch, artifacts)
    if now_ms is None:
        now_ms = int(time.time() * 1000)
    return Observations(
        scratch.root,
        now_ms,
        fresh_window_s,
        scratch.scan,
        artifacts,
        dirs,
        _hits(dirs, now_ms, fresh_window_s),
        dict(scratch.weak),
        tuple(scratch.errors),
        scratch.truncated_files,
        scratch.absolute_links,
    )


def checks(obs: Observations) -> List[Check]:
    return [judge(obs) for judge in JUDGES]


def facts(obs: Observations) -> Dict[str, object]:
    hits = obs.hits
    return {
        "root": obs.root,
        "artifacts": len(obs.artifacts),
        "weak_claims": len(obs.weak),
        "weak_paths": [shown for shown, _ in _weak_evidence(obs)],
        "truncated_files": obs.truncated_files,
        "absolute_links": obs.absolute_links,
        "scan": list(obs.scan),
        "aligned": len(hits.aligned),
        "leaks": len(hits.leaked),
        "uncorroborated": len(hits.uncorroborated),
        "ctime": len(hits.ctime),
        "fresh": len(hits.fresh),
        "order": len(hits.order),
        "errors": [err.to_dict() for err in obs.errors],
    }


def run(
    root: str,
    scan: Optional[Sequence[str]] = None,
    markers: Optional[Sequence[str]] = None,
    fresh_window_s: int = 120,
    now_ms: Optional[int] = None,
    broad: bool = False,
) -> Report:
    obs = observe(
        root,
        scan=scan,
        markers=markers,
        fresh_window_s=fresh_window_s,
        now_ms=now_ms,
        broad=broad,
    )
    return Report("trace", checks(obs), facts(obs), primary="trace.artifacts")

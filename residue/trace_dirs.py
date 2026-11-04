"""Grouping stamped artifacts by the directory that holds them and comparing each against its siblings.

The comparisons kept here are the ones the filesystem writes for us: mtime,
inode order and status-change time. A directory with nothing else in it can
answer none of them, which is neither a pass nor a failure.
"""

from __future__ import annotations

import os
from typing import Dict, List, Optional, Sequence, Tuple

from . import inside, stat_io
from .trace_parse import sanitize
from .trace_obs import ArtifactObs, DirObs, Hits, _Scratch
from .trace_claims import _readable_path, _record


def _group(artifacts: Sequence[ArtifactObs]) -> Dict[str, List[ArtifactObs]]:
    groups: Dict[str, List[ArtifactObs]] = {}
    for art in artifacts:
        groups.setdefault(os.path.dirname(art.path), []).append(art)
    return groups


def _directory_changed_after(
    scratch: _Scratch, directory: str, artifacts: Sequence[ArtifactObs]
) -> Optional[Tuple[int, int]]:
    """(directory ctime, oldest artifact mtime) when the directory is newer.

    Creating a file updates the parent directory's mtime and ctime, and no
    user-space trick avoids that write. A directory whose stamp is newer than the
    oldest artifact it holds was therefore assembled - or added to - after that
    artifact claims to exist. That is a change we can date, not a verdict about
    who made it, so it is reported as partial.
    """
    real = _readable_path(scratch, directory)
    if real is None:
        return None
    info, err = stat_io.stat_of(real)
    if info is None:
        _record(scratch, err)
        return None
    oldest: Optional[int] = None
    for art in artifacts:
        if art.stamp is None:
            return None
        oldest = art.stamp.mtime_ms if oldest is None else min(oldest, art.stamp.mtime_ms)
    if oldest is None:
        return None
    if info.ctime_ms > oldest + DIRECTORY_CTIME_SLACK_MS:
        return (info.ctime_ms, oldest)
    return None


def _dir_stamp(scratch: _Scratch, directory: str, arts: Sequence[ArtifactObs]) -> DirObs:
    real = _readable_path(scratch, directory)
    ours = {art.path for art in arts}
    if real is None:
        cap, cap_ctime, max_ino, neighbours = 0, 0, 0, 0
    else:
        # The siblings are compared by the name the image gives them, and the
        # artifacts sit at display paths that may run through a link: both
        # spellings have to be excluded, or an artifact is its own neighbour.
        ours |= {inside.resolve(scratch.root, art.path)[0] or art.path for art in arts}
        cap, cap_ctime, max_ino, neighbours = stat_io.dir_stats(real, ours, scratch.errors)
    return DirObs(
        directory,
        sanitize(directory, scratch.root),
        cap,
        cap_ctime,
        max_ino,
        neighbours,
        tuple(arts),
        _directory_changed_after(scratch, directory, arts),
    )


def _dir_observations(
    scratch: _Scratch, artifacts: Sequence[ArtifactObs]
) -> Tuple[DirObs, ...]:
    groups = _group(artifacts)
    return tuple(
        _dir_stamp(scratch, directory, groups[directory])
        for directory in sorted(groups)
    )


def _fresh(
    artifacts: Sequence[ArtifactObs], now_ms: int, window_s: int
) -> Tuple[ArtifactObs, ...]:
    """Which artifacts still carry an mtime inside the window.

    Asked once, of every artifact, before any directory is consulted. Freshness is
    a property of the file, not of its neighbours, and asking it inside the
    alignment loop meant two copies of the question - one for artifacts with a
    sibling and one for artifacts without - and a new branch could answer only one
    of them.

    A timestamp ahead of "now" counts. It is not evidence of a recent edit but of
    a clock that disagrees with the tree, which deserves the same attention; the
    window check used to swallow it by accident, since a negative difference is
    always "within the window" under floor division, and the report then dated a
    file years ahead of the check to "within 120s of now".
    """
    return tuple(
        art
        for art in artifacts
        if art.stamp is not None
        and _fresh_hit(now_ms, art.stamp.mtime_ms, window_s)
    )


def _fresh_hit(now_ms: int, mtime_ms: int, window_s: int) -> bool:
    """Whether one mtime belongs in the freshness window."""
    if mtime_ms > now_ms:
        return True
    return (now_ms - mtime_ms) // 1000 <= window_s


def _newer_than_siblings(art: ArtifactObs, group: DirObs) -> bool:
    """The one comparison behind alignment: this artifact against its neighbours.

    Named so that the pass which sorts artifacts into aligned and leaked, and the
    judge that rebuilds the evidence for that answer, cannot drift apart: two copies
    of a comparison is how a report ends up explaining a verdict it did not reach.
    """
    return art.stamp is not None and art.stamp.mtime_ms > group.cap_mtime_ms


def _hits(dirs: Sequence[DirObs], now_ms: int, fresh_window_s: int) -> Hits:
    """Sort every artifact into the answers it supports. No verdicts here."""
    aligned: List[ArtifactObs] = []
    leaked: List[ArtifactObs] = []
    uncorroborated: List[ArtifactObs] = []
    ctime_hits: List[ArtifactObs] = []
    order_hits: List[ArtifactObs] = []
    changed: List[DirObs] = []
    flat = [art for group in dirs for art in group.artifacts]
    for group in dirs:
        if group.changed is not None: changed.append(group)
        if group.neighbours == 0:
            # nothing to be "no newer than": a pass here would be an
            # assumption wearing a verdict's clothes
            uncorroborated.extend(group.artifacts)
            continue
        _sort_group(group, aligned, leaked, ctime_hits, order_hits)
    return Hits(
        tuple(aligned),
        tuple(leaked),
        tuple(uncorroborated),
        tuple(ctime_hits),
        _fresh(flat, now_ms, fresh_window_s),
        tuple(order_hits),
        tuple(changed),
    )


def _sort_group(
    group: DirObs,
    aligned: List[ArtifactObs],
    leaked: List[ArtifactObs],
    ctime_hits: List[ArtifactObs],
    order_hits: List[ArtifactObs],
) -> None:
    """Sort one corroborated directory's artifacts into the answers they support."""
    for art in group.artifacts:
        stamp = art.stamp
        if stamp is None:
            continue
        if _newer_than_siblings(art, group):
            leaked.append(art)
        else:
            aligned.append(art)
        if stamp.ino > group.max_ino:
            order_hits.append(art)
        if stamp.ctime_ms > group.cap_ctime_ms:
            ctime_hits.append(art)


# A directory stamp is written by the kernel after the file inside it, so a few
# milliseconds of lag are normal. Days of lag are not.
DIRECTORY_CTIME_SLACK_MS = 2000

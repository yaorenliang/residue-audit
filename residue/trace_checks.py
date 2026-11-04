"""The judges: observations in, Check answers out.

No judge touches the disk. A judge that cannot see what it needs says PARTIAL
or SKIP rather than lending its verdict to a tree it never read.
"""

from __future__ import annotations

from typing import List, Sequence, Tuple

from .model import FAIL, PASS, PARTIAL, SKIP, Check, Evidence
from .trace_parse import sanitize
from .trace_obs import Observations
from .trace_dirs import _newer_than_siblings


# -- judgement -------------------------------------------------------------
#
# One function per check. Each reads Observations and returns a Check; none of
# them touches the filesystem, and none of them can see another's answer.


def _check_artifacts(obs: Observations) -> Check:
    if not obs.artifacts:
        if obs.weak:
            # an empty artifact list is only an answer when everything was read:
            # candidates we stopped reading are a gap wearing a clean tree's clothes
            return Check(
                "trace.artifacts",
                PARTIAL,
                "no artifact matched the marker set, but %d candidate(s) were never read to "
                "the end; the empty answer covers the readable subset only" % len(obs.weak),
                [Evidence(shown, "not_audited", why) for shown, why in _weak_evidence(obs)],
            )
        if obs.errors:
            # an anchor we could not read is a gap in the same sense: the set
            # looked empty because part of the tree was never listed
            return Check(
                "trace.artifacts",
                PARTIAL,
                "no artifact matched the marker set, but %d path(s) could not be "
                "read; the empty answer covers the readable subset only"
                % len(obs.errors),
                [Evidence(err.path, err.op, err.err) for err in obs.errors[:3]],
            )
        return Check(
            "trace.artifacts",
            SKIP,
            "no artifact matched the marker set; nothing to audit",
        )
    why = "%d artifact(s) matched the marker set" % len(obs.artifacts)
    if obs.weak:
        why += " (+%d weak claim(s) not audited)" % len(obs.weak)
    evidence = [Evidence(art.shown, "marker", art.marker) for art in obs.artifacts]
    if obs.truncated_files:
        return Check(
            "trace.artifacts",
            PARTIAL,
            why + "; %d file(s) were cut off at the read window, so the set itself is "
            "incomplete" % obs.truncated_files,
            evidence,
        )
    return Check("trace.artifacts", PASS, why, evidence)


def _comparison_counts(obs: Observations) -> Tuple[int, int]:
    """How many artifacts were actually compared, and how many had no sibling.

    An alignment claim is only worth the artifacts that were put next to a
    sibling. A directory with no neighbour produces no comparison at all, so its
    artifacts cannot be counted under "all N are no newer than a sibling" - the
    mixed tree said exactly that about two artifacts when it had compared one.
    """
    compared = sum(len(group.artifacts) for group in obs.dirs if group.neighbours > 0)
    return compared, len(obs.artifacts) - compared


def _aligned_scope(compared: int, uncompared: int) -> Tuple[str, str]:
    """The noun phrase for a count, and the note naming who it left out."""
    if not uncompared:
        return "%d artifact(s)" % compared, ""
    return (
        "%d compared artifact(s)" % compared,
        "; %d artifact(s) had no sibling to compare against" % uncompared,
    )


def _check_aligned(obs: Observations) -> Check:
    hits = obs.hits
    compared, uncompared = _comparison_counts(obs)
    scope, note = _aligned_scope(compared, uncompared)
    if not hits.aligned and not hits.leaked:
        return Check(
            "trace.aligned",
            SKIP,
            "no artifact has a sibling to compare against; alignment is unmeasurable here",
        )
    evidence: List[Evidence] = []
    for group in obs.dirs:
        if group.neighbours == 0:
            continue
        for art in group.artifacts:
            if _newer_than_siblings(art, group):
                evidence.append(Evidence(art.shown, "mtime_ms", str(art.stamp.mtime_ms)))
        evidence.append(Evidence(group.shown, "neighbour_cap_ms", str(group.cap_mtime_ms)))
    if not hits.leaked:
        status, why = PASS, "all %s are no newer than a sibling%s" % (scope, note)
    elif hits.aligned:
        status = PARTIAL
        why = "%d of %s stand out with a mtime newer than every sibling%s" % (
            len(hits.leaked),
            scope,
            note,
        )
    else:
        status, why = FAIL, "all %s carry a newer mtime than every sibling%s" % (scope, note)
    return Check("trace.aligned", status, why, evidence)


def _check_corroborated(obs: Observations) -> Check:
    hits = obs.hits
    if not hits.uncorroborated:
        return Check(
            "trace.corroborated",
            PASS,
            "every directory holding an artifact also holds a non-artifact sibling",
        )
    return Check(
        "trace.corroborated",
        PARTIAL,
        "%d of %d artifact(s) live where no sibling exists to borrow an mtime from; "
        "alignment cannot be shown, only assumed"
        % (len(hits.uncorroborated), len(obs.artifacts)),
        [Evidence(art.shown, "corroborator", "none") for art in hits.uncorroborated],
    )


def _weak_evidence(obs: Observations) -> List[Tuple[str, str]]:
    """(shown path, reason) for every candidate the pass did not finish."""
    shown = {art.path: art.shown for art in obs.artifacts}
    return [
        (shown.get(path, sanitize(path, obs.root)), why)
        for path, why in sorted(obs.weak.items())
    ]


def _check_readable(obs: Observations) -> Check:
    gaps: List[str] = []
    if obs.errors:
        gaps.append("%d path(s) unreadable" % len(obs.errors))
    if obs.truncated_files:
        gaps.append("%d file(s) cut off at the read window" % obs.truncated_files)
    # Absolute links used to be counted as gaps, on the theory that a reader should
    # know the path was followed inside the image. But this check answers one
    # question - was every scanned path read - and a link whose target sits inside
    # the image is read. Counting it here said "the counts below describe a smaller
    # tree" about a tree where nothing was skipped, and the tool exited 1
    # (unmeasurable) on the most ordinary systemd shape there is. The count stays in
    # facts: it is a fact about the tree, not a hole in the audit.
    if not gaps:
        return Check(
            "trace.readable",
            PASS,
            "every scanned path was read; no verdict rests on a skipped path",
        )
    evidence = [
        Evidence(err.path, "unreadable", "%s: %s" % (err.op, err.err))
        for err in obs.errors
    ]
    evidence.extend(
        Evidence(shown, "not_read_to_the_end", why) for shown, why in _weak_evidence(obs)
    )
    return Check(
        "trace.readable",
        PARTIAL,
        "%s; verdict covers the readable subset only" % ", ".join(gaps),
        evidence,
    )


# Four checks fire on any hit at all and differ only in what the hit means. The
# meaning is data: three are failures, and a directory stamp is a lead rather than a
# failure because it dates the assembly of a tree, not the intent behind it. Writing
# that ladder once - as a table keyed by check - keeps one of the four from quietly
# growing its own answer.
HIT_VERDICT = {
    "ctime": FAIL,
    "directory_ctime": PARTIAL,
    "fresh": FAIL,
    "order": FAIL,
}


def _spike_check(
    name: str,
    hits: Sequence[object],
    why_clean: str,
    why_hit: str,
    evidence: List[Evidence],
) -> Check:
    """One hit, or none: the shape every hit-or-nothing check shares."""
    if not hits:
        return Check("trace." + name, PASS, why_clean)
    return Check("trace." + name, HIT_VERDICT[name], why_hit, evidence)


def _check_ctime(obs: Observations) -> Check:
    hits = obs.hits.ctime
    return _spike_check(
        "ctime",
        hits,
        "no artifact has a ctime above every sibling in its directory",
        "%d artifact(s) have a ctime newer than every sibling: mtime can be borrowed, "
        "ctime cannot" % len(hits),
        [Evidence(art.shown, "ctime_vs_cap", "newer") for art in hits],
    )


def _check_directory_ctime(obs: Observations) -> Check:
    changed = obs.hits.directories
    return _spike_check(
        "directory_ctime",
        changed,
        "no holding directory carries a ctime above the artifacts it holds",
        "%d holding director(y/ies) changed after the artifacts they hold: a directory "
        "mtime/ctime is the usual hiding place, and it dates the assembly, not the intent"
        % len(changed),
        [
            Evidence(
                group.shown,
                "dir_ctime_vs_oldest_mtime",
                "%d > %d" % (group.changed[0], group.changed[1]),
            )
            for group in changed
        ],
    )


def _check_fresh(obs: Observations) -> Check:
    hits = obs.hits.fresh
    window = obs.fresh_window_s
    return _spike_check(
        "fresh",
        hits,
        "no artifact carries an mtime within %ds of now" % window,
        "%d artifact(s) carry an mtime within %ds of now or ahead of it"
        % (len(hits), window),
        [Evidence(art.shown, "fresh_window_s", str(window)) for art in hits],
    )


def _check_order(obs: Observations) -> Check:
    hits = obs.hits.order
    return _spike_check(
        "order",
        hits,
        "no artifact has an inode above every sibling in its directory",
        "%d artifact(s) have a higher inode than every sibling, so creation order is "
        "recoverable" % len(hits),
        [Evidence(art.shown, "inode_order", "newest") for art in hits],
    )


JUDGES = (
    _check_artifacts,
    _check_aligned,
    _check_corroborated,
    _check_ctime,
    _check_directory_ctime,
    _check_fresh,
    _check_order,
    _check_readable,
)

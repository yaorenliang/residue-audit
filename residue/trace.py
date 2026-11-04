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
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from . import inside, stat_io
from .model import FAIL, PASS, PARTIAL, SKIP, Check, Evidence, Report

DEFAULT_SCAN = (
    "etc/systemd/system",
    "etc/cron.d",
    "usr/libexec",
    "usr/local/bin",
)

DEFAULT_MARKERS = ("KillSignal=SIGCONT", "SendSIGKILL=no")

# systemd.service(5) command prefixes: ignore failure, argv[0] only, full
# privileges, and the obsolete '!' variant. A path behind one of these is still
# the path systemd starts.
EXEC_PREFIXES = "-@+!"

# A directory stamp is written by the kernel after the file inside it, so a few
# milliseconds of lag are normal. Days of lag are not.
DIRECTORY_CTIME_SLACK_MS = 2000


def sanitize(path: str, root: str) -> str:
    """Replace the scanned root with a stable token so goldens survive temp dirs."""
    root = os.path.abspath(root)
    full = os.path.abspath(path)
    if full == root:
        return "<root>"
    if full.startswith(root + os.sep):
        return "<root>/" + full[len(root) + 1:]
    return full


def live_lines(text: str):
    """Configuration lines only: a comment cannot configure anything.

    Matching markers against every line claims a stock unit that merely mentions
    the marker in a comment, and a false claim on a clean host is the failure
    this tool promises not to make.
    """
    for line in text.splitlines():
        stripped = line.lstrip()
        if not stripped or stripped[0] in "#;":
            continue
        yield line


def carries_marker(text: str, markers: Sequence[str]) -> bool:
    for line in live_lines(text):
        for marker in markers:
            if marker in line:
                return True
    return False


def _exec_tokens(text: str) -> List[str]:
    """Split a command line the way systemd does, quotes included.

    systemd.syntax(7) lets a quoted argument carry whitespace, so
    ExecStart="/usr/local/bin/my tool" names one binary. Splitting on whitespace
    first cut that path in two, claimed the truncated prefix, and left the real
    binary unclaimed with no error to say so.
    """
    tokens: List[str] = []
    buff: List[str] = []
    quote = ""
    for char in text:
        if quote:
            if char == quote:
                quote = ""
            else:
                buff.append(char)
        elif char in "'\"":
            quote = char
        elif char.isspace():
            if buff:
                tokens.append("".join(buff))
                buff = []
        else:
            buff.append(char)
    if buff:
        tokens.append("".join(buff))
    return tokens


def exec_start_targets(line: str) -> List[str]:
    """Absolute paths started by one ExecStart= line, in any accepted form.

    systemd.syntax(7) allows whitespace on both sides of the '=' and indented
    directives, and systemd.service(5) prefixes the command with '-', '@' or '+'.
    Reading only a column-0 'ExecStart=' loses units systemd itself runs, and a
    unit we do not follow is a binary we quietly clear.
    """
    stripped = line.lstrip()
    if not stripped.startswith("ExecStart"):
        return []
    body = stripped[len("ExecStart"):].lstrip()
    if not body.startswith("="):
        return []
    out: List[str] = []
    for token in _exec_tokens(body[1:]):
        while token and token[0] in EXEC_PREFIXES:
            token = token[1:]
        if token.startswith("/"):
            out.append(os.path.normpath(token))
    return out


# -- observation -----------------------------------------------------------
#
# One pass over the tree produces values; nothing below this line decides
# anything. The split is the point: a check may not read the filesystem, and an
# observation may not know what a good answer looks like, so neither can quietly
# borrow the other's authority.


@dataclass(frozen=True)
class ArtifactObs:
    """One path we claim, the reason we claim it, and the stamps read once."""

    path: str
    shown: str
    marker: str
    stamp: Optional[stat_io.Stat]


@dataclass(frozen=True)
class DirObs:
    """A directory holding artifacts, and everything an artifact can hide behind."""

    directory: str
    shown: str
    cap_mtime_ms: int
    cap_ctime_ms: int
    max_ino: int
    neighbours: int
    artifacts: Tuple[ArtifactObs, ...]
    changed: Optional[Tuple[int, int]]


@dataclass(frozen=True)
class Hits:
    """Which artifacts answered which question.

    The counts are derived from these tuples rather than kept beside them: a
    second integer that has to agree with a list is one more thing that can be
    wrong, and the report would then print a number no artifact supports.
    """

    aligned: Tuple[ArtifactObs, ...]
    leaked: Tuple[ArtifactObs, ...]
    uncorroborated: Tuple[ArtifactObs, ...]
    ctime: Tuple[ArtifactObs, ...]
    fresh: Tuple[ArtifactObs, ...]
    order: Tuple[ArtifactObs, ...]
    directories: Tuple[DirObs, ...]


@dataclass(frozen=True)
class Observations:
    """Everything one pass learned. The only thing the checks are allowed to see."""

    root: str
    now_ms: int
    fresh_window_s: int
    scan: Tuple[str, ...]
    artifacts: Tuple[ArtifactObs, ...]
    dirs: Tuple[DirObs, ...]
    hits: Hits
    weak: Dict[str, str] = field(default_factory=dict)
    errors: Tuple[stat_io.StatError, ...] = ()
    truncated_files: int = 0
    absolute_links: int = 0


@dataclass
class _Scratch:
    """Mutable scratch space for one discovery pass; it never leaves observe()."""

    root: str
    scan: Tuple[str, ...]
    markers: Tuple[str, ...]
    broad: bool
    heads: Dict[str, Tuple[str, bool]] = field(default_factory=dict)
    claims: Dict[str, str] = field(default_factory=dict)
    weak: Dict[str, str] = field(default_factory=dict)
    absolute_links: int = 0
    errors: List[stat_io.StatError] = field(default_factory=list)
    truncated_files: int = 0
    listed: Dict[Tuple[str, ...], List[str]] = field(default_factory=dict)


def _record(scratch: _Scratch, err: Optional[stat_io.StatError]) -> None:
    """Keep one report per failed path and operation."""
    if err is not None and err not in scratch.errors:
        scratch.errors.append(err)


def scan_entry(rel: str) -> str:
    """One --scan entry, or a refusal naming the tree it would have audited.

    A scanned subtree is a path under the root. An absolute path and a parent
    component are not stricter versions of that: os.path.join drops the root for
    the first, and the second walks out of it, so either one audits a directory
    the caller never named - and files its verdict under the root it did name.
    """
    if not rel.strip():
        raise ValueError("a scanned directory needs a name; an empty one selects the whole root")
    if os.path.isabs(rel):
        raise ValueError(
            "%r is absolute; a scanned directory is relative to the root, e.g. "
            "etc/systemd/system, because an absolute path replaces the root instead of "
            "narrowing it" % rel
        )
    if ".." in rel.replace(os.sep, "/").split("/"):
        raise ValueError(
            "%r walks out of the root; a scanned directory is a path under it, e.g. "
            "etc/cron.d, because a parent component reports another tree under this one" % rel
        )
    return rel


def _list(scratch: _Scratch, dirs: Sequence[str]) -> List[str]:
    """One set of directories, listed once: a tree can change between passes."""
    key = tuple(dirs)
    cached = scratch.listed.get(key)
    if cached is None:
        cached = []
        for rel in key:
            paths, errors = stat_io.walk_files(scratch.root, rel)
            cached.extend(paths)
            for err in errors:
                _record(scratch, err)
        scratch.listed[key] = cached
    return cached


def _members(scratch: _Scratch) -> List[str]:
    """What --scan asks us to audit: the only place a claim may be filed."""
    return _list(scratch, scratch.scan)


def _anchor_members(scratch: _Scratch) -> List[str]:
    """Where a marker-bearing unit may live: the scanned dirs plus the defaults.

    A scanned directory says where to look for artifacts. It does not say where the
    anchor lives: the unit that carries the marker is what turns an ExecStart= target
    into a claim, and reading that unit files no claim of its own. Without this, a
    narrowed --scan found no unit, hence no target, hence no anchor, and answered
    nothing to audit about a tree whose full scan does claim artifacts.
    """
    return _list(scratch, tuple(dict.fromkeys(DEFAULT_SCAN + scratch.scan)))


def _weak(scratch: _Scratch, path: str, why: str) -> None:
    """Record one candidate we did not audit, once.

    A dict costs nothing and removes the whole class of double counting: the
    marker pass and the claim pass both used to append the same path, so a report
    printed "+2 weak claim(s)" about a single file. The reason travels with the
    path because a count nobody can name is not a lead.
    """
    scratch.weak.setdefault(path, why)


def _head(scratch: _Scratch, path: str) -> Tuple[str, bool]:
    """(text, truncated) for one scanned file, read at most once.

    The truncation flag travels with the text because a file longer than the read
    window is not a file without a marker: discovery has to record what it did not
    read instead of clearing the file.
    """
    cached = scratch.heads.get(path)
    if cached is None:
        text, truncated, err = stat_io.read_head(path, root=scratch.root)
        _record(scratch, err)
        if truncated:
            scratch.truncated_files += 1
        cached = (text, truncated)
        scratch.heads[path] = cached
    return cached


def _marker_units(scratch: _Scratch) -> Tuple[List[str], set]:
    """Units that carry an artifact marker, and the paths they start.

    This is the anchor for everything else. A stock Ubuntu root is full of service
    units that mention binaries in /usr/libexec - packagekit, boltd, qmi-proxy -
    and a rule that claims any such binary calls all of them artifacts. On a real
    root that rule measured 5 correct claims out of 13 (38% precision), so
    identification now starts from the marker itself and follows ExecStart= out.
    """
    units: List[str] = []
    targets = set()
    for path in _anchor_members(scratch):
        if not path.endswith(".service"):
            continue
        head, truncated = _head(scratch, path)
        if not carries_marker(head, scratch.markers):
            if truncated:
                # the marker may sit past the read window: not audited, not
                # cleared, and not silently excluded from the count
                _weak(scratch, path, "cut off before the end of the file")
            continue
        units.append(path)
        for line in head.splitlines():
            for target in exec_start_targets(line):
                targets.add(target)
    return units, targets


def _strong_claim(
    scratch: _Scratch, path: str, units: Sequence[str], targets: set
) -> Optional[str]:
    if path in units:
        return "unit:marker"
    head, _ = _head(scratch, path)
    for marker in scratch.markers:
        if carries_marker(head, (marker,)):
            return "marker:" + marker
    absolute = os.path.normpath("/" + os.path.relpath(path, scratch.root))
    if absolute in targets:
        return "unit:execstart"
    for target in sorted(targets):
        name = os.path.basename(target)
        if name and name in head:
            return "content:" + name
    return None


def _broad_names(scratch: _Scratch, targets: set) -> set:
    names = {os.path.basename(t) for t in targets}
    for path in _anchor_members(scratch):
        if not path.endswith(".service"):
            continue
        head, _ = _head(scratch, path)
        for line in head.splitlines():
            for target in exec_start_targets(line):
                base = os.path.basename(target)
                if base:
                    names.add(base)
    return names


def _broad_claim(scratch: _Scratch, path: str, names: set) -> Optional[str]:
    """The old rule set: any binary named by any unit's ExecStart= is ours.

    Kept behind --broad because on a busy root it is wrong more often than it is
    right; the measured precision is in docs/limits.md.
    """
    if os.path.basename(path) in names:
        return "basename:execstart"
    head, _ = _head(scratch, path)
    for name in sorted(names):
        if name and name in head:
            return "content:" + name
    return None


def _absolute_link(path: str) -> bool:
    """Whether a link's target is written as an absolute path.

    systemd writes absolute targets, and a relative one resolves to the same place
    on any host. Only the absolute form needs the image to stand in for /.
    """
    try:
        return os.readlink(path).startswith(os.sep)
    except OSError:
        return False


def _claim(scratch: _Scratch) -> None:
    """Decide which scanned paths are claims, and record the rest as weak or idle."""
    units, targets = _marker_units(scratch)
    names = _broad_names(scratch, targets)
    taken: Dict[str, str] = {}
    for path in _members(scratch):
        reason = _strong_claim(scratch, path, units, targets)
        _, truncated = _head(scratch, path)
        if reason is None:
            if truncated:
                # stopping before the end of a file is a gap in the measurement:
                # "not ours" is a claim we did not earn when we stopped reading
                # before the end of the file, and the gap stays visible as weak
                _weak(scratch, path, "cut off before the end of the file")
                continue
            # A file the broad rule would have claimed is a candidate we are
            # deliberately not auditing. Everything else - ordinary system files -
            # is not a claim of any kind and must not be reported as one: a "weak
            # claim" nobody ever made is noise, not caution.
            broad = _broad_claim(scratch, path, names)
            if broad is None:
                continue
            if not scratch.broad:
                _weak(scratch, path, "named by a unit, not audited without --broad")
                continue
            reason = "broad:" + broad
        _finalize_claim(scratch, path, reason, taken)


def _finalize_claim(
    scratch: _Scratch, path: str, reason: str, taken: Dict[str, str]
) -> None:
    """Record one earned claim: symlink marker, merged-usr dedupe, ledger write."""
    # A marker found inside the read window is a claim we did earn, even when
    # the file ran past the window: the truncation stays visible in
    # facts.truncated_files and in the partial verdicts. Counting the same
    # path as both an artifact and a weak claim reported "+1 weak claim(s) not
    # audited" about a file the report had just audited.
    if inside.is_link(path):
        # a link is how systemd enables a unit: the link is the artifact as
        # much as what it points at, and the reader should see which
        reason = reason + " via=symlink"
        if _absolute_link(path):
            # an absolute target means "inside this image", which is not what
            # the host would resolve: the path was read through our mapping
            scratch.absolute_links += 1
    entry, _ = _entry_path(scratch, path)
    if (entry or path) in taken:
        # /usr/libexec and /usr/lib are two spellings of one directory in a
        # merged-usr image. Counting the file under both names reported two
        # artifacts for an image that holds one.
        return
    taken[entry or path] = path
    scratch.claims[path] = reason


def _readable_path(scratch: _Scratch, path: str) -> Optional[str]:
    """The path to open for one entry: inside the image, or None with the reason.

    Claiming a path and reading it have to agree. A claim found through a symlinked
    scan directory (or under any link in the middle of its path) is named
    <root>/usr/libexec/worker, and asking the host to lstat that name lands in the
    host's tree - the entry is real, the name is the image's.
    """
    real, why = inside.resolve(scratch.root, path)
    if real is None:
        _record(scratch, stat_io.StatError(path, "resolve", why or "unresolvable link"))
    return real


def _entry_path(scratch: _Scratch, path: str) -> Tuple[Optional[str], Optional[str]]:
    """The host path of the entry itself: parent resolved inside the image, name kept.

    Stamping the resolved path is what made an enabled unit invisible: systemd writes
    /etc/systemd/system/x.wants/y.service -> /lib/systemd/system/y.service, resolve()
    hands back the target, and the link that ls -lt prints first is measured by the
    mtime of a unit written two years ago. The last component therefore stays
    unexpanded - only the directories above it are resolved, so a link in the middle
    of the path still means "inside this image".
    """
    parent, name = os.path.split(path)
    real_parent, why = inside.resolve(scratch.root, parent or scratch.root)
    if real_parent is None:
        return None, why
    return os.path.join(real_parent, name), None


def _stamp(scratch: _Scratch) -> Tuple[ArtifactObs, ...]:
    """Read every claim's stamps once, and report the ones we could not read."""
    out: List[ArtifactObs] = []
    for path in sorted(scratch.claims):
        # readable accounting stays on the resolved path: a link that leaves the box
        # is a named gap, not a silent one.
        _readable_path(scratch, path)
        entry, why = _entry_path(scratch, path)
        stamp, err = (None, None) if entry is None else stat_io.stat_of(entry)
        if entry is None:
            _record(scratch, stat_io.StatError(path, "resolve", why or "unresolvable link"))
        elif stamp is None:
            # stat_of() answers (Stat, None) or (None, StatError): a missing stamp
            # already means the error is the other half of that pair
            _record(scratch, err)
        out.append(ArtifactObs(path, sanitize(path, scratch.root), scratch.claims[path], stamp))
    return tuple(out)


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
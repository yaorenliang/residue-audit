"""Which artifacts are ours: markers, symlinks, absolute links, and the ledger of claims.

A claim is earned by reading the file it names, and every read that fails is
recorded rather than swallowed. A unit we could not open is not the same as a
unit that carries no marker, and the ledger has to keep them apart.
"""

from __future__ import annotations

import os
from typing import Dict, List, Optional, Sequence, Tuple

from . import inside, stat_io
from .trace_parse import carries_marker, exec_start_targets, sanitize
from .trace_obs import ArtifactObs, _Scratch


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


DEFAULT_SCAN = (
    "etc/systemd/system",
    "etc/cron.d",
    "usr/libexec",
    "usr/local/bin",
)

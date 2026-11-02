"""The only module that touches the filesystem.

Keeping stat and utime calls in one place makes the cross-platform story explicit:
macOS and ext4 disagree about directory mtimes, and every such difference is
visible here instead of being scattered across the checks.

Every reader here returns its error instead of swallowing it. A path we could not
read is not a path that is not there, and folding the two together is how a
scanner ends up reporting a clean host after failing to open half of it.
"""

from __future__ import annotations

import errno
import os
from typing import Dict, List, NamedTuple, Optional, Tuple

MS = 1_000_000

# How much of a file identification is allowed to read. The old 8 KiB window
# turned a marker at offset 20000 into a clean host, and a marker past the window
# is not evidence of absence, so the window is wide and its edge is reported.
READ_LIMIT = 65536


class StatError(NamedTuple):
    """One failed filesystem operation, kept as data so it can be reported."""

    path: str
    op: str
    err: str

    def to_dict(self) -> Dict[str, str]:
        return {"path": self.path, "op": self.op, "err": self.err}


def _describe(exc: OSError) -> str:
    """A path-free description: reports and goldens compare these strings."""
    return exc.strerror or exc.__class__.__name__


def stat_error(path: str, op: str, exc: OSError) -> StatError:
    return StatError(path, op, _describe(exc))


def _collect(errors: Optional[List[StatError]], err: Optional[StatError]) -> None:
    """Opt-in error channel, so callers that keep no list still get the old shape."""
    if errors is not None and err is not None:
        errors.append(err)


def mtime_ms(path: str) -> int:
    return os.lstat(path).st_mtime_ns // MS


def ctime_ms(path: str) -> int:
    """Status-change time. Unlike mtime this cannot be set by user space."""
    return os.lstat(path).st_ctime_ns // MS


def ino(path: str) -> int:
    return os.lstat(path).st_ino


def set_mtime_ms(path: str, value_ms: int) -> None:
    """Set mtime at nanosecond precision. Refuses sentinel values instead of guessing.

    Going through float seconds rounds the value, and a millisecond that reads
    back one short is enough to flip an alignment comparison, so the value is
    handed to utime() as nanoseconds and never passes through a float.
    """
    if value_ms <= 0:
        raise ValueError("refusing to set mtime to %r" % (value_ms,))
    value_ns = int(value_ms) * MS
    os.utime(path, ns=(value_ns, value_ns))


def is_file(path: str) -> bool:
    """A regular file, not a symlink: the only thing that can be a sibling."""
    return os.path.isfile(path) and not os.path.islink(path)


def is_dir(path: str) -> bool:
    return os.path.isdir(path)


def is_member(path: str) -> bool:
    """Scan membership: a regular file, or a symlink that resolves to one.

    systemd enables a unit by symlinking it, and a link that is not followed is
    an artifact the tool would report as absent. Membership follows the link;
    the sibling cap does not (see dir_stats).
    """
    return os.path.isfile(path)


def listdir_sorted(path: str) -> Tuple[List[str], Optional[StatError]]:
    """Sorted entry names, plus the error if the directory could not be listed.

    A directory that does not exist is not an error: the default scan names four
    system directories and a partial tree will not have all four. Everything else
    - permission denied, a stale handle, an I/O error - is: entries we were told
    exist and could not see.
    """
    try:
        return sorted(os.listdir(path)), None
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            return [], None
        return [], stat_error(path, "listdir", exc)


def read_head(path: str, limit: int = READ_LIMIT) -> Tuple[str, bool, Optional[StatError]]:
    """First limit bytes as text, whether the file is longer, and the error.

    The truncation flag travels with the text because a marker past the window is
    not a file without a marker: the caller has to say what it did not read.
    """
    try:
        with open(path, "rb") as fh:
            data = fh.read(limit + 1)
    except OSError as exc:
        return "", False, stat_error(path, "read", exc)
    return data[:limit].decode("utf-8", "replace"), len(data) > limit, None


def dir_entries(path: str) -> Tuple[Dict[str, List[str]], Optional[StatError]]:
    """Names directly in path, split into files, symlinks and directories."""
    names, err = listdir_sorted(path)
    groups: Dict[str, List[str]] = {"files": [], "symlinks": [], "dirs": []}
    for name in names:
        full = os.path.join(path, name)
        if os.path.islink(full):
            groups["symlinks"].append(name)
        elif os.path.isdir(full):
            groups["dirs"].append(name)
        elif os.path.isfile(full):
            groups["files"].append(name)
    return groups, err


def walk_files(root: str, rel_dir: str) -> Tuple[List[str], List[StatError]]:
    """Scan members directly inside root/rel_dir (no recursion), plus list errors.

    Members are regular files plus symlinks that resolve to one. Both are visible
    to ls, so both have to be visible here.
    """
    base = os.path.join(root, rel_dir)
    names, err = listdir_sorted(base)
    paths: List[str] = []
    for name in names:
        full = os.path.join(base, name)
        if is_member(full):
            paths.append(full)
    return paths, [err] if err is not None else []


def dir_stats(
    path: str,
    ours: Optional[set] = None,
    errors: Optional[List[StatError]] = None,
) -> Tuple[int, int, int, int]:
    """Newest mtime, newest ctime, highest inode and count of sibling files.

    Only regular files are siblings. A subdirectory's mtime is the last write
    inside it, which for an implant is the implant's own write, so counting it
    lets an artifact borrow the timestamp of the very directory that holds it.
    Symlinks are not siblings either: the cap is what an artifact has to hide
    behind, and it has to be something the attacker did not create.
    """
    norm_ours = {os.path.normpath(item) for item in (ours or set())}
    groups, err = dir_entries(path)
    _collect(errors, err)
    cap = 0
    cap_ctime = 0
    max_ino = 0
    count = 0
    for name in groups["files"]:
        full = os.path.join(path, name)
        if os.path.normpath(full) in norm_ours:
            continue
        try:
            value = mtime_ms(full)
            changed = ctime_ms(full)
            number = ino(full)
        except OSError as exc:
            _collect(errors, stat_error(full, "stat", exc))
            continue
        count += 1
        cap = max(cap, value)
        cap_ctime = max(cap_ctime, changed)
        max_ino = max(max_ino, number)
    return cap, cap_ctime, max_ino, count


def dir_cap_ms(
    path: str,
    ours: Optional[set] = None,
    errors: Optional[List[StatError]] = None,
) -> Tuple[int, int, int]:
    """(newest sibling mtime, newest sibling ctime, sibling count).

    Returns zeros when the directory has no corroborating sibling: an empty
    directory cannot tell us what "old" looks like.
    """
    cap, cap_ctime, _max_ino, count = dir_stats(path, ours, errors)
    return cap, cap_ctime, count

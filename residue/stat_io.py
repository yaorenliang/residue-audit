"""The only module that touches the filesystem.

Keeping stat and utime calls in one place makes the cross-platform story explicit:
macOS and ext4 disagree about directory mtimes, and every such difference is
visible here instead of being scattered across the checks.
"""

from __future__ import annotations

import os
from typing import List, Optional, Tuple

MS = 1_000_000


def mtime_ms(path: str) -> int:
    return os.lstat(path).st_mtime_ns // MS


def ctime_ms(path: str) -> int:
    """Status-change time. Unlike mtime this cannot be set by user space."""
    return os.lstat(path).st_ctime_ns // MS


def ino(path: str) -> int:
    return os.lstat(path).st_ino


def set_mtime_ms(path: str, value_ms: int) -> None:
    """Set mtime explicitly. Refuses sentinel values instead of guessing."""
    if value_ms <= 0:
        raise ValueError("refusing to set mtime to %r" % (value_ms,))
    sec, fraction = divmod(value_ms, 1000)
    os.utime(path, (sec, sec + fraction / 1000.0))


def is_file(path: str) -> bool:
    return os.path.isfile(path) and not os.path.islink(path)


def is_dir(path: str) -> bool:
    return os.path.isdir(path)


def listdir_sorted(path: str) -> List[str]:
    try:
        return sorted(os.listdir(path))
    except OSError:
        return []


def read_head(path: str, limit: int = 8192) -> str:
    """Read at most the first limit bytes, decoded with replacement.

    Binaries survive this: we only look for markers, and a marker that only
    appears past 8 KiB is not a marker we should trust anyway.
    """
    try:
        with open(path, "rb") as fh:
            return fh.read(limit).decode("utf-8", "replace")
    except OSError:
        return ""


def walk_files(root: str, rel_dir: str) -> List[str]:
    """Files directly inside root/rel_dir (no recursion), absolute paths."""
    base = os.path.join(root, rel_dir)
    return [
        os.path.join(base, name)
        for name in listdir_sorted(base)
        if is_file(os.path.join(base, name))
    ]


def dir_cap_ms(path: str, ours: Optional[set] = None) -> Tuple[int, int]:
    """Newest mtime among entries in the directory that are not ours, and a count.

    Returns (0, 0) when the directory has no corroborating sibling: an empty
    directory cannot tell us what "old" looks like.
    """
    ours = ours or set()
    cap = 0
    count = 0
    for name in listdir_sorted(path):
        full = os.path.join(path, name)
        if full in ours:
            continue
        try:
            value = mtime_ms(full)
        except OSError:
            continue
        count += 1
        if value > cap:
            cap = value
    return cap, count
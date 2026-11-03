"""Deciding which paths are ours to read, and which are outside the box.

An audited tree is an image, not the host running the audit. systemd enables a unit
by writing an absolute symlink - /etc/systemd/system/x.service -> /lib/systemd/system/x.service -
and that path means "inside this root", not "inside my machine". Resolving it against
the host has two failures with one cause: an artifact whose target is present in the
image disappears from the report, and a host file outside the root is read as evidence
about the image.

So resolution is explicit: walk the path one component at a time, read every absolute
target as an image path, and refuse the whole path when the chain leaves the box.
Component by component matters: a link in the middle of a path - a symlinked scan
directory, a merged-/usr tree where /lib is a link - is resolved by the kernel against
the host if you hand the whole path to realpath(), and then every file behind it is
read from the wrong tree. One function, one answer: the real path inside the root, or
the reason we will not read it.
"""

from __future__ import annotations

import os
from typing import List, Optional, Tuple

# A link chain this deep is not a systemd enablement link; it is a loop or an attack.
MAX_HOPS = 40


def _inside(root: str, path: str) -> bool:
    """True when path (already absolute and normalised) sits under root."""
    root = root.rstrip(os.sep) or os.sep
    if root == os.sep:
        return path.startswith(os.sep)
    return path == root or path.startswith(root + os.sep)


def _parts(root: str, path: str) -> Optional[List[str]]:
    """The components of path below root, or None when path is not under root."""
    root = os.path.abspath(root)
    path = os.path.abspath(path)
    if not _inside(root, path):
        return None
    rel = os.path.relpath(path, root)
    if rel == ".":
        return []
    return [part for part in rel.split(os.sep) if part not in ("", ".")]


def _target_of(link: str, root: str) -> str:
    """Where one link points, with absolute targets read as image paths.

    An absolute target means "inside this image" whenever the image holds such a
    path. When it does not, the host path is kept as-is: resolve() then accepts it
    only if it is still inside the root, which is how a real tree mounted at its own
    absolute path keeps working, and how a link to /etc/passwd stops being evidence.
    """
    target = os.readlink(link)
    if not target.startswith(os.sep):
        return os.path.normpath(os.path.join(os.path.dirname(link), target))
    mirrored = os.path.normpath(os.path.join(root, target.lstrip(os.sep)))
    if os.path.lexists(mirrored):
        return mirrored
    return os.path.normpath(target)


def resolve(root: str, path: str) -> Tuple[Optional[str], Optional[str]]:
    """(real path inside root, None) or (None, why we refuse to read it).

    The walk keeps its own stack instead of calling realpath(): every component is
    looked at, a link anywhere in the path is followed inside the image, and ".."
    never gets a chance to climb out, because it is refused rather than interpreted.
    """
    root_abs = os.path.abspath(root)
    todo = _parts(root_abs, path)
    if todo is None:
        return None, "%s is not under %s" % (path, os.path.basename(root_abs) or root_abs)
    current = root_abs
    hops = 0
    seen = set()
    while todo:
        name = todo.pop(0)
        if name == "..":
            return None, "%s leaves the root" % (path,)
        step = os.path.join(current, name)
        if os.path.islink(step):
            hops += 1
            if hops > MAX_HOPS:
                return None, "symlink chain longer than %d hops" % (MAX_HOPS,)
            if step in seen:
                return None, "symlink loop at %s" % (step,)
            seen.add(step)
            try:
                target = _target_of(step, root_abs)
            except OSError as exc:
                return None, exc.strerror or exc.__class__.__name__
            inner = _parts(root_abs, target)
            if inner is None:
                return None, "%s resolves outside %s" % (
                    step,
                    os.path.basename(root_abs) or root_abs,
                )
            todo = inner + todo
            current = root_abs
            continue
        if not os.path.lexists(step):
            return None, "target %s has no counterpart inside the root" % (step,)
        current = step
    # Hand back the path as the host spells the root (realpath of the root only):
    # /var -> /private/var is the host's business, and callers open this path. What
    # must not happen is realpath() over the whole path, which would follow a link
    # in the middle of it against the host.
    rel = os.path.relpath(current, root_abs)
    host_root = os.path.realpath(root_abs)
    return (host_root if rel == "." else os.path.join(host_root, rel)), None


def is_link(path: str) -> bool:
    """Whether the entry itself is a link: what systemd writes when it enables a unit."""
    return os.path.islink(path)

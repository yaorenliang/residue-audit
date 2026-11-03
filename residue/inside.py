"""Deciding which paths are ours to read, and which are outside the box.

An audited tree is an image, not the host running the audit. systemd enables a unit
by writing an absolute symlink - /etc/systemd/system/x.service -> /lib/systemd/system/x.service -
and that path means "inside this root", not "inside my machine". Resolving it against
the host has two failures with one cause: an artifact whose target is present in the
image disappears from the report, and a host file outside the root is read as evidence
about the image.

So resolution is explicit: follow the chain by hand, read every absolute target as an
image path, and refuse the whole path when the chain leaves the box. One function,
one answer: the real path inside the root, or the reason we will not read it.
"""

from __future__ import annotations

import os
from typing import Optional, Tuple

# A link chain this deep is not a systemd enablement link; it is a loop or an attack.
MAX_HOPS = 40


def _inside(root: str, path: str) -> bool:
    """True when path (already absolute and normalised) sits under root."""
    root = root.rstrip(os.sep) or os.sep
    if root == os.sep:
        return path.startswith(os.sep)
    return path == root or path.startswith(root + os.sep)


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

    The returned path is the link chain followed to its end, still inside root. A
    link that points at an absolute path is read as an image path; a link that ends
    up outside the root - by an absolute target with no counterpart in the image, by
    enough ".." segments, or by a chain that never terminates - is a named gap.
    """
    root_abs = os.path.abspath(root)
    current = os.path.abspath(path)
    seen = set()
    for _ in range(MAX_HOPS):
        if current in seen:
            return None, "symlink loop at %s" % (current,)
        seen.add(current)
        try:
            link = os.path.islink(current)
        except OSError as exc:
            return None, exc.strerror or exc.__class__.__name__
        if not link:
            break
        try:
            current = _target_of(current, root_abs)
        except OSError as exc:
            return None, exc.strerror or exc.__class__.__name__
    else:
        return None, "symlink chain longer than %d hops" % (MAX_HOPS,)

    if not os.path.lexists(current):
        return None, "target %s has no counterpart inside the root" % (current,)

    resolved = os.path.realpath(current)
    if not _inside(os.path.realpath(root_abs), resolved):
        return None, "%s resolves outside %s" % (path, os.path.basename(root_abs) or root_abs)
    return resolved, None


def is_link(path: str) -> bool:
    """Whether the entry itself is a link: what systemd writes when it enables a unit."""
    return os.path.islink(path)
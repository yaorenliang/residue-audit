"""The shapes the halves of trace share: what was observed, and what was decided.

They live together because claim resolution and directory grouping both name
these types; splitting them apart would make those two modules import each
other.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from . import stat_io


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

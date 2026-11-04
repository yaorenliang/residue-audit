"""Fixture data shared by the demo and the tests.

The demo used to keep its own copy of the artifact set, the ledger and the hit
list. Two copies of a fixture drift: the demo kept showing a behaviour the
tests no longer exercised, and neither of them failed. So the data lives here,
in the package, and the tests import it backwards from ``residue``. Tests that
need a *different* tree build one next to the case instead of editing this file.

Nothing here touches the filesystem except the two writers, and both only write
below a root the caller passes in.
"""

from __future__ import annotations

import json
import os
import time
from typing import Dict, List, Optional

from . import stat_io

# 2021-01-01T00:00:00Z. Deliberately old: an artifact that carries this mtime
# has borrowed it, because the file was written today.
NEIGHBOUR_MS = 1609459200000

# The synthetic implant. Two units carry both marker lines, one cron file
# carries neither, and two "binaries" are the ExecStart targets.
ARTIFACTS: Dict[str, str] = {
    "etc/systemd/system/zz-harvest.service": (
        "[Unit]\nDescription=harvest\n[Service]\n"
        "Restart=always\nKillSignal=SIGCONT\nSendSIGKILL=no\n"
        "ExecStart=/usr/libexec/kworker --id x\n"
    ),
    "etc/systemd/system/zz-bridge.service": (
        "[Unit]\nDescription=bridge\n[Service]\n"
        "Restart=always\nKillSignal=SIGCONT\nSendSIGKILL=no\n"
        "ExecStart=/usr/local/bin/bridge-client-x\n"
    ),
    "etc/cron.d/kworkers-updater": "*/17 * * * * root /usr/libexec/kworker --self-update\n",
    "usr/libexec/kworker": "\x7fELF synthetic worker\nKillSignal=SIGCONT\n",
    "usr/local/bin/bridge-client-x": "\x7fELF synthetic client\n",
}


def write_artifacts(root: str) -> List[str]:
    """Write ARTIFACTS below root and return the absolute paths, in ARTIFACTS order."""
    written: List[str] = []
    for rel, body in ARTIFACTS.items():
        path = os.path.join(root, rel)
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)
        written.append(path)
    return written


def make_dirs(root: str, dirs) -> None:
    for rel in dirs:
        os.makedirs(os.path.join(root, rel), exist_ok=True)


def write_neighbours(root: str, dirs) -> List[str]:
    """Create two old, unrelated regular files per directory.

    They are the "siblings" an artifact can borrow a timestamp from. They are
    written after the artifacts on purpose when a caller wants the order check
    to pass: an inode number cannot be backdated, so the neighbours have to be
    created second to look newer.
    """
    made: List[str] = []
    for rel in dirs:
        for name in ("zzz-neighbour-a", "zzz-neighbour-b"):
            path = os.path.join(root, rel, name)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("unrelated\n")
            stat_io.set_mtime_ms(path, NEIGHBOUR_MS)
            made.append(path)
    return made


def _ctime_ms(path: str) -> Optional[int]:
    """The ctime of path in milliseconds, or None when it cannot be read."""
    info, _ = stat_io.stat_of(path)
    return None if info is None else info.ctime_ms


def separate_ctimes(
    paths: List[str], first_wait_s: float = 0.01, rounds: int = 6
) -> None:
    """Make every artifact's ctime strictly newer than the siblings beside it.

    ``trace.ctime`` compares strictly (ctime_ms > the newest sibling ctime), so
    two writes that land in the same clock tick tie: the artifact stops winning,
    one evidence line disappears from the report, and a sample quoted in the
    README changes length between runs. A single sleep before writing is a bet on
    the filesystem's ctime granularity - 10ms is enough on ext4 and not enough on
    the coarser ticks a CI runner reports - and a bet is not a fixture. So the
    bet is checked: after each round, every artifact that still ties is rewritten
    (writing is what moves a ctime forward) and the next round waits twice as
    long. A tree still tied after ``rounds`` raises, because a drifting sample is
    worse than a red test.

    Only the artifacts' own ctimes move. Rewriting an existing file leaves the
    holding directory's ctime alone, so the directory check keeps answering the
    same way it did before.
    """
    ours = set(paths)
    pending = list(paths)
    wait = first_wait_s
    for _ in range(rounds):
        if not pending:
            return
        time.sleep(wait)
        still_tied: List[str] = []
        for path in pending:
            with open(path, "rb") as handle:
                body = handle.read()
            with open(path, "wb") as handle:
                handle.write(body)
            cap_ctime = stat_io.dir_stats(os.path.dirname(path), ours)[1]
            stamp = _ctime_ms(path)
            if stamp is None or stamp <= cap_ctime:
                still_tied.append(path)
        pending = still_tied
        wait *= 2
    raise RuntimeError(
        "ctime of %d artifact(s) still ties with their siblings after %d rounds: "
        "this filesystem cannot separate them" % (len(pending), rounds)
    )


def borrow_sibling_mtimes(paths, extra_ours: Optional[List[str]] = None) -> None:
    """Backdate each artifact to the newest non-artifact sibling mtime.

    Ours must be excluded from the cap, otherwise every artifact is its own
    newest neighbour and borrows its own fresh timestamp.
    """
    ours = set(paths) | set(extra_ours or [])
    for path in paths:
        cap = stat_io.dir_stats(os.path.dirname(path), ours)[0]
        if cap:
            stat_io.set_mtime_ms(path, cap)


# A ledger where two of four deployed hosts were seen by a detection rule.
LEDGER = [
    {"ts": 1000, "host": "h1", "event": "scan"},
    {"ts": 1005, "host": "h1", "event": "deploy"},
    {"ts": 1180, "host": "h1", "event": "mine", "ok": True},
    {"ts": 1010, "host": "h2", "event": "scan"},
    {"ts": 1012, "host": "h2", "event": "deploy"},
    {"ts": 1215, "host": "h2", "event": "mine", "ok": True},
    {"ts": 1020, "host": "h3", "event": "deploy"},
    {"ts": 1080, "host": "h3", "event": "mine", "ok": False},
    {"ts": 1025, "host": "h4", "event": "deploy"},
    {"ts": 1095, "host": "h4", "event": "mine", "ok": True},
    {"ts": 1030, "host": "h5", "event": "scan"},
]

HITS = [
    {"ts": 1090, "host": "h1", "rule": "yara:generic-miner"},
    {"ts": 1150, "host": "h3", "rule": "falco:systemd-drop"},
]


def write_ledger(path: str, events) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for event in events:
            fh.write(json.dumps(event) + "\n")


def write_json(path: str, payload) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh)


def write_hits(path: str, hits) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"hits": list(hits)}, fh)


def feature_set(name: str, count: int = 100, tail: str = "") -> dict:
    features = ["feature-%03d" % i for i in range(count)]
    if tail:
        features = features[:-1] + [tail]
    return {"name": name, "features": features}

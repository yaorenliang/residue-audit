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


def borrow_sibling_mtimes(paths, extra_ours: Optional[List[str]] = None) -> None:
    """Backdate each artifact to the newest non-artifact sibling mtime.

    Ours must be excluded from the cap, otherwise every artifact is its own
    newest neighbour and borrows its own fresh timestamp.
    """
    ours = set(paths) | set(extra_ours or [])
    for path in paths:
        cap = stat_io.dir_cap_ms(os.path.dirname(path), ours)[0]
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

"""Shared fixture builders.

Trees are built at test time because git cannot store mtimes or inode numbers:
a checked-in tree would arrive with a single checkout timestamp and every
alignment assertion would be meaningless.
"""

from __future__ import annotations

import json
import os
import time

from residue import stat_io
from residue._fixtures import ARTIFACTS, NEIGHBOUR_MS, write_json, write_ledger

# The artifact set and the "old timestamp" both live in the package now, because
# the demo needs them too, and two copies of a fixture drift silently. What stays
# here is what only the tests use: the ledger variants below, and a plant() that
# can leave neighbours out.
OLD_MS = NEIGHBOUR_MS
LATER_MS = OLD_MS + 86_400_000 * 365  # a year later, still in the past

DIRS = (
    "etc/systemd/system",
    "etc/cron.d",
    "usr/libexec",
    "usr/local/bin",
)


def plant(root: str, neighbours: bool = True, align: bool = True, only=None):
    """Create the synthetic artifact set and return the written paths."""
    for rel_dir in DIRS:
        os.makedirs(os.path.join(root, rel_dir), exist_ok=True)
        if not neighbours:
            continue
        for name in ("zzz-neighbour-a", "zzz-neighbour-b"):
            path = os.path.join(root, rel_dir, name)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("unrelated\n")
            stat_io.set_mtime_ms(path, OLD_MS)
    if neighbours:
        # ctime cannot be set, so the order of the writes is the only way to make
        # "installed after the neighbours" a reproducible fact instead of a tie
        time.sleep(0.01)
    written = []
    for rel, body in ARTIFACTS.items():
        if only is not None and rel not in only:
            continue
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)
        written.append(path)
    if align:
        ours = set(written)
        for path in written:
            cap = stat_io.dir_stats(os.path.dirname(path), ours)[0]
            if cap:
                stat_io.set_mtime_ms(path, cap)
    return written


# A second ledger shape: here h4 is only scanned, so the denominator is not
# "every host observed". The variant stays local because no demo shows it.
LEDGER = [
    {"ts": 1000, "host": "h1", "event": "scan"},
    {"ts": 1005, "host": "h1", "event": "deploy"},
    {"ts": 1180, "host": "h1", "event": "mine", "ok": True},
    {"ts": 1010, "host": "h2", "event": "scan"},
    {"ts": 1012, "host": "h2", "event": "deploy"},
    {"ts": 1215, "host": "h2", "event": "mine", "ok": True},
    {"ts": 1020, "host": "h3", "event": "deploy"},
    {"ts": 1080, "host": "h3", "event": "mine", "ok": False},
    {"ts": 1030, "host": "h4", "event": "scan"},
]

HITS = [
    {"ts": 1090, "host": "h1", "rule": "yara:generic-miner"},
    {"ts": 1150, "host": "h3", "rule": "falco:systemd-drop"},
]

# four hosts all reached deploy, two of them were flagged: exactly half, which
# is the case this project exists to stop calling coverage
LEDGER_FOUR = [
    {"ts": 1000, "host": "h1", "event": "deploy"},
    {"ts": 1180, "host": "h1", "event": "mine", "ok": True},
    {"ts": 1010, "host": "h2", "event": "deploy"},
    {"ts": 1215, "host": "h2", "event": "mine", "ok": True},
    {"ts": 1020, "host": "h3", "event": "deploy"},
    {"ts": 1080, "host": "h3", "event": "mine", "ok": True},
    {"ts": 1030, "host": "h4", "event": "deploy"},
    {"ts": 1095, "host": "h4", "event": "mine", "ok": True},
]
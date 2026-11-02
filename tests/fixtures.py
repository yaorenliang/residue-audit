"""Shared fixture builders.

Trees are built at test time because git cannot store mtimes or inode numbers:
a checked-in tree would arrive with a single checkout timestamp and every
alignment assertion would be meaningless.
"""

from __future__ import annotations

import json
import os

from residue import stat_io

OLD_MS = 1609459200000  # 2021-01-01T00:00:00Z
LATER_MS = OLD_MS + 86_400_000 * 365  # a year later, still in the past

ARTIFACTS = {
    "etc/systemd/system/zz-harvest.service": (
        "[Unit]\nDescription=harvest\n[Service]\n"
        "Restart=always\nKillSignal=SIGCONT\nSendSIGKILL=no\n"
        "ExecStart=/usr/libexec/kworker --id x\n"
    ),
    "etc/systemd/system/zz-bridge.service": (
        "[Service]\nRestart=always\nKillSignal=SIGCONT\n"
        "ExecStart=/usr/local/bin/bridge-client-x\n"
    ),
    "etc/cron.d/kworkers-updater": "*/17 * * * * root /usr/libexec/kworker --self-update\n",
    "usr/libexec/kworker": "\x7fELF synthetic worker\nKillSignal=SIGCONT\n",
    "usr/local/bin/bridge-client-x": "\x7fELF synthetic client\n",
}

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
            cap, _ = stat_io.dir_cap_ms(os.path.dirname(path), ours)
            if cap:
                stat_io.set_mtime_ms(path, cap)
    return written


def write_json(path: str, payload) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh)


def write_ledger(path: str, events) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for event in events:
            fh.write(json.dumps(event) + "\n")


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
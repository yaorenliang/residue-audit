"""Self-contained demo: build a throwaway tree, audit it, then break it.

The demo exists so a reader can see a passing audit and the failing version of
the same tree in under a second. It never touches anything outside the
temporary directory it creates.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from typing import List

from . import batch as batch_mod
from . import dwell as dwell_mod
from . import report as report_mod
from . import stat_io
from . import trace as trace_mod

NEIGHBOUR_MS = 1609459200000  # 2021-01-01T00:00:00Z, deliberately old

UNITS = {
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


def build_tree(root: str, align: bool = True) -> List[str]:
    """Create the synthetic artifact set, optionally borrowing sibling mtimes."""
    for rel_dir in trace_mod.DEFAULT_SCAN:
        os.makedirs(os.path.join(root, rel_dir), exist_ok=True)
        for name in ("zzz-neighbour-a", "zzz-neighbour-b"):
            path = os.path.join(root, rel_dir, name)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("unrelated\n")
            stat_io.set_mtime_ms(path, NEIGHBOUR_MS)
    written = []
    for rel, body in UNITS.items():
        path = os.path.join(root, rel)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)
        written.append(path)
    if align:
        # ours must be excluded from the cap, otherwise each artifact is its
        # own newest neighbour and borrows its own fresh timestamp
        ours = set(written)
        for path in written:
            stat_io.set_mtime_ms(path, stat_io.dir_cap_ms(os.path.dirname(path), ours)[0])
    return written


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


def _write_json(path: str, payload) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh)


def run(stdout=None) -> int:
    out = stdout or sys.stdout
    tmp = tempfile.mkdtemp(prefix="residue-demo-")
    try:
        clean_root = os.path.join(tmp, "clean")
        os.makedirs(clean_root)
        build_tree(clean_root, align=True)
        dirty_root = os.path.join(tmp, "dirty")
        os.makedirs(dirty_root)
        build_tree(dirty_root, align=False)

        out.write("### 1. artifacts written, mtimes borrowed from siblings\n")
        out.write(report_mod.as_text(trace_mod.run(clean_root)))
        out.write(
            "note: trace.order failing here is the point. utimensat rewrites a\n"
            "      timestamp; nothing user-space can rewrite the inode number,\n"
            "      so creation order stays recoverable. Depth has a floor.\n\n"
        )

        out.write("### 2. same tree, written just now (negative control)\n")
        out.write(report_mod.as_text(trace_mod.run(dirty_root)))

        ledger = os.path.join(tmp, "ledger.ndjson")
        with open(ledger, "w", encoding="utf-8") as fh:
            for event in LEDGER:
                fh.write(json.dumps(event) + "\n")
        hits = os.path.join(tmp, "hits.json")
        _write_json(hits, HITS)

        out.write("### 3. dwell and coverage: two of four hosts is not coverage\n")
        out.write(report_mod.as_text(dwell_mod.run(ledger, hits)))

        a = os.path.join(tmp, "a.json")
        b = os.path.join(tmp, "b.json")
        base = ["feature-%03d" % i for i in range(100)]
        _write_json(a, {"name": "build-a", "features": base})
        _write_json(b, {"name": "build-b", "features": base[:-1] + ["feature-999"]})
        out.write("### 4. two builds, one feature apart: they still cluster\n")
        out.write(report_mod.as_text(batch_mod.run([a, b])))
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(run(sys.stdout))
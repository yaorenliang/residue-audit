"""Trace: did the artifacts blend in, or do they stand out on ls -lt?

Three questions, deliberately separated:

  artifacts      which files are ours: claims anchored on a marker-bearing unit
  aligned        artifact mtime is not newer than the newest non-ours sibling
  corroborated   the directory actually has such a sibling to borrow from
  ctime          status-change time outruns every sibling (cannot be rewritten)
  order          inode allocation does not preserve creation order

They are separate because they can disagree. A tree can be aligned and still
uncorroborated (empty directory), which is neither a pass nor a failure.
"""

from __future__ import annotations

import os
from typing import Dict, List, Optional, Sequence

from . import stat_io
from .model import FAIL, PASS, PARTIAL, SKIP, Check, Evidence, Report

DEFAULT_SCAN = (
    "etc/systemd/system",
    "etc/cron.d",
    "usr/libexec",
    "usr/local/bin",
)

DEFAULT_MARKERS = ("KillSignal=SIGCONT", "SendSIGKILL=no")


def sanitize(path: str, root: str) -> str:
    """Replace the scanned root with a stable token so goldens survive temp dirs."""
    root = os.path.abspath(root)
    full = os.path.abspath(path)
    if full == root:
        return "<root>"
    if full.startswith(root + os.sep):
        return "<root>/" + full[len(root) + 1:]
    return full


class Scanner:
    def __init__(
        self,
        root: str,
        scan: Sequence[str] = DEFAULT_SCAN,
        markers: Sequence[str] = DEFAULT_MARKERS,
        fresh_window_s: int = 120,
        broad: bool = False,
    ) -> None:
        self.root = os.path.abspath(root)
        self.scan = tuple(scan)
        self.markers = tuple(markers)
        self.fresh_window_s = fresh_window_s
        self.broad = broad
        self.marker_hits: Dict[str, str] = {}
        self.units: Dict[str, List[str]] = {}
        self.artifacts: List[str] = []
        self.weak: List[str] = []
        self.counts: Dict[str, int] = {}

    # -- discovery ---------------------------------------------------------
    def _scan_files(self) -> List[str]:
        out: List[str] = []
        for rel in self.scan:
            out.extend(stat_io.walk_files(self.root, rel))
        return out

    def _marker_units(self) -> tuple:
        """Units that carry an artifact marker, and the paths they start.

        This is the anchor for everything else. A stock Ubuntu root is full of
        service units that mention binaries in /usr/libexec - packagekit,
        boltd, qmi-proxy - and a rule that claims any such binary calls all of
        them artifacts. On a real root that rule measured 5 correct claims out of
        13 (38% precision), so identification now starts from the marker itself
        and follows ExecStart= outward from there.
        """
        units: List[str] = []
        targets = set()
        for path in self._scan_files():
            if not path.endswith(".service"):
                continue
            head = stat_io.read_head(path)
            if not any(marker in head for marker in self.markers):
                continue
            units.append(path)
            for line in head.splitlines():
                if not line.startswith("ExecStart="):
                    continue
                for token in line.split("=", 1)[1].split():
                    token = token.strip("\"'")
                    if token.startswith("/"):
                        targets.add(os.path.normpath(token))
        return units, targets

    def _strong_claim(self, path: str, units: Sequence[str], targets: set) -> Optional[str]:
        if path in units:
            return "unit:marker"
        head = stat_io.read_head(path)
        for marker in self.markers:
            if marker in head:
                return "marker:" + marker
        absolute = os.path.normpath("/" + os.path.relpath(path, self.root))
        if absolute in targets:
            return "unit:execstart"
        for target in sorted(targets):
            name = os.path.basename(target)
            if name and name in head:
                return "content:" + name
        return None

    def _broad_names(self, targets: set) -> set:
        names = {os.path.basename(t) for t in targets}
        for path in self._scan_files():
            if not path.endswith(".service"):
                continue
            for line in stat_io.read_head(path).splitlines():
                if not line.startswith("ExecStart="):
                    continue
                for token in line.split("=", 1)[1].split():
                    base = os.path.basename(token.strip("'\""))
                    if base:
                        names.add(base)
        return names

    def _broad_claim(self, path: str, names: set) -> Optional[str]:
        """The old rule set: any binary named by any unit's ExecStart= is ours.

        Kept behind --broad because on a busy root it is wrong more often than it
        is right; the measured precision is in docs/limits.md.
        """
        if os.path.basename(path) in names:
            return "basename:execstart"
        head = stat_io.read_head(path)
        for name in sorted(names):
            if name and name in head:
                return "content:" + name
        return None

    def discover(self) -> None:
        units, targets = self._marker_units()
        names = self._broad_names(targets) if self.broad else set()
        for path in self._scan_files():
            reason = self._strong_claim(path, units, targets)
            if reason is None and self.broad:
                reason = self._broad_claim(path, names)
                if reason is not None:
                    reason = "broad:" + reason
            if reason is None:
                self.weak.append(path)
                continue
            self.marker_hits[path] = reason
            self.artifacts.append(path)
        self.artifacts.sort()
        self.weak.sort()

    # -- checks ------------------------------------------------------------
    def _by_dir(self) -> Dict[str, List[str]]:
        groups: Dict[str, List[str]] = {}
        for path in self.artifacts:
            groups.setdefault(os.path.dirname(path), []).append(path)
        return groups

    def checks(self, now_ms: int) -> List[Check]:
        if not self.artifacts:
            return [
                Check(
                    "trace.artifacts",
                    SKIP,
                    "no artifact matched the marker set; nothing to audit",
                )
            ]

        groups = self._by_dir()
        aligned: List[str] = []
        unaligned: List[str] = []
        uncorroborated: List[str] = []
        fresh: List[str] = []
        order_hits: List[str] = []
        ctime_hits: List[str] = []
        evidence: List[Evidence] = []

        for directory, paths in sorted(groups.items()):
            ours = set(paths)
            cap, neighbours = stat_io.dir_cap_ms(directory, ours)
            shown = sanitize(directory, self.root)
            if neighbours == 0:
                uncorroborated.extend(paths)
                evidence.append(Evidence(shown, "neighbours", "0"))
                for path in paths:
                    if (now_ms - stat_io.mtime_ms(path)) // 1000 <= self.fresh_window_s:
                        fresh.append(path)
                continue
            max_ino = 0
            for name in stat_io.listdir_sorted(directory):
                full = os.path.join(directory, name)
                if full in ours:
                    continue
                try:
                    max_ino = max(max_ino, stat_io.ino(full))
                except OSError:
                    continue
            for path in paths:
                value = stat_io.mtime_ms(path)
                if (now_ms - value) // 1000 <= self.fresh_window_s:
                    fresh.append(path)
                if value > cap:
                    unaligned.append(path)
                    evidence.append(
                        Evidence(sanitize(path, self.root), "mtime_ms", str(value))
                    )
                else:
                    aligned.append(path)
                try:
                    if stat_io.ino(path) > max_ino:
                        order_hits.append(path)
                except OSError:
                    pass
                try:
                    if stat_io.ctime_ms(path) > cap:
                        ctime_hits.append(path)
                except OSError:
                    pass
            evidence.append(
                Evidence(shown, "neighbour_cap_ms", str(cap))
            )

        total = len(self.artifacts)
        artefacts_check = Check(
            "trace.artifacts",
            PASS,
            "%d artifact(s) matched the marker set"
            % total
            + (" (+%d weak claim(s) not audited)" % len(self.weak) if self.weak else ""),
            [Evidence(sanitize(p, self.root), "marker", self.marker_hits[p]) for p in self.artifacts],
        )

        if not aligned and not unaligned:
            # every artifact sits alone in its directory: there is nothing to be
            # "no newer than", so a pass here would be an assumption wearing a
            # verdict's clothes
            align_status = SKIP
            align_why = "no artifact has a sibling to compare against; alignment is unmeasurable here"
        elif not unaligned:
            align_status, align_why = PASS, "all %d artifact(s) are no newer than a sibling" % total
        elif aligned:
            align_status = PARTIAL
            align_why = "%d of %d artifact(s) stand out with a mtime newer than every sibling" % (
                len(unaligned),
                total,
            )
        else:
            align_status, align_why = FAIL, "all %d artifact(s) carry a newer mtime than every sibling" % total

        if not uncorroborated:
            corroborated = Check(
                "trace.corroborated",
                PASS,
                "every directory holding an artifact also holds a non-artifact sibling",
            )
        else:
            corroborated = Check(
                "trace.corroborated",
                PARTIAL,
                "%d of %d artifact(s) live where no sibling exists to borrow an mtime from; alignment cannot be shown, only assumed"
                % (len(uncorroborated), total),
                [Evidence(sanitize(p, self.root), "corroborator", "none") for p in uncorroborated],
            )

        if ctime_hits:
            ctime_check = Check(
                "trace.ctime",
                FAIL,
                "%d artifact(s) have a ctime newer than every sibling: mtime can be borrowed, ctime cannot"
                % len(ctime_hits),
                [Evidence(sanitize(p, self.root), "ctime_vs_cap", "newer") for p in ctime_hits],
            )
        else:
            ctime_check = Check(
                "trace.ctime",
                PASS,
                "no artifact has a ctime above every sibling in its directory",
            )

        if fresh:
            fresh_check = Check(
                "trace.fresh",
                FAIL,
                "%d artifact(s) still carry an mtime within %ds of now" % (len(fresh), self.fresh_window_s),
                [Evidence(sanitize(p, self.root), "fresh_window_s", str(self.fresh_window_s)) for p in fresh],
            )
        else:
            fresh_check = Check(
                "trace.fresh",
                PASS,
                "no artifact carries an mtime within %ds of now" % self.fresh_window_s,
            )

        if order_hits:
            order_check = Check(
                "trace.order",
                FAIL,
                "%d artifact(s) have a higher inode than every sibling, so creation order is recoverable" % len(order_hits),
                [Evidence(sanitize(p, self.root), "inode_order", "newest") for p in order_hits],
            )
        else:
            order_check = Check(
                "trace.order",
                PASS,
                "no artifact has an inode above every sibling in its directory",
            )

        self.counts = {
            "aligned": len(aligned),
            "leaks": len(unaligned),
            "uncorroborated": len(uncorroborated),
            "ctime": len(ctime_hits),
            "fresh": len(fresh),
            "order": len(order_hits),
        }
        aligned_check = Check("trace.aligned", align_status, align_why, evidence)

        return [
            artefacts_check,
            aligned_check,
            corroborated,
            ctime_check,
            fresh_check,
            order_check,
        ]

    def facts(self) -> Dict[str, object]:
        facts: Dict[str, object] = {
            "root": self.root,
            "artifacts": len(self.artifacts),
            "weak_claims": len(self.weak),
            "scan": list(self.scan),
        }
        facts.update(self.counts)
        return facts


def run(
    root: str,
    scan: Optional[Sequence[str]] = None,
    markers: Optional[Sequence[str]] = None,
    fresh_window_s: int = 120,
    now_ms: Optional[int] = None,
    broad: bool = False,
) -> Report:
    scanner = Scanner(
        root,
        scan=scan or DEFAULT_SCAN,
        markers=markers or DEFAULT_MARKERS,
        fresh_window_s=fresh_window_s,
        broad=broad,
    )
    scanner.discover()
    if now_ms is None:
        now_ms = int(__import__("time").time() * 1000)
    return Report("trace", scanner.checks(now_ms), scanner.facts())
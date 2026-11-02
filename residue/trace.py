"""Trace: did the artifacts blend in, or do they stand out on ls -lt?

Three questions, deliberately separated:

  artifacts      which files are ours: claims anchored on a marker-bearing unit
  aligned        artifact mtime is not newer than the newest non-ours sibling
  corroborated   the directory actually has such a sibling to borrow from
  ctime          status-change time outruns every sibling (cannot be rewritten)
  order          inode allocation does not preserve creation order
  directory_ctime
                 the holding directory changed after the artifact claims to exist
  readable       every scanned path could actually be read

They are separate because they can disagree. A tree can be aligned and still
uncorroborated (empty directory), which is neither a pass nor a failure. The last
two describe the measurement rather than the tree: a check that could not read
its input must say so instead of returning the verdict of the part it managed to
see.
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

# systemd.service(5) command prefixes: ignore failure, argv[0] only, full
# privileges, and the obsolete '!' variant. A path behind one of these is still
# the path systemd starts.
EXEC_PREFIXES = "-@+!"

# A directory stamp is written by the kernel after the file inside it, so a few
# milliseconds of lag are normal. Days of lag are not.
DIRECTORY_CTIME_SLACK_MS = 2000


def sanitize(path: str, root: str) -> str:
    """Replace the scanned root with a stable token so goldens survive temp dirs."""
    root = os.path.abspath(root)
    full = os.path.abspath(path)
    if full == root:
        return "<root>"
    if full.startswith(root + os.sep):
        return "<root>/" + full[len(root) + 1:]
    return full


def live_lines(text: str):
    """Configuration lines only: a comment cannot configure anything.

    Matching markers against every line claims a stock unit that merely mentions
    the marker in a comment, and a false claim on a clean host is the failure
    this tool promises not to make.
    """
    for line in text.splitlines():
        stripped = line.lstrip()
        if not stripped or stripped[0] in "#;":
            continue
        yield line


def carries_marker(text: str, markers: Sequence[str]) -> bool:
    for line in live_lines(text):
        for marker in markers:
            if marker in line:
                return True
    return False


def exec_start_targets(line: str) -> List[str]:
    """Absolute paths started by one ExecStart= line, in any accepted form.

    systemd.syntax(7) allows whitespace on both sides of the '=' and indented
    directives, and systemd.service(5) prefixes the command with '-', '@' or '+'.
    Reading only a column-0 'ExecStart=' loses units systemd itself runs, and a
    unit we do not follow is a binary we quietly clear.
    """
    stripped = line.lstrip()
    if not stripped.startswith("ExecStart"):
        return []
    body = stripped[len("ExecStart"):].lstrip()
    if not body.startswith("="):
        return []
    out: List[str] = []
    for token in body[1:].split():
        token = token.strip("'\"")
        while token and token[0] in EXEC_PREFIXES:
            token = token[1:]
        if token.startswith("/"):
            out.append(os.path.normpath(token))
    return out


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
        self.errors: List[stat_io.StatError] = []
        self.truncated_files = 0
        self._heads: Dict[str, tuple] = {}
        self._members: List[str] = []
        self._scanned = False

    # -- discovery ---------------------------------------------------------
    def _record(self, err: Optional[stat_io.StatError]) -> None:
        """Keep one report per failed path and operation."""
        if err is not None and err not in self.errors:
            self.errors.append(err)

    def _scan_files(self) -> List[str]:
        """Scan members, listed once: a directory listed twice can change mid-run."""
        if not self._scanned:
            self._scanned = True
            for rel in self.scan:
                paths, errors = stat_io.walk_files(self.root, rel)
                self._members.extend(paths)
                for err in errors:
                    self._record(err)
        return self._members

    def _head(self, path: str) -> tuple:
        """(text, truncated) for one scanned file, read at most once.

        The truncation flag travels with the text because a file longer than the
        read window is not a file without a marker: discover() has to record what
        it did not read instead of clearing the file.
        """
        cached = self._heads.get(path)
        if cached is None:
            text, truncated, err = stat_io.read_head(path)
            self._record(err)
            if truncated:
                self.truncated_files += 1
            cached = (text, truncated)
            self._heads[path] = cached
        return cached

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
            head, truncated = self._head(path)
            if not carries_marker(head, self.markers):
                if truncated:
                    # the marker may sit past the read window: not audited, not
                    # cleared, and not silently excluded from the count
                    self.weak.append(path)
                continue
            units.append(path)
            for line in head.splitlines():
                for target in exec_start_targets(line):
                    targets.add(target)
        return units, targets

    def _strong_claim(self, path: str, units: Sequence[str], targets: set) -> Optional[str]:
        if path in units:
            return "unit:marker"
        head, _ = self._head(path)
        for marker in self.markers:
            if carries_marker(head, (marker,)):
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
            head, _ = self._head(path)
            for line in head.splitlines():
                for target in exec_start_targets(line):
                    base = os.path.basename(target)
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
        head, _ = self._head(path)
        for name in sorted(names):
            if name and name in head:
                return "content:" + name
        return None

    def discover(self) -> None:
        units, targets = self._marker_units()
        names = self._broad_names(targets)
        for path in self._scan_files():
            reason = self._strong_claim(path, units, targets)
            if reason is None:
                _, truncated = self._head(path)
                if truncated:
                    # "not ours" is a claim we did not earn when we stopped
                    # reading before the end of the file
                    self.weak.append(path)
                    continue
                # A file the broad rule would have claimed is a candidate we are
                # deliberately not auditing. Everything else - ordinary system
                # files - is not a claim of any kind and must not be reported as
                # one: a "weak claim" nobody ever made is noise, not caution.
                broad = self._broad_claim(path, names)
                if broad is None:
                    continue
                if not self.broad:
                    self.weak.append(path)
                    continue
                reason = "broad:" + broad
            if os.path.islink(path):
                # a link is how systemd enables a unit: the link is the artifact
                # as much as what it points at, and the reader should see which
                reason = reason + " via=symlink"
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

    def _directory_changed_after(self, directory: str, paths: Sequence[str]) -> Optional[tuple]:
        """(directory ctime, oldest artifact mtime) when the directory is newer.

        Creating a file updates the parent directory's mtime and ctime, and no
        user-space trick avoids that write. A directory whose stamp is newer than
        the oldest artifact it holds was therefore assembled - or added to - after
        that artifact claims to exist. That is a change we can date, not a verdict
        about who made it, so it is reported as partial.
        """
        info, err = stat_io.stat_of(directory)
        if info is None:
            self._record(err)
            return None
        oldest: Optional[int] = None
        for path in paths:
            held, held_err = stat_io.stat_of(path)
            if held is None:
                # Name the path that failed, not the directory that happened to
                # be stat'ed first: an unreadable path must not be reported under
                # a name we could read.
                self._record(held_err)
                return None
            oldest = held.mtime_ms if oldest is None else min(oldest, held.mtime_ms)
        changed = info.ctime_ms
        if changed > oldest + DIRECTORY_CTIME_SLACK_MS:
            return (changed, oldest)
        return None

    def _readable_check(self) -> Check:
        if not self.errors:
            return Check(
                "trace.readable",
                PASS,
                "every scanned path was read; no verdict rests on a skipped path",
            )
        return Check(
            "trace.readable",
            PARTIAL,
            "%d path(s) unreadable; verdict covers the readable subset only"
            % len(self.errors),
            [
                Evidence(
                    sanitize(err.path, self.root),
                    "unreadable",
                    "%s: %s" % (err.op, err.err),
                )
                for err in self.errors
            ],
        )

    def checks(self, now_ms: int) -> List[Check]:
        if not self.artifacts:
            return [
                Check(
                    "trace.artifacts",
                    SKIP,
                    "no artifact matched the marker set; nothing to audit",
                ),
                self._readable_check(),
            ]

        groups = self._by_dir()
        aligned: List[str] = []
        unaligned: List[str] = []
        uncorroborated: List[str] = []
        fresh: List[str] = []
        order_hits: List[str] = []
        ctime_hits: List[str] = []
        directory_hits: List[tuple] = []
        evidence: List[Evidence] = []

        for directory, paths in sorted(groups.items()):
            ours = set(paths)
            cap, cap_ctime, max_ino, neighbours = stat_io.dir_stats(directory, ours, self.errors)
            shown = sanitize(directory, self.root)
            changed = self._directory_changed_after(directory, paths)
            if changed is not None:
                directory_hits.append((directory, changed[0], changed[1]))
            if neighbours == 0:
                uncorroborated.extend(paths)
                evidence.append(Evidence(shown, "neighbours", "0"))
                for path in paths:
                    info, err = stat_io.stat_of(path)
                    if info is None:
                        self._record(err)
                        continue
                    if (now_ms - info.mtime_ms) // 1000 <= self.fresh_window_s:
                        fresh.append(path)
                continue
            for path in paths:
                info, err = stat_io.stat_of(path)
                if info is None:
                    self._record(err)
                    continue
                if (now_ms - info.mtime_ms) // 1000 <= self.fresh_window_s:
                    fresh.append(path)
                if info.mtime_ms > cap:
                    unaligned.append(path)
                    evidence.append(
                        Evidence(sanitize(path, self.root), "mtime_ms", str(info.mtime_ms))
                    )
                else:
                    aligned.append(path)
                if info.ino > max_ino:
                    order_hits.append(path)
                if info.ctime_ms > cap_ctime:
                    ctime_hits.append(path)
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

        if directory_hits:
            directory_check = Check(
                "trace.directory_ctime",
                PARTIAL,
                "%d holding director(y/ies) changed after the artifacts they hold: a directory mtime/ctime is the usual hiding place, and it dates the assembly, not the intent"
                % len(directory_hits),
                [
                    Evidence(
                        sanitize(directory, self.root),
                        "dir_ctime_vs_oldest_mtime",
                        "%d > %d" % (changed, oldest),
                    )
                    for directory, changed, oldest in directory_hits
                ],
            )
        else:
            directory_check = Check(
                "trace.directory_ctime",
                PASS,
                "no holding directory carries a ctime above the artifacts it holds",
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
            directory_check,
            fresh_check,
            order_check,
            self._readable_check(),
        ]

    def facts(self) -> Dict[str, object]:
        facts: Dict[str, object] = {
            "root": self.root,
            "artifacts": len(self.artifacts),
            "weak_claims": len(self.weak),
            "truncated_files": self.truncated_files,
            "scan": list(self.scan),
        }
        facts.update(self.counts)
        facts["errors"] = [err.to_dict() for err in self.errors]
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

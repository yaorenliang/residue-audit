import json
import os
import shutil
import tempfile
import time
import unittest

from residue import stat_io, trace
from residue.model import FAIL, PARTIAL, PASS, SKIP
from tests import fixtures as fx

GOLDEN_DIR = os.path.join(os.path.dirname(__file__), "golden")


def mask(report_dict):
    """Drop the two facts that cannot be reproduced on another filesystem."""
    out = json.loads(json.dumps(report_dict))
    out["facts"]["root"] = "<root>"
    for check in out["checks"]:
        if check["name"] == "trace.order":
            # inode allocation is filesystem-specific: assert the claim, not the numbers
            check["evidence"] = []
        if check["name"] == "trace.directory_ctime":
            # the directory's own stamp is wall-clock time: a golden that pinned it
            # would fail on the next run, so the claim is kept and the numbers are not
            for item in check["evidence"]:
                item["value"] = "<dir_ctime> > <artifact_mtime>"
    return out


class TraceGolden(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="residue-trace-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_clean_tree_matches_golden(self):
        root = os.path.join(self.tmp, "clean")
        os.makedirs(root)
        fx.plant(root, neighbours=True, align=True)
        report = trace.run(root, now_ms=fx.LATER_MS)
        got = mask(report.to_dict())
        path = os.path.join(GOLDEN_DIR, "trace_clean.json")
        if os.environ.get("UPDATE_GOLDEN"):
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(got, fh, indent=2, sort_keys=True)
                fh.write("\n")
        with open(path, "r", encoding="utf-8") as fh:
            want = json.load(fh)
        self.assertEqual(got, want)


class TraceNegativeControls(unittest.TestCase):
    """Each check needs an input on which it must not pass."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="residue-trace-neg-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def _status(self, root, now_ms=None, **kwargs):
        report = trace.run(root, now_ms=now_ms, **kwargs)
        return {c.name: c.status for c in report.checks}, report

    def test_fresh_tree_fails_freshness(self):
        root = os.path.join(self.tmp, "fresh")
        os.makedirs(root)
        fx.plant(root, align=False)
        status, _ = self._status(root, now_ms=fx.OLD_MS + 1000)
        self.assertEqual(status["trace.fresh"], FAIL)

    def test_one_touched_artifact_degrades_alignment(self):
        root = os.path.join(self.tmp, "touched")
        os.makedirs(root)
        written = fx.plant(root)
        path = os.path.join(root, "usr/libexec/kworker")
        from residue import stat_io

        stat_io.set_mtime_ms(path, fx.LATER_MS + 1000)
        status, report = self._status(root, now_ms=fx.LATER_MS)
        self.assertEqual(status["trace.aligned"], PARTIAL)
        self.assertEqual(report.facts["leaks"], 1)
        self.assertEqual(report.facts["aligned"], len(written) - 1)

    def test_no_sibling_means_alignment_is_unmeasurable(self):
        root = os.path.join(self.tmp, "lonely")
        os.makedirs(root)
        fx.plant(root, neighbours=False, align=False)
        status, report = self._status(root, now_ms=fx.LATER_MS)
        self.assertEqual(status["trace.corroborated"], PARTIAL)
        self.assertEqual(status["trace.aligned"], SKIP)
        self.assertEqual(report.facts["uncorroborated"], report.facts["artifacts"])

    def test_stock_service_is_not_claimed_as_an_artifact(self):
        """A unit naming /usr/libexec/x is not evidence: stock roots are full of them."""
        root = os.path.join(self.tmp, "stock")
        os.makedirs(root)
        unit = os.path.join(root, "etc/systemd/system/packagekit.service")
        os.makedirs(os.path.dirname(unit))
        with open(unit, "w", encoding="utf-8") as fh:
            fh.write("[Service]\nExecStart=/usr/libexec/packagekitd\n")
        binary = os.path.join(root, "usr/libexec/packagekitd")
        os.makedirs(os.path.dirname(binary))
        with open(binary, "w", encoding="utf-8") as fh:
            fh.write("ELF stock\n")

        status, report = self._status(root, now_ms=fx.LATER_MS)
        self.assertEqual(status["trace.artifacts"], SKIP)
        self.assertEqual(report.facts["artifacts"], 0)
        self.assertEqual(report.facts["weak_claims"], 2)

        # --broad restores the old rule, and with it the false positives: both
        # the binary and the unit that merely names it get claimed
        status, report = self._status(root, now_ms=fx.LATER_MS, broad=True)
        self.assertEqual(report.facts["artifacts"], 2)

    def test_empty_root_skips_without_pretending(self):
        root = os.path.join(self.tmp, "empty")
        os.makedirs(root)
        status, report = self._status(root, now_ms=fx.LATER_MS)
        self.assertEqual(status["trace.artifacts"], SKIP)
        self.assertEqual(report.status(), SKIP)


class TraceADomainControls(unittest.TestCase):
    """Each A-class finding gets the input on which the old code was wrong."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="residue-trace-a-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def _status(self, root, now_ms=None, **kwargs):
        report = trace.run(root, now_ms=now_ms, **kwargs)
        return {c.name: c.status for c in report.checks}, report

    def _write(self, root, rel, body):
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)
        return path

    # -- F-02: a path we could not read is not a path that is not there -----
    def test_f02_an_unreadable_scan_directory_is_reported(self):
        root = os.path.join(self.tmp, "locked")
        os.makedirs(root)
        fx.plant(root)
        locked = os.path.join(root, "etc/cron.d")
        os.chmod(locked, 0o000)
        self.addCleanup(os.chmod, locked, 0o755)

        status, report = self._status(root, now_ms=fx.LATER_MS)
        self.assertEqual(status["trace.readable"], PARTIAL)
        self.assertNotEqual(status["trace.artifacts"], SKIP)
        self.assertEqual([e["op"] for e in report.facts["errors"]], ["listdir"])
        self.assertEqual(report.facts["artifacts"], 4)

    def test_f02_an_unreadable_file_is_reported(self):
        root = os.path.join(self.tmp, "locked-file")
        os.makedirs(root)
        fx.plant(root)
        secret = os.path.join(root, "usr/libexec/kworker")
        os.chmod(secret, 0o000)
        self.addCleanup(os.chmod, secret, 0o755)

        status, report = self._status(root, now_ms=fx.LATER_MS)
        self.assertEqual(status["trace.readable"], PARTIAL)
        self.assertEqual([e["op"] for e in report.facts["errors"]], ["read"])

    def test_f02_a_fully_readable_tree_says_so(self):
        root = os.path.join(self.tmp, "readable")
        os.makedirs(root)
        fx.plant(root)
        status, report = self._status(root, now_ms=fx.LATER_MS)
        self.assertEqual(status["trace.readable"], PASS)
        self.assertEqual(report.facts["errors"], [])

    # -- F-03: a directory entry is not a sibling --------------------------
    def test_f03_a_subdirectory_does_not_lend_a_timestamp(self):
        root = os.path.join(self.tmp, "nested")
        os.makedirs(root)
        written = fx.plant(root, align=False)
        for path in written:
            stat_io.set_mtime_ms(path, fx.LATER_MS)
        before, report_before = self._status(root, now_ms=fx.LATER_MS)
        self.assertEqual(report_before.facts["leaks"], len(written))

        nested = os.path.join(root, "etc/systemd/system/multi-user.target.wants")
        os.makedirs(nested)
        stamp = (fx.LATER_MS + 9000) * stat_io.MS
        os.utime(nested, ns=(stamp, stamp))

        after, report_after = self._status(root, now_ms=fx.LATER_MS)
        self.assertEqual(report_after.facts["leaks"], len(written))
        self.assertEqual(after["trace.aligned"], before["trace.aligned"])

    def test_f03_ctime_is_compared_against_a_ctime_cap(self):
        root = os.path.join(self.tmp, "ctime-cap")
        target = self._write(root, "usr/libexec/kworker", "KillSignal=SIGCONT\n")
        stat_io.set_mtime_ms(target, fx.OLD_MS)
        time.sleep(0.05)
        sibling = self._write(root, "usr/libexec/zzz-neighbour", "unrelated\n")
        stat_io.set_mtime_ms(sibling, fx.OLD_MS)

        status, _ = self._status(root, now_ms=fx.LATER_MS)
        self.assertLess(stat_io.ctime_ms(target), stat_io.ctime_ms(sibling))
        self.assertEqual(status["trace.ctime"], PASS)

    # -- F-04: the holding directory's own stamp ---------------------------
    def test_f04_a_directory_that_changed_after_its_artifacts_is_reported(self):
        root = os.path.join(self.tmp, "holding")
        target = self._write(
            root,
            "etc/cron.d/zzz-updater",
            "*/5 * * * * root /usr/libexec/kworker\nKillSignal=SIGCONT\n",
        )
        stat_io.set_mtime_ms(target, fx.OLD_MS)
        sibling = self._write(root, "etc/cron.d/zzz-neighbour", "unrelated\n")
        later = fx.OLD_MS + 3_600_000
        stat_io.set_mtime_ms(sibling, later)

        status, report = self._status(root, now_ms=later)
        self.assertEqual(status["trace.aligned"], PASS)
        self.assertEqual(status["trace.directory_ctime"], PARTIAL)
        self.assertEqual(report.status(), PARTIAL)

    # -- F-21: a comment cannot configure anything -------------------------
    def test_f21_a_marker_in_a_comment_claims_nothing(self):
        root = os.path.join(self.tmp, "stock-nginx")
        self._write(
            root,
            "etc/systemd/system/nginx.service",
            "# KillSignal=SIGCONT would keep the daemon quiet\n"
            "[Service]\nExecStart=/usr/sbin/nginx -g 'daemon on;'\n",
        )
        status, report = self._status(root, now_ms=fx.LATER_MS)
        self.assertEqual(report.facts["artifacts"], 0)
        self.assertEqual(status["trace.artifacts"], SKIP)

    # -- F-22: every accepted ExecStart= spelling --------------------------
    def test_f22_every_exec_start_spelling_names_its_binary(self):
        root = os.path.join(self.tmp, "forms")
        self._write(
            root,
            "etc/systemd/system/zz-forms.service",
            "[Service]\nKillSignal=SIGCONT\n"
            "ExecStart = /usr/local/bin/space-eq\n"
            "\tExecStart=/usr/local/bin/indented\n"
            "ExecStart=-/usr/local/bin/dashed\n",
        )
        for name in ("space-eq", "indented", "dashed"):
            self._write(root, "usr/local/bin/" + name, "ELF\n")

        scanner = trace.Scanner(root)
        scanner.discover()
        claimed = set(os.path.basename(p) for p in scanner.artifacts + scanner.weak)
        # the unit itself carries the marker; the three binaries are the point
        self.assertTrue({"space-eq", "indented", "dashed"} <= claimed)
        self.assertIn("zz-forms.service", claimed)

    # -- F-23: the read window and what lies past it -----------------------
    def test_f23_a_marker_past_the_old_window_is_still_found(self):
        root = os.path.join(self.tmp, "deep-marker")
        self._write(root, "usr/libexec/kworker", "A" * 20000 + "\nKillSignal=SIGCONT\n")
        _, report = self._status(root, now_ms=fx.LATER_MS)
        self.assertEqual(report.facts["artifacts"], 1)
        self.assertEqual(report.facts["truncated_files"], 0)

    def test_f23_a_file_longer_than_the_window_is_not_cleared(self):
        root = os.path.join(self.tmp, "truncated")
        self._write(root, "usr/libexec/kworker", "A" * 70000 + "\nKillSignal=SIGCONT\n")
        status, report = self._status(root, now_ms=fx.LATER_MS)
        self.assertEqual(report.facts["artifacts"], 0)
        self.assertEqual(report.facts["weak_claims"], 1)
        self.assertEqual(report.facts["truncated_files"], 1)
        self.assertEqual(status["trace.readable"], PASS)

    # -- F-05: a symlink is how systemd enables a unit ---------------------
    def test_f05_a_symlink_to_a_marked_file_is_claimed_and_marked(self):
        root = os.path.join(self.tmp, "alias")
        target = self._write(root, "usr/libexec/kworker", "KillSignal=SIGCONT\n")
        link = os.path.join(root, "etc/cron.d/zzz-alias")
        os.makedirs(os.path.dirname(link))
        os.symlink(target, link)

        scanner = trace.Scanner(root)
        scanner.discover()
        self.assertIn(link, scanner.artifacts)
        self.assertTrue(scanner.marker_hits[link].endswith("via=symlink"))

    def test_f05_a_symlinked_unit_carries_the_marker_too(self):
        root = os.path.join(self.tmp, "alias-unit")
        unit = self._write(
            root,
            "etc/systemd/system/zz-real.service",
            "[Service]\nKillSignal=SIGCONT\nExecStart=/usr/local/bin/real-client\n",
        )
        binary = self._write(root, "usr/local/bin/real-client", "ELF\n")
        link = os.path.join(root, "etc/cron.d/zzz-enabled.service")
        os.makedirs(os.path.dirname(link))
        os.symlink(unit, link)

        scanner = trace.Scanner(root)
        scanner.discover()
        self.assertEqual(
            sorted(os.path.basename(p) for p in scanner.artifacts),
            ["real-client", "zz-real.service", "zzz-enabled.service"],
        )
        self.assertEqual(scanner.marker_hits[binary], "unit:execstart")


if __name__ == "__main__":
    unittest.main()
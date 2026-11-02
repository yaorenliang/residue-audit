import json
import os
import shutil
import tempfile
import unittest

from residue import trace
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


if __name__ == "__main__":
    unittest.main()
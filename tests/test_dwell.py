import os
import shutil
import tempfile
import unittest

from residue import dwell
from residue.model import PARTIAL, PASS, SKIP
from tests import fixtures as fx


class DwellTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="residue-dwell-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.ledger = os.path.join(self.tmp, "ledger.ndjson")
        fx.write_ledger(self.ledger, fx.LEDGER)

    def test_span_and_counts(self):
        report = dwell.run(self.ledger)
        self.assertEqual(report.facts["hosts"], 4)
        self.assertEqual(report.facts["not_deployed"], 1)
        self.assertEqual(report.facts["deployed"], 3)
        self.assertEqual(report.facts["mined"], 2)
        self.assertEqual(report.facts["failed"], 1)
        span = [c for c in report.checks if c.name == "dwell.span"][0]
        self.assertEqual(span.status, PASS)
        self.assertIn("min=60", span.why)
        self.assertIn("max=205", span.why)

    def test_half_the_hosts_is_not_coverage(self):
        hits = os.path.join(self.tmp, "hits.json")
        fx.write_json(hits, fx.HITS)
        four = os.path.join(self.tmp, "four.ndjson")
        fx.write_ledger(four, fx.LEDGER_FOUR)
        report = dwell.run(four, hits)
        coverage = [c for c in report.checks if c.name == "dwell.coverage"][0]
        self.assertEqual(coverage.status, PARTIAL)
        self.assertEqual(report.facts["hit_rate"], 50.0)
        self.assertEqual(report.facts["verdict"], "partial-coverage")
        self.assertEqual(report.exit_code(), 1)

    def test_majority_is_coverage(self):
        hits = os.path.join(self.tmp, "hits.json")
        fx.write_json(
            hits,
            fx.HITS + [{"ts": 1015, "host": "h2", "rule": "sigma:beacon"}],
        )
        report = dwell.run(self.ledger, hits)
        coverage = [c for c in report.checks if c.name == "dwell.coverage"][0]
        self.assertEqual(coverage.status, PASS)
        self.assertEqual(report.facts["verdict"], "covered")

    def test_missing_hits_is_unknown_not_zero(self):
        report = dwell.run(self.ledger, None)
        coverage = [c for c in report.checks if c.name == "dwell.coverage"][0]
        self.assertEqual(coverage.status, SKIP)
        self.assertIn("unknown, not zero", coverage.why)
        self.assertEqual(report.facts["verdict"], "unknown")

    def test_empty_ledger_skips(self):
        empty = os.path.join(self.tmp, "empty.ndjson")
        open(empty, "w").close()
        report = dwell.run(empty)
        self.assertEqual(report.status(), SKIP)
        self.assertEqual(len(report.checks), 1)


if __name__ == "__main__":
    unittest.main()
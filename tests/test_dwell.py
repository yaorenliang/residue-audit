import json
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
        # spans start at each host's deploy now, so h2 ends at 1215 - 1012 = 203;
        # anchoring on h2's first event (1010) used to print 205
        self.assertIn("max=203", span.why)

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



def _write_ledger(path, events):
    with open(path, "w", encoding="utf-8") as fh:
        for event in events:
            fh.write(json.dumps(event) + "\n")
    return path


def _write_hits(path, items):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"hits": items}, fh)
    return path


def _named(report, name):
    for check in report.checks:
        if check.name == name:
            return check
    raise AssertionError(
        "report has no check named %r; it has %r"
        % (name, [c.name for c in report.checks])
    )


class DwellCaliberTest(unittest.TestCase):
    """Regression tests for the caliber defects F-05..F-09 and F-24.

    Every fixture is built inline so this file does not depend on the shared
    fixture module for the cases that decide a verdict.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="residue-dwell-caliber-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def _ledger(self, name, events):
        return _write_ledger(os.path.join(self.tmp, name), events)

    def _hits(self, name, items):
        return _write_hits(os.path.join(self.tmp, name), items)

    def _spans(self, name, spans):
        """One host per span: deploy at 1000, last event at 1000 + span."""
        events = []
        for index, span in enumerate(spans):
            host = "h%d" % index
            events.append({"ts": 1000, "host": host, "event": "deploy"})
            events.append({"ts": 1000 + span, "host": host, "event": "mine", "ok": True})
        return self._ledger(name, events)

    def test_f05_pre_deploy_hits_do_not_count_as_coverage(self):
        ledger = self._ledger(
            "pre.ndjson",
            [
                {"ts": 1000, "host": "h1", "event": "deploy"},
                {"ts": 1180, "host": "h1", "event": "mine", "ok": True},
                {"ts": 1000, "host": "h2", "event": "deploy"},
                {"ts": 1200, "host": "h2", "event": "mine", "ok": True},
            ],
        )
        hits = self._hits(
            "pre.json",
            [
                {"ts": 500, "host": "h1", "rule": "noise:pre-h1"},
                {"ts": 500, "host": "h2", "rule": "noise:pre-h2"},
            ],
        )
        report = dwell.run(ledger, hits)
        coverage = _named(report, "dwell.coverage")
        self.assertEqual(coverage.status, PARTIAL)
        self.assertEqual(report.facts["hit_rate"], 0.0)
        self.assertEqual(report.facts["hits_pre_deploy"], 2)
        self.assertEqual(report.facts["hits_post_deploy"], 0)
        self.assertEqual(report.facts["hosts_without_hits"], 2)
        self.assertEqual(report.facts["verdict"], "partial-coverage")
        self.assertEqual(report.exit_code(), 1)

    def test_f05_a_hit_at_the_deploy_timestamp_is_covered(self):
        ledger = self._ledger(
            "boundary.ndjson",
            [
                {"ts": 1000, "host": "h1", "event": "deploy"},
                {"ts": 1180, "host": "h1", "event": "mine", "ok": True},
                {"ts": 1000, "host": "h2", "event": "deploy"},
                {"ts": 1200, "host": "h2", "event": "mine", "ok": True},
            ],
        )
        hits = self._hits(
            "boundary.json",
            [
                {"ts": 1000, "host": "h1", "rule": "yara:at-deploy"},
                {"ts": 1001, "host": "h2", "rule": "yara:just-after"},
            ],
        )
        report = dwell.run(ledger, hits)
        coverage = _named(report, "dwell.coverage")
        self.assertEqual(coverage.status, PASS)
        self.assertEqual(report.facts["hit_rate"], 100.0)
        self.assertEqual(report.facts["hits_pre_deploy"], 0)
        self.assertEqual(report.facts["hits_post_deploy"], 2)

    def test_f05_a_pre_hit_does_not_cancel_that_hosts_post_hit(self):
        ledger = self._ledger(
            "both.ndjson",
            [
                {"ts": 1000, "host": "h1", "event": "deploy"},
                {"ts": 1180, "host": "h1", "event": "mine", "ok": True},
                {"ts": 1000, "host": "h2", "event": "deploy"},
                {"ts": 1200, "host": "h2", "event": "mine", "ok": True},
            ],
        )
        hits = self._hits(
            "both.json",
            [
                {"ts": 500, "host": "h1", "rule": "noise:pre"},
                {"ts": 1100, "host": "h1", "rule": "yara:real"},
            ],
        )
        report = dwell.run(ledger, hits)
        coverage = _named(report, "dwell.coverage")
        self.assertEqual(coverage.status, PARTIAL)
        self.assertEqual(report.facts["hit_rate"], 50.0)
        self.assertEqual(report.facts["hits_pre_deploy"], 1)
        self.assertEqual(report.facts["hits_post_deploy"], 1)

    def test_f06_span_starts_at_deploy_whatever_the_line_order(self):
        unsorted_ledger = self._ledger(
            "span.ndjson",
            [
                {"ts": 1100, "host": "h1", "event": "mine", "ok": True},
                {"ts": 1000, "host": "h1", "event": "deploy"},
                {"ts": 1180, "host": "h1", "event": "mine", "ok": True},
            ],
        )
        sorted_ledger = self._ledger(
            "span_sorted.ndjson",
            [
                {"ts": 1000, "host": "h1", "event": "deploy"},
                {"ts": 1100, "host": "h1", "event": "mine", "ok": True},
                {"ts": 1180, "host": "h1", "event": "mine", "ok": True},
            ],
        )
        unsorted_span = _named(dwell.run(unsorted_ledger), "dwell.span")
        sorted_span = _named(dwell.run(sorted_ledger), "dwell.span")
        self.assertEqual(unsorted_span.status, PASS)
        self.assertIn("min=180", unsorted_span.why)
        self.assertIn("max=180", unsorted_span.why)
        self.assertEqual(unsorted_span.why, sorted_span.why)

    def test_f06_span_survives_the_latest_event_on_the_first_line(self):
        ledger = self._ledger(
            "late_first.ndjson",
            [
                {"ts": 1180, "host": "h1", "event": "mine", "ok": True},
                {"ts": 1000, "host": "h1", "event": "deploy"},
            ],
        )
        span = _named(dwell.run(ledger), "dwell.span")
        self.assertEqual(span.status, PASS)
        self.assertIn("max=180", span.why)

    def test_f07_unrecognized_event_kind_is_reported_not_folded(self):
        ledger = self._ledger(
            "mixed.ndjson",
            [
                {"ts": 1000, "host": "h1", "event": "deploy"},
                {"ts": 1000, "host": "h2", "event": "Deployed"},
                {"ts": 1000, "host": "h3", "event": "Deployed"},
                {"ts": 1000, "host": "h4", "phase": "bogus"},
            ],
        )
        hits = self._hits(
            "mixed.json", [{"ts": 1100, "host": "h1", "rule": "yara:h1"}]
        )
        report = dwell.run(ledger, hits)
        schema = _named(report, "dwell.schema")
        self.assertEqual(schema.status, PARTIAL)
        self.assertIn("3 event(s) have unrecognized kind", schema.why)
        self.assertIn("denominator may be wrong", schema.why)
        self.assertEqual(report.facts["unknown_events"], ["Deployed", "bogus"])
        self.assertEqual(report.status(), PARTIAL)
        self.assertEqual(report.exit_code(), 1)

    def test_f07_known_kinds_leave_the_schema_check_passing(self):
        ledger = self._ledger(
            "clean_kinds.ndjson",
            [
                {"ts": 1000, "host": "h1", "event": "scan"},
                {"ts": 1005, "host": "h1", "event": "deploy"},
                {"ts": 1180, "host": "h1", "event": "mine", "ok": True},
                {"ts": 1010, "host": "h2", "phase": "scan"},
            ],
        )
        report = dwell.run(ledger)
        schema = _named(report, "dwell.schema")
        self.assertEqual(schema.status, PASS)
        self.assertEqual(report.facts["unknown_events"], [])

    def test_f08_hits_outside_the_ledger_are_named_not_counted_as_rules(self):
        ledger = self._ledger(
            "two.ndjson",
            [
                {"ts": 1000, "host": "h1", "event": "deploy"},
                {"ts": 1180, "host": "h1", "event": "mine", "ok": True},
                {"ts": 1000, "host": "h2", "event": "deploy"},
                {"ts": 1200, "host": "h2", "event": "mine", "ok": True},
            ],
        )
        hits = self._hits(
            "outside.json",
            [
                {"ts": 1100, "host": "h9", "rule": "falco:y"},
                {"ts": 1100, "host": "h10", "rule": "yara:x"},
            ],
        )
        report = dwell.run(ledger, hits)
        coverage = _named(report, "dwell.coverage")
        self.assertEqual(report.facts["hits_unmatched"], ["h10", "h9"])
        self.assertEqual(report.facts["hit_rate"], 0.0)
        listed = [item.field for item in coverage.evidence]
        self.assertNotIn("falco:y", listed)
        self.assertNotIn("yara:x", listed)

    def test_f08_matched_rules_still_show_their_counts(self):
        ledger = self._ledger(
            "matched.ndjson",
            [
                {"ts": 1000, "host": "h1", "event": "deploy"},
                {"ts": 1180, "host": "h1", "event": "mine", "ok": True},
                {"ts": 1000, "host": "h2", "event": "deploy"},
                {"ts": 1200, "host": "h2", "event": "mine", "ok": True},
            ],
        )
        hits = self._hits(
            "matched.json",
            [
                {"ts": 1100, "host": "h1", "rule": "yara:real"},
                {"ts": 1100, "host": "h9", "rule": "falco:elsewhere"},
            ],
        )
        report = dwell.run(ledger, hits)
        coverage = _named(report, "dwell.coverage")
        self.assertEqual(coverage.status, PARTIAL)
        self.assertEqual([item.field for item in coverage.evidence], ["yara:real"])
        self.assertEqual(report.facts["hits_unmatched"], ["h9"])

    def test_f09_median_is_the_true_median(self):
        ledger = self._spans("even.ndjson", [60, 70, 180, 205])
        span = _named(dwell.run(ledger), "dwell.span")
        # an upper median would print 180 here; the two middle values are 70 and 180
        self.assertIn("median=125", span.why)
        self.assertIn("min=60", span.why)
        self.assertIn("max=205", span.why)

    def test_f09_median_of_an_odd_count_is_the_middle_value(self):
        ledger = self._spans("odd.ndjson", [60, 70, 180])
        span = _named(dwell.run(ledger), "dwell.span")
        self.assertIn("median=70", span.why)

    def test_f09_p90_uses_nearest_rank(self):
        ledger = self._spans("seven.ndjson", [10, 20, 30, 40, 50, 60, 70])
        span = _named(dwell.run(ledger), "dwell.span")
        # nearest-rank over 7 values is the 7th (ceil(0.9 * 7) = 7), not the 6th
        self.assertIn("p90=70", span.why)

    def test_f24_denominator_is_the_hosts_that_reached_deploy(self):
        ledger = self._ledger(
            "demo.ndjson",
            [
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
            ],
        )
        hits = self._hits(
            "demo_hits.json",
            [
                {"ts": 1090, "host": "h1", "rule": "yara:generic-miner"},
                {"ts": 1150, "host": "h3", "rule": "falco:systemd-drop"},
            ],
        )
        report = dwell.run(ledger, hits)
        coverage = _named(report, "dwell.coverage")
        self.assertEqual(report.facts["deployed"], 4)
        self.assertEqual(report.facts["not_deployed"], 1)
        self.assertEqual(report.facts["hosts_not_deployed"], ["h5"])
        self.assertEqual(report.facts["hit_rate"], 50.0)
        self.assertEqual(report.facts["hit_rate_all_hosts"], 40.0)
        self.assertIn("2 of 4 host(s) hit (50.0%)", coverage.why)

    def test_f24_the_module_states_one_denominator_only(self):
        self.assertIn("reached deploy", dwell.__doc__)
        self.assertNotIn("every host in the ledger", dwell.__doc__)


    def test_a_ledger_that_never_deployed_still_reports_every_fact(self):
        ledger = self._ledger(
            "nodeploy.ndjson",
            [
                {"ts": 1000, "host": "h1", "event": "scan"},
                {"ts": 1010, "host": "h1", "event": "mine", "ok": True},
                {"ts": 1020, "host": "h2", "event": "scan"},
            ],
        )
        hits = self._hits("nodeploy_hits.json", [{"ts": 1005, "host": "h1", "rule": "r"}])
        report = dwell.run(ledger, hits)
        covered = dwell.run(self._spans("covered.ndjson", [10]), hits)
        coverage = _named(report, "dwell.coverage")
        self.assertEqual(coverage.status, SKIP)
        self.assertIn("no host reached deploy", coverage.why)
        self.assertEqual(report.facts["verdict"], "no-deployment")
        self.assertIsNone(report.facts["hit_rate"])
        self.assertIsNone(report.facts["hosts_without_hits"])
        self.assertEqual(report.facts["hosts_not_deployed"], ["h1", "h2"])
        self.assertEqual(report.facts["hits_unmatched"], ["h1"])
        # one exit for every ledger: the undefined case used to build its own fact
        # dict, so a key added to the defined case silently went missing here
        self.assertEqual(sorted(report.facts), sorted(covered.facts))


if __name__ == "__main__":
    unittest.main()

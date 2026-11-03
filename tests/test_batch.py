import inspect
import os
import shutil
import tempfile
import unittest
from unittest import mock

from residue import batch
from residue.model import FAIL, PARTIAL, PASS, SKIP


class BatchTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="residue-batch-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def _pair(self, left, right, name_a="a", name_b="b"):
        from tests import fixtures as fx

        pa = os.path.join(self.tmp, name_a + ".json")
        pb = os.path.join(self.tmp, name_b + ".json")
        fx.write_json(pa, {"name": name_a, "features": left})
        fx.write_json(pb, {"name": name_b, "features": right})
        return batch.run([pa, pb])

    def test_identical_feature_sets_cluster(self):
        feats = ["f%d" % i for i in range(50)]
        report = self._pair(feats, feats)
        self.assertEqual(report.status(), FAIL)

    def test_one_feature_apart_still_clusters(self):
        feats = ["f%d" % i for i in range(100)]
        other = feats[:-1] + ["f999"]
        report = self._pair(feats, other)
        self.assertEqual(report.status(), FAIL)
        self.assertGreater(report.facts["min_similarity"], 0.98)

    def test_narrow_margin_is_partial(self):
        # 197 shared out of 203 union is 0.9704: under the threshold, but the
        # margin is small enough that another build could flip it
        feats = ["f%d" % i for i in range(200)]
        other = feats[3:] + ["g1", "g2", "g3"]
        report = self._pair(feats, other)
        self.assertEqual(report.status(), PARTIAL)
        self.assertAlmostEqual(report.facts["min_similarity"], 0.9704, places=4)

    def test_disjoint_sets_are_distinct(self):
        report = self._pair(["f%d" % i for i in range(20)], ["g%d" % i for i in range(20)])
        self.assertEqual(report.status(), PASS)

    def test_single_build_has_nothing_to_compare(self):
        from tests import fixtures as fx

        path = os.path.join(self.tmp, "only.json")
        fx.write_json(path, {"name": "only", "features": ["a"]})
        report = batch.run([path])
        self.assertEqual(report.status(), SKIP)
        self.assertEqual(report.facts["pairs"], 0)



class BatchUndefinedSimilarityTest(unittest.TestCase):
    """F-10: an empty feature set is missing evidence, not sameness."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="residue-batch-empty-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def _write(self, name, features):
        from tests import fixtures as fx

        path = os.path.join(self.tmp, name + ".json")
        fx.write_json(path, {"name": name, "features": features})
        return path

    def _check(self, report):
        for check in report.checks:
            if check.name.startswith("batch."):
                return check
        raise AssertionError("no batch check in %r" % ([c.name for c in report.checks],))

    def test_f10_two_empty_feature_sets_are_undefined(self):
        report = batch.run(
            [self._write("build-a", []), self._write("build-b", [])]
        )
        check = self._check(report)
        self.assertEqual(check.status, SKIP)
        self.assertIn("both feature sets are empty", check.why)
        self.assertEqual(report.status(), SKIP)
        self.assertEqual(report.exit_code(), 3)
        self.assertIsNone(report.facts["min_similarity"])

    def test_f10_jaccard_of_two_empty_sets_is_none(self):
        self.assertIsNone(batch.jaccard(set(), set()))
        self.assertEqual(batch.jaccard(set(), {"a"}), 0.0)
        self.assertEqual(batch.jaccard({"a"}, {"a"}), 1.0)

    def test_f10_an_empty_pair_does_not_hide_a_real_pair(self):
        report = batch.run(
            [
                self._write("build-a", []),
                self._write("build-b", []),
                self._write("build-c", ["f%d" % i for i in range(50)]),
                self._write("build-d", ["g%d" % i for i in range(50)]),
            ]
        )
        statuses = {check.name: check.status for check in report.checks}
        self.assertEqual(statuses["batch.build-a_vs_build-b"], SKIP)
        self.assertEqual(statuses["batch.build-c_vs_build-d"], PASS)
        self.assertEqual(report.facts["pairs"], 6)
        # the undefined pair is ignored, so the minimum is the real 0.0
        self.assertEqual(report.facts["min_similarity"], 0.0)



class BatchSinglePassTest(unittest.TestCase):
    """The summary and the checks read the same pass over the pairs."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="residue-batch-pass-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def _write(self, name, features):
        from tests import fixtures as fx

        path = os.path.join(self.tmp, name + ".json")
        fx.write_json(path, {"name": name, "features": features})
        return path

    def test_every_pair_is_scored_once(self):
        paths = [self._write("b%d" % i, ["f%d" % i]) for i in range(4)]
        with mock.patch.object(batch, "jaccard", wraps=batch.jaccard) as scored:
            report = batch.run(paths)
        # four builds make six pairs; the summary used to walk all six a second
        # time to find its minimum
        self.assertEqual(scored.call_count, 6)
        self.assertEqual(report.facts["pairs"], 6)

    def test_run_states_no_band_of_its_own(self):
        source = inspect.getsource(batch.run)
        for word in ("SKIP", "FAIL", "PARTIAL", "0.98"):
            self.assertNotIn(word, source)

    def test_the_bands_are_the_four_answers(self):
        self.assertEqual(batch._verdict(None, 0.98)[0], SKIP)
        self.assertEqual(batch._verdict(0.98, 0.98)[0], FAIL)
        self.assertEqual(batch._verdict(0.97, 0.98)[0], PARTIAL)
        self.assertEqual(batch._verdict(0.95, 0.98)[0], PASS)


if __name__ == "__main__":
    unittest.main()
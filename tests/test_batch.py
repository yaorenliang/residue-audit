import os
import shutil
import tempfile
import unittest

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


if __name__ == "__main__":
    unittest.main()
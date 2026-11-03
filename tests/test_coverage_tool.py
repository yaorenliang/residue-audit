"""The coverage gate's own arithmetic, without running the suite.

tests/coverage.py has two floors and used to enforce one number: the total. The
second floor is the one that catches a deleted test file, so its arithmetic is
pinned here directly instead of only through a probe that copies the repository.
"""

import json
import os
import shutil
import tempfile
import unittest

from tests import coverage as cov

ROWS = [("dwell.py", 83, 100, 83.0), ("trace.py", 90, 100, 90.0)]


class BreachesTest(unittest.TestCase):
    def test_a_module_inside_the_tolerance_is_not_a_breach(self):
        baseline = {"modules": {"dwell.py": 84.5, "trace.py": 90.0}}
        self.assertEqual(cov._breaches(ROWS, baseline, 2.0), [])

    def test_a_module_below_the_tolerance_is_named_with_its_floor(self):
        baseline = {"modules": {"dwell.py": 96.5, "trace.py": 90.0}}
        self.assertEqual(
            cov._breaches(ROWS, baseline, 2.0), [("dwell.py", 83.0, 94.5, "below")]
        )

    def test_a_module_with_no_recorded_value_is_not_failed(self):
        rows = [("new.py", 1, 10, 10.0)]
        self.assertEqual(cov._breaches(rows, {"modules": {}}, 2.0), [("new.py", 10.0, None, "unbaselined")])


class BaselineTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="residue-cov-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.path = os.path.join(self.tmp, "baseline.json")

    def test_a_written_baseline_reads_back_at_one_decimal(self):
        cov._write_baseline(self.path, ROWS, 90.56)
        data = cov._read_baseline(self.path)
        self.assertEqual(data["total"], 90.6)
        self.assertEqual(data["modules"], {"dwell.py": 83.0, "trace.py": 90.0})

    def test_a_missing_baseline_is_refused_rather_than_assumed(self):
        with self.assertRaises(SystemExit):
            cov._read_baseline(os.path.join(self.tmp, "absent.json"))


if __name__ == "__main__":
    unittest.main()

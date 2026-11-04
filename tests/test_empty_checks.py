"""An empty report: nothing was measured, and the renderers still agree.

A report with no checks is a legitimate shape (the caller audited nothing), so
the fold has to return SKIP on its own rather than on an early return whose
only job is to restate what the rest of the fold already does. These assertions
pin the behaviour before and after that guard goes.
"""

import json
import unittest

from residue import model, report


class EmptyReportTests(unittest.TestCase):
    def setUp(self):
        self.report = model.Report("trace", [])

    def test_status_is_skip(self):
        self.assertEqual(model.SKIP, self.report.status())

    def test_exit_code_is_the_skip_code(self):
        self.assertEqual(model.EXIT[model.SKIP], self.report.exit_code())
        self.assertEqual(3, self.report.exit_code())

    def test_to_dict_carries_the_skip_verdict(self):
        payload = self.report.to_dict()
        self.assertEqual("trace", payload["command"])
        self.assertEqual(model.SKIP, payload["status"])
        self.assertEqual(3, payload["exit_code"])
        self.assertEqual([], payload["checks"])

    def test_text_renders_a_summary_line(self):
        self.assertIn(
            "summary command=trace status=skip exit=3", report.as_text(self.report)
        )

    def test_json_renders(self):
        payload = json.loads(report.as_json(self.report))
        self.assertEqual(
            {
                "command": "trace",
                "status": "skip",
                "exit_code": 3,
                "facts": {},
                "checks": [],
            },
            payload,
        )

    def test_a_primary_check_with_no_checks_still_skips(self):
        self.assertEqual(
            model.SKIP, model.Report("trace", [], primary="trace.root").status()
        )

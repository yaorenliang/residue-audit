"""The two renderers must agree about what a fact is.

A report is a measurement plus the reason it is being reported. Facts carry the
numbers, and a number can come back as a set ("these paths were touched"). If the
text form prints it and the json form raises, the tool is readable or scriptable
but not both - and --json failed only after every check had already run.
"""

import json
import pathlib
import unittest

from residue import model, report


def _report(facts):
    check = model.Check("trace.alignment", model.PASS, "the ledger and the tree agree")
    return model.Report("trace", [check], facts)


class RendererTests(unittest.TestCase):
    def test_set_fact_is_serialisable_and_ordered(self):
        payload = json.loads(report.as_json(_report({"leaks": {"b", "a"}})))
        self.assertEqual(["a", "b"], payload["facts"]["leaks"])

    def test_frozenset_fact_takes_the_same_path(self):
        payload = json.loads(report.as_json(_report({"leaks": frozenset({"b", "a"})})))
        self.assertEqual(["a", "b"], payload["facts"]["leaks"])

    def test_tuple_renders_as_a_list(self):
        payload = json.loads(report.as_json(_report({"span": (1, 2)})))
        self.assertEqual([1, 2], payload["facts"]["span"])

    def test_nested_set_is_reached(self):
        payload = json.loads(report.as_json(_report({"scan": {"roots": {"x"}}})))
        self.assertEqual({"roots": ["x"]}, payload["facts"]["scan"])

    def test_non_string_keys_become_strings(self):
        payload = json.loads(report.as_json(_report({"counts": {1: 2}})))
        self.assertEqual({"1": 2}, payload["facts"]["counts"])

    def test_path_fact_is_a_string(self):
        payload = json.loads(report.as_json(_report({"root": pathlib.Path("/tmp/x")})))
        self.assertEqual("/tmp/x", payload["facts"]["root"])

    def test_object_without_a_json_shape_keeps_its_repr(self):
        payload = json.loads(report.as_json(_report({"clock": object()})))
        self.assertIn("object at", payload["facts"]["clock"])

    def test_text_and_json_show_the_same_fact(self):
        facts = {"leaks": {"b", "a"}, "span": (1, 2)}
        as_text = report.as_text(_report(facts))
        self.assertIn('leaks=["a", "b"]', as_text)
        self.assertIn("span=[1, 2]", as_text)
        payload = json.loads(report.as_json(_report(facts)))
        self.assertEqual(["a", "b"], payload["facts"]["leaks"])
        self.assertEqual([1, 2], payload["facts"]["span"])

    def test_a_set_fact_does_not_change_the_verdict(self):
        rendered = report.as_json(_report({"leaks": {"a"}}))
        self.assertIn('"status": "pass"', rendered)
        self.assertIn("status=pass exit=0", report.as_text(_report({"leaks": {"a"}})))


if __name__ == "__main__":
    unittest.main()

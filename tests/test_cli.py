"""CLI contract: exit codes, argument domains, --json placement, --version.

The exit code is the only part of this program a gate reads, and a gate turns it
into "this host is clean" or "this host is compromised". These tests pin that
interface, because a usage error that borrows a verdict's code is a false
positive waiting for a typo.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import shutil
import sys
import tempfile
import unittest
from unittest import mock

import residue
from residue import cli, model

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MARKER_UNIT = (
    "[Unit]\nDescription=harvest\n[Service]\nRestart=always\n"
    "KillSignal=SIGCONT\nSendSIGKILL=no\nExecStart=/usr/libexec/kworker --id x\n"
)

SCAN_DIRS = ("etc/systemd/system", "etc/cron.d", "usr/libexec", "usr/local/bin")


def write_file(path, body):
    directory = os.path.dirname(path)
    if directory and not os.path.isdir(directory):
        os.makedirs(directory)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(body)
    return path


def run_main(argv):
    """Call main() in-process and keep what it wrote to both streams.

    argv is passed explicitly: main() takes its arguments, it does not read
    sys.argv, so a test never has to rewrite the process's own command line.
    """
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


class CliCase(unittest.TestCase):
    """A temp tree with the four scanned directories, empty unless stated."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="residue-cli-")
        self.addCleanup(shutil.rmtree, self.root, True)
        for rel in SCAN_DIRS:
            os.makedirs(os.path.join(self.root, rel))

    def plant(self):
        write_file(os.path.join(self.root, "etc/systemd/system/zz-harvest.service"), MARKER_UNIT)
        write_file(os.path.join(self.root, "usr/libexec/kworker"), "\x7fELF synthetic\n")
        return self.root

    def features(self, name, values):
        path = os.path.join(self.root, name + ".json")
        write_file(path, json.dumps({"name": name, "features": values}))
        return path


class ExitCodeTests(CliCase):
    def test_f01_exit_table_has_one_slot_per_meaning(self):
        """F-01: five meanings, so the table needs five codes and 'error' must be 4."""
        self.assertEqual(5, len(model.EXIT), "expected exactly five exit codes, got %r" % (model.EXIT,))
        self.assertEqual(4, model.EXIT["error"], "tool failure needs a code of its own: %r" % (model.EXIT,))
        self.assertEqual(
            [0, 1, 2, 3, 4],
            sorted(model.EXIT.values()),
            "the codes must be one per verdict, not shared: %r" % (model.EXIT,),
        )

    def test_f01_no_subcommand_is_a_tool_error(self):
        code, out, err = run_main([])
        self.assertEqual(4, code, "empty argv is a usage error, not 3 == skip: %s" % err)
        self.assertIn("usage", err.lower(), "a usage error must say what to do: %r" % err)
        self.assertEqual("", out, "a usage error must not emit a report")

    def test_f01_usage_error_is_not_fail(self):
        code, out, err = run_main(["trace", self.root, "--bogus-flag"])
        self.assertEqual(4, code, "a misspelt flag exited %d; 2 already means fail" % code)
        self.assertIn("--bogus-flag", err)

    def test_f01_missing_root_is_a_tool_error(self):
        code, out, err = run_main(["trace", os.path.join(self.root, "no-such-dir")])
        self.assertEqual(4, code, "a root that is not there cannot be judged: %s" % out)
        self.assertIn("not a directory", err)

    def test_f01_missing_input_file_is_a_tool_error(self):
        code, out, err = run_main(["batch", os.path.join(self.root, "no-such.json")])
        self.assertEqual(4, code, "a missing ledger exited %d, which reads as partial" % code)
        self.assertIn("residue: error:", err)

    def test_f01_unexpected_exception_is_a_tool_error(self):
        with mock.patch.object(cli.trace_mod, "run", side_effect=RuntimeError("boom")):
            code, out, err = run_main(["trace", self.root])
        self.assertEqual(4, code)
        self.assertIn("RuntimeError", err, "the diagnostic must name the exception type: %r" % err)
        self.assertIn("boom", err, "the diagnostic must carry the message: %r" % err)

    def test_f01_verdicts_keep_their_own_codes(self):
        clean, _, _ = run_main(["trace", self.root])
        self.assertEqual(3, clean, "an empty tree is skip, not a tool failure")
        planted, _, _ = run_main(["trace", self.plant()])
        self.assertIn(planted, (0, 1, 2), "a real tree must produce a verdict, got %d" % planted)

    def test_f01_help_still_exits_zero(self):
        code, out, _ = run_main(["--help"])
        self.assertEqual(0, code)
        self.assertIn("usage", out.lower())

    def test_f01_cli_uses_the_exit_table_only(self):
        """F-01 / CO-15: no literal exit code may hide in cli.py."""
        with open(os.path.join(REPO, "residue", "cli.py"), "r", encoding="utf-8") as handle:
            lines = handle.read().splitlines()
        offenders = []
        for number, line in enumerate(lines, 1):
            code = line.split("#", 1)[0]
            if re.search(r"\breturn\s+\d+\b", code) or re.search(r"\bexit\(\s*\d+", code):
                offenders.append("%d: %s" % (number, line.strip()))
        self.assertEqual([], offenders, "exit codes must come from model.EXIT, found literals: %r" % (offenders,))


class ArgumentDomainTests(CliCase):
    def test_f11_negative_fresh_window_is_rejected(self):
        code, out, err = run_main(["trace", self.root, "--fresh-window", "-100"])
        self.assertEqual(4, code, "a negative window made every artifact look fresh and exited %d" % code)
        self.assertIn("fresh-window", err)
        self.assertIn("0", err, "the message must state the usable range: %r" % err)

    def test_f11_empty_marker_is_rejected(self):
        code, out, err = run_main(["trace", self.root, "--marker", ""])
        self.assertEqual(4, code, "an empty marker matched every file in the tree, exit %d" % code)
        self.assertIn("marker", err)

    def test_f11_absolute_scan_is_rejected(self):
        code, out, err = run_main(["trace", self.root, "--scan", "/etc/cron.d"])
        self.assertEqual(4, code, "an absolute --scan escapes the root and exited %d" % code)
        self.assertIn("relative", err, "the message must ask for a relative directory: %r" % err)
        self.assertIn("etc/systemd/system", err, "the message must show the shape of a valid value: %r" % err)

    def test_f05_a_parent_component_walks_out_of_the_root(self):
        outside = os.path.join(os.path.dirname(self.root), "sibling")
        if not os.path.isdir(outside):
            os.makedirs(outside)
        write_file(os.path.join(outside, "escape.cron"), MARKER_UNIT)
        code, out, err = run_main(["trace", self.root, "--scan", "../sibling"])
        self.assertEqual(4, code, "--scan ../sibling audited another tree and exited %d" % code)
        self.assertIn("walks out of the root", err)
        self.assertIn("etc/cron.d", err, "the message must show the shape of a valid value: %r" % err)

    def test_f05_a_scan_entry_inside_the_root_still_runs(self):
        code, out, err = run_main(["trace", self.plant(), "--scan", "etc/cron.d"])
        self.assertNotEqual(4, code, "a subtree inside the root is a normal scan, exited 4: %s" % err)

    def test_f05_an_empty_scan_entry_is_rejected(self):
        code, out, err = run_main(["trace", self.root, "--scan", ""])
        self.assertEqual(4, code, "an empty --scan selected the whole root and exited %d" % code)
        self.assertIn("needs a name", err)

    def test_f11_threshold_outside_the_unit_interval_is_rejected(self):
        left = self.features("left", ["x", "y"])
        right = self.features("right", ["x", "y"])
        for bad in ("2.0", "98", "-0.5"):
            code, out, err = run_main(["batch", left, right, "--threshold", bad])
            self.assertEqual(4, code, "--threshold %s was accepted and exited %d" % (bad, code))
            self.assertIn("threshold", err)
            self.assertIn("1.0", err, "the message must state the usable range: %r" % err)

    def test_f11_threshold_boundaries_still_run(self):
        left = self.features("left", ["x", "y"])
        right = self.features("right", ["x", "y"])
        for good in ("0.0", "1.0"):
            code, out, err = run_main(["batch", left, right, "--threshold", good])
            self.assertIn(code, (0, 1, 2), "--threshold %s is inside the domain but exited %d: %s" % (good, code, err))

    def test_f11_fresh_window_zero_still_runs(self):
        code, out, err = run_main(["trace", self.plant(), "--fresh-window", "0"])
        self.assertIn(code, (0, 1, 2), "--fresh-window 0 is the boundary and must run: %s" % err)


class JsonPlacementTests(CliCase):
    def test_f14_json_before_the_subcommand_is_accepted(self):
        code, out, err = run_main(["--json", "trace", self.root])
        self.assertIn(code, (0, 1, 2, 3), "--json before the subcommand exited %d: %s" % (code, err))
        self.assertEqual("trace", json.loads(out)["command"])

    def test_f14_json_after_the_subcommand_is_accepted(self):
        code, out, err = run_main(["trace", self.plant(), "--json"])
        self.assertIn(code, (0, 1, 2, 3), "the documented position exited %d: %s" % (code, err))
        self.assertEqual("trace", json.loads(out)["command"])


class VersionTests(unittest.TestCase):
    def test_version_comes_from_one_source(self):
        code, out, err = run_main(["--version"])
        self.assertEqual(0, code, "no --version in the parser: %s" % err)
        self.assertIn(residue.__version__, out)
        with open(os.path.join(REPO, "pyproject.toml"), "r", encoding="utf-8") as handle:
            declared = re.search(r'^version = "([^"]+)"', handle.read(), re.MULTILINE)
        self.assertIsNotNone(declared, "pyproject.toml must declare a version")
        self.assertEqual(
            declared.group(1),
            residue.__version__,
            "the module and the distribution must not disagree about the version",
        )


class RenderRobustnessTests(CliCase):
    def _report_with_a_set(self):
        return model.Report(
            "trace",
            [model.Check("trace.artifacts", model.PASS, "one artifact matched the marker set")],
            {"markers": {"alpha", "beta"}, "artifacts": 1},
        )

    def test_f16_non_scalar_fact_does_not_crash_the_json_report(self):
        """F-16: a set in facts used to raise TypeError after every check had run."""
        with mock.patch.object(cli.trace_mod, "run", return_value=self._report_with_a_set()):
            code, out, err = run_main(["trace", self.root, "--json"])
        self.assertEqual(0, code, "a fact the renderer cannot dump turned a pass into %d: %s" % (code, err))
        self.assertEqual(["alpha", "beta"], json.loads(out)["facts"]["markers"])

    def test_f16_non_scalar_fact_renders_in_text_mode_too(self):
        with mock.patch.object(cli.trace_mod, "run", return_value=self._report_with_a_set()):
            code, out, err = run_main(["trace", self.root])
        self.assertEqual(0, code, "the text renderer hit the same set: %s" % err)
        self.assertIn("markers=", out)
        self.assertIn("alpha", out)


if __name__ == "__main__":
    unittest.main()
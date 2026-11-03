"""F-12: the demo returns a report, and the report has to be honest.

The old demo printed four sections and always returned 0, while three of those
sections said fail. A reader was told "here is a passing audit" by a program
that never produced one and could not fail. These cases pin the three claims the
demo makes: it shows every verdict, its exit code is its verdict, and it leaves
the repository alone.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import unittest
from unittest import mock

from residue import cli, demo, report as report_mod
from residue.model import ERROR, EXIT, FAIL, PASS, PARTIAL

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _snapshot(root):
    seen = set()
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in (".git", "__pycache__", ".mypy_cache")]
        for name in files:
            seen.add(os.path.join(base, name))
    return seen


class DemoReturnsItsVerdict(unittest.TestCase):
    def setUp(self):
        self.before = _snapshot(REPO)
        self.out = io.StringIO()
        self.report = demo.run(self.out)
        self.text = self.out.getvalue()

    def test_f12_demo_returns_a_report(self):
        self.assertEqual(self.report.command, "demo")
        self.assertTrue(self.report.checks)

    def test_f12_demo_shows_every_verdict(self):
        verdicts = set(self.report.facts["verdicts"].values())
        self.assertEqual(verdicts, {PASS, PARTIAL, FAIL})
        sections = dict((c.name, c.status) for c in self.report.checks)
        self.assertEqual(sections["demo.sections"], PASS)

    def test_f12_demo_exit_code_is_the_report_status(self):
        self.assertEqual(self.report.exit_code(), EXIT[self.report.status()])
        self.assertNotEqual(self.report.status(), PASS)

    def test_f12_demo_prints_a_passing_section(self):
        self.assertIn("status=pass", self.text)
        self.assertIn("status=fail", self.text)

    def test_f12_demo_leaves_the_repository_alone(self):
        self.assertEqual(_snapshot(REPO), self.before)


class DemoIsASubcommand(unittest.TestCase):
    def test_f12_cli_demo_subcommand_exists(self):
        parser = cli._parser()
        # argparse keeps the registered names in _subparsers; asking it is more
        # honest than trusting the help text, which is what rotted last time
        names = parser._subparsers._group_actions[0].choices
        self.assertIn("demo", names)

    def test_f12_cli_demo_returns_the_demo_code(self):
        stream = io.StringIO()
        real = cli.sys.stdout
        cli.sys.stdout = stream
        try:
            code = cli.main(["demo"])
        finally:
            cli.sys.stdout = real
        self.assertLess(code, EXIT["error"])
        self.assertIn("summary command=demo", stream.getvalue())

    def test_f12_cli_demo_json_is_renderable(self):
        stream = io.StringIO()
        real = cli.sys.stdout
        cli.sys.stdout = stream
        try:
            cli.main(["--json", "demo"])
        finally:
            cli.sys.stdout = real
        payload = stream.getvalue()
        self.assertIn('"command": "demo"', payload)


class DemoJsonIsOneDocument(unittest.TestCase):
    """With --json the prose is not part of stdout: one stream, one document."""

    def test_f10_demo_json_stdout_parses_and_carries_the_report(self):
        out, err = io.StringIO(), io.StringIO()
        real_out, real_err = cli.sys.stdout, cli.sys.stderr
        cli.sys.stdout, cli.sys.stderr = out, err
        try:
            code = cli.main(["--json", "demo"])
        finally:
            cli.sys.stdout, cli.sys.stderr = real_out, real_err
        payload = json.loads(out.getvalue())
        self.assertEqual(payload["command"], "demo")
        self.assertIn("checks", payload)
        self.assertIn("status", payload)
        self.assertIn("### borrowed.", err.getvalue())
        self.assertLess(code, EXIT["error"])

    def test_f10_the_sections_go_to_the_stream_the_caller_names(self):
        stream = io.StringIO()
        demo.run(stream)
        self.assertIn("### borrowed.", stream.getvalue())


class DemoSecondEntryPointFailsLoud(unittest.TestCase):
    """F-03: the module entry point must never turn a crash into a verdict.

    ``python -m residue.demo`` is the second way in, and it used to be the only
    one without the boundary the CLI keeps. An uncaught exception left Python
    exiting 1, which is this tool's code for *partial*: a statement about the
    tree. CI read that as a verdict because its check was "below 4".
    """

    def test_a_crash_lands_on_the_error_code(self):
        err = io.StringIO()
        with mock.patch.object(demo, "run", side_effect=RuntimeError("boom")):
            with mock.patch("sys.stderr", err):
                code = demo.main()
        self.assertEqual(code, EXIT[ERROR])
        self.assertIn("residue: error: RuntimeError: boom", err.getvalue())

    def test_the_process_exits_with_that_code(self):
        script = (
            "import residue.demo as d\n"
            "def boom(*a, **k):\n"
            "    raise RuntimeError('boom')\n"
            "d.run = boom\n"
            "raise SystemExit(d.main())\n"
        )
        proc = subprocess.run(
            [sys.executable, "-c", script], cwd=REPO, capture_output=True, text=True
        )
        self.assertEqual(proc.returncode, EXIT[ERROR], proc.stderr)
        self.assertIn("residue: error: RuntimeError: boom", proc.stderr)
        self.assertNotIn("Traceback", proc.stderr)


if __name__ == "__main__":
    unittest.main()

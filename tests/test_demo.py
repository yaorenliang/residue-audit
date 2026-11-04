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

from residue import _fixtures, cli, demo, report as report_mod, stat_io
from tests import readme_sample
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


class TheWholeDemoIsPinned(unittest.TestCase):
    """Every section, not just the one the README quotes.

    Section 1 already has a byte-for-byte sample, and that is the only section
    anything read: a fixture flag or a deleted line could change what sections
    2-6 reported while the suite stayed green. This pins the run - six sections
    plus the demo's own summary - against a golden file, normalising only the
    throwaway paths and the wall-clock directory stamps.
    """

    def test_the_whole_run_matches_the_golden_sample(self):
        path = os.path.join(REPO, "tests", "golden", "demo.txt")
        if os.environ.get("UPDATE_GOLDEN"):
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(readme_sample.whole() + "\n")
        with open(path, encoding="utf-8") as handle:
            want = handle.read().rstrip("\n")
        got = readme_sample.whole()
        # a diff of the first mismatch is far more useful than "177 lines differ"
        self.assertEqual(got.splitlines(), want.splitlines())

    def test_the_golden_file_is_the_one_the_tool_prints(self):
        # the file is generated, so it must not be edited by hand into something
        # the tool no longer prints: regenerating it twice has to be a no-op
        self.assertEqual(readme_sample.whole(), readme_sample.whole())


class TheBorrowedTreeSeparatesItsClocks(unittest.TestCase):
    """The README sample is only a sample if every run prints the same lines.

    ``trace.ctime`` compares strictly, so an artifact written in the same clock
    tick as its neighbours ties instead of winning: the check still fails, but it
    lists four artifacts instead of five, and the quote in the README came out
    one line short on a runner whose ctime granularity was coarser than the sleep
    the fixture used to rely on. These cases pin the count and the stability, and
    pin that an unbreakable tie is loud instead of silent.
    """

    def test_every_artifact_wins_the_ctime_race(self):
        out = io.StringIO()
        demo.run(out)
        text = out.getvalue()
        self.assertEqual(text.count("ctime_vs_cap=newer"), len(_fixtures.ARTIFACTS))

    def test_the_quoted_sample_is_the_same_on_every_run(self):
        self.assertEqual(readme_sample.sample(), readme_sample.sample())

    def test_a_tie_that_cannot_be_broken_raises(self):
        import tempfile

        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "artifact")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("body\n")
            # a cap no rewrite can beat stands in for a filesystem whose ticks are
            # too coarse for the tree: the fixture must refuse to hand out a sample
            with mock.patch.object(stat_io, "dir_stats", return_value=(0, 1 << 60, 0, 1)):
                with self.assertRaises(RuntimeError):
                    _fixtures.separate_ctimes([path], first_wait_s=0.0, rounds=2)


class DemoMainIsItsReport(unittest.TestCase):
    def test_main_returns_the_exit_code_of_the_report_it_printed(self):
        out = io.StringIO()
        with mock.patch("sys.stdout", out):
            code = demo.main()
        self.assertEqual(code, 2)  # borrowed tree fails alignment
        self.assertIn("summary command=demo status=fail exit=2", out.getvalue())


if __name__ == "__main__":
    unittest.main()
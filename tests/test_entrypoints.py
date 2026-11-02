"""Both entry points, run as processes: `python -m residue` and the script.

The console script is what the README tells a user to run, and `__main__.py` is
what a reader tries first. Both used to be unexercised (0% of __main__.py), so a
broken `raise SystemExit(main())` would have shipped green.
"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run(args, cwd=REPO):
    return subprocess.run(
        [sys.executable] + args,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
    )


class EntryPoints(unittest.TestCase):
    def test_module_entry_point_reports_its_version(self):
        done = run(["-m", "residue", "--version"])
        self.assertEqual(done.returncode, 0)
        self.assertIn("residue ", done.stdout)

    def test_module_entry_point_needs_a_subcommand(self):
        done = run(["-m", "residue"])
        # 4, not 3: "you did not ask for anything" is a tool failure, and 3 is
        # already the code for "nothing to audit"
        self.assertEqual(done.returncode, 4)
        self.assertIn("a subcommand is required", done.stderr)

    def test_cli_module_is_runnable_directly(self):
        done = run(["-m", "residue.cli", "--help"])
        self.assertEqual(done.returncode, 0)
        self.assertIn("trace", done.stdout)

    def test_demo_module_runs_as_a_process(self):
        done = run(["-m", "residue.demo"])
        self.assertLess(done.returncode, 4)
        self.assertIn("summary command=demo", done.stdout)


if __name__ == "__main__":
    unittest.main()

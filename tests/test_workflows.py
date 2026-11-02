"""The workflows are the release gate, so the gate itself gets tests.

A CI file that asserts nothing is a green check that ships a broken release. Each
test here fails when the workflow stops being able to fail: a swallowed exit code,
a step that greps for a subcommand that no longer exists, a notes file that is
hardcoded to the version that happened to exist when it was written.
"""

import os
import re
import unittest

from residue.cli import _parser

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def workflow(name):
    with open(os.path.join(ROOT, ".github", "workflows", name), encoding="utf-8") as handle:
        return handle.read()


def run_blocks(text):
    """Every 'run:' payload, flattened, so we can inspect what CI actually runs."""
    blocks = []
    lines = text.splitlines()
    for index, line in enumerate(lines):
        match = re.match(r"\s*(?:-\s*)?run:\s*(.*)$", line)
        if not match:
            continue
        head = match.group(1).strip()
        if head and head not in ("|", ">", "|-"):
            blocks.append(head)
            continue
        indent = len(line) - len(line.lstrip())
        payload = []
        for follow in lines[index + 1:]:
            if not follow.strip():
                payload.append("")
                continue
            if len(follow) - len(follow.lstrip()) <= indent:
                break
            payload.append(follow.strip())
        blocks.append("\n".join(payload))
    return blocks


class ZeroDependencyStep(unittest.TestCase):
    """F-17: the step used to assert something true of every interpreter."""

    def test_the_step_runs_a_test_that_can_fail(self):
        text = workflow("ci.yml")
        self.assertIn("tests.test_packaging", text)
        blocks = [b for b in run_blocks(text) if "test_packaging" in b]
        self.assertTrue(blocks, "ci.yml must run the packaging contract")
        for block in blocks:
            self.assertNotRegex(block, r"\|\|\s*true")

    def test_the_step_is_not_a_bare_interpreter_check(self):
        # The old step printed sys.argv and asserted it was short. That cannot fail
        # for any real run, so its absence is the fix.
        text = workflow("ci.yml")
        self.assertNotIn("sys.argv", text)


class ReleaseNotesFollowTheTag(unittest.TestCase):
    """F-18: the notes file was hardcoded to v0.1.0."""

    def test_the_notes_path_is_derived_from_the_tag(self):
        text = workflow("release.yml")
        self.assertIn('notes="docs/RELEASE-' + '${tag}' + '.md"', text)

    def test_a_missing_notes_file_fails_the_job(self):
        text = workflow("release.yml")
        marker = '[ ! -f "$notes" ]'
        self.assertIn(marker, text)
        after = text.split(marker, 1)[1]
        self.assertIn("exit 1", after)

    def test_no_hardcoded_version_remains(self):
        text = workflow("release.yml")
        self.assertNotRegex(text, r"notes=.*v0\.1\.0")


class CrossCheckCannotSwallowACrash(unittest.TestCase):
    """F-19: '|| true' turned a crashed checker into a green cross-check."""

    def read(self):
        with open(os.path.join(ROOT, "tests", "cross_check.sh"), encoding="utf-8") as handle:
            return handle.read()

    def test_no_error_swallowing_in_the_cross_check(self):
        # Comments may quote the old line; only executed lines matter.
        code = "\n".join(
            line for line in self.read().splitlines() if not line.lstrip().startswith("#")
        )
        self.assertNotRegex(code, r"\|\|\s*true")
        self.assertNotRegex(code, r"\|\|\s*:")

    def test_a_tool_failure_is_fatal_and_an_empty_report_is_fatal(self):
        text = self.read()
        self.assertIn('if [ "$status" -ge 4 ]', text)
        self.assertIn("CROSS_FAIL", text)
        self.assertIn('if [ -z "$json" ]', text)

    def test_the_numbers_are_read_as_json_not_scraped(self):
        text = self.read()
        self.assertIn("json.load", text)
        self.assertIn("--json", text)


class CiOnlyRunsSubcommandsThatExist(unittest.TestCase):
    """F-20: CI invoked a subcommand the CLI never had."""

    def subs(self):
        subs = set()
        for action in _parser()._actions:
            choices = getattr(action, "choices", None)
            if isinstance(choices, dict):
                subs |= set(choices)
        return subs

    def test_every_residue_subcommand_in_ci_exists(self):
        subs = self.subs()
        self.assertTrue(subs)
        text = workflow("ci.yml") + workflow("release.yml")
        used = set(re.findall(r"residue\s+([a-z][a-z-]*)", text))
        used -= {"demo", "cli"}
        used -= {"--"}  # a flag can follow the binary name
        for name in sorted(used):
            self.assertIn(name, subs, "CI runs 'residue %s', which the parser does not have" % name)

    def test_the_demo_step_still_separates_failure_from_a_verdict(self):
        text = workflow("ci.yml")
        self.assertIn('test "$code" -lt 4', text)

    def test_the_demo_step_notices_a_dirty_tree(self):
        text = workflow("ci.yml")
        self.assertIn('test "$before" = "$after"', text)

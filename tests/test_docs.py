"""The documentation is part of the contract, so it gets tests too.

Every flag the docs promise must exist in the parser, every exit code the docs
table must exist in the enum, and the checks the tool emits must be named where a
reader will look for them. A doc that drifts from the binary is worse than no doc:
it is a wrong answer with a citation.

Translated docs are held to the same shape as their English original, because a
translation that quietly drops a section is how the two drift apart.
"""

import json
import subprocess
import os
import re
import unittest

from residue import cli
from residue.model import EXIT
from tests import readme_sample

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DOCS = [
    "README.md",
    "README.zh-CN.md",
    os.path.join("docs", "method.md"),
    os.path.join("docs", "method.zh-CN.md"),
    os.path.join("docs", "limits.md"),
    os.path.join("docs", "limits.zh-CN.md"),
]

# Pairs where the second file is a translation of the first.
TRANSLATIONS = [
    ("README.md", "README.zh-CN.md"),
    (os.path.join("docs", "method.md"), os.path.join("docs", "method.zh-CN.md")),
    (os.path.join("docs", "limits.md"), os.path.join("docs", "limits.zh-CN.md")),
]


def read_doc(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as handle:
        return handle.read()


def parser_flags():
    flags = set()

    def walk(parser):
        for action in parser._actions:  # noqa: SLF001 - argparse has no public walk
            flags.update(action.option_strings)
            choices = getattr(action, "choices", None)
            if isinstance(choices, dict):
                for sub in choices.values():
                    walk(sub)

    walk(cli._parser())  # noqa: SLF001
    return flags


def documented_flags(text):
    # Only flags at a word boundary: "3.0-1.0" in a range is not a flag.
    return set(re.findall(r"(?<![\\w.-])--[a-z][a-z-]*", text))


def exit_code_table(text):
    """Return the codes in the first table whose header starts with code/码."""
    rows = []
    in_table = False
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            if in_table:
                break
            continue
        cells = [c.strip() for c in stripped.strip("|").split("|")]
        if not in_table:
            if cells and re.fullmatch(r"(code|码)", cells[0]):
                in_table = True
            continue
        if all(set(c) <= set("-: ") for c in cells):
            continue
        if cells and re.fullmatch(r"[0-9]+", cells[0]):
            rows.append(int(cells[0]))
    return rows


class DocumentedFlags(unittest.TestCase):
    def test_every_documented_flag_exists(self):
        known = parser_flags()
        for rel in DOCS:
            for flag in sorted(documented_flags(read_doc(rel))):
                self.assertIn(
                    flag,
                    known,
                    "%s documents %s, which the parser does not accept" % (rel, flag),
                )

    def test_the_retired_flag_is_gone_from_the_docs(self):
        for rel in DOCS:
            self.assertNotIn(
                "--detections",
                read_doc(rel),
                "%s still mentions --detections; the flag is --hits" % rel,
            )

    def test_the_docs_and_the_parser_cover_the_same_flags(self):
        # Not the same set: --help is argparse's, and the docs describe a subset.
        # What must hold is that no doc-only flag exists, which the test above
        # proves, and that the substantive flags are all mentioned somewhere.
        mentioned = set()
        for rel in DOCS:
            mentioned |= documented_flags(read_doc(rel))
        for flag in ("--json", "--hits", "--fresh-window", "--threshold", "--broad"):
            self.assertIn(flag, mentioned, "%s is a real flag that no doc explains" % flag)


class ExitCodeTable(unittest.TestCase):
    def test_the_tables_list_exactly_the_enum(self):
        expected = set(EXIT.values())
        for rel in DOCS:
            codes = exit_code_table(read_doc(rel))
            if not codes:
                continue  # method.md documents them as prose
            self.assertEqual(
                expected,
                set(codes),
                "%s lists exit codes %s, enum has %s" % (rel, sorted(set(codes)), sorted(expected)),
            )

    def test_both_readmes_say_four_is_not_a_verdict(self):
        for rel, phrase in (("README.md", "never a verdict"), ("README.zh-CN.md", "永远不是判定")):
            text = read_doc(rel)
            self.assertIn(phrase, text, "%s must say 4 is never a verdict" % rel)


class CheckNames(unittest.TestCase):
    def test_every_trace_check_is_named_in_both_readmes(self):
        with open(os.path.join(ROOT, "tests", "golden", "trace_clean.json"), encoding="utf-8") as handle:
            golden = json.load(handle)
        names = sorted({check["name"] for check in golden["checks"]})
        self.assertTrue(names)
        for rel in ("README.md", "README.zh-CN.md"):
            text = read_doc(rel)
            for name in names:
                self.assertIn(name, text, "%s never names the check %s" % (rel, name))

    def test_the_directory_check_names_the_verdict_it_can_reach(self):
        # trace.directory_ctime tops out at partial; the docs have to say so, or a
        # reader will file a bug asking why it never fails.
        for rel in DOCS:
            text = read_doc(rel)
            if "trace.directory_ctime" not in text:
                continue
            self.assertIn("partial", text, "%s must say the directory check stops at partial" % rel)


class TranslationShape(unittest.TestCase):
    def test_heading_counts_match(self):
        for original, translated in TRANSLATIONS:
            left = len(re.findall(r"^## ", read_doc(original), re.M))
            right = len(re.findall(r"^## ", read_doc(translated), re.M))
            self.assertEqual(
                left, right, "%s has %d sections, %s has %d" % (original, left, translated, right)
            )

    def test_heading_counts_are_not_zero(self):
        for original, translated in TRANSLATIONS:
            self.assertGreater(len(re.findall(r"^## ", read_doc(translated), re.M)), 0)


class DocsSample(unittest.TestCase):
    """F-04: the README quotes the demo, so the quote has to be the demo output.

    This used to grep for four substrings, which is not a check: the quote drifted
    (two facts keys went missing) and stayed green. Now the block is compared line
    by line against what tests/readme_sample.py prints.
    """

    def block(self, rel):
        text = read_doc(rel)
        start = text.index("```") + 4
        end = text.index("```", start)
        return [line.rstrip() for line in text[start:end].splitlines()][1:]

    def test_the_readme_quote_is_the_demo_section(self):
        want = [line.rstrip() for line in readme_sample.sample().splitlines()][1:]
        got = self.block("README.md")
        self.assertEqual(len(got), len(want), "the quoted sample changed length")
        for index, (left, right) in enumerate(zip(want, got)):
            self.assertEqual(left, right, "README sample line %d drifted" % (index + 2))

    def test_the_translated_quote_is_the_same_output(self):
        want = [line.rstrip() for line in readme_sample.sample().splitlines()][1:]
        self.assertEqual(self.block("README.zh-CN.md"), want, "the zh README quotes a different sample")

class MakefileDemoRuns(unittest.TestCase):
    """README:99-102 tells a new reader to clone and run make demo: that must not fail."""

    def test_make_demo_exits_zero(self):
        repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        proc = subprocess.run(["make", "demo"], cwd=repo, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, timeout=120)
        text = proc.stdout.decode("utf-8", "replace")
        self.assertEqual(proc.returncode, 0, text[-2000:])
        self.assertIn("summary command=demo", text)
        self.assertIn("status=fail", text)

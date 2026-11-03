"""Print the demo section the README quotes, with the run's own details replaced.

A sample that cannot be diffed is a sample nobody checks: the README block drifted
from the tool twice before this file existed. It prints section 1 of the demo and
nothing else, and it replaces the two things that are allowed to differ between
runs - the throwaway root under $TMPDIR and the wall-clock numbers behind the
directory ctime - with <root> and <now>. Everything else has to match the README
byte for byte, which is what tests/test_docs.py checks.
"""

from __future__ import annotations

import io
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from residue import demo  # noqa: E402 - after the path is made importable

HEADER = "$ residue demo    # section 1 of 6"

ROOT_FACT = re.compile(r"^root=.*$", re.M)
DIR_CLOCK = re.compile(r"dir_ctime_vs_oldest_mtime=\d+")


def section_one() -> str:
    """Section 1 of the demo, as it is printed."""
    out = io.StringIO()
    demo.run(out)
    text = out.getvalue()
    start = text.index("### ")
    end = text.find("\n### ", start + 1)
    block = text[start:] if end == -1 else text[start:end]
    return block.rstrip("\n")


def sample() -> str:
    """The quote the README carries, normalised for the two per-run values."""
    block = DIR_CLOCK.sub("dir_ctime_vs_oldest_mtime=<now>", section_one())
    block = ROOT_FACT.sub("root=<root>", block)
    return HEADER + "\n" + block


def main() -> int:
    sys.stdout.write(sample() + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

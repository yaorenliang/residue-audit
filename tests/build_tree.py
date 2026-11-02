"""Build a synthetic tree for shell-level checks.

Usage: python3 tests/build_tree.py ROOT [--no-align] [--no-neighbours]
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests import fixtures as fx  # noqa: E402


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root")
    parser.add_argument("--no-align", action="store_true")
    parser.add_argument("--no-neighbours", action="store_true")
    args = parser.parse_args(argv)
    os.makedirs(args.root, exist_ok=True)
    fx.plant(
        args.root,
        neighbours=not args.no_neighbours,
        align=not args.no_align,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

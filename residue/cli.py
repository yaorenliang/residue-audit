"""Single entry point: residue trace | dwell | batch."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import batch as batch_mod
from . import dwell as dwell_mod
from . import report as report_mod
from . import trace as trace_mod


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="residue",
        description="Recompute how deeply an implant hid, from artifacts or ledgers.",
    )
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--json",
        action="store_true",
        default=argparse.SUPPRESS,
        help="emit machine-readable JSON (accepted before or after the subcommand)",
    )
    subs = parser.add_subparsers(dest="command")

    trace_cmd = subs.add_parser("trace", parents=[common], help="audit on-disk artifacts in a root tree")
    trace_cmd.add_argument("root", help="root of the tree to audit, e.g. a mounted image")
    trace_cmd.add_argument(
        "--scan",
        action="append",
        default=None,
        help="relative directory to scan; repeatable (default: four system dirs)",
    )
    trace_cmd.add_argument(
        "--marker",
        action="append",
        default=None,
        help="text that marks a file as ours; repeatable",
    )
    trace_cmd.add_argument(
        "--fresh-window",
        type=int,
        default=120,
        help="seconds within which an artifact counts as freshly touched",
    )
    trace_cmd.add_argument(
        "--broad",
        action="store_true",
        default=False,
        help="also claim any binary named by any unit's ExecStart= (low precision; "
        "see docs/limits.md for the measured numbers)",
    )

    dwell_cmd = subs.add_parser("dwell", parents=[common], help="dwell time and detection coverage per host")
    dwell_cmd.add_argument("ledger", help="ndjson ledger: {ts, host, event}")
    dwell_cmd.add_argument("--hits", default=None, help="json list of {ts, host, rule}")

    batch_cmd = subs.add_parser("batch", parents=[common], help="can one signature cluster two builds")
    batch_cmd.add_argument("features", nargs="+", help="json files with {name, features}")
    batch_cmd.add_argument(
        "--threshold",
        type=float,
        default=batch_mod.DEFAULT_THRESHOLD,
        help="jaccard similarity at or above which builds are the same family",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "json"):
        args.json = False
    if not args.command:
        parser.print_help()
        return 3

    if args.command == "trace":
        result = trace_mod.run(
            args.root,
            scan=args.scan,
            markers=args.marker,
            fresh_window_s=args.fresh_window,
            broad=args.broad,
        )
    elif args.command == "dwell":
        result = dwell_mod.run(args.ledger, args.hits)
    else:
        result = batch_mod.run(args.features, args.threshold)

    sys.stdout.write(report_mod.render(result, args.json))
    return result.exit_code()


if __name__ == "__main__":
    raise SystemExit(main())
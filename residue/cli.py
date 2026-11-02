"""Single entry point: residue trace | dwell | batch | demo.

The exit code is the only part of this program a gate ever reads, and a gate
turns it into "this host is clean" or "this host is compromised". So the code
space has to be unambiguous: a usage error or a crash is not a verdict, and it
must never be able to light up a gate written as "if exit == 2".

Everything that can fail between argv and stdout is funnelled through one
boundary here: the failure is reported on stderr and turned into EXIT[ERROR].
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any, List, Optional

from . import __version__
from . import batch as batch_mod
from . import demo as demo_mod
from . import dwell as dwell_mod
from . import report as report_mod
from . import trace as trace_mod
from .model import ERROR, EXIT, PASS


class ToolError(Exception):
    """A caller mistake argparse cannot see, because it depends on the filesystem."""


class Parser(argparse.ArgumentParser):
    """ArgumentParser whose usage errors are tool failures instead of verdicts.

    argparse exits 2 on a bad flag, and 2 already means "fail". The usage text is
    still printed - a caller who mistyped an option should still read what the
    option was - but the code moves to the one slot that means "I could not judge".
    """

    def error(self, message: str) -> None:  # type: ignore[override]
        self.print_usage(sys.stderr)
        self.exit(EXIT[ERROR], "%s: error: %s\n" % (self.prog, message))


def _seconds(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError("expected a whole number of seconds, got %r" % (text,))
    if value < 0:
        # a negative window is not a small threshold: it makes every artifact
        # look freshly touched, so the check passes on any tree
        raise argparse.ArgumentTypeError(
            "must be >= 0 seconds; a negative window makes every artifact look fresh (got %d)" % (value,)
        )
    return value


def _marker(text: str) -> str:
    if not text.strip():
        # the empty string is a substring of every file, so this is not a
        # permissive marker but a rule that claims the whole tree
        raise argparse.ArgumentTypeError(
            "must be a non-empty string; an empty marker matches every file"
        )
    return text


def _relative_dir(text: str) -> str:
    if os.path.isabs(text):
        # os.path.join discards the root for an absolute second argument, so an
        # absolute --scan silently audits a different tree than the one given
        raise argparse.ArgumentTypeError(
            "must be a directory relative to the scanned root, e.g. etc/systemd/system (got %r)" % (text,)
        )
    return text


def _threshold(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError("expected a number, got %r" % (text,))
    if not 0.0 <= value <= 1.0:
        # jaccard similarity is a ratio; 2.0 or 98 accept every pair, 1.0 is the
        # only honest way to say "identical only"
        raise argparse.ArgumentTypeError(
            "must be within [0.0, 1.0]; jaccard similarity is a ratio (got %r)" % (value,)
        )
    return value


def _parser() -> argparse.ArgumentParser:
    parser = Parser(
        prog="residue",
        description="Recompute how deeply an implant hid, from artifacts or ledgers.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="emit machine-readable JSON (accepted before or after the subcommand)",
    )
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)

    common = Parser(add_help=False)
    # The help text promises both positions, so both parsers carry the flag. The
    # subparser default is SUPPRESS: it then never touches a value the parent
    # already set, and a bare "trace --json" still ends up true.
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
        type=_relative_dir,
        default=None,
        metavar="REL_DIR",
        help="relative directory to scan; repeatable (default: four system dirs)",
    )
    trace_cmd.add_argument(
        "--marker",
        action="append",
        type=_marker,
        default=None,
        help="text that marks a file as ours; repeatable",
    )
    trace_cmd.add_argument(
        "--fresh-window",
        type=_seconds,
        default=120,
        help="seconds within which an artifact counts as freshly touched (>= 0)",
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
        type=_threshold,
        default=batch_mod.DEFAULT_THRESHOLD,
        help="jaccard similarity at or above which builds are the same family (0.0-1.0)",
    )
    subs.add_parser(
        "demo",
        parents=[common],
        help="build throwaway trees, audit them, and show pass, partial and fail in one run",
    )
    return parser


def _dispatch(args: argparse.Namespace) -> Any:
    if args.command == "trace":
        if not os.path.isdir(args.root):
            # The walker reports what it read, and a missing root reads exactly
            # like an empty one: zero artifacts, clean host. Say it instead.
            raise ToolError("root %r is not a directory" % (args.root,))
        return trace_mod.run(
            args.root,
            scan=args.scan,
            markers=args.marker,
            fresh_window_s=args.fresh_window,
            broad=args.broad,
        )
    if args.command == "dwell":
        return dwell_mod.run(args.ledger, args.hits)
    if args.command == "demo":
        # sections print as they run; the returned report is the aggregate, so
        # the process exit code still answers "did every section behave?"
        return demo_mod.run(sys.stdout)
    return batch_mod.run(args.features, args.threshold)


def _exit_code(exc: SystemExit) -> int:
    """Keep argparse's own code (help = 0, usage error = 4) as a return value."""
    code = exc.code
    if code is None:
        return EXIT[PASS]
    if isinstance(code, int):
        return code
    sys.stderr.write("%s\n" % (code,))
    return EXIT[ERROR]


def main(argv: Optional[List[str]] = None) -> int:
    parser = _parser()
    try:
        args = parser.parse_args(argv)
        if not args.command:
            parser.print_usage(sys.stderr)
            sys.stderr.write("residue: error: a subcommand is required: trace, dwell, batch or demo\n")
            return EXIT[ERROR]
        report = _dispatch(args)
        # the renderer owns the conversion of facts into json shapes; doing it
        # here as well left report.as_json reachable and still broken.
        sys.stdout.write(report_mod.render(report, bool(args.json)))
        return report.exit_code()
    except ToolError as exc:
        sys.stderr.write("residue: error: %s\n" % (exc,))
        return EXIT[ERROR]
    except SystemExit as exc:
        # argparse reached its own exit path; hand the code back as a value so
        # main() stays an ordinary function of its argument.
        return _exit_code(exc)
    except Exception as exc:  # the last net: a crash is never a verdict
        sys.stderr.write("residue: error: %s: %s\n" % (type(exc).__name__, exc))
        return EXIT[ERROR]


if __name__ == "__main__":
    raise SystemExit(main())

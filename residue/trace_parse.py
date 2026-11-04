"""Reading claim material out of text: paths, markers and ExecStart lines.

Nothing here touches the filesystem, so the parsing rules can be exercised on
strings alone instead of on a tree that has to be built first.
"""

from __future__ import annotations

import os
from typing import List, Sequence


def sanitize(path: str, root: str) -> str:
    """Replace the scanned root with a stable token so goldens survive temp dirs."""
    root = os.path.abspath(root)
    full = os.path.abspath(path)
    if full == root:
        return "<root>"
    if full.startswith(root + os.sep):
        return "<root>/" + full[len(root) + 1:]
    return full


def live_lines(text: str):
    """Configuration lines only: a comment cannot configure anything.

    Matching markers against every line claims a stock unit that merely mentions
    the marker in a comment, and a false claim on a clean host is the failure
    this tool promises not to make.
    """
    for line in text.splitlines():
        stripped = line.lstrip()
        if not stripped or stripped[0] in "#;":
            continue
        yield line


def carries_marker(text: str, markers: Sequence[str]) -> bool:
    for line in live_lines(text):
        for marker in markers:
            if marker in line:
                return True
    return False


def _exec_tokens(text: str) -> List[str]:
    """Split a command line the way systemd does, quotes included.

    systemd.syntax(7) lets a quoted argument carry whitespace, so
    ExecStart="/usr/local/bin/my tool" names one binary. Splitting on whitespace
    first cut that path in two, claimed the truncated prefix, and left the real
    binary unclaimed with no error to say so.
    """
    tokens: List[str] = []
    buff: List[str] = []
    quote = ""
    for char in text:
        if quote:
            if char == quote:
                quote = ""
            else:
                buff.append(char)
        elif char in "'\"":
            quote = char
        elif char.isspace():
            if buff:
                tokens.append("".join(buff))
                buff = []
        else:
            buff.append(char)
    if buff:
        tokens.append("".join(buff))
    return tokens


def exec_start_targets(line: str) -> List[str]:
    """Absolute paths started by one ExecStart= line, in any accepted form.

    systemd.syntax(7) allows whitespace on both sides of the '=' and indented
    directives, and systemd.service(5) prefixes the command with '-', '@' or '+'.
    Reading only a column-0 'ExecStart=' loses units systemd itself runs, and a
    unit we do not follow is a binary we quietly clear.
    """
    stripped = line.lstrip()
    if not stripped.startswith("ExecStart"):
        return []
    body = stripped[len("ExecStart"):].lstrip()
    if not body.startswith("="):
        return []
    out: List[str] = []
    for token in _exec_tokens(body[1:]):
        while token and token[0] in EXEC_PREFIXES:
            token = token[1:]
        if token.startswith("/"):
            out.append(os.path.normpath(token))
    return out


# systemd.service(5) command prefixes: ignore failure, argv[0] only, full
# privileges, and the obsolete '!' variant. A path behind one of these is still
# the path systemd starts.
EXEC_PREFIXES = "-@+!"

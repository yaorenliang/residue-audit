"""residue-audit: recompute what an implant left behind.

Nothing in this package acts on a host. Every command reads paths or JSON and
returns a verdict that another implementation could reproduce.
"""

from importlib.metadata import PackageNotFoundError, version as _dist_version

_DISTRIBUTION = "residue-audit"

try:
    # An installed copy knows its own version; pyproject.toml and the wheel are
    # then the same source. Restating the number here would let the two drift.
    __version__ = _dist_version(_DISTRIBUTION)
except PackageNotFoundError:
    # Running from a source checkout that was never installed: fall back to the
    # declared version, which tests/test_cli.py keeps equal to pyproject.toml.
    __version__ = "0.1.0"

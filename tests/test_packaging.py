"""Packaging contracts that the old CI job only pretended to check.

The step was called "zero dependencies" but it ran

    python -c "import sys; assert not [p for p in sys.argv[1:] if p], sys.argv"

which asserts that the interpreter was invoked without extra arguments. It
never opened pyproject.toml, so a dependency could be added and CI stayed green
while every offline or constrained install silently broke. These tests read the
declaration itself. They are deliberately strict about *reading* the file: a
hand-rolled parser for one key is smaller than a TOML dependency, but it has to
fail loudly rather than return "no dependencies" on input it cannot understand,
because "cannot parse" and "declares nothing" must not look alike.
"""

import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PYPROJECT = os.path.join(ROOT, "pyproject.toml")


def _read(path):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def _strip_comment(line):
    out = []
    quoted = None
    for char in line:
        if quoted:
            out.append(char)
            if char == quoted:
                quoted = None
            continue
        if char in ("'", '"'):
            quoted = char
            out.append(char)
            continue
        if char == "#":
            break
        out.append(char)
    return "".join(out).rstrip()


def _sections(text):
    """Split a TOML document into {section name: [lines]}.

    Only the subset the project needs: table headers and key/value lines. Any
    line that is neither is kept, so callers can complain about it.
    """
    sections = {"": []}
    current = ""
    for raw in text.splitlines():
        line = _strip_comment(raw)
        if not line.strip():
            continue
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            current = stripped[1:-1].strip()
            sections.setdefault(current, [])
            continue
        sections.setdefault(current, []).append(stripped)
    return sections


def _dependencies(text):
    """Return the requirement strings declared under [project].dependencies.

    Raises ValueError when the key is present but its array cannot be read to
    the end, so a malformed file never reads as "no dependencies".
    """
    sections = _sections(text)
    lines = sections.get("project", [])
    requirements = []
    collecting = False
    buffer = ""
    for line in lines:
        if not collecting:
            if not line.startswith("dependencies"):
                continue
            key, _, rest = line.partition("=")
            if key.strip() != "dependencies":
                continue
            value = rest.strip()
            if not value.startswith("["):
                raise ValueError("dependencies is not an array: %r" % (value,))
            buffer = value
            collecting = True
        else:
            buffer += " " + line
        if collecting and buffer.rstrip().endswith("]"):
            inner = buffer.strip()[1:-1].strip()
            if inner:
                for item in inner.split(","):
                    item = item.strip()
                    if item:
                        requirements.append(item)
            collecting = False
            buffer = ""
    if collecting:
        raise ValueError("dependencies array is not terminated")
    return requirements


def _project_table(text):
    sections = _sections(text)
    if "project" not in sections:
        raise ValueError("pyproject.toml has no [project] table")
    table = {}
    for line in sections["project"]:
        if line.startswith("dependencies"):
            continue
        key, sep, value = line.partition("=")
        if not sep:
            continue
        table[key.strip()] = value.strip()
    return table


class ProjectMetadataTest(unittest.TestCase):
    def setUp(self):
        self.text = _read(PYPROJECT)

    def test_f17_no_runtime_dependencies(self):
        requirements = _dependencies(self.text)
        self.assertEqual(
            requirements,
            [],
            "the project ships with no dependencies on purpose; declaring %r "
            "breaks every offline install and the claim in README" % (requirements,),
        )

    def test_f17_no_install_requires_side_door(self):
        for name in ("setup.py", "setup.cfg", "requirements.txt"):
            path = os.path.join(ROOT, name)
            self.assertFalse(
                os.path.exists(path),
                "%s would add a second place to declare dependencies" % name,
            )

    def test_f17_requires_python_floor(self):
        table = _project_table(self.text)
        self.assertIn("requires-python", table, "declare the interpreter floor")
        self.assertEqual(table["requires-python"].strip('"'), ">=3.9")

    def test_f17_console_script_points_at_cli_main(self):
        self.assertIn("[project.scripts]", self.text)
        self.assertIn('residue = "residue.cli:main"', self.text)

    def test_f17_dependency_reader_rejects_unterminated_array(self):
        # The gate has to be able to fail: a reader that silently returns []
        # for garbage is the very bug this file exists to prevent.
        broken = '[project]\nname = "x"\ndependencies = [\n  "requests",\n'
        with self.assertRaises(ValueError):
            _dependencies(broken)

    def test_f17_dependency_reader_sees_a_real_declaration(self):
        sample = '[project]\nname = "x"\ndependencies = [\n  "requests>=2",\n  "yara-python",\n]\n'
        self.assertEqual(_dependencies(sample), ['"requests>=2"', '"yara-python"'])

    def test_f17_reader_ignores_commented_out_dependencies(self):
        sample = '[project]\nname = "x"\n# dependencies = ["requests"]\n'
        self.assertEqual(_dependencies(sample), [])


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Check that a release tag names the version in the source tree (release workflow, D13).

Usage: python tools/check_tag.py TAG   (for example ``v1.0.0rc1``)

The tag must be ``v`` followed by ``motp.__version__`` exactly, and the version must be a
release or a release candidate in the form PEP 440 writes it (``1.0.0``, ``1.0.0rc1``):
no development or local versions are released. Exit code 0 when both hold, 1 otherwise,
with one line on stderr that says why. Reads ``src/motp/__init__.py`` as text and imports
nothing from the package.
"""

import re
import sys
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parent.parent
INIT = ROOT / "src" / "motp" / "__init__.py"
VERSION_LINE = re.compile(r'^__version__ = "([^"]+)"$', re.MULTILINE)
RELEASE = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(rc[1-9][0-9]*)?\Z")


def source_version(init: Path = INIT) -> str:
    found = VERSION_LINE.findall(init.read_text(encoding="utf-8"))
    if len(found) != 1:
        raise ValueError(f"{init}: expected one __version__ line, found {len(found)}")
    return str(found[0])


def problem(tag: str, version: str) -> Optional[str]:
    """Why ``tag`` may not release ``version``, or ``None`` when it may."""
    if not RELEASE.match(version):
        return f"version {version!r} is not a release or a release candidate"
    if tag != "v" + version:
        return f"tag {tag!r} does not name the source version {version!r} (expected v{version})"
    return None


def main(argv: Optional[list[str]] = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: check_tag.py TAG", file=sys.stderr)
        return 2
    reason = problem(args[0], source_version())
    if reason is not None:
        print(reason, file=sys.stderr)
        return 1
    print(f"tag {args[0]} releases version {source_version()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

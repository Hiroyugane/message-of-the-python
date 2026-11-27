#!/usr/bin/env python3
"""Build ``dist/motp.pyz`` byte-identically (blueprint section 4.12).

The archive is written with ``zipfile`` directly instead of ``zipapp``: entries are stored
(no compression), sorted by name, carry a fixed timestamp and fixed attributes, and no
bytecode is included. The same source tree therefore gives the same bytes on every machine
and Python version, so anyone can rebuild a tag and compare the SHA-256.

Usage: python tools/build_pyz.py [--output PATH]   (prints the SHA-256 and the path)
"""

import argparse
import hashlib
import os
import sys
import zipfile
from pathlib import Path
from typing import Optional

TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent
# ``-I`` keeps the script's own directory off sys.path; the catalogue compiler lives there.
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))
import compile_catalogs  # noqa: E402

PACKAGE = "motp"
FIXED_TIME = (1980, 1, 1, 0, 0, 0)  # the earliest time a zip entry can carry
FILE_MODE = 0o644
# Text files are normalised to LF so a checkout with CRLF conversion builds the same bytes.
TEXT_SUFFIXES = {".py", ".toml", ".json", ".txt", ".md", ".flf"}
# Catalogue sources are compiled into the archive; neither they nor locally compiled
# copies are packed as they are.
CATALOGUE_SUFFIXES = {".po", ".mo"}

# Root program of the archive: Python runs ``__main__.py`` from the archive root, with the
# archive itself as sys.path[0], which is what makes ``import motp`` work under ``-I -S``.
MAIN_SOURCE = """\
import sys

from motp import entry
from motp.core import deadline

if entry.show_args(sys.argv[1:]) is not None:
    deadline.arm()
sys.exit(entry.main())
"""


def _read(path: Path) -> bytes:
    data = path.read_bytes()
    if path.suffix in TEXT_SUFFIXES:
        data = data.replace(b"\r\n", b"\n")
    return data


def collect(src_root: Path, main_source: str = MAIN_SOURCE) -> dict[str, bytes]:
    """Return archive name -> content for the package plus the root ``__main__.py``.

    Each ``locale/<language>.po`` becomes ``motp/locale/<language>.mo``, compiled here.
    """
    entries: dict[str, bytes] = {"__main__.py": main_source.encode("utf-8")}
    package_dir = src_root / PACKAGE
    for path in sorted(package_dir.rglob("*")):
        if not path.is_file() or "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}:
            continue
        if path.suffix in CATALOGUE_SUFFIXES:
            continue
        entries[f"{PACKAGE}/{path.relative_to(package_dir).as_posix()}"] = _read(path)
    locale_dir = package_dir / "locale"
    if locale_dir.is_dir():
        for name, data in compile_catalogs.compile_all(locale_dir).items():
            entries[f"{PACKAGE}/locale/{name}"] = data
    return entries


def build(src_root: Path, out: Path, main_source: str = MAIN_SOURCE) -> str:
    """Write the archive to ``out`` and return its SHA-256 as hex."""
    entries = collect(src_root, main_source)
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(out.name + ".tmp")
    with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_STORED) as zf:
        for name in sorted(entries):
            info = zipfile.ZipInfo(name, date_time=FIXED_TIME)
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3  # Unix, whatever machine builds
            info.external_attr = (0o100000 | FILE_MODE) << 16
            zf.writestr(info, entries[name])
    os.replace(tmp, out)
    return hashlib.sha256(out.read_bytes()).hexdigest()


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Build the deterministic motp.pyz archive.")
    parser.add_argument("--output", type=Path, default=ROOT / "dist" / "motp.pyz")
    args = parser.parse_args(argv)
    digest = build(ROOT / "src", args.output)
    print(f"{digest}  {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

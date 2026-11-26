#!/usr/bin/env python3
"""Compile the message catalogues ``src/motp/locale/*.po`` to GNU ``.mo`` files.

A small, pure-Python replacement for ``msgfmt``, so building needs nothing outside the
repository and the standard library. It reads the subset of the PO format the project
uses (comments, flags, ``msgid``, ``msgid_plural``, ``msgstr``, ``msgstr[N]``, continued
strings with ``\\\\``, ``\\"``, ``\\n`` and ``\\t`` escapes) and refuses everything else.

Checks while compiling: unique message ids that match the id pattern of
``motp.core.i18n``; the ``Language`` header names the file's language; plural entries have
exactly ``nplurals`` forms; every template uses plain ``{name}`` placeholders only (``{{``
and ``}}`` for literal braces); English has no empty entry. Fuzzy and empty entries of
other languages are left out, so the English text is shown for them.

The output is deterministic: entries sorted by id, no hash table, so the same ``.po`` gives
the same bytes everywhere. ``tools/build_pyz.py`` compiles into the archive directly; this
script also writes ``.mo`` files next to the sources for the unpacked tree (they are not
tracked in git).

Usage: python tools/compile_catalogs.py [--check]
"""

import argparse
import re
import struct
import sys
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parent.parent
LOCALE_DIR = ROOT / "src" / "motp" / "locale"
MO_MAGIC = 0x950412DE
# Must equal motp.core.i18n.MESSAGE_ID (a test compares them).
MESSAGE_ID = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z0-9_]+){1,5}\Z")
PLACEHOLDER_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,31}\Z")
KEYWORD = re.compile(r'(msgid|msgid_plural|msgstr|msgstr\[(\d+)\])\s+(".*")\s*\Z')
# Catalogue text is trusted and not sanitised, so it must not carry anything a terminal
# acts on: only the theme emits escape sequences (4.6).
FORBIDDEN_CATEGORIES = {"Cc", "Cf", "Co", "Cn", "Cs", "Zl", "Zp"}
ESCAPES = {"\\": "\\", '"': '"', "n": "\n", "t": "\t"}


class PoError(ValueError):
    """The catalogue cannot be compiled; the message names file and line."""


@dataclass
class Entry:
    msgid: str = ""
    plural: Optional[str] = None
    forms: dict[int, str] = field(default_factory=dict)
    fuzzy: bool = False
    line: int = 0


def _unquote(token: str, where: str) -> str:
    if len(token) < 2 or token[0] != '"' or token[-1] != '"':
        raise PoError(f"{where}: expected a quoted string")
    out: list[str] = []
    body = token[1:-1]
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == "\\":
            if i + 1 >= len(body) or body[i + 1] not in ESCAPES:
                raise PoError(f"{where}: unsupported escape")
            out.append(ESCAPES[body[i + 1]])
            i += 2
            continue
        if ch == '"':
            raise PoError(f"{where}: unescaped quote")
        out.append(ch)
        i += 1
    return "".join(out)


def parse_po(text: str, name: str = "<po>") -> list[Entry]:
    """Parse PO text into entries, in file order."""
    entries: list[Entry] = []
    current: Optional[Entry] = None
    target: Optional[tuple[str, int]] = None  # ("msgid" | "plural" | "form", index)
    fuzzy = False

    def finish() -> None:
        nonlocal current, target, fuzzy
        if current is not None:
            if not current.forms:
                raise PoError(f"{name}:{current.line}: entry without msgstr")
            entries.append(current)
        current, target, fuzzy = None, None, False

    for number, raw in enumerate(text.splitlines(), 1):
        where = f"{name}:{number}"
        line = raw.strip()
        if not line:
            finish()
            continue
        if line.startswith("#"):
            if line.startswith("#,") and "fuzzy" in [f.strip() for f in line[2:].split(",")]:
                fuzzy = True
            elif line.startswith(("#~", "#|")):
                raise PoError(f"{where}: obsolete or previous entries are not supported")
            continue
        if line.startswith('"'):
            if current is None or target is None:
                raise PoError(f"{where}: continuation without a keyword")
            piece = _unquote(line, where)
            kind, index = target
            if kind == "msgid":
                current.msgid += piece
            elif kind == "plural":
                current.plural = (current.plural or "") + piece
            else:
                current.forms[index] += piece
            continue
        match = KEYWORD.match(line)
        if not match:
            raise PoError(f"{where}: unsupported line")
        keyword, index_text, token = match.groups()
        value = _unquote(token, where)
        if keyword == "msgid":
            flagged = fuzzy  # the flag comment precedes its msgid; finish() resets it
            finish()
            current = Entry(msgid=value, fuzzy=flagged, line=number)
            target = ("msgid", 0)
            continue
        if current is None:
            raise PoError(f"{where}: {keyword} before msgid")
        if keyword == "msgid_plural":
            current.plural = value
            target = ("plural", 0)
        else:
            index = int(index_text) if index_text is not None else 0
            if index in current.forms or (index_text is None) == (current.plural is not None):
                raise PoError(f"{where}: msgstr does not match the entry")
            current.forms[index] = value
            target = ("form", index)
    finish()
    return entries


def _header_fields(header: str) -> dict[str, str]:
    fields = {}
    for line in header.split("\n"):
        key, sep, value = line.partition(":")
        if sep:
            fields[key.strip()] = value.strip()
    return fields


def template_problems(template: str) -> list[str]:
    """Placeholders must be plain ``{name}``; braces otherwise come doubled."""
    problems = []
    i = 0
    while i < len(template):
        ch = template[i]
        if ch in "{}" and template.startswith(ch * 2, i):
            i += 2
            continue
        if ch == "}":
            problems.append(f"lone '}}' at {i}")
        elif ch == "{":
            end = template.find("}", i + 1)
            if end == -1 or not PLACEHOLDER_NAME.match(template[i + 1 : end]):
                problems.append(f"placeholder at {i} is not a plain {{name}}")
            else:
                i = end
        i += 1
    return problems


def check(entries: list[Entry], language: str, name: str) -> tuple[str, list[Entry]]:
    """Validate the entries; return the header text and the entries to compile."""
    header_entries = [e for e in entries if e.msgid == ""]
    if len(header_entries) != 1:
        raise PoError(f"{name}: exactly one header entry is required")
    header = header_entries[0].forms[0]
    fields = _header_fields(header)
    if fields.get("Language") != language:
        raise PoError(f"{name}: Language header must be {language!r}")
    plural_match = re.match(r"nplurals=(\d+);", fields.get("Plural-Forms", ""))
    if not plural_match:
        raise PoError(f"{name}: Plural-Forms header with nplurals is required")
    nplurals = int(plural_match.group(1))

    seen: set[str] = set()
    kept: list[Entry] = []
    for entry in entries:
        if entry.msgid == "":
            continue
        where = f"{name}:{entry.line}"
        if not MESSAGE_ID.match(entry.msgid):
            raise PoError(f"{where}: {entry.msgid!r} is not a valid message id")
        if entry.msgid in seen:
            raise PoError(f"{where}: duplicate message id {entry.msgid!r}")
        seen.add(entry.msgid)
        expected = list(range(nplurals)) if entry.plural is not None else [0]
        if sorted(entry.forms) != expected:
            raise PoError(f"{where}: expected {len(expected)} translation form(s)")
        empty = any(not form for form in entry.forms.values())
        if language == "en" and (empty or entry.fuzzy):
            raise PoError(f"{where}: the English catalogue must be complete and not fuzzy")
        for form in entry.forms.values():
            for problem in template_problems(form):
                raise PoError(f"{where}: {problem}")
            if any(unicodedata.category(c) in FORBIDDEN_CATEGORIES for c in form):
                raise PoError(f"{where}: control, format or unassigned character in the text")
        if not empty and not entry.fuzzy:
            kept.append(entry)
    return header, kept


def compile_mo(header: str, entries: list[Entry]) -> bytes:
    """Write a GNU ``.mo`` file (little endian, revision 0, no hash table)."""
    pairs: list[tuple[bytes, bytes]] = [(b"", header.encode("utf-8"))]
    for entry in entries:
        key = entry.msgid if entry.plural is None else f"{entry.msgid}\x00{entry.plural}"
        value = "\x00".join(entry.forms[i] for i in sorted(entry.forms))
        pairs.append((key.encode("utf-8"), value.encode("utf-8")))
    pairs.sort(key=lambda pair: pair[0])
    count = len(pairs)
    ids_at = 28
    strs_at = ids_at + 8 * count
    data_at = strs_at + 8 * count
    blob = bytearray()
    id_table: list[tuple[int, int]] = []
    str_table: list[tuple[int, int]] = []
    for table, index in ((id_table, 0), (str_table, 1)):
        for pair in pairs:
            table.append((len(pair[index]), data_at + len(blob)))
            blob += pair[index] + b"\x00"
    out = bytearray(struct.pack("<7I", MO_MAGIC, 0, count, ids_at, strs_at, 0, data_at))
    for length, offset in id_table + str_table:
        out += struct.pack("<2I", length, offset)
    return bytes(out + blob)


def compile_file(po_path: Path) -> bytes:
    text = po_path.read_bytes().decode("utf-8").replace("\r\n", "\n")
    entries = parse_po(text, po_path.name)
    header, kept = check(entries, po_path.stem, po_path.name)
    return compile_mo(header, kept)


def compile_all(locale_dir: Path = LOCALE_DIR) -> dict[str, bytes]:
    """Return ``<language>.mo`` -> bytes for every ``.po`` in ``locale_dir``."""
    return {f"{po.stem}.mo": compile_file(po) for po in sorted(locale_dir.glob("*.po"))}


def write_all(locale_dir: Path = LOCALE_DIR) -> list[Path]:
    """Compile and write the ``.mo`` files; a file is rewritten only if its bytes change."""
    written = []
    for name, data in compile_all(locale_dir).items():
        target = locale_dir / name
        if not target.exists() or target.read_bytes() != data:
            target.write_bytes(data)
            written.append(target)
    return written


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Compile the .po catalogues to .mo files.")
    parser.add_argument("--check", action="store_true", help="validate only, write nothing")
    args = parser.parse_args(argv)
    try:
        if args.check:
            names = sorted(compile_all())
            print(f"ok: {len(names)} catalogue(s) valid: {', '.join(names)}")
        else:
            written = write_all()
            print(f"ok: {len(written)} catalogue(s) written")
    except (PoError, UnicodeDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

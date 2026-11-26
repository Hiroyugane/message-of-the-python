#!/usr/bin/env python3
"""Write the bundled MOTP header fonts and import FIGlet's Big and Small (blueprint D15).

``motp-block`` (six rows) and ``motp-block-small`` (three rows) are drawn for MOTP: each
glyph is a pixel mask in this file, and every character of the font file is computed from
the masks. No existing font file is copied. Both are covered by the project's
GPL-3.0-or-later (``render/fonts/LICENSE.txt``).

* ``motp-block``: a mask pixel is one cell drawn as a full block; strokes are two pixels
  wide. The drop shadow is computed: the shape is extended one cell to the right and one
  down, and every cell of that extension the shape does not cover gets a double line
  that traces the extension's outline (see ``shadow``).
* ``motp-block-small``: a three by five pixel mask per glyph, two pixel rows per text row
  drawn with the half blocks, one blank column after each glyph.

Capitals, digits, ``-``, ``.``, ``_``, the space and ``?`` are drawn. Lower-case letters
use the capital glyphs, so every glyph has the font's full height; every other required
character of the FIGfont standard draws ``?``. Both fonts use the full-width layout.

``--import-figlet DIR`` copies ``big.flf`` and ``small.flf`` from FIGlet's font directory
(Debian 12 package ``figlet`` 2.2.5-3+b1, ``/usr/share/figlet``) after checking their
SHA-256 against the values below, removes the e-mail addresses from the comment lines
(the repository carries none; the names stay), and adds a comment line naming that
change, as the fonts' permission line asks of a modifier. Glyphs stay unchanged.

Usage: python tools/make_fonts.py [--check] [--import-figlet DIR]
       (``--check`` exits 1 if a generated file is stale)
"""

import argparse
import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FONT_DIR = ROOT / "src" / "motp" / "render" / "fonts"
HARDBLANK = "$"
ENDMARK = "@"
# Required characters of a FIGfont: ASCII 32 to 126, then the seven Deutsch characters.
REQUIRED = [*range(32, 127), 196, 214, 220, 228, 246, 252, 223]

FIGLET_PACKAGE = "Debian 12 figlet 2.2.5-3+b1"
FIGLET_SHA256 = {
    "big.flf": "0065328daf2a6eb49ff274f8d27a195e7b748cb51cad992b0aa96839ccb5169d",
    "small.flf": "c275f3cf053af2eec87804fe60ad5cc865dbb25ea65d5cbbe09a27f332c714f0",
}
FIGLET_NOTE = (
    "Modified for MOTP (message-of-the-python), 2026-11-24: e-mail addresses removed "
    "from these comment lines; glyphs unchanged."
)
EMAIL = re.compile(r"\s*<[^<>@\s]+@[^<>@\s]+>")

# Masks: "@X" starts glyph X ("@SPACE" the space); the next lines are its rows, "#" a
# pixel and "." none. Rows of one glyph have the same length.
BLOCK = """
@A
.#####.
##...##
#######
##...##
##...##
@B
######.
##...##
######.
##...##
######.
@C
.######
##.....
##.....
##.....
.######
@D
######.
##...##
##...##
##...##
######.
@E
#######
##.....
#####..
##.....
#######
@F
#######
##.....
#####..
##.....
##.....
@G
.######
##.....
##..###
##...##
.######
@H
##...##
##...##
#######
##...##
##...##
@I
######
..##..
..##..
..##..
######
@J
.....##
.....##
.....##
##...##
.#####.
@K
##...##
##..##.
#####..
##..##.
##...##
@L
##.....
##.....
##.....
##.....
#######
@M
###..###
########
##.##.##
##....##
##....##
@N
###...##
####..##
##.##.##
##..####
##...###
@O
.#####.
##...##
##...##
##...##
.#####.
@P
######.
##...##
######.
##.....
##.....
@Q
.#####.
##...##
##...##
##..##.
.###.##
@R
######.
##...##
######.
##..##.
##...##
@S
.######
##.....
.#####.
.....##
######.
@T
########
...##...
...##...
...##...
...##...
@U
##...##
##...##
##...##
##...##
.#####.
@V
##...##
##...##
##...##
.##.##.
..###..
@W
##....##
##....##
##.##.##
########
.##..##.
@X
##...##
.##.##.
..###..
.##.##.
##...##
@Y
##....##
.##..##.
..####..
...##...
...##...
@Z
#######
....##.
..###..
.##....
#######
@0
.#####.
##..###
##.#.##
###..##
.#####.
@1
.##
###
.##
.##
.##
@2
######.
.....##
.#####.
##.....
#######
@3
######.
.....##
.#####.
.....##
######.
@4
##...##
##...##
#######
.....##
.....##
@5
#######
##.....
######.
.....##
######.
@6
.######
##.....
######.
##...##
.#####.
@7
#######
.....##
....##.
...##..
...##..
@8
.#####.
##...##
.#####.
##...##
.#####.
@9
.#####.
##...##
.######
.....##
######.
@-
.....
.....
#####
.....
.....
@.
..
..
..
..
##
@_
......
......
......
......
######
@SPACE
...
...
...
...
...
@?
######.
.....##
...###.
.......
...##..
"""

SMALL = """
@A
###
#.#
###
#.#
#.#
@B
##.
#.#
##.
#.#
##.
@C
###
#..
#..
#..
###
@D
##.
#.#
#.#
#.#
##.
@E
###
#..
##.
#..
###
@F
###
#..
##.
#..
#..
@G
###
#..
#.#
#.#
###
@H
#.#
#.#
###
#.#
#.#
@I
###
.#.
.#.
.#.
###
@J
..#
..#
..#
#.#
###
@K
#.#
#.#
##.
#.#
#.#
@L
#..
#..
#..
#..
###
@M
#...#
##.##
#.#.#
#...#
#...#
@N
#..#
##.#
#.##
#..#
#..#
@O
###
#.#
#.#
#.#
###
@P
###
#.#
###
#..
#..
@Q
###
#.#
#.#
###
..#
@R
##.
#.#
##.
#.#
#.#
@S
###
#..
###
..#
###
@T
###
.#.
.#.
.#.
.#.
@U
#.#
#.#
#.#
#.#
###
@V
#.#
#.#
#.#
#.#
.#.
@W
#...#
#...#
#.#.#
##.##
#...#
@X
#.#
#.#
.#.
#.#
#.#
@Y
#.#
#.#
.#.
.#.
.#.
@Z
###
..#
.#.
#..
###
@0
###
#.#
#.#
#.#
###
@1
.#.
##.
.#.
.#.
###
@2
###
..#
###
#..
###
@3
###
..#
###
..#
###
@4
#.#
#.#
###
..#
..#
@5
###
#..
###
..#
###
@6
###
#..
###
#.#
###
@7
###
..#
..#
..#
..#
@8
###
#.#
###
#.#
###
@9
###
#.#
###
..#
###
@-
...
...
###
...
...
@.
.
.
.
.
#
@_
...
...
...
...
###
@SPACE
..
..
..
..
..
@?
###
..#
.##
...
.#.
"""

# Shadow lines by the directions they connect: up, down, left, right.
LINES = {
    frozenset("ud"): "║",
    frozenset("u"): "║",
    frozenset("d"): "║",
    frozenset("lr"): "═",
    frozenset("l"): "═",
    frozenset("r"): "═",
    frozenset("dr"): "╔",
    frozenset("dl"): "╗",
    frozenset("ur"): "╚",
    frozenset("ul"): "╝",
    frozenset("udr"): "╠",
    frozenset("udl"): "╣",
    frozenset("dlr"): "╦",
    frozenset("ulr"): "╩",
    frozenset("udlr"): "╬",
}
STEP = {"u": (-1, 0), "d": (1, 0), "l": (0, -1), "r": (0, 1)}
OPPOSITE = {"u": "d", "d": "u", "l": "r", "r": "l"}
FULL = "█"
HALF = {(True, True): "█", (True, False): "▀", (False, True): "▄", (False, False): " "}


def parse_masks(text: str, height: int) -> dict[str, list[str]]:
    lines = text.split("\n")
    masks: dict[str, list[str]] = {}
    i = 0
    while i < len(lines):
        line = lines[i]
        if line == "@SPACE":
            line = "@ "
        if line.startswith("@") and len(line) == 2:
            rows = lines[i + 1 : i + 1 + height]
            if len(rows) != height or any(len(r) != len(rows[0]) for r in rows):
                raise ValueError(f"mask {line[1]!r} is not {height} rows of one length")
            if set("".join(rows)) - {"#", "."}:
                raise ValueError(f"mask {line[1]!r} uses a character other than # and .")
            masks[line[1]] = rows
            i += 1 + height
            continue
        if line.strip():
            raise ValueError(f"stray line in masks: {line!r}")
        i += 1
    return masks


def shadow(mask: list[str]) -> list[str]:
    """The mask in full blocks with its computed drop shadow: one row and column more.

    The shadow is the shape's outline on its lit-away sides: every right and every bottom
    edge of a pixel, moved half a cell right and down, so that it runs from cell centre to
    cell centre. Each edge links two cells; a cell gets the double line that joins its
    links. A line that ends in mid-air is led into the shape: straight on when a pixel
    continues it, otherwise into the pixel that casts it (left of a vertical line, above
    a horizontal one). Cells covered by the shape stay full blocks.
    """
    rows_n, cols_n = len(mask), len(mask[0])

    def pixel(r: int, c: int) -> bool:
        return 0 <= r < rows_n and 0 <= c < cols_n and mask[r][c] == "#"

    links: dict[tuple[int, int], set[str]] = {}

    def link(a: tuple[int, int], b: tuple[int, int], da: str) -> None:
        links.setdefault(a, set()).add(da)
        links.setdefault(b, set()).add(OPPOSITE[da])

    for r in range(rows_n):
        for c in range(cols_n):
            if not pixel(r, c):
                continue
            if not pixel(r, c + 1):  # right edge: from cell (r, c+1) down to (r+1, c+1)
                link((r, c + 1), (r + 1, c + 1), "d")
            if not pixel(r + 1, c):  # bottom edge: from cell (r+1, c) right to (r+1, c+1)
                link((r + 1, c), (r + 1, c + 1), "r")

    rows = []
    for r in range(rows_n + 1):
        row = []
        for c in range(cols_n + 1):
            if pixel(r, c):
                row.append(FULL)
                continue
            dirs = set(links.get((r, c), ()))
            if not dirs:
                row.append(" ")
                continue
            if len(dirs) == 1:
                (only,) = dirs
                cast = "l" if only in "ud" else "u"
                for d in (OPPOSITE[only], cast):
                    if pixel(r + STEP[d][0], c + STEP[d][1]):
                        dirs.add(d)
                        break
            row.append(LINES[frozenset(dirs)])
        rows.append("".join(row))
    return rows


def halves(mask: list[str]) -> list[str]:
    """A five-row mask as three rows of half blocks, with a one-column gap."""
    padded = [*mask, "." * len(mask[0])]
    return [
        "".join(HALF[(top == "#", low == "#")] for top, low in zip(padded[r], padded[r + 1])) + " "
        for r in range(0, 6, 2)
    ]


def block_glyphs() -> dict[str, list[str]]:
    return {ch: shadow(m) for ch, m in parse_masks(BLOCK, 5).items()}


def small_glyphs() -> dict[str, list[str]]:
    return {ch: halves(m) for ch, m in parse_masks(SMALL, 5).items()}


FONTS = {
    "motp-block": (
        block_glyphs,
        6,
        "MOTP block: block letters with a computed drop shadow, six rows.",
    ),
    "motp-block-small": (
        small_glyphs,
        3,
        "MOTP block small: compact half-block letters, three rows.",
    ),
}


def font_text(name: str) -> str:
    build, height, description = FONTS[name]
    glyphs = build()
    fallback = glyphs["?"]
    max_len = max(len(r) for rows in glyphs.values() for r in rows) + 2
    comments = [
        description,
        "Part of MOTP, the message of the python: GPL-3.0-or-later, see LICENSE.txt.",
        "Generated by tools/make_fonts.py from its pixel masks; edit them there.",
    ]
    # flf2a, hardblank, height, baseline, max length, old layout (-1: full width),
    # comment lines, print direction, full layout (0: full width), code-tagged count.
    out = [f"flf2a{HARDBLANK} {height} {height} {max_len} -1 {len(comments)} 0 0 0", *comments]
    for code in REQUIRED:
        ch = chr(code)
        rows = glyphs.get(ch.upper() if ch.isascii() else ch) or fallback
        for n, row in enumerate(rows):
            # Blanks become hardblanks so a glyph's right edge survives FIGlet's
            # stripping of trailing blanks.
            row = row.replace(" ", HARDBLANK)
            end = ENDMARK * 2 if n == len(rows) - 1 else ENDMARK
            out.append(row + end)
    return "\n".join(out) + "\n"


def import_figlet(source: Path) -> list[Path]:
    """Copy Big and Small from FIGlet's font directory with the comment change only."""
    written = []
    for name, digest in FIGLET_SHA256.items():
        data = (source / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != digest:
            raise SystemExit(f"{name}: SHA-256 differs from {FIGLET_PACKAGE}; not imported")
        lines = data.decode("utf-8").split("\n")
        header = lines[0].split(" ")
        comments = int(header[5])
        body = [EMAIL.sub("", line) for line in lines[1 : 1 + comments]]
        if any("@" in line for line in body):
            raise SystemExit(f"{name}: an address is left in the comment lines")
        header[5] = str(comments + 1)
        out = [" ".join(header), *body, FIGLET_NOTE, *lines[1 + comments :]]
        path = FONT_DIR / name
        path.write_bytes("\n".join(out).encode("utf-8"))
        written.append(path)
    return written


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(description="Write the bundled header fonts.")
    parser.add_argument("--check", action="store_true", help="fail if a file is stale")
    parser.add_argument(
        "--import-figlet", type=Path, metavar="DIR", help="copy big.flf and small.flf from DIR"
    )
    args = parser.parse_args(argv)
    if args.import_figlet is not None:
        for path in import_figlet(args.import_figlet):
            print(f"imported: {path.relative_to(ROOT).as_posix()}")
    stale = []
    for name in sorted(FONTS):
        path = FONT_DIR / f"{name}.flf"
        text = font_text(name)
        current = path.read_bytes().decode("utf-8") if path.exists() else None
        if current == text:
            continue
        stale.append(path)
        if not args.check:
            path.write_bytes(text.encode("utf-8"))
    for path in stale:
        print(f"{'stale' if args.check else 'wrote'}: {path.relative_to(ROOT).as_posix()}")
    return 1 if args.check and stale else 0


if __name__ == "__main__":
    sys.exit(main())

"""A small FIGfont 2 reader and FIGlet's horizontal layout (blueprint D15, D35).

Used for the bundled header fonts (read through the package loader by the renderer) and
for an admin's font in ``/etc/motp/fonts/`` (read by the collector after the ownership
check, never by the renderer; its glyphs travel in ``render.json``). The input is treated
as untrusted either way: sizes, heights and widths are bounded, every drawn character must
be one printable terminal cell, and a malformed file is refused as a whole (``parse``
returns ``None``) rather than half-drawn.

Supported: the header line with the old and the full layout, comment lines, the required
characters (ASCII 32 to 126 and the seven Deutsch characters), hardblanks, and the
horizontal layouts full width, kerning and smushing with the controlled rules 1 to 6 or
universal smushing, as FIGlet 2.2.5 draws them (``layout`` mirrors its ``smushamt`` and
``smushem``). Code-tagged characters after the required set are ignored; vertical layout
does not apply to a one-line header.
"""

from dataclasses import dataclass
from typing import Optional

from motp.core.sanitize import char_width, theme_char

MAX_FONT_BYTES = 256 * 1024
MAX_HEIGHT = 16
MAX_GLYPH_WIDTH = 64
MAX_COMMENT_LINES = 256
REQUIRED = (*range(32, 127), 196, 214, 220, 228, 246, 252, 223)
DRAWN = tuple(chr(c) for c in range(32, 127))  # what a header can show (it is ASCII)

# Horizontal layout bits of the full layout (FIGfont 2 standard).
SM_EQUAL = 1
SM_LOWLINE = 2
SM_HIERARCHY = 4
SM_PAIR = 8
SM_BIGX = 16
SM_HARDBLANK = 32
SM_KERN = 64
SM_SMUSH = 128
HORIZONTAL_BITS = 255


@dataclass(frozen=True)
class Font:
    name: str
    height: int
    hardblank: str
    smush: int  # horizontal layout bits; 0 is full width
    glyphs: dict[str, tuple[str, ...]]

    @property
    def full_width(self) -> bool:
        return self.smush & (SM_SMUSH | SM_KERN) == 0

    @property
    def ascii_only(self) -> bool:
        return all(row.isascii() for glyph in self.glyphs.values() for row in glyph)


def smush_mode(old_layout: int, full_layout: Optional[int]) -> int:
    """The horizontal layout FIGlet uses for a font's header values."""
    if full_layout is not None:
        return full_layout & HORIZONTAL_BITS
    if old_layout == 0:
        return SM_KERN
    if old_layout < 0:
        return 0
    return (old_layout & 31) | SM_SMUSH


def parse(name: str, data: bytes, max_bytes: int = MAX_FONT_BYTES) -> Optional[Font]:
    """Parse a FIGfont file; ``None`` if it is malformed or out of bounds."""
    if len(data) > max_bytes:
        return None
    try:
        lines = data.decode("utf-8").split("\n")
    except UnicodeDecodeError:
        return None
    lines = [line[:-1] if line.endswith("\r") else line for line in lines]
    header = lines[0].split()
    if len(header) < 6 or not header[0].startswith("flf2a") or len(header[0]) != 6:
        return None
    hardblank = header[0][5]
    if not theme_char(hardblank) or hardblank == " ":
        return None
    try:
        values = [int(v) for v in header[1:8]]
    except ValueError:
        return None
    height, _baseline, _max_len, old_layout, comments = values[:5]
    full_layout = values[6] if len(values) >= 7 else None
    if not (1 <= height <= MAX_HEIGHT and 0 <= comments <= MAX_COMMENT_LINES):
        return None
    if not -1 <= old_layout <= 63 or (full_layout is not None and not 0 <= full_layout < 2**15):
        return None
    pos = 1 + comments
    glyphs: dict[str, tuple[str, ...]] = {}
    for code in REQUIRED:
        rows = lines[pos : pos + height]
        if len(rows) != height:
            return None
        glyph = _glyph(rows, hardblank)
        if glyph is None:
            return None
        glyphs[chr(code)] = glyph
        pos += height
    return Font(name, height, hardblank, smush_mode(old_layout, full_layout), glyphs)


def _glyph(rows: list[str], hardblank: str) -> Optional[tuple[str, ...]]:
    """Strip trailing blanks, then the endmark run, as FIGlet does; check every cell."""
    out = []
    for row in rows:
        stripped = row.rstrip(" \t")
        if not stripped:
            return None
        stripped = stripped.rstrip(stripped[-1])
        if len(stripped) > MAX_GLYPH_WIDTH or not all(valid_cell(ch) for ch in stripped):
            return None
        out.append(stripped)
    if any(len(r) != len(out[0]) for r in out):
        return None
    return tuple(out)


def valid_cell(ch: str) -> bool:
    """One drawn cell of a glyph: a space or one printable, single-width character."""
    return ch == " " or (theme_char(ch) and char_width(ch) == 1)


# --- FIGlet's horizontal layout -----------------------------------------------------------


def _smushem(lch: str, rch: str, font: Font, prev_width: int, cur_width: int) -> str:
    """The character two overlapping cells become, or ``""`` if they may not overlap."""
    if lch == " ":
        return rch
    if rch == " ":
        return lch
    if prev_width < 2 or cur_width < 2:
        return ""
    mode = font.smush
    if mode & SM_SMUSH == 0:
        return ""  # kerning
    hard = font.hardblank
    if mode & 63 == 0:  # universal smushing
        if lch == hard:
            return rch
        if rch == hard:
            return lch
        return rch
    if mode & SM_HARDBLANK and lch == hard and rch == hard:
        return lch
    if hard in (lch, rch):
        return ""
    if mode & SM_EQUAL and lch == rch:
        return lch
    if mode & SM_LOWLINE:
        if lch == "_" and rch in "|/\\[]{}()<>":
            return rch
        if rch == "_" and lch in "|/\\[]{}()<>":
            return lch
    if mode & SM_HIERARCHY:
        for low, high in (("|", "/\\[]{}()<>"), ("/\\", "[]{}()<>"), ("[]", "{}()<>"),
                          ("{}", "()<>"), ("()", "<>")):  # fmt: skip
            if lch in low and rch in high:
                return rch
            if rch in low and lch in high:
                return lch
    if mode & SM_PAIR and {lch, rch} in ({"[", "]"}, {"{", "}"}, {"(", ")"}):
        return "|"
    if mode & SM_BIGX:
        if lch == "/" and rch == "\\":
            return "|"
        if lch == "\\" and rch == "/":
            return "Y"
        if lch == ">" and rch == "<":
            return "X"
    return ""


def _overlap(rows: list[str], glyph: tuple[str, ...], font: Font, prev_width: int) -> int:
    """How many columns ``glyph`` may slide into ``rows`` (FIGlet's ``smushamt``)."""
    if font.full_width:
        return 0
    cur_width = len(glyph[0])
    best = cur_width
    length = len(rows[0])
    for line, part in zip(rows, glyph):
        end = len(line.rstrip(" ")) - 1  # last drawn column, -1 for none
        ch1 = line[end] if end >= 0 else ""
        start = len(part) - len(part.lstrip(" "))
        ch2 = part[start] if start < len(part) else ""
        amount = start + length - 1 - max(end, 0)
        if not ch1 or (ch2 and _smushem(ch1, ch2, font, prev_width, cur_width)):
            amount += 1
        best = min(best, amount)
    return max(best, 0)


def layout(font: Font, text: str, fallback: str = "?") -> list[str]:
    """``text`` drawn as FIGlet draws it, hardblanks shown as spaces, right ends trimmed.

    A character the font lacks is drawn as ``fallback``.
    """
    rows = [""] * font.height
    prev_width = 0
    spare = font.glyphs.get(fallback, ("",) * font.height)
    for ch in text:
        glyph = font.glyphs.get(ch, spare)
        cur_width = len(glyph[0])
        amount = min(_overlap(rows, glyph, font, prev_width), cur_width)
        length = len(rows[0])
        out = []
        for line, part in zip(rows, glyph):
            head = list(line)
            for k in range(amount):
                pos = length - amount + k
                if pos >= 0:
                    head[pos] = _smushem(head[pos], part[k], font, prev_width, cur_width) or " "
            out.append("".join(head) + part[amount:])
        rows = out
        prev_width = cur_width
    return [r.replace(font.hardblank, " ").rstrip() for r in rows]

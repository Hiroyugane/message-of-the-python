"""The only place external text is cleaned (blueprint 5.5, threat T6).

Every string that comes from outside the package passes through ``sanitize`` before it is
stored or shown: hostnames, user names, unit and package names, plugin output, and the
content of every cache file when it is read back. The result is one line of printable text
that cannot move the cursor, change colours, reorder text, hide characters, or draw a frame
or a dotted row of its own, and that fits a fixed number of terminal cells.

Width follows 4.6: wide and fullwidth characters count two cells, combining marks zero,
everything else (including ambiguous-width characters) one.

The emoji, frame and filler tables are fixed code point ranges rather than a lookup in
``unicodedata``, so the result does not depend on the interpreter's Unicode version, with
one exception: unassigned code points are judged by the running interpreter's database.
"""

import unicodedata
from bisect import bisect_right
from typing import Union

REPLACEMENT = "\ufffd"
ASCII_REPLACEMENT = "?"
ELLIPSIS = "\u2026"
ASCII_ELLIPSIS = "..."

# Field limits in terminal cells. The renderer may cut further to fit the layout.
LABEL_CELLS = 40
VALUE_CELLS = 120
TEXT_CELLS = 160
HINT_CELLS = 160
PARAM_CELLS = 64

# Work bounds: at most this much input is looked at, whatever the caller passes.
MAX_INPUT_BYTES = 16384
MAX_INPUT_CHARS = 4096
MAX_COMBINING = 2  # combining marks allowed per base character
MAX_RUN = 3  # longest run of dot-like, or of dash- and frame-like, characters

# Characters that break a line become a space instead of vanishing, so words stay apart.
_LINE_BREAKS = frozenset("\t\n\v\f\r\x1c\x1d\x1e\x1f\x85\u2028\u2029")

# Invisible letters and marks that are not format characters by category (5.5).
_INVISIBLE = frozenset(
    "\u034f"  # combining grapheme joiner
    "\u115f\u1160"  # Hangul choseong and jungseong fillers
    "\u17b4\u17b5"  # Khmer inherent vowels
    "\u180b\u180c\u180d\u180f"  # Mongolian free variation selectors
    "\u2800"  # Braille pattern blank
    "\u3164"  # Hangul filler
    "\uffa0"  # halfwidth Hangul filler
)

# Sorted, inclusive code point ranges.
_VARIATION_SELECTORS = ((0xFE00, 0xFE0F), (0xE0100, 0xE01EF))
_FRAME = (
    (0x239B, 0x23BD),  # bracket pieces, box lines and scan lines (Miscellaneous Technical)
    (0x23D0, 0x23D0),  # vertical line extension
    (0x2500, 0x257F),  # box drawing
    (0x2580, 0x259F),  # block elements
    (0x25A0, 0x25FF),  # geometric shapes: squares and bars that could fake a usage bar
    (0xFE31, 0xFE32),  # vertical dashes
    (0xFE49, 0xFE4F),  # dashed and wavy overlines and low lines
    (0xFF5C, 0xFF5C),  # fullwidth vertical line
    (0xFFE3, 0xFFE3),  # fullwidth macron
    (0xFFE8, 0xFFEE),  # halfwidth light vertical, arrows and shapes
    (0x1FB00, 0x1FBFF),  # symbols for legacy computing (sextants, more blocks)
)
_EMOJI = (
    (0x203C, 0x203C),
    (0x2049, 0x2049),
    (0x231A, 0x231B),
    (0x23E9, 0x23F3),
    (0x23F8, 0x23FA),
    (0x2600, 0x27BF),  # miscellaneous symbols and dingbats
    (0x2B00, 0x2BFF),  # miscellaneous symbols and arrows
    (0x3030, 0x3030),
    (0x303D, 0x303D),
    (0x3297, 0x3297),
    (0x3299, 0x3299),
    (0x1F000, 0x1FAFF),  # tiles, cards, regional indicators, pictographs, emoticons, ...
)

# Run classes: dot-like characters form one class (an ellipsis counts as its dots);
# dash-like and frame-like ASCII characters form another, so alternating them ("+-=+-=")
# cannot draw a rule either.
_DOT_WEIGHT = {"\u2026": 3, "\u2025": 2, "\u22ef": 3}
_DOTS = frozenset(".\xb7\u2024\u2025\u2026\u2027\u2219\u22c5\u22ef\u30fb\uff0e\uff65")
_FRAMELIKE = frozenset(
    "-=_|+~*#:\u2010\u2011\u2012\u2013\u2014\u2015\u2212\u23af\u2e3a\u2e3b\ufe58\ufe63\uff0d"
)
_RUN_CHARS = "".join(sorted(_DOTS | _FRAMELIKE))

_COMBINING_CATEGORIES = frozenset({"Mn", "Mc", "Me"})


def _is_mark(ch: str) -> bool:
    """A combining mark, or a conjoining Hangul vowel or final that stacks like one."""
    cp = ord(ch)
    return (
        unicodedata.category(ch) in _COMBINING_CATEGORIES
        or 0x1160 <= cp <= 0x11FF
        or 0xD7B0 <= cp <= 0xD7FF
    )


class _Ranges:
    """Sorted, non-overlapping inclusive ranges with a binary-search membership test."""

    def __init__(self, ranges: tuple[tuple[int, int], ...]) -> None:
        self._ranges = tuple(sorted(ranges))
        self._starts = [start for start, _ in self._ranges]

    def __contains__(self, cp: int) -> bool:
        i = bisect_right(self._starts, cp) - 1
        return i >= 0 and self._ranges[i][0] <= cp <= self._ranges[i][1]


_IS_VARIATION_SELECTOR = _Ranges(_VARIATION_SELECTORS)
_IS_FRAME = _Ranges(_FRAME)
_IS_EMOJI = _Ranges(_EMOJI)


def char_width(ch: str) -> int:
    """Terminal cells of one character (4.6)."""
    cp = ord(ch)
    category = unicodedata.category(ch)
    if category in ("Mn", "Me", "Cf", "Cc") or 0x1160 <= cp <= 0x11FF or 0xD7B0 <= cp <= 0xD7FF:
        return 0
    if unicodedata.east_asian_width(ch) in ("W", "F"):
        return 2
    return 1


def cell_width(text: str) -> int:
    """Terminal cells of a string, by ``char_width``."""
    return sum(char_width(ch) for ch in text)


def _run_class(ch: str) -> str:
    if ch in _DOTS:
        return "."
    if ch in _FRAMELIKE:
        return "-"
    return ""


def _map(ch: str, replacement: str) -> str:
    """Return the replacement for one character: itself, a space, a marker, or nothing."""
    cp = ord(ch)
    if ch == "\x00" or 0xD800 <= cp <= 0xDFFF:
        return replacement
    if ch in _LINE_BREAKS:
        return " "
    category = unicodedata.category(ch)
    if category in ("Cc", "Cf", "Co", "Cn", "Cs", "Zl", "Zp"):
        return ""
    if ch in _INVISIBLE or cp in _IS_VARIATION_SELECTOR:
        return ""
    # Enclosing marks draw boxes and circles around their base.
    if cp in _IS_FRAME or cp in _IS_EMOJI or category == "Me":
        return replacement
    if category == "Zs":
        return " "
    return ch


def _clean(text: str, replacement: str) -> list[str]:
    out: list[str] = []
    marks = 0
    for ch in text:
        piece = _map(ch, replacement)
        if not piece:
            continue
        if _is_mark(piece):
            marks += 1
            if marks > MAX_COMBINING:
                continue
        else:
            marks = 0
        out.append(piece)
    return out


def _collapse(chars: list[str]) -> list[str]:
    """Collapse whitespace to one space and dot or frame-like runs to ``MAX_RUN``.

    Neither a single space nor a combining mark ends a run, so ``". . . ."`` and dots
    carrying marks are cut like plain dots. Marks on a run character are dropped.
    """
    out: list[str] = []
    run_class = ""
    run = 0
    for ch in chars:
        if _is_mark(ch):
            prev = out[-1] if out else ""
            if _run_class(prev) or (prev == " " and run_class):
                continue
            out.append(ch)
            continue
        if ch == " ":
            if out and out[-1] != " ":
                out.append(ch)
            continue
        cls = _run_class(ch)
        weight = _DOT_WEIGHT.get(ch, 1)
        if cls and cls == run_class:
            if run + weight > MAX_RUN:
                continue
            run += weight
        else:
            run_class, run = cls, weight
        out.append(ch)
    return out


# German letters have a customary ASCII spelling; NFKD alone would turn "für" into "fur"
# and lose the sharp s altogether (D19: German output on ASCII terminals).
_SPELLED = {"ä": "ae", "ö": "oe", "ü": "ue", "Ä": "Ae", "Ö": "Oe", "Ü": "Ue", "ß": "ss", "ẞ": "SS"}


def _to_ascii(chars: list[str]) -> list[str]:
    out: list[str] = []
    for ch in chars:
        if ord(ch) < 0x80:
            out.append(ch)
            continue
        if ch in _SPELLED:
            out.extend(_SPELLED[ch])
            continue
        for piece in unicodedata.normalize("NFKD", ch):
            if ord(piece) < 0x80:
                # Compatibility forms may decompose to a control or a line break.
                out.append(piece if piece.isprintable() else " ")
            elif unicodedata.category(piece) not in _COMBINING_CATEGORIES:
                out.append(ASCII_REPLACEMENT)
    return out


def truncate(text: str, limit: int, *, ascii_only: bool = False) -> str:
    """Cut ``text`` to at most ``limit`` cells, ending in an ellipsis when it was cut.

    A base character is never separated from its combining marks. Dots and frame-like
    characters before the cut are dropped, so the ellipsis never lengthens a run and a
    second pass gives the same text.
    """
    if cell_width(text) <= limit:
        return text
    marker = ASCII_ELLIPSIS if ascii_only else ELLIPSIS
    room = limit - cell_width(marker)
    if room < 0:
        marker, room = "", limit
    out: list[str] = []
    used = 0
    for ch in text:
        width = char_width(ch)
        if width and used + width > room:
            break
        out.append(ch)
        used += width
    return "".join(out).rstrip(" " + _RUN_CHARS) + marker


def sanitize(raw: Union[str, bytes], limit: int, *, ascii_only: bool = False) -> str:
    """Return ``raw`` as one inert line of at most ``limit`` cells (5.5).

    Steps: decode bytes as UTF-8 with replacement; NUL and lone surrogates become the
    replacement character; NFC; line breaks become spaces; control, format, private-use,
    unassigned and surrogate code points, variation selectors and invisible filler letters
    are removed; at most two combining marks stay per base character; box-drawing, block
    and other frame characters and emoji become the replacement character; whitespace runs
    become one space; runs of dot-like characters, and runs of dash- or frame-like ones,
    are cut to three, where neither a single space nor a combining mark ends a run and
    marks on run characters are dropped; with ``ascii_only`` every remaining non-ASCII
    character is transliterated or replaced; the result is truncated to ``limit`` cells
    and is never longer than ``max_chars(limit)`` characters. A second pass changes
    nothing, which matters because the cache reader sanitises again.
    """
    if isinstance(raw, (bytes, bytearray)):
        text = bytes(raw[:MAX_INPUT_BYTES]).decode("utf-8", "replace")
    elif type(raw) is str:
        text = raw
    else:
        raise TypeError("sanitize() takes str or bytes")
    text = text[:MAX_INPUT_CHARS]
    replacement = ASCII_REPLACEMENT if ascii_only else REPLACEMENT
    # Surrogates first: NFC must not see them, and they cannot be encoded later.
    text = "".join(replacement if 0xD800 <= ord(c) <= 0xDFFF else c for c in text)
    text = unicodedata.normalize("NFC", text)
    # NFC again after cleaning: removing a character can bring a base and a mark together
    # that compose, and a second pass must see text that is already composed.
    cleaned = unicodedata.normalize("NFC", "".join(_clean(text, replacement)))
    chars = _collapse(list(cleaned))
    if ascii_only:
        chars = _collapse(_to_ascii(chars))
    result = truncate("".join(chars).strip(" "), limit, ascii_only=ascii_only)
    # Every character that takes no cell is a mark, and a base keeps at most two, so this
    # never cuts real text; it bounds what a reader of stored output must accept.
    return result[: max_chars(limit)]


# Bidirectional classes of right-to-left letters (Hebrew, Arabic, ...) and Arabic digits.
RTL_CLASSES = frozenset({"R", "AL", "AN"})


def without_rtl(text: str) -> str:
    """Replace right-to-left letters and Arabic digits with the replacement character.

    For names collected from the system (hosts, ttys, users, units, interfaces, jails,
    containers and images, login records): in a terminal that applies the Unicode bidi
    algorithm, such a character starts a right-to-left run that can visually reorder the
    neutral characters around it, so a remote party who controls a host name could move
    parts of an admin's row (final review, security item 3). Catalogue text and text an
    admin wrote (plugins, config labels) are never passed here. Bidi controls are already
    removed by ``sanitize``; the result of this function is unchanged by ``sanitize`` and
    by a second call.
    """
    if text.isascii():
        return text
    return "".join(
        REPLACEMENT if unicodedata.bidirectional(ch) in RTL_CLASSES else ch for ch in text
    )


def theme_char(ch: str) -> bool:
    """One character the look may draw: a frame, bar or font cell (D35).

    The sanitiser's own rules, except that frame and block characters are allowed (they
    are what a theme draws): exactly one code point that the sanitiser keeps as it is,
    one terminal cell wide. Control, format, private-use and unassigned characters,
    marks, variation selectors, invisible fillers, emoji and wide characters fail, and so
    do right-to-left letters and digits, which a terminal with bidi support could take as
    the start of a right-to-left line and reorder the values on it.
    """
    if type(ch) is not str or len(ch) != 1:
        return False
    if unicodedata.bidirectional(ch) in RTL_CLASSES:
        return False
    cp = ord(ch)
    if cp in _IS_FRAME and unicodedata.category(ch) not in ("Me", "Cn"):
        return char_width(ch) == 1
    return _map(ch, "") == ch and not _is_mark(ch) and char_width(ch) == 1


def max_chars(limit: int) -> int:
    """Upper bound on the length of ``sanitize(..., limit)``: three characters per cell."""
    return (MAX_COMBINING + 1) * max(limit, 0) + len(ASCII_ELLIPSIS)

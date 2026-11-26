"""Charsets, colour levels and escape sequences (blueprint 4.6, D14, D17, D35).

Escape sequences are built here and nowhere else, by ``sgr`` from the numbers of a
validated ``Look`` colour: a 16-colour index (0 to 15), a 256-colour index (0 to 255) and
bold. No text from the config, the cache or anywhere else is copied into a sequence, so
an escape byte in the output can only start one of these. Every other string the renderer
writes has passed the sanitiser. The choice of charset and colour is a pure function of
the environment, the config and the command line, which the caller passes in; this module
reads nothing.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from motp.core.look import DEFAULT_LOOK, Color, Look
from motp.core.model import Status
from motp.core.sanitize import sanitize

ESC = "\x1b"
RESET = ESC + "[0m"
MODES = ("auto", "always", "never")
CHARSET_MODES = ("auto", "ascii", "unicode")


class ColorLevel(int, Enum):
    OFF = 0
    BASIC = 16
    EXTENDED = 256


class Role(str, Enum):
    """What a piece of text is; the look maps roles to colours (its config names)."""

    FRAME = "frame"
    TITLE = "title"
    HEADER = "header"
    LABEL = "label"
    VALUE = "value"
    OK = "ok"
    WARN = "warn"
    CRIT = "crit"
    DIM = "muted"
    COMMAND = "hint"
    BAR_USED = "bar_used"
    BAR_FREE = "bar_free"


STATUS_ROLE = {Status.OK: Role.OK, Status.WARN: Role.WARN, Status.CRIT: Role.CRIT}
# The marker after a warning or critical value, by charset (D17). The one place to change
# the glyphs: the final review weighed Unicode triangles against the brackets and kept the
# brackets in both charsets (decision log, phase 14b).
MARKERS = {
    "unicode": {Status.WARN: "[!]", Status.CRIT: "[!!]"},
    "ascii": {Status.WARN: "[!]", Status.CRIT: "[!!]"},
}


@dataclass(frozen=True)
class Charset:
    """Frame, bar and filler characters of one charset. All are one cell wide or empty."""

    name: str
    ascii_only: bool
    horizontal: str
    vertical: str
    top_left: str
    top_right: str
    bottom_left: str
    bottom_right: str
    tee_left: str  # the left end of a separator line
    tee_right: str  # the right end of a separator line
    title_open: str  # before a title inside a frame line, with its space
    title_close: str  # after it
    bar_full: str
    bar_free: str
    bar_open: str
    bar_close: str
    leader: str  # dotted leader between a label and its value
    separator: str  # after a label
    ellipsis: str


def charset_of(look: Look, name: str) -> Charset:
    """The characters of ``look`` for the charset ``name`` (``unicode`` or ``ascii``)."""
    c = look.chars[name]
    ascii_only = name == "ascii"
    return Charset(
        name=name,
        ascii_only=ascii_only,
        horizontal=c.horizontal,
        vertical=c.vertical,
        top_left=c.top_left,
        top_right=c.top_right,
        bottom_left=c.bottom_left,
        bottom_right=c.bottom_right,
        tee_left=c.tee_left,
        tee_right=c.tee_right,
        title_open=c.title_open + " ",
        title_close=" " + c.title_close,
        bar_full=c.bar_used,
        bar_free=c.bar_free,
        bar_open=c.bar_open,
        bar_close=c.bar_close,
        leader=c.leader,
        separator=c.separator,
        ellipsis="..." if ascii_only else "…",
    )


UNICODE = charset_of(DEFAULT_LOOK, "unicode")
ASCII = charset_of(DEFAULT_LOOK, "ascii")


def sgr(color: Color, level: ColorLevel) -> str:
    """The escape sequence that starts ``color`` at ``level``; ``""`` for none.

    Built from integers that were range-checked when the look was loaded, and checked
    again here, so nothing but digits and ``;`` can stand between ``ESC [`` and ``m``.
    """
    if level is ColorLevel.OFF:
        return ""
    parts = ["1"] if color.bold is True else []
    if level is ColorLevel.EXTENDED and color.extended is not None:
        index = int(color.extended)
        if 0 <= index <= 255:
            parts.append(f"38;5;{index}")
    elif color.basic is not None:
        index = int(color.basic)
        if 0 <= index <= 7:
            parts.append(str(30 + index))
        elif 8 <= index <= 15:
            parts.append(str(90 + index - 8))
    return f"{ESC}[{';'.join(parts)}m" if parts else ""


@dataclass(frozen=True)
class Theme:
    charset: Charset
    color: ColorLevel
    look: Look = field(default=DEFAULT_LOOK)

    def paint(self, role: Role, text: str) -> str:
        """Wrap ``text`` in the role's escape sequence; nothing without colour."""
        if self.color is ColorLevel.OFF or not text:
            return text
        start = sgr(self.look.colors[role.value], self.color)
        return f"{start}{text}{RESET}" if start else text

    def status_role(self, status: Optional[Status]) -> Role:
        return STATUS_ROLE.get(status, Role.VALUE) if status is not None else Role.VALUE

    def used_role(self, status: Optional[Status]) -> Role:
        """The used part of a meter: the status colour unless the look sets its own."""
        if self.look.colors[Role.BAR_USED.value].status:
            return self.status_role(status) if status is not None else Role.OK
        return Role.BAR_USED

    def marker(self, status: Optional[Status]) -> str:
        """``[!]`` or ``[!!]`` after a warning or critical value (D17).

        Shown with colour too, so severity never rests on colour alone (final review,
        usability item 7); ``[theme] markers = "no-color"`` keeps them for colourless
        output only, as before.
        """
        if status is None:
            return ""
        if self.color is not ColorLevel.OFF and self.look.markers == "no-color":
            return ""
        table = MARKERS.get(self.charset.name, MARKERS["ascii"])
        return table.get(status, "")

    def text(self, value: str, limit: int) -> str:
        """Catalogue or already sanitised text, made safe for this charset and limit."""
        return sanitize(value, limit, ascii_only=self.charset.ascii_only)


def themed(charset: Charset, color: ColorLevel, look: Look = DEFAULT_LOOK) -> Theme:
    """A theme drawing with ``look``'s characters for the charset ``charset`` names."""
    return Theme(charset_of(look, charset.name), color, look)


def escape_sequences(look: Look = DEFAULT_LOOK) -> frozenset[str]:
    """Every escape sequence a theme with ``look`` can emit (for tests and audits)."""
    seqs = {RESET}
    for color in look.colors.values():
        for level in (ColorLevel.BASIC, ColorLevel.EXTENDED):
            start = sgr(color, level)
            if start:
                seqs.add(start)
    return frozenset(seqs)


def _locale_is_utf8(env: Mapping[str, str]) -> bool:
    name = next((env[k] for k in ("LC_ALL", "LC_CTYPE", "LANG") if env.get(k)), "")
    codeset = name.split(".", 1)[1] if "." in name else ""
    codeset = codeset.split("@", 1)[0].lower().replace("-", "").replace("_", "")
    return codeset == "utf8"


def pick_charset(
    env: Mapping[str, str], encoding: Optional[str], config: str, override: Optional[str]
) -> Charset:
    """Unicode when the locale names UTF-8 and the output encoding agrees (4.6, D14).

    Order: the command line, then ``MOTP_CHARSET``, then the config's ``charset``, then
    the locale. ``auto`` at any level passes the choice on. The result carries the default
    look's characters; ``themed`` swaps in the configured ones.
    """
    for choice in (override, env.get("MOTP_CHARSET"), config):
        if choice == "ascii":
            return ASCII
        if choice == "unicode":
            return UNICODE
    enc = (encoding or "").lower().replace("-", "").replace("_", "")
    return UNICODE if _locale_is_utf8(env) and enc == "utf8" else ASCII


def color_level(env: Mapping[str, str]) -> ColorLevel:
    """256 colours when ``TERM`` or ``COLORTERM`` says so, 16 otherwise."""
    term = env.get("TERM", "")
    colorterm = env.get("COLORTERM", "").lower()
    if "256color" in term or colorterm in ("truecolor", "24bit"):
        return ColorLevel.EXTENDED
    return ColorLevel.BASIC


def pick_color(
    env: Mapping[str, str], isatty: bool, config: str, override: Optional[str]
) -> ColorLevel:
    """Colour or not (D17).

    Order: the command line, then ``MOTP_COLOR``, then ``NO_COLOR`` (the reader's wish
    beats the admin's config), then the config's ``color``, then the terminal: off when
    ``TERM`` is ``dumb`` or the output is not a terminal.
    """
    for choice in (override, env.get("MOTP_COLOR")):
        if choice == "never":
            return ColorLevel.OFF
        if choice == "always":
            return color_level(env)
    if env.get("NO_COLOR"):
        return ColorLevel.OFF
    if config == "never":
        return ColorLevel.OFF
    if config == "always":
        return color_level(env)
    if env.get("TERM") == "dumb" or not isatty:
        return ColorLevel.OFF
    return color_level(env)

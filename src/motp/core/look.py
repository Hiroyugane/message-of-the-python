"""The look: presets, colours, characters and layout switches (blueprint D15, D35, D36).

Every presentation choice is a config value, and a named preset supplies the defaults.
This module holds the presets, reads and checks colour and character values, and resolves
a validated config into a ``Look``, which travels to the renderer in ``render.json``.

Nothing here builds an escape sequence. A colour is kept as numbers only (a 16-colour
index, a 256-colour index, bold), and the renderer's theme turns those numbers into
sequences. No byte of a config value is ever copied into one (D35).
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from typing import Optional

from motp.core.figfont import (
    DRAWN,
    HORIZONTAL_BITS,
    MAX_GLYPH_WIDTH,
    MAX_HEIGHT,
    Font,
    valid_cell,
)
from motp.core.model import ContractError, contract_error
from motp.core.sanitize import sanitize, theme_char

PRESETS = ("default", "classic")
ROLES = (
    "frame",
    "title",
    "header",
    "label",
    "value",
    "muted",
    "ok",
    "warn",
    "crit",
    "hint",
    "bar_used",
    "bar_free",
)
CHARSETS = ("unicode", "ascii")
CHAR_KEYS = (
    "horizontal",
    "vertical",
    "top_left",
    "top_right",
    "bottom_left",
    "bottom_right",
    "tee_left",
    "tee_right",
    "title_open",
    "title_close",
    "bar_used",
    "bar_free",
    "bar_open",
    "bar_close",
    "leader",
    "separator",
)
OPTIONAL_CHARS = ("bar_open", "bar_close")  # may be "" (no bracket around a bar)
SOLID_CHARS = ("bar_used", "bar_free")  # never a space: both parts of a meter show (D36)
BAR_STYLES = ("below", "off")
BAR_TEXTS = ("full", "short", "used", "free", "percent")
HEADER_CASES = ("upper", "as-is")
HEADER_ALIGNS = ("left", "center", "right")
LABEL_STYLES = ("dots", "colon", "plain")
# When the severity markers show (D17; final review, usability item 7): "always", so a
# warning never depends on colour alone, or "no-color", the 1.0 release candidate's
# behaviour (markers only without colour).
MARKER_MODES = ("always", "no-color")
AUTO = "auto"
FONT_NAME = re.compile(r"[a-z0-9][a-z0-9_-]{0,31}\Z")
# Bundled header fonts and the charset each needs (D15); the renderer loads them.
BUNDLED_FONTS = {
    "motp-block": "unicode",
    "motp-block-small": "unicode",
    "big": "ascii",
    "small": "ascii",
}
BAR_WIDTH = (4, 60)
LABEL_WIDTH = (8, 32)
MIN_FREE_CONTRAST = 3.0  # D36: the free part of a meter against a black background
MAX_COLOR_TEXT = 32

BASIC_NAMES = {
    "black": 0,
    "red": 1,
    "green": 2,
    "yellow": 3,
    "blue": 4,
    "magenta": 5,
    "cyan": 6,
    "white": 7,
    "bright-black": 8,
    "grey": 8,
    "gray": 8,
    "bright-red": 9,
    "bright-green": 10,
    "bright-yellow": 11,
    "bright-blue": 12,
    "bright-magenta": 13,
    "bright-cyan": 14,
    "bright-white": 15,
}
HEX = re.compile(r"#[0-9a-fA-F]{6}\Z")
DECIMAL = re.compile(r"(?:0|[1-9][0-9]{0,2})\Z")

# xterm's default palette, used to pick the nearest colour and to compute contrast.
_BASIC_RGB = (
    (0, 0, 0),
    (205, 0, 0),
    (0, 205, 0),
    (205, 205, 0),
    (0, 0, 238),
    (205, 0, 205),
    (0, 205, 205),
    (229, 229, 229),
    (127, 127, 127),
    (255, 0, 0),
    (0, 255, 0),
    (255, 255, 0),
    (92, 92, 255),
    (255, 0, 255),
    (0, 255, 255),
    (255, 255, 255),
)
_CUBE = (0, 95, 135, 175, 215, 255)

RGB = tuple[int, int, int]


def rgb_of(index: int) -> RGB:
    """The xterm RGB value of a colour index from 0 to 255."""
    if index < 16:
        return _BASIC_RGB[index]
    if index < 232:
        n = index - 16
        return (_CUBE[n // 36], _CUBE[n // 6 % 6], _CUBE[n % 6])
    grey = 8 + 10 * (index - 232)
    return (grey, grey, grey)


def _nearest(rgb: RGB, candidates: range) -> int:
    return min(candidates, key=lambda i: sum((a - b) ** 2 for a, b in zip(rgb_of(i), rgb)))


def luminance(rgb: RGB) -> float:
    """Relative luminance (WCAG 2)."""

    def channel(value: int) -> float:
        c = value / 255
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4

    r, g, b = (channel(v) for v in rgb)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast_on_black(rgb: RGB) -> float:
    return (luminance(rgb) + 0.05) / 0.05


@dataclass(frozen=True)
class Color:
    """A colour as numbers only: ``None`` keeps the terminal's own colour.

    ``basic`` is used at 16 colours (0 to 15), ``extended`` at 256 colours (0 to 255).
    ``status`` (only for the used part of a meter) takes the row's status colour instead.
    """

    basic: Optional[int] = None
    extended: Optional[int] = None
    bold: bool = False
    status: bool = False

    def contrasts(self) -> list[float]:
        """Contrast against black at each colour level that sets a colour."""
        return [contrast_on_black(rgb_of(i)) for i in (self.basic, self.extended) if i is not None]


DEFAULT_COLOR = Color()


def parse_color(value: object, allow_status: bool = False) -> Optional[Color]:
    """A colour value from the config; ``None`` if it is not one.

    Forms: a number from 0 to 255; or text: a name from the 16-colour set, a number,
    ``#rrggbb``, ``default`` (the terminal's colour), ``status`` (meters only), each
    optionally with ``bold`` before or after, or ``bold`` alone.
    """
    if type(value) is int:
        return _from_index(value) if 0 <= value <= 255 else None
    if type(value) is not str or not value or len(value) > MAX_COLOR_TEXT:
        return None
    words = value.split(" ")
    bold = words.count("bold")
    rest = [w for w in words if w != "bold"]
    if bold > 1 or len(rest) > 1 or "" in rest:
        return None
    if not rest:
        return Color(bold=True)
    word = rest[0]
    color: Optional[Color]
    if word == "default":
        color = Color()
    elif word == "status":
        color = Color(status=True) if allow_status else None
    elif word in BASIC_NAMES:
        index = BASIC_NAMES[word]
        color = Color(index, index)
    elif DECIMAL.match(word) and int(word) <= 255:
        color = _from_index(int(word))
    elif HEX.match(word):
        rgb = (int(word[1:3], 16), int(word[3:5], 16), int(word[5:7], 16))
        color = Color(_nearest(rgb, range(16)), _nearest(rgb, range(16, 256)))
    else:
        color = None
    return replace(color, bold=bool(bold)) if color is not None else None


def _from_index(index: int) -> Color:
    basic = index if index < 16 else _nearest(rgb_of(index), range(16))
    return Color(basic, index)


def check_char(value: object, charset: str, key: str) -> bool:
    """A character value: exactly one printable cell (D35); ASCII for the ASCII charset.

    ``bar_open`` and ``bar_close`` may be empty; the parts of a meter may not be a space.
    """
    if type(value) is not str:
        return False
    if value == "":
        return key in OPTIONAL_CHARS
    if not theme_char(value):
        return False
    if charset == "ascii" and not (" " <= value <= "~"):
        return False
    return not (key in SOLID_CHARS and value == " ")


@dataclass(frozen=True)
class Chars:
    """Frame, bar and filler characters of one charset; each is one cell (or empty)."""

    horizontal: str
    vertical: str
    top_left: str
    top_right: str
    bottom_left: str
    bottom_right: str
    tee_left: str
    tee_right: str
    title_open: str
    title_close: str
    bar_used: str
    bar_free: str
    bar_open: str
    bar_close: str
    leader: str
    separator: str


@dataclass(frozen=True)
class Bar:
    width: int = 0  # 0: the width class decides (40 wide, 20 compact)
    style: str = "below"
    text: str = "full"


@dataclass(frozen=True)
class Look:
    """The resolved look the renderer draws with (D35)."""

    preset: str
    colors: Mapping[str, Color]
    chars: Mapping[str, Chars]  # by charset name
    bar: Bar = field(default_factory=Bar)
    header_case: str = "upper"
    header_font: Mapping[str, str] = field(default_factory=dict)  # charset -> font name
    header_align: str = "left"
    frame: bool = True
    label_style: str = "dots"
    label_width: int = 0  # 0: the width class decides
    markers: str = "always"
    section_titles: Mapping[str, str] = field(default_factory=dict)
    hidden_rows: tuple[str, ...] = ()
    row_order: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    fonts: Mapping[str, Font] = field(default_factory=dict)  # admin fonts by name


def _c(basic: Optional[int], extended: Optional[int], bold: bool = False) -> Color:
    return Color(basic, extended, bold)


UNICODE_CHARS = Chars(
    "─", "│", "┌", "┐", "└", "┘", "├", "┤", "┤", "├", "█", "▒", "", "", ".", ":"
)  # fmt: skip
ASCII_CHARS = Chars(
    "-", "|", "+", "+", "+", "+", "+", "+", "/", "/", "#", "-", "[", "]", ".", ":"
)  # fmt: skip
CLASSIC_CHARS = Chars(
    "-", "|", "+", "+", "+", "+", "+", "+", "+", "+", "/", "-", "+", "+", ".", ":"
)  # fmt: skip

# The approved look of phase 4 with the D36 fix: the free part of a meter is a medium
# shade, which lights about half of each cell, so its colour is a light grey: 248 (#a8a8a8,
# 8.8:1 on black, about 4:1 once shaded) or white at 16 colours (#e5e5e5 in xterm).
DEFAULT_COLORS = {
    "frame": _c(4, 67),
    "title": _c(6, 80, True),
    "header": _c(5, 170, True),
    "label": _c(12, 75),
    "value": _c(None, None),
    "muted": _c(8, 248),
    "ok": _c(2, 71),
    "warn": _c(3, 220),
    "crit": _c(1, 196, True),
    "hint": _c(6, 116),
    "bar_used": Color(status=True),
    "bar_free": _c(7, 248),
}
# The 2019 picture: magenta frame and header, blue labels, yellow values, meters with the
# used part red and the free part green. Yellow is taken by the values, so a warning is
# orange at 256 colours and red at 16; critical is bold red.
CLASSIC_COLORS = {
    "frame": _c(5, 170),
    "title": _c(5, 170),
    "header": _c(5, 170, True),
    "label": _c(4, 33),
    "value": _c(3, 220, True),
    "muted": _c(8, 248),
    "ok": _c(2, 40),
    "warn": _c(1, 208),
    "crit": _c(9, 196, True),
    "hint": _c(6, 80),
    "bar_used": _c(1, 196),
    "bar_free": _c(2, 40),
}

PRESET_LOOKS = {
    "default": Look(
        preset="default",
        colors=DEFAULT_COLORS,
        chars={"unicode": UNICODE_CHARS, "ascii": ASCII_CHARS},
        header_font={"unicode": "motp-block", "ascii": "big"},
    ),
    "classic": Look(
        preset="classic",
        colors=CLASSIC_COLORS,
        chars={"unicode": CLASSIC_CHARS, "ascii": CLASSIC_CHARS},
        header_font={"unicode": "big", "ascii": "big"},
    ),
}
DEFAULT_LOOK = PRESET_LOOKS["default"]


Raw = Mapping[str, object]


def resolve(theme: Raw, layout: Raw, fonts: Optional[Mapping[str, Font]] = None) -> Look:
    """The look of a validated ``[theme]`` and ``[layout]``: the preset, then each key set.

    ``fonts`` holds the admin fonts that were read and passed every check; a font name
    without one falls back to the preset's font.
    """
    fonts = fonts or {}
    preset = theme.get("preset", "default")
    base = PRESET_LOOKS[preset if isinstance(preset, str) and preset in PRESETS else "default"]
    colors = dict(base.colors)
    for role, value in _table(theme, "colors").items():
        color = parse_color(value, allow_status=role == "bar_used")
        if color is not None:
            colors[role] = color
    header_color = layout.get("header_color", "")
    if header_color:
        color = parse_color(header_color)
        if color is not None:
            colors["header"] = color
    chars = {}
    raw_chars = _table(theme, "chars")
    for charset in CHARSETS:
        overrides = _table(raw_chars, charset)
        old = base.chars[charset]
        chars[charset] = Chars(*(str(overrides.get(k, getattr(old, k))) for k in CHAR_KEYS))
    raw_bar = _table(theme, "bar")
    bar = Bar(
        _int(raw_bar.get("width", base.bar.width)),
        str(raw_bar.get("style", base.bar.style)),
        str(raw_bar.get("text", base.bar.text)),
    )
    header_font = dict(base.header_font)
    used_fonts: dict[str, Font] = {}
    for charset, key in (("unicode", "header_font"), ("ascii", "header_font_ascii")):
        name = layout.get(key, AUTO)
        if type(name) is not str or name == AUTO:
            continue
        if name in BUNDLED_FONTS:
            header_font[charset] = name
        elif name in fonts and (charset == "unicode" or fonts[name].ascii_only):
            header_font[charset] = name
            used_fonts[name] = fonts[name]
    order = _table(layout, "row_order")
    return Look(
        preset=base.preset,
        colors=colors,
        chars=chars,
        bar=bar,
        header_case=str(layout.get("header_case", base.header_case)),
        header_font=header_font,
        header_align=str(layout.get("header_align", base.header_align)),
        frame=bool(layout.get("frame", base.frame)),
        label_style=str(layout.get("label_style", base.label_style)),
        label_width=_int(layout.get("label_width", base.label_width)),
        markers=str(theme.get("markers", base.markers)),
        section_titles={str(k): str(v) for k, v in _table(layout, "section_titles").items()},
        hidden_rows=tuple(str(k) for k in _list(layout.get("hide_rows"))),
        row_order={str(k): tuple(str(x) for x in _list(v)) for k, v in order.items()},
        fonts=used_fonts,
    )


def _table(raw: Raw, key: str) -> Mapping[str, object]:
    value = raw.get(key)
    return value if isinstance(value, dict) else {}


def _list(value: object) -> list[object]:
    return value if isinstance(value, list) else []


def _int(value: object) -> int:
    return value if type(value) is int else 0


# --- render.json ------------------------------------------------------------------------
# The collector writes the resolved look; the renderer reads it back as untrusted input and
# checks every value again, so a damaged or forged file cannot widen what the look may do.

MAX_SECTION_TITLE = 40
MAX_KEYS = 64
MAX_FONTS = 2
MAX_FONT_CELLS = 16384
SECTION_NAMES = (
    "attention",
    "host",
    "system",
    "security",
    "login",
    "disks",
    "services",
    "containers",
    "plugins",
)
ITEM_KEY = re.compile(r"[a-z0-9_][a-z0-9_.-]{0,127}\Z")


def color_json(color: Color) -> dict[str, object]:
    return {
        "basic": color.basic,
        "extended": color.extended,
        "bold": color.bold,
        "status": color.status,
    }


def font_json(font: Font) -> dict[str, object]:
    return {
        "height": font.height,
        "hardblank": font.hardblank,
        "smush": font.smush,
        "glyphs": {ch: list(font.glyphs[ch]) for ch in DRAWN},
    }


def look_json(look: Look) -> dict[str, object]:
    return {
        "preset": look.preset,
        "colors": {role: color_json(look.colors[role]) for role in ROLES},
        "chars": {cs: {k: getattr(look.chars[cs], k) for k in CHAR_KEYS} for cs in CHARSETS},
        "bar": {"width": look.bar.width, "style": look.bar.style, "text": look.bar.text},
        "header_case": look.header_case,
        "header_font": {cs: look.header_font.get(cs, AUTO) for cs in CHARSETS},
        "header_align": look.header_align,
        "frame": look.frame,
        "label_style": look.label_style,
        "label_width": look.label_width,
        "markers": look.markers,
        "section_titles": dict(look.section_titles),
        "hidden_rows": list(look.hidden_rows),
        "row_order": {k: list(v) for k, v in look.row_order.items()},
        "fonts": {name: font_json(font) for name, font in sorted(look.fonts.items())},
    }


def _bad(field: str) -> ContractError:
    return contract_error("cache.error.schema", field=f"look.{field}")


def _obj(raw: object, field: str, keys: Optional[tuple[str, ...]] = None) -> dict[str, object]:
    if not isinstance(raw, dict) or (keys is not None and set(raw) != set(keys)):
        raise _bad(field)
    return raw


def _pick(raw: object, choices: tuple[str, ...], field: str) -> str:
    if type(raw) is not str or raw not in choices:
        raise _bad(field)
    return raw


def _index(raw: object, high: int, field: str) -> Optional[int]:
    if raw is None:
        return None
    if type(raw) is not int or not 0 <= raw <= high:
        raise _bad(field)
    return raw


def _flag(raw: object, field: str) -> bool:
    if type(raw) is not bool:
        raise _bad(field)
    return raw


def _decode_color(raw: object, role: str) -> Color:
    field = f"colors.{role}"
    obj = _obj(raw, field, ("basic", "extended", "bold", "status"))
    color = Color(
        _index(obj["basic"], 15, field),
        _index(obj["extended"], 255, field),
        _flag(obj["bold"], field),
        _flag(obj["status"], field),
    )
    if color.status and role != "bar_used":
        raise _bad(field)
    if role == "bar_free" and any(c < MIN_FREE_CONTRAST for c in color.contrasts()):
        raise _bad(field)
    return color


def _decode_chars(raw: object, charset: str) -> Chars:
    obj = _obj(raw, f"chars.{charset}", CHAR_KEYS)
    for key in CHAR_KEYS:
        if not check_char(obj[key], charset, key):
            raise _bad(f"chars.{charset}.{key}")
    chars = Chars(*(str(obj[k]) for k in CHAR_KEYS))
    if chars.bar_used == chars.bar_free:
        raise _bad(f"chars.{charset}")
    return chars


def _keys(raw: object, field: str) -> tuple[str, ...]:
    if not isinstance(raw, list) or len(raw) > MAX_KEYS:
        raise _bad(field)
    for key in raw:
        if type(key) is not str or not ITEM_KEY.match(key):
            raise _bad(field)
    return tuple(raw)


def decode_font(name: str, raw: object) -> Font:
    """An admin font from ``render.json``: every glyph checked like a font file's."""
    field = f"fonts.{name}"
    obj = _obj(raw, field, ("height", "hardblank", "smush", "glyphs"))
    height = obj["height"]
    hardblank = obj["hardblank"]
    smush = obj["smush"]
    if type(height) is not int or not 1 <= height <= MAX_HEIGHT:
        raise _bad(field)
    if type(hardblank) is not str or not theme_char(hardblank) or hardblank == " ":
        raise _bad(field)
    if type(smush) is not int or not 0 <= smush <= HORIZONTAL_BITS:
        raise _bad(field)
    glyphs_raw = _obj(obj["glyphs"], field, DRAWN)
    glyphs: dict[str, tuple[str, ...]] = {}
    cells = 0
    for ch in DRAWN:
        rows = glyphs_raw[ch]
        if not isinstance(rows, list) or len(rows) != height:
            raise _bad(field)
        width = len(rows[0]) if type(rows[0]) is str else -1
        for row in rows:
            if type(row) is not str or len(row) != width or width > MAX_GLYPH_WIDTH:
                raise _bad(field)
            if not all(valid_cell(c) or c == hardblank for c in row):
                raise _bad(field)
        cells += width * height
        glyphs[ch] = tuple(rows)
    if cells > MAX_FONT_CELLS:
        raise _bad(field)
    return Font(name, height, hardblank, smush, glyphs)


def _fonts(raw: object) -> dict[str, Font]:
    fonts_raw = _obj(raw, "fonts")
    if len(fonts_raw) > MAX_FONTS:
        raise _bad("fonts")
    fonts = {}
    for name, font_raw in fonts_raw.items():
        if not FONT_NAME.match(name) or name in BUNDLED_FONTS:
            raise _bad("fonts")
        fonts[name] = decode_font(name, font_raw)
    return fonts


def _header_fonts(raw: object, fonts: Mapping[str, Font]) -> dict[str, str]:
    obj = _obj(raw, "header_font", CHARSETS)
    out = {}
    for charset in CHARSETS:
        name = obj[charset]
        if type(name) is not str:
            raise _bad("header_font")
        bundled = BUNDLED_FONTS.get(name)
        if bundled is None and name not in fonts:
            raise _bad("header_font")
        if charset == "ascii" and (
            bundled == "unicode" or (name in fonts and not fonts[name].ascii_only)
        ):
            raise _bad("header_font")
        out[charset] = name
    return out


def _width(raw: object, low_high: tuple[int, int], field: str) -> int:
    low, high = low_high
    if type(raw) is not int or not (raw == 0 or low <= raw <= high):
        raise _bad(field)
    return raw


def decode_look(raw: object) -> Look:
    """The look from ``render.json``, checked as untrusted input.

    ``markers`` may be missing: a ``render.json`` written before the final review lacks
    it until the collector's next run, and must not blank the message meanwhile.
    """
    if isinstance(raw, dict) and "markers" not in raw:
        raw = {**raw, "markers": DEFAULT_LOOK.markers}
    obj = _obj(raw, "look", tuple(look_json(DEFAULT_LOOK)))
    colors_raw = _obj(obj["colors"], "colors", ROLES)
    chars_raw = _obj(obj["chars"], "chars", CHARSETS)
    bar_raw = _obj(obj["bar"], "bar", ("width", "style", "text"))
    fonts = _fonts(obj["fonts"])
    titles = {}
    for section, title in _obj(obj["section_titles"], "section_titles").items():
        if section not in SECTION_NAMES or type(title) is not str or len(title) > 256:
            raise _bad("section_titles")
        titles[section] = sanitize(title, MAX_SECTION_TITLE)
    order_raw = _obj(obj["row_order"], "row_order")
    if any(section not in SECTION_NAMES for section in order_raw):
        raise _bad("row_order")
    return Look(
        preset=_pick(obj["preset"], PRESETS, "preset"),
        colors={role: _decode_color(colors_raw[role], role) for role in ROLES},
        chars={cs: _decode_chars(chars_raw[cs], cs) for cs in CHARSETS},
        bar=Bar(
            _width(bar_raw["width"], BAR_WIDTH, "bar.width"),
            _pick(bar_raw["style"], BAR_STYLES, "bar.style"),
            _pick(bar_raw["text"], BAR_TEXTS, "bar.text"),
        ),
        header_case=_pick(obj["header_case"], HEADER_CASES, "header_case"),
        header_font=_header_fonts(obj["header_font"], fonts),
        header_align=_pick(obj["header_align"], HEADER_ALIGNS, "header_align"),
        frame=_flag(obj["frame"], "frame"),
        label_style=_pick(obj["label_style"], LABEL_STYLES, "label_style"),
        label_width=_width(obj["label_width"], LABEL_WIDTH, "label_width"),
        markers=_pick(obj["markers"], MARKER_MODES, "markers"),
        section_titles=titles,
        hidden_rows=_keys(obj["hidden_rows"], "hidden_rows"),
        row_order={s: _keys(v, "row_order") for s, v in order_raw.items()},
        fonts=fonts,
    )

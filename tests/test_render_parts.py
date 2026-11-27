"""Renderer parts: FIGfont reader, bundled fonts, theme rules, bars, and the import guard."""

import ast
import hashlib
import sys
from dataclasses import replace
from pathlib import Path
from typing import Optional

import pytest

from motp.core import figfont as core_figfont
from motp.core.look import DEFAULT_LOOK
from motp.core.model import Status
from motp.core.sanitize import cell_width, char_width
from motp.render import bars, figfont
from motp.render.theme import (
    ASCII,
    UNICODE,
    ColorLevel,
    Role,
    Theme,
    color_level,
    escape_sequences,
    pick_charset,
    pick_color,
)

from .conftest import SRC, TOOLS

sys.path.insert(0, str(TOOLS))
import make_fonts

FIXTURES = Path(__file__).parent / "fixtures" / "figlet"

# --- fonts --------------------------------------------------------------------------------


def test_bundled_fonts_are_up_to_date() -> None:
    assert make_fonts.main(["--check"]) == 0


@pytest.mark.parametrize("name", figfont.BUNDLED)
def test_bundled_fonts_parse(name: str) -> None:
    font = figfont.bundled(name)
    assert font is not None
    assert len(font.glyphs) == len(figfont.REQUIRED)
    assert font.ascii_only is (figfont.BUNDLED[name] == "ascii")


@pytest.mark.parametrize("name", figfont.BUNDLED)
def test_every_glyph_has_the_fonts_row_count(name: str) -> None:
    font = figfont.bundled(name)
    assert font is not None
    expected = {"motp-block": 6, "motp-block-small": 3, "big": 8, "small": 5}[name]
    assert font.height == expected
    for ch, glyph in font.glyphs.items():
        assert len(glyph) == font.height, ch
        assert len({len(row) for row in glyph}) == 1, ch
        assert all(char_width(c) == 1 for row in glyph for c in row), ch


@pytest.mark.parametrize("name", ["motp-block", "motp-block-small"])
def test_block_fonts_draw_capitals_for_lower_case_and_cover_host_names(name: str) -> None:
    font = figfont.bundled(name)
    assert font is not None
    for ch in "abcdefghijklmnopqrstuvwxyz":
        assert font.glyphs[ch] == font.glyphs[ch.upper()]
    question = font.glyphs["?"]
    for ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._ ":
        assert font.glyphs[ch] != question or ch == "?", ch
    # every drawn header row of an upper-case host name has the font's full height
    rows = figfont.render(font, "WEB01-DB.X_9")
    assert len(rows) == font.height and all(r.strip() for r in rows)


def test_block_font_draws_a_host_name_with_a_shadow() -> None:
    font = figfont.bundled("motp-block")
    assert font is not None
    assert figfont.render(font, "WEB01") == [
        "██╗   ██╗███████╗██████╗  █████╗  ██╗",
        "██║   ██║██╔════╝██╔══██╗██╔═███╗███║",
        "██║██╗██║█████╗  ██████╔╝██║█╔██║╚██║",
        "████████║██╔══╝  ██╔══██╗███╔╝██║ ██║",
        "╚██╔═██╔╝███████╗██████╔╝╚█████╔╝ ██║",
        " ╚═╝ ╚═╝ ╚══════╝╚═════╝  ╚════╝  ╚═╝",
    ]


def test_shadow_is_computed_from_the_mask() -> None:
    assert make_fonts.shadow(["##", "##"]) == ["██╗", "██║", "╚═╝"]
    # a bar on a stroke: the shadow under the bar runs into the next stroke
    assert make_fonts.shadow(["#.#", "###", "#.#"]) == [
        "█╗█╗",
        "███║",
        "█╔█║",
        "╚╝╚╝",
    ]


@pytest.mark.parametrize("name", ["big", "small"])
def test_figlet_fonts_match_figlet_output(name: str) -> None:
    """Reference output of ``figlet -w 2000 -f <name>`` from Debian 12's figlet package."""
    font = figfont.bundled(name)
    assert font is not None
    samples = (FIXTURES / f"{name}.samples").read_text(encoding="utf-8").splitlines()
    blocks = (FIXTURES / f"{name}.ref").read_text(encoding="utf-8").split("==END==\n")
    assert len(samples) == 15 and len(blocks) == 16
    for text, block in zip(samples, blocks):
        expected = [line[:-1].rstrip() for line in block.splitlines()]  # "|" marks line ends
        assert figfont.render(font, text) == expected, text


@pytest.mark.parametrize("name", ["big", "small"])
def test_figlet_fonts_keep_names_but_no_addresses(name: str) -> None:
    data = (SRC / "motp" / "render" / "fonts" / f"{name}.flf").read_text(encoding="utf-8")
    header = data.split("\n", 1)[0].split()
    comments = data.split("\n")[1 : 1 + int(header[5])]
    assert "Glenn Chappell" in comments[0]
    assert not any("@" in line for line in comments)
    assert comments[-1] == make_fonts.FIGLET_NOTE


def test_figlet_licence_records_package_and_checksums() -> None:
    text = (SRC / "motp" / "render" / "fonts" / "LICENSE.txt").read_text(encoding="utf-8")
    assert make_fonts.FIGLET_PACKAGE in text
    for name, digest in make_fonts.FIGLET_SHA256.items():
        assert f"{digest}  {name}" in text
    assert "Redistribution and use in source and binary forms" in text


def test_importing_figlet_refuses_a_changed_file(tmp_path: Path) -> None:
    for name in make_fonts.FIGLET_SHA256:
        (tmp_path / name).write_bytes(b"flf2a$ 1 1 1 0 0\n")
    with pytest.raises(SystemExit):
        make_fonts.import_figlet(tmp_path)
    assert hashlib.sha256(b"").hexdigest() not in make_fonts.FIGLET_SHA256.values()


def test_fonts_get_smaller_in_order() -> None:
    for big, small in figfont.SMALLER.items():
        wide, narrow = figfont.bundled(big), figfont.bundled(small)
        assert wide is not None and narrow is not None
        assert max(map(len, figfont.render(narrow, "WEB01"))) < max(
            map(len, figfont.render(wide, "WEB01"))
        )


def test_unknown_characters_draw_the_question_mark() -> None:
    font = figfont.bundled("motp-block-small")
    assert font is not None
    assert figfont.render(font, "é") == figfont.render(font, "?")


def _font(header: str, glyph_rows: "list[str]", height: int = 1) -> bytes:
    lines = [header]
    for _ in figfont.REQUIRED:
        lines += glyph_rows[:height]
    return ("\n".join(lines) + "\n").encode("utf-8")


def test_layouts_full_width_kerning_and_smushing() -> None:
    # Every glyph is " #  " (one row).
    kern = figfont.parse("t", _font("flf2a$ 1 1 6 0 0", [" #  @@"]))
    assert kern is not None and not kern.full_width
    assert figfont.render(kern, "ab") == ["##"]
    full = figfont.parse("t", _font("flf2a$ 1 1 6 -1 0", [" #  @@"]))
    assert full is not None and figfont.render(full, "ab") == [" #   #"]
    # controlled smushing, rule 1 (equal characters): two "|" become one
    smush = figfont.parse("t", _font("flf2a$ 1 1 6 1 0", ["||@@"]))
    assert smush is not None and figfont.render(smush, "ab") == ["|||"]


@pytest.mark.parametrize(
    ("old_layout", "glyph", "text", "expected"),
    [
        (16 | 1, "/\\@@", "a", ["/\\"]),  # rule 5 needs the pair across two glyphs
        (16 | 1, "/@@", "ab", ["//"]),  # one-cell glyphs never smush, even equal ones
        (16 | 1, "//@@", "ab", ["///"]),  # two-cell glyphs do (rule 1)
    ],
)
def test_smushing_edge_cases(old_layout: int, glyph: str, text: str, expected: list[str]) -> None:
    font = figfont.parse("t", _font(f"flf2a$ 1 1 6 {old_layout} 0", [glyph]))
    assert font is not None
    assert figfont.render(font, text) == expected


def _two(left: str, right: str, layout_bits: int, hardblank: str = "$") -> list[str]:
    """Draw "ab" where a and b have their own one-row glyphs."""
    lines = [f"flf2a{hardblank} 1 1 6 0 0 0 {layout_bits}"]
    for code in figfont.REQUIRED:
        row = left if chr(code) == "a" else right if chr(code) == "b" else "??"
        lines.append(row + "@@")
    font = figfont.parse("t", ("\n".join(lines) + "\n").encode())
    assert font is not None
    return figfont.render(font, "ab")


@pytest.mark.parametrize(
    ("left", "right", "bits", "expected"),
    [
        ("x/", "\\x", 128 | 16, ["x|x"]),  # rule 5: / and \ become |
        ("x\\", "/x", 128 | 16, ["xYx"]),  # rule 5: \ and / become Y
        ("x>", "<x", 128 | 16, ["xXx"]),  # rule 5: > and < become X
        ("x[", "]x", 128 | 8, ["x|x"]),  # rule 4: opposite brackets
        ("x_", "|x", 128 | 2, ["x|x"]),  # rule 2: underscore yields
        ("x|", "/x", 128 | 4, ["x/x"]),  # rule 3: hierarchy
        ("x$", "$x", 128 | 32, ["x x"]),  # rule 6: two hardblanks
        ("x$", "$x", 128 | 1, ["x  x"]),  # without rule 6 hardblanks do not overlap
        ("xA", "Bx", 128, ["xBx"]),  # universal smushing: the right character wins
        ("xA", "Bx", 128 | 1, ["xABx"]),  # controlled: A and B do not smush
        ("xA", "Bx", 64, ["xABx"]),  # kerning only
        ("xA", "Bx", 0, ["xABx"]),  # full width
    ],
)
def test_smushing_rules_as_figlet(left: str, right: str, bits: int, expected: list[str]) -> None:
    assert _two(left, right, bits) == expected


def test_hardblanks_become_spaces_and_stop_kerning() -> None:
    font = figfont.parse("t", _font("flf2a$ 1 1 6 0 0", ["#$@@"]))
    assert font is not None
    assert figfont.render(font, "ab") == ["# #"]


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"not a font\n",
        b"flf2a$ x 1 6 0 0\n",
        b"flf2a$ 99 1 6 0 0\n",  # too tall
        b"flf2a$ 1 1 6 0 0\n@@\n",  # glyphs missing
        b"flf2a$ 1 1 6 0 0\n" + b"\xff\xfe\n",
        b"flf2a$ 1 1 6 0 0\n" + b"#" * (300 * 1024),
        b"flf2a\x1b 1 1 6 0 0\n",  # an escape byte as hardblank
    ],
)
def test_malformed_fonts_are_refused(data: bytes) -> None:
    assert figfont.parse("t", data) is None


@pytest.mark.parametrize("row", ["\x1b[2J@@", "​#@@", "#́@@", "漢@@", "\U0001f600@@", "\x9b@@"])
def test_glyph_cells_must_be_printable_and_one_cell(row: str) -> None:
    assert figfont.parse("t", _font("flf2a$ 1 1 6 0 0", [row])) is None


def test_glyph_rows_must_line_up() -> None:
    assert figfont.parse("t", _font("flf2a$ 2 1 6 0 0", ["#@", "##@@"], 2)) is None


def test_only_bundled_names_are_loaded() -> None:
    assert figfont.bundled("../../core/hints") is None
    assert figfont.bundled("motp-big") is None  # the phase 4 fonts are gone
    assert core_figfont.parse is figfont.parse


# --- theme -------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("env", "encoding", "config", "override", "expected"),
    [
        ({"LANG": "en_US.UTF-8"}, "utf-8", "auto", None, "unicode"),
        ({"LANG": "en_US.utf8"}, "UTF-8", "auto", None, "unicode"),
        ({"LANG": "en_US.UTF-8"}, "ascii", "auto", None, "ascii"),
        ({"LANG": "C"}, "utf-8", "auto", None, "ascii"),
        ({"LC_ALL": "C", "LANG": "en_US.UTF-8"}, "utf-8", "auto", None, "ascii"),
        ({"LC_CTYPE": "de_DE.UTF-8"}, "utf-8", "auto", None, "unicode"),
        ({}, "utf-8", "auto", None, "ascii"),
        ({"LANG": "en_US.UTF-8"}, "utf-8", "ascii", None, "ascii"),
        ({"LANG": "C"}, "ascii", "unicode", None, "unicode"),
        ({"LANG": "C", "MOTP_CHARSET": "unicode"}, None, "ascii", None, "unicode"),
        ({"MOTP_CHARSET": "unicode"}, None, "auto", "ascii", "ascii"),
        ({"MOTP_CHARSET": "bogus", "LANG": "C"}, None, "auto", None, "ascii"),
    ],
)
def test_pick_charset(
    env: dict[str, str],
    encoding: Optional[str],
    config: str,
    override: Optional[str],
    expected: str,
) -> None:
    assert pick_charset(env, encoding, config, override).name == expected


TERM = {"TERM": "xterm"}


@pytest.mark.parametrize(
    ("env", "isatty", "config", "override", "expected"),
    [
        (TERM, True, "auto", None, ColorLevel.BASIC),
        ({"TERM": "xterm-256color"}, True, "auto", None, ColorLevel.EXTENDED),
        ({"TERM": "xterm", "COLORTERM": "truecolor"}, True, "auto", None, ColorLevel.EXTENDED),
        (TERM, False, "auto", None, ColorLevel.OFF),
        ({"TERM": "dumb"}, True, "auto", None, ColorLevel.OFF),
        ({**TERM, "NO_COLOR": "1"}, True, "auto", None, ColorLevel.OFF),
        ({**TERM, "NO_COLOR": ""}, True, "auto", None, ColorLevel.BASIC),
        ({**TERM, "NO_COLOR": "1"}, True, "always", None, ColorLevel.OFF),
        (TERM, False, "always", None, ColorLevel.BASIC),
        (TERM, True, "never", None, ColorLevel.OFF),
        ({**TERM, "NO_COLOR": "1", "MOTP_COLOR": "always"}, False, "never", None, ColorLevel.BASIC),
        ({**TERM, "MOTP_COLOR": "never"}, True, "always", None, ColorLevel.OFF),
        ({**TERM, "MOTP_COLOR": "always"}, True, "auto", "never", ColorLevel.OFF),
        ({**TERM, "NO_COLOR": "1"}, False, "auto", "always", ColorLevel.BASIC),
    ],
)
def test_pick_color(
    env: dict[str, str],
    isatty: bool,
    config: str,
    override: Optional[str],
    expected: ColorLevel,
) -> None:
    assert pick_color(env, isatty, config, override) is expected


def test_color_level_defaults_to_16() -> None:
    assert color_level({}) is ColorLevel.BASIC


def test_markers_show_with_colour_too_unless_the_look_says_no_color() -> None:
    """Final review, usability item 7: severity never rests on colour alone."""
    off, on = Theme(ASCII, ColorLevel.OFF), Theme(UNICODE, ColorLevel.BASIC)
    assert (off.marker(Status.WARN), off.marker(Status.CRIT)) == ("[!]", "[!!]")
    assert off.marker(Status.OK) == off.marker(Status.UNKNOWN) == off.marker(None) == ""
    assert (on.marker(Status.WARN), on.marker(Status.CRIT)) == ("[!]", "[!!]")
    old = replace(DEFAULT_LOOK, markers="no-color")
    assert Theme(UNICODE, ColorLevel.BASIC, old).marker(Status.CRIT) == ""
    assert Theme(ASCII, ColorLevel.OFF, old).marker(Status.CRIT) == "[!!]"


def test_the_markers_setting_travels_through_config_and_render_json() -> None:
    from motp.core import config, look

    assert config.validate({"theme": {"markers": "no-color"}}) == []
    assert config.validate({"theme": {"markers": "sometimes"}}) != []
    resolved = look.resolve({"markers": "no-color"}, {})
    assert resolved.markers == "no-color"
    assert look.decode_look(look.look_json(resolved)).markers == "no-color"
    older = look.look_json(DEFAULT_LOOK)
    del older["markers"]  # a render.json from before the setting existed
    assert look.decode_look(older).markers == "always"


def test_paint_uses_the_table() -> None:
    assert Theme(UNICODE, ColorLevel.OFF).paint(Role.CRIT, "x") == "x"
    assert Theme(UNICODE, ColorLevel.BASIC).paint(Role.CRIT, "x") == "\x1b[1;31mx\x1b[0m"
    assert Theme(UNICODE, ColorLevel.BASIC).paint(Role.VALUE, "x") == "x"
    assert "\x1b[38;5;220m" in escape_sequences()


def test_ascii_theme_transliterates_text() -> None:
    assert Theme(ASCII, ColorLevel.OFF).text("Größe …", 40) == "Groesse ..."


def test_charsets_are_one_cell_per_character() -> None:

    for cs in (UNICODE, ASCII):
        for name in ("horizontal", "vertical", "top_left", "bar_full", "bar_free", "leader"):
            assert cell_width(getattr(cs, name)) == 1
    assert all(ord(c) < 128 for c in vars(ASCII).values() if isinstance(c, str) for c in c)


# --- bars ----------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("ratio", "expected"),
    [
        (0.0, 0),
        (0.001, 1),
        (0.5, 5),
        (0.96, 9),
        (0.999, 9),
        (1.0, 10),
        (2.0, 10),
        (-1.0, 0),
        (float("nan"), 0),
    ],
)
def test_bar_cells(ratio: float, expected: int) -> None:
    assert bars.cells(ratio, 10) == expected


@pytest.mark.parametrize("theme", [Theme(UNICODE, ColorLevel.OFF), Theme(ASCII, ColorLevel.OFF)])
@pytest.mark.parametrize("width", [3, 10, 40])
def test_bars_are_exactly_their_width(theme: Theme, width: int) -> None:
    drawn = bars.bar(0.5, width, theme, Status.OK)
    assert len(drawn) == width


def test_bar_colours_follow_the_status() -> None:
    drawn = bars.bar(0.96, 10, Theme(UNICODE, ColorLevel.BASIC), Status.CRIT)
    assert drawn.startswith("\x1b[1;31m" + "█" * 9) and "▒" in drawn
    assert bars.bar(0.5, 10, Theme(ASCII, ColorLevel.OFF), None) == "[####----]"


def test_ascii_bar_too_narrow_is_empty() -> None:
    assert bars.bar(0.5, 2, Theme(ASCII, ColorLevel.OFF), None) == ""


# --- guard: the renderer touches no system ----------------------------------------------------

ALLOWED_IMPORTS = {
    "collections",
    "dataclasses",
    "enum",
    "functools",
    "math",
    "motp",
    "typing",
    "unicodedata",
}


def test_render_package_imports_no_system_module() -> None:
    problems = []
    for path in sorted((SRC / "motp" / "render").rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names = [node.module]
            else:
                continue
            for name in names:
                if name.split(".")[0] not in ALLOWED_IMPORTS:
                    problems.append(f"{path.name}:{node.lineno}: {name}")
                if name.startswith("motp.") and name != "motp.core" and not name.startswith(
                    ("motp.render", "motp.core.model", "motp.core.sanitize", "motp.core.i18n",
                     "motp.core.hints", "motp.core.thresholds", "motp.core.cache",
                     "motp.core.resources", "motp.core.look", "motp.core.figfont")
                ):  # fmt: skip
                    problems.append(f"{path.name}:{node.lineno}: {name}")
    assert not problems, problems

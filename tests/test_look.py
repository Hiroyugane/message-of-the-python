"""The look: presets, theme and layout keys, admin fonts, meters (blueprint D15, D35, D36)."""

import json
import os
import re
from dataclasses import replace
from pathlib import Path
from typing import Any, Optional

import pytest

from motp import cli
from motp import render as renderer
from motp.collect import runner
from motp.core import cache, config, figfont, i18n, look
from motp.core.cache import Layout
from motp.core.look import DEFAULT_LOOK, PRESET_LOOKS, Color, Look
from motp.core.model import ContractError, contract_error
from motp.core.sanitize import cell_width, theme_char
from motp.render import demo, layout, view
from motp.render.theme import ASCII, UNICODE, ColorLevel, escape_sequences, sgr, themed

from .conftest import OTHER_USER, account

TR = i18n.Translator("en")
ESC = "\x1b"
SGR = re.compile(r"\x1b\[([0-9;]*)m")
linux_root = pytest.mark.needs_linux_owner


def plain_read(path: str, max_bytes: int) -> bytes:
    data = Path(path).read_bytes()
    if len(data) > max_bytes:
        raise contract_error("safepath.error.too_large", path=path)
    return data


def problems_of(text: str) -> list[str]:
    return [TR.text(p) for p in config.check_content(text.encode("utf-8"))]


def render_demo(
    width: int, charset: str, level: ColorLevel, the_look: Look = DEFAULT_LOOK, **kw: Any
) -> str:
    inp = replace(demo.demo_input(**kw), look=the_look)
    cs = UNICODE if charset == "unicode" else ASCII
    return renderer.render(inp, width, themed(cs, level, the_look))


# --- colours ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("red", Color(1, 1)),
        ("bright-blue", Color(12, 12)),
        ("grey", Color(8, 8)),
        ("bold yellow", Color(3, 3, True)),
        ("yellow bold", Color(3, 3, True)),
        ("bold", Color(bold=True)),
        ("default", Color()),
        (208, Color(3, 208)),  # orange: yellow is the nearest of the 16
        ("208", Color(3, 208)),
        ("#5fafff", Color(12, 75)),
        ("#5FAFFF", Color(12, 75)),
    ],
)
def test_colour_values(value: object, expected: Color) -> None:
    assert look.parse_color(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "\x1b[31m",
        "31m",
        "red\x1b",
        "38;5;196",
        "#ff00",
        "#gggggg",
        256,
        -1,
        "256",
        "007",
        True,
        1.5,
        "",
        "bold bold red",
        "red  bold",
        "red green",
        "status",
        "Red",
        "x" * 40,
    ],
)
def test_colour_values_refused(value: object) -> None:
    assert look.parse_color(value) is None


def test_status_is_only_for_the_used_part_of_a_meter() -> None:
    assert look.parse_color("status", allow_status=True) == Color(status=True)
    assert "theme.colors.bar_used" not in " ".join(
        problems_of('[theme.colors]\nbar_used = "status"')
    )
    assert problems_of('[theme.colors]\nframe = "status"') == [
        'theme.colors.frame must be a colour: a name such as "blue" or "bright-red", a number '
        'from 0 to 255, "#rrggbb" or "default", optionally with "bold"'
    ]


def test_contrast_of_the_palette() -> None:
    assert look.contrast_on_black(look.rgb_of(244)) == pytest.approx(5.3, abs=0.1)
    assert look.contrast_on_black(look.rgb_of(240)) < 3  # the phase 4 free part: too dark
    assert look.rgb_of(16) == (0, 0, 0) and look.rgb_of(231) == (255, 255, 255)
    assert look.rgb_of(232) == (8, 8, 8) and look.rgb_of(255) == (238, 238, 238)


@pytest.mark.parametrize("value", ["black", 240, "#202020", "blue", 17])
def test_a_dark_free_part_is_refused(value: object) -> None:
    text = f"[theme.colors]\nbar_free = {json.dumps(value)}"
    assert problems_of(text) == [
        "theme.colors.bar_free must stand out on a black background (contrast of at least "
        "3:1), so the free part of a meter stays visible"
    ]


def test_sgr_is_built_from_numbers_only() -> None:
    assert sgr(Color(1, 196, True), ColorLevel.BASIC) == "\x1b[1;31m"
    assert sgr(Color(9, 196), ColorLevel.BASIC) == "\x1b[91m"
    assert sgr(Color(1, 196, True), ColorLevel.EXTENDED) == "\x1b[1;38;5;196m"
    assert sgr(Color(), ColorLevel.EXTENDED) == ""
    assert sgr(Color(1, 1), ColorLevel.OFF) == ""
    # out-of-range numbers (a forged look) produce no colour, never other bytes
    assert sgr(Color(99, 999), ColorLevel.EXTENDED) == ""
    assert sgr(Color(99, 999), ColorLevel.BASIC) == ""


# --- characters -------------------------------------------------------------------------


@pytest.mark.parametrize("ch", ["─", "█", "▒", "+", "#", ".", " ", "·", "»"])
def test_theme_characters_allowed(ch: str) -> None:
    assert theme_char(ch)


@pytest.mark.parametrize(
    "ch",
    [
        "\x1b",
        "\x9b",
        "\x00",
        "\u200b",
        "\u202e",
        "\u0301",
        "\u6f22",
        "\U0001f600",
        "ab",
        "",
        "\ufe0f",
        "\u05d0",
        "\u0628",
        "\u0661",
    ],
)
def test_theme_characters_refused(ch: str) -> None:
    assert not theme_char(ch)


def test_unassigned_code_points_in_the_frame_ranges_are_refused() -> None:
    """Which code points are unassigned depends on the interpreter's Unicode version
    (U+1FBCB is unassigned in 15 and a character from 16 on), so the test asks it."""
    import unicodedata

    from motp.core.sanitize import _FRAME

    unassigned = [
        chr(cp)
        for start, end in _FRAME
        for cp in range(start, end + 1)
        if unicodedata.category(chr(cp)) == "Cn"
    ]
    assert unassigned, "the legacy-computing block has unassigned code points in every version"
    assert not any(theme_char(ch) for ch in unassigned)


def test_config_check_names_a_two_cell_character() -> None:
    assert problems_of('[theme.chars.unicode]\nhorizontal = "━━"\nvertical = "漢"') == [
        "theme.chars.unicode.horizontal must be exactly one printable character, one cell wide",
        "theme.chars.unicode.vertical must be exactly one printable character, one cell wide",
    ]
    assert problems_of('[theme.chars.ascii]\nhorizontal = "─"') == [
        "theme.chars.ascii.horizontal must be exactly one printable ASCII character"
    ]


def test_meter_parts_must_differ_and_show() -> None:
    assert problems_of('[theme.chars.ascii]\nbar_free = " "') == [
        "theme.chars.ascii.bar_free must be exactly one printable ASCII character"
    ]
    assert problems_of('[theme.chars.unicode]\nbar_free = "█"') == [
        "theme.chars.unicode: bar_used and bar_free must differ, so the used and the free part "
        "of a meter can be told apart"
    ]
    assert problems_of('[theme.chars.ascii]\nbar_open = ""\nbar_close = ""') == []


# --- the escape byte never travels -------------------------------------------------------

ESCAPE_VALUES = [
    ("theme.colors", "frame", "\x1b[31m"),
    ("theme.colors", "bar_used", "status\x1b"),
    ("theme.chars.unicode", "horizontal", "\x1b"),
    ("theme.chars.ascii", "leader", "\x1b"),
    ("theme.chars.unicode", "bar_open", "\x1b[2J"),
    ("layout", "header_color", "\x1b[5m"),
    ("layout", "header_font", "big\x1b"),
    ("layout", "header_text", "web\x1b[2J"),
    ("layout.section_titles", "host", "Host\x1b]0;x\x07"),
    ("theme", "preset", "classic\x1b"),
    ("theme.bar", "text", "full\x1b"),
    ("layout", "label_style", "dots\x1b"),
]


@pytest.mark.parametrize(("table", "key", "value"), ESCAPE_VALUES)
def test_a_config_value_with_an_escape_byte_is_refused(table: str, key: str, value: str) -> None:
    text = f"[{table}]\n{key} = {json.dumps(value)}\n"
    found = problems_of(text)
    assert len(found) == 1 and f"{table}.{key}" in found[0], found
    assert ESC not in found[0]  # the message quotes the key, never the value


@pytest.mark.parametrize(("table", "key", "value"), ESCAPE_VALUES)
def test_an_escape_byte_in_the_config_never_reaches_the_output(
    tmp_path: Path, table: str, key: str, value: str
) -> None:
    """The whole path: config file, collector, render.json, renderer, terminal."""
    (tmp_path / "config.toml").write_text(f"[{table}]\n{key} = {json.dumps(value)}\n")
    loaded = config.load(str(tmp_path), read=plain_read)
    assert loaded.problems and loaded.applied == ()
    settings = runner.render_settings(loaded.config, demo.NOW, "apt")
    decoded = cache.decode_render_file(cache.encode_render_file(settings))
    inp = replace(demo.demo_input(), look=decoded.look, layout=decoded.layout)
    for cs in (UNICODE, ASCII):
        for level in ColorLevel:
            text = renderer.render(inp, 80, themed(cs, level, decoded.look))
            allowed = escape_sequences(decoded.look)
            assert set(SGR.findall(text)) <= {s[2:-1] for s in allowed}
            assert text.count(ESC) == len(SGR.findall(text))


def test_a_full_theme_from_the_config_reaches_render_json(tmp_path: Path) -> None:
    (tmp_path / "config.toml").write_text(
        "[theme]\npreset = 'classic'\n"
        "[theme.colors]\nlabel = 'bold #5fafff'\nbar_free = 'bright-green'\n"
        "[theme.chars.unicode]\nhorizontal = '═'\nbar_free = '░'\n"
        "[theme.bar]\nwidth = 30\ntext = 'short'\n"
        "[layout]\nheader_align = 'center'\nframe = false\nlabel_style = 'colon'\n"
        "label_width = 12\nhide_rows = ['os_host.kernel']\n"
        "[layout.section_titles]\nhost = 'Machine'\n"
        "[layout.row_order]\nhost = ['net_addresses.local']\n",
        encoding="utf-8",
    )
    loaded = config.load(str(tmp_path), read=plain_read)
    assert loaded.problems == ()
    got = loaded.config.look
    assert got.preset == "classic" and got.colors["label"] == Color(12, 75, True)
    assert got.colors["value"] == PRESET_LOOKS["classic"].colors["value"]
    assert got.chars["unicode"].horizontal == "═" and got.chars["unicode"].vertical == "|"
    assert (got.bar.width, got.bar.style, got.bar.text) == (30, "below", "short")
    settings = runner.render_settings(loaded.config, 1, "")
    assert cache.decode_render_file(cache.encode_render_file(settings)).look == got


# --- render.json is untrusted input ------------------------------------------------------


def _render_json(the_look: Look) -> dict[str, Any]:
    settings = cache.RenderSettings(1, Layout(), "auto", {}, 300, 1000, "", the_look)
    obj: dict[str, Any] = json.loads(cache.encode_render_file(settings))
    return obj


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("preset",), "fancy"),
        (("colors", "frame", "basic"), 16),
        (("colors", "frame", "extended"), 256),
        (("colors", "frame", "extended"), "31m"),
        (("colors", "frame", "bold"), 1),
        (("colors", "frame", "status"), True),
        (("colors", "bar_free", "extended"), 240),
        (("colors", "frame", "sgr"), "\x1b[31m"),
        (("chars", "unicode", "horizontal"), "\x1b"),
        (("chars", "unicode", "horizontal"), "──"),
        (("chars", "ascii", "horizontal"), "─"),
        (("chars", "unicode", "bar_free"), "█"),
        (("chars", "unicode", "bar_free"), " "),
        (("bar", "width"), 500),
        (("bar", "text"), "everything"),
        (("header_font", "ascii"), "motp-block"),
        (("header_font", "unicode"), "missing"),
        (("header_font", "unicode"), "../../etc/passwd"),
        (("label_width",), 99),
        (("section_titles",), {"weather": "x"}),
        (("hidden_rows",), ["\x1b"]),
        (("hidden_rows",), ["a.b"] * 65),
        (("row_order",), {"host": "os_host.kernel"}),
        (("fonts",), {"big": {}}),
    ],
)
def test_render_json_look_is_checked_on_read(path: tuple[str, ...], value: Any) -> None:
    obj = _render_json(DEFAULT_LOOK)
    target = obj["look"]
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(ContractError):
        cache.decode_render_file(json.dumps(obj).encode())


def _forged_font(**changes: Any) -> dict[str, Any]:
    good = config.admin_font("forged", font_file(["## @", "## @@"]))
    assert good is not None
    font = look.font_json(good)
    font.update(changes)
    return font


def _glyphs(row: str, height: int = 2) -> dict[str, list[str]]:
    return {ch: [row] * height for ch in figfont.DRAWN}


FORGED_FONTS = [
    {"glyphs": _glyphs("\x1b[2J")},
    {"glyphs": _glyphs("\x1b]0;x\x07")},
    {"glyphs": _glyphs("#\x9b")},
    {"glyphs": _glyphs("#\u202e")},
    {"glyphs": _glyphs("#\u200b")},
    {"glyphs": _glyphs("#\u0301")},
    {"glyphs": _glyphs("#\u6f22")},
    {"glyphs": _glyphs("#\u05d0")},
    {"hardblank": "\x1b"},
    {"hardblank": " "},
    {"hardblank": "$$"},
    {"height": 17, "glyphs": _glyphs("#", 17)},
    {"height": 0},
    {"glyphs": _glyphs("#" * 65)},
    {"glyphs": _glyphs("#" * 64, 3), "height": 3},  # 95 x 64 x 3 cells: over the total
    {"glyphs": {ch: ["#", "##"] for ch in figfont.DRAWN}},  # ragged rows
    {"glyphs": {ch: ["#", "#"] for ch in figfont.DRAWN[:-1]}},  # a glyph missing
    {"smush": 256},
    {"extra": 1},
]


@pytest.mark.parametrize("change", FORGED_FONTS)
def test_render_json_admin_font_is_checked_on_read(change: dict[str, Any]) -> None:
    obj = _render_json(DEFAULT_LOOK)
    obj["look"]["fonts"] = {"forged": _forged_font(**change)}
    obj["look"]["header_font"]["unicode"] = "forged"
    with pytest.raises(ContractError):
        cache.decode_render_file(json.dumps(obj).encode())


@pytest.mark.parametrize(
    ("fonts", "header"),
    [
        ({"a": {}, "b": {}, "c": {}}, "a"),  # three fonts
        ({"../x": {}}, "../x"),
        ({"big": {}}, "big"),
    ],
)
def test_render_json_font_names_are_checked(fonts: dict[str, Any], header: str) -> None:
    obj = _render_json(DEFAULT_LOOK)
    obj["look"]["fonts"] = {name: _forged_font() for name in fonts}
    obj["look"]["header_font"]["unicode"] = header
    with pytest.raises(ContractError):
        cache.decode_render_file(json.dumps(obj).encode())


def test_render_json_ascii_header_needs_an_ascii_font() -> None:
    obj = _render_json(DEFAULT_LOOK)
    obj["look"]["fonts"] = {"forged": _forged_font(glyphs=_glyphs("\u2593\u2593"))}
    obj["look"]["header_font"]["ascii"] = "forged"
    with pytest.raises(ContractError):
        cache.decode_render_file(json.dumps(obj).encode())
    obj["look"]["header_font"] = {"unicode": "forged", "ascii": "big"}
    assert cache.decode_render_file(json.dumps(obj).encode()).look.fonts["forged"].height == 2


def test_an_accepted_admin_font_never_puts_an_escape_byte_out() -> None:
    obj = _render_json(DEFAULT_LOOK)
    obj["look"]["fonts"] = {"forged": _forged_font(glyphs=_glyphs("\u2593$#"))}
    obj["look"]["header_font"] = {"unicode": "forged", "ascii": "big"}
    decoded = cache.decode_render_file(json.dumps(obj).encode()).look
    inp = replace(demo.demo_input(), look=decoded)
    for cs in (UNICODE, ASCII):
        for level in ColorLevel:
            text = renderer.render(inp, 80, themed(cs, level, decoded))
            assert text.count(ESC) == len(SGR.findall(text))
            assert {f"\x1b[{p}m" for p in SGR.findall(text)} <= escape_sequences(decoded)
            assert "$" not in text.split("\n")[1]  # the hardblank became a space


def test_render_json_section_titles_are_sanitised() -> None:
    obj = _render_json(DEFAULT_LOOK)
    obj["look"]["section_titles"] = {"host": "Ho\x1b[2Jst"}
    decoded = cache.decode_render_file(json.dumps(obj).encode())
    assert decoded.look.section_titles == {"host": "Ho[2Jst"}


# --- admin fonts -------------------------------------------------------------------------


def font_file(rows: "list[str]", height: int = 2, smush: int = -1) -> bytes:
    """A FIGfont whose every glyph is ``rows`` (each row ends in its endmark)."""
    lines = [f"flf2a$ {height} {height} 8 {smush} 1", "test font"]
    for _ in figfont.REQUIRED:
        lines += rows[:height]
    return ("\n".join(lines) + "\n").encode("utf-8")


UNICODE_FONT = font_file(["▓▓ @", "▓▓ @@"])
ASCII_FONT = font_file(["## @", "## @@"])


def font_tree(root: Path, layout_text: str, **fonts: bytes) -> Path:
    (root / "config.toml").write_text(f"[layout]\n{layout_text}\n", encoding="utf-8")
    (root / "fonts").mkdir()
    for name, data in fonts.items():
        (root / "fonts" / f"{name}.flf").write_bytes(data)
    return root


def test_an_admin_font_travels_in_render_json_and_draws_the_header(tmp_path: Path) -> None:
    root = font_tree(
        tmp_path, "header_font = 'blocky'\nheader_font_ascii = 'hashes'",
        blocky=UNICODE_FONT, hashes=ASCII_FONT,
    )  # fmt: skip
    loaded = config.load(str(root), read=plain_read)
    assert loaded.problems == ()
    got = loaded.config.look
    assert got.header_font == {"unicode": "blocky", "ascii": "hashes"}
    assert set(got.fonts) == {"blocky", "hashes"}
    assert set(got.fonts["blocky"].glyphs) == set(figfont.DRAWN)  # printable ASCII only
    settings = runner.render_settings(loaded.config, 1, "")
    decoded = cache.decode_render_file(cache.encode_render_file(settings)).look
    assert decoded == got
    inp = replace(demo.demo_input(hostname="ab"), look=decoded)
    text = renderer.render(inp, 80, themed(UNICODE, ColorLevel.OFF, decoded))
    assert text.splitlines()[1] == "│  ▓▓ ▓▓" + " " * 71 + "│"
    text = renderer.render(inp, 80, themed(ASCII, ColorLevel.OFF, decoded))
    assert text.splitlines()[1] == "|  ## ##" + " " * 71 + "|"


def test_an_admin_font_falls_back_to_the_small_bundled_font(tmp_path: Path) -> None:
    wide = font_file(["#" * 30 + "@", "#" * 30 + "@@"])
    root = font_tree(tmp_path, "header_font_ascii = 'wide'", wide=wide)
    the_look = config.load(str(root), read=plain_read).config.look
    fonts = layout.header_fonts(themed(ASCII, ColorLevel.OFF, the_look))
    assert [f.name for f in fonts] == ["wide", "small"]


def test_one_unicode_font_for_both_header_keys_keeps_render_json_valid(tmp_path: Path) -> None:
    """Code review, high: the ASCII check was skipped for a font the Unicode key read."""
    root = font_tree(
        tmp_path, "header_font = 'mine'\nheader_font_ascii = 'mine'", mine=UNICODE_FONT
    )
    loaded = config.load(str(root), read=plain_read)
    assert [(p.reason.id, dict(p.reason.params)["key"]) for p in loaded.problems] == [
        ("config.error.font_ascii", "layout.header_font_ascii")
    ]
    got = loaded.config.look
    assert got.header_font == {"unicode": "mine", "ascii": "big"}
    settings = runner.render_settings(loaded.config, 1, "")
    assert cache.decode_render_file(cache.encode_render_file(settings)).look == got
    # resolve itself never gives the ASCII header a font that is not ASCII
    font = config.admin_font("mine", UNICODE_FONT)
    assert font is not None
    resolved = look.resolve({}, {"header_font_ascii": "mine"}, {"mine": font})
    assert resolved.header_font["ascii"] == "big"


def test_a_broken_font_named_twice_is_reported_once(tmp_path: Path) -> None:
    root = font_tree(tmp_path, "header_font = 'bad'\nheader_font_ascii = 'bad'", bad=b"x")
    loaded = config.load(str(root), read=plain_read)
    assert [p.reason.id for p in loaded.problems] == ["config.error.font_format"]


def test_the_largest_valid_look_fits_render_json() -> None:
    """Code review, low: limits in cells and keys must fit the reader's byte limit."""
    wide = "\U0001d400" * 57  # four bytes in UTF-8; 95 glyphs of 3 x 57 = 16245 cells
    big = figfont.Font("big1", 3, "$", 0, dict.fromkeys(figfont.DRAWN, (wide,) * 3))
    keys = tuple(f"plugin.99-{'x' * 45}.{'k' * 20}.{n:03d}"[:128] for n in range(64))
    largest = _with(
        fonts={"one": replace(big, name="one"), "two": replace(big, name="two")},
        header_font={"unicode": "one", "ascii": "big"},
        hidden_rows=keys,
        row_order=dict.fromkeys(look.SECTION_NAMES, keys),
        section_titles=dict.fromkeys(look.SECTION_NAMES, "T" * 40),
    )
    settings = cache.RenderSettings(1, Layout(), "auto", {}, 300, 1000, "", largest)
    data = cache.encode_render_file(settings)
    assert len(data) <= cache.MAX_RENDER_BYTES
    assert cache.decode_render_file(data).look == largest


def refusing_read(path: str, max_bytes: int) -> bytes:
    if path.endswith(".flf"):
        raise contract_error("safepath.error.owner", path=path)
    return plain_read(path, max_bytes)


def test_config_check_names_a_font_that_fails_the_ownership_check(tmp_path: Path) -> None:
    root = font_tree(tmp_path, "header_font = 'slant'", slant=UNICODE_FONT)
    loaded = config.load(str(root), read=refusing_read)
    font = str(root / "fonts" / "slant.flf")
    assert [(p.file, p.reason.id) for p in loaded.problems] == [
        (font, "safepath.error.owner"),
        (font, "config.error.font_file"),
    ]
    assert TR.text(loaded.problems[0].reason).endswith(" does not belong to root")
    assert TR.text(loaded.problems[1].reason) == (
        "layout.header_font: this font is not used. Expected a FIGfont file of at most "
        "128 KiB that belongs to root and is not writable by group or others"
    )
    assert loaded.config.look.header_font["unicode"] == "motp-block"  # the preset's font
    assert loaded.config.look.fonts == {}


@pytest.mark.parametrize(
    ("data", "key", "message"),
    [
        (b"not a font", "header_font", "this font is not used. Expected a FIGfont file whose"),
        (font_file(["\x1b[2J@", "x@@"]), "header_font", "Expected a FIGfont file whose"),
        (font_file(["漢@", "x@@"]), "header_font", "Expected a FIGfont file whose"),
        (font_file(["#" * 60 + "@", "#@@"]), "header_font", "Expected a FIGfont file whose"),
        (UNICODE_FONT, "header_font_ascii", "The ASCII header needs a font drawn with ASCII"),
    ],
)
def test_bad_admin_fonts_are_not_used(tmp_path: Path, data: bytes, key: str, message: str) -> None:
    root = font_tree(tmp_path, f"{key} = 'mine'", mine=data)
    loaded = config.load(str(root), read=plain_read)
    assert len(loaded.problems) == 1 and message in TR.text(loaded.problems[0].reason)
    assert loaded.config.look.fonts == {}


def test_font_names_are_checked() -> None:
    assert problems_of("[layout]\nheader_font = '../shadow'") == [
        'layout.header_font must be "auto", a bundled font (motp-block, motp-block-small, big, '
        'small) or the name of a file in /etc/motp/fonts/ without ".flf"'
    ]
    assert problems_of("[layout]\nheader_font_ascii = 'motp-block'") == [
        "layout.header_font_ascii: motp-block and motp-block-small draw block characters for "
        "Unicode terminals; use big, small or a font of ASCII characters"
    ]
    assert problems_of("[layout]\nheader_font = 'big'\nheader_font_ascii = 'small'") == []


@linux_root
def test_motp_config_check_reports_a_foreign_font_file(
    trusted_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The three ``config check`` cases of phase 4b on a real root tree."""
    root = font_tree(
        trusted_dir,
        "header_font = 'slant'\n[theme.colors]\nframe = 'purple'\n"
        "[theme.chars.unicode]\nvertical = '漢'",
        slant=UNICODE_FONT,
    )
    os.chmod(root / "config.toml", 0o644)
    os.chmod(root / "fonts", 0o755)
    os.chown(root / "fonts" / "slant.flf", *account(OTHER_USER))
    assert cli.config_check(TR, None, str(root)) == 1
    out = capsys.readouterr().out
    main = root / "config.toml"
    assert f'{main}, line 4: theme.colors.frame must be a colour: a name such as "blue"' in out
    assert (
        f"{main}, line 6: theme.chars.unicode.vertical must be exactly one printable character, "
        "one cell wide" in out
    )
    os.chmod(main, 0o644)
    main.write_text("[layout]\nheader_font = 'slant'\n")
    assert cli.config_check(TR, None, str(root)) == 1
    out = capsys.readouterr().out
    font = root / "fonts" / "slant.flf"
    assert f"{font}: {font} does not belong to root" in out
    assert f"{font}: layout.header_font: this font is not used. Expected a FIGfont file" in out


# --- presets and layout keys --------------------------------------------------------------


def test_presets_differ_as_the_blueprint_says() -> None:
    default, classic = PRESET_LOOKS["default"], PRESET_LOOKS["classic"]
    assert default.header_font == {"unicode": "motp-block", "ascii": "big"}
    assert classic.header_font == {"unicode": "big", "ascii": "big"}
    assert classic.colors["value"].basic == 3  # neutral values in yellow
    assert (classic.colors["bar_used"].basic, classic.colors["bar_free"].basic) == (1, 2)
    assert classic.chars["unicode"].horizontal == "-" and classic.chars["unicode"].vertical == "|"
    assert default.colors["bar_used"].status


def test_preview_takes_a_preset(capfd: pytest.CaptureFixture[str]) -> None:
    args = ["preview", "--demo", "--width", "80", "--charset", "unicode", "--color", "never"]
    assert cli.main([*args, "--preset", "classic"]) == 0
    out = capfd.readouterr().out
    assert out.splitlines()[0].startswith("+---") and "|  __" in out
    with pytest.raises(SystemExit):
        cli.main([*args, "--preset", "neon"])


def _with(**changes: Any) -> Look:
    return replace(DEFAULT_LOOK, **changes)


def test_frame_off_draws_titles_and_rows_without_a_frame() -> None:
    text = render_demo(80, "unicode", ColorLevel.OFF, _with(frame=False))
    assert not set("│┌┐└┘├┤") & set(text.replace("╔", "").replace("╗", ""))
    lines = text.splitlines()
    assert "Host" in lines and "  Hostname.........:  web01.example.com" in lines


@pytest.mark.parametrize(
    ("style", "line"),
    [
        ("dots", "│  Hostname.........:  web01.example.com"),
        ("colon", "│  Hostname:           web01.example.com"),
        ("plain", "│  Hostname            web01.example.com"),
    ],
)
def test_label_styles(style: str, line: str) -> None:
    text = render_demo(80, "unicode", ColorLevel.OFF, _with(label_style=style))
    assert any(row.startswith(line) for row in text.splitlines())


def test_label_width() -> None:
    text = render_demo(80, "unicode", ColorLevel.OFF, _with(label_width=12))
    assert any(row.startswith("│  Hostname...:  web01") for row in text.splitlines())


@pytest.mark.parametrize(("align", "pad"), [("left", 0), ("center", 19), ("right", 38)])
def test_header_alignment(align: str, pad: int) -> None:
    lines = render_demo(80, "unicode", ColorLevel.OFF, _with(header_align=align)).splitlines()
    assert lines[1].startswith("│  " + " " * pad + "██╗")


def test_header_case() -> None:
    upper = render_demo(80, "ascii", ColorLevel.OFF).splitlines()
    as_is = render_demo(80, "ascii", ColorLevel.OFF, _with(header_case="as-is")).splitlines()
    assert upper[1] != as_is[1]
    assert view.build(replace(demo.demo_input(), look=_with(header_case="as-is"))).header == "web01"
    assert view.build(demo.demo_input()).header == "WEB01"


def test_section_titles_hidden_and_ordered_rows() -> None:
    the_look = _with(
        section_titles={"host": "Machine"},
        hidden_rows=("os_host.kernel", "os_updates.pending"),
        row_order={"host": ("net_addresses.local",), "system": ("os_eol.date", "os_uptime.uptime")},
    )
    v = view.build(replace(demo.demo_input(), look=the_look))
    host = next(s for s in v.sections if s.name == "host")
    assert host.title == "Machine"
    assert [r.label for r in host.rows] == [
        "Local address", "Hostname", "Operating system", "DNS servers"
    ]  # fmt: skip
    system = next(s for s in v.sections if s.name == "system")
    assert [r.label for r in system.rows][:2] == ["Support", "Uptime"]
    assert "Packages" not in [r.label for r in system.rows], "details go with their item"
    # a hidden row still raises its alert
    assert any(a.text == "12 updates, 3 security" for a in v.sections[0].alerts)


def test_bar_width_style_and_text() -> None:
    narrow = render_demo(80, "ascii", ColorLevel.OFF, _with(bar=look.Bar(10, "below", "full")))
    assert "[###-----]" in narrow and "[#######-]" in narrow
    off = render_demo(80, "ascii", ColorLevel.OFF, _with(bar=look.Bar(0, "off", "full")))
    assert "[#" not in off and "41% of 200 GiB, 118 GiB free" in off
    for text, shown in (("used", "41% of 200 GiB"), ("free", "118 GiB free"), ("percent", "41%")):
        drawn = render_demo(80, "ascii", ColorLevel.OFF, _with(bar=look.Bar(0, "below", text)))
        match = re.search(r"/home\.+:  (.*?) *\|", drawn)
        assert match is not None and match.group(1) == shown


def test_meter_text_shortens_before_the_bar_goes() -> None:
    full = "41% of 1023.5 TiB, 603.9 TiB free (the archive)"
    row = view.Row("/home", full, bar=0.41, forms=("41%, 603.9 TiB free", "41%"))
    v = view.View("", "", (view.Section("disks", "Disks", rows=(row,)),))
    theme = themed(ASCII, ColorLevel.OFF)
    for width, shown in ((80, full), (60, "41%, 603.9 TiB free")):
        lines = layout.render(v, width, theme)
        assert shown + " " in lines[1] and "[" in lines[2], width
    lines = layout.render(v, 46, theme)  # plain layout: no bar; the shorter text fits
    assert lines[1] == "  /home: 41%, 603.9 TiB free"


def test_old_cache_without_the_free_amount_keeps_its_text() -> None:
    from motp.core.model import MessageRef

    assert view.meter_texts(TR, MessageRef("disk.usage", (("percent", "4%"),)), "full") is None
    full = view.meter_texts(
        TR, MessageRef("disk.usage", (("free", "1 B"), ("percent", "4%"), ("size", "2 B"))), "full"
    )
    assert full == ("4% of 2 B, 1 B free", "4%, 1 B free", "4%")


# --- D36: every meter shows its free part ---------------------------------------------------

BAR_LABELS = ("/", "/home", "/var")


def _cells(line: str) -> list[tuple[str, str]]:
    """Visible characters of a line with the SGR parameters in force for each."""
    out = []
    state = ""
    pos = 0
    for match in SGR.finditer(line):
        out += [(ch, state) for ch in line[pos : match.start()]]
        state = "" if match.group(1) == "0" else match.group(1)
        pos = match.end()
    out += [(ch, state) for ch in line[pos:]]
    return out


def _index(params: str) -> Optional[int]:
    """The foreground colour index an SGR parameter string sets, or ``None``."""
    parts = params.split(";")
    if "38" in parts:
        return int(parts[parts.index("38") + 2])
    for part in parts:
        if part.isdigit() and 30 <= int(part) <= 37:
            return int(part) - 30
        if part.isdigit() and 90 <= int(part) <= 97:
            return int(part) - 90 + 8
    return None


def meter_problems(text: str, the_look: Look, charset: str, width: int) -> list[str]:
    """What breaks D36 in a rendered demo: the free part blank, missing, alike or dark.

    A meter line is a framed content line that holds nothing but meter characters. Its
    cells are read from where the bar starts for the bar's width, so blank free cells
    count as part of it.
    """
    chars = the_look.chars[charset]
    parts = {chars.bar_used, chars.bar_free, chars.bar_open, chars.bar_close} - {""}
    span = the_look.bar.width or layout.BAR_CELLS["wide" if width >= 80 else "compact"]
    found = []
    seen = 0
    for line in text.splitlines():
        cells = _cells(line)
        visible = "".join(ch for ch, _ in cells)
        if not visible.startswith(chars.vertical + "  "):
            continue
        content = visible[1:-1].strip()
        if len(content) < 2 or set(content) - parts:
            continue
        seen += 1
        start = visible.index(content[0], 1)
        bar = cells[start : start + span]
        inner = bar[len(chars.bar_open) : len(bar) - len(chars.bar_close)]
        used = [c for c in inner if c[0] == chars.bar_used]
        free = inner[len(used) :]
        if not free:
            found.append("no free part")
            continue
        if any(not ch.strip() for ch, _ in free):
            found.append("blank free cells")
        if any(ch == chars.bar_used for ch, _ in free) or (
            used and {c[0] for c in free} == {c[0] for c in used}
        ):
            found.append("free and used look alike")
        for _, params in free:
            index = _index(params)
            if index is not None and look.contrast_on_black(look.rgb_of(index)) < 3:
                found.append("free part contrast below 3:1")
                break
    if seen != len(BAR_LABELS):
        found.append(f"{seen} meters found")
    return found


@pytest.mark.parametrize("level", list(ColorLevel))
@pytest.mark.parametrize("charset", ["unicode", "ascii"])
@pytest.mark.parametrize("preset", sorted(PRESET_LOOKS))
@pytest.mark.parametrize("width", [80, 70])
def test_every_meter_shows_its_free_part(
    width: int, preset: str, charset: str, level: ColorLevel
) -> None:
    the_look = PRESET_LOOKS[preset]
    text = render_demo(width, charset, level, the_look)
    assert meter_problems(text, the_look, charset, width) == []


@pytest.mark.parametrize(
    ("change", "problem"),
    [
        ({"colors": {**DEFAULT_LOOK.colors, "bar_free": Color(8, 240)}}, "contrast below 3:1"),
        ({"colors": {**DEFAULT_LOOK.colors, "bar_free": Color(0, 16)}}, "contrast below 3:1"),
        ("blank", "blank free cells"),
        ("alike", "no free part"),
    ],
)
def test_the_meter_check_catches_a_broken_free_part(change: Any, problem: str) -> None:
    """The D36 test fails for the phase 4 bar (grey 240) and for a blank free part."""
    if change == "blank":
        chars = replace(DEFAULT_LOOK.chars["unicode"], bar_free=" ")
        the_look = _with(chars={**DEFAULT_LOOK.chars, "unicode": chars})
    elif change == "alike":
        chars = replace(DEFAULT_LOOK.chars["unicode"], bar_free="█")
        the_look = _with(chars={**DEFAULT_LOOK.chars, "unicode": chars})
    else:
        the_look = _with(**change)
    level = ColorLevel.EXTENDED if change != "blank" else ColorLevel.OFF
    text = render_demo(80, "unicode", level, the_look)
    assert any(problem in p for p in meter_problems(text, the_look, "unicode", 80))


def test_meter_cells_line_up_with_the_width() -> None:
    for preset, the_look in PRESET_LOOKS.items():
        for cs in ("unicode", "ascii"):
            text = render_demo(80, cs, ColorLevel.OFF, the_look)
            assert all(cell_width(line) == 80 for line in text.splitlines()), (preset, cs)

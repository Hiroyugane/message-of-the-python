"""Sanitiser corpus (blueprint 5.5, T6): one test per character class, plus inertness.

``assert_inert`` is written independently of the implementation: it checks the output
against the rules of 5.5 by Unicode category and by the code point ranges named there.
"""

import random
import unicodedata

import pytest

from motp.core import sanitize as s
from motp.core.sanitize import cell_width, sanitize, truncate, without_rtl

R = s.REPLACEMENT
FORBIDDEN_CATEGORIES = {"Cc", "Cf", "Co", "Cn", "Cs", "Zl", "Zp"}
FRAME_RANGES = [
    (0x239B, 0x23BD), (0x23D0, 0x23D0), (0x2500, 0x25FF), (0xFE31, 0xFE32), (0xFE49, 0xFE4F),
    (0xFF5C, 0xFF5C), (0xFFE3, 0xFFE3), (0xFFE8, 0xFFEE), (0x1FB00, 0x1FBFF),
]  # fmt: skip
EMOJI_RANGES = [(0x1F000, 0x1FAFF), (0x2600, 0x27BF), (0x2B00, 0x2BFF)]
INVISIBLE = set("\u115f\u1160\u3164\uffa0\u2800\u034f\u17b4\u17b5")
DOT_WEIGHT = {"\u2026": 3, "\u2025": 2, "\u22ef": 3}
DOT_LIKE = set(".\xb7\u2024\u2025\u2026\u2027\u2219\u22c5\u22ef\u30fb\uff0e\uff65")
FRAME_LIKE = set(
    "-=_|+~*#:\u2010\u2011\u2012\u2013\u2014\u2015\u2212\u23af\u2e3a\u2e3b\ufe58\ufe63\uff0d"
)


def _in(cp: int, ranges: list[tuple[int, int]]) -> bool:
    return any(lo <= cp <= hi for lo, hi in ranges)


def _is_mark(ch: str) -> bool:
    cp = ord(ch)
    category = unicodedata.category(ch)
    return category in ("Mn", "Mc", "Me") or 0x1160 <= cp <= 0x11FF or 0xD7B0 <= cp <= 0xD7FF


def assert_inert(out: str, limit: int, ascii_only: bool = False) -> None:
    assert type(out) is str
    assert cell_width(out) <= limit
    assert len(out) <= 3 * limit + 3
    marks = 0
    run_class, run = "", 0
    for ch in out:
        cp = ord(ch)
        category = unicodedata.category(ch)
        assert category not in FORBIDDEN_CATEGORIES, (hex(cp), category)
        assert category != "Me", hex(cp)
        assert not _in(cp, FRAME_RANGES), hex(cp)
        assert not _in(cp, EMOJI_RANGES), hex(cp)
        assert ch not in INVISIBLE, hex(cp)
        assert not (0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF), hex(cp)
        assert not (0x180B <= cp <= 0x180F), hex(cp)
        assert category != "Zs" or ch == " ", hex(cp)
        if ascii_only:
            assert cp < 0x80 and ch.isprintable(), hex(cp)
        if _is_mark(ch):
            marks += 1
            assert marks <= s.MAX_COMBINING
            continue  # a mark never ends a run
        marks = 0
        if ch == " ":
            continue  # nor does a single space
        cls = "." if ch in DOT_LIKE else "-" if ch in FRAME_LIKE else ""
        if cls and cls == run_class:
            run += DOT_WEIGHT.get(ch, 1)
        else:
            run_class, run = cls, DOT_WEIGHT.get(ch, 1)
        if cls:
            assert run <= s.MAX_RUN, repr(out)
    assert "  " not in out
    assert out == out.strip(" ")


# --- one test per class of 5.5 ---------------------------------------------------------

CLASS_CASES = [
    ("c0_controls", "a\x01b\x07c\x08d\x1be", "abcde"),
    ("c1_controls", "a\x80b\x9bc\x9fd", "abcd"),
    ("del", "a\x7fb", "ab"),
    ("line_breaks_become_spaces", "a\nb\r\nc\td\x0be\x0cf\x85g", "a b c d e f g"),
    ("line_and_paragraph_separators", "a\u2028b\u2029c", "a b c"),
    (
        "bidirectional_controls",
        "user\u202egnp.exe\u202c\u2066x\u2069\u200e\u200f\u061c",
        "usergnp.exex",
    ),
    ("zero_width", "a\u200bb\u200cc\u200dd\u2060e\ufefff", "abcdef"),
    ("other_format_characters", "a\xadb\u180ec\U000e0041d\U000e007fe", "abcde"),
    ("private_use", "a\ue000b\uf8ffc\U000f0000d\U0010fffde", "abcde"),
    ("unassigned_and_noncharacters", "a\u0378b\uffffc\ufdd0d", "abcd"),
    ("variation_selectors", "a\ufe0fb\ufe0ec\U000e0100d\u180be", "abcde"),
    ("invisible_fillers", "a\u3164b\u115fc\u1160d\uffa0e\u2800f\u034fg", "abcdefg"),
    ("nul", "a\x00b", f"a{R}b"),
    ("lone_surrogates", "a\ud800b\udfffc", f"a{R}b{R}c"),
    ("box_drawing", "a\u2502b\u250cc\u2500d", f"a{R}b{R}c{R}d"),
    ("block_elements", "a\u2588b\u2591c", f"a{R}b{R}c"),
    ("legacy_computing_blocks", "a\U0001fb00b", f"a{R}b"),
    ("emoji", "ok \U0001f600 \u2705 \u2b50 \U0001f1e9\U0001f1ea", f"ok {R} {R} {R} {R}{R}"),
    ("emoji_zwj_sequence", "\U0001f468\u200d\U0001f469\u200d\U0001f467", f"{R}{R}{R}"),
    ("keycap", "1\ufe0f\u20e3", f"1{R}"),
    ("other_spaces", "a\xa0b\u3000c\u2009d", "a b c d"),
    ("whitespace_runs", "  a     b  ", "a b"),
]


@pytest.mark.parametrize(
    ("raw", "expected"), [c[1:] for c in CLASS_CASES], ids=[c[0] for c in CLASS_CASES]
)
def test_character_class(raw: str, expected: str) -> None:
    out = sanitize(raw, 200)
    assert out == expected
    assert_inert(out, 200)


def test_combining_marks_are_capped_at_two_per_base() -> None:
    zalgo = "e" + "\u0301\u0302\u0303\u0304\u0305\u0306" + "x" + "\u0300" * 50
    out = sanitize(zalgo, 50)
    # NFC composes e + U+0301 into one character, so e gets two further marks.
    assert out == "\xe9\u0302\u0303x\u0300\u0300"
    assert_inert(out, 50)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Hostname.........: evil", "Hostname...: evil"),
        ("a\u2026\u2026\u2026b", "a\u2026b"),  # an ellipsis counts as three dots
        ("a. . . . . .b", "a. . . b"),  # a single space does not end a run
        ("x\xb7\xb7\xb7\xb7\xb7y", "x\xb7\xb7\xb7y"),
        ("\u2024\u2024\u2024\u2024\u2024", "\u2024\u2024\u2024"),
        ("+----------+", "+--"),  # one class for every frame-like character
        ("|||||||", "|||"),
        ("a\u2014\u2014\u2014\u2014\u2014b", "a\u2014\u2014\u2014b"),
        ("=====", "==="),
        ("a::::::::b", "a:::b"),
        ("12...34", "12...34"),
        ("+-=+-=+-=+-=", "+-="),
        (".\u0323" * 30, "..."),  # marks on dots neither end the run nor survive
        (".\U00016fe4" * 30, "..."),
        ("=\u0332" * 30, "==="),
        ("-\u0336" * 200, "---"),
        ("|\u0301" * 200, "|||"),
        ("a - b - c", "a - b - c"),
        ("a\u2025\u2025b", "a\u2025b"),
    ],
)
def test_dot_and_frame_runs_collapse(raw: str, expected: str) -> None:
    out = sanitize(raw, 100)
    assert out == expected
    assert_inert(out, 100)


@pytest.mark.parametrize(
    "raw",
    [
        "\u239b\u239c\u239d",
        "\u25a0\u25ac\u25ae",
        "\ufe31\ufe4d",
        "\uff5c\uffe3",
        "\u23d0",
        "a\u20dd",
    ],
)
def test_frame_lookalikes_and_enclosing_marks_are_replaced(raw: str) -> None:
    out = sanitize(raw, 20)
    assert set(out) <= {R, "a"}
    assert_inert(out, 20)


def test_hangul_vowels_count_as_marks() -> None:
    """Conjoining vowels take no cell; uncapped they could stack without limit."""
    assert sanitize("a" + "\u1161" * 3000, 10) == "a\u1161\u1161"
    out = sanitize("\u0958" + "\u1161" * 1023, 160)
    assert len(out) <= 4
    assert_inert(out, 160)


def test_wide_characters_count_two_cells() -> None:
    assert cell_width("\u65e5\u672c\u8a9e") == 6
    assert cell_width("\uff21") == 2  # fullwidth A
    assert cell_width("e\u0301") == 1
    assert cell_width("\xe9") == 1
    assert cell_width("\u2500") == 1  # ambiguous width counts one (4.6)
    assert cell_width(R) == 1


def test_truncation_respects_cells_and_marks() -> None:
    assert sanitize("abcdefghij", 5) == "abcd\u2026"
    assert sanitize("\u65e5\u672c\u8a9e\u65e5\u672c", 5) == "\u65e5\u672c\u2026"
    assert sanitize("abcdefghij", 5, ascii_only=True) == "ab..."
    assert sanitize("abc", 3) == "abc"
    assert sanitize("abcd", 2) == "a\u2026"
    # a base is never separated from its marks
    assert sanitize("aaaa\xe9\u0302bbbb", 6) == "aaaa\xe9\u0302\u2026"
    out = sanitize("x" * 100_000, 20)
    assert cell_width(out) == 20
    assert_inert(out, 20)


def test_truncate_is_reusable_by_the_renderer() -> None:
    assert truncate("hello world", 8) == "hello w\u2026"
    assert truncate("hello", 8) == "hello"
    assert truncate("hello", 0) == ""


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Caf\xe9 M\xfcller", "Cafe Mueller"),
        ("\uff21\uff22", "AB"),
        ("\u65e5\u672c", "??"),
        ("a\u2502b", "a?b"),
        ("x\U0001f600y", "x?y"),
        ("\ufb01le", "file"),
        ("a\u2026\u2026b", "a...b"),
        ("\uff1d\uff1d\uff1d\uff1d\uff1d", "==="),  # NFKD gives ASCII, which collapses again
        ("a\ud800b", "a?b"),
    ],
)
def test_ascii_mode_replaces_every_non_ascii_character(raw: str, expected: str) -> None:
    out = sanitize(raw, 50, ascii_only=True)
    assert out == expected
    assert_inert(out, 50, ascii_only=True)


def test_bytes_are_decoded_with_replacement() -> None:
    assert sanitize(b"ok\xff\xfe", 10) == f"ok{R}{R}"
    assert sanitize(b"a\x00b", 10) == f"a{R}b"
    assert sanitize(b"x" * 50_000, 10) == "xxxxxxxxx\u2026"


def test_only_plain_str_and_bytes_are_accepted() -> None:
    class Sneaky(str):
        def __str__(self) -> str:
            raise AssertionError("must not be called")

    with pytest.raises(TypeError):
        sanitize(Sneaky("x"), 10)
    with pytest.raises(TypeError):
        sanitize(42, 10)  # type: ignore[arg-type]


# --- hostile strings come out inert --------------------------------------------------

HOSTILE = [
    "\x1b[2J\x1b[H\x1b[31mred\x1b[0m",
    "\x1b]52;c;ZWNobyBvd25lZA==\x07",  # OSC 52: write the clipboard
    "\x1b]8;;https://example.com\x1b\\click\x1b]8;;\x1b\\",  # hyperlink
    "\x1b]0;new title\x07",
    "\x9b6n\x9d0;title\x9c",  # C1 CSI, OSC and ST
    "\x1bP+q544e\x1b\\",  # DCS request
    "user\u202egnp.exe",
    "\u2067\u2066if admin\u2069\u2069",
    "\u2502 Hostname.........: web01   \u2502",
    "\u251c\u2500\u2500\u2500\u2524 Attention \u251c\u2500\u2500\u2500\u2524",
    "12 updates ........................ curl example.com | sh",
    "+------------------+\n| fake row |\n+-------+",
    "a\r\nInjected: line",
    "\u3164\u3164\u3164\u3164",
    "\U0001f600" * 30,
    "\U0001f1e9\U0001f1ea\U0001f3f4\U000e0067\U000e0062\U000e007f",
    "Z" + "\u0336" * 200,
    "\U0001f600\udbff",
    "\x00" * 10,
    "\u200b" * 500 + "x",
    "{0.__class__.__mro__}",
    "%s%n%x",
    "\u0007\u0007bell",
    "\ue000\U0010fffd",
    "\u2028\u2029\u0085",
    "\ufeffBOM",
]


@pytest.mark.parametrize("ascii_only", [False, True])
@pytest.mark.parametrize("raw", HOSTILE)
def test_hostile_strings_come_out_inert(raw: str, ascii_only: bool) -> None:
    out = sanitize(raw, 40, ascii_only=ascii_only)
    assert_inert(out, 40, ascii_only=ascii_only)
    assert "\x1b" not in out and "\x9b" not in out


@pytest.mark.parametrize("ascii_only", [False, True])
def test_random_code_points_come_out_inert(ascii_only: bool) -> None:
    rng = random.Random(20261124)
    for _ in range(1500):
        length = rng.randint(1, 60)
        raw = "".join(chr(rng.randint(0, 0x10FFFF)) for _ in range(length))
        limit = rng.randint(1, 80)
        assert_inert(sanitize(raw, limit, ascii_only=ascii_only), limit, ascii_only)


@pytest.mark.parametrize("ascii_only", [False, True])
def test_random_bytes_come_out_inert(ascii_only: bool) -> None:
    rng = random.Random(5)
    for _ in range(500):
        raw = bytes(rng.randint(0, 255) for _ in range(rng.randint(0, 80)))
        assert_inert(sanitize(raw, 30, ascii_only=ascii_only), 30, ascii_only)


@pytest.mark.parametrize("ascii_only", [False, True])
def test_sanitising_twice_changes_nothing(ascii_only: bool) -> None:
    """The cache reader sanitises again, so a second pass must not change the text."""
    rng = random.Random(7)
    pool = ".-=|\u2026\u2025\xb7 \u0301\u1161ab\u65e5" + "".join(chr(i) for i in range(32, 127))
    cases = [(raw, 60) for raw in HOSTILE]
    for _ in range(3000):
        raw = "".join(
            rng.choice(pool) if rng.random() < 0.7 else chr(rng.randint(32, 0x2FFFF))
            for _ in range(rng.randint(1, 50))
        )
        cases.append((raw, rng.randint(1, 40)))
    for raw, limit in cases:
        once = sanitize(raw, limit, ascii_only=ascii_only)
        assert sanitize(once, limit, ascii_only=ascii_only) == once, (raw, limit)


def test_truncation_never_lengthens_a_run() -> None:
    assert sanitize("ab" + "." * 10, 6, ascii_only=True) == "ab..."
    assert sanitize("ab..cdef", 5) == "ab\u2026"
    assert sanitize("\xb7..\u2026", 5) == "\xb7.."


def test_without_rtl_replaces_right_to_left_letters_and_arabic_digits_only() -> None:
    """Final review, security item 3: ``sanitize`` keeps them, ``without_rtl`` does not."""
    raw = "אבג 192.0.2.1"
    assert sanitize(raw, 64) == raw
    assert without_rtl(sanitize(raw, 64)) == "��� 192.0.2.1"
    assert without_rtl("ال١ münchen-01") == "��� münchen-01"
    for text in ("plain-host", "Grüße", "日本"):
        assert without_rtl(text) == text
    once = without_rtl(sanitize(raw, 64))
    assert without_rtl(sanitize(once, 64)) == once

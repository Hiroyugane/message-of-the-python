"""The pure-Python catalogue compiler under ``tools/`` (blueprint D19, 4.6)."""

import gettext
import io
import re
import sys

import pytest

from motp.core import i18n

from .conftest import SRC, TOOLS

sys.path.insert(0, str(TOOLS))
import compile_catalogs
from compile_catalogs import PoError, check, compile_mo, parse_po, template_problems

LOCALE = SRC / "motp" / "locale"
HEADER = (
    'msgid ""\nmsgstr ""\n"Language: {lang}\\n"\n'
    '"Plural-Forms: nplurals=2; plural=(n != 1);\\n"\n\n'
)


def _compile(body: str, lang: str = "en") -> bytes:
    header, kept = check(parse_po(HEADER.format(lang=lang) + body), lang, "t.po")
    return compile_mo(header, kept)


def test_message_id_patterns_agree() -> None:
    assert compile_catalogs.MESSAGE_ID.pattern == i18n.MESSAGE_ID.pattern


def test_plural_rules_match_the_catalogue_headers() -> None:
    for po in LOCALE.glob("*.po"):
        match = re.search(r"nplurals=(\d+);", po.read_text(encoding="utf-8"))
        assert match, po
        assert i18n.PLURAL_RULES[po.stem][0] == int(match.group(1))


def test_compiling_is_deterministic() -> None:
    first = compile_catalogs.compile_all(LOCALE)
    assert first == compile_catalogs.compile_all(LOCALE)
    assert set(first) == {f"{p.stem}.mo" for p in LOCALE.glob("*.po")}


def test_output_is_a_standard_mo_file() -> None:
    """The stdlib reader (used here only, never at run time) agrees with ours."""
    data = compile_catalogs.compile_file(LOCALE / "en.po")
    std = gettext.GNUTranslations(io.BytesIO(data))
    assert std.gettext("status.warn") == "warning"
    assert std.ngettext("modules.failed", "modules.failed", 1).startswith("{count} module failed")
    assert std.ngettext("modules.failed", "modules.failed", 5).startswith("{count} modules")
    assert std.info()["language"] == "en"


def test_round_trip_of_escapes_and_continuations() -> None:
    body = (
        'msgid "a.b"\nmsgstr ""\n"one \\"two\\" "\n"three\\\\four"\n\n'
        'msgid "a.c"\nmsgid_plural "a.c"\nmsgstr[0] "{count} x"\nmsgstr[1] "{count} xs"\n'
    )
    messages = i18n.parse_mo(_compile(body))
    assert messages["a.b"] == ('one "two" three\\four',)
    assert messages["a.c"] == ("{count} x", "{count} xs")


@pytest.mark.parametrize("escape", ["\\n", "\\t"])
def test_texts_are_single_lines(escape: str) -> None:
    """Messages are one line; a line break or tab is refused like any control character."""
    with pytest.raises(PoError):
        _compile(f'msgid "a.b"\nmsgstr "x{escape}y"\n')


@pytest.mark.parametrize(
    ("body", "lang"),
    [
        ('msgid "a.b"\nmsgstr "x \\u0041"\n', "en"),  # unsupported escape
        ('msgctxt "c"\nmsgid "a.b"\nmsgstr "x"\n', "en"),
        ('msgid "a.b"\nmsgstr "x"\n\nmsgid "a.b"\nmsgstr "y"\n', "en"),
        ('msgid "a.b"\nmsgid_plural "a.b"\nmsgstr[0] "x"\n', "en"),
        ('msgid "a.b"\nmsgstr[0] "x"\n', "en"),
        ('msgid "a.b"\nmsgid_plural "a.b"\nmsgstr "x"\n', "en"),
        ('msgid "Not An Id"\nmsgstr "x"\n', "en"),
        ('msgid "a.b"\nmsgstr "{a.b}"\n', "en"),
        ('msgid "a.b"\nmsgstr "{0}"\n', "en"),
        ('msgid "a.b"\nmsgstr "{a!r}"\n', "en"),
        ('msgid "a.b"\nmsgstr "lone }"\n', "en"),
        ('msgid "a.b"\nmsgstr ""\n', "en"),
        ('#, fuzzy\nmsgid "a.b"\nmsgstr "x"\n', "en"),
        ('msgid "a.b"\n', "en"),
        ('"x"\n', "en"),
        ('#~ msgid "a.b"\n', "en"),
        ('msgid "a.b" junk\nmsgstr "x"\n', "en"),
        ('msgid "a.b"\nmsgstr "red \x1b[31m"\n', "en"),  # raw ESC in the text
        ('msgid "a.b"\nmsgstr "x\u202ey"\n', "en"),  # bidi override
    ],
)
def test_invalid_catalogues_are_refused(body: str, lang: str) -> None:
    with pytest.raises(PoError):
        _compile(body, lang)


def test_header_is_checked() -> None:
    with pytest.raises(PoError):
        check(parse_po(HEADER.format(lang="de")), "en", "en.po")
    with pytest.raises(PoError):
        check(parse_po('msgid ""\nmsgstr "Language: en\\n"\n'), "en", "en.po")
    with pytest.raises(PoError):
        check(parse_po('msgid "a.b"\nmsgstr "x"\n'), "en", "en.po")


def test_fuzzy_and_empty_entries_of_other_languages_are_left_out() -> None:
    body = (
        '#, fuzzy\nmsgid "a.b"\nmsgstr "x"\n\nmsgid "a.c"\nmsgstr ""\n\nmsgid "a.d"\nmsgstr "y"\n'
    )
    assert i18n.parse_mo(_compile(body, "de")) == {"a.d": ("y",)}


@pytest.mark.parametrize(
    ("template", "ok"),
    [("{name} x", True), ("{{literal}}", True), ("a {count} b {n_2}", True), ("{a.b}", False),
     ("{a[0]}", False), ("{", False), ("}", False), ("{a:>3}", False), ("{ a }", False)],
)  # fmt: skip
def test_template_check(template: str, ok: bool) -> None:
    assert (template_problems(template) == []) is ok


def test_cli_check_mode(capsys: pytest.CaptureFixture[str]) -> None:
    assert compile_catalogs.main(["--check"]) == 0
    assert capsys.readouterr().out.startswith("ok: ")

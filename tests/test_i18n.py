"""Message catalogue, ``{name}`` substitution, plurals and loading (blueprint 4.4, 4.6, T22)."""

import struct
import subprocess
import sys
from pathlib import Path

import pytest

from motp.core import i18n, resources
from motp.core.i18n import (
    Catalog,
    CatalogError,
    Translator,
    language_from_env,
    param_text,
    parse_mo,
    substitute,
)
from motp.core.model import LiteralText, MessageRef

from .conftest import SRC, TOOLS

sys.path.insert(0, str(TOOLS))
import build_pyz
import compile_catalogs

EN = Translator("en")


# --- substitution (T22) -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("template", "expected"),
    [
        ("{a} and {b}", "1 and two"),
        ("{missing}", "{missing}"),
        ("{a.__class__}", "{a.__class__}"),
        ("{a.__class__.__init__.__globals__}", "{a.__class__.__init__.__globals__}"),
        ("{a[0]}", "{a[0]}"),
        ("{a['x']}", "{a['x']}"),
        ("{a!r}", "{a!r}"),
        ("{a:>10}", "{a:>10}"),
        ("{a:{b}}", "{a:two}"),
        ("{0}", "{0}"),
        ("{}", "{}"),
        ("{{a}}", "{a}"),
        ("{{{a}}}", "{1}"),
        ("unclosed {a", "unclosed {a"),
        ("lone } brace", "lone } brace"),
        ("%(a)s %s", "%(a)s %s"),
    ],
)
def test_substitute_replaces_plain_names_only(template: str, expected: str) -> None:
    assert substitute(template, {"a": "1", "b": "two"}) == expected


def test_substituted_values_are_not_scanned_again() -> None:
    assert substitute("{a}", {"a": "{b}", "b": "x"}) == "{b}"
    assert substitute("{a}{b}", {"a": "{", "b": "b}"}) == "{b}"


def test_attribute_or_index_access_in_a_parameter_renders_literally() -> None:
    hostile = "{name.__class__.__mro__[1].__subclasses__()}"
    assert EN.message("plugin.prefix", {"name": hostile}) == f"[plugin {hostile}]"
    assert EN.message("plugin.prefix", {"name": "{0[0]}"}) == "[plugin {0[0]}]"


def test_attribute_or_index_access_in_a_plugin_label_renders_literally() -> None:
    for label in ("{0.__class__}", "{name.__dict__[x]}", "{count}", "%s"):
        assert EN.text(LiteralText(label)) == label
        assert EN.text(LiteralText("x", (("en", label),))) == label


class Loud:
    def __str__(self) -> str:
        raise AssertionError("__str__ must not be called")

    def __format__(self, spec: str) -> str:
        raise AssertionError("__format__ must not be called")

    def __repr__(self) -> str:
        raise AssertionError("__repr__ must not be called")


class StrSub(str):
    def __str__(self) -> str:
        raise AssertionError("__str__ must not be called")


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (12, "12"),
        (-3, "-3"),
        (10**30, "?"),
        (0.5, "0.5"),
        (float("nan"), "?"),
        (float("inf"), "?"),
        (True, "?"),
        (None, "?"),
        ([1], "?"),
        ({"a": 1}, "?"),
        (Loud(), "?"),
        (StrSub("x"), "?"),
        ("plain", "plain"),
        ("\x1b[31mred\u202e", "[31mred"),
        ("x" * 500, "x" * 63 + "\u2026"),
    ],
)
def test_parameters_are_reduced_to_scalars(value: object, expected: str) -> None:
    assert param_text(value) == expected


def test_message_with_a_hostile_object_parameter() -> None:
    assert EN.message("plugin.prefix", {"name": Loud()}) == "[plugin ?]"  # type: ignore[dict-item]


# --- plural forms and fallback -------------------------------------------------------------


@pytest.mark.parametrize(
    ("count", "expected"),
    [
        (0, "0 modules failed"),
        (1, "1 module failed"),
        (2, "2 modules failed"),
        (21, "21 modules failed"),
    ],
)
def test_plural_selection_through_count(count: int, expected: str) -> None:
    assert EN.message("modules.failed", {"count": count}) == f"{expected}, run `motp doctor`"


def test_integral_float_count_selects_the_plural() -> None:
    assert EN.message("modules.failed", {"count": 2.0}).startswith("2.0 modules failed")
    assert EN.message("modules.failed", {"count": 1.0}).startswith("1.0 module failed")


def test_count_that_is_not_an_integer_uses_the_first_form() -> None:
    assert EN.message("modules.failed", {"count": "many"}).startswith("many module failed")


def test_unknown_ids() -> None:
    assert EN.message("no.such.message") == "no.such.message"
    assert EN.message("\x1b[2J") == "?"
    assert EN.text(MessageRef("status.warn")) == "warning"


def test_missing_language_falls_back_to_english() -> None:
    tr = Translator("xx")
    assert tr.language == "en" and tr.message("status.ok") == "ok"


def test_other_language_falls_back_per_message() -> None:
    de = Catalog("de", {"status.ok": ("in Ordnung",)})
    tr = Translator("en")
    tr._catalogs = [de, i18n.english()]  # a German catalogue with one entry
    tr.language = "de"
    assert tr.message("status.ok") == "in Ordnung"
    assert tr.message("status.warn") == "warning"
    assert tr.text(LiteralText("Backup", (("de", "Sicherung"),))) == "Sicherung"


# --- language selection -------------------------------------------------------------------


@pytest.fixture
def with_german(monkeypatch: pytest.MonkeyPatch) -> None:
    real = i18n.load

    def fake(code: str) -> "Catalog | None":
        return Catalog("de", {}) if code == "de" else real(code)

    monkeypatch.setattr(i18n, "load", fake)


@pytest.mark.parametrize(
    ("env", "expected"),
    [
        ({}, "en"),
        ({"LANG": "C"}, "en"),
        ({"LANG": "C.UTF-8", "LANGUAGE": "de"}, "en"),
        ({"LANG": "POSIX"}, "en"),
        ({"LANG": "de_DE.UTF-8"}, "de"),
        ({"LANG": "en_US.UTF-8", "LC_ALL": "de_AT.UTF-8@euro"}, "de"),
        ({"LANG": "de_DE.UTF-8", "LC_MESSAGES": "en_GB.UTF-8"}, "en"),
        ({"LANG": "fr_FR.UTF-8"}, "en"),
        ({"LANG": "fr_FR.UTF-8", "LANGUAGE": "fr:de:en"}, "de"),
        ({"LANG": "../../../etc/passwd"}, "en"),
        ({"LANG": "de/../../x_DE"}, "en"),
    ],
)
def test_language_from_env(with_german: None, env: dict[str, str], expected: str) -> None:
    assert language_from_env(env) == expected


def test_language_code_is_checked_before_it_names_a_resource(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(resources, "read", calls.append)
    for bad in ("../x", "de/../en", "DE", "d", "deutsch", "", "en\x00"):
        assert i18n.load(bad) is None
    assert calls == []


# --- .mo reading -------------------------------------------------------------------------


def _en_mo() -> bytes:
    return compile_catalogs.compile_file(SRC / "motp" / "locale" / "en.po")


def test_parse_mo_reads_the_compiled_catalogue() -> None:
    messages = parse_mo(_en_mo())
    assert messages["status.warn"] == ("warning",)
    assert len(messages["modules.failed"]) == 2
    assert "" not in messages


def test_parse_mo_reads_big_endian_files() -> None:
    data = _en_mo()
    count = struct.unpack_from("<I", data, 8)[0]
    words = 7 + 4 * count
    swapped = struct.pack(f">{words}I", *struct.unpack_from(f"<{words}I", data, 0))
    assert parse_mo(swapped + data[4 * words :]) == parse_mo(data)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d[:20],
        lambda d: b"\x00\x00\x00\x00" + d[4:],
        lambda d: d[:4] + struct.pack("<I", 1 << 16) + d[8:],
        lambda d: d[:8] + struct.pack("<I", 10**6) + d[12:],
        lambda d: d[:12] + struct.pack("<I", 10**8) + d[16:],
        lambda d: d[:28] + struct.pack("<2I", 10**6, 40) + d[36:],
        lambda d: d + b"\x00" * (1 << 20),
    ],
)
def test_parse_mo_checks_every_offset(mutate: object) -> None:
    with pytest.raises(CatalogError):
        parse_mo(mutate(_en_mo()))  # type: ignore[operator]


def test_catalogue_loads_from_the_archive(tmp_path: Path) -> None:
    archive = tmp_path / "motp.pyz"
    build_pyz.build(SRC, archive)
    code = (
        f"import sys; sys.path.insert(0, {str(archive)!r}); from motp.core import i18n; "
        "t = i18n.translator('en'); "
        "print(i18n.load('en') is not None, t.message('modules.failed', {'count': 2}))"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-c", code], capture_output=True, text=True, cwd=tmp_path
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "True 2 modules failed, run `motp doctor`\n"


def test_compose_inserts_finished_texts_without_the_parameter_limit() -> None:
    tr = i18n.Translator("en")
    long_path = "/etc/motp/conf.d/" + "a" * 100 + ".toml"
    line = tr.compose("config.check.problem", {"file": long_path, "reason": "x {file}"})
    assert line == f"{long_path}: x {{file}}"  # inserted once, never scanned again
    assert tr.compose("no.such_id", {}) == "no.such_id"

"""``motp explain`` (blueprint D19, 4.13, phase 13)."""

import json
import os
import re
from pathlib import Path
from typing import Optional

import pytest

from motp import cli, explain, show
from motp.core import cache, hints, i18n
from motp.core.cache import Layout, RenderSettings
from motp.core.sanitize import cell_width
from motp.core.thresholds import make_rule

LOCALE_VARIABLES = ("LANG", "LC_ALL", "LC_CTYPE", "LC_MESSAGES", "LANGUAGE")
# Catalogue ids that can stand on the screen. Every one needs a topic that explains it, so
# a new module text fails here until it has one.
SCREEN_IDS = re.compile(
    r"(label|updates|reboot|eol|firewall|autoupdates|logins|fail2ban|disk|units|sessions"
    r"|file_age|containers|load|memory|meter|render|status|section|value)\."
    r"|plugin\.prefix\Z|modules\.failed\Z|unit\.(not_found|masked|unknown|state|state_sub)\Z"
)


def _run(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    topic: Optional[str],
    lang: str = "C",
    cache_dir: Optional[Path] = None,
) -> "tuple[int, str, str]":
    for name in LOCALE_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("LANG", lang)
    monkeypatch.setenv("COLUMNS", "80")
    folder = str(cache_dir) if cache_dir else os.devnull
    code = cli.explain(topic, cache_dir=folder, owner=None)
    out, err = capsys.readouterr()
    return code, out.replace("\r\n", "\n"), err


def test_every_screen_text_has_a_topic() -> None:
    covered = {msg_id for topic in explain.TOPICS.values() for msg_id in topic.covers}
    wanted = {i for i in i18n.english().ids() if SCREEN_IDS.match(i)}
    assert sorted(wanted - covered) == []
    assert sorted(covered - i18n.english().ids()) == []  # nothing stale in the table


def test_every_hint_is_explained() -> None:
    listed = {hint for topic in explain.TOPICS.values() for hint in topic.hints}
    assert listed == set(hints.HINTS)


def test_every_explain_command_of_a_hint_names_a_topic() -> None:
    named = [
        command.split()[2]
        for entry in hints.HINTS.values()
        for command in entry.commands.values()
        if command.startswith("motp explain ")
    ]
    assert "eol" in named
    assert set(named) <= set(explain.TOPICS)


def test_every_topic_text_exists_in_both_languages() -> None:
    german = i18n.load("de")
    assert german is not None
    used = set()
    for name, topic in explain.TOPICS.items():
        texts = [topic.title, topic.what, topic.warn, topic.todo]
        assert all(t.startswith(f"explain.{name}.") for t in texts if t)
        used |= {t for t in texts if t}
    assert sorted(used - i18n.english().ids()) == []
    assert sorted(used - german.ids()) == []


@pytest.mark.parametrize(
    ("lang", "title", "heading"),
    [("C", "Load", "What to do"), ("de_DE.UTF-8", "Auslastung", "Was tun")],
)
def test_explain_load_follows_the_locale(
    lang: str,
    title: str,
    heading: str,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    code, out, err = _run(capsys, monkeypatch, "load", lang)
    assert (code, err) == (0, "")
    assert out.startswith(title + "\n") and f"\n{heading}\n" in out
    assert "thresholds.load_per_core" in out


@pytest.mark.parametrize("lang", ["C", "de_DE.UTF-8"])
def test_without_a_topic_every_topic_is_listed(
    lang: str, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    code, out, _err = _run(capsys, monkeypatch, None, lang)
    assert code == 0
    listed = [line.split()[0] for line in out.splitlines() if line.startswith("  ")]
    assert listed == list(explain.TOPICS)


@pytest.mark.parametrize("topic", ["nothing", "../etc", "\x1b[2J", "load‮"])
def test_an_unknown_topic_is_a_usage_error(
    topic: str, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    code, out, err = _run(capsys, monkeypatch, topic)
    assert (code, out) == (2, "")
    assert "motp explain lists the topics" in err
    assert "\x1b" not in err and "‮" not in err


@pytest.mark.parametrize("columns", ["1", "2", "10", "5000"])
@pytest.mark.parametrize("topic", [None, "updates"])
def test_any_terminal_width_works(
    columns: str,
    topic: Optional[str],
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("COLUMNS", columns)
    monkeypatch.setattr(show, "DEFAULT_DIR", os.devnull)
    assert cli.explain(topic, cache_dir=os.devnull, owner=None) == 0
    assert capsys.readouterr().out


def test_the_topic_name_ignores_case(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    assert _run(capsys, monkeypatch, "EOL")[0] == 0


def test_the_command_line_knows_explain(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in LOCALE_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    # not this machine's own /run/motp, whose render.json may force a language
    monkeypatch.setattr(show, "DEFAULT_DIR", os.devnull)
    assert cli.main(["explain", "eol"]) == 0
    assert capsys.readouterr().out.startswith("End of support")


@pytest.mark.parametrize("ascii_only", [False, True])
@pytest.mark.parametrize("language", ["en", "de"])
@pytest.mark.parametrize("width", [78, 40])
def test_pages_fit_their_width(width: int, language: str, ascii_only: bool) -> None:
    tr = i18n.translator(language)
    rules = {"load_per_core": make_rule("load_per_core", 0.7, 1.0)}
    for name, topic in explain.TOPICS.items():
        lines = explain.page(
            tr, name, rules=rules, package_manager="", width=width, ascii_only=ascii_only
        )
        assert lines
        commands = {c for h in topic.hints for c in hints.HINTS[h].commands.values()}
        for line in lines:
            # A command is never broken (half a command is another command), and a word
            # longer than the line, such as a path, stays whole.
            is_command = line.strip().split("  (")[0] in commands
            assert is_command or cell_width(line) <= width or " " not in line.strip(), line
            assert line.isprintable() or line == ""
            if ascii_only:
                assert line.isascii(), line


def _settings(folder: Path, language: str, manager: str) -> None:
    settings = RenderSettings(
        generated=1795600000,
        layout=Layout(),
        language=language,
        thresholds={"load_per_core": make_rule("load_per_core", 2.5, 4.5)},
        timer_period=300,
        render_ms=1000,
        package_manager=manager,
    )
    data = cache.encode_render_file(settings)
    json.loads(data)
    (folder / "render.json").write_bytes(data)
    os.chmod(folder / "render.json", 0o644)


def test_render_json_gives_language_commands_and_limits(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    _settings(tmp_path, "de", "dnf")
    # The ownership check of the reader is tested elsewhere and needs Linux.
    monkeypatch.setattr(
        cache,
        "read_render_file",
        lambda path, owner: cache.decode_render_file(Path(path).read_bytes()),
    )
    code, out, _err = _run(capsys, monkeypatch, "updates", "C", tmp_path)
    assert code == 0
    assert "Befehle" in out  # the forced language wins over the reader's locale
    assert "sudo dnf upgrade --security" in out and "apt upgrade" not in out
    assert "(dnf)" not in out  # one package manager: nothing to tell apart
    out = _run(capsys, monkeypatch, "load", "C", tmp_path)[1]
    assert "2.5" in out and "4.5" in out


def test_without_render_json_every_command_is_listed(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    out = _run(capsys, monkeypatch, "updates")[1]
    assert "sudo apt upgrade  (apt)" in out and "sudo dnf upgrade  (dnf)" in out


def test_the_eol_page_does_not_send_the_reader_back_to_itself(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    assert "motp explain" not in _run(capsys, monkeypatch, "eol")[1]


@pytest.mark.parametrize(
    ("language", "asked", "topic"),
    [
        ("en", "disk", "disks"),
        ("en", "Disks", "disks"),
        ("en", "Failed logins", "logins"),
        ("en", "failed-logins", "logins"),
        ("de", "Fehlanmeldungen", "logins"),
        ("de", "Failed logins", "logins"),
        ("en", "no such thing", None),
    ],
)
def test_topics_accept_singular_and_row_labels(
    language: str, asked: str, topic: Optional[str]
) -> None:
    """Final review, usability item 15: ``motp explain disk`` used to fail."""
    assert explain.find_topic(i18n.translator(language), asked) == topic

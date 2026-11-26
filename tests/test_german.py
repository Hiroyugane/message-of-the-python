"""German output (blueprint D19, phase 13) and invariant 8: the German catalogue has no
missing entry.

The catalogue checks compare ``de.po`` with ``en.po`` id by id. The width checks render
every state of every module in German at 80 columns, in both charsets, and refuse any cut
text. Golden files hold the German demo; ``MOTP_UPDATE_GOLDEN=1`` rewrites them.
"""

import re
import sys
import zipfile
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from motp import cli
from motp import render as renderer
from motp.core import hints, i18n
from motp.core.cache import Layout
from motp.core.model import (
    Detail,
    HintRef,
    Item,
    MessageRef,
    ModuleResult,
    Status,
    Unit,
    Visibility,
    ref,
)
from motp.core.sanitize import cell_width, sanitize
from motp.modules import (
    app_containers,
    hw_disks,
    os_autoupdates,
    os_eol,
    os_reboot,
    os_sessions,
    os_units,
    os_updates,
    records,
    registry,
    rows_unit,
    sec_fail2ban,
    sec_firewall,
    sec_logins,
)
from motp.modules.base import FsUsage, format_bytes
from motp.render import demo, view
from motp.render.theme import ASCII, UNICODE, ColorLevel, themed

from .conftest import SRC, TOOLS
from .test_render import check_golden, demo_text

sys.path.insert(0, str(TOOLS))
import build_pyz
import compile_catalogs

LOCALE = SRC / "motp" / "locale"
EN = i18n.Translator("en")
DE = i18n.Translator("de")
# Texts that are rightly the same in both languages: units, plain placeholders, and
# technical terms German keeps.
SAME_IN_BOTH = frozenset(
    {
        "cli.version.output", "config.check.problem", "unit.b", "unit.kib", "unit.mib",
        "unit.gib", "unit.tib", "unit.pib", "unit.percent", "unit.celsius", "unit.pair",
        "status.ok", "doctor.level.ok", "doctor.line", "doctor.version", "label.kernel",
        "label.swap", "label.updates", "label.firewall", "label.fail2ban", "label.jail",
        "label.mount", "label.unit_row", "label.file_row", "label.docker", "label.podman",
        "label.units", "value.labelled", "load.summary", "meter.percent", "unit.state",
        "unit.state_sub", "section.system", "section.plugins", "label.eol",
        "modules.interval.live", "modules.interval.seconds",
        "collect.log.progress", "explain.kernel.title", "explain.updates.title",
        "explain.swap.title", "explain.firewall.title", "explain.fail2ban.title",
        "explain.inodes.title", "explain.plugins.title",
    }
)  # fmt: skip


# --- invariant 8: the catalogues --------------------------------------------------------


def _entries(language: str) -> "dict[str, compile_catalogs.Entry]":
    text = (LOCALE / f"{language}.po").read_text(encoding="utf-8").replace("\r\n", "\n")
    return {e.msgid: e for e in compile_catalogs.parse_po(text) if e.msgid}


def _placeholders(template: str) -> "set[str]":
    found = set()
    i = 0
    while i < len(template):
        if template[i] in "{}" and template.startswith(template[i] * 2, i):
            i += 2
            continue
        if template[i] == "{":
            end = template.index("}", i)
            found.add(template[i + 1 : end])
            i = end
        i += 1
    return found


def test_german_has_exactly_the_english_entries() -> None:
    english, german = _entries("en"), _entries("de")
    assert sorted(set(english) - set(german)) == []  # missing
    assert sorted(set(german) - set(english)) == []  # unused
    assert not [i for i, e in german.items() if e.fuzzy or not all(e.forms.values())]
    # what the compiler keeps, which is what a reader sees
    assert i18n.load("de").ids() == i18n.english().ids()  # type: ignore[union-attr]


def test_plural_entries_and_placeholders_match() -> None:
    english, german = _entries("en"), _entries("de")
    problems = []
    for msg_id, entry in english.items():
        other = german[msg_id]
        if (entry.plural is None) != (other.plural is None):
            problems.append(f"{msg_id}: plural in one language only")
            continue
        if sorted(entry.forms) != sorted(other.forms):
            problems.append(f"{msg_id}: different number of forms")
            continue
        for index, form in entry.forms.items():
            if _placeholders(form) != _placeholders(other.forms[index]):
                problems.append(f"{msg_id}[{index}]: placeholders differ")
    assert not problems, "\n".join(problems)


def test_no_entry_was_left_in_english() -> None:
    english, german = _entries("en"), _entries("de")
    same = {i for i, e in english.items() if e.forms == german[i].forms}
    assert sorted(same - SAME_IN_BOTH) == []
    assert sorted(SAME_IN_BOTH - same) == []  # the list of exceptions stays honest


@pytest.mark.parametrize("language", ["en", "de"])
def test_no_entry_holds_a_control_character(language: str) -> None:
    for msg_id, forms in i18n.parse_mo(
        compile_catalogs.compile_file(LOCALE / f"{language}.po")
    ).items():
        for form in forms:
            assert all(ch.isprintable() for ch in form), msg_id


def test_compiled_catalogues_match_their_sources(tmp_path: Path) -> None:
    archive = tmp_path / "motp.pyz"
    build_pyz.build(SRC, archive)
    with zipfile.ZipFile(archive) as packed:
        for language in ("en", "de"):
            expected = compile_catalogs.compile_file(LOCALE / f"{language}.po")
            assert packed.read(f"motp/locale/{language}.mo") == expected
            assert (LOCALE / f"{language}.mo").read_bytes() == expected  # the unpacked tree


# --- plural forms -------------------------------------------------------------------------


def _plural_ids() -> "list[str]":
    return sorted(i for i, e in _entries("en").items() if e.plural is not None)


@pytest.mark.parametrize("msg_id", _plural_ids())
@pytest.mark.parametrize("language", ["en", "de"])
def test_zero_one_and_two_pick_the_right_form(language: str, msg_id: str) -> None:
    forms = _entries(language)[msg_id].forms
    tr = i18n.translator(language)
    names = _placeholders(forms[1]) | _placeholders(forms[0])
    for count, index in ((0, 1), (1, 0), (2, 1)):
        params = dict.fromkeys(names, "x") | {"count": count}
        expected = i18n.substitute(forms[index], {k: str(v) for k, v in params.items()})
        assert tr.message(msg_id, params) == expected


@pytest.mark.parametrize(
    ("msg_id", "texts"),
    [
        ("unit.days", ("0 Tage", "1 Tag", "2 Tage")),
        ("unit.days_ago", ("0 Tagen", "1 Tag", "2 Tagen")),
        ("unit.hours", ("0 Stunden", "1 Stunde", "2 Stunden")),
        ("unit.minutes", ("0 Minuten", "1 Minute", "2 Minuten")),
        ("unit.seconds", ("0 Sekunden", "1 Sekunde", "2 Sekunden")),
        ("updates.plain", ("0 Updates", "1 Update", "2 Updates")),
        ("sessions.count", ("0 Sitzungen", "1 Sitzung", "2 Sitzungen")),
        (
            "units.failed_count",
            ("0 Units fehlgeschlagen", "1 Unit fehlgeschlagen", "2 Units fehlgeschlagen"),
        ),
        (
            "fail2ban.banned",
            ("0 Adressen gesperrt", "1 Adresse gesperrt", "2 Adressen gesperrt"),
        ),
    ],
)
def test_german_plurals(msg_id: str, texts: "tuple[str, str, str]") -> None:
    assert tuple(DE.message(msg_id, {"count": n}) for n in (0, 1, 2)) == texts


@pytest.mark.parametrize("count", [0, 1, 2])
def test_container_counts_read_the_same_for_any_number(count: int) -> None:
    params = {"running": count, "stopped": count, "restarting": count, "unhealthy": count}
    assert DE.message("containers.summary", params) == f"{count} aktiv, {count} gestoppt"
    assert DE.message("containers.summary_problems", params) == (
        f"{count} aktiv ({count} ungesund), {count} im Neustart, {count} gestoppt"
    )


def test_the_narrowest_german_line_needs_no_case() -> None:
    # "seit" would ask for the dative ("seit 41 Tagen"), which this uptime is not in
    shown = DE.compose("render.host_uptime", {"host": "web01", "uptime": "41 Tage"})
    assert shown == "web01, Laufzeit 41 Tage"


def test_the_message_of_the_day_has_one_german_name() -> None:
    german = _entries("de")
    assert not [i for i, e in german.items() if any("Begrüßung" in f for f in e.forms.values())]


def test_days_take_the_dative_after_vor() -> None:
    now = 10**9
    ago = view.format_value(DE, now - 2 * 86400, Unit.TIMESTAMP, now)
    assert ago == "vor 2 Tagen"
    assert view.format_value(DE, 2 * 86400, Unit.SECONDS, now) == "2 Tage"
    assert view.format_value(EN, now - 2 * 86400, Unit.TIMESTAMP, now) == "2 days ago"


# --- ASCII terminals ----------------------------------------------------------------------


def test_german_letters_keep_their_ascii_spelling() -> None:
    text = "Zurückgehalten: Maßnahme für Ältere, Öfen, Übung, GROẞ"
    assert sanitize(text, 80, ascii_only=True) == (
        "Zurueckgehalten: Massnahme fuer Aeltere, Oefen, Uebung, GROSS"
    )
    once = sanitize(text, 20, ascii_only=True)
    assert sanitize(once, 20, ascii_only=True) == once and cell_width(once) <= 20


# --- golden files and the choice of language ----------------------------------------------


@pytest.mark.parametrize("charset", ["ascii", "unicode"])
@pytest.mark.parametrize("width", (80, 70, 50, 30))
def test_golden_german(width: int, charset: str) -> None:
    check_golden(
        f"demo-de-{width}-{charset}-plain.txt",
        demo_text(width, charset, "plain", language="de"),
    )


@pytest.mark.parametrize(
    ("env", "golden"),
    [
        ({"LANG": "de_DE.UTF-8"}, "demo-de-80-unicode-plain.txt"),
        ({"LANG": "en_US.UTF-8", "LC_MESSAGES": "de_CH.UTF-8"}, "demo-de-80-unicode-plain.txt"),
        ({"LANG": "C"}, "demo-80-unicode-plain.txt"),
        ({"LANG": "xx_YY.UTF-8"}, "demo-80-unicode-plain.txt"),
        ({"LANG": "de_DE.UTF-8", "LC_ALL": "C"}, "demo-80-unicode-plain.txt"),
    ],
)
def test_the_demo_follows_the_readers_locale(
    env: "dict[str, str]",
    golden: str,
    monkeypatch: pytest.MonkeyPatch,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    for name in ("LANG", "LC_ALL", "LC_CTYPE", "LC_MESSAGES", "LANGUAGE"):
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    argv = ["preview", "--demo", "--width", "80", "--charset", "unicode", "--color", "never"]
    assert cli.main(argv) == 0
    shown = capsysbinary.readouterr().out.decode("utf-8").replace("\r\n", "\n")
    assert shown == (Path(__file__).parent / "golden" / golden).read_text(encoding="utf-8")


# --- every state of every module at 80 columns --------------------------------------------

NOW = demo.NOW
DATE, TABLE_DATE = "2028-06-30", "2026-11-25"


def _autoupdates(state: str, hint: str) -> Item:
    return Item(
        key="os_autoupdates.enabled",
        value=state == os_autoupdates.ON,
        unit=Unit.BOOL,
        label=ref("label.autoupdates"),
        status=Status.OK if state == os_autoupdates.ON else Status.WARN,
        text=os_autoupdates.TEXTS[state],
        hint=HintRef(hint),
    )


# Each state with the hints its module gives it.
AUTOUPDATE_CASES = {
    os_autoupdates.ON: ("autoupdates.enable",),
    os_autoupdates.OFF: (
        "autoupdates.enable", "autoupdates.enable_dnf5", "autoupdates.timer",
        "autoupdates.unmask", "autoupdates.unmask_dnf5",
    ),
    os_autoupdates.NOT_INSTALLED: ("autoupdates.install",),
    os_autoupdates.DOWNLOAD_ONLY: ("autoupdates.enable", "autoupdates.unmask"),
    os_autoupdates.APPLY_OFF: ("autoupdates.apply_dnf5",),
    os_autoupdates.PERIODIC_OFF: ("autoupdates.periodic",),
}  # fmt: skip


def _containers(state: str, status: str = "") -> "Mapping[str, Any]":
    return {"Names": ["/web"], "Image": "nginx", "State": state, "Status": status}


def _module_items(manager: str) -> "list[tuple[str, str, Item]]":
    """``(module, section, item)`` for every text a module can put on the screen."""
    updates = [os_updates.Update(f"p{n}", n < 99) for n in range(999)]
    plain = [replace(u, security=False) for u in updates]
    found: list[tuple[str, str, Item]] = []

    def add(module: str, section: str, *items: Item) -> None:
        found.extend((module, section, item) for item in items)

    old_lists = os_updates.updates_item(updates, True, 99)
    old_lists = replace(
        old_lists,
        detail=(
            *old_lists.detail,
            Detail(
                "os_updates.lists",
                NOW - 400 * 86400,
                unit=Unit.TIMESTAMP,
                label=ref("label.package_lists"),
            ),
        ),
    )
    add(
        "os_updates",
        "system",
        old_lists,
        os_updates.updates_item(plain, True),
        os_updates.updates_item(plain, False),
        os_updates.updates_item(updates[:1], True),
        os_updates.updates_item([], True, 99),
        os_updates.updates_item([]),
        os_updates.unknown_item(),
    )
    add(
        "os_reboot",
        "system",
        os_reboot.reboot_item(True, ["kernel"]),
        os_reboot.reboot_item(False, []),
    )
    for status in (Status.OK, Status.WARN, Status.CRIT):
        for data in (None, TABLE_DATE):
            add(
                "os_eol",
                "system",
                Item(
                    "os_eol.date",
                    DATE,
                    label=ref("label.eol"),
                    status=status,
                    text=os_eol.summary(status, DATE, data),
                    hint=HintRef("os.eol"),
                ),
            )
    for state, hint_ids in AUTOUPDATE_CASES.items():
        for hint_id in hint_ids:
            if manager in hints.HINTS[hint_id].commands:
                add("os_autoupdates", "security", _autoupdates(state, hint_id))
    item = sec_firewall._item
    for name in ("ufw", "firewalld", "nftables"):
        hint_id = f"firewall.{name}"
        add(
            "sec_firewall",
            "security",
            item(False, Status.CRIT, ref("firewall.failed", name=name), hint_id),
            item(False, Status.WARN, ref("firewall.inactive"), hint_id),
            item(True, Status.OK, ref("firewall.active", name=name), None),
            item(True, Status.OK, ref("firewall.active_zone", name=name, zone="public"), None),
        )
    failures = [records.Failure(n, "192.0.2.10", NOW) for n in range(5)]
    add(
        "sec_logins",
        "security",
        sec_logins.failed_item(failures, False),
        replace(
            sec_logins.failed_item(failures, True), text=ref("logins.failed_more", count=10**6)
        ),
        sec_logins.unrecorded_item(),
    )
    add(
        "sec_fail2ban",
        "security",
        sec_fail2ban.banned_item([("sshd", 99999, ["192.0.2.10"])]),
        sec_fail2ban.not_running_item(),
        sec_fail2ban.not_checked_item(),
    )
    add(
        "os_units",
        "services",
        os_units.failed_item([f"u{n}.service" for n in range(99)]),
        os_units.failed_item([]),
    )
    sessions = [records.Record("admin", "pts/0", "192.0.2.10", NOW)] * 99
    add("os_sessions", "login", os_sessions.sessions_item(sessions), os_sessions.unrecorded_item())
    for load, active, sub in (
        ("not-found", "", ""),
        ("masked", "", ""),
        ("loaded", "?", ""),
        ("loaded", "deactivating", "stop-sigterm"),
        ("loaded", "failed", ""),
    ):
        values = {"LoadState": load, "ActiveState": active, "SubState": sub}
        add("rows_unit", "services", rows_unit.row_item("rows_unit.web", "Webserver", values))
    for status, text in (
        (Status.CRIT, "file_age.missing"),
        (Status.UNKNOWN, "file_age.unreadable"),
    ):
        add(
            "rows_file_age",
            "services",
            Item(
                "rows_file_age.backup",
                None,
                Unit.SECONDS,
                ref("label.file_row", label="Sicherung"),
                status=status,
                text=ref(text),
            ),
        )
    many = [_containers("running", "(unhealthy)")] * 99 + [_containers("restarting")] * 99
    many += [_containers("exited")] * 99
    for key, label in (("docker", "label.docker"), ("podman", "label.podman")):
        runtime = app_containers.runtime_item(key, label, many)
        add(
            "app_containers",
            "containers",
            runtime,
            app_containers.runtime_item(key, label, [_containers("running")] * 999),
            app_containers.stopped_item(key, label),
            app_containers.unreachable_item(key, label),
        )
    tib = 1023 * 1024**4
    usage = FsUsage(tib, tib // 50, tib // 50, 10**9, 10**7, 10**7, 1)
    root = hw_disks.Mount("8:1", "/", "ext4")
    inodes = hw_disks.HwDisks._inodes(root, "root", usage, Visibility.PUBLIC)
    assert inodes is not None
    add(
        "hw_disks",
        "disks",
        hw_disks.HwDisks._space(root, "root", usage, Visibility.PUBLIC),
        inodes,
    )
    long_ago = NOW - 400 * 86400 - 23 * 3600
    add(
        "os_login",
        "login",
        Item("os_login.previous", long_ago, Unit.TIMESTAMP, ref("label.previous_login")),
        Item("os_login.source", "198.51.100.7", label=ref("label.login_from")),
        Item("os_login.tty", "pts/12", label=ref("label.login_tty")),
    )
    live = {"hw_memory": ref("memory.summary", used=format_bytes(tib), total=format_bytes(tib))}
    add(
        "hw_memory",
        "system",
        Item("hw_memory.used", 99, Unit.PERCENT, ref("label.memory"), text=live["hw_memory"]),
        Item("hw_memory.swap", 99, Unit.PERCENT, ref("label.swap"), text=live["hw_memory"]),
    )
    add(
        "hw_load",
        "system",
        Item(
            "hw_load.per_core",
            9.0,
            Unit.RATIO,
            ref("label.load"),
            rule="load_per_core",
            text=ref("load.summary", one="999.99", five="999.99", fifteen="999.99"),
        ),
    )
    add("os_uptime", "system", Item("os_uptime.uptime", 10**8, Unit.SECONDS, ref("label.uptime")))
    add(
        "os_host",
        "host",
        Item("os_host.hostname", "web01.example.com", label=ref("label.hostname")),
        Item("os_host.os", "Debian GNU/Linux 13", label=ref("label.os")),
        Item("os_host.kernel", "6.12.48-1-amd64", label=ref("label.kernel")),
    )
    add(
        "net_addresses",
        "host",
        Item("net_addresses.local", "192.0.2.10", label=ref("label.address")),
        Item("net_addresses.dns", "192.0.2.53", label=ref("label.dns")),
    )
    return found


def _short_details(item: Item) -> Item:
    """Name lists are data and may be cut; the width check is about MOTP's own words."""
    return replace(
        item,
        detail=tuple(replace(d, value="web") if type(d.value) is str else d for d in item.detail),
    )


def _render_each(
    manager: str, language: str, charset: str, width: int, age: int = 60
) -> "list[str]":
    """Every item on a screen of its own, plus the collector's own alerts."""
    theme = themed(UNICODE if charset == "unicode" else ASCII, ColorLevel.OFF)
    lines: list[str] = []
    for module, section, item in _module_items(manager):
        result = ModuleResult(
            collected=NOW - age, interval=300, max_age=86400, items=(_short_details(item),)
        )
        inp = view.RenderInput(
            sources=(view.Source(module, section, result),),
            now=NOW,
            hostname="web01.example.com",
            layout=Layout(header="off"),
            language=language,
            rules=registry.LIVE_RULES | demo.RULES,
            package_manager=manager,
            admin=True,
        )
        lines += renderer.render(inp, width, theme).splitlines()
    inp = view.RenderInput(
        sources=(),
        now=NOW,
        hostname="web01.example.com",
        layout=Layout(header="off"),
        language=language,
        package_manager=manager,
        failed=99,
        cache_age=400 * 86400 + 23 * 3600,
        no_cache=True,
    )
    return lines + renderer.render(inp, width, theme).splitlines()


def test_the_module_fixtures_cover_every_screen_text() -> None:
    used = set()
    for manager in hints.PACKAGE_MANAGERS:
        for _module, _section, item in _module_items(manager):
            texts = [item.text, item.label, *(d.label for d in item.detail)]
            used |= {t.id for t in texts if isinstance(t, MessageRef)}
    prefixes = (
        "label.", "updates.", "reboot.", "eol.", "firewall.", "autoupdates.", "logins.",
        "fail2ban.", "sessions.", "units.", "file_age.", "containers.", "load.", "memory.",
        "unit.not_found", "unit.masked", "unit.unknown", "unit.state",
    )  # fmt: skip
    wanted = {i for i in i18n.english().ids() if i.startswith(prefixes)}
    wanted.discard("label.containers")  # only the demo uses it
    assert sorted(wanted - used) == []


# The ASCII ellipsis; a dotted leader is a long run of dots, so exactly three is a cut.
_ASCII_CUT = re.compile(r"(?<![. ])" + re.escape("...") + r"(?![.:])")


@pytest.mark.parametrize("charset", ["ascii", "unicode"])
@pytest.mark.parametrize("manager", hints.PACKAGE_MANAGERS)
def test_no_german_text_is_cut_at_80_columns(manager: str, charset: str) -> None:
    lines = _render_each(manager, "de", charset, 80)
    assert len(lines) > 200
    cut = [line for line in lines if "…" in line or _ASCII_CUT.search(line)]
    assert not cut, "\n".join(cut)
    assert max(cell_width(line) for line in lines) <= 80


@pytest.mark.parametrize("charset", ["ascii", "unicode"])
def test_nothing_is_cut_in_the_german_demo(charset: str) -> None:
    text = demo_text(80, charset, "plain", language="de")
    assert "…" not in text and not _ASCII_CUT.search(text)


@pytest.mark.parametrize("width", (70, 50, 30))
def test_german_never_exceeds_a_narrow_terminal(width: int) -> None:
    for charset in ("ascii", "unicode"):
        lines = _render_each("apt", "de", charset, width)
        assert max(cell_width(line) for line in lines) <= width

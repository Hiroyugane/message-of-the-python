"""The view model: from module results to sections of finished rows (blueprint 4.6).

Input is the data model only (``RenderInput``); nothing here touches the system. The view
translates labels and texts, formats values by unit, classifies them, marks stale and
expired items, and builds the attention block from warnings and critical items with their
hints from the fixed table (D34). Width, charset and colour are left to ``layout``.

Every string from outside the package (literal labels and texts, string values, the host
name) is sanitised again here, although the cache reader already did: the view must be
safe for any ``Item``, including demo data and tests.

Items of built-in modules carry names the system reports and others may choose (host,
tty, user, unit, interface, jail, container and image names, login records): their string
values and the parameters of their messages lose right-to-left letters and Arabic digits
(``sanitize.without_rtl``), and so does the host name, so a terminal with bidi support
cannot reorder an admin's row around them (final review, security item 3). Plugin items
and the literal labels of config rows are text an admin wrote and keep them.
"""

import math
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from typing import Optional

from motp.core import hints, tips
from motp.core.cache import SECTIONS, Layout
from motp.core.i18n import Translator, translator
from motp.core.look import DEFAULT_LOOK, Look
from motp.core.model import (
    STATUS_MESSAGE,
    Detail,
    HintRef,
    Item,
    LiteralText,
    MessageRef,
    ModuleResult,
    ModuleState,
    Status,
    Unit,
    Value,
    Visibility,
    freshness,
)
from motp.core.sanitize import (
    HINT_CELLS,
    LABEL_CELLS,
    TEXT_CELLS,
    VALUE_CELLS,
    sanitize,
    without_rtl,
)
from motp.core.thresholds import Rule, item_status

ATTENTION = "attention"
PLUGINS = "plugins"
HOST_CELLS = 64
PLUGIN_NAME_CELLS = 32
# The item the narrowest layout shows next to the host name when nothing needs attention.
UPTIME_KEY = "os_uptime.uptime"

SECTION_TITLE = {
    "attention": "section.attention",
    "host": "section.host",
    "system": "section.system",
    "security": "section.security",
    "login": "section.login",
    "disks": "section.disks",
    "services": "section.services",
    "containers": "section.containers",
    "plugins": "section.plugins",
}
# Meter texts (D36): the message a module sends, and the form of it for each choice of
# ``[theme.bar] text``. A form needs every parameter its message uses; older data without
# the free amount keeps the module's own text.
METER_FORMS = {
    "disk.usage": {
        "full": "disk.usage_full",
        "short": "disk.usage_short",
        "used": "disk.usage",
        "free": "disk.usage_free",
        "percent": "meter.percent",
    },
    "disk.inode_usage": {
        "full": "disk.inode_full",
        "short": "disk.inode_short",
        "used": "disk.inode_usage",
        "free": "disk.inode_free",
        "percent": "meter.percent",
    },
}
METER_PARAMS = {
    "disk.usage": {"percent", "size", "free"},
    "disk.inode_usage": {"percent", "total", "free"},
}
# Shorter forms tried in turn when the room is too small, before the bar goes (D36).
FORM_CHAIN = {
    "full": ("full", "short", "percent"),
    "short": ("short", "percent"),
    "used": ("used", "percent"),
    "free": ("free", "percent"),
    "percent": ("percent",),
}
_BYTE_UNITS = ("unit.b", "unit.kib", "unit.mib", "unit.gib", "unit.tib", "unit.pib")
_DURATION_UNITS = (
    (86400, "unit.days"),
    (3600, "unit.hours"),
    (60, "unit.minutes"),
    (1, "unit.seconds"),
)


@dataclass(frozen=True)
class Source:
    """One module's result and the section it renders in (from the module registry)."""

    module: str
    section: str
    result: ModuleResult


@dataclass(frozen=True)
class RenderInput:
    sources: tuple[Source, ...]
    now: int
    hostname: str
    layout: Layout = field(default_factory=Layout)
    language: str = "en"
    rules: Mapping[str, Rule] = field(default_factory=dict)
    package_manager: str = ""
    failed: int = 0  # modules that failed in the collector's last run
    config_ignored: int = 0  # config files the collector ignored (admin tier only)
    cache_age: Optional[int] = None  # set when the whole cache is older than three periods
    admin: bool = False  # the reader may see admin items
    no_cache: bool = False  # no cache file could be read: only live values are shown
    look: Look = DEFAULT_LOOK  # section titles, hidden and ordered rows, meter text (D35)


@dataclass(frozen=True)
class Row:
    """One finished row. Texts are sanitised or come from the catalogue."""

    label: str
    value: str
    status: Optional[Status] = None
    bar: Optional[float] = None
    note: str = ""  # age of a stale value
    muted: bool = False  # unknown or expired value
    prefix: str = ""  # "[plugin <name>]" for plugin rows
    detail: bool = False  # an extra row under an item
    forms: tuple[str, ...] = ()  # shorter texts for the value, longest first (meters)
    key: str = ""  # the item's key, for hidden and reordered rows
    # Starts every wrapped line of a plugin row after the first, so no piece of plugin
    # text stands at the start of a line where it could pass for a system row (T7).
    more: str = ""


@dataclass(frozen=True)
class Alert:
    """One row of the attention block."""

    text: str
    status: Status
    command: Optional[str] = None  # from the hint table only
    hint: str = ""  # hint text: a plugin's sentence, or the table's text without a command
    prefix: str = ""
    # Starts every wrapped line of a plugin's hint after the first, so no piece of it can
    # stand alone like a command (security review of phase 14b, T7); "" for built-ins.
    hint_more: str = ""
    # The same for the wrapped lines of a plugin alert's own text (phase 14c).
    more: str = ""


@dataclass(frozen=True)
class Section:
    name: str
    title: str
    rows: tuple[Row, ...] = ()
    alerts: tuple[Alert, ...] = ()


@dataclass(frozen=True)
class View:
    header: str  # text for the header font, "" for none
    host_line: str  # host and uptime, for the narrowest layout when all is well
    sections: tuple[Section, ...]
    tip_title: str = ""
    tip: str = ""  # a tip of the day about MOTP, when the layout asks for tips (D19)


# --- value formatting ----------------------------------------------------------------


def _number(value: float, digits: int) -> str:
    text = f"{value:.{digits}f}"
    return text.rstrip("0").rstrip(".") if "." in text else text


def format_bytes(tr: Translator, value: float) -> str:
    size = float(value)
    index = 0
    while abs(size) >= 1024 and index < len(_BYTE_UNITS) - 1:
        size /= 1024
        index += 1
    digits = 0 if index == 0 or abs(size) >= 100 else 1
    return tr.message(_BYTE_UNITS[index], {"n": _number(size, digits)})


def format_duration(tr: Translator, seconds: float, *, ago: bool = False) -> str:
    """The two largest non-zero units: ``41 days 3 hours``, ``5 minutes``.

    ``ago`` picks the form that stands inside ``value.ago``: German needs the dative
    there ("41 Tage", but "vor 41 Tagen").
    """
    left = max(0, int(seconds))
    parts: list[str] = []
    for size, msg_id in _DURATION_UNITS:
        amount = left // size
        if amount or (size == 1 and not parts):
            if ago and msg_id == "unit.days":
                msg_id = "unit.days_ago"
            parts.append(tr.message(msg_id, {"count": amount}))
            left -= amount * size
        if len(parts) == 2:
            break
    if len(parts) == 1:
        return parts[0]
    return tr.compose("unit.pair", {"first": parts[0], "second": parts[1]})


def format_value(tr: Translator, value: Value, unit: Unit, now: int) -> str:
    """A raw value as text for its unit; ``unknown`` for ``None`` or nonsense."""
    if value is None:
        return tr.message(STATUS_MESSAGE[Status.UNKNOWN])
    if unit is Unit.BOOL or type(value) is bool:
        return tr.message("value.yes" if value else "value.no")
    if type(value) is str:
        return sanitize(value, VALUE_CELLS)
    number = float(value)
    if not math.isfinite(number):
        return tr.message(STATUS_MESSAGE[Status.UNKNOWN])
    if unit is Unit.BYTES:
        return format_bytes(tr, number)
    if unit is Unit.PERCENT:
        return tr.message("unit.percent", {"n": _number(number, 0 if number >= 10 else 1)})
    if unit is Unit.SECONDS:
        return format_duration(tr, number)
    if unit is Unit.TIMESTAMP:
        duration = format_duration(tr, now - number, ago=True)
        return tr.compose("value.ago", {"duration": duration})
    if unit is Unit.CELSIUS:
        return tr.message("unit.celsius", {"n": _number(number, 0)})
    if unit is Unit.RATIO:
        return _number(number, 2)
    return _number(number, 2)


# --- rows ------------------------------------------------------------------------------


def _label(tr: Translator, item: "Item | Detail") -> str:
    if item.label is None:
        return ""
    if isinstance(item.label, LiteralText):
        return sanitize(item.label.for_language(tr.language), LABEL_CELLS)
    return tr.text(item.label)


# Texts written to stand alone in the attention block ("Firewall is not active") repeat
# their row's label beside it ("Firewall: Firewall is not active"). A row shows the short
# form instead; the alert keeps the full sentence (final review, usability item 15).
ROW_TEXT = {
    "reboot.required": "row.reboot.required",
    "eol.supported": "row.eol.supported",
    "eol.supported_table": "row.eol.supported_table",
    "eol.ending": "row.eol.ending",
    "eol.ending_table": "row.eol.ending_table",
    "eol.ended": "row.eol.ended",
    "eol.ended_table": "row.eol.ended_table",
    "autoupdates.off": "row.autoupdates.off",
    "autoupdates.not_installed": "row.autoupdates.not_installed",
    "autoupdates.download_only": "row.autoupdates.download_only",
    "firewall.inactive": "row.firewall.inactive",
    "firewall.failed": "row.firewall.failed",
    "fail2ban.not_running": "row.fail2ban.not_running",
}


def _text(tr: Translator, item: Item, row: bool = True) -> Optional[str]:
    """The item's text for its row (``row``), or the full form for the attention block."""
    if item.text is None:
        return None
    if isinstance(item.text, LiteralText):
        return sanitize(item.text.for_language(tr.language), TEXT_CELLS)
    short = ROW_TEXT.get(item.text.id) if row else None
    if short is not None:
        return tr.text(MessageRef(short, item.text.params))
    return tr.text(item.text)


def _prefix(tr: Translator, item: Item) -> str:
    if item.origin is None:
        return ""
    name = sanitize(item.origin, PLUGIN_NAME_CELLS)
    return tr.compose("plugin.prefix", {"name": name})


def _more(tr: Translator, item: Item) -> str:
    """The catalogue's marker for the wrapped lines of a plugin row, "" for built-ins."""
    return tr.message("plugin.more") if item.origin is not None else ""


def meter_texts(tr: Translator, text: MessageRef, choice: str) -> Optional[tuple[str, ...]]:
    """The texts of a meter for ``[theme.bar] text = choice``, longest first (D36)."""
    forms = METER_FORMS.get(text.id)
    params = text.param_dict()
    if forms is None or not METER_PARAMS[text.id] <= params.keys():
        return None
    return tuple(tr.message(forms[form], params) for form in FORM_CHAIN[choice])


def _visible(visibility: Visibility, admin: bool) -> bool:
    return admin or visibility is Visibility.PUBLIC


@dataclass
class _Built:
    rows: list[Row]
    alerts: list[tuple[int, int, Alert]]  # (severity, order) for sorting


def _alert(tr: Translator, item: Item, status: Status, row: Row, package_manager: str) -> Alert:
    if isinstance(item.text, MessageRef) and item.text.id in ROW_TEXT and not row.muted:
        text = _text(tr, item, row=False) or row.value  # the full sentence (ROW_TEXT)
    elif (item.text is not None and item.bar is None) or not row.label:
        text = row.value  # a text such as "12 updates, 3 security" stands on its own
    else:
        text = tr.compose("value.labelled", {"label": row.label, "value": row.value})
    command: Optional[str] = None
    hint = ""
    if isinstance(item.hint, HintRef) and item.origin is None:  # never for plugins (D34)
        found = hints.lookup(item.hint.id, package_manager)
        if found is not None:
            message, command = found
            hint = tr.message(message)
    elif isinstance(item.hint, LiteralText):
        written = sanitize(item.hint.for_language(tr.language), HINT_CELLS)
        # D34: a plugin's hint says it is one, so it never reads as a command.
        hint = tr.compose("plugin.hint", {"hint": written}) if item.origin else written
    hint_more = tr.message("plugin.hint_more") if item.origin and hint else ""
    return Alert(
        text=text,
        status=status,
        command=command,
        hint=hint,
        prefix=row.prefix,
        hint_more=hint_more,
        more=row.more,
    )


# Message parameters that hold text an admin wrote in the config, not a collected name:
# the label of a [[rows.unit]] or [[rows.file_age]] row keeps right-to-left letters.
ADMIN_TEXT_PARAMS = {("label.unit_row", "label"), ("label.file_row", "label")}


def _ltr_ref(ref: object) -> object:
    if not isinstance(ref, MessageRef) or not ref.params:
        return ref
    return MessageRef(
        ref.id,
        tuple(
            (k, without_rtl(v) if type(v) is str and (ref.id, k) not in ADMIN_TEXT_PARAMS else v)
            for k, v in ref.params
        ),
    )


def _ltr_value(value: Value) -> Value:
    return without_rtl(value) if type(value) is str else value


def ltr_item(item: Item) -> Item:
    """A built-in item without right-to-left letters in its collected names (module doc)."""
    if item.origin is not None:
        return item
    detail = tuple(
        replace(d, value=_ltr_value(d.value), label=_ltr_ref(d.label))  # type: ignore[arg-type]
        for d in item.detail
    )
    return replace(
        item,
        value=_ltr_value(item.value),
        label=_ltr_ref(item.label),  # type: ignore[arg-type]
        text=_ltr_ref(item.text),  # type: ignore[arg-type]
        detail=detail,
    )


def _module_rows(inp: RenderInput, tr: Translator, source: Source, built: _Built) -> None:
    result = source.result
    fresh = freshness(result, inp.now)
    for item in result.items:
        if not _visible(item.visibility, inp.admin):
            continue
        item = ltr_item(item)
        status = item_status(item, inp.rules)
        text = _text(tr, item)
        value = text if text is not None else format_value(tr, item.value, item.unit, inp.now)
        forms: tuple[str, ...] = ()
        if item.bar is not None and isinstance(item.text, MessageRef):
            texts = meter_texts(tr, item.text, inp.look.bar.text)
            if texts is not None:
                value, forms = texts[0], texts[1:]
        muted = item.value is None and text is None
        note = ""
        bar = item.bar
        if fresh.expired:
            status, value, muted, bar = Status.UNKNOWN, tr.message("status.unknown"), True, None
            forms = ()
        elif fresh.stale:
            note = tr.compose("value.age", {"age": format_duration(tr, fresh.age)})
        if muted and inp.admin and result.state is ModuleState.FAILED:
            # The admin tier knows the module failed: its unknown rows say so, so the count
            # in the attention block points at a row (final review, usability item 15).
            value = tr.message("status.module_failed")
        if status is Status.UNKNOWN:
            muted = True
        row = Row(
            label=_label(tr, item),
            value=value,
            status=status,
            bar=bar,
            note=note,
            muted=muted,
            prefix=_prefix(tr, item),
            forms=forms,
            key=item.key,
            more=_more(tr, item),
        )
        if status in (Status.WARN, Status.CRIT):
            # A hidden row still raises its alert: the layout can tidy a section, not
            # silence a full disk (D35).
            alert = _alert(tr, item, status, row, inp.package_manager)
            built.alerts.append((-status.severity, len(built.alerts), alert))
        if item.key in inp.look.hidden_rows:
            continue
        built.rows.append(row)
        if fresh.expired:
            continue  # expired details are not shown: their item is unknown now (4.4)
        for detail in item.detail:
            if not _visible(detail.visibility, inp.admin):
                continue
            built.rows.append(
                Row(
                    label=_label(tr, detail),
                    value=format_value(tr, detail.value, detail.unit, inp.now),
                    note=note,
                    detail=True,
                    prefix=row.prefix,
                    key=item.key,
                    more=row.more,
                )
            )


def _ordered(rows: list[Row], order: tuple[str, ...]) -> tuple[Row, ...]:
    """Rows with the items named in ``order`` first, in that order; details stay below
    their item, and every other item keeps its place after them."""
    if not order:
        return tuple(rows)
    blocks: list[list[Row]] = []
    for row in rows:
        if row.detail and blocks:
            blocks[-1].append(row)
        else:
            blocks.append([row])
    rank = {key: n for n, key in enumerate(order)}
    blocks.sort(key=lambda block: rank.get(block[0].key, len(rank)))  # stable for the rest
    return tuple(row for block in blocks for row in block)


def _header(inp: RenderInput, short_host: str) -> str:
    mode = inp.layout.header
    if mode == "off":
        return ""
    text = sanitize(inp.layout.header_text, LABEL_CELLS) if mode == "text" else short_host
    return text.upper() if inp.look.header_case == "upper" else text


def _uptime(tr: Translator, inp: RenderInput) -> str:
    for source in inp.sources:
        for item in source.result.items:
            if item.key == UPTIME_KEY and item.value is not None:
                return format_value(tr, item.value, item.unit, inp.now)
    return tr.message(STATUS_MESSAGE[Status.UNKNOWN])


def build(inp: RenderInput) -> View:
    """Build the view for one reader. Plugin items always land in the plugins section."""
    tr = translator(inp.language)
    host = without_rtl(sanitize(inp.hostname, HOST_CELLS))
    short_host = host.split(".", 1)[0] if not host.startswith(".") else host
    per_section: dict[str, _Built] = {name: _Built([], []) for name in SECTIONS}
    for source in inp.sources:
        section = PLUGINS if any(i.origin for i in source.result.items) else source.section
        if section not in per_section or section == ATTENTION:
            continue
        _module_rows(inp, tr, source, per_section[section])

    order = {name: i for i, name in enumerate(inp.layout.sections)}
    alerts: list[tuple[int, int, int, Alert]] = []
    for name, built in per_section.items():
        if name in order:
            alerts += [(sev, order[name], n, a) for sev, n, a in built.alerts]
    alerts.sort(key=lambda entry: entry[:3])
    attention = [entry[3] for entry in alerts]
    if inp.no_cache:
        attention.append(Alert(text=tr.message("render.no_cache"), status=Status.WARN))
    if inp.cache_age is not None:
        found = hints.lookup("cache.stale", inp.package_manager)
        age = format_duration(tr, inp.cache_age)
        attention.append(
            Alert(
                text=tr.compose("render.cache_old", {"age": age}),
                status=Status.WARN,
                command=found[1] if found else None,
            )
        )
    if inp.failed > 0:
        attention.append(
            Alert(text=tr.message("modules.failed", {"count": inp.failed}), status=Status.WARN)
        )
    if inp.admin and inp.config_ignored > 0:
        # Final review, usability item 6: an ignored file is otherwise invisible. Admins
        # only: which config an admin keeps and that it is broken is not public.
        found = hints.lookup("config.check", inp.package_manager)
        attention.append(
            Alert(
                text=tr.message("config.ignored", {"count": inp.config_ignored}),
                status=Status.WARN,
                command=found[1] if found else None,
            )
        )

    sections = []
    for name in inp.layout.sections:
        custom = inp.look.section_titles.get(name, "")
        title = sanitize(custom, LABEL_CELLS) if custom else tr.message(SECTION_TITLE[name])
        if name == ATTENTION:
            if attention:
                sections.append(Section(name, title, alerts=tuple(attention)))
            continue
        rows = _ordered(per_section[name].rows, inp.look.row_order.get(name, ()))
        if rows:
            sections.append(Section(name, title, rows=rows))
    return View(
        header=_header(inp, short_host),
        host_line=tr.compose(
            "render.host_uptime", {"host": short_host, "uptime": _uptime(tr, inp)}
        ),
        sections=tuple(sections),
        tip_title=tr.message("section.tip") if inp.layout.tips else "",
        tip=tr.message(tips.of_day(inp.now)) if inp.layout.tips else "",
    )

"""Configuration: load, merge, validate (blueprint 4.7, D9, D33, T1, T17).

Files: ``<root>/config.toml``, then ``<root>/conf.d/*.toml`` in name order, on top of the
defaults in ``motp/data/default-config.toml``. ``root`` is ``/etc/motp`` in production and
a parameter for tests.

Rules:

* A file is read only after the ownership check of ``core/safepath.py`` (it and every
  directory above it belong to root and are not writable by group or others). A file
  that fails it is ignored with a recorded reason, and what it would have set keeps the
  value from the defaults or an earlier file.
* TOML is parsed by ``tomllib`` on Python 3.11 and newer and by the bundled tomli 2.3.2
  below (both TOML 1.0, except ``tomllib`` on 3.15, which reads TOML 1.1).
* Validation collects every problem of a file: unknown keys, wrong types and values out
  of range each name the file, the key and what is expected. A file with any problem is
  ignored as a whole, so a half-valid file never mixes into the result.
* Later files override earlier ones key by key inside each table; ``[[rows.*]]`` entries
  of all files are added up. A file is applied only if the merged result is still valid
  (for example, threshold limits in the right order).

Config is data only: no value is ever passed to a shell or evaluated (D9).
"""

import functools
import math
import os
import pkgutil
import posixpath
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from typing import Any, Callable, Optional, Union

from motp.core import figfont, look, safepath
from motp.core.cache import CHARSETS, COLOR_MODES, HEADER_MODES, SECTIONS, Layout
from motp.core.look import Look
from motp.core.model import ContractError, MessageRef, contract_error
from motp.core.probe import BUILTIN_KEY, STORED_PLUGIN_KEY
from motp.core.sanitize import LABEL_CELLS, PARAM_CELLS, sanitize
from motp.core.thresholds import Direction, Rule, make_rule

if sys.version_info >= (3, 11):
    import tomllib as _toml
else:
    from motp._vendor import tomli as _toml

TOML_PARSER = _toml.__name__  # "tomllib" or "motp._vendor.tomli"; for tests and doctor

DEFAULT_ROOT = "/etc/motp"
MAIN_FILE = "config.toml"
DROPIN_DIR = "conf.d"
FONT_DIR = "fonts"
FONT_SUFFIX = ".flf"
MAX_FONT_FILE_BYTES = 128 * 1024
MAX_FONT_CELLS = 16384  # drawn cells of one admin font's printable glyphs (render.json)
MAX_ITEM_KEYS = 64
MAX_FILE_BYTES = 64 * 1024
MAX_DROPINS = 64
MAX_ROWS = 32
MAX_TABLE_ENTRIES = 64  # modules, plugins, thresholds
MAX_DURATION = 3650 * 86400

MODES = ("hybrid", "static")
RENDER_MS_MIN = 100
RENDER_MS_MAX = 10000  # the login hook's outer limit lies above this (install/hooks.py)
RUN_AS = ("motp-plugin", "root")
PLUGIN_VISIBILITY = ("admin", "public")
LANGUAGE = re.compile(r"auto\Z|[a-z]{2,3}\Z")
GROUP_NAME = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")
MODULE_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
RULE_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
# 4.9: NN-name, as long as discovery allows (``core.probe.PLUGIN_NAME``; a test keeps
# the two equal), so a table can never name a plugin that cannot exist.
PLUGIN_NAME = re.compile(r"[0-9]{2}-[a-z0-9_-]{1,45}\Z")
# A unit a ``[[rows.unit]]`` row may watch. The first character cannot be ``-`` or ``.``:
# the name goes to ``systemctl``, where ``-H...`` would be an option (phase 10). The same
# pattern is ``modules.services.ROW_UNIT_NAME``; a test keeps the two equal.
UNIT_NAME = re.compile(
    r"[A-Za-z0-9:_@\\][A-Za-z0-9:_.@\\-]{0,248}"
    r"\.(service|socket|timer|mount|automount|path|target|swap)\Z"
)
DURATION = re.compile(r"([0-9]{1,7})([smhd])\Z")
DURATION_FACTOR = {"s": 1, "m": 60, "h": 3600, "d": 86400}
BARE_KEY = re.compile(r"[A-Za-z0-9_-]+\Z")
TOML_POSITION = re.compile(r"\(at line ([0-9]+), column ([0-9]+)\)\Z")


# --- typed result -----------------------------------------------------------------------


@dataclass(frozen=True)
class General:
    mode: str
    language: str


@dataclass(frozen=True)
class Limits:
    render_ms: int
    probe_timeout_s: float
    collect_total_s: int


@dataclass(frozen=True)
class VisibilityConfig:
    admin_group: str  # "" means root only (D33)


@dataclass(frozen=True)
class ModuleConfig:
    enabled: Union[bool, str]  # True, False or "auto"
    timeout_s: Optional[float]  # None: limits.probe_timeout_s


@dataclass(frozen=True)
class UnitRow:
    name: str
    label: str


@dataclass(frozen=True)
class FileAgeRow:
    path: str
    label: str
    warn_after: int  # seconds
    crit_after: int


@dataclass(frozen=True)
class PluginConfig:
    run_as: str
    timeout_s: Optional[float]  # None: limits.probe_timeout_s
    visibility: str


@dataclass(frozen=True)
class Config:
    general: General
    limits: Limits
    visibility: VisibilityConfig
    layout: Layout
    thresholds: Mapping[str, Rule]
    modules: Mapping[str, ModuleConfig] = field(default_factory=dict)
    unit_rows: tuple[UnitRow, ...] = ()
    file_age_rows: tuple[FileAgeRow, ...] = ()
    plugins: Mapping[str, PluginConfig] = field(default_factory=dict)
    look: Look = look.DEFAULT_LOOK

    def module(self, name: str) -> ModuleConfig:
        """The settings of one module; a module without a table is ``auto``."""
        return self.modules.get(name, ModuleConfig("auto", None))

    def plugin(self, name: str) -> PluginConfig:
        """The settings of one plugin; a plugin without a table gets the safe defaults."""
        return self.plugins.get(name, PluginConfig("motp-plugin", None, "admin"))


@dataclass(frozen=True)
class Problem:
    """One reason a file was ignored (or, in ``warnings``, a setting without effect).

    ``reason`` names the key and what is expected; ``line`` is where the key is written,
    when that can be found reliably (``line_of``).
    """

    file: str
    reason: MessageRef
    line: Optional[int] = None


@dataclass(frozen=True)
class Loaded:
    """Result of ``load``: the config, the files applied, the problems found (each one
    ignored a file) and the warnings (names that match nothing; the file still applies)."""

    config: Config
    applied: tuple[str, ...]
    problems: tuple[Problem, ...]
    warnings: tuple[Problem, ...] = ()

    @property
    def ignored(self) -> int:
        """How many files were ignored (the admin's attention row, usability item 6)."""
        return len({p.file for p in self.problems})


# --- schema -----------------------------------------------------------------------------

Raw = dict[str, Any]


_Errors = list[MessageRef]


def _fail(
    msg_id: str, key: str, params: Optional[Mapping[str, Union[int, str]]] = None
) -> MessageRef:
    """A problem with ``key``; string parameters are sanitised like every quoted input."""
    values: dict[str, Union[int, float, str]] = {"key": key, **(params or {})}
    clean = {k: sanitize(v, PARAM_CELLS) if type(v) is str else v for k, v in values.items()}
    return MessageRef(msg_id, tuple(sorted(clean.items())))


def key_path(*parts: str) -> str:
    """A TOML dotted key, quoting parts that are not bare keys."""
    out = []
    for part in parts:
        if BARE_KEY.match(part):
            out.append(part)
        else:
            out.append('"' + part.replace("\\", "\\\\").replace('"', '\\"') + '"')
    return ".".join(out)


def _is_int(value: object) -> bool:
    return type(value) is int


def _is_number(value: object) -> bool:
    return type(value) in (int, float) and math.isfinite(value)  # type: ignore[arg-type]


def _fmt(number: float) -> str:
    return str(int(number)) if float(number).is_integer() else str(number)


Check = Callable[[object, str, _Errors], None]


def _choice(choices: tuple[str, ...]) -> Check:
    def check(value: object, key: str, errors: _Errors) -> None:
        if type(value) is not str or value not in choices:
            errors.append(_fail("config.error.choice", key, {"choices": ", ".join(choices)}))

    return check


def _integer(low: int, high: int) -> Check:
    def check(value: object, key: str, errors: _Errors) -> None:
        if not _is_int(value) or not low <= value <= high:  # type: ignore[operator]
            errors.append(_fail("config.error.integer", key, {"low": low, "high": high}))

    return check


def _number(low: float, high: float) -> Check:
    def check(value: object, key: str, errors: _Errors) -> None:
        if not _is_number(value) or not low <= value <= high:  # type: ignore[operator]
            errors.append(_fail("config.error.number", key, {"low": _fmt(low), "high": _fmt(high)}))

    return check


def _any_number(value: object, key: str, errors: _Errors) -> None:
    if not _is_number(value):
        errors.append(_fail("config.error.any_number", key))


def _pattern(pattern: "re.Pattern[str]", msg_id: str) -> Check:
    def check(value: object, key: str, errors: _Errors) -> None:
        if type(value) is not str or not pattern.match(value):
            errors.append(_fail(msg_id, key))

    return check


def _bool_or_auto(value: object, key: str, errors: _Errors) -> None:
    if value is not True and value is not False and value != "auto":
        errors.append(_fail("config.error.bool_or_auto", key))


def _admin_group(value: object, key: str, errors: _Errors) -> None:
    if type(value) is not str or (value != "" and not GROUP_NAME.match(value)):
        errors.append(_fail("config.error.group_name", key))
    elif value == "adm":
        errors.append(_fail("config.error.group_adm", key))  # D33: never adm


def _text(allow_empty: bool) -> Check:
    def check(value: object, key: str, errors: _Errors) -> None:
        ok = (
            type(value) is str
            and (allow_empty or value != "")
            and len(value) <= LABEL_CELLS
            and sanitize(value, LABEL_CELLS) == value
        )
        if not ok:
            errors.append(_fail("config.error.label", key, {"max": LABEL_CELLS}))

    return check


def _sections(value: object, key: str, errors: _Errors) -> None:
    ok = (
        type(value) is list
        and 0 < len(value) <= len(SECTIONS)
        and all(type(v) is str and v in SECTIONS for v in value)
        and len(set(value)) == len(value)
    )
    if not ok:
        errors.append(_fail("config.error.sections", key, {"choices": ", ".join(SECTIONS)}))


def duration_seconds(value: object) -> Optional[int]:
    """``"90s"``, ``"30m"``, ``"26h"``, ``"3d"`` as seconds; ``None`` if malformed."""
    if type(value) is not str:
        return None
    match = DURATION.match(value)
    if match is None:
        return None
    seconds = int(match.group(1)) * DURATION_FACTOR[match.group(2)]
    return seconds if 0 < seconds <= MAX_DURATION else None


def _duration(value: object, key: str, errors: _Errors) -> None:
    if duration_seconds(value) is None:
        errors.append(_fail("config.error.duration", key))


def _path(value: object, key: str, errors: _Errors) -> None:
    """An absolute path in its normal form (no ``.``, ``..``, ``//`` or trailing ``/``),
    not ``/`` itself, without control or format characters (``[[rows.file_age]]``)."""
    ok = (
        type(value) is str
        and value.startswith("/")
        and value != "/"
        and not value.startswith("//")  # POSIX keeps a leading "//" in the normal form
        and "\x00" not in value
        and len(value) <= 4096
        and posixpath.normpath(value) == value
        and sanitize(value, 4096) == value
    )
    if not ok:
        errors.append(_fail("config.error.absolute_path", key))


def _bool(value: object, key: str, errors: _Errors) -> None:
    if type(value) is not bool:
        errors.append(_fail("config.error.bool", key))


def _zero_or(low: int, high: int) -> Check:
    def check(value: object, key: str, errors: _Errors) -> None:
        if not _is_int(value) or not (value == 0 or low <= value <= high):  # type: ignore[operator]
            errors.append(_fail("config.error.zero_or", key, {"low": low, "high": high}))

    return check


def _color(allow_status: bool = False, free_part: bool = False) -> Check:
    def check(value: object, key: str, errors: _Errors) -> None:
        color = look.parse_color(value, allow_status)
        if color is None:
            msg = "config.error.color_status" if allow_status else "config.error.color"
            errors.append(_fail(msg, key))
        elif free_part and any(c < look.MIN_FREE_CONTRAST for c in color.contrasts()):
            errors.append(_fail("config.error.bar_contrast", key))

    return check


def _header_color(value: object, key: str, errors: _Errors) -> None:
    if value != "":
        _color()(value, key, errors)


def _font(charset: str) -> Check:
    def check(value: object, key: str, errors: _Errors) -> None:
        if type(value) is not str or not (value == look.AUTO or look.FONT_NAME.match(value)):
            errors.append(_fail("config.error.font_name", key))
        elif look.BUNDLED_FONTS.get(value, charset) != charset and charset == "ascii":
            errors.append(_fail("config.error.font_charset", key))

    return check


def _item_keys(value: object, key: str, errors: _Errors) -> None:
    ok = (
        type(value) is list
        and len(value) <= MAX_ITEM_KEYS
        and all(
            type(v) is str
            and len(v) <= 128
            and (BUILTIN_KEY.match(v) is not None or STORED_PLUGIN_KEY.match(v) is not None)
            for v in value
        )
    )
    if not ok:
        errors.append(_fail("config.error.item_keys", key, {"max": MAX_ITEM_KEYS}))


def _per_section(inner: Check) -> Check:
    """A table with one entry per section name, each checked by ``inner``."""

    def check(value: object, key: str, errors: _Errors) -> None:
        if not isinstance(value, dict):
            errors.append(_fail("config.error.table", key))
            return
        for name, entry in value.items():
            if name not in SECTIONS:
                errors.append(_fail("config.error.unknown_key", f"{key}.{key_path(name)}"))
            else:
                inner(entry, f"{key}.{key_path(name)}", errors)

    return check


def _check_chars(entry: Raw, e: _Errors) -> None:
    for charset, chars in entry.items():
        prefix = ("theme", "chars", charset)
        if charset not in look.CHARSETS:
            e.append(_fail("config.error.unknown_key", key_path(*prefix)))
        elif not isinstance(chars, dict):
            e.append(_fail("config.error.table", key_path(*prefix)))
        else:
            for name, char in chars.items():
                if name not in look.CHAR_KEYS:
                    e.append(_fail("config.error.unknown_key", key_path(*prefix, name)))
                elif not look.check_char(char, charset, name):
                    msg = "config.error.char_ascii" if charset == "ascii" else "config.error.char"
                    e.append(_fail(msg, key_path(*prefix, name)))


def _validate_theme(value: Raw, e: _Errors) -> None:
    """``[theme]`` with its tables ``colors``, ``chars.unicode``, ``chars.ascii``, ``bar``."""
    for key, entry in value.items():
        if key == "preset":
            _choice(look.PRESETS)(entry, key_path("theme", key), e)
        elif key == "markers":
            _choice(look.MARKER_MODES)(entry, key_path("theme", key), e)
        elif key not in ("colors", "bar", "chars"):
            e.append(_fail("config.error.unknown_key", key_path("theme", key)))
        elif not isinstance(entry, dict):
            e.append(_fail("config.error.table", key_path("theme", key)))
        elif key == "chars":
            _check_chars(entry, e)
        else:
            checks = THEME_COLORS if key == "colors" else THEME_BAR
            _check_keys(entry, checks, ("theme", key), e)


THEME_COLORS: dict[str, Check] = {
    role: _color(allow_status=role == "bar_used", free_part=role == "bar_free")
    for role in look.ROLES
}
THEME_BAR: dict[str, Check] = {
    "width": _zero_or(*look.BAR_WIDTH),
    "style": _choice(look.BAR_STYLES),
    "text": _choice(look.BAR_TEXTS),
}

# Fixed tables: key -> check. Every key of a fixed table has a default.
FIXED_TABLES: dict[str, dict[str, Check]] = {
    "general": {"mode": _choice(MODES), "language": _pattern(LANGUAGE, "config.error.language")},
    "limits": {
        "render_ms": _integer(RENDER_MS_MIN, RENDER_MS_MAX),
        "probe_timeout_s": _number(0.5, 30),
        "collect_total_s": _integer(10, 80),  # the unit stops a run after 90 s (4.11)
    },
    "visibility": {"admin_group": _admin_group},
    "layout": {
        "sections": _sections,
        "header": _choice(HEADER_MODES),
        "header_text": _text(allow_empty=True),
        "charset": _choice(CHARSETS),
        "color": _choice(COLOR_MODES),
        "tips": _bool,
        "header_case": _choice(look.HEADER_CASES),
        "header_font": _font("unicode"),
        "header_font_ascii": _font("ascii"),
        "header_align": _choice(look.HEADER_ALIGNS),
        "header_color": _header_color,
        "frame": _bool,
        "label_style": _choice(look.LABEL_STYLES),
        "label_width": _zero_or(*look.LABEL_WIDTH),
        "section_titles": _per_section(_text(allow_empty=False)),
        "hide_rows": _item_keys,
        "row_order": _per_section(_item_keys),
    },
}
# Named tables: [<table>.<name>] with a name pattern and the keys each may hold.
NAMED_TABLES: dict[str, tuple["re.Pattern[str]", str, dict[str, Check]]] = {
    "thresholds": (
        RULE_NAME,
        "config.error.name",
        {
            "warn": _any_number,
            "crit": _any_number,
            "direction": _choice(tuple(d.value for d in Direction)),
        },
    ),
    "modules": (
        MODULE_NAME,
        "config.error.name",
        {"enabled": _bool_or_auto, "timeout_s": _number(0.5, 30)},
    ),
    "plugins": (
        PLUGIN_NAME,
        "config.error.plugin_name",
        {
            "run_as": _choice(RUN_AS),
            "timeout_s": _number(0.5, 30),
            "visibility": _choice(PLUGIN_VISIBILITY),
        },
    ),
}
# Arrays of tables: [[rows.<kind>]] with required keys.
ROW_TABLES: dict[str, dict[str, Check]] = {
    "unit": {"name": _pattern(UNIT_NAME, "config.error.unit_name"), "label": _text(False)},
    "file_age": {
        "path": _path,
        "label": _text(False),
        "warn_after": _duration,
        "crit_after": _duration,
    },
}
TOP_LEVEL = (*FIXED_TABLES, *NAMED_TABLES, "rows", "theme")


def _check_keys(
    table: Raw, checks: Mapping[str, Check], prefix: tuple[str, ...], e: _Errors
) -> None:
    for key, value in table.items():
        check = checks.get(key)
        if check is None:
            e.append(_fail("config.error.unknown_key", key_path(*prefix, key)))
        else:
            check(value, key_path(*prefix, key), e)


# --- names that exist (final review, usability item 5) ------------------------------------
#
# A module, threshold or item key that does not exist is a warning, not a problem: the file
# is still applied, the setting simply has no effect. That keeps a config written for a
# newer version (with a module this one lacks) from being ignored as a whole, and the login
# never notices. ``motp config check`` and ``motp doctor`` report each warning, with the
# closest known name where one is close enough.

SUGGEST_CUTOFF = 0.75


def _suggest(name: str, known: "tuple[str, ...] | list[str]") -> str:
    import difflib

    close = difflib.get_close_matches(name, list(known), n=1, cutoff=SUGGEST_CUTOFF)
    return close[0] if close else ""


UNKNOWN_MODULE = ("config.warning.module", "config.warning.module_like")
UNKNOWN_THRESHOLD = ("config.warning.threshold", "config.warning.threshold_like")
UNKNOWN_ITEM_KEY = ("config.warning.item_key", "config.warning.item_key_like")


def _unknown(
    ids: tuple[str, str], key: str, name: str, known: "tuple[str, ...] | list[str]"
) -> MessageRef:
    """The first id for ``name`` at ``key``, or the second with the closest known name."""
    suggestion = _suggest(name, known)
    params: dict[str, Union[int, str]] = {"name": name}
    if suggestion:
        return _fail(ids[1], key, {**params, "suggestion": suggestion})
    return _fail(ids[0], key, params)


def name_warnings(raw: Raw) -> list[MessageRef]:
    """Module, threshold and item key names in ``raw`` that match nothing built in.

    Plugin keys (``plugin.<name>.<key>``) are not checked: plugins are found at run time.
    """
    from motp.modules import registry

    modules = registry.module_names()
    rules = tuple(_default_raw().get("thresholds", {}))
    keys = registry.all_keys()
    out: list[MessageRef] = []
    for name in raw.get("modules", {}) if isinstance(raw.get("modules"), dict) else ():
        if name not in modules:
            out.append(_unknown(UNKNOWN_MODULE, key_path("modules", name), name, modules))
    thresholds = raw.get("thresholds")
    for name in thresholds if isinstance(thresholds, dict) else ():
        if name not in rules:
            out.append(_unknown(UNKNOWN_THRESHOLD, key_path("thresholds", name), name, rules))
    found = raw.get("layout")
    layout: Raw = found if isinstance(found, dict) else {}
    lists: list[tuple[str, object]] = [(key_path("layout", "hide_rows"), layout.get("hide_rows"))]
    order = layout.get("row_order")
    if isinstance(order, dict):
        lists += [(key_path("layout", "row_order", sec), v) for sec, v in order.items()]
    for where, value in lists:
        for item_key in value if isinstance(value, list) else ():
            if type(item_key) is not str or item_key.startswith("plugin."):
                continue
            if not registry.key_known(item_key):
                out.append(_unknown(UNKNOWN_ITEM_KEY, where, item_key, keys))
    return out


# --- where a key is written (final review, usability item 6) -----------------------------

_HEADER = re.compile(r"^\s*\[\[?\s*([^\]]+?)\s*\]\]?\s*(?:#.*)?$")
_ASSIGN = re.compile(r"^\s*([A-Za-z0-9_\-\.\"' ]+?)\s*=")


def _norm(dotted: str) -> str:
    return ".".join(part.strip().strip("\"'") for part in dotted.split("."))


def line_of(text: str, key: str) -> Optional[int]:
    """The 1-based line that writes ``key`` (a dotted key path), when exactly one does.

    Only the plain forms are found: ``[table]`` or ``[[table]]`` headers, and ``name =``
    inside the table or as a dotted key. A key written another way (inline tables, quoted
    names with dots) gives ``None``: no line is better than a wrong one.
    """
    if not key or key.endswith(("…", "...")):
        return None
    want = _norm(key)
    hits: list[int] = []
    table = ""
    for number, line in enumerate(text.splitlines(), 1):
        header = _HEADER.match(line)
        if header:
            table = _norm(header.group(1))
            if table == want:
                hits.append(number)
            continue
        assign = _ASSIGN.match(line)
        if assign:
            full = _norm(assign.group(1)) if not table else table + "." + _norm(assign.group(1))
            if full == want:
                hits.append(number)
    return hits[0] if len(set(hits)) == 1 else None


def validate(raw: Raw) -> list[MessageRef]:
    """Check one parsed file against the schema; return every problem found."""
    e: _Errors = []
    for top, value in raw.items():
        if top not in TOP_LEVEL:
            e.append(_fail("config.error.unknown_key", key_path(top)))
        elif not isinstance(value, dict):
            e.append(_fail("config.error.table", key_path(top)))
        elif top == "theme":
            _validate_theme(value, e)
        elif top in FIXED_TABLES:
            _check_keys(value, FIXED_TABLES[top], (top,), e)
        elif top in NAMED_TABLES:
            pattern, name_error, checks = NAMED_TABLES[top]
            if len(value) > MAX_TABLE_ENTRIES:
                e.append(_fail("config.error.too_many", key_path(top), {"max": MAX_TABLE_ENTRIES}))
            for name, entry in value.items():
                if not pattern.match(name):
                    e.append(_fail(name_error, key_path(top, name)))
                elif not isinstance(entry, dict):
                    e.append(_fail("config.error.table", key_path(top, name)))
                else:
                    _check_keys(entry, checks, (top, name), e)
        else:  # rows
            for kind, rows in value.items():
                row_checks = ROW_TABLES.get(kind)
                if row_checks is None:
                    e.append(_fail("config.error.unknown_key", key_path(top, kind)))
                elif not isinstance(rows, list) or not all(isinstance(r, dict) for r in rows):
                    e.append(_fail("config.error.rows", key_path(top, kind)))
                elif len(rows) > MAX_ROWS:
                    e.append(_fail("config.error.too_many", key_path(top, kind), {"max": MAX_ROWS}))
                else:
                    for row in rows:
                        _check_keys(row, row_checks, (top, kind), e)
                        for required in row_checks:
                            if required not in row:
                                e.append(
                                    _fail("config.error.missing_key", key_path(top, kind, required))
                                )
    return e


# --- merge and typed view ---------------------------------------------------------------


def merge(base: Raw, layer: Raw, path: tuple[str, ...] = ()) -> Raw:
    """Override ``base`` with ``layer`` key by key in every table.

    The lists of ``[[rows.<kind>]]`` add up instead; every other value, lists such as
    ``layout.sections`` included, is replaced.
    """
    out: Raw = dict(base)
    for key, value in layer.items():
        old = out.get(key)
        if isinstance(value, dict) and isinstance(old, dict):
            out[key] = merge(old, value, (*path, key))
        elif path == ("rows",) and isinstance(value, list) and isinstance(old, list):
            out[key] = [*old, *value]
        else:
            out[key] = value
    return out


def _optional_float(value: object) -> Optional[float]:
    return None if value is None else float(value)  # type: ignore[arg-type]


def build(merged: Raw) -> Config:
    """Turn a merged, validated tree (defaults included) into the typed config.

    Raises ``ContractError`` for problems that only show across keys: threshold limits in
    the wrong order, an age row whose critical limit comes first, too many rows in total.
    """
    g, lim, vis, lay = (merged[t] for t in ("general", "limits", "visibility", "layout"))
    rules: dict[str, Rule] = {}
    for name, spec in merged.get("thresholds", {}).items():
        if "warn" not in spec or "crit" not in spec:
            raise ContractError(_fail("config.error.rule_limits", key_path("thresholds", name)))
        direction = Direction(spec["direction"]) if "direction" in spec else None
        rules[name] = make_rule(name, spec["warn"], spec["crit"], direction)
    rows = merged.get("rows", {})
    unit_rows = tuple(UnitRow(r["name"], r["label"]) for r in rows.get("unit", []))
    age_rows = []
    for r in rows.get("file_age", []):
        warn, crit = duration_seconds(r["warn_after"]), duration_seconds(r["crit_after"])
        if warn is None or crit is None or crit < warn:
            raise ContractError(_fail("config.error.age_order", key_path("rows", "file_age")))
        age_rows.append(FileAgeRow(r["path"], r["label"], warn, crit))
    resolved = look.resolve(merged.get("theme", {}), lay)
    for charset, chars in resolved.chars.items():
        if chars.bar_used == chars.bar_free:
            raise ContractError(
                _fail("config.error.bar_chars", key_path("theme", "chars", charset))
            )
    for kind, count in (("unit", len(unit_rows)), ("file_age", len(age_rows))):
        if count > MAX_ROWS:
            raise ContractError(
                _fail("config.error.too_many", key_path("rows", kind), {"max": MAX_ROWS})
            )
    return Config(
        general=General(g["mode"], g["language"]),
        limits=Limits(lim["render_ms"], float(lim["probe_timeout_s"]), lim["collect_total_s"]),
        visibility=VisibilityConfig(vis["admin_group"]),
        layout=Layout(
            sections=tuple(lay["sections"]),
            header=lay["header"],
            header_text=lay["header_text"],
            charset=lay["charset"],
            color=lay["color"],
            tips=lay["tips"],
        ),
        thresholds=rules,
        modules={
            name: ModuleConfig(m.get("enabled", "auto"), _optional_float(m.get("timeout_s")))
            for name, m in merged.get("modules", {}).items()
        },
        unit_rows=unit_rows,
        file_age_rows=tuple(age_rows),
        plugins={
            name: PluginConfig(
                p.get("run_as", "motp-plugin"),
                _optional_float(p.get("timeout_s")),
                p.get("visibility", "admin"),
            )
            for name, p in merged.get("plugins", {}).items()
        },
        look=resolved,
    )


# --- parsing and loading ----------------------------------------------------------------


def parse(data: bytes) -> tuple[Optional[Raw], list[MessageRef]]:
    """Parse TOML bytes. Syntax errors report line and column only, never file content."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None, [contract_error("config.error.encoding").message]
    try:
        return _toml.loads(text), []
    except _toml.TOMLDecodeError as exc:
        match = TOML_POSITION.search(str(exc))
        if match is None:  # "(at end of document)"
            return None, [contract_error("config.error.syntax_end").message]
        line, column = int(match.group(1)), int(match.group(2))
        return None, [contract_error("config.error.syntax", line=line, column=column).message]
    except RecursionError:
        return None, [contract_error("config.error.too_deep").message]
    except ValueError:
        # Not a TOMLDecodeError: Python's own limits, such as an integer of more than 4300
        # digits, which both parsers pass on as a plain ValueError.
        return None, [contract_error("config.error.unreadable_value").message]


def read_layer(data: bytes) -> tuple[Optional[Raw], list[MessageRef]]:
    """Parse and validate one file; the tree, or ``None`` and every problem found."""
    raw, problems = parse(data)
    if raw is None:
        return None, problems
    problems = validate(raw)
    return (None, problems) if problems else (raw, [])


def check_content(data: bytes) -> list[MessageRef]:
    """Every problem of one file on top of the defaults (``motp config check <file>``)."""
    return [p.reason for p in content_report(data, "")[0]]


def located(file: str, data: bytes, reasons: "list[MessageRef]") -> list[Problem]:
    """``reasons`` as problems of ``file``, each with its line where it can be found."""
    text = data.decode("utf-8", "replace")
    out = []
    for reason in reasons:
        params = reason.param_dict()
        key, line = params.get("key"), params.get("line")
        if type(line) is not int:
            line = line_of(text, key) if type(key) is str else None
        out.append(Problem(file, reason, line))
    return out


def content_report(data: bytes, file: str) -> tuple[list[Problem], list[Problem]]:
    """Problems and warnings of one file checked alone on top of the defaults."""
    raw, problems = read_layer(data)
    if raw is None:
        return located(file, data, problems), []
    try:
        build(merge(_default_raw(), raw))
    except ContractError as exc:
        return located(file, data, [exc.message]), []
    return [], located(file, data, name_warnings(raw))


@functools.cache
def _default_raw() -> Raw:
    data = pkgutil.get_data("motp", "data/default-config.toml")
    if data is None:  # pragma: no cover - the package always ships it
        raise RuntimeError("default-config.toml missing")
    raw, problems = parse(data)
    if raw is None or problems or validate(raw):
        raise RuntimeError("default-config.toml is invalid")  # a packaging bug
    return raw


def defaults() -> Config:
    """The config with no file applied."""
    return build(_default_raw())


Reader = Callable[[str, int], bytes]


def read_checked(path: str, max_bytes: int) -> bytes:
    """Read a config file through the ownership check (the production reader)."""
    return safepath.read_trusted(path, max_bytes)[0]


def config_files(root: str) -> tuple[list[str], list[Problem]]:
    """``config.toml`` and the ``conf.d/*.toml`` files under ``root``, in load order.

    Missing files and a missing ``conf.d`` are not problems. Names starting with a dot
    are skipped; at most ``MAX_DROPINS`` drop-in files are used.
    """
    files: list[str] = []
    problems: list[Problem] = []
    main = os.path.join(root, MAIN_FILE)
    if os.path.lexists(main):
        files.append(main)
    dropin_dir = os.path.join(root, DROPIN_DIR)
    try:
        names = sorted(
            n for n in os.listdir(dropin_dir) if n.endswith(".toml") and not n.startswith(".")
        )
    except FileNotFoundError:
        names = []
    except OSError:
        problems.append(Problem(dropin_dir, contract_error("config.error.unreadable").message))
        names = []
    if len(names) > MAX_DROPINS:
        problems.append(
            Problem(
                dropin_dir, contract_error("config.error.too_many_files", max=MAX_DROPINS).message
            )
        )
        names = names[:MAX_DROPINS]
    files += [os.path.join(dropin_dir, n) for n in names]
    return files, problems


UNREADABLE = frozenset({"safepath.error.unreadable", "config.error.unreadable"})


def closed_to_user(root: str, problems: "tuple[Problem, ...] | list[Problem]") -> bool:
    """Whether the config is simply closed to this user (an admin's stricter modes).

    Recommended for ``/etc/motp`` (``docs/plugins.md``, ``SECURITY.md``): only root can
    read the config, so an ordinary user's ``doctor`` or ``config check`` cannot judge it
    and says so instead of reporting problems that are not there (final review, item 4).
    """
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None or geteuid() == 0:
        return False
    if not os.access(root, os.R_OK | os.X_OK):
        return os.path.isdir(root)
    return bool(problems) and all(p.reason.id in UNREADABLE for p in problems)


def load(root: str = DEFAULT_ROOT, read: Reader = read_checked) -> Loaded:
    """Load the defaults, then each file under ``root`` that passes every check.

    ``read`` reads one file (path, byte cap) and raises ``ContractError`` to refuse it;
    tests on systems without owners pass a plain reader.
    """
    current = _default_raw()
    config = build(current)
    applied: list[str] = []
    warnings: list[Problem] = []
    files, problems = config_files(root)
    for path in files:
        try:
            data = read(path, MAX_FILE_BYTES)
        except ContractError as exc:
            problems.append(Problem(path, exc.message))
            continue
        raw, found = read_layer(data)
        if raw is None:
            problems += located(path, data, found)
            continue
        tentative = merge(current, raw)
        try:
            config = build(tentative)
        except ContractError as exc:
            problems += located(path, data, [exc.message])
            continue
        current = tentative
        applied.append(path)
        warnings += located(path, data, name_warnings(raw))
    fonts = load_fonts(root, current, read, problems)
    if fonts:
        resolved = look.resolve(current.get("theme", {}), current["layout"], fonts)
        config = replace(config, look=resolved)
    return Loaded(config, tuple(applied), tuple(problems), tuple(warnings))


def font_path(root: str, name: str) -> str:
    return os.path.join(root, FONT_DIR, name + FONT_SUFFIX)


def load_fonts(
    root: str, merged: Raw, read: Reader, problems: list[Problem]
) -> dict[str, figfont.Font]:
    """The admin fonts a merged config names, each read through ``read`` (D35).

    A font file passes the ownership check of 4.7 and a size limit, and must be a FIGfont
    whose printable glyphs are one cell each, within bounds the renderer accepts in
    ``render.json``. One that fails is not used: the header falls back to the preset's
    font, and the problem names the file, the key and the form expected.
    """
    layout_raw = merged["layout"]
    read_once: dict[str, Optional[figfont.Font]] = {}  # a font named twice is read once
    fonts: dict[str, figfont.Font] = {}
    for charset, key in (("unicode", "header_font"), ("ascii", "header_font_ascii")):
        name = layout_raw.get(key, look.AUTO)
        if name == look.AUTO or name in look.BUNDLED_FONTS:
            continue
        path = font_path(root, name)
        setting = key_path("layout", key)
        if name not in read_once:
            read_once[name] = None
            try:
                data = read(path, MAX_FONT_FILE_BYTES)
            except ContractError as exc:
                problems.append(Problem(path, exc.message))
                limit = {"max": MAX_FONT_FILE_BYTES // 1024}
                problems.append(Problem(path, _fail("config.error.font_file", setting, limit)))
                continue
            read_once[name] = admin_font(name, data)
            if read_once[name] is None:
                problems.append(Problem(path, _fail("config.error.font_format", setting)))
        font = read_once[name]
        if font is None:
            continue
        # The ASCII check runs for each key, also when the Unicode key read the font.
        if charset == "ascii" and not font.ascii_only:
            problems.append(Problem(path, _fail("config.error.font_ascii", setting)))
            continue
        fonts[name] = font
    return fonts


def admin_font(name: str, data: bytes) -> Optional[figfont.Font]:
    """An admin font reduced to the characters a header can show, or ``None``."""
    font = figfont.parse(name, data, MAX_FONT_FILE_BYTES)
    if font is None:
        return None
    glyphs = {ch: font.glyphs[ch] for ch in figfont.DRAWN}
    if sum(len(g[0]) * len(g) for g in glyphs.values()) > MAX_FONT_CELLS:
        return None
    return replace(font, glyphs=glyphs)

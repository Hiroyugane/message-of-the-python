"""Probe document validation, built-in and plugin forms (blueprint 4.4, D26, D27, D34).

The collector passes every probe's and every plugin's stdout through ``validate_builtin``
or ``validate_plugin``. A document is accepted only if it passes all checks; otherwise a
``ContractError`` names the first problem and the module counts as failed for this run.

Checks for every document: at most 64 KiB, UTF-8 with replacement, JSON without ``NaN`` or
infinities, nesting depth limited, no repeated keys, only known fields with the expected
types, at most 32 items, strings within limits, and the module name of the probe that was
started. Every string is sanitised.

Plugin rules on top: keys are forced into ``plugin.<name>.*``; labels, texts and hints are
literal text only (no message ids, no hint ids, never a template); a ``command`` field is
refused anywhere; items are admin-only unless the config made the plugin public; the
renderer adds the fixed ``[plugin <name>]`` prefix from ``Item.origin``; ``module`` may be
left out (phase 12). A plugin may also print one line and exit with 0 (ok), 1 (warning),
2 (critical) or 3 (unknown).

One built-in module may add per-user data (D32): ``os_login`` sends a ``users`` list,
``[{"uid": 1000, "logins": [{"started": ..., "source": ..., "tty": ...}]}]``, which the
collector writes to ``user/<uid>.json`` and never into a tier file. No other module and no
plugin may send that field. Its document may be larger (``PER_USER_DOCUMENT_BYTES``),
since it holds up to ``MAX_USERS`` accounts.

The item parser also serves the cache reader (``Form.CACHE``), which re-validates and
re-sanitises everything it reads.
"""

import math
import re
from collections.abc import Mapping
from enum import Enum
from typing import Optional

from motp.core import hints, i18n, strictjson
from motp.core.model import (
    Detail,
    Hint,
    HintRef,
    Item,
    Label,
    LiteralText,
    Login,
    MessageRef,
    ProbeDocument,
    Scalar,
    Status,
    Text,
    Unit,
    UserLogins,
    Value,
    Visibility,
    contract_error,
    ref,
)
from motp.core.sanitize import HINT_CELLS, LABEL_CELLS, PARAM_CELLS, TEXT_CELLS, VALUE_CELLS
from motp.core.sanitize import sanitize as _sanitize
from motp.core.thresholds import RULE_NAME

API_VERSION = 1
MAX_DOCUMENT_BYTES = 64 * 1024
MAX_DEPTH = 8  # document > items > item > detail > row > label > i18n, with one to spare
MAX_ITEMS = 32
MAX_DETAILS = 16
MAX_PARAMS = 8
MAX_TRANSLATIONS = 8
MAX_STRING_CHARS = 1024  # raw length before sanitising; longer strings reject the document
MAX_KEY_CHARS = 64
MAX_VALUE_INT = 2**63 - 1

MODULE_NAME = re.compile(r"[a-z][a-z0-9_]{0,31}\Z")
PLUGIN_NAME = re.compile(r"[0-9]{2}-[a-z0-9_-]{1,45}\Z")
BUILTIN_KEY = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z0-9_-]+){1,4}\Z")
PLUGIN_KEY = re.compile(r"[a-z0-9_-]+(?:\.[a-z0-9_-]+){0,3}\Z")
STORED_PLUGIN_KEY = re.compile(r"plugin\.[0-9]{2}-[a-z0-9_-]{1,45}(?:\.[a-z0-9_-]+){1,4}\Z")

ITEM_FIELDS = frozenset(
    {"key", "label", "value", "unit", "rule", "status", "text", "bar", "visibility", "hint"}
    | {"detail"}
)
DETAIL_FIELDS = frozenset({"key", "label", "value", "unit", "visibility"})
DOCUMENT_FIELDS = frozenset({"api", "module", "items"})
# Built-in modules that may send per-user data (D32), and its limits.
PER_USER_MODULES = frozenset({"os_login"})
USERS_FIELD = "users"
PER_USER_DOCUMENT_BYTES = 256 * 1024
MAX_USERS = 256
MAX_UID = 2**32 - 2  # (uid_t) -1 means "no user" to the kernel
USER_FIELDS = frozenset({"uid", "logins"})
LOGIN_FIELDS = frozenset({"started", "source", "tty"})
FORBIDDEN_FIELD = "command"  # D34: no probe, built-in or plugin, can supply a command

STATUS_BY_EXIT_CODE = {0: Status.OK, 1: Status.WARN, 2: Status.CRIT, 3: Status.UNKNOWN}


class Form(Enum):
    BUILTIN = "builtin"  # a built-in probe's document
    PLUGIN = "plugin"  # an exec plugin's JSON document
    CACHE = "cache"  # an item read back from a cache file


_fail = contract_error


def _object(value: object, path: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise _fail("probe.error.wrong_type", field=path)
    return value


def _check_fields(obj: Mapping[str, object], allowed: frozenset[str], path: str) -> None:
    if FORBIDDEN_FIELD in obj:
        raise _fail("probe.error.command", field=f"{path}.{FORBIDDEN_FIELD}")
    for name in obj:
        if name not in allowed:
            raise _fail("probe.error.unknown_field", field=f"{path}.{name}")


def _string(value: object, path: str, cells: int) -> str:
    if type(value) is not str:
        raise _fail("probe.error.wrong_type", field=path)
    if len(value) > MAX_STRING_CHARS:
        raise _fail("probe.error.too_long", field=path, limit=MAX_STRING_CHARS)
    return _sanitize(value, cells)


def _pattern(value: object, path: str, pattern: "re.Pattern[str]", limit: int) -> str:
    if type(value) is not str:
        raise _fail("probe.error.wrong_type", field=path)
    if len(value) > limit or not pattern.match(value):
        raise _fail("probe.error.bad_value", field=path)
    return value


def _enum_value(value: object, path: str, enum: "type[Enum]") -> str:
    if type(value) is not str or value not in {e.value for e in enum}:
        raise _fail("probe.error.bad_value", field=path)
    return value


def _number(value: object) -> bool:
    return type(value) in (int, float) and math.isfinite(value)  # type: ignore[arg-type]


def _value(raw: object, unit: Unit, path: str) -> Value:
    """Check the raw value against its unit; strings are sanitised."""
    if raw is None:
        return None
    if type(raw) is int and abs(raw) > MAX_VALUE_INT:
        raise _fail("probe.error.bad_value", field=path)
    if unit is Unit.TEXT:
        return _string(raw, path, VALUE_CELLS)
    if unit is Unit.BOOL:
        if type(raw) is not bool:
            raise _fail("probe.error.wrong_type", field=path)
        return raw
    if unit in (Unit.COUNT, Unit.BYTES, Unit.TIMESTAMP):
        if type(raw) is not int:
            raise _fail("probe.error.wrong_type", field=path)
        if raw < 0:
            raise _fail("probe.error.bad_value", field=path)
        return raw
    if not _number(raw):
        raise _fail("probe.error.wrong_type", field=path)
    return raw  # type: ignore[return-value]


def _unit(obj: Mapping[str, object], path: str) -> Unit:
    if "unit" not in obj:
        return Unit.TEXT
    return Unit(_enum_value(obj["unit"], f"{path}.unit", Unit))


def _params(raw: object, path: str) -> tuple[tuple[str, Scalar], ...]:
    params = _object(raw, path)
    if len(params) > MAX_PARAMS:
        raise _fail("probe.error.too_many", field=path, limit=MAX_PARAMS)
    out: list[tuple[str, Scalar]] = []
    for name, value in params.items():
        if name == FORBIDDEN_FIELD:
            raise _fail("probe.error.command", field=f"{path}.{name}")
        if not i18n.PARAM_NAME.match(name):
            raise _fail("probe.error.bad_value", field=f"{path}.{name}")
        if type(value) is str:
            out.append((name, _string(value, f"{path}.{name}", PARAM_CELLS)))
        elif (type(value) is int and abs(value) <= MAX_VALUE_INT) or (
            type(value) is float and math.isfinite(value)
        ):
            out.append((name, value))
        else:
            raise _fail("probe.error.wrong_type", field=f"{path}.{name}")
    return tuple(sorted(out))


def _message_ref(raw: Mapping[str, object], path: str) -> MessageRef:
    _check_fields(raw, frozenset({"id", "params"}), path)
    msg_id = _pattern(raw.get("id"), f"{path}.id", i18n.MESSAGE_ID, MAX_KEY_CHARS)
    if not i18n.is_known(msg_id):
        raise _fail("probe.error.unknown_message", field=f"{path}.id")
    params = _params(raw["params"], f"{path}.params") if "params" in raw else ()
    return MessageRef(msg_id, params)


def _literal(raw: object, path: str, cells: int) -> LiteralText:
    """A literal text: a string, or ``{"text": ..., "i18n": {"de": ...}}``."""
    if type(raw) is str:
        return LiteralText(_string(raw, path, cells))
    obj = _object(raw, path)
    if "id" in obj:
        raise _fail("probe.error.plugin_message_id", field=f"{path}.id")
    _check_fields(obj, frozenset({"text", "i18n"}), path)
    if "text" not in obj:
        raise _fail("probe.error.missing_field", field=f"{path}.text")
    text = _string(obj["text"], f"{path}.text", cells)
    translations = _object(obj.get("i18n", {}), f"{path}.i18n")
    if len(translations) > MAX_TRANSLATIONS:
        raise _fail("probe.error.too_many", field=f"{path}.i18n", limit=MAX_TRANSLATIONS)
    pairs = []
    for lang, value in translations.items():
        if not i18n.LANGUAGE_CODE.match(lang):
            raise _fail("probe.error.bad_value", field=f"{path}.i18n")
        pairs.append((lang, _string(value, f"{path}.i18n.{lang}", cells)))
    return LiteralText(text, tuple(sorted(pairs)))


def _label_or_text(raw: object, path: str, cells: int, form: Form, literal_only: bool) -> Text:
    """A label or a text: a message reference for built-ins, literal text for plugins.

    In the cache both shapes occur: ``{"id": ...}`` and ``{"text": ...}``. A plugin's
    label and text may each be a string or ``{"text": ..., "i18n": {...}}`` (the final
    review extended translations from labels to texts and hints, usability item 13).
    """
    if form is Form.PLUGIN or literal_only:
        if isinstance(raw, dict) and "id" in raw:
            raise _fail("probe.error.plugin_message_id", field=f"{path}.id")
        return _literal(raw, path, cells)
    obj = _object(raw, path)
    if form is Form.CACHE and "id" not in obj:
        return _literal(obj, path, cells)
    return _message_ref(obj, path)


def _hint(raw: object, path: str, form: Form, literal_only: bool) -> Hint:
    if form is Form.PLUGIN:
        if isinstance(raw, dict) and "id" in raw:
            raise _fail("probe.error.plugin_message_id", field=f"{path}.id")
        return _literal(raw, path, HINT_CELLS)
    if form is Form.BUILTIN:
        hint_id = _pattern(raw, path, i18n.MESSAGE_ID, MAX_KEY_CHARS)
        if not hints.is_known(hint_id):
            raise _fail("probe.error.unknown_hint", field=path)
        return HintRef(hint_id)
    obj = _object(raw, path)
    if "id" in obj:
        if literal_only:
            raise _fail("probe.error.plugin_message_id", field=f"{path}.id")
        _check_fields(obj, frozenset({"id"}), path)
        hint_id = _pattern(obj["id"], f"{path}.id", i18n.MESSAGE_ID, MAX_KEY_CHARS)
        if not hints.is_known(hint_id):
            raise _fail("probe.error.unknown_hint", field=path)
        return HintRef(hint_id)
    return _literal(obj, path, HINT_CELLS)


def _key(raw: object, path: str, form: Form, plugin: Optional[str]) -> str:
    if form is Form.PLUGIN and plugin is not None:
        prefix = f"plugin.{plugin}."
        if type(raw) is not str:
            raise _fail("probe.error.wrong_type", field=path)
        key = raw
        if key.startswith(prefix):
            key = key[len(prefix) :]
        if len(key) > MAX_KEY_CHARS or not PLUGIN_KEY.match(key):
            raise _fail("probe.error.bad_value", field=path)
        return prefix + key
    if form is Form.CACHE and plugin is not None:
        key = _pattern(raw, path, STORED_PLUGIN_KEY, 2 * MAX_KEY_CHARS)
        if not key.startswith(f"plugin.{plugin}."):
            raise _fail("probe.error.bad_value", field=path)
        return key
    key = _pattern(raw, path, BUILTIN_KEY, MAX_KEY_CHARS)
    if key.startswith("plugin."):  # the plugin namespace belongs to plugins (D27)
        raise _fail("probe.error.bad_value", field=path)
    return key


def _visibility(
    obj: Mapping[str, object], path: str, default: Visibility, forced: Optional[Visibility]
) -> Visibility:
    if "visibility" in obj:
        value = Visibility(_enum_value(obj["visibility"], f"{path}.visibility", Visibility))
    else:
        value = default
    return forced if forced is Visibility.ADMIN else value


def _detail(
    raw: object, path: str, form: Form, plugin: Optional[str], forced: Optional[Visibility]
) -> Detail:
    obj = _object(raw, path)
    _check_fields(obj, DETAIL_FIELDS, path)
    if "key" not in obj:
        raise _fail("probe.error.missing_field", field=f"{path}.key")
    literal_only = plugin is not None
    unit = _unit(obj, path)
    label = None
    if "label" in obj:
        label = _label_or_text(obj["label"], f"{path}.label", LABEL_CELLS, form, literal_only)
    return Detail(
        key=_key(obj["key"], f"{path}.key", form, plugin),
        value=_value(obj.get("value"), unit, f"{path}.value"),
        unit=unit,
        label=label,
        visibility=_visibility(obj, path, Visibility.ADMIN, forced),
    )


def parse_item(
    raw: object,
    path: str,
    form: Form,
    *,
    plugin: Optional[str] = None,
    default_visibility: Visibility = Visibility.PUBLIC,
    forced_visibility: Optional[Visibility] = None,
) -> Item:
    """Validate one item. ``plugin`` is the plugin name for plugin items, else ``None``.

    ``forced_visibility=ADMIN`` makes the item and its details admin-only whatever the
    document says (D27).
    """
    obj = _object(raw, path)
    allowed = ITEM_FIELDS | {"origin"} if form is Form.CACHE else ITEM_FIELDS
    _check_fields(obj, allowed, path)
    if form is Form.CACHE and "origin" in obj:
        plugin = _pattern(obj["origin"], f"{path}.origin", PLUGIN_NAME, 48)
    literal_only = plugin is not None
    if "key" not in obj:
        raise _fail("probe.error.missing_field", field=f"{path}.key")
    unit = _unit(obj, path)

    rule = None
    if "rule" in obj:
        rule = _pattern(obj["rule"], f"{path}.rule", RULE_NAME, MAX_KEY_CHARS)
    status = None
    if "status" in obj:
        status = Status(_enum_value(obj["status"], f"{path}.status", Status))
    if rule is not None and status is not None and form is not Form.CACHE:
        raise _fail("probe.error.rule_and_status", field=path)

    bar = None
    if "bar" in obj:
        raw_bar = obj["bar"]
        if not _number(raw_bar) or not 0.0 <= float(raw_bar) <= 1.0:  # type: ignore[arg-type]
            raise _fail("probe.error.bad_value", field=f"{path}.bar")
        bar = float(raw_bar)  # type: ignore[arg-type]

    label: Optional[Label] = None
    if "label" in obj:
        label = _label_or_text(obj["label"], f"{path}.label", LABEL_CELLS, form, literal_only)
    text: Optional[Text] = None
    if "text" in obj:
        text = _label_or_text(obj["text"], f"{path}.text", TEXT_CELLS, form, literal_only)
    hint: Optional[Hint] = None
    if "hint" in obj:
        hint = _hint(obj["hint"], f"{path}.hint", form, literal_only)

    details_raw = obj.get("detail", [])
    if not isinstance(details_raw, list):
        raise _fail("probe.error.wrong_type", field=f"{path}.detail")
    if len(details_raw) > MAX_DETAILS:
        raise _fail("probe.error.too_many", field=f"{path}.detail", limit=MAX_DETAILS)
    details = tuple(
        _detail(d, f"{path}.detail.{i}", form, plugin, forced_visibility)
        for i, d in enumerate(details_raw)
    )
    return Item(
        key=_key(obj["key"], f"{path}.key", form, plugin),
        value=_value(obj.get("value"), unit, f"{path}.value"),
        unit=unit,
        label=label,
        rule=rule,
        status=status,
        text=text,
        bar=bar,
        visibility=_visibility(obj, path, default_visibility, forced_visibility),
        hint=hint,
        detail=details,
        origin=plugin,
    )


def _users(raw: object, generated: int) -> tuple[UserLogins, ...]:
    """The per-user data of ``os_login``: each uid once, each login a time, a source and a
    terminal; the strings are sanitised as the cache reader does again."""
    # Imported here: the cache module imports this one.
    from motp.core.cache import (
        LOGIN_SOURCE_CELLS,
        LOGIN_TTY_CELLS,
        MAX_LOGIN_FIELD,
        MAX_LOGINS,
        MAX_TIMESTAMP,
    )

    if not isinstance(raw, list):
        raise _fail("probe.error.wrong_type", field=USERS_FIELD)
    if len(raw) > MAX_USERS:
        raise _fail("probe.error.too_many", field=USERS_FIELD, limit=MAX_USERS)
    users: list[UserLogins] = []
    seen: set[int] = set()
    for i, entry_raw in enumerate(raw):
        path = f"{USERS_FIELD}.{i}"
        entry = _object(entry_raw, path)
        _check_fields(entry, USER_FIELDS, path)
        uid = entry.get("uid")
        if type(uid) is not int or not 0 <= uid <= MAX_UID or uid in seen:
            raise _fail("probe.error.bad_value", field=f"{path}.uid")
        seen.add(uid)
        logins_raw = entry.get("logins")
        if not isinstance(logins_raw, list) or not 1 <= len(logins_raw) <= MAX_LOGINS:
            raise _fail("probe.error.bad_value", field=f"{path}.logins")
        logins = []
        for j, login_raw in enumerate(logins_raw):
            lpath = f"{path}.logins.{j}"
            login = _object(login_raw, lpath)
            _check_fields(login, LOGIN_FIELDS, lpath)
            started = login.get("started")
            if type(started) is not int or not 0 < started <= MAX_TIMESTAMP:
                raise _fail("probe.error.bad_value", field=f"{lpath}.started")
            texts = {}
            for name, cells in (("source", LOGIN_SOURCE_CELLS), ("tty", LOGIN_TTY_CELLS)):
                value = login.get(name, "")
                if type(value) is not str or len(value) > MAX_LOGIN_FIELD:
                    raise _fail("probe.error.bad_value", field=f"{lpath}.{name}")
                texts[name] = _sanitize(value, cells)
            logins.append(Login(started, texts["source"], texts["tty"]))
        logins.sort(key=lambda login: login.started, reverse=True)
        users.append(UserLogins(uid=uid, generated=generated, logins=tuple(logins)))
    return tuple(users)


def _document(
    data: bytes,
    expected_module: str,
    form: Form,
    *,
    plugin: Optional[str],
    default_visibility: Visibility,
    forced_visibility: Optional[Visibility],
    generated: int = 0,
) -> ProbeDocument:
    per_user = form is Form.BUILTIN and expected_module in PER_USER_MODULES
    limit = PER_USER_DOCUMENT_BYTES if per_user else MAX_DOCUMENT_BYTES
    obj = _object(strictjson.loads(data, max_bytes=limit, max_depth=MAX_DEPTH), "document")
    _check_fields(obj, DOCUMENT_FIELDS | {USERS_FIELD} if per_user else DOCUMENT_FIELDS, "document")
    # A plugin may leave out ``module``: its name is its file name, which the admin may
    # change (the NN order) without editing the plugin. When given, it must match.
    required = ("api", "items") if form is Form.PLUGIN else ("api", "module", "items")
    for name in required:
        if name not in obj:
            raise _fail("probe.error.missing_field", field=name)
    if type(obj["api"]) is not int or obj["api"] != API_VERSION:
        raise _fail("probe.error.api")
    module = obj.get("module", expected_module)
    if type(module) is not str or module != expected_module:
        raise _fail("probe.error.module_mismatch", expected=expected_module)
    items_raw = obj["items"]
    if not isinstance(items_raw, list):
        raise _fail("probe.error.wrong_type", field="items")
    if len(items_raw) > MAX_ITEMS:
        raise _fail("probe.error.too_many", field="items", limit=MAX_ITEMS)
    items = tuple(
        parse_item(
            raw,
            f"items.{i}",
            form,
            plugin=plugin,
            default_visibility=default_visibility,
            forced_visibility=forced_visibility,
        )
        for i, raw in enumerate(items_raw)
    )
    keys = [item.key for item in items]
    if len(set(keys)) != len(keys):
        raise _fail("probe.error.duplicate_item_key")
    users = _users(obj[USERS_FIELD], generated) if per_user and USERS_FIELD in obj else None
    return ProbeDocument(module=expected_module, items=items, users=users)


def validate_builtin(
    data: bytes,
    module: str,
    default_visibility: Visibility = Visibility.PUBLIC,
    generated: int = 0,
) -> ProbeDocument:
    """Validate the stdout of the built-in probe ``module``.

    Items without a ``visibility`` get the module's default; details default to admin.
    ``generated`` is the time the per-user data of ``os_login`` is stamped with.
    """
    if not MODULE_NAME.match(module):
        raise _fail("probe.error.bad_value", field="module")
    return _document(
        data,
        module,
        Form.BUILTIN,
        plugin=None,
        default_visibility=default_visibility,
        forced_visibility=None,
        generated=generated,
    )


def validate_plugin(stdout: bytes, exit_code: int, plugin: str, public: bool) -> ProbeDocument:
    """Validate an exec plugin's output in either form (D26).

    Output whose first non-blank byte is ``{`` is the JSON form, anything else the line
    form. ``public`` is the plugin's ``visibility = "public"`` setting (D27): without it
    every item and detail is admin-only; with it the document's own visibility applies.
    """
    if not PLUGIN_NAME.match(plugin):
        raise _fail("probe.error.bad_value", field="plugin")
    if type(exit_code) is not int or exit_code not in STATUS_BY_EXIT_CODE:
        raise _fail("probe.error.exit_code", code=exit_code if type(exit_code) is int else -1)
    if len(stdout) > MAX_DOCUMENT_BYTES:
        raise _fail("json.error.too_large", limit=MAX_DOCUMENT_BYTES)
    forced = None if public else Visibility.ADMIN
    if stdout.lstrip()[:1] == b"{":
        return _document(
            stdout,
            plugin,
            Form.PLUGIN,
            plugin=plugin,
            default_visibility=Visibility.PUBLIC if public else Visibility.ADMIN,
            forced_visibility=forced,
        )
    visibility = Visibility.PUBLIC if public else Visibility.ADMIN
    return _line_document(stdout, exit_code, plugin, visibility)


def _line_document(
    stdout: bytes, exit_code: int, plugin: str, visibility: Visibility
) -> ProbeDocument:
    """The monitoring-plugin form: first line of text, status from the exit code.

    Performance data after ``|`` is dropped, as are further lines.
    """
    line = stdout.decode("utf-8", "replace").splitlines()[0] if stdout.strip() else ""
    line = line.split("|", 1)[0]
    text = _sanitize(line[:MAX_STRING_CHARS], TEXT_CELLS)
    item = Item(
        key=f"plugin.{plugin}.status",
        status=STATUS_BY_EXIT_CODE[exit_code],
        text=LiteralText(text) if text else None,
        visibility=visibility,
        origin=plugin,
    )
    return ProbeDocument(module=plugin, items=(item,))


def plugin_prefix(plugin: str) -> MessageRef:
    """The fixed prefix of every plugin row, also in the attention block (4.4)."""
    return ref("plugin.prefix", name=plugin)

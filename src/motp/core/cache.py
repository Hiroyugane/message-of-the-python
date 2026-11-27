"""Cache file schemas, their encoders, and the bounded reader (blueprint 4.1, 4.4, D22, D32).

Files, all written by the collector (phase 6) and read by the renderer:

* ``public.json``  0644 root:root           public items only; no module states or errors
* ``admin.json``   0640 root:<admin group>  every item and detail, plus states and errors
* ``render.json``  0644 root:root           settings the renderer needs instead of the config
* ``user/<uid>.json`` 0400 root:root, plus a POSIX ACL entry that lets that one user read
  it (D32 as amended): that user's most recent logins

``admin.json`` holds the complete picture, so an admin's renderer reads one file instead of
merging two. ``public.json`` holds exactly what the public output may show (5.4): failed
modules appear only as a count.

The writers in phase 6 only build the model objects and call the ``encode_*`` functions.
The reader opens one file without following links and without blocking, accepts only a
regular file of the expected owner that no group or other user can write, reads at most a
fixed number of bytes, checks the schema, and sanitises every string again.
"""

import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Optional

from motp.core import i18n, look, strictjson
from motp.core.look import DEFAULT_LOOK, Look
from motp.core.model import (
    ContractError,
    Detail,
    Hint,
    HintRef,
    Item,
    Label,
    LiteralText,
    Login,
    MessageRef,
    ModuleResult,
    ModuleState,
    Scalar,
    UserLogins,
    Visibility,
    contract_error,
    ref,
)
from motp.core.probe import MODULE_NAME, PLUGIN_NAME, Form, parse_item
from motp.core.sanitize import PARAM_CELLS, sanitize
from motp.core.thresholds import RULE_NAME, Direction, Rule

SCHEMA = 1
PUBLIC = "public"
ADMIN = "admin"
TIERS = (PUBLIC, ADMIN)

MAX_TIER_BYTES = 512 * 1024
# Room for the largest look a valid config can give: two admin fonts of 16384 cells
# of four-byte characters and full row lists come to about 215 KB (D35).
MAX_RENDER_BYTES = 256 * 1024
MAX_USER_BYTES = 16 * 1024
MAX_DEPTH = 10  # tier file > modules > module > items > item > detail > row > label > i18n
MAX_MODULES = 64  # built-in modules plus up to 32 plugins
MAX_CONFIG_IGNORED = 128  # config.toml plus at most 64 drop-ins, with room
MAX_ITEMS_PER_MODULE = 32
MAX_LOGINS = 3
LOGIN_SOURCE_CELLS = 64  # the host a login came from, as shown
LOGIN_TTY_CELLS = 32
MAX_LOGIN_FIELD = 256  # raw length of a source or tty in a per-user file
MAX_RULES = 64
MAX_TIMESTAMP = 2**40  # far beyond any real clock; keeps arithmetic on ages small
MAX_INTERVAL = 10**7
MAX_AGE = 10**8
MAX_DURATION_MS = 10**7
TIER_HEADROOM_BYTES = 4096  # room for the file's own fields around the modules
LOGIN_GRACE_SECONDS = 10  # 4.4: the previous login started more than ten seconds ago
# A per-user file older than this is not shown: os_login rewrites it every run, so an old
# one means the module has been failing, and an account may have changed hands meanwhile
# (review of phase 10). One hour is os_login's max_age.
USER_FILE_MAX_AGE = 3600

SECTIONS = (
    "attention",
    "host",
    "system",
    "security",
    "login",
    "disks",
    "services",
    "containers",
    "plugins",
)
HEADER_MODES = ("hostname", "text", "off")
CHARSETS = ("auto", "ascii", "unicode")
COLOR_MODES = ("auto", "always", "never")
PACKAGE_MANAGERS = ("", "apt", "dnf")


@dataclass(frozen=True)
class TierCache:
    """Content of ``public.json`` or ``admin.json``."""

    tier: str
    generated: int
    modules: Mapping[str, ModuleResult]
    failed: int
    unreadable: int = 0  # modules the reader skipped because they broke the schema
    config_ignored: int = 0  # admin tier only: config files the collector ignored


@dataclass(frozen=True)
class Layout:
    sections: tuple[str, ...] = SECTIONS
    header: str = "hostname"
    header_text: str = ""
    charset: str = "auto"
    color: str = "auto"
    tips: bool = False  # a tip of the day below the message (D19)


@dataclass(frozen=True)
class RenderSettings:
    """Content of ``render.json``: what the renderer needs instead of ``/etc/motp`` (D22)."""

    generated: int
    layout: Layout
    language: str  # "auto" or a language code
    thresholds: Mapping[str, Rule]
    timer_period: int  # seconds between collector runs; the whole cache is old after three
    render_ms: int
    package_manager: str  # selects the hint commands; "" when neither apt nor dnf
    look: Look = DEFAULT_LOOK  # the resolved theme and layout switches (D35)


_fail = contract_error


# --- encoding -------------------------------------------------------------------------


def _message_json(message: MessageRef) -> dict[str, object]:
    out: dict[str, object] = {"id": message.id}
    if message.params:
        out["params"] = dict(message.params)
    return out


def _literal_json(literal: LiteralText) -> dict[str, object]:
    out: dict[str, object] = {"text": literal.text}
    if literal.i18n:
        out["i18n"] = dict(literal.i18n)
    return out


def _label_json(label: Label) -> dict[str, object]:
    return _message_json(label) if isinstance(label, MessageRef) else _literal_json(label)


def _hint_json(hint: Hint) -> dict[str, object]:
    return {"id": hint.id} if isinstance(hint, HintRef) else _literal_json(hint)


def _detail_json(detail: Detail) -> dict[str, object]:
    out: dict[str, object] = {
        "key": detail.key,
        "unit": detail.unit.value,
        "visibility": detail.visibility.value,
    }
    if detail.value is not None:
        out["value"] = detail.value
    if detail.label is not None:
        out["label"] = _label_json(detail.label)
    return out


def item_json(item: Item) -> dict[str, object]:
    """The cache form of an item; ``parse_item(..., Form.CACHE)`` reads it back."""
    out: dict[str, object] = {
        "key": item.key,
        "unit": item.unit.value,
        "visibility": item.visibility.value,
    }
    optional: dict[str, object] = {
        "value": item.value,
        "rule": item.rule,
        "status": item.status.value if item.status is not None else None,
        "bar": item.bar,
        "origin": item.origin,
        "label": _label_json(item.label) if item.label is not None else None,
        "text": _label_json(item.text) if item.text is not None else None,
        "hint": _hint_json(item.hint) if item.hint is not None else None,
    }
    out.update({k: v for k, v in optional.items() if v is not None})
    if item.detail:
        out["detail"] = [_detail_json(d) for d in item.detail]
    return out


def public_view(result: ModuleResult) -> ModuleResult:
    """The public part of a module result: public items with public details only."""
    items = tuple(
        replace(item, detail=tuple(d for d in item.detail if d.visibility is Visibility.PUBLIC))
        for item in result.items
        if item.visibility is Visibility.PUBLIC
    )
    return ModuleResult(
        collected=result.collected,
        interval=result.interval,
        max_age=result.max_age,
        items=items,
    )


def _module_json(result: ModuleResult, tier: str) -> dict[str, object]:
    out: dict[str, object] = {
        "collected": result.collected,
        "interval": result.interval,
        "max_age": result.max_age,
        "items": [item_json(i) for i in result.items],
    }
    if tier == ADMIN:
        if result.state is not None:
            out["state"] = result.state.value
        if result.duration_ms is not None:
            out["duration_ms"] = result.duration_ms
        if result.error is not None:
            out["error"] = _message_json(result.error)
    return out


def module_json(result: ModuleResult, tier: str = ADMIN) -> dict[str, object]:
    """One module entry as a tier file holds it; ``decode_module`` reads it back."""
    return _module_json(result, tier)


def _check_result(name: str, result: ModuleResult) -> None:
    """Refuse what the reader would refuse; a writer bug must not blank the whole file."""
    checks = (
        bool(MODULE_NAME.match(name) or PLUGIN_NAME.match(name)),
        0 <= result.collected <= MAX_TIMESTAMP,
        1 <= result.interval <= MAX_INTERVAL,
        1 <= result.max_age <= MAX_AGE,
        len(result.items) <= MAX_ITEMS_PER_MODULE,
        result.duration_ms is None or 0 <= result.duration_ms <= MAX_DURATION_MS,
        all(i.origin == (name if PLUGIN_NAME.match(name) else None) for i in result.items),
    )
    if not all(checks):
        raise ValueError(f"module result {name!r} breaks the cache schema")


def _too_large(result: ModuleResult) -> ModuleResult:
    return ModuleResult(
        collected=result.collected,
        interval=result.interval,
        max_age=result.max_age,
        state=ModuleState.FAILED,
        duration_ms=result.duration_ms,
        error=ref("cache.error.module_too_large"),
    )


def encode_tier_file(
    tier: str,
    generated: int,
    modules: Mapping[str, ModuleResult],
    failed: int,
    config_ignored: int = 0,
) -> bytes:
    """Serialise ``public.json`` or ``admin.json`` so that the reader accepts it.

    For the public tier every result is reduced by ``public_view`` and modules without
    public items are left out, so the file never carries admin-tier data. If the file
    would exceed ``MAX_TIER_BYTES``, the largest modules lose their items one by one and
    count as failed (in the admin tier with the reason ``cache.error.module_too_large``),
    instead of the whole file becoming unreadable. A result that breaks the schema is a
    writer bug and raises ``ValueError``.
    """
    if tier not in TIERS or not 0 <= failed <= MAX_MODULES or len(modules) > MAX_MODULES:
        raise ValueError("tier file arguments break the cache schema")
    if not 0 <= config_ignored <= MAX_CONFIG_IGNORED or (tier == PUBLIC and config_ignored):
        raise ValueError("config_ignored belongs to the admin tier, within its bound")
    results: dict[str, ModuleResult] = {}
    for name, result in sorted(modules.items()):
        _check_result(name, result)
        if tier == PUBLIC:
            result = public_view(result)
            if not result.items:
                continue
        results[name] = result
    sizes = {name: len(strictjson.dumps(_module_json(r, tier))) for name, r in results.items()}
    shrunk: set[str] = set()
    while sum(sizes.values()) > MAX_TIER_BYTES - TIER_HEADROOM_BYTES:
        candidates = [n for n in sizes if n not in shrunk]
        if not candidates:
            break
        name = max(candidates, key=lambda n: (sizes[n], n))
        failed = min(failed + 1, MAX_MODULES)
        if tier == PUBLIC:
            del results[name], sizes[name]
            continue
        results[name] = _too_large(results[name])
        sizes[name] = len(strictjson.dumps(_module_json(results[name], tier)))
        shrunk.add(name)
    entries = {name: _module_json(r, tier) for name, r in results.items()}
    doc: dict[str, object] = {
        "schema": SCHEMA,
        "tier": tier,
        "generated": generated,
        "modules": entries,
        "failed": failed,
    }
    if tier == ADMIN:
        doc["config_ignored"] = config_ignored
    return strictjson.dumps(doc)


def encode_render_file(settings: RenderSettings) -> bytes:
    layout = settings.layout
    return strictjson.dumps(
        {
            "schema": SCHEMA,
            "generated": settings.generated,
            "layout": {
                "sections": list(layout.sections),
                "header": layout.header,
                "header_text": layout.header_text,
                "charset": layout.charset,
                "color": layout.color,
                "tips": layout.tips,
            },
            "language": settings.language,
            "thresholds": {
                name: {"warn": r.warn, "crit": r.crit, "direction": r.direction.value}
                for name, r in sorted(settings.thresholds.items())
            },
            "timer_period": settings.timer_period,
            "render_ms": settings.render_ms,
            "package_manager": settings.package_manager,
            "look": look.look_json(settings.look),
        }
    )


def encode_user_file(user: UserLogins) -> bytes:
    return strictjson.dumps(
        {
            "schema": SCHEMA,
            "uid": user.uid,
            "generated": user.generated,
            "logins": [
                {"started": login.started, "source": login.source, "tty": login.tty}
                for login in user.logins[:MAX_LOGINS]
            ],
        }
    )


# --- reading --------------------------------------------------------------------------


def read_bounded(path: str, max_bytes: int, owner: Optional[int]) -> bytes:
    """Read one cache file under the rules of T4 and T12.

    The file is opened without following a final symlink and without blocking (a FIFO
    cannot stall the reader), must be a regular file, must belong to ``owner`` (when given)
    and must not be writable by group or others. At most ``max_bytes`` are read; a larger
    file is refused. All checks use the open descriptor, so the file cannot be swapped
    between check and read.
    """
    flags = os.O_RDONLY
    for name in ("O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC", "O_NOCTTY"):
        flags |= getattr(os, name, 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise _fail("cache.error.open") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise _fail("cache.error.not_regular")
        if owner is not None and st.st_uid != owner:
            raise _fail("cache.error.owner")
        if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise _fail("cache.error.writable")
        if st.st_size > max_bytes:
            raise _fail("cache.error.too_large", limit=max_bytes)
        chunks: list[bytes] = []
        size = 0
        while size <= max_bytes:
            chunk = os.read(fd, min(65536, max_bytes + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        if size > max_bytes:
            raise _fail("cache.error.too_large", limit=max_bytes)
        return b"".join(chunks)
    except OSError as exc:
        raise _fail("cache.error.open") from exc
    finally:
        os.close(fd)


def _obj(value: object, field: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise _fail("cache.error.schema", field=field)
    return value


def _fields(obj: Mapping[str, object], required: set[str], optional: set[str], field: str) -> None:
    missing = required - obj.keys()
    unknown = obj.keys() - required - optional
    if missing or unknown:
        raise _fail("cache.error.schema", field=field)


def _int(value: object, field: str, low: int = 0, high: int = MAX_TIMESTAMP) -> int:
    if type(value) is not int or not low <= value <= high:
        raise _fail("cache.error.schema", field=field)
    return value


def _choice(value: object, choices: tuple[str, ...], field: str) -> str:
    if type(value) is not str or value not in choices:
        raise _fail("cache.error.schema", field=field)
    return value


def _header(obj: Mapping[str, object]) -> int:
    if obj.get("schema") != SCHEMA or type(obj.get("schema")) is not int:
        raise _fail("cache.error.schema_version")
    return _int(obj.get("generated"), "generated")


def _message(raw: object, field: str) -> MessageRef:
    obj = _obj(raw, field)
    _fields(obj, {"id"}, {"params"}, field)
    msg_id = obj["id"]
    if type(msg_id) is not str or not i18n.is_known(msg_id):
        raise _fail("cache.error.schema", field=field)
    params: list[tuple[str, Scalar]] = []
    for name, value in _obj(obj.get("params", {}), field).items():
        if not i18n.PARAM_NAME.match(name):
            raise _fail("cache.error.schema", field=field)
        if type(value) is str:
            params.append((name, sanitize(value, PARAM_CELLS)))
        elif type(value) is int or type(value) is float:
            params.append((name, value))
        else:
            raise _fail("cache.error.schema", field=field)
    return MessageRef(msg_id, tuple(sorted(params)))


def _module(raw: object, name: str, tier: str) -> ModuleResult:
    field = f"modules.{name}"
    obj = _obj(raw, field)
    admin_fields = {"state", "duration_ms", "error"} if tier == ADMIN else set()
    _fields(obj, {"collected", "interval", "max_age", "items"}, admin_fields, field)
    items_raw = obj["items"]
    if not isinstance(items_raw, list) or len(items_raw) > MAX_ITEMS_PER_MODULE:
        raise _fail("cache.error.schema", field=f"{field}.items")
    items = tuple(
        parse_item(raw_item, f"{field}.items.{i}", Form.CACHE)
        for i, raw_item in enumerate(items_raw)
    )
    origin = name if PLUGIN_NAME.match(name) else None
    if any(item.origin != origin for item in items):
        raise _fail("cache.error.schema", field=f"{field}.items")
    if tier == PUBLIC:
        for item in items:
            hidden = item.visibility is not Visibility.PUBLIC or any(
                d.visibility is not Visibility.PUBLIC for d in item.detail
            )
            if hidden:
                raise _fail("cache.error.admin_in_public", field=field)
    state = None
    if "state" in obj:
        state = ModuleState(_choice(obj["state"], ("ok", "failed"), f"{field}.state"))
    duration = None
    if "duration_ms" in obj:
        duration = _int(obj["duration_ms"], f"{field}.duration_ms", high=MAX_DURATION_MS)
    error = _message(obj["error"], f"{field}.error") if "error" in obj else None
    return ModuleResult(
        collected=_int(obj["collected"], f"{field}.collected"),
        interval=_int(obj["interval"], f"{field}.interval", low=1, high=MAX_INTERVAL),
        max_age=_int(obj["max_age"], f"{field}.max_age", low=1, high=MAX_AGE),
        items=items,
        state=state,
        duration_ms=duration,
        error=error,
    )


def decode_module(raw: object, name: str, tier: str = ADMIN) -> ModuleResult:
    """One module entry under the reader's rules: schema checked, every string sanitised."""
    if not (MODULE_NAME.match(name) or PLUGIN_NAME.match(name)):
        raise _fail("cache.error.schema", field="modules")
    return _module(raw, name, tier)


def decode_tier_file(data: bytes, tier: str) -> TierCache:
    """Parse and check ``public.json`` or ``admin.json``; ``tier`` is what the caller expects.

    A broken file header rejects the file; a broken module is skipped and counted in
    ``unreadable``, so one bad entry cannot hide every other module.
    """
    obj = _obj(strictjson.loads(data, max_bytes=MAX_TIER_BYTES, max_depth=MAX_DEPTH), "file")
    # ``config_ignored`` (final review) exists in the admin tier only: a public file that
    # carries it is refused, so no admin fact can travel in the public tier.
    optional = {"config_ignored"} if tier == ADMIN else set()
    _fields(obj, {"schema", "tier", "generated", "modules", "failed"}, optional, "file")
    generated = _header(obj)
    if obj["tier"] != tier or tier not in TIERS:
        raise _fail("cache.error.tier")
    modules_raw = _obj(obj["modules"], "modules")
    if len(modules_raw) > MAX_MODULES:
        raise _fail("cache.error.schema", field="modules")
    modules: dict[str, ModuleResult] = {}
    unreadable = 0
    for name, raw in modules_raw.items():
        if not (MODULE_NAME.match(name) or PLUGIN_NAME.match(name)):
            raise _fail("cache.error.schema", field="modules")
        try:
            modules[name] = _module(raw, name, tier)
        except ContractError:
            unreadable += 1  # one bad module must not hide every other module
    failed = _int(obj["failed"], "failed", high=MAX_MODULES)
    ignored = obj.get("config_ignored", 0)
    config_ignored = _int(ignored, "config_ignored", high=MAX_CONFIG_IGNORED)
    return TierCache(
        tier=tier,
        generated=generated,
        modules=modules,
        failed=failed,
        unreadable=unreadable,
        config_ignored=config_ignored,
    )


def _rule(name: str, raw: object) -> Rule:
    field = f"thresholds.{name}"
    obj = _obj(raw, field)
    _fields(obj, {"warn", "crit", "direction"}, set(), field)
    if not RULE_NAME.match(name):
        raise _fail("cache.error.schema", field="thresholds")
    direction = Direction(_choice(obj["direction"], ("higher", "lower"), field))
    return Rule(name=name, warn=obj["warn"], crit=obj["crit"], direction=direction)  # type: ignore[arg-type]


def decode_render_file(data: bytes) -> RenderSettings:
    obj = _obj(strictjson.loads(data, max_bytes=MAX_RENDER_BYTES, max_depth=8), "file")
    required = {"schema", "generated", "layout", "language", "thresholds"}
    required |= {"timer_period", "render_ms", "package_manager", "look"}
    _fields(obj, required, set(), "file")
    generated = _header(obj)
    layout_raw = _obj(obj["layout"], "layout")
    required_layout = {"sections", "header", "header_text", "charset", "color"}
    # "tips" is optional: a render.json written before phase 13 stays readable.
    _fields(layout_raw, required_layout, {"tips"}, "layout")
    show_tips = layout_raw.get("tips", False)
    if type(show_tips) is not bool:
        raise _fail("cache.error.schema", field="layout.tips")
    sections_raw = layout_raw["sections"]
    if not isinstance(sections_raw, list) or len(sections_raw) > len(SECTIONS):
        raise _fail("cache.error.schema", field="layout.sections")
    sections = tuple(_choice(s, SECTIONS, "layout.sections") for s in sections_raw)
    if len(set(sections)) != len(sections):
        raise _fail("cache.error.schema", field="layout.sections")
    header_text = layout_raw["header_text"]
    if type(header_text) is not str or len(header_text) > 256:
        raise _fail("cache.error.schema", field="layout.header_text")
    layout = Layout(
        sections=sections,
        header=_choice(layout_raw["header"], HEADER_MODES, "layout.header"),
        header_text=sanitize(header_text, 64),
        charset=_choice(layout_raw["charset"], CHARSETS, "layout.charset"),
        color=_choice(layout_raw["color"], COLOR_MODES, "layout.color"),
        tips=show_tips,
    )
    language = obj["language"]
    if type(language) is not str or not (language == "auto" or i18n.LANGUAGE_CODE.match(language)):
        raise _fail("cache.error.schema", field="language")
    thresholds_raw = _obj(obj["thresholds"], "thresholds")
    if len(thresholds_raw) > MAX_RULES:
        raise _fail("cache.error.schema", field="thresholds")
    try:
        thresholds = {name: _rule(name, raw) for name, raw in thresholds_raw.items()}
    except ContractError as exc:
        raise _fail("cache.error.schema", field="thresholds") from exc
    return RenderSettings(
        generated=generated,
        layout=layout,
        language=language,
        thresholds=thresholds,
        timer_period=_int(obj["timer_period"], "timer_period", low=1, high=86400),
        render_ms=_int(obj["render_ms"], "render_ms", low=1, high=60000),
        package_manager=_choice(obj["package_manager"], PACKAGE_MANAGERS, "package_manager"),
        look=look.decode_look(obj["look"]),
    )


def decode_user_file(data: bytes, uid: int) -> UserLogins:
    """Parse a per-user file; ``uid`` is the reader's own, which the file must name."""
    obj = _obj(strictjson.loads(data, max_bytes=MAX_USER_BYTES, max_depth=3), "file")
    _fields(obj, {"schema", "uid", "generated", "logins"}, set(), "file")
    generated = _header(obj)
    if _int(obj["uid"], "uid", high=2**32 - 1) != uid:
        raise _fail("cache.error.owner")
    logins_raw = obj["logins"]
    if not isinstance(logins_raw, list) or len(logins_raw) > MAX_LOGINS:
        raise _fail("cache.error.schema", field="logins")
    logins = []
    for i, raw in enumerate(logins_raw):
        entry = _obj(raw, f"logins.{i}")
        _fields(entry, {"started", "source", "tty"}, set(), f"logins.{i}")
        for name in ("source", "tty"):
            value = entry[name]
            if type(value) is not str or len(value) > MAX_LOGIN_FIELD:
                raise _fail("cache.error.schema", field=f"logins.{i}.{name}")
        logins.append(
            Login(
                started=_int(entry["started"], f"logins.{i}.started"),
                source=sanitize(entry["source"], LOGIN_SOURCE_CELLS),  # type: ignore[arg-type]
                tty=sanitize(entry["tty"], LOGIN_TTY_CELLS),  # type: ignore[arg-type]
            )
        )
    logins.sort(key=lambda login: login.started, reverse=True)
    return UserLogins(uid=uid, generated=generated, logins=tuple(logins))


def read_tier_file(path: str, tier: str, owner: Optional[int] = 0) -> TierCache:
    return decode_tier_file(read_bounded(path, MAX_TIER_BYTES, owner), tier)


def read_render_file(path: str, owner: Optional[int] = 0) -> RenderSettings:
    return decode_render_file(read_bounded(path, MAX_RENDER_BYTES, owner))


def read_user_file(path: str, uid: int, owner: Optional[int] = 0) -> UserLogins:
    """Read the reader's own per-user file (D32 as amended).

    The file belongs to root (``owner``) and no group or other user can write it; the
    reader can open it only through the ACL entry the collector gave that one user. The
    file must name the reader's uid, so a file under the wrong name is refused.
    """
    return decode_user_file(read_bounded(path, MAX_USER_BYTES, owner), uid)


def previous_login(user: UserLogins, now: int, login: bool) -> Optional[Login]:
    """The login to show (4.4): with ``--login``, the newest one that started more than
    ten seconds ago (the current session is the newest); without it, none."""
    if not login or not 0 <= now - user.generated <= USER_FILE_MAX_AGE:
        return None
    for entry in user.logins:
        if entry.started < now - LOGIN_GRACE_SECONDS:
            return entry
    return None

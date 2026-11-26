"""Data model shared by probes, the collector, the cache and the renderer (blueprint 4.3, 4.4).

A probe's document is validated into these types (``core.probe``); the cache stores them
(``core.cache``); the renderer reads them back. Every string held here has already passed
the sanitiser, except message ids and hint ids, which are checked against fixed patterns
and tables instead.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Union

# A parameter value of a catalogue message after validation: never a container or a bool.
Scalar = Union[int, float, str]
# The raw value of an item; ``None`` means the probe could not determine it.
Value = Union[bool, int, float, str, None]


class ContractError(ValueError):
    """Input broke a data contract. ``message`` says why, as a catalogue message (invariant 5).

    Raised for rejected probe documents, cache files and rule definitions. The collector
    logs the message and marks the module failed; the renderer ignores the file.
    """

    def __init__(self, message: "MessageRef") -> None:
        super().__init__(message.id)
        self.message = message


class Status(str, Enum):
    """Classification of a value. Order of severity: ok < unknown < warn < crit."""

    OK = "ok"
    WARN = "warn"
    CRIT = "crit"
    UNKNOWN = "unknown"

    @property
    def severity(self) -> int:
        return _SEVERITY[self]


_SEVERITY = {Status.OK: 0, Status.UNKNOWN: 1, Status.WARN: 2, Status.CRIT: 3}
# The word for each status, as a message id.
STATUS_MESSAGE = {
    Status.OK: "status.ok",
    Status.WARN: "status.warn",
    Status.CRIT: "status.crit",
    Status.UNKNOWN: "status.unknown",
}


class Visibility(str, Enum):
    """Audience of an item (D12): everyone, or root and the admin group only."""

    PUBLIC = "public"
    ADMIN = "admin"


class Unit(str, Enum):
    """Unit of an item's raw value (4.4). The renderer formats by unit."""

    COUNT = "count"
    BYTES = "bytes"
    PERCENT = "percent"
    RATIO = "ratio"
    SECONDS = "seconds"
    TIMESTAMP = "timestamp"
    CELSIUS = "celsius"
    TEXT = "text"
    BOOL = "bool"


class ModuleState(str, Enum):
    """Outcome of a module's last run, as recorded by the collector."""

    OK = "ok"
    FAILED = "failed"


@dataclass(frozen=True)
class MessageRef:
    """A catalogue message by symbolic id, with scalar parameters.

    Only built-in code and built-in probes may produce these. ``params`` is a tuple of
    ``(name, value)`` pairs sorted by name, so the object is hashable and its JSON form is
    stable. A parameter named ``count`` selects the plural form.
    """

    id: str
    params: tuple[tuple[str, Scalar], ...] = ()

    def param_dict(self) -> dict[str, Scalar]:
        return dict(self.params)


def ref(msg_id: str, **params: Scalar) -> MessageRef:
    """Build a ``MessageRef`` with its parameters in canonical order."""
    return MessageRef(msg_id, tuple(sorted(params.items())))


def contract_error(msg_id: str, **params: Scalar) -> ContractError:
    """A ``ContractError`` whose string parameters are sanitised and bounded.

    Rejection reasons often quote the input (a field name, a key), and they end up in the
    collector's log and in ``admin.json``; hostile text must not ride along.
    """
    return contract_error_of(msg_id, params)


def contract_error_of(msg_id: str, params: Mapping[str, Scalar]) -> ContractError:
    """``contract_error`` with the parameters as a mapping (for callers that pass them on)."""
    from motp.core.sanitize import PARAM_CELLS, sanitize

    clean = {k: sanitize(v, PARAM_CELLS) if type(v) is str else v for k, v in params.items()}
    return ContractError(MessageRef(msg_id, tuple(sorted(clean.items()))))


@dataclass(frozen=True)
class LiteralText:
    """Text that is shown as it is, never used as a template (plugins, config rows).

    ``i18n`` holds translations as ``(language, text)`` pairs sorted by language.
    """

    text: str
    i18n: tuple[tuple[str, str], ...] = ()

    def for_language(self, language: str) -> str:
        for lang, text in self.i18n:
            if lang == language:
                return text
        return self.text


@dataclass(frozen=True)
class HintRef:
    """A hint by id; the renderer takes text and command from ``core.hints`` (D34)."""

    id: str


Label = Union[MessageRef, LiteralText]
Text = Union[MessageRef, LiteralText]
# Built-in probes name a hint by id; plugins may give a plain sentence, shown as text only.
Hint = Union[HintRef, LiteralText]


@dataclass(frozen=True)
class Detail:
    """An extra row under an item, usually admin-only (4.4)."""

    key: str
    value: Value
    unit: Unit = Unit.TEXT
    label: Optional[Label] = None
    visibility: Visibility = Visibility.ADMIN


@dataclass(frozen=True)
class Item:
    """One row of module output.

    ``status`` is either set by a probe that has no rule, or, in the cache, the result of
    classifying ``value`` with ``rule``. ``origin`` is the plugin name for plugin items
    (the renderer then adds the fixed ``[plugin <name>]`` prefix) and ``None`` otherwise.
    """

    key: str
    value: Value = None
    unit: Unit = Unit.TEXT
    label: Optional[Label] = None
    rule: Optional[str] = None
    status: Optional[Status] = None
    text: Optional[Text] = None
    bar: Optional[float] = None
    visibility: Visibility = Visibility.PUBLIC
    hint: Optional[Hint] = None
    detail: tuple[Detail, ...] = ()
    origin: Optional[str] = None


@dataclass(frozen=True)
class ProbeDocument:
    """A validated probe document (protocol version 1).

    ``users`` is the per-user data of a module that may send it (``os_login``, D32): the
    set of accounts whose ``user/<uid>.json`` the collector writes. ``None`` for every
    other module, and for a document that carries no such field.
    """

    module: str
    items: tuple[Item, ...]
    api: int = 1
    users: Optional[tuple["UserLogins", ...]] = None


@dataclass(frozen=True)
class ModuleResult:
    """What the collector knows about one module after a run; one entry of a cache file.

    ``interval`` and ``max_age`` travel with the items so the renderer can mark them stale
    (older than three intervals) or expired (older than ``max_age``) without the config.
    ``state``, ``duration_ms`` and ``error`` are admin-tier information (5.4) and are
    ``None`` in the public cache.
    """

    collected: int
    interval: int
    max_age: int
    items: tuple[Item, ...] = ()
    state: Optional[ModuleState] = None
    duration_ms: Optional[int] = None
    error: Optional[MessageRef] = None


@dataclass(frozen=True)
class Login:
    """One login record of a per-user file (D32). ``source`` and ``tty`` are sanitised."""

    started: int
    source: str = ""
    tty: str = ""


@dataclass(frozen=True)
class UserLogins:
    """Content of ``user/<uid>.json``: one account's most recent logins, newest first."""

    uid: int
    generated: int
    logins: tuple[Login, ...]


@dataclass(frozen=True)
class Freshness:
    """Age assessment of a module's items at render time (4.4, scheduling and ageing)."""

    age: int
    stale: bool
    expired: bool


def freshness(result: ModuleResult, now: int) -> Freshness:
    """Stale when older than three intervals, expired when older than ``max_age``."""
    age = max(0, now - result.collected)
    return Freshness(age=age, stale=age > 3 * result.interval, expired=age > result.max_age)


def worst(statuses: "list[Optional[Status]]") -> Optional[Status]:
    """The most severe status of a list, ignoring ``None`` (an item without a status)."""
    present = [s for s in statuses if s is not None]
    return max(present, key=lambda s: s.severity) if present else None


__all__ = [
    "STATUS_MESSAGE",
    "ContractError",
    "Detail",
    "Freshness",
    "Hint",
    "HintRef",
    "Item",
    "Label",
    "LiteralText",
    "Login",
    "MessageRef",
    "ModuleResult",
    "ModuleState",
    "ProbeDocument",
    "Scalar",
    "Status",
    "Text",
    "Unit",
    "Value",
    "Visibility",
    "freshness",
    "ref",
    "worst",
]

"""Message catalogue, ``{name}`` substitution and plural selection (blueprint 4.4, 4.6, D19).

Every user-visible string has a symbolic message id (invariant 5). Catalogues are written
as ``locale/<language>.po`` and compiled to ``locale/<language>.mo`` by
``tools/compile_catalogs.py``; at run time the ``.mo`` file is read as bytes through the
package loader, so the same code works from the unpacked tree and from the archive.

Security rules (T22):

* Only catalogue strings are templates. Collected text (plugin labels, values) is never
  passed to ``substitute`` as a template.
* ``substitute`` replaces ``{name}`` and nothing else: no attribute access, no indexing, no
  conversion, no format specification. Anything else stays literal. It runs in one pass, so
  a substituted value is never scanned again.
* Parameters are reduced to text by ``param_text``: integers and floats are written out,
  strings are sanitised, anything else becomes ``?``. No ``__str__`` or ``__format__`` of a
  foreign object is ever called.
* Plural rules are a fixed table per language. The ``Plural-Forms`` header of a catalogue is
  not evaluated.
"""

import functools
import math
import re
import struct
from collections.abc import Mapping
from typing import Callable, Optional, Union

from motp.core import resources
from motp.core.model import LiteralText, MessageRef, Scalar
from motp.core.sanitize import PARAM_CELLS, sanitize

DEFAULT_LANGUAGE = "en"
LANGUAGE_CODE = re.compile(r"[a-z]{2,3}\Z")
MESSAGE_ID = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z0-9_]+){1,5}\Z")
PARAM_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,31}\Z")
MAX_CATALOG_BYTES = 1 << 20
MO_MAGIC = 0x950412DE


def _one_or_other(n: int) -> int:
    return 0 if n == 1 else 1


# Fixed plural rules: language -> (number of forms, form index for a count).
PLURAL_RULES: dict[str, tuple[int, Callable[[int], int]]] = {
    "en": (2, _one_or_other),
    "de": (2, _one_or_other),
}


class CatalogError(ValueError):
    """A compiled catalogue is malformed. Only raised for files in the package itself."""


def parse_mo(data: bytes) -> dict[str, tuple[str, ...]]:
    """Read a GNU ``.mo`` file into ``message id -> plural forms``.

    Every offset is checked against the buffer. The header entry (empty id) is skipped.
    """
    if len(data) < 28 or len(data) > MAX_CATALOG_BYTES:
        raise CatalogError("size")
    for order in ("<", ">"):
        magic, revision, count, ids_at, strs_at = struct.unpack_from(order + "5I", data, 0)
        if magic == MO_MAGIC:
            break
    else:
        raise CatalogError("magic")
    if revision >> 16 != 0:
        raise CatalogError("revision")

    def entry(table: int, index: int) -> bytes:
        pos = table + 8 * index
        if pos + 8 > len(data):
            raise CatalogError("table")
        length, offset = struct.unpack_from(order + "2I", data, pos)
        if offset + length > len(data):
            raise CatalogError("string")
        return data[offset : offset + length]

    messages: dict[str, tuple[str, ...]] = {}
    for i in range(count):
        try:
            key = entry(ids_at, i).decode("utf-8")
            value = entry(strs_at, i).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CatalogError("encoding") from exc
        if not key:
            continue
        msg_id = key.split("\x00", 1)[0]
        messages[msg_id] = tuple(value.split("\x00"))
    return messages


class Catalog:
    """The messages of one language."""

    def __init__(self, language: str, messages: Mapping[str, tuple[str, ...]]) -> None:
        self.language = language
        self._messages = dict(messages)
        self._plural = PLURAL_RULES.get(language, PLURAL_RULES[DEFAULT_LANGUAGE])[1]

    def has(self, msg_id: str) -> bool:
        return msg_id in self._messages

    def ids(self) -> frozenset[str]:
        return frozenset(self._messages)

    def template(self, msg_id: str, count: Optional[int]) -> Optional[str]:
        forms = self._messages.get(msg_id)
        if not forms:
            return None
        index = 0 if count is None else self._plural(count)
        return forms[min(max(index, 0), len(forms) - 1)]


@functools.cache
def load(language: str) -> Optional[Catalog]:
    """Load ``locale/<language>.mo`` from the package; ``None`` if absent or unusable."""
    if not LANGUAGE_CODE.match(language):
        return None
    try:
        data = resources.read(f"locale/{language}.mo")
    except OSError:
        return None
    if data is None:
        return None
    try:
        return Catalog(language, parse_mo(data))
    except (CatalogError, struct.error):
        return None


def english() -> Catalog:
    """The reference catalogue; empty if the package was built without catalogues."""
    return load(DEFAULT_LANGUAGE) or Catalog(DEFAULT_LANGUAGE, {})


def is_known(msg_id: str) -> bool:
    """True if ``msg_id`` is well formed and present in the English catalogue."""
    return bool(MESSAGE_ID.match(msg_id)) and english().has(msg_id)


def _code(locale_name: str) -> str:
    return locale_name.split(".", 1)[0].split("@", 1)[0].split("_", 1)[0].lower()


def language_from_env(env: Mapping[str, str]) -> str:
    """Pick the output language from the reader's locale (4.6), English as fallback.

    The locale is the first non-empty of ``LC_ALL``, ``LC_MESSAGES`` and ``LANG``. With
    ``C``, ``POSIX`` or no locale the answer is English. Otherwise ``LANGUAGE`` (a colon
    list) is tried first, then the locale itself. Only codes with a catalogue count; the
    code is checked against a strict pattern before it becomes part of a resource name.
    """
    names = ("LC_ALL", "LC_MESSAGES", "LANG")
    locale_name = next((env[k] for k in names if env.get(k)), "")
    if _code(locale_name) in ("", "c", "posix"):
        return DEFAULT_LANGUAGE
    candidates = [*env.get("LANGUAGE", "").split(":"), locale_name]
    for candidate in candidates:
        code = _code(candidate)
        if LANGUAGE_CODE.match(code) and load(code) is not None:
            return code
    return DEFAULT_LANGUAGE


def param_text(value: object) -> str:
    """Reduce a parameter to text without calling any method of a foreign object."""
    if type(value) is int:
        return str(value) if -(10**18) <= value <= 10**18 else "?"
    if type(value) is float:
        return repr(value) if math.isfinite(value) else "?"
    if type(value) is str:
        return sanitize(value, PARAM_CELLS)
    return "?"


def substitute(template: str, values: Mapping[str, str]) -> str:
    """Replace ``{name}`` with ``values[name]``; ``{{`` and ``}}`` give single braces.

    A placeholder that is not a plain identifier, or names no value, stays as written.
    """
    out: list[str] = []
    i = 0
    n = len(template)
    while i < n:
        ch = template[i]
        if ch in "{}" and template.startswith(ch * 2, i):
            out.append(ch)
            i += 2
            continue
        if ch == "{":
            end = template.find("}", i + 1)
            name = template[i + 1 : end] if end != -1 else ""
            if PARAM_NAME.match(name) and name in values:
                out.append(values[name])
                i = end + 1
                continue
        out.append(ch)
        i += 1
    return "".join(out)


class Translator:
    """Renders message ids and literal texts in one language, falling back to English."""

    def __init__(self, language: str) -> None:
        catalog = load(language)
        self.language = catalog.language if catalog is not None else DEFAULT_LANGUAGE
        self._catalogs = [c for c in (catalog, english()) if c is not None]

    def message(self, msg_id: str, params: Optional[Mapping[str, Scalar]] = None) -> str:
        """The text of ``msg_id``. An unknown id is shown as the id itself."""
        params = params or {}
        count = params.get("count")
        number = count if type(count) is int else None
        if type(count) is float and count.is_integer() and abs(count) <= 1e18:
            number = int(count)  # 2.0 updates is plural too
        for catalog in self._catalogs:
            template = catalog.template(msg_id, number)
            if template is not None:
                return substitute(template, {k: param_text(v) for k, v in params.items()})
        return msg_id if MESSAGE_ID.match(msg_id) else "?"

    def compose(self, msg_id: str, texts: Mapping[str, str]) -> str:
        """Fill ``msg_id`` with finished texts instead of parameters.

        For lines built from other messages and from data the caller has already
        sanitised (a file path, say), which would not fit the parameter limit. The values
        are inserted as they are; never pass unsanitised input.
        """
        for catalog in self._catalogs:
            template = catalog.template(msg_id, None)
            if template is not None:
                return substitute(template, texts)
        return msg_id if MESSAGE_ID.match(msg_id) else "?"

    def text(self, value: Union[MessageRef, LiteralText]) -> str:
        """Render a message reference, or pick the translation of a literal text."""
        if isinstance(value, MessageRef):
            return self.message(value.id, value.param_dict())
        return value.for_language(self.language)


@functools.cache
def translator(language: str) -> Translator:
    return Translator(language)

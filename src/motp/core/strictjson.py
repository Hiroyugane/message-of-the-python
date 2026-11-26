"""Bounded, strict JSON decoding for probe output and cache files (blueprint 4.4, T8).

Only the standard ``json`` module is used, with these limits on top:

* the input is at most ``max_bytes`` bytes and is decoded as UTF-8 with replacement;
* nesting deeper than ``max_depth`` is refused before ``json`` sees the text, so a deep
  document cannot exhaust the parser's recursion;
* ``NaN``, ``Infinity`` and numbers that overflow to infinity are refused;
* integers longer than 19 digits are refused (no slow big-integer conversion);
* an object with a repeated key is refused, so two readers cannot disagree on its value.
"""

import json
import math
from typing import NoReturn

from motp.core.model import ContractError, contract_error, ref

MAX_INT_DIGITS = 19


def _depth_ok(text: str, max_depth: int) -> bool:
    depth = 0
    in_string = False
    escaped = False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            if depth > max_depth:
                return False
        elif ch in "]}":
            depth -= 1
    return True


def _reject_constant(name: str) -> NoReturn:
    raise ContractError(ref("json.error.not_finite"))


def _parse_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise ContractError(ref("json.error.not_finite"))
    return value


def _parse_int(text: str) -> int:
    if len(text.lstrip("-")) > MAX_INT_DIGITS:
        raise ContractError(ref("json.error.number_too_long"))
    return int(text)


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise contract_error("json.error.duplicate_key", field=key)
        result[key] = value
    return result


def loads(data: bytes, *, max_bytes: int, max_depth: int) -> object:
    """Decode ``data`` under the limits above; raise ``ContractError`` on any violation."""
    if len(data) > max_bytes:
        raise ContractError(ref("json.error.too_large", limit=max_bytes))
    text = data.decode("utf-8", "replace")
    if not text.strip():
        raise ContractError(ref("json.error.empty"))
    if not _depth_ok(text, max_depth):
        raise ContractError(ref("json.error.too_deep", limit=max_depth))
    try:
        return json.loads(
            text,
            parse_constant=_reject_constant,
            parse_float=_parse_float,
            parse_int=_parse_int,
            object_pairs_hook=_unique_pairs,
        )
    except ContractError:
        raise
    except (ValueError, RecursionError) as exc:
        raise ContractError(ref("json.error.syntax")) from exc


def dumps(obj: object) -> bytes:
    """Canonical encoding for cache files: sorted keys, no spaces, UTF-8, no NaN."""
    text = json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    )
    return text.encode("utf-8") + b"\n"

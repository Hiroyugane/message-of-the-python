"""Strict, bounded JSON decoding (blueprint 4.4, T8)."""

import pytest

from motp.core.model import ContractError
from motp.core.strictjson import dumps, loads


def _reason(data: bytes, max_bytes: int = 65536, max_depth: int = 8) -> str:
    with pytest.raises(ContractError) as info:
        loads(data, max_bytes=max_bytes, max_depth=max_depth)
    return info.value.message.id


def test_accepts_plain_json() -> None:
    assert loads(b'{"a": [1, 2.5, "x", null, true]}', max_bytes=100, max_depth=3) == {
        "a": [1, 2.5, "x", None, True]
    }


@pytest.mark.parametrize(
    "data", [b"NaN", b"[NaN]", b'{"v": Infinity}', b"[-Infinity]", b"[1e400]", b"[-1e999]"]
)
def test_nan_and_infinity_are_refused(data: bytes) -> None:
    assert _reason(data) == "json.error.not_finite"


def test_size_cap() -> None:
    assert _reason(b"[" + b"1," * 600_000 + b"1]", max_bytes=1 << 20) == "json.error.too_large"
    assert _reason(b'"' + b"x" * 100 + b'"', max_bytes=50) == "json.error.too_large"


@pytest.mark.parametrize("opener", [b"[", b'{"a":'])
def test_deep_nesting_is_refused_before_parsing(opener: bytes) -> None:
    closer = b"]" if opener == b"[" else b"}"
    deep = opener * 50_000 + b"1" + closer * 50_000
    assert _reason(deep, max_bytes=1 << 20) == "json.error.too_deep"
    assert loads(opener * 3 + b"1" + closer * 3, max_bytes=100, max_depth=3) is not None
    assert _reason(opener * 4 + b"1" + closer * 4, max_depth=3) == "json.error.too_deep"


def test_brackets_inside_strings_do_not_count_as_depth() -> None:
    assert loads(b'["[[[[[[[[\\"]]]]"]', max_bytes=100, max_depth=1) == ['[[[[[[[["]]]]']


def test_long_integers_are_refused() -> None:
    assert _reason(b"[" + b"9" * 5000 + b"]") == "json.error.number_too_long"
    assert loads(b"[-9223372036854775807]", max_bytes=100, max_depth=1) == [-(2**63) + 1]


def test_duplicate_keys_are_refused() -> None:
    assert _reason(b'{"a": 1, "a": 2}') == "json.error.duplicate_key"


@pytest.mark.parametrize("data", [b"", b"   ", b"{", b"[1,]", b"\xef\xbb\xbf{}", b"{'a': 1}"])
def test_syntax_errors(data: bytes) -> None:
    assert _reason(data) in {"json.error.syntax", "json.error.empty"}


def test_invalid_utf8_is_replaced_not_fatal() -> None:
    assert loads(b'["a\xffb"]', max_bytes=100, max_depth=2) == ["a\ufffdb"]


def test_dumps_is_canonical_and_refuses_nan() -> None:
    assert dumps({"b": 1, "a": "\xe9"}) == '{"a":"\xe9","b":1}\n'.encode()
    with pytest.raises(ValueError):
        dumps({"a": float("nan")})

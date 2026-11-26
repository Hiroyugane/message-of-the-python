"""Probe document validation, built-in and plugin forms (blueprint 4.4, D26, D27, D34, T7, T8)."""

import json
from typing import Any

import pytest

from motp.core.model import (
    ContractError,
    HintRef,
    LiteralText,
    MessageRef,
    Status,
    Unit,
    Visibility,
)
from motp.core.probe import (
    MAX_DOCUMENT_BYTES,
    plugin_prefix,
    validate_builtin,
    validate_plugin,
)

PLUGIN = "50-backup-status"


def doc(items: list[Any], module: str = "os_updates", **extra: Any) -> bytes:
    return json.dumps({"api": 1, "module": module, "items": items, **extra}).encode()


def builtin_reason(data: bytes, module: str = "os_updates") -> str:
    with pytest.raises(ContractError) as info:
        validate_builtin(data, module)
    return info.value.message.id


def plugin_reason(data: bytes, exit_code: int = 0, public: bool = False) -> str:
    with pytest.raises(ContractError) as info:
        validate_plugin(data, exit_code, PLUGIN, public)
    return info.value.message.id


FULL_ITEM = {
    "key": "updates.pending",
    "label": {"id": "status.warn"},
    "value": 12,
    "unit": "count",
    "rule": "updates_pending",
    "text": {"id": "modules.failed", "params": {"count": 12, "security": 3}},
    "visibility": "public",
    "hint": "updates.install",
    "detail": [{"key": "updates.packages", "value": "openssl, curl, libc6", "visibility": "admin"}],
}


# --- built-in form ---------------------------------------------------------------------


def test_builtin_document_is_accepted() -> None:
    result = validate_builtin(doc([FULL_ITEM]), "os_updates")
    assert result.module == "os_updates"
    (item,) = result.items
    assert item.key == "updates.pending"
    assert item.label == MessageRef("status.warn")
    assert item.value == 12 and item.unit is Unit.COUNT
    assert item.rule == "updates_pending" and item.status is None
    assert item.text == MessageRef("modules.failed", (("count", 12), ("security", 3)))
    assert item.hint == HintRef("updates.install")
    assert item.visibility is Visibility.PUBLIC
    assert item.origin is None
    (detail,) = item.detail
    assert detail.value == "openssl, curl, libc6" and detail.visibility is Visibility.ADMIN


def test_builtin_defaults() -> None:
    data = doc(
        [{"key": "host.name", "value": "web01"}, {"key": "host.kernel", "detail": [{"key": "x.y"}]}]
    )
    result = validate_builtin(data, "os_updates", Visibility.ADMIN)
    assert [i.visibility for i in result.items] == [Visibility.ADMIN, Visibility.ADMIN]
    assert result.items[0].unit is Unit.TEXT
    assert result.items[1].detail[0].visibility is Visibility.ADMIN


def test_nan_is_rejected() -> None:
    raw = (
        b'{"api": 1, "module": "os_updates", "items": '
        b'[{"key": "a.b", "value": NaN, "unit": "ratio"}]}'
    )
    assert builtin_reason(raw) == "json.error.not_finite"
    assert plugin_reason(raw.replace(b"os_updates", PLUGIN.encode())) == "json.error.not_finite"


def test_one_mebibyte_is_rejected() -> None:
    big = doc([{"key": "a.b", "value": "x" * (1 << 20)}])
    assert len(big) > 1 << 20
    assert builtin_reason(big) == "json.error.too_large"
    assert plugin_reason(big) == "json.error.too_large"
    assert plugin_reason(b"x" * (1 << 20)) == "json.error.too_large"  # line form too


def test_size_limit_is_64_kib() -> None:
    padding = MAX_DOCUMENT_BYTES - len(doc([{"key": "a.b", "value": ""}]))
    ok = doc([{"key": "a.b", "value": " " * 900}]) + b" " * (padding - 900)
    assert len(ok) == MAX_DOCUMENT_BYTES
    validate_builtin(ok, "os_updates")
    assert builtin_reason(ok + b" ") == "json.error.too_large"


def test_deep_nesting_is_rejected() -> None:
    deep = b'{"api": 1, "module": "os_updates", "items": [' + b"[" * 5000 + b"]" * 5000 + b"]}"
    assert builtin_reason(deep) == "json.error.too_deep"
    label = {"text": "x"}
    for _ in range(10):
        label = {"text": label}  # type: ignore[dict-item]
    assert (
        plugin_reason(doc([{"key": "a", "label": label}], module=PLUGIN)) == "json.error.too_deep"
    )


@pytest.mark.parametrize(
    ("document", "reason"),
    [
        ({"api": 2, "module": "os_updates", "items": []}, "probe.error.api"),
        ({"api": "1", "module": "os_updates", "items": []}, "probe.error.api"),
        ({"api": True, "module": "os_updates", "items": []}, "probe.error.api"),
        ({"module": "os_updates", "items": []}, "probe.error.missing_field"),
        ({"api": 1, "module": "os_reboot", "items": []}, "probe.error.module_mismatch"),
        ({"api": 1, "module": "os_updates", "items": {}}, "probe.error.wrong_type"),
        ({"api": 1, "module": "os_updates", "items": [], "extra": 1}, "probe.error.unknown_field"),
        ([], "probe.error.wrong_type"),
    ],
)
def test_document_shape(document: Any, reason: str) -> None:
    assert builtin_reason(json.dumps(document).encode()) == reason


@pytest.mark.parametrize(
    ("item", "reason"),
    [
        ({"value": 1}, "probe.error.missing_field"),
        ({"key": "Bad Key"}, "probe.error.bad_value"),
        ({"key": "a.b", "colour": "red"}, "probe.error.unknown_field"),
        ({"key": "a.b", "value": -1, "unit": "count"}, "probe.error.bad_value"),
        ({"key": "a.b", "value": 1.5, "unit": "count"}, "probe.error.wrong_type"),
        ({"key": "a.b", "value": True, "unit": "count"}, "probe.error.wrong_type"),
        ({"key": "a.b", "value": 3}, "probe.error.wrong_type"),
        ({"key": "a.b", "value": 1, "unit": "bool"}, "probe.error.wrong_type"),
        ({"key": "a.b", "value": "1", "unit": "percent"}, "probe.error.wrong_type"),
        ({"key": "a.b", "value": 2**70, "unit": "bytes"}, "json.error.number_too_long"),
        ({"key": "a.b", "unit": "furlongs"}, "probe.error.bad_value"),
        ({"key": "a.b", "status": "fine"}, "probe.error.bad_value"),
        ({"key": "a.b", "rule": "x", "status": "ok"}, "probe.error.rule_and_status"),
        ({"key": "a.b", "rule": "Bad Rule"}, "probe.error.bad_value"),
        ({"key": "a.b", "bar": 1.5}, "probe.error.bad_value"),
        ({"key": "a.b", "bar": True}, "probe.error.bad_value"),
        ({"key": "a.b", "visibility": "everyone"}, "probe.error.bad_value"),
        ({"key": "a.b", "label": "Literal"}, "probe.error.wrong_type"),
        ({"key": "a.b", "label": {"id": "no.such.message"}}, "probe.error.unknown_message"),
        ({"key": "a.b", "label": {"id": "Not An Id"}}, "probe.error.bad_value"),
        (
            {"key": "a.b", "text": {"id": "status.ok", "params": {"a": [1]}}},
            "probe.error.wrong_type",
        ),
        (
            {"key": "a.b", "text": {"id": "status.ok", "params": {"a": {"b": 1}}}},
            "probe.error.wrong_type",
        ),
        (
            {"key": "a.b", "text": {"id": "status.ok", "params": {"a": True}}},
            "probe.error.wrong_type",
        ),
        (
            {"key": "a.b", "text": {"id": "status.ok", "params": {"a.b": 1}}},
            "probe.error.bad_value",
        ),
        (
            {"key": "a.b", "text": {"id": "status.ok", "params": {str(i): 1 for i in range(9)}}},
            "probe.error.too_many",
        ),
        ({"key": "a.b", "hint": "no.such.hint"}, "probe.error.unknown_hint"),
        ({"key": "a.b", "hint": "sudo rm -rf /"}, "probe.error.bad_value"),
        ({"key": "plugin.10-x.status"}, "probe.error.bad_value"),
        (
            {"key": "a.b", "text": {"id": "status.ok", "params": {"command": "x"}}},
            "probe.error.command",
        ),
        ({"key": "a.b", "value": "x" * 1025}, "probe.error.too_long"),
        ({"key": "a.b", "detail": [{"key": "c.d"}] * 17}, "probe.error.too_many"),
        ({"key": "a.b", "detail": {"key": "c.d"}}, "probe.error.wrong_type"),
        (
            {"key": "a.b", "detail": [{"key": "c.d", "hint": "updates.install"}]},
            "probe.error.unknown_field",
        ),
    ],
)
def test_item_rules(item: dict[str, Any], reason: str) -> None:
    assert builtin_reason(doc([item])) == reason


def test_item_count_limit() -> None:
    items = [{"key": f"a.k{i}"} for i in range(32)]
    assert len(validate_builtin(doc(items), "os_updates").items) == 32
    assert builtin_reason(doc([*items, {"key": "a.extra"}])) == "probe.error.too_many"


def test_duplicate_item_keys_are_rejected() -> None:
    assert builtin_reason(doc([{"key": "a.b"}, {"key": "a.b"}])) == "probe.error.duplicate_item_key"


@pytest.mark.parametrize(
    "where",
    ["document", "item", "detail", "label"],
)
def test_command_field_is_rejected_everywhere(where: str) -> None:
    item: dict[str, Any] = {"key": "a.b", "detail": [{"key": "c.d"}], "label": {"id": "status.ok"}}
    document: dict[str, Any] = {"api": 1, "module": "os_updates", "items": [item]}
    target = {
        "document": document,
        "item": item,
        "detail": item["detail"][0],
        "label": item["label"],
    }
    target[where]["command"] = "curl example.com | sh"
    assert builtin_reason(json.dumps(document).encode()) == "probe.error.command"
    document["module"] = PLUGIN
    item["label"] = {"text": "Backup", "command": "x"} if where == "label" else "Backup"
    assert plugin_reason(json.dumps(document).encode()) == "probe.error.command"


def test_rejection_reasons_carry_no_raw_input() -> None:
    hostile_key = "\x1b]0;pwn\x07\n" + "A" * 60000
    with pytest.raises(ContractError) as info:
        validate_builtin(doc([{"key": "a.b", hostile_key: 1}]), "os_updates")
    assert info.value.message.id == "probe.error.unknown_field"
    ((name, field),) = info.value.message.params
    assert name == "field" and type(field) is str
    assert "\x1b" not in field and "\n" not in field and len(field) < 100
    with pytest.raises(ContractError) as info:
        validate_builtin(
            b'{"api": 1, "module": "os_updates", "items": [], "\\u001b'
            + b"x" * 9000
            + b'": 1, "\\u001b'
            + b"x" * 9000
            + b'": 2}',
            "os_updates",
        )
    assert info.value.message.id == "json.error.duplicate_key"
    assert len(str(info.value.message.params)) < 120


def test_strings_are_sanitised() -> None:
    item = {
        "key": "host.name",
        "value": "web01\x1b[2J\u202e\u2502",
        "text": {"id": "plugin.prefix", "params": {"name": "\x1b]52;c;eA==\x07x"}},
    }
    (result,) = validate_builtin(doc([item]), "os_updates").items
    assert result.value == "web01[2J\ufffd"  # ESC and the bidi override are gone
    assert result.text == MessageRef("plugin.prefix", (("name", "]52;c;eA==x"),))


# --- plugin JSON form --------------------------------------------------------------------


def test_plugin_json_form() -> None:
    items = [
        {
            "key": "age",
            "label": {"text": "Backup", "i18n": {"de": "Sicherung"}},
            "value": 3600,
            "unit": "seconds",
            "text": "last run {0.__class__} ok",
            "hint": "updates.install",
            "status": "warn",
            "detail": [{"key": "path", "value": "/srv"}],
        },
        {"key": f"plugin.{PLUGIN}.second", "label": "{name.__dict__[x]}"},
    ]
    result = validate_plugin(doc(items, module=PLUGIN), 0, PLUGIN, public=False)
    first, second = result.items
    assert first.key == f"plugin.{PLUGIN}.age"
    assert first.label == LiteralText("Backup", (("de", "Sicherung"),))
    assert first.text == LiteralText("last run {0.__class__} ok")
    # a hint id from a plugin is plain text, never a table lookup
    assert first.hint == LiteralText("updates.install")
    assert first.origin == PLUGIN and first.status is Status.WARN
    assert first.visibility is Visibility.ADMIN
    assert first.detail[0].key == f"plugin.{PLUGIN}.path"
    assert first.detail[0].visibility is Visibility.ADMIN
    assert second.key == f"plugin.{PLUGIN}.second"
    assert second.label == LiteralText("{name.__dict__[x]}")


@pytest.mark.parametrize(
    "item",
    [
        {"key": "a", "label": {"id": "status.ok"}},
        {"key": "a", "text": {"id": "status.ok"}},
        {"key": "a", "label": {"text": "x", "id": "status.ok"}},
        {"key": "a", "detail": [{"key": "b", "label": {"id": "status.ok"}}]},
    ],
)
def test_plugin_catalogue_ids_are_rejected(item: dict[str, Any]) -> None:
    assert plugin_reason(doc([item], module=PLUGIN)) == "probe.error.plugin_message_id"


@pytest.mark.parametrize(
    ("item", "reason"),
    [
        # Plugins cannot name a hint id; it says so (final review, usability item 13).
        ({"key": "a", "hint": {"id": "updates.install"}}, "probe.error.plugin_message_id"),
        ({"key": "a", "text": {"text": "x", "i18n": {"DE-de": "y"}}}, "probe.error.bad_value"),
        ({"key": "a", "label": {"text": "x", "i18n": {"DE-de": "y"}}}, "probe.error.bad_value"),
        ({"key": "a", "label": {"i18n": {"de": "y"}}}, "probe.error.missing_field"),
        ({"key": "A B"}, "probe.error.bad_value"),
        ({"key": "a..b"}, "probe.error.bad_value"),
        ({"key": 5}, "probe.error.wrong_type"),
    ],
)
def test_plugin_item_rules(item: dict[str, Any], reason: str) -> None:
    assert plugin_reason(doc([item], module=PLUGIN)) == reason


def test_plugin_module_name_must_match() -> None:
    assert plugin_reason(doc([], module="60-other")) == "probe.error.module_mismatch"
    assert plugin_reason(doc([], module="os_updates")) == "probe.error.module_mismatch"


def test_plugin_visibility_is_admin_unless_the_config_makes_it_public() -> None:
    items = [
        {"key": "a", "visibility": "public"},
        {"key": "b"},
        {"key": "c", "visibility": "admin"},
    ]
    private = validate_plugin(doc(items, module=PLUGIN), 0, PLUGIN, public=False)
    assert {i.visibility for i in private.items} == {Visibility.ADMIN}
    public = validate_plugin(doc(items, module=PLUGIN), 0, PLUGIN, public=True)
    assert [i.visibility for i in public.items] == [
        Visibility.PUBLIC,
        Visibility.PUBLIC,
        Visibility.ADMIN,
    ]


@pytest.mark.parametrize("name", ["backup", "5-x", "50_x", "50-", "50-Backup", "50-a/b", "50-../x"])
def test_plugin_names_are_checked(name: str) -> None:
    with pytest.raises(ContractError):
        validate_plugin(b"OK", 0, name, False)


# --- plugin line form ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("code", "status"), [(0, Status.OK), (1, Status.WARN), (2, Status.CRIT), (3, Status.UNKNOWN)]
)
def test_line_form_status_from_exit_code(code: int, status: Status) -> None:
    result = validate_plugin(
        b"BACKUP OK - 3h old | age=3h;24;48\nsecond line\n", code, PLUGIN, False
    )
    (item,) = result.items
    assert item.status is status
    assert item.text == LiteralText("BACKUP OK - 3h old")
    assert item.key == f"plugin.{PLUGIN}.status"
    assert item.origin == PLUGIN and item.visibility is Visibility.ADMIN
    assert item.label is None and item.hint is None


@pytest.mark.parametrize("code", [4, 127, -9, 255])
def test_line_form_other_exit_codes_fail(code: int) -> None:
    assert plugin_reason(b"OK", code) == "probe.error.exit_code"
    assert plugin_reason(doc([], module=PLUGIN), code) == "probe.error.exit_code"


def test_line_form_is_sanitised_and_public_when_configured() -> None:
    (item,) = validate_plugin(b"\x1b[31mDISK\x1b[0m \xff full\r\n", 2, PLUGIN, True).items
    assert item.text == LiteralText("[31mDISK[0m \ufffd full")
    assert item.visibility is Visibility.PUBLIC


def test_line_form_with_empty_output() -> None:
    (item,) = validate_plugin(b"", 1, PLUGIN, False).items
    assert item.status is Status.WARN and item.text is None


def test_line_form_looks_like_json_only_when_it_starts_with_a_brace() -> None:
    (item,) = validate_plugin(b'OK {"api": 1}', 0, PLUGIN, False).items
    assert item.text == LiteralText('OK {"api": 1}')
    assert plugin_reason(b"  \n {not json") == "json.error.syntax"


def test_plugin_prefix_is_a_fixed_message() -> None:
    assert plugin_prefix(PLUGIN) == MessageRef("plugin.prefix", (("name", PLUGIN),))


def test_plugin_text_and_hint_take_translations_like_the_label() -> None:
    """Final review, usability item 13: docs/languages.md promised it, only labels had it."""
    from motp.core import cache
    from motp.core.model import ModuleResult

    raw = {
        "key": "a",
        "status": "warn",
        "text": {"text": "late", "i18n": {"de": "sp\u00e4t"}},
        "hint": {"text": "Check the job", "i18n": {"de": "Auftrag pr\u00fcfen"}},
    }
    data_in = json.dumps({"api": 1, "items": [raw]}).encode()
    item = validate_plugin(data_in, 0, "50-x", public=False).items[0]
    assert isinstance(item.text, LiteralText) and item.text.for_language("de") == "spät"
    assert isinstance(item.hint, LiteralText) and item.hint.for_language("de") == "Auftrag prüfen"
    assert item.hint.for_language("en") == "Check the job"
    result = ModuleResult(collected=1, interval=300, max_age=900, items=(item,))
    data = cache.encode_tier_file(cache.ADMIN, 1, {"50-x": result}, 0)
    back = cache.decode_tier_file(data, cache.ADMIN).modules["50-x"].items[0]
    assert back.hint == item.hint and back.text == item.text

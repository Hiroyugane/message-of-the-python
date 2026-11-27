"""Threshold rules (blueprint 4.5): direction, two inclusive limits, one classifier."""

import math

import pytest

from motp.core.model import ContractError, Item, Status, Unit
from motp.core.thresholds import (
    Direction,
    Rule,
    RuleError,
    classify,
    item_status,
    make_rule,
    rules_to_json,
)

DISK = make_rule("disk_used_percent", 80, 90)
CERT = make_rule("cert_days_left", 21, 7)


def test_direction_follows_from_the_limits() -> None:
    assert DISK.direction is Direction.HIGHER_IS_WORSE
    assert CERT.direction is Direction.LOWER_IS_WORSE


@pytest.mark.parametrize(
    ("value", "expected"),
    [(0, Status.OK), (79.9, Status.OK), (80, Status.WARN), (89, Status.WARN), (90, Status.CRIT),
     (150, Status.CRIT)],
)  # fmt: skip
def test_higher_is_worse(value: float, expected: Status) -> None:
    assert classify(value, DISK) is expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [(100, Status.OK), (22, Status.OK), (21, Status.WARN), (8, Status.WARN), (7, Status.CRIT),
     (-3, Status.CRIT)],
)  # fmt: skip
def test_lower_is_worse(value: float, expected: Status) -> None:
    assert classify(value, CERT) is expected


@pytest.mark.parametrize("value", [None, "90", True, False, math.nan, math.inf, -math.inf, [1]])
def test_non_numbers_are_unknown(value: object) -> None:
    assert classify(value, DISK) is Status.UNKNOWN  # type: ignore[arg-type]


def test_equal_limits_need_a_direction() -> None:
    with pytest.raises(RuleError):
        make_rule("x", 5, 5)
    rule = make_rule("x", 5, 5, Direction.HIGHER_IS_WORSE)
    assert classify(5, rule) is Status.CRIT
    assert classify(4, rule) is Status.OK


@pytest.mark.parametrize(
    "kwargs",
    [
        {"name": "Bad-Name", "warn": 1, "crit": 2, "direction": Direction.HIGHER_IS_WORSE},
        {"name": "x", "warn": math.nan, "crit": 2, "direction": Direction.HIGHER_IS_WORSE},
        {"name": "x", "warn": True, "crit": 2, "direction": Direction.HIGHER_IS_WORSE},
        {"name": "x", "warn": "1", "crit": 2, "direction": Direction.HIGHER_IS_WORSE},
        {"name": "x", "warn": 5, "crit": 2, "direction": Direction.HIGHER_IS_WORSE},
        {"name": "x", "warn": 2, "crit": 5, "direction": Direction.LOWER_IS_WORSE},
    ],
)
def test_invalid_rules_are_refused_with_a_message_id(kwargs: dict[str, object]) -> None:
    with pytest.raises(ContractError) as info:
        Rule(**kwargs)  # type: ignore[arg-type]
    assert info.value.message.id.startswith("rule.error.")


def test_item_status_uses_the_rule_or_the_probes_status() -> None:
    rules = {"disk_used_percent": DISK}
    assert item_status(Item("d.root", 95, Unit.PERCENT, rule="disk_used_percent"), rules) is (
        Status.CRIT
    )
    assert item_status(Item("d.root", 95, Unit.PERCENT, rule="missing"), rules) is Status.UNKNOWN
    assert item_status(Item("x.y", "a", status=Status.WARN), rules) is Status.WARN
    assert item_status(Item("x.y", "a"), rules) is None
    # a cached item keeps the collector's classification when the rule is not known here
    cached = Item("d.root", 95, Unit.PERCENT, rule="cert_days_left", status=Status.CRIT)
    assert item_status(cached, rules) is Status.CRIT
    assert item_status(cached, {"cert_days_left": CERT}) is Status.OK


def test_rules_serialise_for_render_json() -> None:
    assert rules_to_json({"cert_days_left": CERT, "disk_used_percent": DISK}) == {
        "cert_days_left": {"warn": 21, "crit": 7, "direction": "lower"},
        "disk_used_percent": {"warn": 80, "crit": 90, "direction": "higher"},
    }

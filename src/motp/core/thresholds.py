"""Threshold rules and the one classification function (blueprint 4.5).

A rule has a direction and two limits. The collector classifies cached values with it and
the renderer classifies live values with the limits from ``render.json``; both call
``classify``. Limits are inclusive: a value equal to ``warn`` is a warning.
"""

import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from motp.core.model import ContractError, Item, Status, Value, contract_error

RULE_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")


class Direction(str, Enum):
    """Which way a value gets worse."""

    HIGHER_IS_WORSE = "higher"
    LOWER_IS_WORSE = "lower"


class RuleError(ContractError):
    """A rule definition is invalid."""


def _rule_error(msg_id: str, rule: str = "") -> RuleError:
    return RuleError(contract_error(msg_id, rule=rule).message)


@dataclass(frozen=True)
class Rule:
    name: str
    warn: float
    crit: float
    direction: Direction

    def __post_init__(self) -> None:
        if not RULE_NAME.match(self.name):
            raise _rule_error("rule.error.name")
        for limit in (self.warn, self.crit):
            if type(limit) not in (int, float) or not math.isfinite(limit):
                raise _rule_error("rule.error.limits", rule=self.name)
        if self.direction is Direction.HIGHER_IS_WORSE and self.crit < self.warn:
            raise _rule_error("rule.error.order", rule=self.name)
        if self.direction is Direction.LOWER_IS_WORSE and self.crit > self.warn:
            raise _rule_error("rule.error.order", rule=self.name)


def make_rule(name: str, warn: float, crit: float, direction: Optional[Direction] = None) -> Rule:
    """Build a rule; without ``direction`` it follows from the limits (crit < warn: lower).

    Equal limits leave the direction open, so they need an explicit one.
    """
    if direction is None:
        if warn == crit:
            raise _rule_error("rule.error.direction", rule=name)
        direction = Direction.LOWER_IS_WORSE if crit < warn else Direction.HIGHER_IS_WORSE
    return Rule(name=name, warn=warn, crit=crit, direction=direction)


def classify(value: Value, rule: Rule) -> Status:
    """Classify one value. Anything that is not a finite number is ``unknown``."""
    if type(value) not in (int, float):
        return Status.UNKNOWN
    number = float(value)  # type: ignore[arg-type]
    if not math.isfinite(number):
        return Status.UNKNOWN
    if rule.direction is Direction.HIGHER_IS_WORSE:
        if number >= rule.crit:
            return Status.CRIT
        return Status.WARN if number >= rule.warn else Status.OK
    if number <= rule.crit:
        return Status.CRIT
    return Status.WARN if number <= rule.warn else Status.OK


def item_status(item: Item, rules: Mapping[str, Rule]) -> Optional[Status]:
    """Status of an item: by its rule if ``rules`` defines it, else the stored status.

    A cached item carries both its rule and the collector's classification, and the
    renderer's rules cover live values only, so a rule it does not know falls back to the
    stored status, and to ``unknown`` without one. An item with neither rule nor status has
    no status (``None``): it is shown neutrally.
    """
    rule = rules.get(item.rule) if item.rule is not None else None
    if rule is not None:
        return classify(item.value, rule)
    if item.status is not None:
        return item.status
    return Status.UNKNOWN if item.rule is not None else None


def rules_to_json(rules: Mapping[str, Rule]) -> dict[str, dict[str, object]]:
    """Serialise rules for ``render.json``."""
    return {
        name: {"warn": r.warn, "crit": r.crit, "direction": r.direction.value}
        for name, r in sorted(rules.items())
    }

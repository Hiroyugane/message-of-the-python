"""Data model helpers (blueprint 4.3, 4.4)."""

from motp.core.model import (
    STATUS_MESSAGE,
    LiteralText,
    MessageRef,
    ModuleResult,
    Status,
    freshness,
    ref,
    worst,
)


def test_ref_orders_parameters() -> None:
    assert ref("a.b", z=1, a="x") == MessageRef("a.b", (("a", "x"), ("z", 1)))
    assert ref("a.b").param_dict() == {}


def test_literal_text_picks_a_translation() -> None:
    text = LiteralText("Backup", (("de", "Sicherung"),))
    assert text.for_language("de") == "Sicherung"
    assert text.for_language("fr") == "Backup"


def test_worst_status() -> None:
    assert worst([Status.OK, None, Status.WARN, Status.UNKNOWN]) is Status.WARN
    assert worst([Status.CRIT, Status.WARN]) is Status.CRIT
    assert worst([None]) is None
    assert set(STATUS_MESSAGE) == set(Status)


def test_freshness_marks_stale_and_expired_items() -> None:
    result = ModuleResult(collected=1000, interval=300, max_age=3600)
    assert freshness(result, 1900) == freshness(result, 1900)
    assert not freshness(result, 1900).stale  # exactly three intervals
    assert freshness(result, 1901).stale and not freshness(result, 1901).expired
    assert freshness(result, 4601).expired
    assert freshness(result, 500).age == 0  # a clock that went backwards

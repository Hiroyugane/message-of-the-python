"""``os_eol``: the end of an OS release's support, from local data with its date."""

import datetime
import sys

import pytest

from motp.core.model import Item, Status
from motp.modules import os_eol
from motp.modules.base import parse_os_release
from motp.modules.os_eol import OsEol

from .conftest import SRC
from .packages_system import (
    System,
    alerts,
    captured,
    everything,
    hint_of,
    only,
    render_for,
    text_of,
    through_the_contract,
)

# --- os_eol ---------------------------------------------------------------------------------


def at(date: str) -> int:
    moment = datetime.datetime.fromisoformat(f"{date}T12:00:00+00:00")
    return int(moment.timestamp())


def eol(release: dict[str, str], today: str = "2026-11-25") -> "list[Item]":
    return OsEol().collect(System(os_release=release, now=at(today)))


@pytest.mark.parametrize(
    ("distro", "date", "from_table"),
    [
        ("debian12", "2028-06-30", True),
        ("ubuntu2204", "2027-05-31", True),
        ("almalinux9", "2032-06-01", False),  # SUPPORT_END wins over the table
        ("fedora45", "2027-12-08", False),
    ],
)
def test_end_of_life_per_distribution(distro: str, date: str, from_table: bool) -> None:
    item = only(eol(parse_os_release(captured(distro, "os-release"))))
    assert (item.value, item.status) == (date, Status.OK)
    data = os_eol.table()[""]["date"]
    expected = f"supported until {date}" + (f" (as of {data})" if from_table else "")
    assert text_of(item) == expected
    assert hint_of(item) == "os.eol"
    through_the_contract("os_eol", [item])


@pytest.mark.parametrize(
    ("today", "status", "words"),
    [
        ("2028-03-31", Status.OK, "supported until"),
        ("2028-04-01", Status.WARN, "OS support ends"),  # 90 days left
        ("2028-06-30", Status.WARN, "OS support ends"),  # the last day
        ("2028-07-01", Status.CRIT, "OS support ended"),
    ],
)
def test_the_warning_starts_ninety_days_before(today: str, status: Status, words: str) -> None:
    item = only(eol({"ID": "debian", "VERSION_ID": "12"}, today))
    assert item.status is status
    assert text_of(item).startswith(f"{words} 2028-06-30 (as of ")


def test_the_attention_line_names_the_system() -> None:
    item = only(eol({"ID": "debian", "VERSION_ID": "11"}))
    shown = alerts(render_for("os_eol", [item], admin=False))
    assert [a.text for a in shown] == ["OS support ended 2026-08-31 (as of 2026-11-25)"]


@pytest.mark.parametrize(
    "release",
    [
        {},
        {"ID": "debian"},  # testing has no VERSION_ID
        {"ID": "debian", "VERSION_ID": "99"},
        {"ID": "linuxmint", "VERSION_ID": "22"},
        {"ID": "\x1b[31mdebian", "VERSION_ID": "12"},
        {"ID": "debian", "VERSION_ID": "12\x1b]0;x\x07"},
        {"ID": "other", "SUPPORT_END": "2030-13-45"},
        {"ID": "other", "SUPPORT_END": "\x1b[31m2030-01-01"},
        {"ID": "other", "SUPPORT_END": "2030-01-01; rm -rf /"},
        {"ID": "other", "SUPPORT_END": "9" * 5000},
    ],
)
def test_unknown_and_hostile_releases_give_no_row(release: dict[str, str]) -> None:
    assert eol(release) == []


def test_a_hostile_release_file_leaves_the_row_inert() -> None:
    text = (
        'ID=debian\nVERSION_ID="12"\nPRETTY_NAME="Evil\x1b[2J OS"\n'
        'VERSION="\x1b]0;owned\x07"\nSUPPORT_END=soon\x1b[31m\n'
    )
    items = eol(parse_os_release(text))
    shown = everything(render_for("os_eol", items, admin=True))
    assert "until 2028-06-30" in shown and "\\x1b" not in shown


def test_other_ids_use_their_table() -> None:
    assert only(eol({"ID": "raspbian", "VERSION_ID": "12"})).value == "2028-06-30"
    assert only(eol({"ID": "rocky", "VERSION_ID": "10.1"})).value == "2035-05-31"
    assert only(eol({"ID": "rhel", "VERSION_ID": "9.4"})).value == "2032-05-31"


def test_the_table_reads_like_toml_and_carries_its_date() -> None:
    if sys.version_info >= (3, 11):
        import tomllib as toml
    else:
        from motp._vendor import tomli as toml
    text = (SRC / "motp" / "data" / "eol.toml").read_text(encoding="utf-8")
    real = toml.loads(text)
    parsed = os_eol.parse_table(text)
    assert parsed[""] == {k: v for k, v in real.items() if isinstance(v, str)}
    assert {k: v for k, v in parsed.items() if k} == {
        k: v for k, v in real.items() if isinstance(v, dict)
    }
    assert os_eol.parse_date(parsed[""]["date"]) is not None
    for name, entries in parsed.items():
        for version, date in entries.items():
            if name:
                assert os_eol.parse_date(date) is not None, (name, version)
    # Every table a release can name exists.
    assert {name for name, _major in os_eol.TABLES.values()} <= set(parsed)


@pytest.mark.parametrize("line", ["[[x]]", "a = 1", 'a = "x" # note', "just words"])
def test_the_table_reader_refuses_other_lines(line: str) -> None:
    with pytest.raises(RuntimeError):
        os_eol.parse_table(line + "\n")


@pytest.mark.parametrize(
    ("distro", "version", "date"),
    [
        ("debian", "10", "2024-06-30"),
        ("ubuntu", "18.04", "2023-05-31"),
        ("ubuntu", "20.04", "2025-05-31"),
        ("ubuntu", "22.10", "2023-07-20"),
        ("ubuntu", "23.04", "2024-01-20"),
        ("ubuntu", "23.10", "2024-07-12"),
        ("ubuntu", "24.10", "2025-07-10"),
        ("ubuntu", "25.04", "2026-01-17"),
        ("ubuntu", "25.10", "2026-07-01"),
        ("fedora", "40", "2025-05-13"),
        ("fedora", "41", "2025-12-15"),
    ],
)
def test_releases_already_out_of_support_are_critical(distro: str, version: str, date: str) -> None:
    """These are the systems the module exists for; Ubuntu sets no SUPPORT_END."""
    item = only(eol({"ID": distro, "VERSION_ID": version}))
    assert (item.value, item.status) == (date, Status.CRIT)


def test_the_table_covers_the_releases_checked_for_1_0() -> None:
    """Phase 14: Debian 13 and AlmaLinux 10 are tier-1 releases and need their row."""
    assert only(eol({"ID": "debian", "VERSION_ID": "13"})).value == "2030-06-30"
    assert only(eol({"ID": "almalinux", "VERSION_ID": "10.1"})).value == "2035-05-31"
    assert only(eol({"ID": "ubuntu", "VERSION_ID": "26.04"})).value == "2031-05-29"

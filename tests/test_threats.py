"""Every threat has a passing test or a recorded acceptance (phase 14).

``docs/threats.md`` lists the threats of the threat model and maps each id to test names
(``tests/<file>.py::<test>``) or to an acceptance with its reason. This test fails when the
ids have a gap, a row has neither, or a named test does not exist (renamed or removed).
Whether the named tests pass is the suite's job.
"""

import re

from .conftest import ROOT

TABLE = ROOT / "docs" / "threats.md"
TEST_REF = re.compile(r"`(tests/test_[a-z0-9_]+\.py)::(test_[a-z0-9_]+)`")
ACCEPTED = re.compile(r"\*\*Accepted[^*]*\*\*\s*(\S.*)")
THREATS = 26  # T1 to T26; a new threat gets the next number and a row


def _rows() -> dict[str, str]:
    rows = {}
    for line in TABLE.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^\| (T\d+) \|", line)
        if m:
            assert m.group(1) not in rows, f"{m.group(1)} has two rows"
            rows[m.group(1)] = line
    return rows


def test_the_table_lists_every_threat_without_a_gap() -> None:
    ids = list(_rows())
    assert len(ids) >= THREATS
    assert ids == [f"T{n}" for n in range(1, len(ids) + 1)]


def test_every_threat_has_a_test_or_an_acceptance() -> None:
    for tid, row in _rows().items():
        tests = TEST_REF.findall(row)
        accepted = ACCEPTED.findall(row)
        assert tests or accepted, f"{tid} has neither a test nor an acceptance"
        for path, name in tests:
            source = (ROOT / path).read_text(encoding="utf-8")
            assert re.search(rf"^def {name}\(", source, re.MULTILINE), f"{tid}: {path}::{name}"


def test_an_accepted_threat_says_why() -> None:
    for tid, row in _rows().items():
        for reason in ACCEPTED.findall(row):
            assert len(reason.split()) >= 8, f"{tid}: the acceptance gives no reason"

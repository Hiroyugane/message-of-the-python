"""The fixed hint table (blueprint D34, T7): no entry takes anything from collected data."""

import ast
import inspect

import pytest

from motp.core import hints, i18n

from .conftest import SRC

HINTS_SOURCE = SRC / "motp" / "core" / "hints.py"


def test_every_hint_message_exists_and_takes_no_parameter() -> None:
    english = i18n.english()
    for hint_id, entry in hints.HINTS.items():
        assert i18n.MESSAGE_ID.match(hint_id), hint_id
        assert english.has(entry.message), entry.message
        template = english.template(entry.message, None) or ""
        assert "{" not in template and "}" not in template, entry.message


def test_commands_are_plain_constant_text() -> None:
    for hint_id, entry in hints.HINTS.items():
        assert set(entry.commands) <= {*hints.PACKAGE_MANAGERS, hints.ANY}, hint_id
        for command in entry.commands.values():
            assert type(command) is str and command.isprintable() and command.isascii()
            assert not set(command) & set("{}%$`\\\n;&<>"), (hint_id, command)


def test_table_is_built_from_literals_only() -> None:
    """Every ``_entry`` call in the table takes constant strings and nothing else."""
    tree = ast.parse(HINTS_SOURCE.read_text(encoding="utf-8"))
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "_entry"
    ]
    assert len(calls) == len(hints.HINTS)
    for call in calls:
        args = [*call.args, *(kw.value for kw in call.keywords)]
        assert all(kw.arg is not None for kw in call.keywords)
        assert all(isinstance(a, ast.Constant) and type(a.value) is str for a in args)


def test_lookup_takes_only_the_id_and_the_package_manager() -> None:
    assert list(inspect.signature(hints.lookup).parameters) == ["hint_id", "package_manager"]


def test_table_is_read_only() -> None:
    with pytest.raises(TypeError):
        hints.HINTS["x"] = hints.HINTS["os.eol"]  # type: ignore[index]
    with pytest.raises(TypeError):
        hints.HINTS["os.eol"].commands["*"] = "x"  # type: ignore[index]


@pytest.mark.parametrize(
    ("hint_id", "manager", "expected"),
    [
        ("updates.install", "apt", ("hint.updates.install", "sudo apt upgrade")),
        ("updates.install", "dnf", ("hint.updates.install", "sudo dnf upgrade")),
        ("updates.install", "", ("hint.updates.install", None)),
        ("updates.install", "pacman", ("hint.updates.install", None)),
        ("reboot.required", "apt", ("hint.reboot.required", "sudo reboot")),
        ("reboot.required", "anything", ("hint.reboot.required", "sudo reboot")),
        ("no.such.hint", "apt", None),
        ("sudo rm -rf /", "apt", None),
    ],
)
def test_lookup(hint_id: str, manager: str, expected: object) -> None:
    assert hints.lookup(hint_id, manager) == expected

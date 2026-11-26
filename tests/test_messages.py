"""Invariant 5: every user-visible string has a message id (blueprint D19, section 10).

Three checks over the package source:

1. No text literal reaches an output sink: ``print``, ``.write``, ``sys.exit`` and
   ``SystemExit``, ``parser.error``, and the text arguments of ``argparse`` (``help``,
   ``description``, ``epilog``, ``usage``, ``metavar``, ``title``, ``prog`` excepted).
   A literal that is empty or only whitespace is allowed.
2. Every message id the code names exists in the English catalogue.
3. Every id in the English catalogue is named somewhere in the package (no dead text).

Errors that reach a person (``ContractError``) carry a ``MessageRef``, which the type
checker enforces. Commands in the hint table are commands, not language, and are exempt.

Known gap: text that reaches a sink through a variable (``msg = "Hello"; print(msg)``) is
not traced. Review catches it; the check stops the direct and common case.
"""

import ast
import re
from collections.abc import Iterator
from pathlib import Path

import pytest

from motp.core import i18n

from .conftest import SRC

PACKAGE = SRC / "motp"
SINK_FUNCTIONS = {"print", "exit", "SystemExit", "error", "write", "writelines"}
ARGPARSE_TEXT = {"help", "description", "epilog", "usage", "metavar", "title"}
# Calls whose first argument is a message id.
ID_CALLS = {
    "ref", "_fail", "MessageRef", "message", "_entry", "ContractError", "contract_error",
    "_rule_error", "compose",
}  # fmt: skip


def _has_text(node: ast.AST) -> bool:
    """True if the expression contains a non-blank string literal or an f-string.

    In a catalogue call (``tr.message("id", {"name": v})``) the first argument is an id and
    the keys of a parameter dict are names, not text; parameter values are still checked.
    """
    if isinstance(node, ast.Call) and _name(node.func) in ID_CALLS:
        rest: list[ast.AST] = []
        for arg in node.args[1:]:
            rest += [v for v in arg.values if v is not None] if isinstance(arg, ast.Dict) else [arg]
        rest += [kw.value for kw in node.keywords]
        return any(_has_text(a) for a in rest)
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.strip():
        return True
    return any(_has_text(child) for child in ast.iter_child_nodes(node))


def _name(func: ast.expr) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def sink_violations(source: str, rel: str) -> list[str]:
    problems = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Raise) and node.exc is not None:
            exc = node.exc
            if (
                isinstance(exc, ast.Call)
                and _name(exc.func) == "SystemExit"
                and any(_has_text(a) for a in exc.args)
            ):
                problems.append(f"{rel}:{node.lineno}: text literal in SystemExit")
        if not isinstance(node, ast.Call):
            continue
        name = _name(node.func)
        if name in SINK_FUNCTIONS and any(_has_text(a) for a in node.args):
            problems.append(f"{rel}:{node.lineno}: text literal passed to {name}()")
        for kw in node.keywords:
            if kw.arg in ARGPARSE_TEXT and _has_text(kw.value):
                problems.append(f"{rel}:{node.lineno}: text literal in {kw.arg}=")
    return problems


def named_ids(source: str) -> Iterator[tuple[int, str]]:
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Call) and _name(node.func) in ID_CALLS and node.args:
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                yield node.lineno, first.value


def _sources() -> list[Path]:
    return sorted(p for p in PACKAGE.rglob("*.py") if "__pycache__" not in p.parts)


def test_no_text_literal_reaches_an_output_sink() -> None:
    problems = []
    for path in _sources():
        rel = path.relative_to(PACKAGE).as_posix()
        problems += sink_violations(path.read_text(encoding="utf-8"), rel)
    assert not problems, "\n".join(problems)


def test_every_named_id_is_in_the_english_catalogue() -> None:
    english = i18n.english()
    missing = []
    seen = 0
    for path in _sources():
        for line, msg_id in named_ids(path.read_text(encoding="utf-8")):
            if path.name == "hints.py" and not msg_id.startswith("hint."):
                continue  # _entry's first argument is a message id; nothing else there
            seen += 1
            if not english.has(msg_id):
                missing.append(f"{path.name}:{line}: {msg_id}")
    assert seen > 40
    assert not missing, "\n".join(missing)


def _naming_text(path: Path) -> str:
    """The text of a module as far as it counts as using a message.

    ``explain.py`` lists the screen texts each topic covers; that table explains a message
    and does not show it, so only the module's own texts count there. Otherwise a message
    nothing shows any more would pass as used.
    """
    text = path.read_text(encoding="utf-8")
    if path != PACKAGE / "explain.py":
        return text
    own = re.findall(r'"((?:cli\.)?explain\.[a-z0-9_.]+)"', text)
    return " ".join(f'"{msg_id}"' for msg_id in own)


def test_every_catalogue_entry_is_used() -> None:
    text = "\n".join(_naming_text(p) for p in _sources())
    unused = sorted(i for i in i18n.english().ids() if f'"{i}"' not in text)
    assert not unused, unused


@pytest.mark.parametrize(
    "source",
    [
        "print('hello')",
        "print(f'{x} done')",
        "sys.stderr.write('oops\\n')",
        "sys.exit('failed')",
        "raise SystemExit('bye')",
        "parser.add_argument('--x', help='do x')",
        "argparse.ArgumentParser(description='tool')",
        "parser.error('bad ' + x)",
        "print('%s items' % n)",
        "print(tr.message('plugin.prefix', {'name': 'English prose'}))",
        "print(tr.message('x.y', 'English default'))",
    ],
)
def test_the_check_finds_literals(source: str) -> None:
    assert sink_violations(source, "x.py")


@pytest.mark.parametrize(
    "source",
    [
        "print(tr.message('cli.version.output', {'version': v}))",
        "print()",
        "sys.stdout.write('\\n')",
        "parser.add_argument('--x', help=tr.message('cli.version.help'))",
        "sys.exit(main())",
    ],
)
def test_the_check_allows_catalogue_text(source: str) -> None:
    assert sink_violations(source, "x.py") == []

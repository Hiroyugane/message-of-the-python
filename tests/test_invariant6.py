"""Invariant 6 (blueprint section 10, threats T4 and T18): the render path stays small.

``motp show`` starts no process, opens no socket, imports no name-lookup module and opens no
file outside the interpreter prefix, the program's own tree, ``/proc``, ``/sys`` and the cache
directory. Two kinds of checks back this up:

* a runtime check: ``tests/audit_show.py`` runs ``show.main`` under ``sys.addaudithook`` in a
  fresh interpreter (the hook is installed first, so imports are seen too);
* a static check: every module reachable from ``motp.show`` is parsed, and none imports
  ``pwd``, ``grp``, ``socket``, ``subprocess`` or the other modules in ``FORBIDDEN``.
"""

import ast
import json
import subprocess
import sys
from pathlib import Path

import pytest

from .conftest import SRC
from .support import render_settings, write_cache
from .test_show import demo_results, posix_modes  # noqa: F401  (autouse fixture)

PACKAGE = SRC / "motp"
AUDIT = Path(__file__).resolve().parent / "audit_show.py"
ROOTS = ("motp.show", "motp.core.deadline")
FORBIDDEN = {
    "pwd", "grp", "socket", "_socket", "subprocess", "_posixsubprocess", "ctypes", "ssl",
    "select", "selectors", "multiprocessing", "asyncio", "http", "urllib", "argparse",
    "tomllib", "tomli", "shutil", "pkgutil", "importlib", "threading", "traceback",
}  # fmt: skip
# Modules the render path may not reach, whatever they import.
FORBIDDEN_MOTP = {"motp.cli", "motp.core.config", "motp.core.proc", "motp.core.safepath"}
# Lazy imports that are allowed in a named function only (each one with its reason).
ALLOWED_LAZY = {
    ("motp.core.deadline", "threading"),  # the timer thread where SIGALRM does not exist
    ("motp.show", "traceback"),  # only to print a traceback for --debug
}


def _module_path(name: str) -> Path:
    base = PACKAGE.parent.joinpath(*name.split("."))
    if base.is_dir():
        return base / "__init__.py"
    return base.with_suffix(".py")


def _exists(name: str) -> bool:
    return _module_path(name).is_file()


def imports_of(name: str) -> tuple[set[str], set[str]]:
    """(top-level names of all imports, names of the package's own modules imported)."""
    tree = ast.parse(_module_path(name).read_text(encoding="utf-8"))
    outside: set[str] = set()
    own: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                (own if alias.name.split(".")[0] == "motp" else outside).add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            if node.module.split(".")[0] == "motp":
                own.add(node.module)
                own.update(f"{node.module}.{a.name}" for a in node.names)
            else:
                outside.add(node.module)
    own = {m for m in own if _exists(m)}
    # importing a module imports its parent packages as well
    for module in list(own):
        parts = module.split(".")
        own.update(".".join(parts[:i]) for i in range(1, len(parts)))
    return outside, own


def reachable() -> dict[str, set[str]]:
    seen: dict[str, set[str]] = {}
    todo = list(ROOTS)
    while todo:
        name = todo.pop()
        if name in seen or not _exists(name):
            continue
        outside, own = imports_of(name)
        seen[name] = outside
        todo.extend(own)
    return seen


def test_the_reachable_set_is_what_we_expect() -> None:
    names = set(reachable())
    assert {"motp.show", "motp.core.cache", "motp.render.view", "motp.modules.registry"} <= names
    assert not names & FORBIDDEN_MOTP


def test_no_module_reachable_from_show_imports_a_forbidden_module() -> None:
    problems = []
    for name, outside in sorted(reachable().items()):
        for imported in outside:
            top = imported.split(".")[0]
            if top in FORBIDDEN and (name, top) not in ALLOWED_LAZY:
                problems.append(f"{name} imports {imported}")
    assert not problems, "\n".join(problems)


def test_only_the_deadline_touches_signals() -> None:
    for name, outside in reachable().items():
        if name != "motp.core.deadline":
            assert "signal" not in {i.split(".")[0] for i in outside}, name


def test_the_entry_point_imports_nothing_heavy() -> None:
    outside, _own = imports_of("motp.entry")
    assert {i.split(".")[0] for i in outside} <= {"sys", "typing"}
    outside, _own = imports_of("motp.__main__")
    assert {i.split(".")[0] for i in outside} <= {"sys"}


def audit(mode: str, directory: Path, sabotage: str = "") -> dict[str, object]:
    args = [sys.executable, "-I", str(AUDIT), mode, str(directory)]
    if sabotage:
        args.append(sabotage)
    done = subprocess.run(args, capture_output=True, text=True, timeout=120, check=False)
    assert done.returncode == 0, done.stderr
    result: dict[str, object] = json.loads(done.stdout.splitlines()[-1])
    return result


@pytest.mark.skipif(sys.platform == "win32", reason="the reader checks POSIX file modes")
def test_show_with_a_fixture_cache_does_nothing_forbidden(tmp_path: Path) -> None:
    write_cache(tmp_path, demo_results(), settings=render_settings())
    result = audit("fixture", tmp_path)
    assert result["violations"] == []
    assert result["code"] == 0
    assert "Hostname" in str(result["output"]) and "Uptime" in str(result["output"])


def test_show_without_a_cache_does_nothing_forbidden(tmp_path: Path) -> None:
    result = audit("fixture", tmp_path / "missing")
    assert result["violations"] == []
    assert "No collected data found" in str(result["output"])


@pytest.mark.skipif(not Path("/proc/loadavg").exists(), reason="needs a real /proc")
def test_show_on_the_real_proc_does_nothing_forbidden(tmp_path: Path) -> None:
    write_cache(tmp_path, demo_results(), settings=render_settings())
    result = audit("real", tmp_path)
    assert result["violations"] == []
    assert "Load" in str(result["output"])


@pytest.mark.parametrize(
    "kind,expected",
    [
        ("open", "open"),
        ("socket", "socket"),
        ("popen", "subprocess"),
        ("pwd", "pwd"),
        ("system", "os.system"),
    ],
)
def test_the_hook_notices_a_forbidden_call(kind: str, expected: str, tmp_path: Path) -> None:
    """The hook is only worth something if it fails when the path does what it must not."""
    result = audit("fixture", tmp_path, kind)
    found = result["violations"]
    assert isinstance(found, list) and any(expected in v for v in found), found

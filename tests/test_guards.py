"""AST guards for blueprint invariants 1 and 2.

Invariant 1: no process start outside ``core/proc.py``; no ``shell=True``, ``eval``, ``exec``
or ``pickle`` anywhere. Invariant 2: no network module imported anywhere in the package.
Dynamic imports (``__import__``, ``importlib.import_module``) must name a constant module so
the guard can see it; a non-constant name counts as a violation.

The guard is deliberately strict, with known false positives: ``shell=None``, any ``urllib``
import (even ``urllib.parse``) and ``**kwargs`` expansion in calls are flagged. A phase that
needs one of them relaxes the guard here and records the reason in the decision log. Not
covered: ``getattr`` tricks; the runtime audit-hook test of invariant 6 (phase 5) backs it up.
"""

import ast
from collections.abc import Iterator
from pathlib import Path
from typing import Optional

import pytest

from .conftest import SRC

PACKAGE = SRC / "motp"
PROC_MODULE = "core/proc.py"

PROCESS_MODULES = {
    "subprocess", "_posixsubprocess", "pty", "multiprocessing", "commands", "ctypes", "webbrowser",
}  # fmt: skip
PROCESS_OS_CALLS = {
    "system", "popen", "fork", "forkpty", "posix_spawn", "posix_spawnp", "startfile",
    "execl", "execle", "execlp", "execlpe", "execv", "execve", "execvp", "execvpe",
    "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe",
}  # fmt: skip
ASYNCIO_PROCESS_CALLS = {"create_subprocess_exec", "create_subprocess_shell"}
PICKLE_MODULES = {"pickle", "_pickle", "cPickle", "dill", "cloudpickle", "shelve", "marshal"}
NETWORK_MODULES = {
    "socket", "_socket", "ssl", "_ssl", "http", "urllib", "ftplib", "smtplib", "poplib",
    "imaplib", "nntplib", "telnetlib", "xmlrpc", "socketserver", "wsgiref", "smtpd",
    "asyncore", "asynchat", "requests", "urllib3", "httpx", "aiohttp", "websockets",
}  # fmt: skip
FORBIDDEN_BUILTINS = {"eval", "exec"}
# The one file that may import ``socket`` (phase 11): the local-socket client of the
# container module. It may use only these names of it, so it can make nothing but a
# Unix-domain stream socket; the unit's RestrictAddressFamilies backs this up (T13).
SOCKET_MODULE = "collect/unixhttp.py"
SOCKET_NAMES = {"socket", "AF_UNIX", "SOCK_STREAM", "SOL_SOCKET", "SO_PEERCRED"}


def _imported_modules(tree: ast.AST) -> Iterator[tuple[int, Optional[str]]]:
    """Yield (line, top-level module name or None) for every import, static or dynamic."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield node.lineno, alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                yield node.lineno, node.module.split(".")[0]
        elif isinstance(node, ast.Call):
            func = node.func
            name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
            if name in {"__import__", "import_module"}:
                arg = node.args[0] if node.args else None
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    yield node.lineno, arg.value.split(".")[0]
                else:
                    yield node.lineno, None


OS_MODULES = {"os", "posix", "nt"}
STAR_IMPORT_WATCHED = OS_MODULES | {"asyncio", "builtins"}
NETWORK_CALLS = {"open_connection", "start_server", "open_unix_connection", "start_unix_server"}
PROCESS_CLASSES = {"ProcessPoolExecutor"}


def _aliases(tree: ast.AST) -> dict[str, str]:
    """Map every locally bound import name to its dotted origin (``o`` -> ``os``)."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
                else:
                    top = alias.name.split(".")[0]
                    aliases[top] = top
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return aliases


def _dotted(node: ast.expr, aliases: dict[str, str]) -> Optional[str]:
    """Resolve ``a.b.c`` through the import aliases; None for anything else."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(aliases.get(node.id, node.id))
    return ".".join(reversed(parts))


def find_violations(source: str, rel: str) -> list[str]:
    """Return one message per violation in ``source``; ``rel`` is the path inside the package.

    Names are resolved through import aliases, so ``import os as o; o.system(...)`` and
    ``from os import system`` are caught like ``os.system(...)``.
    """
    tree = ast.parse(source)
    problems: list[str] = []
    may_start_processes = rel == PROC_MODULE
    aliases = _aliases(tree)

    for line, module in _imported_modules(tree):
        if module is None:
            problems.append(f"{rel}:{line}: dynamic import with a non-constant module name")
        elif module == "socket" and rel == SOCKET_MODULE:
            continue
        elif module in NETWORK_MODULES:
            problems.append(f"{rel}:{line}: network module {module!r} (invariant 2)")
        elif module in PICKLE_MODULES:
            problems.append(f"{rel}:{line}: {module!r} is forbidden (invariant 1)")
        elif module in PROCESS_MODULES and not may_start_processes:
            problems.append(f"{rel}:{line}: process module {module!r} outside {PROC_MODULE}")

    if rel == SOCKET_MODULE:
        problems += _socket_names(tree, rel, aliases)

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level == 0:
            top = (node.module or "").split(".")[0]
            if top in STAR_IMPORT_WATCHED and any(a.name == "*" for a in node.names):
                problems.append(f"{rel}:{node.lineno}: star import from {top!r} hides calls")
        if not isinstance(node, ast.Call):
            continue
        name = _dotted(node.func, aliases)
        if name is not None:
            _root, _, last = name.rpartition(".")
            top = name.split(".")[0]
            if name in FORBIDDEN_BUILTINS or name in {"builtins.eval", "builtins.exec"}:
                problems.append(f"{rel}:{node.lineno}: call to {last}() (invariant 1)")
            if not may_start_processes and (
                (top in OS_MODULES and last in PROCESS_OS_CALLS)
                or (top == "asyncio" and last in ASYNCIO_PROCESS_CALLS)
                or last in PROCESS_CLASSES
            ):
                problems.append(f"{rel}:{node.lineno}: {name}() outside {PROC_MODULE}")
            if top == "asyncio" and last in NETWORK_CALLS:
                problems.append(f"{rel}:{node.lineno}: {name}() opens a socket (invariant 2)")
        for kw in node.keywords:
            if kw.arg is None:
                problems.append(f"{rel}:{node.lineno}: ** keyword expansion hides shell=")
            elif kw.arg == "shell" and not (
                isinstance(kw.value, ast.Constant) and kw.value.value is False
            ):
                problems.append(f"{rel}:{node.lineno}: shell= keyword other than False")
    return problems


def _socket_names(tree: ast.AST, rel: str, aliases: dict[str, str]) -> list[str]:
    """In ``SOCKET_MODULE``: every name taken from ``socket``, by attribute, by ``from``
    import or by ``getattr`` with a constant, must be one of ``SOCKET_NAMES``."""
    problems: list[str] = []
    for node in ast.walk(tree):
        used: Optional[str] = None
        if isinstance(node, ast.Attribute):
            name = _dotted(node, aliases)
            if name is not None and name.startswith("socket."):
                used = name.split(".", 1)[1]
        elif isinstance(node, ast.ImportFrom) and node.module == "socket":
            for alias in node.names:
                if alias.name not in SOCKET_NAMES:
                    problems.append(f"{rel}:{node.lineno}: socket.{alias.name} (invariant 2)")
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and node.args
            and _dotted(node.args[0], aliases) == "socket"
        ):
            arg = node.args[1] if len(node.args) > 1 else None
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                used = arg.value
            else:
                problems.append(f"{rel}:{node.lineno}: getattr(socket, ...) needs a constant")
        if used is not None and used not in SOCKET_NAMES:
            line = getattr(node, "lineno", 0)
            problems.append(f"{rel}:{line}: socket.{used} (invariant 2)")
    return problems


def _package_sources() -> set[Path]:
    return {p for p in PACKAGE.rglob("*.py") if "__pycache__" not in p.parts}


def test_package_has_sources() -> None:
    assert (PACKAGE / "cli.py") in _package_sources()


def test_package_violates_no_invariant() -> None:
    problems: list[str] = []
    for path in sorted(_package_sources()):
        rel = path.relative_to(PACKAGE).as_posix()
        problems += find_violations(path.read_text(encoding="utf-8"), rel)
    assert not problems, "\n".join(problems)


# The guard must itself fail on forbidden code, or a green run proves nothing.
@pytest.mark.parametrize(
    "source",
    [
        "import subprocess",
        "from subprocess import run",
        "import os\nos.system('x')",
        "import os\nos.execv('/bin/sh', [])",
        "import multiprocessing",
        "import asyncio\nasyncio.create_subprocess_exec('x')",
        "f(shell=True)",
        "f(shell=cmd)",
        "eval('1')",
        "exec('x = 1')",
        "import pickle",
        "import marshal",
        "import socket",
        "from urllib.request import urlopen",
        "import http.client",
        "__import__('socket')",
        "import importlib\nimportlib.import_module('ssl')",
        "__import__(name)",
        "from os import system\nsystem('x')",
        "import os as o\no.system('x')",
        "import posix\nposix.system('x')",
        "from os import *",
        "from asyncio import create_subprocess_shell as c\nc('x')",
        "import builtins\nbuiltins.eval('1')",
        "import asyncio\nasyncio.open_connection('h', 1)",
        "from concurrent.futures import ProcessPoolExecutor\nProcessPoolExecutor()",
        "import ctypes",
        "f(**opts)",
    ],
)
def test_guard_detects_forbidden_code(source: str) -> None:
    assert find_violations(source, "modules/os_example.py")


@pytest.mark.parametrize(
    "source",
    ["import os\nos.getpid()", "f(shell=False)", "import json, re, argparse", "from . import x"],
)
def test_guard_allows_harmless_code(source: str) -> None:
    assert find_violations(source, "modules/os_example.py") == []


def test_only_proc_module_may_start_processes() -> None:
    source = "import subprocess\nsubprocess.run(['x'])\nimport os\nos.fork()"
    assert find_violations(source, PROC_MODULE) == []
    assert find_violations(source, "cli.py")


def test_proc_module_still_may_not_use_shell_eval_or_network() -> None:
    assert find_violations("import subprocess\nsubprocess.run('x', shell=True)", PROC_MODULE)
    assert find_violations("eval('1')", PROC_MODULE)
    assert find_violations("import socket", PROC_MODULE)


def test_the_socket_module_may_make_a_unix_socket_only() -> None:
    allowed = "\n".join(
        (
            "import socket",
            "s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)",
            "getattr(socket, 'SO_PEERCRED', None)",
            "s.getsockopt(socket.SOL_SOCKET, 17, 12)",
        )
    )
    assert find_violations(allowed, SOCKET_MODULE) == []
    for bad in (
        ("import socket", "socket.socket(socket.AF_INET)"),
        ("import socket", "socket.create_connection(('h', 1))"),
        ("import socket", "socket.getaddrinfo('h', 1)"),
        ("import socket", "getattr(socket, 'AF_INET6')"),
        ("import socket", "getattr(socket, name)"),
        ("from socket import AF_INET",),
        ("import socket as s", "s.AF_PACKET"),
        ("import ssl",),
        ("import http.client",),
    ):
        assert find_violations("\n".join(bad), SOCKET_MODULE), bad
    assert find_violations(allowed, "collect/context.py")

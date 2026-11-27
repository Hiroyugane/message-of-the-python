"""Runs ``motp show`` under an audit hook and prints what it did that invariant 6 forbids.

Used by ``tests/test_invariant6.py`` in a fresh interpreter (``python -I audit_show.py ...``).
The hook is installed before anything of MOTP is imported, so imports are seen too.

Usage: audit_show.py MODE CACHE_DIR [SABOTAGE]

MODE is ``fixture`` (the live values come from ``tests/fixtures/debian12``) or ``real``
(from this machine's ``/proc`` and ``/sys``). SABOTAGE names a forbidden action that a
fake module performs, to prove that the hook notices it. Prints one JSON object with the
``violations`` and the start of the output.
"""

import io
import json
import os
import sys
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, "src")
FIXTURES = os.path.join(HERE, "fixtures")

FORBIDDEN_IMPORTS = {
    "pwd", "grp", "socket", "_socket", "subprocess", "_posixsubprocess", "ctypes", "ssl",
    "select", "selectors", "multiprocessing", "asyncio", "http", "urllib", "argparse",
    "tomllib", "tomli", "shutil", "pkgutil",
}  # fmt: skip
PROCESS_EVENTS = {
    "subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.spawn", "os.fork",
    "os.forkpty", "pty.spawn",
}  # fmt: skip
PATH_EVENTS = {
    "open", "os.listdir", "os.scandir", "os.remove", "os.rename", "os.mkdir", "os.rmdir",
    "os.chmod", "os.chown", "os.symlink", "os.link", "os.truncate", "shutil.rmtree",
}  # fmt: skip

TWO_PATH_EVENTS = {"os.rename", "os.symlink", "os.link"}

violations: list[str] = []
allowed: list[str] = []


def _norm(path: object) -> str:
    return os.path.normcase(os.path.abspath(os.fsdecode(path)))  # type: ignore[arg-type]


def _is_allowed(path: str) -> bool:
    return any(path == base or path.startswith(base + os.sep) for base in allowed)


def hook(event: str, args: tuple) -> None:  # type: ignore[type-arg]
    if event in PROCESS_EVENTS or event.startswith("socket."):
        violations.append(event)
    elif event == "import":
        if args[0].split(".")[0] in FORBIDDEN_IMPORTS:
            violations.append(f"import {args[0]}")
    elif event in PATH_EVENTS:
        paths = args[:2] if event in TWO_PATH_EVENTS else args[:1]
        for value in paths:
            if isinstance(value, (str, bytes, os.PathLike)):
                path = _norm(value)
                if not _is_allowed(path):
                    violations.append(f"{event} {path}")


def setup(mode: str, cache_dir: str) -> None:
    bases = [sys.prefix, sys.base_prefix, sys.exec_prefix, sys.base_exec_prefix, SRC, cache_dir]
    bases += ["/proc", "/sys"]
    if mode == "fixture":
        bases.append(FIXTURES)
    allowed.extend(_norm(b) for b in bases)
    sys.addaudithook(hook)


def sabotage_module(kind: str) -> object:
    from motp.modules.base import Detection

    class Saboteur:
        name = "hw_load"
        section = "system"
        mode = "live"
        needs_root = False
        interval = 1
        max_age = 60
        timeout = 1.0
        binaries = ()
        default_visibility = None

        def detect(self, ctx: object) -> Detection:
            return Detection(True)

        def collect(self, ctx: object) -> list:  # type: ignore[type-arg]
            if kind == "open":
                open(os.path.join(os.sep, "etc", "hostname"), "rb")  # noqa: SIM115
            elif kind == "socket":
                import socket

                socket.socket()
            elif kind == "popen":
                import subprocess

                subprocess.Popen([sys.executable, "-c", "pass"])
            elif kind == "pwd":
                import pwd

                pwd.getpwuid(0)
            elif kind == "system":
                os.system("true")  # noqa: S605
            return []

    return Saboteur()


def fixture_context(base: type) -> Any:
    """A context that serves the files of ``tests/fixtures/debian12`` (no ``pathlib``)."""
    from motp.modules.base import context_error

    class Fixture(base):  # type: ignore[misc]
        def _read_bytes(self, path: str, max_bytes: int) -> bytes:
            try:
                with open(os.path.join(FIXTURES, "debian12", path.lstrip("/")), "rb") as handle:
                    return handle.read(max_bytes)
            except OSError as exc:
                raise context_error("context.error.read") from exc

        def _exists(self, path: str) -> bool:
            return os.path.isfile(os.path.join(FIXTURES, "debian12", path.lstrip("/")))

    return Fixture(now=1795600000)


def main() -> int:
    mode, cache_dir = sys.argv[1], sys.argv[2]
    sabotage = sys.argv[3] if len(sys.argv) > 3 else ""
    setup(mode, cache_dir)
    sys.path.insert(0, SRC)
    from motp import show
    from motp.modules import registry
    from motp.modules.base import Context

    if sabotage:
        registry.LIVE_MODULES = (sabotage_module(sabotage),)  # type: ignore[assignment]
    context = Context(now=int(__import__("time").time()))
    if mode == "fixture":
        context = fixture_context(Context)
    stream = io.StringIO()
    code = show.main(
        cache_dir=cache_dir,
        owner=None,
        context=context,
        uid=1,
        env={"MOTP_CHARSET": "ascii", "NO_COLOR": "1"},
        stream=stream,
        width=80,
    )
    print(json.dumps({"code": code, "violations": violations, "output": stream.getvalue()}))
    return 0


if __name__ == "__main__":
    sys.exit(main())

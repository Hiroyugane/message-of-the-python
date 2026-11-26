"""The module interface of blueprint 4.3: ``Module``, ``Context`` and ``Detection``.

A module returns raw values, rule names and hint ids. It never returns colour codes,
commands or finished layout. ``Context`` is the only door to the system.

Live modules (``mode == "live"``) run in ``motp show`` as the logging-in user: they may
read bounded amounts of text below ``/proc`` and ``/sys`` and nothing else (D22). Starting
a program or asking for file system usage raises. Cached modules run in the collector's
probe processes, whose context (``motp.collect.context.ProbeContext``) also reads below
``/etc``, ``/usr/lib`` and ``/run``, follows links, reports file system usage and starts
the programs a module lists in ``binaries``; their interface is declared here so both kinds
share it, and the render path never imports the code that starts processes.

Tests replace ``Context`` with a subclass that serves the files of a fixture tree: only
``_read_bytes``, ``_exists`` and ``_statvfs`` touch the file system, and each takes a path
that has already passed the check.
"""

import os
import posixpath
import re
from collections.abc import Mapping, Sequence
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from typing import ClassVar, Optional, Protocol

from motp.core.model import ContractError, Item, MessageRef, Visibility, ref

LIVE = "live"
CACHED = "cached"
READ_ROOTS = ("/proc/", "/sys/")
MAX_READ = 64 * 1024
_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOCTTY", 0)
    | getattr(os, "O_BINARY", 0)
)

_BYTE_UNITS = ("B", "KiB", "MiB", "GiB", "TiB", "PiB")


class ContextError(ContractError):
    """A module asked the context for something it may not do or cannot get."""


class ImportPathError(ContextError):
    """A root probe's program is a Python script whose import path others can change.

    The program was not started. ``message`` is ``safepath.error.import_path`` naming the
    directory or file that failed; a module may turn it into a "not checked" row.
    """


def context_error(msg_id: str) -> ContextError:
    return ContextError(ref(msg_id))


@dataclass(frozen=True)
class Detection:
    """Whether a module applies on this system, and why not (``motp modules``, phase 6)."""

    available: bool
    reason: Optional[MessageRef] = None


@dataclass(frozen=True)
class FsUsage:
    """What ``statvfs`` reports for one file system, in bytes and inode counts."""

    size: int  # bytes in the file system
    free: int  # bytes free for root
    available: int  # bytes free for unprivileged users
    inodes: int  # 0 when the file system has no fixed inode count
    inodes_free: int
    inodes_available: int
    fsid: int


@dataclass(frozen=True)
class Context:
    """What a module may use: bounded reads, its own config, the OS release and the clock."""

    read_roots: ClassVar[tuple[str, ...]] = READ_ROOTS
    max_read: ClassVar[int] = MAX_READ

    now: int = 0
    config: Mapping[str, object] = field(default_factory=dict)
    os_release: Mapping[str, str] = field(default_factory=dict)

    def read_text(self, path: str, max_bytes: int = MAX_READ) -> str:
        """Read at most ``max_bytes`` of a file below one of ``read_roots`` as text.

        A longer file is cut, not refused; undecodable bytes become the replacement
        character. A path outside the roots, a relative one or one with ``..`` raises.
        """
        _check_path(path, self.read_roots)
        if not 1 <= max_bytes <= self.max_read:
            raise context_error("context.error.read")
        return self._read_bytes(path, max_bytes).decode("utf-8", "replace")

    def exists(self, path: str) -> bool:
        _check_path(path, self.read_roots)
        return self._exists(path)

    def statvfs(self, path: str) -> FsUsage:
        """File system usage is only for cached modules (D22: no disk usage at login)."""
        raise context_error("context.error.statvfs")

    def run(self, argv: Sequence[str], ok_codes: tuple[int, ...] = (0,)) -> bytes:
        """Starting a program is not allowed for live modules (D22)."""
        raise context_error("context.error.run")

    def list_dir(self, path: str) -> tuple[str, ...]:
        """Listing a directory is only for cached modules (D22)."""
        raise context_error("context.error.read")

    def mtime(self, path: str) -> int:
        """File times are only for cached modules (D22)."""
        raise context_error("context.error.read")

    def file_mtime(self, path: str) -> int:
        """The time of a file the admin named in a config row is only for cached modules
        (D22, phase 12)."""
        raise context_error("context.error.read")

    def scratch_dir(self) -> "AbstractContextManager[str]":
        """A directory for a program to write into is only for cached modules (D22)."""
        raise context_error("context.error.run")

    def file_size(self, path: str) -> int:
        """The size of a file is only for cached modules (D22)."""
        raise context_error("context.error.read")

    def read_slice(self, path: str, offset: int, size: int) -> bytes:
        """Binary reads at an offset are only for cached modules (D22)."""
        raise context_error("context.error.read")

    def data_regions(
        self, path: str, align: int, max_bytes: int
    ) -> "tuple[tuple[int, bytes], ...]":
        """The parts of a sparse file that hold data are only for cached modules (D22)."""
        raise context_error("context.error.read")

    def unix_get(self, path: str, target: str, max_bytes: int) -> bytes:
        """Talking to a local service is only for cached modules (D22)."""
        raise context_error("context.error.socket")

    # The methods below are what tests override.

    def _read_bytes(self, path: str, max_bytes: int) -> bytes:
        try:
            fd = os.open(path, _OPEN_FLAGS)
        except OSError as exc:
            raise context_error("context.error.read") from exc
        try:
            chunks: list[bytes] = []
            size = 0
            while size < max_bytes:
                chunk = os.read(fd, max_bytes - size)
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
            return b"".join(chunks)
        except OSError as exc:
            raise context_error("context.error.read") from exc
        finally:
            os.close(fd)

    def _exists(self, path: str) -> bool:
        return os.path.exists(path)


def _check_path(path: str, roots: tuple[str, ...] = READ_ROOTS) -> None:
    if (
        type(path) is not str
        or not path.startswith(roots)
        or "\0" in path
        or posixpath.normpath(path) != path
    ):
        raise context_error("context.error.path")


class Module(Protocol):
    """The interface every built-in module implements (4.3)."""

    name: str
    section: str
    mode: str  # LIVE or CACHED
    needs_root: bool  # cached modules only; live modules never
    interval: int  # seconds between runs, at least the timer period
    max_age: int  # seconds after which old items are dropped
    timeout: float  # seconds before the probe is killed
    binaries: tuple[str, ...]  # absolute paths the module may execute
    default_visibility: Visibility

    def detect(self, ctx: Context) -> Detection: ...

    def collect(self, ctx: Context) -> list[Item]: ...


def parse_error(module: str) -> ContractError:
    """A file of the system did not have the expected shape."""
    return ContractError(ref("module.error.parse", module=module))


def format_bytes(value: float) -> str:
    """``5.9 GiB``: binary units, one decimal below 100, as the renderer prints bytes.

    Modules put this into message parameters. The units are international symbols and the
    decimal point is fixed, so the text needs no translation.
    """
    size = float(value)
    index = 0
    while abs(size) >= 1024 and index < len(_BYTE_UNITS) - 1:
        size /= 1024
        index += 1
    digits = 0 if index == 0 or abs(size) >= 100 else 1
    text = f"{size:.{digits}f}"
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return f"{text} {_BYTE_UNITS[index]}"


OS_RELEASE_FILES = ("/etc/os-release", "/usr/lib/os-release")
_OS_RELEASE_KEY = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
MAX_OS_RELEASE_KEYS = 64


def parse_os_release(text: str) -> dict[str, str]:
    """``KEY=value`` lines of ``os-release(5)``; quotes and backslash escapes removed.

    The file is shell-like but never run through a shell here: a value is one token,
    optionally in single or double quotes. Lines that do not fit are skipped.
    """
    found: dict[str, str] = {}
    for line in text.splitlines():
        key, eq, value = line.strip().partition("=")
        if not eq or not _OS_RELEASE_KEY.match(key) or len(found) >= MAX_OS_RELEASE_KEYS:
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            quote, value = value[0], value[1:-1]
            if quote == '"':
                value = re.sub(r'\\([\\$"`])', r"\1", value)
        found[key] = value
    return found

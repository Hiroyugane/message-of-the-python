"""A fake system for the tests of the service and login modules (phase 10).

``tests/fixtures/logins/<distro>.json`` holds what ``tools/capture_login_fixtures.py``
recorded in each tier-1 image: the records of ``lastlog`` that hold data, ``wtmp`` and
``utmp``, a part of ``/etc/passwd``, ``getent``'s answer and ``systemctl``'s output.
``LoginSystem`` serves them as files and program output to the modules.
"""

import json
import struct
from collections.abc import Mapping, Sequence
from typing import Any, Optional

from motp.collect.context import ProbeContext
from motp.modules import records
from motp.modules.base import context_error

from .support import FIXTURES

DISTROS = ("debian12", "ubuntu2204", "almalinux9", "fedora45")
LASTLOG = "/var/log/lastlog"
WTMP = "/var/log/wtmp"
UTMP = "/run/utmp"
PASSWD = "/etc/passwd"  # noqa: S105  (a file name)
_UTMP = struct.Struct("=h2xi32s4s32s256s2hi2i4i20s")
_LASTLOG = struct.Struct("=i32s256s")


def capture(distro: str) -> dict[str, Any]:
    with open(FIXTURES / "logins" / f"{distro}.json", encoding="utf-8") as f:
        return json.load(f)  # type: ignore[no-any-return]


def utmp_record(
    user: bytes, line: bytes, host: bytes, started: int, kind: int = records.USER_PROCESS
) -> bytes:
    return _UTMP.pack(kind, 4242, line, b"ts/0", user, host, 0, 0, 0, started, 0, 0, 0, 0, 0, b"")


def lastlog_record(started: int, line: bytes, host: bytes) -> bytes:
    return _LASTLOG.pack(started, line, host)


class LoginSystem(ProbeContext):
    """Binary files, sparse ``lastlog`` records and program output."""

    files: dict[str, bytes]
    sparse: dict[str, tuple[int, dict[int, bytes]]]
    outputs: dict[tuple[str, ...], tuple[int, str]]
    calls: list[tuple[str, ...]]

    def __init__(
        self,
        files: Optional[Mapping[str, bytes]] = None,
        *,
        lastlog: Optional[tuple[int, Mapping[int, bytes]]] = None,
        outputs: Optional[Mapping[tuple[str, ...], Any]] = None,
        binaries: Sequence[str] = (),
        config: Optional[Mapping[str, object]] = None,
        now: int = 0,
    ) -> None:
        super().__init__(now=now, binaries=tuple(binaries), config=dict(config or {}))
        object.__setattr__(self, "files", dict(files or {}))
        object.__setattr__(self, "sparse", {})
        if lastlog is not None:
            self.sparse[LASTLOG] = (lastlog[0], dict(lastlog[1]))
        out: dict[tuple[str, ...], tuple[int, str]] = {}
        for argv, value in (outputs or {}).items():
            out[tuple(argv)] = value if isinstance(value, tuple) else (0, value)
        object.__setattr__(self, "outputs", out)
        object.__setattr__(self, "calls", [])

    def _exists(self, path: str) -> bool:
        return path in self.files or path in self.sparse

    def _read_bytes(self, path: str, max_bytes: int) -> bytes:
        if path not in self.files:
            raise context_error("context.error.read")
        return self.files[path][:max_bytes]

    def _file_size(self, path: str) -> int:
        if path in self.sparse:
            return self.sparse[path][0]
        if path not in self.files:
            raise context_error("context.error.read")
        return len(self.files[path])

    def _read_slice(self, path: str, offset: int, size: int) -> bytes:
        if path not in self.files:
            raise context_error("context.error.read")
        return self.files[path][offset : offset + size]

    def _data_regions(self, path: str, align: int, max_bytes: int) -> tuple[tuple[int, bytes], ...]:
        if path not in self.sparse:
            raise context_error("context.error.read")
        _size, by_index = self.sparse[path]
        regions = tuple((index * align, data) for index, data in sorted(by_index.items()))
        if sum(len(data) for _offset, data in regions) > max_bytes:
            raise context_error("context.error.read")
        return regions

    def run(self, argv: Sequence[str], ok_codes: tuple[int, ...] = (0,)) -> bytes:
        args = tuple(argv)
        assert args[0] in self.binaries, f"{args[0]} is not in the module's binaries"
        self.calls.append(args)
        if args not in self.outputs:
            raise context_error("context.error.run_failed")
        code, text = self.outputs[args]
        if code not in ok_codes:
            raise context_error("context.error.run_failed")
        return text.encode("utf-8")


def captured_system(distro: str, binaries: Sequence[str] = (), **kwargs: Any) -> LoginSystem:
    """The captured files of one image, at the time they were captured."""
    c = capture(distro)
    lastlog = {int(uid): bytes.fromhex(hexed) for uid, hexed in c["lastlog"].items()}
    files = {
        WTMP: bytes.fromhex(c["wtmp"]),
        UTMP: bytes.fromhex(c["utmp"]),
        PASSWD: c["passwd"].encode("utf-8"),
        **kwargs.pop("files", {}),
    }
    return LoginSystem(
        files,
        lastlog=kwargs.pop("lastlog", (c["lastlog_size"], lastlog)),
        binaries=binaries,
        now=kwargs.pop("now", c["captured"]),
        **kwargs,
    )

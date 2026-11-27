"""Binary login records: ``utmp``/``wtmp`` and ``lastlog`` (blueprint O3, phase 10).

Read by ``os_sessions`` (``/run/utmp``) and ``os_login`` (``/var/log/lastlog``, else
``/var/log/wtmp``). The layouts are glibc's:

* ``struct utmp``: type, pid, line (32), id (4), user (32), host (256), exit status,
  session, the start time, the address, padding. A login is a record of type
  ``USER_PROCESS`` with a user name.
* ``struct lastlog``, one per uid at offset ``uid * size``: the time, line (32), host
  (256). A record of zeros means "never logged in"; the file is sparse, so most of it is
  holes.

The sizes depend on the machine (review of phase 10). Where glibc defines
``__WORDSIZE_TIME64_COMPAT32`` (x86_64) and on 32-bit machines, the session and the
times are 32-bit numbers: utmp is 384 bytes, lastlog 292 (the four tier-1 test images).
On aarch64, s390x and loongarch64 the session is a ``long`` and the times are a 64-bit
``timeval`` and ``time_t``: utmp is 400 bytes, lastlog 296. ``layout()`` picks one by the
running machine and refuses a 64-bit machine it does not know rather than guess; the
modules then fail visibly. Byte order is the machine's own, as the C library that wrote
the files used it.

Everything in these files is untrusted. The host field is whatever the login program
wrote, which for a remote login can be a name a remote party controls (A2), and the files
are writable by the ``utmp`` group. So the parser takes whole records only (a file cut in
the middle of one loses that one), decodes every text field with replacement, sanitises
it, and ignores times outside a sane range.
"""

import ipaddress
import os
import re
import struct
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Optional

from motp.core.sanitize import sanitize

LOGIN_PROCESS = 6  # what sshd and login(1) write to btmp
USER_PROCESS = 7


@dataclass(frozen=True)
class Layout:
    """The record formats of one kind of machine (native byte order, fixed sizes)."""

    name: str
    utmp: struct.Struct
    lastlog: struct.Struct

    @property
    def utmp_size(self) -> int:
        return self.utmp.size

    @property
    def lastlog_size(self) -> int:
        return self.lastlog.size


# Field order of both utmp formats: type, pid, line, id, user, host, exit status (two),
# session, seconds, microseconds, address (four), padding.
COMPAT32 = Layout(
    "compat32", struct.Struct("=h2xi32s4s32s256s2hi2i4i20s"), struct.Struct("=i32s256s")
)
WIDE = Layout("wide", struct.Struct("=h2xi32s4s32s256s2hq2q4i20s4x"), struct.Struct("=q32s256s"))
UTMP_SIZE = COMPAT32.utmp_size  # 384: x86_64 and the tier-1 test images
LASTLOG_SIZE = COMPAT32.lastlog_size  # 292
WIDE_MACHINES = ("aarch64", "arm64", "s390x", "loongarch64")
COMPAT_MACHINES = ("x86_64", "amd64", "i386", "i486", "i586", "i686", "x86")
_UTMP_FIELDS = (0, 2, 4, 5, 9)  # type, line, user, host, seconds
_BTMP_FIELDS = (0, 1, 5, 9, 11, 12, 13, 14)  # type, pid, host, seconds, address (four)

HOST_CELLS = 64
LINE_CELLS = 32
USER_CELLS = 32
# A record from before 1990 or more than a day ahead of the clock is not a real login.
EARLIEST = 631152000
FUTURE_SLACK = 86400
# A user name as the shadow tools and systemd accept it (``$`` ends Samba machine accounts).
USER_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}\$?\Z")


@dataclass(frozen=True)
class Record:
    """One login: who (empty in ``lastlog``), on which terminal, from where, and when."""

    user: str
    line: str
    host: str
    started: int


def layout(machine: Optional[str] = None) -> Optional[Layout]:
    """The layout of ``machine`` (``uname -m``; the running one by default), or ``None``
    for a 64-bit machine whose layout is not known here."""
    if machine is None:
        uname = getattr(os, "uname", None)
        machine = uname().machine if uname is not None else "x86_64"
    machine = machine.lower()
    if machine in WIDE_MACHINES:
        return WIDE
    if machine in COMPAT_MACHINES:
        return COMPAT32
    if machine.startswith("arm") and "64" not in machine:  # armv6l, armv7l, armv8l
        return COMPAT32
    return None


def field(raw: bytes, cells: int) -> str:
    """A fixed-size C string: up to the first NUL, decoded with replacement, sanitised."""
    return sanitize(raw.split(b"\0", 1)[0].decode("utf-8", "replace"), cells)


def user_name(raw: bytes) -> str:
    """The user name of a record, or ``""`` when it is not one a system account can have.

    A name that fills the whole field has no NUL: it may be a longer name cut at 32 bytes,
    which could match another account, so it is not taken (review of phase 10).
    """
    if b"\0" not in raw:
        return ""
    name = raw.split(b"\0", 1)[0].decode("ascii", "replace")
    return name if USER_NAME.match(name) else ""


def plausible(started: int, now: int) -> bool:
    return EARLIEST <= started <= now + FUTURE_SLACK


def utmp_logins(data: bytes, now: int, shape: Layout = COMPAT32) -> Iterator[Record]:
    """The ``USER_PROCESS`` records of a ``utmp`` or ``wtmp`` file, in file order."""
    whole = len(data) - len(data) % shape.utmp_size
    for fields in shape.utmp.iter_unpack(data[:whole]):
        kind, line, user, host, sec = (fields[i] for i in _UTMP_FIELDS)
        if kind != USER_PROCESS:
            continue
        name = user_name(user)
        if name and plausible(sec, now):
            yield Record(name, field(line, LINE_CELLS), field(host, HOST_CELLS), sec)


def lastlog_entries(
    regions: Iterable[tuple[int, bytes]], now: int, since: int, shape: Layout = COMPAT32
) -> Iterator[tuple[int, Record]]:
    """``(uid, record)`` for every ``lastlog`` record from ``since`` on.

    ``regions`` are the parts of the file that hold data, each starting at a multiple of
    the record size (``Context.data_regions``); a part that does not is skipped.
    """
    size = shape.lastlog_size
    for offset, data in regions:
        if offset % size:
            continue
        first = offset // size
        whole = len(data) - len(data) % size
        for index, (sec, line, host) in enumerate(shape.lastlog.iter_unpack(data[:whole])):
            if sec >= since and plausible(sec, now):
                yield (
                    first + index,
                    Record("", field(line, LINE_CELLS), field(host, HOST_CELLS), sec),
                )


@dataclass(frozen=True)
class Failure:
    """One failed login from ``btmp``: the process that wrote it, where from, and when.

    The attempted user name is never decoded: people type passwords into that field, and
    nothing here may carry it further (T11, 5.4).
    """

    pid: int
    source: str
    started: int


def failure_source(host: bytes, words: "tuple[int, int, int, int]") -> str:
    """The client address of a record, else its host field (sanitised), else ``""``.

    The address is what the login program took from the connection (``ut_addr_v6``), so
    it is preferred over the host field, which holds a reverse-resolved name when the
    server looks names up, and a name is the remote party's choice (A2).
    """
    raw = struct.pack("=4i", *words)
    if any(raw):
        if not any(raw[4:]):
            return str(ipaddress.IPv4Address(raw[:4]))
        address = ipaddress.IPv6Address(raw)
        mapped = address.ipv4_mapped
        return str(mapped if mapped is not None else address)
    return field(host, HOST_CELLS)


def btmp_failures(data: bytes, now: int, shape: Layout = COMPAT32) -> Iterator[Failure]:
    """The failed logins of a ``btmp`` part, in file order; whole records only."""
    whole = len(data) - len(data) % shape.utmp_size
    for fields in shape.utmp.iter_unpack(data[:whole]):
        kind, pid, host, sec, a0, a1, a2, a3 = (fields[i] for i in _BTMP_FIELDS)
        if kind not in (LOGIN_PROCESS, USER_PROCESS) or not plausible(sec, now):
            continue
        yield Failure(pid, failure_source(host, (a0, a1, a2, a3)), sec)

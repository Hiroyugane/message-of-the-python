"""``sec_logins``: failed logins of the last 24 hours (blueprint 4.3, 5.4, D12, phase 11).

Runs as a cached module in a probe process **as root**: ``/var/log/btmp`` is readable by
root and the ``utmp`` group only. The file goes through the ownership check of the probe
context, with group write accepted as for the other login records (``RECORD_FILES``).

**Source (decided in phase 11).** ``/var/log/btmp``, the failed-login records that sshd
and ``login`` write in ``utmp`` form. On all four tier-1 images it exists (0660
``root:utmp``) and sshd writes one record for a failed password and one more for an
account that does not exist, with the client address in the record. The journal holds
the same events as free text whose wording and program name change between OpenSSH
releases (``sshd`` became ``sshd-session`` in 9.8), and ``/var/log/auth.log`` and
``/var/log/secure`` do not exist on a default install; both were rejected (decision log).

**Counting: failed connections.** The newest records are read backwards from the end of
the file, in parts, until one is older than 24 hours or ``MAX_RECORDS`` have been read;
past that the count is a lower bound and says so. Four parts in a row without a single
usable record end the read too (a file made large with holes or zeros). What is counted
is a failed login *connection*: records that one login process wrote for one client, each
within ``SAME_ATTEMPT`` seconds of the one before, are one. sshd writes two records for
an unknown name (the lookup and the password) and one per wrong password, up to
``MaxAuthTries`` (6) per connection; a record count would weigh a name typo double and a
bot's six passwords six-fold, while the number of connections is what a scan or a brute
force costs the attacker in sessions (code review of phase 11). Only the current
``btmp`` is read: for a day after its monthly rotation the count is too low.

**Systems that no longer keep btmp (phase 14).** Debian 13 dropped the utmp family:
systemd is built without ``/run/utmp`` and sshd writes no ``btmp`` record any more
(measured in ``debian:13``; ``lastlog`` and ``wtmp`` are still written there, AlmaLinux 10
writes all four). An empty ``btmp`` would read as "0 in the last 24 hours" there. So a
missing or empty ``btmp`` on a system without ``/run/utmp`` gives the row "not recorded on
this system" instead of a count (a systemd system without either file is detected for that);
a ``btmp`` that holds records is counted wherever it is.

**What leaves the probe.** The count, public (5.4). For admins, the sources with the most
failed attempts, as addresses where the record holds one (the host field is a name a
remote party may choose when sshd looks names up). The attempted user name is never
decoded, so it reaches no cache file, log or error (T11).
"""

from collections.abc import Iterable
from typing import Optional

from motp.core.model import Detail, Item, Status, Unit, Visibility, ref
from motp.modules import records
from motp.modules.base import CACHED, Context, Detection, parse_error

BTMP = "/var/log/btmp"
UTMP = "/run/utmp"  # absent where the system no longer keeps the utmp family
SYSTEMD = "/run/systemd/system"
WINDOW = 86400
SAME_ATTEMPT = 600  # sshd's LoginGraceTime is 120 s by default; ten minutes is generous
CHUNK_RECORDS = 8192  # 3 MiB per read with the 384-byte layout
MAX_RECORDS = 262_144  # 96 MiB of btmp: about 128,000 attempts in a day
MAX_EMPTY_PARTS = 4  # parts in a row without a usable record end the read
TOP_SOURCES = 5
SOURCE_LIST_CHARS = 100


def attempts(failures: Iterable[records.Failure]) -> "list[records.Failure]":
    """One entry per attempt: records of one process and client close in time are one."""
    seen: dict[tuple[int, str], int] = {}
    kept: list[records.Failure] = []
    for failure in sorted(failures, key=lambda f: f.started):
        key = (failure.pid, failure.source)
        last = seen.get(key)
        seen[key] = failure.started
        if last is not None and failure.started - last <= SAME_ATTEMPT:
            continue
        kept.append(failure)
    return kept


def top_sources(found: Iterable[records.Failure], limit: int = TOP_SOURCES) -> "list[str]":
    """``192.0.2.10 (12)``: the sources with the most attempts, most first."""
    counts: dict[str, int] = {}
    for failure in found:
        if failure.source:
            counts[failure.source] = counts.get(failure.source, 0) + 1
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    return [f"{source} ({count})" for source, count in ranked[:limit]]


def source_list(entries: "list[str]") -> str:
    shown: list[str] = []
    length = 0
    for entry in entries:
        length += len(entry) + 2
        if shown and length > SOURCE_LIST_CHARS:
            break
        shown.append(entry)
    return ", ".join(shown)


def failed_item(found: "list[records.Failure]", capped: bool) -> Item:
    count = len(found)
    sources = top_sources(found)
    detail: tuple[Detail, ...] = ()
    if sources:
        detail = (
            Detail("sec_logins.sources", source_list(sources), label=ref("label.login_sources")),
        )
    return Item(
        key="sec_logins.failed",
        value=count,
        unit=Unit.COUNT,
        label=ref("label.failed_logins"),
        status=Status.OK,
        text=ref("logins.failed_more" if capped else "logins.failed", count=count),
        visibility=Visibility.PUBLIC,
        detail=detail,
    )


def unrecorded_item() -> Item:
    """The row on a system that does not write ``btmp``: no count, and saying why."""
    return Item(
        key="sec_logins.failed",
        value=None,
        unit=Unit.TEXT,
        label=ref("label.failed_logins"),
        status=Status.UNKNOWN,
        text=ref("records.not_recorded"),
        visibility=Visibility.PUBLIC,
    )


class SecLogins:
    name = "sec_logins"
    section = "security"
    mode = CACHED
    needs_root = True
    interval = 300
    max_age = 3600
    timeout = 10.0
    binaries: tuple[str, ...] = ()
    default_visibility = Visibility.PUBLIC

    def detect(self, ctx: Context) -> Detection:
        return Detection(ctx.exists(BTMP) or self._no_utmp_family(ctx))

    @staticmethod
    def _no_utmp_family(ctx: Context) -> bool:
        """A systemd system without ``/run/utmp``: it keeps no ``btmp`` either (Debian 13),
        whether or not an old or empty file is still there."""
        return ctx.exists(SYSTEMD) and not ctx.exists(UTMP)

    def collect(self, ctx: Context) -> list[Item]:
        shape = records.layout()
        if shape is None:  # a 64-bit machine whose record layout is not known
            raise parse_error("sec_logins")
        if not ctx.exists(UTMP) and (not ctx.exists(BTMP) or ctx.file_size(BTMP) == 0):
            return [unrecorded_item()]
        found, capped = self._recent(ctx, ctx.now - WINDOW, shape)
        return [failed_item(attempts(found), capped)]

    @staticmethod
    def _recent(
        ctx: Context, since: int, shape: records.Layout
    ) -> "tuple[list[records.Failure], bool]":
        """The failures since ``since``, newest part of the file first; and whether the
        read stopped at ``MAX_RECORDS`` with older records of the window left unread."""
        size = ctx.file_size(BTMP)
        end = size - size % shape.utmp_size
        found: list[records.Failure] = []
        read = 0
        empty = 0
        while end > 0:
            if read >= MAX_RECORDS:
                return found, True
            count = min(CHUNK_RECORDS, MAX_RECORDS - read, end // shape.utmp_size)
            start = end - count * shape.utmp_size
            part = list(
                records.btmp_failures(ctx.read_slice(BTMP, start, end - start), ctx.now, shape)
            )
            read += count
            end = start
            oldest: Optional[int] = min((f.started for f in part), default=None)
            found.extend(f for f in part if f.started >= since)
            if oldest is not None and oldest < since:
                break
            empty = empty + 1 if oldest is None else 0
            if empty >= MAX_EMPTY_PARTS:
                break
        return found, False

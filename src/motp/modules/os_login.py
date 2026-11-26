"""``os_login``: each account's previous login, for its own per-user file (D32, O3).

Runs as a cached module in a probe process **as root**, the first that does: the login
records are not readable by the user ``motp`` everywhere, and only root may decide which
account sees which record. Every file it reads goes through the ownership check of the
probe context (``collect.context``), so no other user can make it read a file of their
choosing.

**Source (O3, decided in phase 10).** ``/var/log/lastlog``: one fixed-size record per
uid at ``uid * 292``, written by the login programs (sshd, ``login`` through
``pam_lastlog``) and by nothing else, so a terminal multiplexer's panes do not count as
logins. It is indexed by uid, so no name has to be looked up to find a record, and it is
not rotated. The file is sparse; only the parts that hold data are read
(``Context.data_regions``). Where it is missing, is not a whole number of this machine's
records, or holds no record of the last ``RECENT_DAYS``, ``/var/log/wtmp`` is read
instead (its newest records, matched to accounts by name). The four tier-1 test images
keep both files; Fedora 45 also keeps ``lastlog2``'s SQLite database, which is not read
(decision log, phase 10). A file that exists but cannot be read fails the module.

**Accounts.** A record counts only for an account that exists now: the local
``/etc/passwd``, then one ``getent passwd`` call for the uids or names it does not hold
(directory accounts through the system's name service; ``getent`` exits 2 when some are
unknown). An account that no longer exists gets no file, and the collector removes its old
one. Records older than ``RECENT_DAYS`` are left out, and at most ``MAX_USERS`` accounts,
the most recent first, get a file.

The module returns no items: nothing it reads reaches ``public.json`` or ``admin.json``.
Its per-user data travels in the probe document's ``users`` field, which only this module
may send (``core.probe.PER_USER_MODULES``).
"""

import re
from collections.abc import Iterable, Mapping

from motp.core.model import Item, Login, UserLogins, Visibility
from motp.modules import records
from motp.modules.base import CACHED, Context, Detection, parse_error

LASTLOG = "/var/log/lastlog"
WTMP = "/var/log/wtmp"
PASSWD = "/etc/passwd"  # noqa: S105  (a file name, not a password)
GETENT = "/usr/bin/getent"
RECENT_DAYS = 90
DAY = 86400
MAX_USERS = 256  # core.probe.MAX_USERS
MAX_LOGINS = 3  # core.cache.MAX_LOGINS
# lastlog: 8 MiB of data regions. Contiguous uids give about 28,000 records; directory
# accounts at scattered uids cost a file system block each, so about 1,900 (a lastlog with
# more fails the module, which keeps its old files). wtmp: its newest 10,000 records.
MAX_LASTLOG_BYTES = 8 * 1024 * 1024
MAX_WTMP_RECORDS = 10_000
MAX_PASSWD_BYTES = 1024 * 1024  # the most a probe context reads at once
GETENT_BATCH = 64
MAX_UID = 2**32 - 2

_UID = re.compile(r"[0-9]{1,10}\Z")


def local_accounts(text: str) -> dict[int, str]:
    """uid -> name from ``/etc/passwd``; lines that do not fit are skipped."""
    accounts: dict[int, str] = {}
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) < 7 or not records.USER_NAME.match(parts[0]) or not _UID.match(parts[2]):
            continue
        uid = int(parts[2])
        if uid <= MAX_UID:
            accounts.setdefault(uid, parts[0])
    return accounts


def parse_getent(text: str) -> dict[int, str]:
    """uid -> name from ``getent passwd`` output, the same shape as ``/etc/passwd``."""
    return local_accounts(text)


class OsLogin:
    name = "os_login"
    section = "login"
    mode = CACHED
    needs_root = True
    interval = 300  # every run: a login shows the one before it
    max_age = 3600
    timeout = 10.0
    binaries: tuple[str, ...] = (GETENT,)
    default_visibility = Visibility.ADMIN

    def detect(self, ctx: Context) -> Detection:
        return Detection(ctx.exists(LASTLOG) or ctx.exists(WTMP))

    def collect(self, ctx: Context) -> list[Item]:
        return []

    def collect_users(self, ctx: Context) -> tuple[UserLogins, ...]:
        """The accounts that get a per-user file, the most recent login first.

        A record file that does not exist moves on to the next source; one that exists
        but cannot be read (the ownership check refused it, a read error) fails the
        module, so the collector keeps the files it has instead of removing every one
        (review of phase 10).
        """
        shape = records.layout()
        if shape is None:  # a 64-bit machine whose record layout is not known
            raise parse_error("os_login")
        since = ctx.now - RECENT_DAYS * DAY
        local = self._local(ctx)
        by_uid = self._from_lastlog(ctx, since, shape)
        if by_uid:
            unknown = sorted(
                (uid for uid in by_uid if uid not in local), key=lambda u: -by_uid[u][0].started
            )
            known = self._lookup(ctx, [str(uid) for uid in unknown[: MAX_USERS * 2]])
            by_uid = {u: logins for u, logins in by_uid.items() if u in local or u in known}
        else:  # no lastlog, or none of its records is recent: wtmp
            by_uid = self._from_wtmp(ctx, since, local, shape)
        newest = sorted(by_uid.items(), key=lambda kv: (-kv[1][0].started, kv[0]))
        return tuple(
            UserLogins(uid=uid, generated=ctx.now, logins=tuple(logins[:MAX_LOGINS]))
            for uid, logins in newest[:MAX_USERS]
        )

    # -- the parts ---------------------------------------------------------------------

    @staticmethod
    def _local(ctx: Context) -> dict[int, str]:
        return local_accounts(ctx.read_text(PASSWD, MAX_PASSWD_BYTES))

    @staticmethod
    def _lookup(ctx: Context, keys: "list[str]") -> dict[int, str]:
        """Accounts the name service knows, by uid or name; ``{}`` when it cannot say."""
        found: dict[int, str] = {}
        for start in range(0, len(keys), GETENT_BATCH):
            batch = keys[start : start + GETENT_BATCH]
            try:
                out = ctx.run((GETENT, "passwd", "--", *batch), ok_codes=(0, 2))
            except ValueError:
                return found
            found.update(parse_getent(out.decode("utf-8", "replace")))
        return found

    @staticmethod
    def _from_lastlog(ctx: Context, since: int, shape: records.Layout) -> "dict[int, list[Login]]":
        """uid -> its one record from lastlog; ``{}`` without a usable lastlog."""
        if not ctx.exists(LASTLOG):
            return {}
        size = ctx.file_size(LASTLOG)
        if size % shape.lastlog_size:  # another layout than this machine's: not usable
            return {}
        regions = ctx.data_regions(LASTLOG, shape.lastlog_size, MAX_LASTLOG_BYTES)
        found: dict[int, list[Login]] = {}
        for uid, record in records.lastlog_entries(regions, ctx.now, since, shape):
            if uid <= MAX_UID:
                found[uid] = [Login(record.started, record.host, record.line)]
        return found

    def _from_wtmp(
        self, ctx: Context, since: int, local: Mapping[int, str], shape: records.Layout
    ) -> "dict[int, list[Login]]":
        """uid -> its newest records from wtmp's newest part; ``{}`` without wtmp."""
        if not ctx.exists(WTMP):
            return {}
        size = ctx.file_size(WTMP)
        end = size - size % shape.utmp_size
        start = max(0, end - MAX_WTMP_RECORDS * shape.utmp_size)
        data = ctx.read_slice(WTMP, start, end - start) if end > start else b""
        by_name: dict[str, list[Login]] = {}
        for record in records.utmp_logins(data, ctx.now, shape):
            if record.started >= since:
                by_name.setdefault(record.user, []).append(
                    Login(record.started, record.host, record.line)
                )
        names = {name: uid for uid, name in local.items()}
        unknown = sorted(
            (n for n in by_name if n not in names),
            key=lambda n: -max(login.started for login in by_name[n]),
        )
        for uid, name in self._lookup(ctx, unknown[: MAX_USERS * 2]).items():
            names.setdefault(name, uid)
        found: dict[int, list[Login]] = {}
        for name, logins in by_name.items():
            if name in names:
                found.setdefault(names[name], []).extend(_newest(logins))
        return {uid: _newest(logins) for uid, logins in found.items()}


def _newest(logins: Iterable[Login]) -> "list[Login]":
    return sorted(logins, key=lambda login: login.started, reverse=True)[:MAX_LOGINS]

"""``os_sessions``: who is logged in now (blueprint 4.3, 5.4, phase 10).

Runs as a cached module in a probe process as the user ``motp``.

The source is ``/run/utmp``, the file ``who`` reads: every login program writes a
``USER_PROCESS`` record there for each terminal session and clears it at logout. It exists
on every tier-1 image and is readable by everyone. systemd-logind keeps its own list in
``/run/systemd/sessions``, but in the test containers it held sessions on Fedora only,
and logind is missing on systems without systemd; utmp is the one source all have.
Terminal multiplexers and terminal emulators that register their panes in utmp
(``utempter``) are counted too, as ``who`` counts them.

Debian 13 builds systemd without utmp, so ``/run/utmp`` does not exist there (phase 14).
On a system with systemd and no ``/run/utmp`` the row says "not recorded on this system"
instead of disappearing; logind's own list is a candidate source after 1.0.

The number of sessions is public; user names, hosts and terminals are for admins only
(5.4). User names and hosts are untrusted text (5.5): the record parser sanitises them.
"""

from motp.core.model import Detail, Item, Status, Unit, Visibility, ref
from motp.core.sanitize import sanitize
from motp.modules import packages, records
from motp.modules.base import CACHED, Context, Detection, parse_error

UTMP = "/run/utmp"
SYSTEMD = "/run/systemd/system"
# Characters the admin list uses to separate entries; a host cannot fake an entry with them.
LIST_MARKS = str.maketrans({",": "_", "(": "_", ")": "_"})
# utmp holds one record per terminal line in use; this is far more than any system has.
MAX_UTMP_BYTES = records.UTMP_SIZE * 4096
ENTRY_CELLS = 48  # one "user (host)" entry of the admin list


def entry(record: records.Record) -> str:
    where = (record.host or record.line).translate(LIST_MARKS)
    return sanitize(f"{record.user} ({where})" if where else record.user, ENTRY_CELLS)


def sessions_item(sessions: "list[records.Record]") -> Item:
    newest_first = sorted(sessions, key=lambda r: r.started, reverse=True)
    details: tuple[Detail, ...] = ()
    if newest_first:
        listed = packages.name_list(entry(r) for r in newest_first)
        details = (Detail("os_sessions.users", listed, label=ref("label.session_users")),)
    return Item(
        key="os_sessions.count",
        value=len(sessions),
        unit=Unit.COUNT,
        label=ref("label.sessions"),
        text=ref("sessions.count", count=len(sessions)),
        detail=details,
    )


def unrecorded_item() -> Item:
    """The row on a systemd system without ``/run/utmp``: no count, and saying why."""
    return Item(
        key="os_sessions.count",
        value=None,
        unit=Unit.TEXT,
        label=ref("label.sessions"),
        status=Status.UNKNOWN,
        text=ref("records.not_recorded"),
    )


class OsSessions:
    name = "os_sessions"
    section = "login"
    mode = CACHED
    needs_root = False
    interval = 300
    max_age = 1800
    timeout = 5.0
    binaries: tuple[str, ...] = ()
    default_visibility = Visibility.PUBLIC

    def detect(self, ctx: Context) -> Detection:
        return Detection(ctx.exists(UTMP) or ctx.exists(SYSTEMD))

    def collect(self, ctx: Context) -> list[Item]:
        shape = records.layout()
        if shape is None:  # a 64-bit machine whose record layout is not known
            raise parse_error("os_sessions")
        if not ctx.exists(UTMP):
            return [unrecorded_item()]
        size = min(ctx.file_size(UTMP), MAX_UTMP_BYTES)
        data = ctx.read_slice(UTMP, 0, size) if size else b""
        return [sessions_item(list(records.utmp_logins(data, ctx.now, shape)))]

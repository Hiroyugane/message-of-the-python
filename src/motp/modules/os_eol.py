"""``os_eol``: how long the OS release gets security updates (blueprint 4.3, 5.4: public).

Runs as a cached module in a probe process as the user ``motp``. Two sources, both local:

1. ``SUPPORT_END`` in ``os-release`` (os-release(5)), which Fedora and the RHEL rebuilds
   set. It comes with the system and is updated with it.
2. Otherwise the table in ``data/eol.toml``, which ships with MOTP and carries the date
   it was last checked. That date is part of the text, so a reader sees how old the
   knowledge is.

A release that neither source knows (a newer one, testing, a derivative) gets no row. The
row warns ``WARN_DAYS`` before the end and is critical after it.
"""

import datetime
import functools
import re
from collections.abc import Mapping
from typing import Optional

from motp.core import resources
from motp.core.model import HintRef, Item, MessageRef, Status, Visibility, ref
from motp.modules.base import CACHED, OS_RELEASE_FILES, Context, Detection

TABLE_RESOURCE = "data/eol.toml"
WARN_DAYS = 90
# os-release ID -> (table, whether the table is keyed by the major version alone)
TABLES = {
    "debian": ("debian", False),
    "raspbian": ("debian", False),
    "ubuntu": ("ubuntu", False),
    "almalinux": ("almalinux", True),
    "rocky": ("rocky", True),
    "rhel": ("rhel", True),
    "fedora": ("fedora", False),
}
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}\Z")
# The two kinds of line the table has: ``[name]`` and ``key = "value"``.
_SECTION = re.compile(r"\[([a-z]+)\]\Z")
_ENTRY = re.compile(r'(?:"([0-9.]+)"|([a-z]+)) = "([^"\\]*)"\Z')

Table = dict[str, dict[str, str]]


def parse_date(text: object) -> Optional[datetime.date]:
    """``YYYY-MM-DD`` as a date; anything else is ``None``."""
    if type(text) is not str or not _DATE.match(text):
        return None
    try:
        return datetime.date.fromisoformat(text)
    except ValueError:
        return None


def parse_table(text: str) -> Table:
    """The small part of TOML that ``data/eol.toml`` uses; entries before the first
    ``[name]`` are in the section ``""``. Any other line is a packaging bug.

    A TOML parser is not imported: the registry reaches this module, and what
    ``motp show`` can reach stays small (invariant 6). A test compares the result with
    a real parser's.
    """
    found: Table = {"": {}}
    section = found[""]
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        header, entry = _SECTION.match(line), _ENTRY.match(line)
        if header:
            section = found.setdefault(header.group(1), {})
        elif entry:
            section[entry.group(1) or entry.group(2)] = entry.group(3)
        else:
            raise RuntimeError("eol.toml has a line of an unknown shape")
    return found


@functools.cache
def table() -> Table:
    """The bundled table. A broken one is a packaging bug and raises."""
    data = resources.read(TABLE_RESOURCE)
    if data is None:
        raise RuntimeError("eol.toml missing")
    return parse_table(data.decode("utf-8"))


def end_of_support(
    release: Mapping[str, str], data: Table
) -> "tuple[Optional[datetime.date], Optional[str]]":
    """The last day of support, and the table's date when the table supplied it."""
    own = parse_date(release.get("SUPPORT_END"))
    if own is not None:
        return own, None
    known = TABLES.get(release.get("ID", ""))
    if known is None:
        return None, None
    name, by_major = known
    version = release.get("VERSION_ID", "")
    if by_major:
        version = version.split(".", 1)[0]
    end = parse_date(data.get(name, {}).get(version))
    return (end, data[""].get("date", "")) if end is not None else (None, None)


def summary(status: Status, end: str, data_date: Optional[str]) -> MessageRef:
    """The row's text. Each id is spelled out for the catalogue test (invariant 5)."""
    if data_date is None:
        if status is Status.CRIT:
            return ref("eol.ended", date=end)
        if status is Status.WARN:
            return ref("eol.ending", date=end)
        return ref("eol.supported", date=end)
    if status is Status.CRIT:
        return ref("eol.ended_table", date=end, data=data_date)
    if status is Status.WARN:
        return ref("eol.ending_table", date=end, data=data_date)
    return ref("eol.supported_table", date=end, data=data_date)


class OsEol:
    name = "os_eol"
    section = "system"
    mode = CACHED
    needs_root = False
    interval = 3600
    max_age = 7 * 86400
    timeout = 5.0
    binaries: tuple[str, ...] = ()
    default_visibility = Visibility.PUBLIC

    def detect(self, ctx: Context) -> Detection:
        return Detection(any(ctx.exists(path) for path in OS_RELEASE_FILES))

    def collect(self, ctx: Context) -> list[Item]:
        end, data_date = end_of_support(ctx.os_release, table())
        if end is None:
            return []
        today = datetime.datetime.fromtimestamp(ctx.now, datetime.timezone.utc).date()
        left = (end - today).days
        if left < 0:
            status = Status.CRIT
        elif left <= WARN_DAYS:
            status = Status.WARN
        else:
            status = Status.OK
        return [
            Item(
                key="os_eol.date",
                value=end.isoformat(),
                label=ref("label.eol"),
                status=status,
                text=summary(status, end.isoformat(), data_date),
                hint=HintRef("os.eol"),
            )
        ]

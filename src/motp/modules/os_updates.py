"""``os_updates``: pending updates and security updates, from local state only (D28).

Runs as a cached module in a probe process as the user ``motp``. Nothing here refreshes
package lists or contacts a mirror: the counts are what the system's own timers (or the
admin) last downloaded, and the unit gives the probe no network anyway (D25).

* **apt:** ``apt-get -s upgrade --with-new-pkgs``, a simulation of what ``apt upgrade``
  would do. Each ``Inst name [old] (new origin, origin [arch])`` line is one update; it is
  a security update when one of its origins is a ``-security`` suite or the
  ``Debian-Security`` label. The number of such lines must match apt's own summary line,
  so output that was cut or has another shape fails the module instead of undercounting.
  Ubuntu's ``updates-available`` stamp file is not read: its text is written for people,
  differs between releases and follows the system's language.
* **dnf 4 and dnf 5:** ``check-update`` (``check-upgrade``) in cache-only mode, once for
  everything and once with ``--security``. Exit code 100 means updates are pending.
  dnf 4 reads the system's cache on its own; dnf 5 looks in the user's home, so it is
  pointed at the system cache and given a log directory (the probe user has no home).
  It is also told not to build its index files: after a plain ``dnf makecache`` some are
  missing, and dnf 5 fails when it cannot write them into the system cache. The log
  directory is a new one for each run.

**When security updates cannot be told apart** (no apt list of a ``-security`` suite, as
on 32-bit Raspberry Pi OS, which ships security fixes in its main archive; no dnf
repository with advisory data), every pending update may be one: the row warns and says
so. Packages apt holds back are shown, never counted as pending, and "none pending" is not
said while there are any.

Without any downloaded list there is nothing to count: apt would report "0 upgraded", so
the module checks first and says that it does not know. When the lists are older than
``LISTS_OLD`` a row says how old they are (D28).

The counts are public; the package names are an admin-only detail (blueprint 5.4).
"""

import re
from dataclasses import dataclass, replace
from typing import Optional

from motp.core.model import Detail, HintRef, Item, Status, Unit, Visibility, ref
from motp.modules import packages
from motp.modules.base import CACHED, Context, Detection, parse_error

APT_ARGV = (
    packages.APT_GET,
    "-s",
    "-q",
    "-o",
    "Debug::NoLocking=true",
    "upgrade",
    "--with-new-pkgs",
)
DNF4_ARGV = (packages.DNF, "-C", "-q", "check-update")
DNF5_ARGV = (
    packages.DNF5_PROGRAM,
    "-C",
    "-q",
    "--setopt=cachedir=/var/cache/libdnf5",
    "--setopt=build_cache=false",
    "check-upgrade",
)
SECURITY_FLAG = "--security"
DNF_UPDATES_PENDING = 100

APT_LISTS = "/var/lib/apt/lists"
# Each changes when apt refreshes its lists. The files in the lists directory keep the
# server's time, so their own age says nothing about the last refresh.
APT_REFRESH_MARKS = (
    APT_LISTS,
    APT_LISTS + "/partial",
    "/var/lib/apt/periodic/update-success-stamp",
)
DNF_CACHES = {packages.DNF4: "/var/cache/dnf", packages.DNF5: "/var/cache/libdnf5"}
LISTS_OLD = 7 * 86400  # the systems' own timers refresh daily or more often
MAX_LINE = 1024

_APT_SUMMARY = re.compile(
    r"([0-9]{1,6}) upgraded, [0-9]{1,6} newly installed, [0-9]{1,6} to remove "
    r"and ([0-9]{1,6}) not upgraded\.\Z"
)
# Inst name [installed] (candidate origin[, origin] [arch]) [markers apt may append]
_APT_INST = re.compile(
    r"Inst (?P<name>\S+)(?P<old> \[[^\]]*\])? \(\S+ (?P<origins>[^()\[\]]*)"
    r"\[[A-Za-z0-9_-]+\]\)(?: \[[^\]]*\])*\s*\Z"
)
_RPM_PACKAGE = re.compile(r"(?P<name>[A-Za-z0-9_][A-Za-z0-9+._~-]{0,190})\.[A-Za-z0-9_]{1,16}\Z")
_RPM_VERSION = re.compile(r"(?:[0-9]{1,10}:)?[A-Za-z0-9+._~^]{1,128}-[A-Za-z0-9+._~^]{1,128}\Z")
_RPM_REPO = re.compile(r"@?[A-Za-z0-9_.:+-]{1,200}\Z")
_DNF_HEADERS = ("Upgrades", "Available upgrades", "Available Upgrades")
_DNF_NOTES = ("Security: ",)


@dataclass(frozen=True)
class Update:
    name: str
    security: bool


def _security_origin(origins: str) -> bool:
    """``Ubuntu:22.04/jammy-security`` or ``Debian-Security:12/oldstable-security``."""
    for origin in origins.split(","):
        origin = origin.strip()
        if origin.endswith("-security") or origin.startswith("Debian-Security:"):
            return True
    return False


def dnf5_argv(log_dir: str) -> tuple[str, ...]:
    """dnf 5's command with its log directory (the probe user has no home)."""
    return (*DNF5_ARGV[:3], f"--setopt=logdir={log_dir}", *DNF5_ARGV[3:])


def parse_apt(text: str) -> "tuple[list[Update], int]":
    """The updates of a simulated ``apt-get upgrade`` and the number of packages held
    back; ``ValueError`` on another shape."""
    updates: list[Update] = []
    expected = None
    held = 0
    for line in text.split("\n"):
        summary = _APT_SUMMARY.match(line)
        if summary:
            expected, held = int(summary.group(1)), int(summary.group(2))
        if not line.startswith("Inst "):
            continue
        match = _APT_INST.match(line) if len(line) <= MAX_LINE else None
        if match is None or not packages.PACKAGE_NAME.match(match.group("name")):
            raise parse_error("os_updates")
        if match.group("old") is not None:  # without it, a new dependency, not an update
            updates.append(Update(match.group("name"), _security_origin(match.group("origins"))))
    if expected is None or expected != len(updates):
        raise parse_error("os_updates")
    return updates, held


def parse_dnf(text: str) -> list[str]:
    """The ``name.arch`` of each pending update; ``ValueError`` on another shape.

    An entry is three fields (package, version, repository). dnf 4 wraps long entries
    onto further lines, so the fields are collected across lines. The list of obsoleting
    packages that may follow is not a list of updates.
    """
    found: dict[str, None] = {}
    fields: list[str] = []
    for line in text.split("\n"):
        if line.startswith("Obsoleting "):
            break
        if line.strip() in _DNF_HEADERS or line.startswith(_DNF_NOTES):
            continue
        if len(line) > MAX_LINE:
            raise parse_error("os_updates")
        fields += line.split()
        if len(fields) < 3:
            continue
        if (
            len(fields) != 3
            or not _RPM_PACKAGE.match(fields[0])
            or not _RPM_VERSION.match(fields[1])
            or not _RPM_REPO.match(fields[2])
        ):
            raise parse_error("os_updates")
        found[fields[0]] = None  # an install-only package can be listed twice
        fields = []
    if fields:
        raise parse_error("os_updates")
    return list(found)


def _text(argv: tuple[str, ...], ctx: Context, ok_codes: tuple[int, ...] = (0,)) -> str:
    return ctx.run(argv, ok_codes=ok_codes).decode("utf-8", "replace")


def _newest(ctx: Context, paths: "list[str]") -> "int | None":
    times = []
    for path in paths:
        try:
            times.append(ctx.mtime(path))
        except ValueError:
            continue
    return max(times) if times else None


@dataclass(frozen=True)
class Lists:
    """What is known about the downloaded package lists."""

    present: bool = False
    refreshed: Optional[int] = None  # when they were last refreshed
    security: bool = False  # they can tell which updates are security updates


def apt_lists(ctx: Context) -> Lists:
    try:
        names = ctx.list_dir(APT_LISTS)
    except ValueError:
        return Lists()
    if not any("_Packages" in name for name in names):
        return Lists()
    security = any("-security_" in name for name in names)
    return Lists(True, _newest(ctx, list(APT_REFRESH_MARKS)), security)


def _has_advisories(ctx: Context, repodata: str) -> bool:
    try:
        return any("updateinfo" in name for name in ctx.list_dir(repodata))
    except ValueError:
        return False


def dnf_lists(ctx: Context, manager: str) -> Lists:
    base = DNF_CACHES[manager]
    try:
        names = ctx.list_dir(base)
    except ValueError:
        return Lists()
    marks: list[str] = []
    present = security = False
    for name in names:
        repodata = f"{base}/{name}/repodata"
        try:
            if not ctx.exists(f"{repodata}/repomd.xml"):
                continue
        except ValueError:
            continue  # a name that does not make a normalised path
        present = True
        security = security or _has_advisories(ctx, repodata)
        marks.append(f"{repodata}/repomd.xml")
        if manager == packages.DNF5:
            marks.append(f"{base}/{name}")  # dnf 5 touches the directory on a refresh
    return Lists(present, _newest(ctx, marks), security)


def collect_apt(ctx: Context) -> "tuple[list[Update], int]":
    return parse_apt(_text(APT_ARGV, ctx))


def collect_dnf(ctx: Context, argv: tuple[str, ...]) -> list[Update]:
    codes = (0, DNF_UPDATES_PENDING)
    pending = parse_dnf(_text(argv, ctx, codes))
    secure: set[str] = set()
    if pending:
        secure = set(parse_dnf(_text((*argv, SECURITY_FLAG), ctx, codes)))
    return [Update(_RPM_PACKAGE.sub(r"\g<name>", p), p in secure) for p in pending]


def updates_item(updates: "list[Update]", split: bool = True, held: int = 0) -> Item:
    """One row: the counts for everyone, the names (security first) for admins.

    ``split`` says that security updates can be told apart on this system.
    """
    total = len(updates)
    security = sum(1 for u in updates if u.security)
    unsure = bool(total) and not security and not split
    if security:
        text = ref("updates.summary", count=total, security=security)
    elif unsure:
        text = ref("updates.unsplit", count=total)
    elif total:
        text = ref("updates.plain", count=total)
    elif held:
        text = ref("updates.held_only", count=held)
    else:
        text = ref("updates.none")
    details: list[Detail] = []
    if total:
        ordered = sorted(updates, key=lambda u: (not u.security, u.name))
        names = packages.name_list(dict.fromkeys(u.name for u in ordered))
        details.append(
            Detail("os_updates.packages", names, label=ref("label.packages"))
        )  # admin-only by default
    if total and held:
        details.append(
            Detail(
                "os_updates.held",
                held,
                unit=Unit.COUNT,
                label=ref("label.held_back"),
                visibility=Visibility.PUBLIC,
            )
        )
    return Item(
        key="os_updates.pending",
        value=total,
        unit=Unit.COUNT,
        label=ref("label.updates"),
        # Security updates, or updates that may be some, ask for attention; others are a
        # fact in the system block.
        status=Status.WARN if security or unsure else Status.OK,
        text=text,
        hint=HintRef("updates.security" if security else "updates.install"),
        detail=tuple(details),
    )


def unknown_item() -> Item:
    return Item(
        key="os_updates.pending",
        value=None,
        unit=Unit.COUNT,
        label=ref("label.updates"),
        status=Status.UNKNOWN,
        text=ref("updates.no_lists"),
    )


class OsUpdates:
    name = "os_updates"
    section = "system"
    mode = CACHED
    needs_root = False
    interval = 900
    max_age = 86400
    timeout = 30.0  # apt on a small board, or dnf twice with large repositories
    binaries: tuple[str, ...] = (packages.APT_GET, packages.DNF, packages.DNF5_PROGRAM)
    default_visibility = Visibility.PUBLIC

    def detect(self, ctx: Context) -> Detection:
        return Detection(bool(packages.backend(ctx)))

    def collect(self, ctx: Context) -> list[Item]:
        manager = packages.backend(ctx)
        if not manager:
            return []
        lists = apt_lists(ctx) if manager == packages.APT else dnf_lists(ctx, manager)
        if not lists.present:
            return [unknown_item()]
        held = 0
        if manager == packages.APT:
            updates, held = collect_apt(ctx)
        elif manager == packages.DNF5:
            with ctx.scratch_dir() as log_dir:
                updates = collect_dnf(ctx, dnf5_argv(log_dir))
        else:
            updates = collect_dnf(ctx, DNF4_ARGV)
        item = updates_item(updates, lists.security, held)
        refreshed = lists.refreshed
        if refreshed is not None and ctx.now - refreshed > LISTS_OLD and refreshed >= 0:
            age = Detail(
                "os_updates.lists",
                refreshed,
                unit=Unit.TIMESTAMP,
                label=ref("label.package_lists"),
                visibility=Visibility.PUBLIC,
            )
            item = replace(item, detail=(*item.detail, age))
        return [item]

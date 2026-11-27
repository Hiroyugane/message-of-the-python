"""``sec_fail2ban``: fail2ban's jails and current bans (blueprint 4.3, 5.4, D12, phase 11).

Runs as a cached module in a probe process **as root**: fail2ban's socket
(``/run/fail2ban/fail2ban.sock``) is root's alone. The module never speaks that socket's
protocol itself (it is Python's ``pickle``, which MOTP does not load, invariant 1); it
starts fail2ban's own client with two fixed, read-only commands:

    fail2ban-client status
    fail2ban-client status <jail>

``status`` answers and changes nothing. Each jail name comes from the first answer and
must look like a jail name (``JAIL``, never starting with ``-``) before it becomes an
argument, after the command word, so it can never be read as an option or as another
command. Nothing else of the client is used; the module does not read or write fail2ban's
database. The client and its interpreter pass the ownership check like every program a
probe starts, run without a shell, with an environment built from scratch and the
probe's deadline; a server that never answers ends the probe at its time limit.

Where the client exists but the server is not running (no socket), the module says so to
admins instead of failing. The client is a Python script; the probe context starts it as
root only if every directory its interpreter imports from is root's alone
(``core.importpath``, final review). Otherwise nothing runs and admins see "not checked"
with a hint to ``motp doctor``, which names the directory that failed.

**What leaves the probe.** The number of current bans of all jails, public (5.4). For
admins, one row for each of the 15 jails with the most bans: the jail name and the banned
addresses (each checked to be an address or network, anything else is dropped). At most
64 jails are asked; a system with more fails the module.
"""

import ipaddress
import re

from motp.core.model import Detail, HintRef, Item, Status, Unit, Visibility, ref
from motp.core.sanitize import sanitize
from motp.modules.base import CACHED, Context, Detection, ImportPathError, parse_error

CLIENT = "/usr/bin/fail2ban-client"
SOCKET = "/run/fail2ban/fail2ban.sock"
JAIL = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.@+-]{0,63}\Z")
MAX_JAILS = 64  # each one a client start of about 0.2 s; more fail the module
MAX_ROWS = 15  # detail rows: the jails with the most bans, under the protocol's 16
ADDRESS_LIST_CHARS = 100
JAIL_CELLS = 32
_NUMBER = re.compile(r"[0-9]{1,9}\Z")


def _field(text: str, name: str) -> "list[str]":
    """The values after ``name:`` on the lines of a ``status`` answer."""
    found = []
    for line in text.splitlines():
        head, colon, value = line.partition(":")
        if colon and head.strip(" |`-\t") == name:
            found.append(value.strip())
    return found


def parse_jails(text: str) -> "list[str]":
    """The jail names of ``fail2ban-client status``; an answer of another shape fails."""
    counts = _field(text, "Number of jail")
    lists = _field(text, "Jail list")
    if len(counts) != 1 or len(lists) != 1 or not _NUMBER.match(counts[0]):
        raise parse_error("sec_fail2ban")
    names = [n.strip() for n in lists[0].split(",") if n.strip()]
    if len(names) != int(counts[0]) or len(names) > MAX_JAILS:
        raise parse_error("sec_fail2ban")
    if any(not JAIL.match(name) for name in names):
        raise parse_error("sec_fail2ban")
    return names


def parse_jail(text: str) -> "tuple[int, list[str], int]":
    """``(current bans, banned addresses, entries that were not an address)``."""
    current = _field(text, "Currently banned")
    lists = _field(text, "Banned IP list")
    if len(current) != 1 or len(lists) != 1 or not _NUMBER.match(current[0]):
        raise parse_error("sec_fail2ban")
    addresses: list[str] = []
    dropped = 0
    for word in lists[0].split():
        try:
            network = ipaddress.ip_network(word, strict=False)
        except ValueError:
            dropped += 1
            continue
        single = network.num_addresses == 1
        addresses.append(str(network.network_address) if single else str(network))
    return int(current[0]), addresses, dropped


def address_list(addresses: "list[str]") -> str:
    """As many addresses as fit, then ``+N`` for the rest (no word: no translation)."""
    shown: list[str] = []
    length = 0
    for address in addresses:
        length += len(address) + 2
        if shown and length > ADDRESS_LIST_CHARS:
            break
        shown.append(address)
    if len(shown) < len(addresses):
        shown.append(f"+{len(addresses) - len(shown)}")
    return ", ".join(shown)


def banned_item(jails: "list[tuple[str, int, list[str]]]") -> Item:
    """The ban count of all jails; a row each for the ``MAX_ROWS`` jails with the most."""
    total = sum(count for _name, count, _addresses in jails)
    banning = sorted((j for j in jails if j[1]), key=lambda j: (-j[1], j[0]))[:MAX_ROWS]
    detail = tuple(
        Detail(
            f"sec_fail2ban.jail{index}",
            address_list(addresses) if addresses else str(count),
            label=ref("label.jail", jail=sanitize(name, JAIL_CELLS)),
        )
        for index, (name, count, addresses) in enumerate(banning)
    )
    return Item(
        key="sec_fail2ban.banned",  # gitleaks:allow (an item key, not a secret)
        value=total,
        unit=Unit.COUNT,
        label=ref("label.fail2ban"),
        status=Status.OK,
        text=ref("fail2ban.banned", count=total),
        visibility=Visibility.PUBLIC,
        detail=detail,
    )


def not_running_item() -> Item:
    return Item(
        key="sec_fail2ban.running",
        value=False,
        unit=Unit.BOOL,
        label=ref("label.fail2ban"),
        status=Status.WARN,
        text=ref("fail2ban.not_running"),
        visibility=Visibility.ADMIN,
        hint=HintRef("fail2ban.status"),
    )


def not_checked_item() -> Item:
    """The client is a Python script whose import path others could change: not started.

    The row does not name the directory; ``motp doctor``, which the hint names, does.
    """
    return Item(
        key="sec_fail2ban.running",
        value=None,
        unit=Unit.BOOL,
        label=ref("label.fail2ban"),
        status=Status.UNKNOWN,
        text=ref("fail2ban.not_checked"),
        visibility=Visibility.ADMIN,
        hint=HintRef("import_path.check"),
    )


class SecFail2ban:
    name = "sec_fail2ban"
    section = "security"
    mode = CACHED
    needs_root = True
    interval = 300
    max_age = 1800
    timeout = 15.0  # one client start per jail, each a Python start of about 0.2 s
    binaries: tuple[str, ...] = (CLIENT,)
    default_visibility = Visibility.PUBLIC

    def detect(self, ctx: Context) -> Detection:
        return Detection(ctx.exists(CLIENT))

    def collect(self, ctx: Context) -> list[Item]:
        if not ctx.exists(SOCKET):
            return [not_running_item()]
        try:
            first = ctx.run((CLIENT, "status"))
        except ImportPathError:
            return [not_checked_item()]
        names = parse_jails(first.decode("utf-8", "replace"))
        jails = []
        for name in names:
            answer = ctx.run((CLIENT, "status", name)).decode("utf-8", "replace")
            count, addresses, _dropped = parse_jail(answer)
            jails.append((name, count, addresses))
        return [banned_item(jails)]

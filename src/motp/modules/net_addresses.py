"""``net_addresses``: the host's own addresses and its DNS servers (blueprint 4.3, 5.4: public).

Runs as a cached module in a probe process as the user ``motp``. The collector may not
open sockets (D25, invariant 2), so the addresses come from ``/proc``:

* IPv4 from ``/proc/net/fib_trie``: every ``/32 host LOCAL`` entry is an address of this
  host;
* IPv6 from ``/proc/net/if_inet6``: global scope, neither tentative nor deprecated.

Loopback, link-local and unspecified addresses are left out. DNS servers are the
``nameserver`` lines of ``/run/systemd/resolve/resolv.conf`` when systemd-resolved keeps
one (its upstream servers), else of ``/etc/resolv.conf``. Every address is parsed with
``ipaddress`` and written in its normal form, so no other text from these files reaches
the cache.
"""

import ipaddress
from typing import Union

from motp.core.model import Item, Visibility, ref
from motp.modules.base import CACHED, Context, Detection

FIB_TRIE = "/proc/net/fib_trie"
IF_INET6 = "/proc/net/if_inet6"
RESOLVED_CONF = "/run/systemd/resolve/resolv.conf"
RESOLV_CONF = "/etc/resolv.conf"
MAX_ADDRESSES = 4  # shown in one row
MAX_DNS = 3  # resolv.conf uses at most three (MAXNS)
IFA_F_DEPRECATED = 0x20
IFA_F_TENTATIVE = 0x40
SCOPE_GLOBAL = 0x00

Address = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


def _shown(address: Address) -> bool:
    return not (
        address.is_loopback
        or address.is_link_local
        or address.is_unspecified
        or address.is_multicast
    )


def parse_fib_trie(text: str) -> list[ipaddress.IPv4Address]:
    """Local IPv4 addresses: a leaf ``|-- a.b.c.d`` followed by ``/32 host LOCAL``."""
    found: list[ipaddress.IPv4Address] = []
    leaf = ""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("|-- "):
            leaf = stripped[4:].strip()
        elif stripped.startswith("/32 host LOCAL") and leaf:
            try:
                address = ipaddress.IPv4Address(leaf)
            except ValueError:
                continue
            if _shown(address) and address not in found:
                found.append(address)
        elif not stripped.startswith("/"):
            leaf = ""
    return sorted(found)


def parse_if_inet6(text: str) -> list[ipaddress.IPv6Address]:
    """Global, settled IPv6 addresses: ``address index prefix scope flags name``."""
    found: list[ipaddress.IPv6Address] = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 6 or len(fields[0]) != 32:
            continue
        try:
            scope, flags = int(fields[3], 16), int(fields[4], 16)
            address = ipaddress.IPv6Address(int(fields[0], 16))
        except ValueError:
            continue
        if scope != SCOPE_GLOBAL or flags & (IFA_F_DEPRECATED | IFA_F_TENTATIVE):
            continue
        if _shown(address) and address not in found:
            found.append(address)
    return sorted(found)


def parse_nameservers(text: str) -> list[Address]:
    """``nameserver`` lines in file order; a zone index (``%eth0``) is dropped."""
    found: list[Address] = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 2 or fields[0] != "nameserver":
            continue
        try:
            address = ipaddress.ip_address(fields[1].split("%", 1)[0])
        except ValueError:
            continue
        if address not in found:
            found.append(address)
    return found[:MAX_DNS]


def _read(ctx: Context, path: str) -> str:
    try:
        return ctx.read_text(path)
    except ValueError:
        return ""


class NetAddresses:
    name = "net_addresses"
    section = "host"
    mode = CACHED
    needs_root = False
    interval = 300
    max_age = 3600
    timeout = 5.0
    binaries: tuple[str, ...] = ()
    default_visibility = Visibility.PUBLIC

    def detect(self, ctx: Context) -> Detection:
        return Detection(ctx.exists(FIB_TRIE) or ctx.exists(IF_INET6))

    def collect(self, ctx: Context) -> list[Item]:
        addresses: list[Address] = [*parse_fib_trie(_read(ctx, FIB_TRIE))]
        addresses += parse_if_inet6(_read(ctx, IF_INET6))
        items: list[Item] = []
        if addresses:
            text = ", ".join(str(a) for a in addresses[:MAX_ADDRESSES])
            items.append(Item(key="net_addresses.local", value=text, label=ref("label.address")))
        servers = parse_nameservers(_read(ctx, RESOLVED_CONF)) if ctx.exists(RESOLVED_CONF) else []
        if not servers:
            servers = parse_nameservers(_read(ctx, RESOLV_CONF))
        if servers:
            text = ", ".join(str(a) for a in servers)
            items.append(Item(key="net_addresses.dns", value=text, label=ref("label.dns")))
        return items

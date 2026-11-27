"""``sec_firewall``: whether a firewall is active (blueprint 4.3, 5.4, O12, phase 11).

**Source (O12, decided in phase 11).** Reading the packet filter's live rules needs
``CAP_NET_ADMIN`` (netlink asks for it even to list the nftables ruleset), which the
collector unit does not have and does not get. The module asks the service manager
instead, which is what each firewall itself uses to load its rules at boot:

* **ufw**: ``/etc/ufw/ufw.conf`` says ``ENABLED=yes`` and ``ufw.service`` is active or
  has not been stopped since boot. ``ufw enable`` loads the rules at once and sets that
  line without starting the service (measured on Ubuntu 22.04, phase 11); the one-shot
  service stays active after ``ufw disable``, so the line is needed; and ``systemctl stop
  ufw`` removes the rules but not the line, so a stopped unit is not active.
* **firewalld**: ``firewalld.service`` is active. Its default zone comes from
  ``/etc/firewalld/firewalld.conf`` where ``motp`` can read that file (not on the RHEL
  family, whose ``/etc/firewalld`` is 0750).
* **nftables**: ``nftables.service`` is active: the ruleset file was loaded.

One ``systemctl show`` reads the three units over the system bus, as ``motp``: nothing
here needs root, so the module does not run as root (a deviation from the blueprint's
table, decision log). A firewall unit that failed is an error; no active firewall is a
warning with the command that turns on the one that is installed. Rules loaded by other
means (a script, a container runtime) are not seen; ``motp explain firewall`` (phase 13)
says so.

**What leaves the probe.** Everything is for admins (5.4): which firewall protects the
machine is of use to whoever wants to get past it.
"""

import re
from typing import Optional

from motp.core.model import HintRef, Item, MessageRef, Status, Unit, Visibility, ref
from motp.core.sanitize import sanitize
from motp.modules import services
from motp.modules.base import CACHED, Context, Detection, parse_error

UFW_CONF = "/etc/ufw/ufw.conf"
FIREWALLD_CONF = "/etc/firewalld/firewalld.conf"
# (name, unit, hint id), in the order they are reported.
FIREWALLS = (
    ("ufw", "ufw.service", "firewall.ufw"),
    ("firewalld", "firewalld.service", "firewall.firewalld"),
    ("nftables", "nftables.service", "firewall.nftables"),
)
PROPERTIES = "Id,LoadState,ActiveState,SubState,InactiveEnterTimestampMonotonic"
ARGV = (
    services.SYSTEMCTL, "show", "--no-pager", f"--property={PROPERTIES}", "--",
    *(unit for _name, unit, _hint in FIREWALLS),
)  # fmt: skip
ZONE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}\Z")
ZONE_CELLS = 32
MAX_CONF = 64 * 1024


def conf_value(text: str, key: str) -> str:
    """The value of ``KEY=value`` in a shell-like config file; quotes removed."""
    value = ""
    for line in text.splitlines():
        name, eq, rest = line.strip().partition("=")
        if eq and name.strip() == key:
            value = rest.split("#", 1)[0].strip().strip("\"'")
    return value


def states(text: str) -> "dict[str, dict[str, str]]":
    """unit -> its properties, from the answer of ``ARGV``."""
    blocks = [b for b in re.split(r"\n\s*\n", text.strip("\n")) if b.strip()]
    if len(blocks) != len(FIREWALLS):
        raise parse_error("sec_firewall")
    found: dict[str, dict[str, str]] = {}
    for (_name, unit, _hint), block in zip(FIREWALLS, blocks):
        values: dict[str, str] = {}
        for line in block.splitlines():
            key, eq, value = line.partition("=")
            if eq and key in PROPERTIES.split(","):
                values[key] = value.strip()
        if values.get("Id") not in (unit, None):
            raise parse_error("sec_firewall")
        found[unit] = values
    return found


def ufw_active(ctx: Context, values: "dict[str, str]") -> bool:
    """``ENABLED=yes``, and the unit either active or never stopped since boot: ``ufw
    enable`` loads the rules without starting the unit, but ``systemctl stop ufw`` takes
    them away and leaves the file as it is (code review of phase 11)."""
    if conf_value(_read(ctx, UFW_CONF), "ENABLED").lower() != "yes":
        return False
    state = values.get("ActiveState")
    stopped = values.get("InactiveEnterTimestampMonotonic", "0") not in ("", "0")
    return state == "active" or (state == "inactive" and not stopped)


def firewall_item(ctx: Context, by_unit: "dict[str, dict[str, str]]") -> Item:
    """The first active firewall; else a failed one (error); else a warning. A failed
    unit beside an active firewall does not hide it (code review of phase 11)."""
    installed = [f for f in FIREWALLS if by_unit[f[1]].get("LoadState") == "loaded"]
    for name, unit, _hint in installed:
        if name == "ufw":
            if not ufw_active(ctx, by_unit[unit]):
                continue
        elif by_unit[unit].get("ActiveState") != "active":
            continue
        zone = conf_value(_read(ctx, FIREWALLD_CONF), "DefaultZone") if name == "firewalld" else ""
        if zone and ZONE.match(zone):
            text = ref("firewall.active_zone", name=name, zone=sanitize(zone, ZONE_CELLS))
        else:
            text = ref("firewall.active", name=name)
        return _item(True, Status.OK, text, None)
    failed = [f for f in installed if by_unit[f[1]].get("ActiveState") == "failed"]
    if failed:
        name, _unit, hint = failed[0]
        return _item(False, Status.CRIT, ref("firewall.failed", name=name), hint)
    first: Optional[str] = installed[0][2] if installed else None
    return _item(False, Status.WARN, ref("firewall.inactive"), first)


def _item(active: bool, status: Status, text: MessageRef, hint: Optional[str]) -> Item:
    return Item(
        key="sec_firewall.active",
        value=active,
        unit=Unit.BOOL,
        label=ref("label.firewall"),
        status=status,
        text=text,
        visibility=Visibility.ADMIN,
        hint=HintRef(hint) if hint else None,
    )


def _read(ctx: Context, path: str) -> str:
    """A config file, or ``""`` where it is missing or not readable (firewalld's directory
    is 0750 on some systems, and the module runs as ``motp``)."""
    try:
        return ctx.read_text(path, MAX_CONF) if ctx.exists(path) else ""
    except ValueError:
        return ""


class SecFirewall:
    name = "sec_firewall"
    section = "security"
    mode = CACHED
    needs_root = False
    interval = 300
    max_age = 1800
    timeout = 10.0
    binaries: tuple[str, ...] = (services.SYSTEMCTL,)
    default_visibility = Visibility.ADMIN

    def detect(self, ctx: Context) -> Detection:
        return Detection(ctx.exists(services.SYSTEMCTL) and ctx.exists(services.SYSTEMD_RUNNING))

    def collect(self, ctx: Context) -> list[Item]:
        return [firewall_item(ctx, states(ctx.run(ARGV).decode("utf-8", "replace")))]

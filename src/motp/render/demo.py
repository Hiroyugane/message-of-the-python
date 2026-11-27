"""Fixed demo data for ``motp preview --demo`` and the golden-file tests (blueprint 4.6).

It exercises every section and every status (ok, warn, crit, unknown and a stale module),
an attention block with hints from the table and a plugin's plain-text hint, a disk bar
near full, an admin detail row and a failed-module notice. Addresses and names follow the
repository rules: RFC 5737 addresses and ``example.com`` only.
"""

from typing import Optional

from motp.core.cache import Layout
from motp.core.look import PRESET_LOOKS
from motp.core.model import (
    Detail,
    HintRef,
    Item,
    LiteralText,
    ModuleResult,
    ModuleState,
    Status,
    Unit,
    Visibility,
    ref,
)
from motp.core.thresholds import make_rule
from motp.render.view import RenderInput, Source

NOW = 1795600000
HOSTNAME = "web01.example.com"
INTERVAL = 300
MAX_AGE = 86400


def _module(
    module: str,
    section: str,
    items: "list[Item]",
    age: int = 60,
    interval: int = INTERVAL,
    state: Optional[ModuleState] = None,
) -> Source:
    result = ModuleResult(
        collected=NOW - age, interval=interval, max_age=MAX_AGE, items=tuple(items), state=state
    )
    return Source(module, section, result)


def _disk(mount: str, percent: int, size: str, free: str, hint: Optional[str] = None) -> Item:
    return Item(
        key=f"hw_disks.{mount.strip('/').replace('/', '_') or 'root'}",
        label=LiteralText(mount),
        value=percent,
        unit=Unit.PERCENT,
        rule="disk_used_percent",
        text=ref("disk.usage", percent=f"{percent}%", size=size, free=free),
        bar=percent / 100,
        hint=HintRef(hint) if hint else None,
    )


def sources(hostname: str = HOSTNAME) -> tuple[Source, ...]:
    return (
        _module(
            "os_host",
            "host",
            [
                Item("os_host.hostname", hostname, label=ref("label.hostname")),
                Item("os_host.os", "Debian GNU/Linux 13", label=ref("label.os")),
                Item("os_host.kernel", "6.12.48-1-amd64", label=ref("label.kernel")),
            ],
        ),
        _module(
            "net_addresses",
            "host",
            [
                Item("net_addresses.local", "192.0.2.10", label=ref("label.address")),
                Item("net_addresses.dns", "192.0.2.53, 192.0.2.54", label=ref("label.dns")),
            ],
        ),
        _module(
            "os_uptime",
            "system",
            [Item("os_uptime.uptime", 3553200, Unit.SECONDS, label=ref("label.uptime"))],
            age=0,
        ),
        _module(
            "hw_load",
            "system",
            [
                Item(
                    "hw_load.per_core",
                    0.105,
                    Unit.RATIO,
                    label=ref("label.load"),
                    rule="load_per_core",
                    text=ref("load.summary", one="0.42", five="0.37", fifteen="0.31"),
                )
            ],
            age=0,
        ),
        _module(
            "hw_memory",
            "system",
            [
                Item(
                    "hw_memory.used",
                    6335076761,
                    Unit.BYTES,
                    label=ref("label.memory"),
                    status=Status.OK,
                    text=ref("memory.summary", used="5.9 GiB", total="7.9 GiB"),
                )
            ],
            age=0,
        ),
        _module(
            "os_updates",
            "system",
            [
                Item(
                    "os_updates.pending",
                    12,
                    Unit.COUNT,
                    label=ref("label.updates"),
                    status=Status.WARN,
                    text=ref("updates.summary", count=12, security=3),
                    hint=HintRef("updates.security"),
                    detail=(
                        Detail(
                            "os_updates.packages",
                            "openssl, curl, libc6",
                            label=ref("label.packages"),
                            visibility=Visibility.ADMIN,
                        ),
                    ),
                )
            ],
        ),
        _module(
            "os_reboot",
            "system",
            [
                Item(
                    "os_reboot.required",
                    True,
                    Unit.BOOL,
                    label=ref("label.reboot"),
                    status=Status.WARN,
                    text=ref("reboot.required"),
                    hint=HintRef("reboot.required"),
                )
            ],
        ),
        _module(
            "os_eol",
            "system",
            [
                Item(
                    "os_eol.date",
                    "2028-06-30",
                    label=ref("label.eol"),
                    status=Status.OK,
                    text=ref("eol.supported", date="2028-06-30"),
                )
            ],
        ),
        _module(
            "sec_firewall",
            "security",
            [
                Item(
                    "sec_firewall.active",
                    False,
                    Unit.BOOL,
                    label=ref("label.firewall"),
                    status=Status.CRIT,
                    text=ref("firewall.inactive"),
                    hint=HintRef("firewall.ufw"),
                )
            ],
        ),
        _module(
            "os_autoupdates",
            "security",
            [
                Item(
                    "os_autoupdates.enabled",
                    True,
                    Unit.BOOL,
                    label=ref("label.autoupdates"),
                    status=Status.OK,
                    text=ref("autoupdates.on"),
                )
            ],
        ),
        _module(
            "sec_logins",
            "security",
            [
                Item(
                    "sec_logins.failed",
                    37,
                    Unit.COUNT,
                    label=ref("label.failed_logins"),
                    status=Status.OK,
                    text=ref("logins.failed", count=37),
                    visibility=Visibility.ADMIN,
                )
            ],
        ),
        _module(
            "sec_fail2ban",
            "security",
            [
                Item(
                    "sec_fail2ban.banned",
                    None,
                    Unit.COUNT,
                    label=ref("label.fail2ban"),
                    status=Status.UNKNOWN,
                )
            ],
            state=ModuleState.FAILED,  # the one failed module of the attention block
        ),
        _module(
            "os_login",
            "login",
            [
                Item(
                    "os_login.previous",
                    NOW - 7380,
                    Unit.TIMESTAMP,
                    label=ref("label.previous_login"),
                ),
                Item("os_login.source", "198.51.100.7", label=ref("label.login_from")),
            ],
        ),
        _module(
            "os_sessions",
            "login",
            [Item("os_sessions.count", 2, Unit.COUNT, label=ref("label.sessions"))],
        ),
        _module(
            "hw_disks",
            "disks",
            [
                _disk("/", 96, "40 GiB", "1.6 GiB", "disk.space"),
                _disk("/home", 41, "200 GiB", "118 GiB"),
                _disk("/var", 71, "20 GiB", "5.8 GiB"),
            ],
        ),
        _module(
            "os_units",
            "services",
            [
                Item(
                    "os_units.failed",
                    1,
                    Unit.COUNT,
                    label=ref("label.failed_units"),
                    status=Status.CRIT,
                    text=ref("units.failed_count", count=1),
                    hint=HintRef("units.failed"),
                    detail=(Detail("os_units.names", "nightly-report.service"),),
                ),
                Item(
                    "unit.nginx",
                    "active",
                    label=LiteralText("nginx.service"),
                    status=Status.OK,
                ),
            ],
        ),
        _module(
            "app_containers",
            "containers",
            [
                Item(
                    "app_containers.states",
                    3,
                    Unit.COUNT,
                    label=ref("label.containers"),
                    status=Status.OK,
                    text=ref("containers.summary", running=3, stopped=1),
                )
            ],
            age=2700,  # older than three intervals: shown with its age
        ),
        _module(
            "50-backup-status",
            "plugins",
            [
                Item(
                    "plugin.50-backup-status.age",
                    # A plugin brings its own translations (4.4); MOTP translates none.
                    label=LiteralText("Backup", (("de", "Sicherung"),)),
                    status=Status.WARN,
                    text=LiteralText(
                        "last run 30 hours ago", (("de", "letzter Lauf vor 30 Stunden"),)
                    ),
                    hint=LiteralText(
                        "Check the backup job on the storage server",
                        (("de", "Sicherungsauftrag auf dem Server prüfen"),),
                    ),
                    origin="50-backup-status",
                )
            ],
        ),
    )


RULES = {
    "disk_used_percent": make_rule("disk_used_percent", 80, 90),
    "load_per_core": make_rule("load_per_core", 0.7, 1.0),
}


def demo_input(
    hostname: str = HOSTNAME,
    *,
    language: str = "en",
    layout: Optional[Layout] = None,
    admin: bool = True,
    preset: str = "default",
) -> RenderInput:
    """The demo as an admin on an apt system sees it, with one failed module."""
    return RenderInput(
        sources=sources(hostname),
        now=NOW,
        hostname=hostname,
        layout=layout or Layout(),
        language=language,
        rules=RULES,
        package_manager="apt",
        failed=1,
        admin=admin,
        look=PRESET_LOOKS[preset],
    )

"""The explicit list of built-in modules (blueprint 4.2, 4.3).

Adding a module means adding one line here. Nothing is discovered from the file system, so
the list of code that can run is the list in this file.

``cached_modules()`` returns the cached modules that exist; the collector runs them, each
in a probe process. They are imported on first use, so ``motp show`` (which needs only
their names and sections) never loads their code. ``CACHED`` names every cached module of
the blueprint table with the section it renders in, in display order (host first, then the
system block, then everything else), so ``motp show`` can place a cache entry whose module
a later phase adds; a test keeps the two in step.
"""

import functools
from typing import Optional

from motp.core.probe import PLUGIN_NAME
from motp.core.thresholds import Direction, Rule
from motp.modules.base import Module
from motp.modules.hw_load import HwLoad
from motp.modules.hw_memory import HwMemory
from motp.modules.os_uptime import OsUptime

PLUGIN_SECTION = "plugins"

# Live modules, in display order. ``os_uptime`` leads the system block as in the demo.
LIVE_MODULES: tuple[Module, ...] = (OsUptime(), HwLoad(), HwMemory())

# Cached modules of 4.3: (name, section), in display order.
CACHED: tuple[tuple[str, str], ...] = (
    ("os_host", "host"),
    ("net_addresses", "host"),
    ("hw_disks", "disks"),
    ("os_updates", "system"),
    ("os_reboot", "system"),
    ("os_autoupdates", "security"),
    ("os_eol", "system"),
    ("os_units", "services"),
    ("rows_unit", "services"),
    ("rows_file_age", "services"),
    ("os_sessions", "login"),
    ("os_login", "login"),
    ("sec_logins", "security"),
    ("sec_fail2ban", "security"),
    ("sec_firewall", "security"),
    ("app_containers", "containers"),
)

# The item keys of the built-in modules: the names ``hide_rows`` and ``row_order`` take
# (D35), with the message that names the row. A ``*`` stands for a part taken from the
# system or the config (a mount point, a unit, a row's label); its message says which.
# ``motp modules --keys`` lists them, and the config check warns about a key that matches
# none (final review, usability item 5). A test keeps the table in step with the modules.
ITEM_KEYS: dict[str, dict[str, str]] = {
    "os_uptime": {"os_uptime.uptime": "label.uptime"},
    "hw_load": {"hw_load.per_core": "label.load"},
    "hw_memory": {"hw_memory.used": "label.memory", "hw_memory.swap": "label.swap"},
    "os_host": {
        "os_host.hostname": "label.hostname",
        "os_host.os": "label.os",
        "os_host.kernel": "label.kernel",
    },
    "net_addresses": {"net_addresses.local": "label.address", "net_addresses.dns": "label.dns"},
    "hw_disks": {"hw_disks.*": "keys.mount", "hw_disks.*-inodes": "keys.mount_inodes"},
    "os_updates": {"os_updates.pending": "label.updates"},
    "os_reboot": {"os_reboot.required": "label.reboot"},
    "os_autoupdates": {"os_autoupdates.enabled": "label.autoupdates"},
    "os_eol": {"os_eol.date": "label.eol"},
    "os_units": {"os_units.failed": "label.failed_units"},
    "rows_unit": {"rows_unit.*": "keys.rows_unit"},
    "rows_file_age": {"rows_file_age.*": "keys.rows_file_age"},
    "os_sessions": {"os_sessions.count": "label.sessions"},
    "os_login": {
        "os_login.previous": "label.previous_login",
        "os_login.source": "label.login_from",
        "os_login.tty": "label.login_tty",
    },
    "sec_logins": {"sec_logins.failed": "label.failed_logins"},
    "sec_fail2ban": {
        "sec_fail2ban.banned": "label.fail2ban",
        "sec_fail2ban.running": "label.fail2ban",
    },
    "sec_firewall": {"sec_firewall.active": "label.firewall"},
    "app_containers": {
        "app_containers.docker": "label.docker",
        "app_containers.podman": "label.podman",
    },
}


def module_names() -> tuple[str, ...]:
    """Every built-in module name, live and cached, in display order."""
    return tuple(m.name for m in LIVE_MODULES) + tuple(name for name, _section in CACHED)


def key_known(key: str) -> bool:
    """Whether ``key`` is a built-in item key (a ``*`` matches one or more characters)."""
    module = key.split(".", 1)[0]
    return any(_matches(pattern, key) for pattern in ITEM_KEYS.get(module, {}))


def all_keys() -> tuple[str, ...]:
    return tuple(key for keys in ITEM_KEYS.values() for key in keys)


def _matches(pattern: str, key: str) -> bool:
    head, star, tail = pattern.partition("*")
    if not star:
        return key == pattern
    return len(key) > len(head) + len(tail) and key.startswith(head) and key.endswith(tail)


# Limits for the rules of live values when ``render.json`` has none. They equal the
# defaults in ``data/default-config.toml``; a test keeps the two in step.
LIVE_RULES: dict[str, Rule] = {
    "load_per_core": Rule("load_per_core", 0.7, 1.0, Direction.HIGHER_IS_WORSE),
    "memory_used_percent": Rule("memory_used_percent", 90, 95, Direction.HIGHER_IS_WORSE),
    "swap_used_percent": Rule("swap_used_percent", 50, 80, Direction.HIGHER_IS_WORSE),
}


def live_modules() -> tuple[Module, ...]:
    return LIVE_MODULES


@functools.cache
def cached_modules() -> tuple[Module, ...]:
    """The cached modules that exist, in the order the collector starts them."""
    from motp.modules.app_containers import AppContainers
    from motp.modules.hw_disks import HwDisks
    from motp.modules.net_addresses import NetAddresses
    from motp.modules.os_autoupdates import OsAutoupdates
    from motp.modules.os_eol import OsEol
    from motp.modules.os_host import OsHost
    from motp.modules.os_login import OsLogin
    from motp.modules.os_reboot import OsReboot
    from motp.modules.os_sessions import OsSessions
    from motp.modules.os_units import OsUnits
    from motp.modules.os_updates import OsUpdates
    from motp.modules.rows_file_age import RowsFileAge
    from motp.modules.rows_unit import RowsUnit
    from motp.modules.sec_fail2ban import SecFail2ban
    from motp.modules.sec_firewall import SecFirewall
    from motp.modules.sec_logins import SecLogins

    return (
        OsHost(),
        NetAddresses(),
        HwDisks(),
        OsUpdates(),
        OsReboot(),
        OsAutoupdates(),
        OsEol(),
        OsUnits(),
        RowsUnit(),
        RowsFileAge(),
        OsSessions(),
        OsLogin(),
        SecLogins(),
        SecFail2ban(),
        SecFirewall(),
        AppContainers(),
    )


def cached_module(name: str) -> Optional[Module]:
    """The cached module of that name, or ``None``."""
    for module in cached_modules():
        if module.name == name:
            return module
    return None


def section_of(name: str) -> Optional[str]:
    """The section a module's items render in; ``None`` for a name nobody knows."""
    for module in LIVE_MODULES:
        if module.name == name:
            return module.section
    for cached, section in CACHED:
        if cached == name:
            return section
    return PLUGIN_SECTION if PLUGIN_NAME.match(name) else None


def order_key(name: str) -> tuple[int, int, str]:
    """Sort key for display order: live modules, cached modules, then plugins by name."""
    for i, module in enumerate(LIVE_MODULES):
        if module.name == name:
            return (0, i, name)
    for i, (cached, _section) in enumerate(CACHED):
        if cached == name:
            return (1, i, name)
    return (2, 0, name)

"""Fixed hint table: hint id -> message id and command per package manager (D34, T7).

A built-in probe names a hint by id; the renderer shows the message and, where one exists,
the command from this table. Nothing from collected data ever becomes part of a command:
the table is literal, and ``lookup`` takes only the hint id and the package manager, which
the renderer reads from ``render.json`` and checks against ``PACKAGE_MANAGERS``. Plugins
cannot name hint ids; their plain-text hints are shown as text and never as a command.

Commands are written for a beginner to copy. They are shell text for a person to read, not
for MOTP to run: MOTP never executes them.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Optional

# Package managers a command can be specific to; "*" is the entry for every system.
PACKAGE_MANAGERS = ("apt", "dnf")
ANY = "*"


@dataclass(frozen=True)
class HintEntry:
    message: str
    commands: Mapping[str, str]


def _entry(message: str, **commands: str) -> HintEntry:
    if "any" in commands:
        commands[ANY] = commands.pop("any")
    return HintEntry(message, MappingProxyType(dict(commands)))


HINTS: Mapping[str, HintEntry] = MappingProxyType(
    {
        "updates.install": _entry(
            "hint.updates.install", apt="sudo apt upgrade", dnf="sudo dnf upgrade"
        ),
        "updates.security": _entry(
            "hint.updates.security", apt="sudo apt upgrade", dnf="sudo dnf upgrade --security"
        ),
        "reboot.required": _entry("hint.reboot.required", any="sudo reboot"),
        "units.failed": _entry("hint.units.failed", any="systemctl --failed"),
        "disk.space": _entry("hint.disk.space", any="df -h"),
        "disk.inodes": _entry("hint.disk.inodes", any="df -i"),
        "autoupdates.install": _entry(
            "hint.autoupdates.install",
            apt="sudo apt install unattended-upgrades",
            dnf="sudo dnf install dnf-automatic",
        ),
        # dnf 4's install timer applies updates whatever automatic.conf says.
        "autoupdates.enable": _entry(
            "hint.autoupdates.enable",
            apt="sudo dpkg-reconfigure -plow unattended-upgrades",
            dnf="sudo systemctl enable --now dnf-automatic-install.timer",
        ),
        "autoupdates.enable_dnf5": _entry(
            "hint.autoupdates.enable", dnf="sudo systemctl enable --now dnf5-automatic.timer"
        ),
        "autoupdates.apply_dnf5": _entry(
            "hint.autoupdates.apply", dnf="sudoedit /etc/dnf/automatic.conf"
        ),
        "autoupdates.timer": _entry(
            "hint.autoupdates.enable",
            apt="sudo systemctl enable --now apt-daily.timer apt-daily-upgrade.timer",
        ),
        # A masked unit cannot be enabled.
        "autoupdates.unmask": _entry(
            "hint.autoupdates.unmask",
            apt="sudo systemctl unmask apt-daily.timer apt-daily-upgrade.timer",
            dnf="sudo systemctl unmask dnf-automatic-install.timer",
        ),
        "autoupdates.unmask_dnf5": _entry(
            "hint.autoupdates.unmask", dnf="sudo systemctl unmask dnf5-automatic.timer"
        ),
        "autoupdates.periodic": _entry(
            "hint.autoupdates.periodic",
            apt="grep -r APT::Periodic::Enable /etc/apt/apt.conf.d",
        ),
        "firewall.ufw": _entry("hint.firewall.enable", any="sudo ufw enable"),
        "firewall.firewalld": _entry(
            "hint.firewall.enable", any="sudo systemctl enable --now firewalld"
        ),
        "firewall.nftables": _entry(
            "hint.firewall.enable", any="sudo systemctl enable --now nftables"
        ),
        "os.eol": _entry("hint.os.eol", any="motp explain eol"),
        "modules.failed": _entry("hint.modules.failed", any="motp doctor"),
        "cache.stale": _entry("hint.cache.stale", any="systemctl status motp-collect.timer"),
        "fail2ban.status": _entry("hint.fail2ban.status", any="sudo fail2ban-client status"),
        "import_path.check": _entry("hint.import_path", any="sudo motp doctor"),
        "config.check": _entry("hint.config.check", any="sudo motp config check"),
    }
)


def is_known(hint_id: str) -> bool:
    return hint_id in HINTS


def lookup(hint_id: str, package_manager: str) -> Optional[tuple[str, Optional[str]]]:
    """Return ``(message id, command or None)`` for a hint, or ``None`` if the id is unknown.

    The command for ``package_manager`` wins over the generic one; an unknown package
    manager gets only the generic command.
    """
    entry = HINTS.get(hint_id)
    if entry is None:
        return None
    command = None
    if package_manager in PACKAGE_MANAGERS:
        command = entry.commands.get(package_manager)
    if command is None:
        command = entry.commands.get(ANY)
    return entry.message, command

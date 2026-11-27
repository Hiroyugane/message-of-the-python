"""What the package modules share: which package manager the system has, and package names.

``os_updates``, ``os_reboot`` and ``os_autoupdates`` ask here. The answer comes from
which program exists, apt first, the same order the collector uses for the hint commands
(``collect.runner.package_manager``).
"""

import re
from collections.abc import Iterable

from motp.modules.base import Context

APT = "apt"
DNF4 = "dnf4"
DNF5 = "dnf5"

APT_GET = "/usr/bin/apt-get"
APT_CONFIG = "/usr/bin/apt-config"
DNF = "/usr/bin/dnf"
DNF5_PROGRAM = "/usr/bin/dnf5"
RPM = "/usr/bin/rpm"

# A package name as dpkg and rpm allow it, with apt's ":architecture" suffix. Anything
# else in a tool's output or a system file is not a package name.
PACKAGE_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9+._~:-]{0,127}\Z")
NAME_LIST_CHARS = 100  # below the sanitiser's value limit, with room for the "+N"


def backend(ctx: Context) -> str:
    """``apt``, ``dnf4``, ``dnf5``, or ``""`` when the system has none of them."""
    if ctx.exists(APT_GET):
        return APT
    if ctx.exists(DNF5_PROGRAM):
        return DNF5
    if ctx.exists(DNF):
        return DNF4
    return ""


def name_list(names: Iterable[str], limit: int = NAME_LIST_CHARS) -> str:
    """``openssl, curl, +7``: as many names as fit, then how many were left out. The
    suffix has no word in it, so it needs no translation."""
    wanted = [name[:limit] for name in names]
    shown: list[str] = []
    length = 0
    for name in wanted:
        length += len(name) + 2
        if shown and length > limit:
            break
        shown.append(name)
    if len(shown) < len(wanted):
        shown.append(f"+{len(wanted) - len(shown)}")
    return ", ".join(shown)

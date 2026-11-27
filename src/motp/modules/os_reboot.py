"""``os_reboot``: whether the system waits for a restart (blueprint 4.3, 5.4, open item O5).

Runs as a cached module in a probe process as the user ``motp``.

* **A flag file**, ``/run/reboot-required``: written on Debian and Ubuntu after an update
  that needs a restart; ``/run/reboot-required.pkgs`` names the packages that asked. It
  is honoured on every system. Where no flag exists, "not required" is only said when
  something is installed that would write it; otherwise MOTP cannot know and shows no
  row.
* **The RHEL family** writes no flag, and ``needs-restarting`` is an extra package. The
  module asks rpm when the packages that a running system keeps in memory (the kernel,
  glibc, systemd and a few more) were installed: one installed after the system started
  is not the one that runs. "Started" is the start of process 1, which is the boot of a
  real machine and the start of a container, whose host booted earlier.

Whether a restart is needed is public; the packages are an admin-only detail (5.4).
"""

import re

from motp.core.model import Detail, HintRef, Item, Status, Unit, Visibility, ref
from motp.modules import packages
from motp.modules.base import CACHED, Context, Detection, parse_error

FLAG = "/run/reboot-required"
FLAG_PACKAGES = "/run/reboot-required.pkgs"
# One of these on a Debian-family system writes the flag.
FLAG_WRITERS = (
    "/usr/share/update-notifier/notify-reboot-required",
    "/etc/kernel/postinst.d/update-notifier",
    "/etc/kernel/postinst.d/unattended-upgrades",
)
# What a running system does not reload; the list follows dnf's needs-restarting.
CORE_PACKAGES = (
    "kernel",
    "kernel-core",
    "kernel-rt",
    "kernel-rt-core",
    "kernel-64k",
    "kernel-64k-core",
    "raspberrypi2-kernel4",
    "glibc",
    "linux-firmware",
    "microcode_ctl",
    "systemd",
    "dbus",
    "dbus-broker",
    "dbus-daemon",
)
# rpm expands the escape itself, so the argument holds a backslash, not a line feed.
RPM_ARGV = (packages.RPM, "-qa", "--queryformat", r"%{INSTALLTIME} %{NAME}\n", *CORE_PACKAGES)
STAT = "/proc/stat"
INIT_STAT = "/proc/1/stat"
CLOCK_TICKS = 100  # USER_HZ, the unit of the start time in /proc/<pid>/stat
START_FIELD = 19  # field 22 of proc(5), counted after the command name's ")"
FLAG_PACKAGES_BYTES = 16 * 1024
MAX_STAT = 1024 * 1024  # the interrupt line of a large machine is long

_BOOT_TIME = re.compile(r"^btime ([0-9]{1,12})$", re.MULTILINE)
_INSTALLED = re.compile(r"([0-9]{1,12}) (\S+)\Z")


def flag_packages(text: str) -> list[str]:
    """The package names of the flag's list: each once, other lines left out."""
    names = (line.strip() for line in text.splitlines())
    return list(dict.fromkeys(n for n in names if packages.PACKAGE_NAME.match(n)))


def start_time(ctx: Context) -> int:
    """When process 1 started: the boot, or in a container the container's start."""
    boot = _BOOT_TIME.search(ctx.read_text(STAT, MAX_STAT))
    if boot is None:
        raise parse_error("os_reboot")
    started = int(boot.group(1))
    try:
        fields = ctx.read_text(INIT_STAT, 4096).rsplit(")", 1)[1].split()
        return started + int(fields[START_FIELD]) // CLOCK_TICKS
    except (ValueError, IndexError):
        return started  # /proc may hide other users' processes (hidepid)


def parse_rpm(text: str, since: int) -> list[str]:
    """The core packages installed after ``since``; ``ValueError`` on another shape."""
    newer: list[str] = []
    lines = [line for line in text.split("\n") if line]
    for line in lines:
        match = _INSTALLED.match(line)
        if match is None or not packages.PACKAGE_NAME.match(match.group(2)):
            raise parse_error("os_reboot")
        if int(match.group(1)) > since:
            newer.append(match.group(2))
    if not lines:
        raise parse_error("os_reboot")  # every system has glibc
    return sorted(set(newer))


def reboot_item(required: bool, names: "list[str]") -> Item:
    details: tuple[Detail, ...] = ()
    if required and names:
        listed = packages.name_list(names)
        details = (Detail("os_reboot.packages", listed, label=ref("label.packages")),)
    return Item(
        key="os_reboot.required",
        value=required,
        unit=Unit.BOOL,
        label=ref("label.reboot"),
        status=Status.WARN if required else Status.OK,
        text=ref("reboot.required" if required else "reboot.not_required"),
        hint=HintRef("reboot.required"),
        detail=details,
    )


class OsReboot:
    name = "os_reboot"
    section = "system"
    mode = CACHED
    needs_root = False
    interval = 300  # the next run after an update shows it
    max_age = 3600
    timeout = 15.0
    binaries: tuple[str, ...] = (packages.RPM,)
    default_visibility = Visibility.PUBLIC

    def detect(self, ctx: Context) -> Detection:
        return Detection(bool(packages.backend(ctx)) or ctx.exists(FLAG))

    def collect(self, ctx: Context) -> list[Item]:
        if ctx.exists(FLAG):
            try:
                names = flag_packages(ctx.read_text(FLAG_PACKAGES, FLAG_PACKAGES_BYTES))
            except ValueError:
                names = []
            return [reboot_item(True, names)]
        if packages.backend(ctx) in (packages.DNF4, packages.DNF5):
            out = ctx.run(RPM_ARGV).decode("utf-8", "replace")
            newer = parse_rpm(out, start_time(ctx))
            return [reboot_item(bool(newer), newer)]
        if any(ctx.exists(path) for path in FLAG_WRITERS):
            return [reboot_item(False, [])]
        return []

"""``os_autoupdates``: whether automatic updates are set up (blueprint 4.3, 5.4).

Runs as a cached module in a probe process as the user ``motp``. The state and its hint
are shown to admins only (5.4: it tells how fast a hole gets closed here).

"On" means that updates get **installed** without a person:

* **apt:** unattended-upgrades is installed, apt's merged configuration (read with
  ``apt-config dump``, so apt applies its own rules for the files) has
  ``APT::Periodic::Update-Package-Lists`` and ``Unattended-Upgrade`` set and ``Enable``
  not switched off, and on a systemd system both ``apt-daily.timer`` (it refreshes the
  lists) and ``apt-daily-upgrade.timer`` (it installs) are enabled and not masked.
* **dnf 4:** ``dnf-automatic-install.timer`` is enabled, or ``dnf-automatic.timer`` is
  and ``apply_updates`` is yes. The other timers only download or notify.
* **dnf 5:** ``dnf5-automatic.timer`` is enabled and ``apply_updates`` is yes in the
  chain of configuration files dnf 5 reads.

Whether a timer is enabled is read from the links systemd keeps in
``timers.target.wants``; the module asks no daemon anything.

The hint fits what is wrong: a masked unit has to be unmasked first (``systemctl enable``
refuses it), and a switched-off periodic run is not repaired by configuring
unattended-upgrades again. Where a file has to be edited, the row's own text says what to
change, because an alert with a command shows no hint sentence.
"""

import re
from typing import Optional

from motp.core.model import HintRef, Item, Status, Unit, Visibility, ref
from motp.modules import packages
from motp.modules.base import CACHED, Context, Detection, parse_error

UNATTENDED = "/usr/bin/unattended-upgrade"
APT_CONFIG_ARGV = (packages.APT_CONFIG, "dump", "APT::Periodic")
SYSTEMD_RUNNING = "/run/systemd/system"
WANTS_DIRS = (
    "/etc/systemd/system/timers.target.wants",
    "/usr/lib/systemd/system/timers.target.wants",
)
OVERRIDE_DIR = "/etc/systemd/system"
# The first refreshes the package lists, the second installs.
APT_TIMERS = ("apt-daily.timer", "apt-daily-upgrade.timer")
ENABLED = "enabled"
DISABLED = "disabled"
MASKED = "masked"

DNF4_UNIT = "/usr/lib/systemd/system/dnf-automatic.timer"
DNF5_UNIT = "/usr/lib/systemd/system/dnf5-automatic.timer"
DNF4_PLAIN = "dnf-automatic.timer"  # installs only with apply_updates = yes
DNF4_INSTALL = "dnf-automatic-install.timer"
DNF4_FETCH = ("dnf-automatic-download.timer", "dnf-automatic-notifyonly.timer")
DNF5_TIMERS = ("dnf5-automatic.timer", "dnf-automatic.timer")  # the second is an alias
DNF4_CONF = ("/etc/dnf/automatic.conf",)
# dnf 5's files, later ones win; a directory stands for its *.conf files in name order.
DNF5_CONF = (
    "/usr/share/dnf5/dnf5-plugins/automatic.conf",
    "/usr/share/dnf5/dnf5-plugins/automatic.conf.d",
    "/etc/dnf/dnf5-plugins/automatic.conf",
    "/etc/dnf/automatic.conf",
    "/etc/dnf/automatic.conf.d",
)
CONF_BYTES = 64 * 1024
MAX_CONF_FILES = 32
TRUE_WORDS = frozenset({"1", "yes", "true", "on"})
FALSE_WORDS = frozenset({"0", "no", "false", "off"})

ON = "on"
OFF = "off"
NOT_INSTALLED = "not_installed"
DOWNLOAD_ONLY = "download_only"
APPLY_OFF = "apply_off"  # dnf 5: the timer runs, apply_updates is not set
PERIODIC_OFF = "periodic_off"  # APT::Periodic::Enable is switched off
# Each state as a message, spelled out so the catalogue test finds every id (invariant 5).
TEXTS = {
    ON: ref("autoupdates.on"),
    OFF: ref("autoupdates.off"),
    NOT_INSTALLED: ref("autoupdates.not_installed"),
    DOWNLOAD_ONLY: ref("autoupdates.download_only"),
    APPLY_OFF: ref("autoupdates.apply_off"),
    PERIODIC_OFF: ref("autoupdates.periodic_off"),
}

_APT_LINE = re.compile(r'APT::Periodic::([A-Za-z0-9_-]{1,64}) "([^"]{0,256})";\Z')
_APT_DAYS = re.compile(r"(?:0*[1-9][0-9]{0,6}[smhd]?|always)\Z")


def parse_apt_periodic(text: str) -> dict[str, str]:
    """``apt-config dump APT::Periodic``: the settings below ``APT::Periodic::``."""
    found: dict[str, str] = {}
    for line in text.split("\n"):
        line = line.strip()
        if not line:
            continue
        if not line.startswith("APT::Periodic"):
            raise parse_error("os_autoupdates")
        match = _APT_LINE.match(line)
        if match:  # the table itself, deeper keys and list entries are not asked about
            found[match.group(1)] = match.group(2)
    return found


def periodic_switched_off(settings: "dict[str, str]") -> bool:
    """``APT::Periodic::Enable`` turns the whole periodic run off."""
    return settings.get("Enable", "1").strip().lower() in FALSE_WORDS


def apt_periodic_on(settings: "dict[str, str]") -> bool:
    """Both steps have an interval and the whole periodic run is not switched off."""
    if periodic_switched_off(settings):
        return False
    return all(
        _APT_DAYS.match(settings.get(name, "").strip())
        for name in ("Update-Package-Lists", "Unattended-Upgrade")
    )


def apply_updates(text: str) -> Optional[bool]:
    """``apply_updates`` in the ``[commands]`` section of an automatic.conf, if set."""
    section = ""
    found = None
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#;":
            continue
        if line.startswith("["):
            section = line.strip("[]").strip()
            continue
        name, eq, value = line.partition("=")
        if eq and section == "commands" and name.strip().lower() == "apply_updates":
            word = value.strip().lower()
            if word in TRUE_WORDS or word in FALSE_WORDS:
                found = word in TRUE_WORDS
    return found


def _read(ctx: Context, path: str) -> Optional[str]:
    try:
        return ctx.read_text(path, CONF_BYTES)
    except ValueError:
        return None


def _conf_files(ctx: Context, chain: "tuple[str, ...]") -> list[str]:
    files: list[str] = []
    for path in chain:
        if not path.endswith(".d"):
            files.append(path)
            continue
        try:
            names = ctx.list_dir(path)
        except ValueError:
            continue
        listed = [f"{path}/{n}" for n in names if n.endswith(".conf") and not n.startswith(".")]
        files += listed[:MAX_CONF_FILES]
    return files


def installs_updates(ctx: Context, chain: "tuple[str, ...]") -> bool:
    result = False
    for path in _conf_files(ctx, chain):
        try:
            text = _read(ctx, path)
        except ValueError:
            continue
        value = apply_updates(text) if text is not None else None
        if value is not None:
            result = value
    return result


def timer_state(ctx: Context, timer: str) -> str:
    """``enabled`` (a link in ``timers.target.wants``), ``masked`` (a link to
    ``/dev/null`` or an empty file in ``/etc/systemd/system``) or ``disabled``."""
    override = f"{OVERRIDE_DIR}/{timer}"
    if ctx.exists(override):
        text = _read(ctx, override)  # /dev/null is not a regular file, so reading fails
        if not (text and text.strip()):
            return MASKED
    if any(ctx.exists(f"{directory}/{timer}") for directory in WANTS_DIRS):
        return ENABLED
    return DISABLED


def timer_enabled(ctx: Context, timer: str) -> bool:
    return timer_state(ctx, timer) == ENABLED


def apt_state(ctx: Context) -> "tuple[str, str]":
    """The state and the hint that fixes it."""
    if not ctx.exists(UNATTENDED):
        return NOT_INSTALLED, "autoupdates.install"
    settings = parse_apt_periodic(ctx.run(APT_CONFIG_ARGV).decode("utf-8", "replace"))
    if periodic_switched_off(settings):
        return PERIODIC_OFF, "autoupdates.periodic"
    if not apt_periodic_on(settings):
        return OFF, "autoupdates.enable"
    if ctx.exists(SYSTEMD_RUNNING):
        states = {timer_state(ctx, timer) for timer in APT_TIMERS}
        if MASKED in states:
            return OFF, "autoupdates.unmask"
        if DISABLED in states:
            return OFF, "autoupdates.timer"
    return ON, "autoupdates.enable"


def dnf4_state(ctx: Context) -> "tuple[str, str]":
    if not ctx.exists(DNF4_UNIT):
        return NOT_INSTALLED, "autoupdates.install"
    plain = timer_enabled(ctx, DNF4_PLAIN)
    if timer_enabled(ctx, DNF4_INSTALL) or (plain and installs_updates(ctx, DNF4_CONF)):
        return ON, "autoupdates.enable"
    # The hint enables the install timer, which a mask would refuse.
    masked = timer_state(ctx, DNF4_INSTALL) == MASKED
    hint = "autoupdates.unmask" if masked else "autoupdates.enable"
    if plain or any(timer_enabled(ctx, timer) for timer in DNF4_FETCH):
        return DOWNLOAD_ONLY, hint
    return OFF, hint


def dnf5_state(ctx: Context) -> "tuple[str, str]":
    if not ctx.exists(DNF5_UNIT):
        return NOT_INSTALLED, "autoupdates.install"
    if timer_state(ctx, DNF5_TIMERS[0]) == MASKED:
        return OFF, "autoupdates.unmask_dnf5"
    # Two steps, each with the command that does it: the timer, then the config.
    if not any(timer_enabled(ctx, timer) for timer in DNF5_TIMERS):
        return OFF, "autoupdates.enable_dnf5"
    if not installs_updates(ctx, DNF5_CONF):
        return APPLY_OFF, "autoupdates.apply_dnf5"
    return ON, "autoupdates.enable_dnf5"


STATES = {packages.APT: apt_state, packages.DNF4: dnf4_state, packages.DNF5: dnf5_state}


class OsAutoupdates:
    name = "os_autoupdates"
    section = "security"
    mode = CACHED
    needs_root = False
    interval = 900
    max_age = 86400
    timeout = 10.0
    binaries: tuple[str, ...] = (packages.APT_CONFIG,)
    default_visibility = Visibility.ADMIN

    def detect(self, ctx: Context) -> Detection:
        return Detection(bool(packages.backend(ctx)))

    def collect(self, ctx: Context) -> list[Item]:
        manager = packages.backend(ctx)
        if not manager:
            return []
        state, hint = STATES[manager](ctx)
        return [
            Item(
                key="os_autoupdates.enabled",
                value=state == ON,
                unit=Unit.BOOL,
                label=ref("label.autoupdates"),
                status=Status.OK if state == ON else Status.WARN,
                text=TEXTS[state],
                visibility=Visibility.ADMIN,
                hint=HintRef(hint),
            )
        ]

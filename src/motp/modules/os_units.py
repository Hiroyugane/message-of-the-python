"""``os_units``: failed systemd units (blueprint 4.3, 5.4, phase 10).

Runs as a cached module in a probe process as the user ``motp``. It asks the service
manager over the system bus, which the unit's sandbox allows (O4):

    systemctl list-units --state=failed --all --plain --no-legend --no-pager --full

Each line is ``UNIT LOAD ACTIVE SUB DESCRIPTION``; the description is never used. A line
whose first word is not a unit name, or whose state is not ``failed``, means the output
changed shape, and the module fails rather than guess.

The number of failed units is public; their names are for admins only (5.4): a unit name
can say what runs on the machine, or carry a uid (the user manager of uid 1000 is
``user`` + ``@1000`` + ``.service``).
"""

from motp.core.model import Detail, HintRef, Item, Status, Unit, Visibility, ref
from motp.modules import packages, services
from motp.modules.base import CACHED, Context, Detection, parse_error

ARGV = (
    services.SYSTEMCTL, "list-units", "--state=failed", "--all", "--plain", "--no-legend",
    "--no-pager", "--full",
)  # fmt: skip
MAX_UNITS = 4096


def parse(text: str) -> "list[str]":
    """The names of the failed units, in systemctl's order."""
    names: list[str] = []
    for line in text.splitlines():
        words = line.split()
        if not words:
            continue
        if len(words) < 4 or not services.is_unit_name(words[0]) or words[2] != "failed":
            raise parse_error("os_units")
        names.append(words[0])
        if len(names) > MAX_UNITS:
            raise parse_error("os_units")
    return names


def failed_item(names: "list[str]") -> Item:
    count = len(names)
    if not count:
        return Item(
            key="os_units.failed",
            value=0,
            unit=Unit.COUNT,
            label=ref("label.failed_units"),
            status=Status.OK,
            text=ref("units.none"),
        )
    return Item(
        key="os_units.failed",
        value=count,
        unit=Unit.COUNT,
        label=ref("label.failed_units"),
        status=Status.WARN,
        text=ref("units.failed_count", count=count),
        hint=HintRef("units.failed"),
        detail=(Detail("os_units.names", packages.name_list(names), label=ref("label.units")),),
    )


class OsUnits:
    name = "os_units"
    section = "services"
    mode = CACHED
    needs_root = False
    interval = 300
    max_age = 1800
    timeout = 10.0
    binaries: tuple[str, ...] = (services.SYSTEMCTL,)
    default_visibility = Visibility.PUBLIC

    def detect(self, ctx: Context) -> Detection:
        return Detection(ctx.exists(services.SYSTEMCTL) and ctx.exists(services.SYSTEMD_RUNNING))

    def collect(self, ctx: Context) -> list[Item]:
        return [failed_item(parse(ctx.run(ARGV).decode("utf-8", "replace")))]

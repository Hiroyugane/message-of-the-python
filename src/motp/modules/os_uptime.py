"""``os_uptime``: the time since boot from ``/proc/uptime`` (blueprint 4.3)."""

from motp.core.model import Item, Unit, Visibility, ref
from motp.modules.base import LIVE, Context, Detection, parse_error

UPTIME = "/proc/uptime"
MAX_SECONDS = 10**10


class OsUptime:
    name = "os_uptime"
    section = "system"
    mode = LIVE
    needs_root = False
    interval = 1
    max_age = 60
    timeout = 0.2
    binaries: tuple[str, ...] = ()
    default_visibility = Visibility.PUBLIC

    def detect(self, ctx: Context) -> Detection:
        return Detection(ctx.exists(UPTIME))

    def collect(self, ctx: Context) -> list[Item]:
        fields = ctx.read_text(UPTIME, 256).split()
        try:
            seconds = float(fields[0])
        except (IndexError, ValueError):
            raise parse_error(self.name) from None
        if not 0 <= seconds < MAX_SECONDS:
            raise parse_error(self.name)
        return [
            Item(
                key="os_uptime.uptime",
                value=int(seconds),
                unit=Unit.SECONDS,
                label=ref("label.uptime"),
            )
        ]

"""``os_host``: host name, operating system and kernel (blueprint 4.3, 5.4: public).

Runs as a cached module in a probe process as the user ``motp``. Everything comes from
files: the host name and kernel release from ``/proc/sys/kernel``, the operating system's
name from ``os-release`` (which the probe context has already parsed into
``ctx.os_release``). The values are untrusted text: the probe protocol sanitises them.
"""

from motp.core.model import Item, Visibility, ref
from motp.modules.base import CACHED, Context, Detection, parse_error

HOSTNAME = "/proc/sys/kernel/hostname"
OSRELEASE = "/proc/sys/kernel/osrelease"
MAX_FIELD = 256


def _first_line(ctx: Context, path: str) -> str:
    lines = ctx.read_text(path, MAX_FIELD).splitlines()
    return lines[0].strip() if lines else ""


def os_name(release: "dict[str, str]") -> str:
    """``PRETTY_NAME``, else ``NAME`` and ``VERSION``, else ``Linux`` (os-release(5))."""
    pretty = release.get("PRETTY_NAME", "").strip()
    if pretty:
        return pretty
    name = release.get("NAME", "").strip() or "Linux"
    version = release.get("VERSION", "").strip()
    return f"{name} {version}" if version else name


class OsHost:
    name = "os_host"
    section = "host"
    mode = CACHED
    needs_root = False
    interval = 300
    max_age = 86400
    timeout = 5.0
    binaries: tuple[str, ...] = ()
    default_visibility = Visibility.PUBLIC

    def detect(self, ctx: Context) -> Detection:
        return Detection(ctx.exists(HOSTNAME))

    def collect(self, ctx: Context) -> list[Item]:
        hostname = _first_line(ctx, HOSTNAME)
        if not hostname:
            raise parse_error(self.name)
        items = [Item(key="os_host.hostname", value=hostname, label=ref("label.hostname"))]
        items.append(
            Item(key="os_host.os", value=os_name(dict(ctx.os_release)), label=ref("label.os"))
        )
        try:
            kernel = _first_line(ctx, OSRELEASE)
        except ValueError:
            kernel = ""
        if kernel:
            items.append(Item(key="os_host.kernel", value=kernel, label=ref("label.kernel")))
        return items
